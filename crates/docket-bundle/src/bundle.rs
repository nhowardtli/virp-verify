//! The minimal Docket evidence bundle: a directory.
//!
//! ```text
//! <bundle>/
//!   manifest.json            required — see [`Manifest`]
//!   keys.json                optional — key_id → public key (see [`KeyFile`])
//!   sessions/<name>.json     one [`SessionChain`] per session, paths named in the manifest
//!   seal/<name>.json         optional D-0 seal anchor, path named in the manifest
//!   seal/<name>.minisig      optional detached minisign signature over the seal file,
//!                            path named in the manifest (`seal_signature`)
//!   artifacts/<hash>         optional raw artifact bodies, paths named in the manifest
//! ```
//!
//! The seal SIGNATURE may travel in the bundle; the seal PUBLIC KEY never
//! does. It arrives out of band ([`SealKeyCheck`]) or the signature stays
//! UNVERIFIABLE — the seal's own `seal_public_key` field is ignored either
//! way, and the report says so.
//!
//! Every path in the manifest is relative to the bundle root and may not
//! escape it. The reader is strict: unknown manifest versions, missing
//! files, a key whose bytes do not derive its claimed `key_id`, or a session
//! file whose `session_id` disagrees with the manifest are all hard errors —
//! a bundle that cannot be read is never reported as anything but unreadable.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::camera::{claimed_camera_ids, grade_capture_completeness, CaptureGrade, CaptureReport};
use crate::hash::is_hex_digest_64;
use crate::limits::Limits;
use crate::minisign::{MinisignError, MinisignPublicKey, MinisignSignature};
use crate::producer::{grade_producer_signatures, ProducerSignerReport};
use crate::seal::Seal;
use crate::sig::PublicKey;
use crate::verify::{
    grade_artifact_binding, verify_session, ArtifactCoverage, ArtifactStore, Keyring, SessionChain, SessionReport,
    Status, Verdict,
};

pub const BUNDLE_VERSION: &str = "docket-bundle/0.1";
pub const CHAIN_FORMAT: &str = "v1";
/// Version of the report schema ([`BundleReport`] as serialized by
/// `virp-verify --json` and served at `/api/report`). The unversioned report
/// that predates this field is retroactively `docket-report/0.1`; `0.2`
/// added the field itself, the per-session `signer` object
/// (signature validity / signer trust / trust source), the
/// `pinned_key_ids` / `bundle_key_ids` split, and the
/// `cryptographically_consistent` verdict. `0.3` added the per-session
/// `capture_completeness` object and the top-level `boundary` object
/// (`source_device_established`, `capture_completeness`); no existing field
/// changed shape or meaning, no verdict or exit code changed, so a tolerant
/// consumer of 0.2 sees two new keys and nothing else. `0.4` added the
/// per-session `producer` object (producer-signature validity / producer
/// trust — the capture host's key, a separate boundary from the O-Node
/// chain key) and the top-level `producer_key_ids` list; again additive
/// only: no existing field changed shape or meaning, no verdict changed.
/// `0.5` added the per-session `external_predecessor_gaps` list inside
/// `capture_completeness` (gap records at a sliced export's left boundary,
/// citing a predecessor the bundle does not carry); additive only: no
/// existing field changed shape or meaning, no verdict or exit code
/// changed — but a session whose only capture defect was such a boundary
/// gap now grades INTERRUPTED / ACCOUNTED where 0.4 graded it FAILED.
pub const REPORT_VERSION: &str = "docket-report/0.5";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSession {
    pub session_id: String,
    /// Relative path to the session JSON.
    pub path: String,
}

/// One carried artifact body: the exact bytes whose SHA-256 an entry's
/// `artifact_hash` commits to, stored verbatim in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    /// The `artifact_hash` this body claims to be the preimage of. A claim:
    /// the verifier recomputes SHA-256 over the file bytes and grades a
    /// mismatch FAILED (`artifact_binding`).
    pub artifact_hash: String,
    /// Relative path to the raw body bytes.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Must be `docket-bundle/0.1`.
    pub docket_bundle_version: String,
    /// Must be `v1` — the VIRP canonical format. Signed entries are
    /// distinguished by the presence of their `signature` object, not by a
    /// format bump (DRAFT07-NOTES §2).
    pub chain_format: String,
    #[serde(default)]
    pub producer: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    pub sessions: Vec<ManifestSession>,
    /// Relative path to `keys.json`.
    #[serde(default)]
    pub keys: Option<String>,
    /// Relative path to the seal JSON.
    #[serde(default)]
    pub seal: Option<String>,
    /// Relative path to the detached minisign signature over the seal file.
    /// A signature is a claim the verifier grades, so it may travel in-band;
    /// the PUBLIC KEY that checks it never does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_signature: Option<String>,
    /// Artifact bodies carried in this bundle (exporter `--artifacts`).
    /// Absent in hash-only bundles; when absent, no `artifact_binding` is
    /// graded and nothing in the report implies bodies exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<ManifestArtifact>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Claimed `sha256-raw-16` id — checked against the bytes, never trusted.
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    pub keys: Vec<KeyEntry>,
}

/// Why a bundle could not be read. None of these is a verification
/// outcome; they mean the verifier never got to look.
#[derive(Debug)]
pub enum BundleError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    UnsupportedVersion(String),
    UnsupportedChainFormat(String),
    UnsafePath(String),
    KeyIdMismatch {
        claimed: String,
        derived: String,
    },
    UnsupportedKeyAlgorithm(String),
    InvalidKey(String),
    SessionIdMismatch {
        manifest: String,
        file: String,
    },
    Seal(crate::seal::SealError),
    /// The carried seal signature file is not a minisign signature. A
    /// cryptographically WRONG signature is graded FAILED at verify time;
    /// this is a file the reader cannot interpret at all.
    SealSignature(MinisignError),
    /// The manifest names a seal signature but no seal: a signature over
    /// nothing that is present cannot be graded against anything.
    SealSignatureWithoutSeal(String),
    /// A manifest `artifacts[].artifact_hash` label is not a 64-hex digest.
    MalformedArtifactHash(String),
    /// Two manifest artifact rows claim the same `artifact_hash`.
    DuplicateArtifact(String),
    /// A carried body is referenced by no entry in the bundle: content
    /// nothing in the evidence commits to. Strict reading rejects it.
    UnreferencedArtifact(String),
    /// A file exceeds its ceiling in [`Limits`]. Reading stops at the limit,
    /// so the oversized content is never allocated.
    TooLarge {
        path: PathBuf,
        what: &'static str,
        max: u64,
    },
    /// A count exceeds its ceiling in [`Limits`].
    TooMany {
        what: &'static str,
        max: usize,
    },
    /// Two manifest rows name the same session, or two loaded session files
    /// carry the same `session_id`. One session presented twice inflates
    /// every count in the report.
    DuplicateSession(String),
    /// Two manifest rows name the same session file.
    DuplicateSessionPath(String),
    /// A path inside the bundle is, or passes through, a symlink. A bundle
    /// is a self-contained directory; a symlink in one can leave it.
    SymlinkInBundle {
        manifest_path: String,
        component: PathBuf,
    },
    /// A string field carries a byte the producer could not have written
    /// into the canonical form unescaped. See [`unencodable_byte`].
    UnencodableField {
        session_id: String,
        sequence: i64,
        field: &'static str,
        offset: usize,
        byte: u8,
    },
    /// A string field exceeds its ceiling in [`Limits`]. Checked before the
    /// canonical bytes that would embed it are built.
    FieldTooLong {
        session_id: String,
        sequence: i64,
        field: &'static str,
        len: usize,
        max: usize,
    },
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "{}: invalid JSON: {source}", path.display()),
            Self::UnsupportedVersion(v) => write!(f, "unsupported docket_bundle_version {v:?} (want {BUNDLE_VERSION})"),
            Self::UnsupportedChainFormat(v) => write!(f, "unsupported chain_format {v:?} (want {CHAIN_FORMAT})"),
            Self::UnsafePath(p) => write!(f, "manifest path {p:?} is absolute or escapes the bundle"),
            Self::KeyIdMismatch { claimed, derived } => {
                write!(
                    f,
                    "keys file claims key_id {claimed} but the key bytes derive {derived}"
                )
            }
            Self::UnsupportedKeyAlgorithm(a) => write!(f, "unsupported key algorithm {a:?} (want ed25519)"),
            Self::InvalidKey(k) => write!(f, "public key {k} is not a valid Ed25519 key"),
            Self::SessionIdMismatch { manifest, file } => {
                write!(f, "manifest names session {manifest:?} but the file says {file:?}")
            }
            Self::Seal(e) => write!(f, "seal: {e}"),
            Self::SealSignature(e) => write!(f, "seal signature: {e}"),
            Self::SealSignatureWithoutSeal(p) => {
                write!(f, "manifest names seal signature {p:?} but no seal document")
            }
            Self::MalformedArtifactHash(h) => {
                write!(
                    f,
                    "manifest artifacts entry claims artifact_hash {h:?}, which is not a 64-hex digest"
                )
            }
            Self::DuplicateArtifact(h) => {
                write!(f, "manifest lists more than one artifact body for artifact_hash {h}")
            }
            Self::UnreferencedArtifact(h) => {
                write!(
                    f,
                    "carried artifact body {h} is referenced by no entry in the bundle (unattested content)"
                )
            }
            Self::TooLarge { path, what, max } => {
                write!(f, "{}: {what} exceeds the {max}-byte limit", path.display())
            }
            Self::TooMany { what, max } => write!(f, "bundle exceeds the limit of {max} {what}"),
            Self::DuplicateSession(id) => write!(
                f,
                "session {id:?} appears more than once; one session presented twice is two sessions in every count the report prints"
            ),
            Self::DuplicateSessionPath(p) => {
                write!(f, "manifest lists the session file {p:?} more than once")
            }
            // The offending byte is reported as a number, never echoed: the
            // values this rejects include raw control characters, and writing
            // them to a terminal is how a diagnostic becomes an attack.
            Self::UnencodableField {
                session_id,
                sequence,
                field,
                offset,
                byte,
            } => write!(
                f,
                "session {session_id:?} sequence {sequence}: {field} contains byte 0x{byte:02x} at offset {offset}, \
                 which the producer could not have written into the canonical form (VIRP v1 inserts string values \
                 unescaped, so this value's field boundaries are ambiguous)"
            ),
            Self::SymlinkInBundle {
                manifest_path,
                component,
            } => write!(
                f,
                "manifest path {manifest_path:?} resolves through a symlink ({}); a bundle is a self-contained directory and may not contain one",
                component.display()
            ),
            Self::FieldTooLong {
                session_id,
                sequence,
                field,
                len,
                max,
            } => write!(
                f,
                "session {session_id:?} sequence {sequence}: {field} is {len} bytes, over the {max}-byte limit"
            ),
        }
    }
}

impl std::error::Error for BundleError {}

/// A fully read bundle.
#[derive(Debug)]
pub struct Bundle {
    pub root: PathBuf,
    pub manifest: Manifest,
    pub keyring: Keyring,
    pub sessions: Vec<SessionChain>,
    pub seal: Option<Seal>,
    /// The seal file's exact bytes — what a minisign signature signs.
    /// `Some` whenever `seal` is.
    pub seal_bytes: Option<Vec<u8>>,
    /// The carried detached signature over the seal file, when the manifest
    /// names one. Parsed strictly at read; graded only under an out-of-band
    /// key at verify.
    pub seal_signature: Option<MinisignSignature>,
    /// Carried artifact bodies keyed by claimed `artifact_hash`. `None` for
    /// a hash-only bundle (no `artifacts` key in the manifest).
    pub artifacts: Option<ArtifactStore>,
}

/// Resolve a manifest-relative path inside the bundle root.
///
/// Two independent checks, because the lexical one alone is not the property
/// the module doc claims.
///
/// 1. **Lexical.** No absolute paths, no `..`, no `.`, no prefix or root
///    components — only plain names.
/// 2. **No symlinks, at any depth.** A manifest path of `sessions/s.json` is
///    lexically spotless and still reads `/etc/shadow` if `s.json` — or
///    `sessions/` — is a symlink. Both were confirmed to escape: an absolute
///    target and a `../../` relative target each verified
///    CRYPTOGRAPHICALLY-VERIFIED against a file outside the bundle.
///
/// Symlinks are rejected outright rather than resolved-and-contained. A
/// bundle is a self-contained directory, so a symlink inside one is not a
/// legitimate construct and there is nothing to preserve by allowing it. A
/// containment check would also still admit a symlink that stays *inside* the
/// root, which creates aliasing — two manifest paths naming one file — that
/// is finding 9's inflation problem arriving through a second door. And
/// `canonicalize`-then-compare resolves the path twice: once for the check,
/// once for the open, which is a race the outright rejection does not need.
///
/// Every component BELOW the root is checked. The root itself is not: the
/// operator names it on the command line, and if they point the verifier at
/// a symlink that is their own directory they are choosing.
///
/// Residual, and worth stating plainly: `symlink_metadata` and the later
/// `open` are still two separate resolutions, so an attacker who can mutate
/// the bundle directory *while the verifier runs* can swap a component
/// between them. That is a strictly smaller threat than the one closed here,
/// and closing it needs per-component `openat`, which this crate cannot reach
/// without `unsafe` or a new dependency.
fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, BundleError> {
    let p = Path::new(rel);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(BundleError::UnsafePath(rel.to_owned()));
    }
    let mut walked = root.to_path_buf();
    for component in p.components() {
        walked.push(component);
        match std::fs::symlink_metadata(&walked) {
            Ok(md) if md.file_type().is_symlink() => {
                return Err(BundleError::SymlinkInBundle {
                    manifest_path: rel.to_owned(),
                    component: walked,
                });
            }
            Ok(_) => {}
            // Not there. Not this function's error to report: the read that
            // follows produces a precise `Io` with the full path.
            Err(_) => break,
        }
    }
    Ok(root.join(p))
}

/// Read at most `max` bytes, and fail if the file has more.
///
/// Deliberately not `metadata().len()` followed by `fs::read`: the length a
/// filesystem reports is not a promise (a named pipe reports 0 and streams
/// forever), and between the check and the read the file can change. Taking
/// `max + 1` bytes bounds the allocation by construction — one byte over the
/// ceiling is enough to know the file is too big, and no more than that is
/// ever held.
fn read_capped(path: &Path, max: u64, what: &'static str) -> Result<Vec<u8>, BundleError> {
    use std::io::Read as _;
    let io = |source| BundleError::Io {
        path: path.to_owned(),
        source,
    };
    let file = std::fs::File::open(path).map_err(io)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(io)?;
    if bytes.len() as u64 > max {
        return Err(BundleError::TooLarge {
            path: path.to_owned(),
            what,
            max,
        });
    }
    Ok(bytes)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, max: u64, what: &'static str) -> Result<T, BundleError> {
    let bytes = read_capped(path, max, what)?;
    serde_json::from_slice(&bytes).map_err(|source| BundleError::Json {
        path: path.to_owned(),
        source,
    })
}

/// Read and validate one docket keys file ([`KeyFile`] format). One reader
/// for both provenances — a bundle's `keys.json` and an examiner's `--pin`
/// file get identical strictness: `ed25519` only, and every claimed `key_id`
/// must derive from the key bytes. Provenance is the CALLER's statement
/// ([`Keyring::insert_bundle`] vs [`Keyring::insert_pinned`]), never the
/// file's.
pub fn read_key_file(path: &Path, limits: &Limits) -> Result<Vec<PublicKey>, BundleError> {
    let kf: KeyFile = read_json(path, limits.keys_bytes, "keys file")?;
    let mut keys = Vec::with_capacity(kf.keys.len());
    for k in kf.keys {
        if k.algorithm != "ed25519" {
            return Err(BundleError::UnsupportedKeyAlgorithm(k.algorithm));
        }
        let pk =
            PublicKey::from_hex(&k.public_key_hex).map_err(|_| BundleError::InvalidKey(k.public_key_hex.clone()))?;
        if pk.key_id() != k.key_id {
            return Err(BundleError::KeyIdMismatch {
                claimed: k.key_id,
                derived: pk.key_id().to_owned(),
            });
        }
        keys.push(pk);
    }
    Ok(keys)
}

/// The first byte in `s` that a VIRP v1 producer could not have written into
/// a canonical string value, with its offset.
///
/// # Why this guard exists, and what it is not
///
/// Docket reproduces VIRP's canonical construction exactly, including the
/// fact that string values are inserted **without JSON escaping**. That
/// reproduction is correct and must not change: it is the compatibility
/// contract with the C tree and with the golden vectors, and altering a byte
/// of it would invalidate every signature ever produced.
///
/// The consequence is that canonical bytes are not guaranteed to be valid
/// JSON, and a value containing a quote can forge a field boundary. This
/// function is the read-side half of the answer: a value that could not have
/// been encoded safely is refused, so it never reaches the canonical builder.
///
/// **This is defence in depth, not the fix.** The real fix is producer-side —
/// escaping in the C canonical builder, or length-delimited encoding — and it
/// requires a NEW canonical format version, because either one changes the
/// bytes that get signed. Until that exists, refusing the input is the only
/// thing Docket can do without breaking the contract it exists to honour.
///
/// # What is rejected
///
/// * `"` (0x22) — closes the string value and forges a boundary.
/// * `\` (0x5C) — the escape introducer a v1 producer never emits.
/// * any byte below 0x20, and 0x7F — control characters, which are not legal
///   unescaped inside a JSON string in any case.
///
/// Banning the quote subsumes every delimiter pattern the review lists
/// (`","`, `":`, `{"`, `"}`): each contains one, so none is reachable.
///
/// # What is deliberately NOT rejected
///
/// Non-ASCII. A UTF-8 continuation byte is always >= 0x80 and can never be
/// 0x22 or 0x5C, so multibyte text creates no ambiguity in the canonical and
/// banning it would make the guard narrower than the property it defends.
/// Device and site names are the obvious future source of non-ASCII, and
/// refusing them would be a self-inflicted narrowing.
///
/// # Confirmed against real data
///
/// Every canonical string field of all 13,864 entries on the live chain
/// (2026-08-26, WAL-inclusive) was scanned: no quote, no backslash, no
/// control character, no invalid UTF-8. The values in use are drawn from
/// `[-0-9:a-zR]`. The guard rejects nothing that exists.
pub fn unencodable_byte(s: &str) -> Option<(usize, u8)> {
    s.bytes()
        .enumerate()
        .find(|&(_, b)| b == b'"' || b == b'\\' || b < 0x20 || b == 0x7f)
}

/// Check the string fields that go into an entry's canonical bytes, before
/// those bytes are built: length ceilings and encodability, in one pass.
/// Read-time validation of one session's input, whatever produced it.
///
/// A bundle from a stranger and a live chain database are the same kind of
/// input: bytes this process did not write. The bundle reader has always run
/// these checks; `docket view --db` built a `SessionChain` straight from
/// SQLite rows and ran none of them, so a hostile string field in a live
/// database reached the canonical builder by a path the bundle reader
/// closes. Both callers now go through here.
///
/// What it enforces: the per-session entry ceiling, the per-field length
/// ceilings, and the canonical-encodability guard (no quote, backslash or
/// control byte in a field that enters the canonical bytes). What it does
/// NOT do is grade anything — every property is still decided later, by
/// verify, and a session that passes here can still fail every check there.
pub fn validate_session_input(chain: &SessionChain, limits: &Limits) -> Result<(), BundleError> {
    if chain.entries.len() > limits.entries_per_session {
        return Err(BundleError::TooMany {
            what: "entries in one session",
            max: limits.entries_per_session,
        });
    }
    check_entry_field_lengths(chain, limits)
}

fn check_entry_field_lengths(chain: &SessionChain, limits: &Limits) -> Result<(), BundleError> {
    let too_long = |sequence: i64, field: &'static str, len: usize, max: usize| BundleError::FieldTooLong {
        session_id: chain.session_id.clone(),
        sequence,
        field,
        len,
        max,
    };
    let unencodable = |sequence: i64, field: &'static str, value: &str| {
        unencodable_byte(value).map(|(offset, byte)| BundleError::UnencodableField {
            session_id: chain.session_id.clone(),
            sequence,
            field,
            offset,
            byte,
        })
    };

    if chain.session_id.len() > limits.session_id_bytes {
        return Err(too_long(
            -1,
            "session_id",
            chain.session_id.len(),
            limits.session_id_bytes,
        ));
    }
    if let Some(e) = unencodable(-1, "session_id", &chain.session_id) {
        return Err(e);
    }

    for e in &chain.entries {
        let f = &e.fields;
        // Every string field that enters the canonical bytes. The two digest
        // fields are included: `entry_hashes` requires them to be 64-hex, but
        // that is a graded property that runs later, and a read-time gate must
        // not depend on a check that has not happened yet.
        for (field, value, max) in [
            ("session_id", &f.session_id, limits.session_id_bytes),
            ("artifact_id", &f.artifact_id, limits.artifact_id_bytes),
            ("artifact_type", &f.artifact_type, limits.artifact_type_bytes),
            (
                "artifact_hash_alg",
                &f.artifact_hash_alg,
                limits.artifact_hash_alg_bytes,
            ),
            (
                "artifact_schema_version",
                &f.artifact_schema_version,
                limits.artifact_schema_version_bytes,
            ),
            ("signer_org_id", &f.signer_org_id, limits.signer_org_id_bytes),
            ("artifact_hash", &f.artifact_hash, limits.session_id_bytes),
            ("previous_entry_hash", &f.previous_entry_hash, limits.session_id_bytes),
        ] {
            if value.len() > max {
                return Err(too_long(f.sequence, field, value.len(), max));
            }
            if let Some(err) = unencodable(f.sequence, field, value) {
                return Err(err);
            }
        }
    }

    if let Some(h) = &chain.head {
        if h.fields.session_id.len() > limits.session_id_bytes {
            return Err(too_long(
                h.fields.last_sequence,
                "head session_id",
                h.fields.session_id.len(),
                limits.session_id_bytes,
            ));
        }
        for (field, value) in [
            ("head session_id", &h.fields.session_id),
            ("head last_entry_hash", &h.fields.last_entry_hash),
        ] {
            if let Some(err) = unencodable(h.fields.last_sequence, field, value) {
                return Err(err);
            }
        }
    }
    Ok(())
}

impl Bundle {
    /// Read a bundle directory under [`Limits::default`]. Strict; see the
    /// module docs.
    pub fn read_dir(root: &Path) -> Result<Bundle, BundleError> {
        Bundle::read_dir_with_limits(root, &Limits::default())
    }

    /// Read a bundle directory under caller-chosen resource ceilings.
    pub fn read_dir_with_limits(root: &Path, limits: &Limits) -> Result<Bundle, BundleError> {
        let manifest: Manifest = read_json(
            &safe_join(root, "manifest.json")?,
            limits.manifest_bytes,
            "manifest.json",
        )?;
        if manifest.docket_bundle_version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion(manifest.docket_bundle_version));
        }
        if manifest.chain_format != CHAIN_FORMAT {
            return Err(BundleError::UnsupportedChainFormat(manifest.chain_format));
        }
        if manifest.sessions.len() > limits.sessions {
            return Err(BundleError::TooMany {
                what: "sessions",
                max: limits.sessions,
            });
        }
        if let Some(list) = &manifest.artifacts {
            if list.len() > limits.artifact_bodies {
                return Err(BundleError::TooMany {
                    what: "artifact bodies",
                    max: limits.artifact_bodies,
                });
            }
        }

        let mut keyring = Keyring::new();
        if let Some(rel) = &manifest.keys {
            // Bundle-carried keys: still supported — they are what makes a
            // bundle self-describing — but tagged with their provenance, so
            // they can never stand as an examiner-selected trust anchor on
            // their own.
            for pk in read_key_file(&safe_join(root, rel)?, limits)? {
                keyring.insert_bundle(pk);
            }
        }

        // Uniqueness on all three axes a bundle can duplicate: the manifest's
        // session ids, the manifest's paths, and the identity each loaded file
        // claims for itself. Verification stays cryptographically correct on
        // every copy — that is exactly what makes this worth rejecting, since
        // an inflated report is one where every session says VERIFIED.
        //
        // Paths are compared as component sequences rather than as strings, so
        // two spellings of one path cannot slip past by differing in
        // separators. safe_join has already established that every component
        // is a plain name.
        let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
        let mut seen_paths: BTreeSet<Vec<Component<'_>>> = BTreeSet::new();
        for ms in &manifest.sessions {
            if !seen_ids.insert(ms.session_id.as_str()) {
                return Err(BundleError::DuplicateSession(ms.session_id.clone()));
            }
            if let Some((offset, byte)) = unencodable_byte(&ms.session_id) {
                return Err(BundleError::UnencodableField {
                    session_id: ms.session_id.clone(),
                    sequence: -1,
                    field: "manifest session_id",
                    offset,
                    byte,
                });
            }
            let components: Vec<Component<'_>> = Path::new(ms.path.as_str()).components().collect();
            if !seen_paths.insert(components) {
                return Err(BundleError::DuplicateSessionPath(ms.path.clone()));
            }
        }

        let mut sessions = Vec::with_capacity(manifest.sessions.len());
        let mut entries_total = 0usize;
        let mut loaded_ids: BTreeSet<String> = BTreeSet::new();
        for ms in &manifest.sessions {
            let chain: SessionChain = read_json(&safe_join(root, &ms.path)?, limits.session_bytes, "session file")?;
            if chain.session_id != ms.session_id {
                return Err(BundleError::SessionIdMismatch {
                    manifest: ms.session_id.clone(),
                    file: chain.session_id,
                });
            }
            validate_session_input(&chain, limits)?;
            entries_total = entries_total.saturating_add(chain.entries.len());
            if entries_total > limits.entries_total {
                return Err(BundleError::TooMany {
                    what: "entries across the bundle",
                    max: limits.entries_total,
                });
            }
            // Third axis: identity as the FILE states it. Redundant with the
            // manifest check only while the manifest/file agreement check
            // above holds; asserted separately so that neither check silently
            // becomes the only one.
            if !loaded_ids.insert(chain.session_id.clone()) {
                return Err(BundleError::DuplicateSession(chain.session_id));
            }
            sessions.push(chain);
        }

        let (seal, seal_bytes) = match &manifest.seal {
            None => (None, None),
            Some(rel) => {
                let path = safe_join(root, rel)?;
                let bytes = read_capped(&path, limits.seal_bytes, "seal file")?;
                let seal = Seal::from_slice(&bytes).map_err(BundleError::Seal)?;
                (Some(seal), Some(bytes))
            }
        };

        let seal_signature = match &manifest.seal_signature {
            None => None,
            Some(rel) => {
                if seal.is_none() {
                    return Err(BundleError::SealSignatureWithoutSeal(rel.clone()));
                }
                let path = safe_join(root, rel)?;
                let bytes = read_capped(&path, limits.seal_sig_bytes, "seal signature file")?;
                let text = String::from_utf8(bytes).map_err(|_| {
                    BundleError::SealSignature(MinisignError::Malformed("file is not UTF-8 text".to_owned()))
                })?;
                Some(MinisignSignature::from_text(&text).map_err(BundleError::SealSignature)?)
            }
        };

        // Carried artifact bodies: read the raw bytes verbatim. Structural
        // strictness only (hex label, no duplicates, no unreferenced body);
        // whether a body actually hashes to its label is verify()'s call —
        // a mislabelled body is graded FAILED, not "unreadable".
        let artifacts = match &manifest.artifacts {
            None => None,
            Some(list) => {
                let mut store = ArtifactStore::new();
                let mut artifact_bytes_total = 0u64;
                for ma in list {
                    if !is_hex_digest_64(&ma.artifact_hash) {
                        return Err(BundleError::MalformedArtifactHash(ma.artifact_hash.clone()));
                    }
                    let path = safe_join(root, &ma.path)?;
                    let bytes = read_capped(&path, limits.artifact_body_bytes, "artifact body")?;
                    artifact_bytes_total = artifact_bytes_total.saturating_add(bytes.len() as u64);
                    if artifact_bytes_total > limits.artifact_bytes_total {
                        return Err(BundleError::TooLarge {
                            path: root.to_owned(),
                            what: "artifact bodies in total",
                            max: limits.artifact_bytes_total,
                        });
                    }
                    if store.insert(ma.artifact_hash.clone(), bytes).is_some() {
                        return Err(BundleError::DuplicateArtifact(ma.artifact_hash.clone()));
                    }
                }
                // Index the entries' hashes once, then look each body up.
                //
                // This was a nested scan: for every carried body, walk every
                // entry of every session. O(bodies x entries), and measurably
                // so — 1,000 bodies took 0.01 s, 16,000 took 0.92 s, and
                // 32,000 took 7.52 s, roughly 8x per doubling. The same 32,000
                // entries with no artifacts section took 0.12 s, so the nested
                // scan was ~60x the rest of the read. Extrapolated, a manifest
                // of a few tens of MB with 1-byte bodies buys an hour of CPU.
                //
                // A size ceiling does not fix an algorithm: `Limits` allows
                // 200,000 bodies, which under the old scan would have run for
                // hours while staying comfortably inside every limit. Hence
                // the index rather than a tighter cap.
                let referenced: BTreeSet<&str> = sessions
                    .iter()
                    .flat_map(|c| c.entries.iter().map(|e| e.fields.artifact_hash.as_str()))
                    .collect();
                for hash in store.keys() {
                    if !referenced.contains(hash.as_str()) {
                        return Err(BundleError::UnreferencedArtifact(hash.clone()));
                    }
                }
                Some(store)
            }
        };

        Ok(Bundle {
            root: root.to_owned(),
            manifest,
            keyring,
            sessions,
            seal,
            seal_bytes,
            seal_signature,
            artifacts,
        })
    }

    /// Verify every session and grade the seal, with no seal public key:
    /// the seal's minisign signature stays UNVERIFIABLE.
    pub fn verify(&self) -> BundleReport {
        self.verify_with_seal_key(None)
    }

    /// Like [`Bundle::verify`], with an OUT-OF-BAND seal public key.
    ///
    /// The key in `check` is the only key the seal signature is ever graded
    /// under. The seal's own `seal_public_key` field is never read — a
    /// bundle naming its own trust root would be vouching for itself — and
    /// the report's detail line says so. `check.signature`, when given,
    /// overrides any signature carried in the bundle (for bundles exported
    /// before the signature travelled in-band).
    pub fn verify_with_seal_key(&self, check: Option<&SealKeyCheck<'_>>) -> BundleReport {
        self.verify_with(check, &[])
    }

    /// Like [`Bundle::verify_with_seal_key`], with examiner-supplied
    /// producer PUBLIC keys (`--producer-key`, out of band — a bundle never
    /// carries a producer key, only each camera record's `producer_key_id`).
    /// Empty means none were supplied: every session's producer signature is
    /// UNVERIFIABLE and producer trust UNESTABLISHED, stated per session.
    pub fn verify_with(&self, check: Option<&SealKeyCheck<'_>>, producer_keys: &[PublicKey]) -> BundleReport {
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for chain in &self.sessions {
            let report = verify_session(chain, &self.keyring);
            let seal_head_match = match (&self.seal, &chain.head) {
                (None, _) => None,
                (Some(_), None) => Some(Status::unverifiable("no head to anchor")),
                (Some(seal), Some(head)) => {
                    // Only anchor a head the walk has verified as committing
                    // to the entries; otherwise the anchor would be
                    // anchoring a claim, not a verified fact.
                    let head_ok = report.status(crate::verify::property::HEAD_COMMITMENT) == Some(&Status::Verified);
                    if head_ok {
                        Some(seal.anchor(
                            &chain.session_id,
                            head.fields.last_sequence,
                            &head.fields.last_entry_hash,
                        ))
                    } else {
                        Some(Status::unverifiable("head commitment did not verify; not anchoring"))
                    }
                }
            };
            let (artifact_binding, artifact_coverage) = match &self.artifacts {
                None => (None, None),
                Some(store) => {
                    let (status, coverage) = grade_artifact_binding(chain, store);
                    (Some(status), Some(coverage))
                }
            };
            let capture_completeness = grade_capture_completeness(chain, self.artifacts.as_ref());
            let producer = grade_producer_signatures(chain, self.artifacts.as_ref(), producer_keys);
            sessions.push(SessionOutcome {
                report,
                seal_head_match,
                artifact_binding,
                artifact_coverage,
                producer,
                capture_completeness,
            });
        }

        let seal = self.seal.as_ref().map(|s| {
            let (signature, signature_detail) = self.grade_seal_signature(check);
            SealOutcome {
                seal_version: s.seal_version.clone(),
                created_at: s.created_at.clone(),
                sealed_by: s.sealed_by.clone(),
                session_count: s.sessions.len(),
                consistency: s.consistency(),
                signature,
                signature_detail,
                residual_disclosure: s.residual_disclosure.clone(),
            }
        });

        let verdict = overall_verdict(&sessions, seal.as_ref());
        let boundary = boundary_report(self, &sessions);
        BundleReport {
            docket_report_version: REPORT_VERSION.to_owned(),
            bundle_version: self.manifest.docket_bundle_version.clone(),
            chain_format: self.manifest.chain_format.clone(),
            key_ids: self.keyring.key_ids().map(str::to_owned).collect(),
            pinned_key_ids: self.keyring.pinned_key_ids().map(str::to_owned).collect(),
            bundle_key_ids: self.keyring.bundle_key_ids().map(str::to_owned).collect(),
            producer_key_ids: producer_keys.iter().map(|k| k.key_id().to_owned()).collect(),
            sessions,
            seal,
            boundary,
            verdict,
        }
    }

    /// Grade the seal's minisign signature. Only called with a seal present.
    ///
    /// Deliberately separate from `seal_head_match`: that property says the
    /// bundle agrees with the seal file beside it; this one says whether the
    /// seal file itself is signed by the key the OPERATOR supplied. Two
    /// facts, two lines (split on 2026-08-26; do not collapse them).
    fn grade_seal_signature(&self, check: Option<&SealKeyCheck<'_>>) -> (Status, String) {
        let Some(check) = check else {
            return (
                Status::unverifiable(
                    "minisign signature not checked: no seal public key was supplied \
                     (--seal-key; the key must arrive out of band, never from inside the bundle)",
                ),
                String::new(),
            );
        };
        // The out-of-band signature, when given, wins over the carried one.
        let (sig, source) = match (check.signature, &self.seal_signature) {
            (Some(s), _) => (s, "signature supplied out of band"),
            (None, Some(s)) => (s, "signature carried in the bundle"),
            (None, None) => {
                return (
                    Status::unverifiable(
                        "seal public key supplied, but there is no signature to check: \
                         the bundle carries none and no --seal-sig was given",
                    ),
                    String::new(),
                )
            }
        };
        // The embedded-claim note is unconditional: the seal document always
        // names a seal_public_key, and the reader must be told it played no
        // part in this grade.
        let detail = format!(
            "{}, {} under minisign key id {}; key supplied out of band — the seal's embedded \
             seal_public_key claim is ignored",
            source,
            sig.alg_label(),
            check.key.key_id_hex()
        );
        let bytes = self.seal_bytes.as_deref().unwrap_or_default();
        match sig.verify(check.key, bytes) {
            Ok(()) => (Status::Verified, detail),
            Err(e @ MinisignError::KeyIdMismatch { .. }) => {
                // Not graded as tampering: under a different key than the
                // signature names, nothing was checked — saying FAILED would
                // accuse the evidence when the likely error is the operator's
                // key choice.
                (
                    Status::unverifiable(format!("{e}; nothing was checked under the supplied key")),
                    detail,
                )
            }
            Err(e) => (Status::failed(e.to_string()), detail),
        }
    }
}

/// The out-of-band material for checking the seal's minisign signature.
///
/// The KEY is required and never comes from the bundle. The SIGNATURE is
/// optional: when absent, the bundle-carried signature (if any) is graded.
#[derive(Debug, Clone, Copy)]
pub struct SealKeyCheck<'a> {
    pub key: &'a MinisignPublicKey,
    pub signature: Option<&'a MinisignSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    #[serde(flatten)]
    pub report: SessionReport,
    /// Whether the seal's row for this session names the same head the
    /// chain walk verified. The name says what was checked, not what it
    /// proves: the seal itself is unauthenticated here (see
    /// [`SealOutcome::signature`]), so a VERIFIED head match means the
    /// bundle agrees with the seal file beside it, not that the seal is
    /// genuine. Present only when the bundle carries a seal.
    #[serde(default, rename = "seal_head_match", skip_serializing_if = "Option::is_none")]
    pub seal_head_match: Option<Status>,
    /// Present only when the bundle carries artifact bodies: whether every
    /// carried body hashes to the `artifact_hash` its entries commit to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<Status>,
    /// Present alongside `artifact_binding`: per-entry body coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_coverage: Option<ArtifactCoverage>,
    /// Producer-signature result: did the CAPTURE HOST's own key sign the
    /// carried camera records? A third distinct result beside chain-signature
    /// validity and signer trust — the O-Node chain key must never stand in
    /// for the producer key. Validity and trust are separate axes here too.
    /// Always graded; a session whose evidence cannot carry the answer says
    /// so.
    pub producer: ProducerSignerReport,
    /// Capture completeness: was the camera recording across this session's
    /// whole window, by the capture policy carried inside the chain-signed
    /// camera record? A separate
    /// axis from every cryptographic property above — it never feeds the
    /// verdict, and the verdict never implies it (chain contiguity proves no
    /// missing sequence number, not no missing time). Always graded; a
    /// session whose evidence cannot carry the answer says UNVERIFIABLE and
    /// why.
    pub capture_completeness: CaptureReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealOutcome {
    pub seal_version: String,
    pub created_at: String,
    pub sealed_by: String,
    pub session_count: usize,
    /// Merkle root recomputed from the listed sessions.
    pub consistency: Status,
    /// The seal's minisign signature. UNVERIFIABLE unless a seal public key
    /// was supplied out of band ([`SealKeyCheck`]); then VERIFIED or FAILED.
    /// A distinct fact from every session's `seal_head_match`, deliberately.
    pub signature: Status,
    /// Where the graded signature came from and which key checked it —
    /// including that the seal's embedded key claim was ignored. Empty when
    /// nothing was graded.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_detail: String,
    pub residual_disclosure: String,
}

/// Boundary results: questions about this verifier's own limits, answered
/// from the evidence rather than stated as copy. Each is a question with a
/// computed answer, NOT a new verdict tier — the five-status property
/// vocabulary and the five verdicts are unchanged. A report without this
/// object comes from a verifier that does not implement these checks (NOT
/// GRADED) — a different statement from UNVERIFIABLE, which means the check
/// ran here and the evidence lacks what it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryReport {
    /// Does anything independently trusted establish WHICH PHYSICAL DEVICE
    /// produced these bytes? The signatures prove the producer key committed
    /// to them; the bodies claim a camera_id; neither is a device
    /// credential. Always NO from this verifier version — stated per bundle
    /// with the claimed identity named, so the answer changes when the
    /// evidence changes rather than when the copy is edited.
    pub source_device_established: SourceDeviceReport,
    /// The weakest per-session capture-completeness grade, with the
    /// per-session grades restated. See [`CaptureReport`] on each session
    /// for the outage/overlap detail.
    pub capture_completeness: CaptureSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDeviceReport {
    pub answer: SourceDeviceAnswer,
    pub detail: String,
}

/// The only answer this verifier version can give is NO: it implements no
/// device-credential check, and the evidence format carries no independently
/// trusted device credential to check. The enum exists so a future YES is a
/// new value, never a reworded string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDeviceAnswer {
    No,
}

impl SourceDeviceAnswer {
    pub fn label(self) -> &'static str {
        match self {
            SourceDeviceAnswer::No => "NO",
        }
    }
}

/// Bundle-level capture-completeness roll-up: the weakest session grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSummary {
    #[serde(flatten)]
    pub grade: CaptureGrade,
    pub detail: String,
}

fn boundary_report(bundle: &Bundle, sessions: &[SessionOutcome]) -> BoundaryReport {
    let mut camera_ids: Vec<String> = Vec::new();
    for chain in &bundle.sessions {
        for id in claimed_camera_ids(chain, bundle.artifacts.as_ref()) {
            if !camera_ids.contains(&id) {
                camera_ids.push(id);
            }
        }
    }
    let source_detail = if camera_ids.is_empty() {
        "no independently trusted device credential establishes a source device, and the carried \
         evidence names no claimed source (no camera_segment records); the signatures prove what \
         the signing key committed to, not which physical device produced it"
            .to_owned()
    } else {
        format!(
            "the camera records identify the source as {}; no independently trusted device \
             credential establishes that identity — the signatures prove what the signing keys \
             committed to, not that the bytes originated at that physical camera",
            camera_ids
                .iter()
                .map(|id| format!("{id:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    // Weakest link across sessions, same discipline as the verdict roll-up.
    // UNVERIFIABLE outranks the interruption grades: a bundle where part of
    // the evidence cannot be graded must not summarize as graded-clean.
    let worst = CaptureGrade::worst(sessions.iter().map(|s| &s.capture_completeness.grade))
        .cloned()
        .unwrap_or(CaptureGrade::Unverifiable {
            reason: "the bundle contains no sessions".to_owned(),
        });
    let per_session = sessions
        .iter()
        .map(|s| format!("{}: {}", s.report.session_id, s.capture_completeness.grade.label()))
        .collect::<Vec<_>>()
        .join("; ");
    BoundaryReport {
        source_device_established: SourceDeviceReport {
            answer: SourceDeviceAnswer::No,
            detail: source_detail,
        },
        capture_completeness: CaptureSummary {
            grade: worst,
            detail: per_session,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    /// Report schema version ([`REPORT_VERSION`]). Absent from reports
    /// produced before `docket-report/0.2`.
    #[serde(default)]
    pub docket_report_version: String,
    pub bundle_version: String,
    pub chain_format: String,
    /// Every key the verifier could use, whatever its provenance — the union
    /// of the two lists below (kept for consumers of the 0.1 report).
    pub key_ids: Vec<String>,
    /// Keys the examiner supplied out of band (`--pin`). Only these can make
    /// signer trust PINNED.
    #[serde(default)]
    pub pinned_key_ids: Vec<String>,
    /// Keys carried inside the bundle's own `keys.json`. These prove
    /// internal consistency only, never an examiner-selected trust anchor.
    #[serde(default)]
    pub bundle_key_ids: Vec<String>,
    /// Producer PUBLIC keys the examiner supplied out of band
    /// (`--producer-key`). Empty when none were supplied — the bundle itself
    /// never carries a producer key, only each record's `producer_key_id`.
    #[serde(default)]
    pub producer_key_ids: Vec<String>,
    pub sessions: Vec<SessionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealOutcome>,
    /// Boundary results, computed on every report ([`BoundaryReport`]).
    pub boundary: BoundaryReport,
    /// The weakest session verdict; Failed if anything failed. `boundary`
    /// is deliberately not an input — those axes report beside the verdict,
    /// never inside it (see the roll-up note on [`overall_verdict`]).
    pub verdict: Verdict,
}

impl BundleReport {
    /// The top-line verdict as every surface renders it.
    ///
    /// When a boundary result is FAILED, that fact rides in the line
    /// itself, so the top line cannot be quoted in isolation while a result
    /// literally named FAILED stands further down the page. The verdict,
    /// its JSON value and the exit code are untouched — the axes stay
    /// separate (a capture defect does not weaken the proof of the records
    /// that exist) — but a defensible classification is not a license for a
    /// top line that misleads a reader who stops there.
    pub fn verdict_line(&self) -> String {
        let v = self.verdict.label();
        match &self.boundary.capture_completeness.grade {
            CaptureGrade::Failed { .. } => {
                format!("{v} — boundary result capture_completeness FAILED (beside this verdict, not inside it)")
            }
            _ => v.to_owned(),
        }
    }
}

/// Weakest-link: any failure (including a failed seal head match, a failed
/// artifact binding, an inconsistent seal or a failed seal signature) is
/// FAILED; otherwise the least-authenticated session verdict. An empty
/// bundle has nothing verified and is FAILED. A VERIFIED seal signature
/// upgrades nothing: it authenticates the seal, not the sessions.
///
/// Capture completeness is deliberately NOT an input, in either direction —
/// including its FAILED grade. The verdict vocabulary speaks to the
/// cryptographic verification of the records that exist; completeness
/// speaks to the time they cover. An unexplained outage does not weaken the
/// proof of the records around it, and a verified signature chain must
/// never read as "the camera kept recording". Folding one axis into the
/// other, in any direction, is exactly the collapse this vocabulary exists
/// to prevent; the exit code follows the verdict, unchanged.
fn overall_verdict(sessions: &[SessionOutcome], seal: Option<&SealOutcome>) -> Verdict {
    if sessions.is_empty() {
        return Verdict::Failed;
    }
    let seal_failed = seal.is_some_and(|s| s.consistency.is_failed() || s.signature.is_failed());
    let any_failed = sessions.iter().any(|s| {
        s.report.verdict == Verdict::Failed
            || s.seal_head_match.as_ref().is_some_and(Status::is_failed)
            || s.artifact_binding.as_ref().is_some_and(Status::is_failed)
    });
    if any_failed || seal_failed {
        return Verdict::Failed;
    }
    let rank = |v: Verdict| match v {
        Verdict::Failed => 0,
        Verdict::ConsistentUnauthenticated => 1,
        Verdict::OperatorAttestedUnverifiable => 2,
        // Above OPERATOR-ATTESTED: real cryptography was checked and held
        // (one keyholder produced everything; tamper-evident against anyone
        // without the private key). Below CRYPTOGRAPHICALLY-VERIFIED: that
        // keyholder could be anyone.
        Verdict::CryptographicallyConsistent => 3,
        Verdict::CryptographicallyVerified => 4,
    };
    sessions
        .iter()
        .map(|s| s.report.verdict)
        .min_by_key(|v| rank(*v))
        .unwrap_or(Verdict::Failed)
}
