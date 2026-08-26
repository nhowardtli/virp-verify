//! The minimal Docket evidence bundle: a directory.
//!
//! ```text
//! <bundle>/
//!   manifest.json            required — see [`Manifest`]
//!   keys.json                optional — key_id → public key (see [`KeyFile`])
//!   sessions/<name>.json     one [`SessionChain`] per session, paths named in the manifest
//!   seal/<name>.json         optional D-0 seal anchor, path named in the manifest
//!   artifacts/<hash>         optional raw artifact bodies, paths named in the manifest
//! ```
//!
//! Every path in the manifest is relative to the bundle root and may not
//! escape it. The reader is strict: unknown manifest versions, missing
//! files, a key whose bytes do not derive its claimed `key_id`, or a session
//! file whose `session_id` disagrees with the manifest are all hard errors —
//! a bundle that cannot be read is never reported as anything but unreadable.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash::is_hex_digest_64;
use crate::limits::Limits;
use crate::seal::Seal;
use crate::sig::PublicKey;
use crate::verify::{
    grade_artifact_binding, verify_session, ArtifactCoverage, ArtifactStore, Keyring, SessionChain, SessionReport,
    Status, Verdict,
};

pub const BUNDLE_VERSION: &str = "docket-bundle/0.1";
pub const CHAIN_FORMAT: &str = "v1";

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
                    "keys.json claims key_id {claimed} but the key bytes derive {derived}"
                )
            }
            Self::UnsupportedKeyAlgorithm(a) => write!(f, "unsupported key algorithm {a:?} (want ed25519)"),
            Self::InvalidKey(k) => write!(f, "public key {k} is not a valid Ed25519 key"),
            Self::SessionIdMismatch { manifest, file } => {
                write!(f, "manifest names session {manifest:?} but the file says {file:?}")
            }
            Self::Seal(e) => write!(f, "seal: {e}"),
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

/// Check the string fields that go into an entry's canonical bytes, before
/// those bytes are built.
///
/// The digest fields are absent on purpose: `entry_hashes` separately
/// requires them to be 64 lowercase hex characters, a tighter bound than any
/// ceiling here would be.
fn check_entry_field_lengths(chain: &SessionChain, limits: &Limits) -> Result<(), BundleError> {
    let too_long = |sequence: i64, field: &'static str, len: usize, max: usize| BundleError::FieldTooLong {
        session_id: chain.session_id.clone(),
        sequence,
        field,
        len,
        max,
    };
    if chain.session_id.len() > limits.session_id_bytes {
        return Err(too_long(
            -1,
            "session_id",
            chain.session_id.len(),
            limits.session_id_bytes,
        ));
    }
    for e in &chain.entries {
        let f = &e.fields;
        for (field, len, max) in [
            ("session_id", f.session_id.len(), limits.session_id_bytes),
            ("artifact_id", f.artifact_id.len(), limits.artifact_id_bytes),
            ("artifact_type", f.artifact_type.len(), limits.artifact_type_bytes),
            (
                "artifact_hash_alg",
                f.artifact_hash_alg.len(),
                limits.artifact_hash_alg_bytes,
            ),
            (
                "artifact_schema_version",
                f.artifact_schema_version.len(),
                limits.artifact_schema_version_bytes,
            ),
            ("signer_org_id", f.signer_org_id.len(), limits.signer_org_id_bytes),
        ] {
            if len > max {
                return Err(too_long(f.sequence, field, len, max));
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
            let kf: KeyFile = read_json(&safe_join(root, rel)?, limits.keys_bytes, "keys.json")?;
            for k in kf.keys {
                if k.algorithm != "ed25519" {
                    return Err(BundleError::UnsupportedKeyAlgorithm(k.algorithm));
                }
                let pk = PublicKey::from_hex(&k.public_key_hex)
                    .map_err(|_| BundleError::InvalidKey(k.public_key_hex.clone()))?;
                if pk.key_id() != k.key_id {
                    return Err(BundleError::KeyIdMismatch {
                        claimed: k.key_id,
                        derived: pk.key_id().to_owned(),
                    });
                }
                keyring.insert(pk);
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
            if chain.entries.len() > limits.entries_per_session {
                return Err(BundleError::TooMany {
                    what: "entries in one session",
                    max: limits.entries_per_session,
                });
            }
            entries_total = entries_total.saturating_add(chain.entries.len());
            if entries_total > limits.entries_total {
                return Err(BundleError::TooMany {
                    what: "entries across the bundle",
                    max: limits.entries_total,
                });
            }
            check_entry_field_lengths(&chain, limits)?;
            // Third axis: identity as the FILE states it. Redundant with the
            // manifest check only while the manifest/file agreement check
            // above holds; asserted separately so that neither check silently
            // becomes the only one.
            if !loaded_ids.insert(chain.session_id.clone()) {
                return Err(BundleError::DuplicateSession(chain.session_id));
            }
            sessions.push(chain);
        }

        let seal = match &manifest.seal {
            None => None,
            Some(rel) => {
                let path = safe_join(root, rel)?;
                let bytes = read_capped(&path, limits.seal_bytes, "seal file")?;
                Some(Seal::from_slice(&bytes).map_err(BundleError::Seal)?)
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
                for hash in store.keys() {
                    let referenced = sessions
                        .iter()
                        .any(|c| c.entries.iter().any(|e| &e.fields.artifact_hash == hash));
                    if !referenced {
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
            artifacts,
        })
    }

    /// Verify every session and grade the seal.
    pub fn verify(&self) -> BundleReport {
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for chain in &self.sessions {
            let report = verify_session(chain, &self.keyring);
            let seal_anchor = match (&self.seal, &chain.head) {
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
            sessions.push(SessionOutcome {
                report,
                seal_anchor,
                artifact_binding,
                artifact_coverage,
            });
        }

        let seal = self.seal.as_ref().map(|s| SealOutcome {
            seal_version: s.seal_version.clone(),
            created_at: s.created_at.clone(),
            sealed_by: s.sealed_by.clone(),
            session_count: s.sessions.len(),
            consistency: s.consistency(),
            signature: Status::unverifiable("minisign signature not checked by this verifier (not implemented)"),
            residual_disclosure: s.residual_disclosure.clone(),
        });

        let verdict = overall_verdict(&sessions, seal.as_ref());
        BundleReport {
            bundle_version: self.manifest.docket_bundle_version.clone(),
            chain_format: self.manifest.chain_format.clone(),
            key_ids: self.keyring.key_ids().map(str::to_owned).collect(),
            sessions,
            seal,
            verdict,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    #[serde(flatten)]
    pub report: SessionReport,
    /// Present only when the bundle carries a seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_anchor: Option<Status>,
    /// Present only when the bundle carries artifact bodies: whether every
    /// carried body hashes to the `artifact_hash` its entries commit to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_binding: Option<Status>,
    /// Present alongside `artifact_binding`: per-entry body coverage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_coverage: Option<ArtifactCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealOutcome {
    pub seal_version: String,
    pub created_at: String,
    pub sealed_by: String,
    pub session_count: usize,
    /// Merkle root recomputed from the listed sessions.
    pub consistency: Status,
    /// The seal's own signature — not checked by Docket today.
    pub signature: Status,
    pub residual_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    pub bundle_version: String,
    pub chain_format: String,
    pub key_ids: Vec<String>,
    pub sessions: Vec<SessionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealOutcome>,
    /// The weakest session verdict; Failed if anything failed.
    pub verdict: Verdict,
}

/// Weakest-link: any failure (including a failed seal anchor, a failed
/// artifact binding or an inconsistent seal) is FAILED; otherwise the
/// least-authenticated session verdict. An empty bundle has nothing
/// verified and is FAILED.
fn overall_verdict(sessions: &[SessionOutcome], seal: Option<&SealOutcome>) -> Verdict {
    if sessions.is_empty() {
        return Verdict::Failed;
    }
    let seal_failed = seal.is_some_and(|s| s.consistency.is_failed());
    let any_failed = sessions.iter().any(|s| {
        s.report.verdict == Verdict::Failed
            || s.seal_anchor.as_ref().is_some_and(Status::is_failed)
            || s.artifact_binding.as_ref().is_some_and(Status::is_failed)
    });
    if any_failed || seal_failed {
        return Verdict::Failed;
    }
    let rank = |v: Verdict| match v {
        Verdict::Failed => 0,
        Verdict::ConsistentUnauthenticated => 1,
        Verdict::OperatorAttestedUnverifiable => 2,
        Verdict::CryptographicallyVerified => 3,
    };
    sessions
        .iter()
        .map(|s| s.report.verdict)
        .min_by_key(|v| rank(*v))
        .unwrap_or(Verdict::Failed)
}
