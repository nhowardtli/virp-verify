//! The verifier: walks one session's chain and grades each property.
//!
//! Three tiers, each independent (SECURITY.md "Three verification tiers"):
//!
//! | tier | Docket needs | what it proves |
//! | --- | --- | --- |
//! | keyless | nothing | hash + genesis + prev-link + contiguity + head commitment. The head's length claim is **unauthenticated**. |
//! | symmetric (note only) | `K_chain` — which Docket **never holds** | Docket cannot check `chain_hmac`/`head_hmac`. FULL presence is reported as *operator-attested, unverifiable by this verifier*; never a pass. PARTIAL presence is FAILED — see the symmetric-tier block in [`verify_session`]. |
//! | asymmetric | the signer's PUBLIC key | Ed25519 over the head and every entry, under the session-granularity key rule. |
//!
//! The asymmetric tier reports along TWO axes, never merged: signature
//! validity (did the cryptography hold) and signer trust (did the signatures
//! verify under an examiner-pinned key — [`SignerTrust`]). A key carried
//! inside the bundle being examined can prove internal consistency only;
//! PINNED requires a key the examiner supplied out of band
//! ([`Keyring::insert_pinned`]).
//!
//! The vocabulary is deliberately incapable of collapsing these into one
//! green checkmark: see [`Status`], [`SignerTrust`] and [`Verdict`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::canonical::{genesis_hash_hex, EntryFields, HeadFields};
use crate::hash::is_hex_digest_64;
use crate::sig::{check_session_key_binding, PublicKey, SessionKeyBinding, SigDomain, SCHEME};

// ---------------------------------------------------------------------------
// Input types — what a bundle hands the verifier for one session
// ---------------------------------------------------------------------------

/// A detached signature as stored alongside an entry or head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    /// Must be `ed25519-detached-v1`.
    pub signature_scheme: String,
    /// `sha256-raw-16` key id of the signing key, 32 lowercase hex chars.
    pub signing_key_id: String,
    /// 128 hex chars.
    pub signature_hex: String,
}

/// One chain entry as carried in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry {
    #[serde(flatten)]
    pub fields: EntryFields,
    /// The producer's stored hash (what we recompute and compare against).
    pub chain_entry_hash: String,
    /// Optional verbatim copy of the canonical bytes (the exact signed
    /// input). When present it MUST equal the bytes rebuilt from `fields`;
    /// a mismatch is a failure. Lets a bundle carry the signed bytes
    /// themselves, not only their preimage fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_utf8: Option<String>,
    /// HMAC-SHA256 under `K_chain`. Docket cannot verify this; it is carried
    /// so the operator-attested tier can be *reported*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hmac: Option<String>,
    /// D-1 detached signature, if the session is signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<DetachedSignature>,
}

/// The per-session head record as carried in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    #[serde(flatten)]
    pub fields: HeadFields,
    /// Optional verbatim copy of the head canonical bytes; must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_utf8: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_hmac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<DetachedSignature>,
}

/// One session's chain: entries in sequence order plus the head record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionChain {
    pub session_id: String,
    pub entries: Vec<ChainEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<ChainHead>,
}

/// Where a public key came from. This is the axis signer trust rests on:
/// only a key the examiner supplied out of band earns PINNED; a key that
/// travelled inside the bundle being examined cannot, because anyone can
/// generate a keypair, sign fabricated evidence, and ship the public half
/// alongside. Pinning proves the signatures verify under the key the
/// examiner selected — where the examiner got that key, and whether it
/// belongs to who they think, is outside this tool entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustSource {
    /// Supplied by the examiner out of band (`--pin` / `--keys`).
    ExaminerTrustStore,
    /// Carried in the bundle's own `keys.json`.
    BundleProvidedKey,
}

impl TrustSource {
    pub fn label(self) -> &'static str {
        match self {
            TrustSource::ExaminerTrustStore => "examiner trust store",
            TrustSource::BundleProvidedKey => "bundle-provided key",
        }
    }
}

/// Public keys the verifier may use, addressed by `key_id`, each tagged with
/// its [`TrustSource`]. There is no untagged insert: every call site must
/// state whether a key arrived out of band or from inside the evidence.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    keys: BTreeMap<String, (PublicKey, TrustSource)>,
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring::default()
    }

    /// Add a key the EXAMINER supplied out of band. Its `key_id` is DERIVED
    /// from the key bytes, never taken on trust from a label — a file that
    /// labels a key with the wrong id simply won't find it.
    pub fn insert_pinned(&mut self, key: PublicKey) {
        self.keys
            .insert(key.key_id().to_owned(), (key, TrustSource::ExaminerTrustStore));
    }

    /// Add a key carried inside the bundle. A pinned key never loses its
    /// provenance to a bundle copy of itself: same id means same bytes
    /// (`key_id` is derived), so the examiner-supplied entry stands.
    pub fn insert_bundle(&mut self, key: PublicKey) {
        self.keys
            .entry(key.key_id().to_owned())
            .or_insert((key, TrustSource::BundleProvidedKey));
    }

    pub fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.keys.get(key_id).map(|(k, _)| k)
    }

    /// Where the key under `key_id` came from, if it is present.
    pub fn source(&self, key_id: &str) -> Option<TrustSource> {
        self.keys.get(key_id).map(|(_, s)| *s)
    }

    /// Whether the examiner supplied ANY key out of band. When they did, a
    /// session signed under a key outside that set is a [`SignerTrust::Mismatch`],
    /// not merely unestablished.
    pub fn has_pinned(&self) -> bool {
        self.keys.values().any(|(_, s)| *s == TrustSource::ExaminerTrustStore)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }

    /// Ids of keys the examiner supplied out of band.
    pub fn pinned_key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys
            .iter()
            .filter(|(_, (_, s))| *s == TrustSource::ExaminerTrustStore)
            .map(|(id, _)| id.as_str())
    }

    /// Ids of keys carried inside the bundle.
    pub fn bundle_key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys
            .iter()
            .filter(|(_, (_, s))| *s == TrustSource::BundleProvidedKey)
            .map(|(id, _)| id.as_str())
    }
}

// ---------------------------------------------------------------------------
// Output types — the report
// ---------------------------------------------------------------------------

/// The status of one verified property. Exactly one of these is ever
/// attached to a property, and only [`Status::Verified`] means "this
/// verifier proved it".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Status {
    /// Cryptographically verified by this verifier from public inputs.
    Verified,
    /// Present in the evidence, but rests on a secret this verifier does not
    /// hold (the operator's `K_chain`). The operator attests; Docket cannot
    /// check. This is NOT a pass.
    OperatorAttested,
    /// Could not be checked here for a stated reason (e.g. signed under a
    /// key the verifier was not given). Soft: the other tiers still apply.
    Unverifiable { reason: String },
    /// The property is not present in the evidence (e.g. an unsigned
    /// pre-D-1 session has no signatures). Neutral.
    Absent,
    /// Checked and wrong: the evidence is inconsistent with the property.
    /// Consistent with tampering, corruption or an operational change; this
    /// verifier does not determine which, and the detail must not claim to.
    ///
    /// Serialized as `failure`, not `detail`: `PropertyReport` flattens this
    /// enum next to its own generic `detail` field, and two `detail` keys in
    /// one JSON object made parsers silently drop the failure text.
    Failed {
        #[serde(rename = "failure")]
        detail: String,
    },
}

impl Status {
    pub fn failed(detail: impl Into<String>) -> Status {
        Status::Failed { detail: detail.into() }
    }

    pub fn unverifiable(reason: impl Into<String>) -> Status {
        Status::Unverifiable { reason: reason.into() }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Status::Failed { .. })
    }

    /// Short upper-case label for reports.
    pub fn label(&self) -> &'static str {
        match self {
            Status::Verified => "VERIFIED",
            Status::OperatorAttested => "OPERATOR-ATTESTED (unverifiable here)",
            Status::Unverifiable { .. } => "UNVERIFIABLE",
            Status::Absent => "ABSENT",
            Status::Failed { .. } => "FAILED",
        }
    }
}

/// Names of the properties a session report always contains, in order.
pub mod property {
    pub const ENTRY_HASHES: &str = "entry_hashes";
    pub const GENESIS: &str = "genesis";
    pub const LINKS: &str = "links";
    pub const CONTIGUITY: &str = "contiguity";
    pub const HEAD_COMMITMENT: &str = "head_commitment";
    pub const ENTRY_HMACS: &str = "entry_hmacs";
    pub const HEAD_HMAC: &str = "head_hmac";
    pub const HEAD_SIGNATURE: &str = "head_signature";
    pub const SESSION_KEY_BINDING: &str = "session_key_binding";
    pub const ENTRY_SIGNATURES: &str = "entry_signatures";
    pub const ALL: [&str; 10] = [
        ENTRY_HASHES,
        CONTIGUITY,
        GENESIS,
        LINKS,
        HEAD_COMMITMENT,
        ENTRY_HMACS,
        HEAD_HMAC,
        HEAD_SIGNATURE,
        SESSION_KEY_BINDING,
        ENTRY_SIGNATURES,
    ];
}

/// One graded property.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropertyReport {
    pub name: String,
    #[serde(flatten)]
    pub status: Status,
    /// Human-readable detail (counts, sequences, key ids).
    pub detail: String,
}

/// Signer trust: a separate axis from signature validity, deliberately.
///
/// "Ed25519 verified under the supplied public key" is true and ambiguous —
/// it reads the same whether the key came from the examiner's own trust
/// store or from inside the bundle being examined. In the second case the
/// signature proves the bundle is internally consistent and proves nothing
/// about who produced it. This enum states which case holds, next to (never
/// merged with) whether the cryptography held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerTrust {
    /// The key that verified the signatures was supplied by the examiner out
    /// of band, and every signature verifies under it.
    Pinned,
    /// The only key available (if any) came from inside the bundle, so no
    /// signer trust is established — whatever the signatures prove about
    /// consistency. Also the state of an unsigned session, which has no
    /// signature to check under any key.
    Unestablished,
    /// The examiner pinned keys out of band and this session's signatures do
    /// NOT verify under any of them: signed by someone else, or failing
    /// under the pinned key. A different and more serious statement than
    /// UNESTABLISHED — the examiner stated an expectation and the evidence
    /// does not meet it.
    Mismatch,
}

impl SignerTrust {
    pub fn label(self) -> &'static str {
        match self {
            SignerTrust::Pinned => "PINNED",
            SignerTrust::Unestablished => "UNESTABLISHED",
            SignerTrust::Mismatch => "MISMATCH",
        }
    }
}

/// The two-axis signer summary for one session: signature validity (did the
/// cryptography hold) and signer trust (did the signatures verify under an
/// examiner-pinned key). Two results, rendered separately, never collapsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerReport {
    /// Roll-up of `head_signature`, `session_key_binding` and
    /// `entry_signatures` — a summary line, not a new check: the three
    /// property rows keep their independent grades.
    pub signature_validity: Status,
    pub trust: SignerTrust,
    /// Provenance of the key the verifier used (or would use) to check this
    /// session's signatures. `None` when no key was available or the session
    /// is unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_source: Option<TrustSource>,
    /// Human-readable statement of what the trust grade rests on.
    pub detail: String,
}

/// The overall verdict for a session. Five words, never one checkmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// At least one property FAILED: the chain is cryptographically
    /// inconsistent. Why is outside what this verifier checks.
    Failed,
    /// Every keyless property holds, the head plus every entry carry a valid
    /// Ed25519 signature, AND the verifying key was supplied by the examiner
    /// out of band ([`SignerTrust::Pinned`]). This verifier proved
    /// authenticity without any secret.
    CryptographicallyVerified,
    /// Every keyless property holds and every signature verifies — but only
    /// under a key that did not come from the examiner (bundle-provided, or
    /// outside the examiner's pins). The cryptography held without an
    /// examiner-selected trust anchor: anyone can generate a keypair, sign
    /// fabricated evidence with it, and ship the public half alongside.
    /// Strictly weaker than [`Verdict::CryptographicallyVerified`].
    CryptographicallyConsistent,
    /// Every keyless property holds. Authenticity of the head and entries
    /// rests ONLY on material this verifier cannot check: the operator's
    /// HMAC and/or a signature under a key it was not given. The operator
    /// attests; this verifier does not.
    OperatorAttestedUnverifiable,
    /// Every keyless property holds, but nothing — not even an operator
    /// HMAC — attests authenticity. Internally consistent; anyone could have
    /// produced it.
    ConsistentUnauthenticated,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Failed => "FAILED",
            Verdict::CryptographicallyVerified => "CRYPTOGRAPHICALLY-VERIFIED",
            Verdict::CryptographicallyConsistent => "CRYPTOGRAPHICALLY-CONSISTENT (signer trust not established)",
            Verdict::OperatorAttestedUnverifiable => "OPERATOR-ATTESTED (unverifiable by this verifier)",
            Verdict::ConsistentUnauthenticated => "CONSISTENT-UNAUTHENTICATED",
        }
    }
}

/// The full report for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReport {
    pub session_id: String,
    pub entry_count: usize,
    /// The head's signing key id, if the head is signed.
    pub signing_key_id: Option<String>,
    pub properties: Vec<PropertyReport>,
    /// The two-axis signer summary: signature validity next to signer trust.
    pub signer: SignerReport,
    pub verdict: Verdict,
}

impl SessionReport {
    pub fn property(&self, name: &str) -> Option<&PropertyReport> {
        self.properties.iter().find(|p| p.name == name)
    }

    pub fn status(&self, name: &str) -> Option<&Status> {
        self.property(name).map(|p| &p.status)
    }
}

// ---------------------------------------------------------------------------
// Artifact-body binding (graded only when a bundle carries bodies)
// ---------------------------------------------------------------------------

/// Bodies carried alongside a chain, keyed by the `artifact_hash` they claim
/// to be the preimage of. The key is a CLAIM: [`grade_artifact_binding`]
/// recomputes SHA-256 over the bytes and compares against each referencing
/// entry's stored `artifact_hash`, so a mislabelled body fails rather than
/// passes.
pub type ArtifactStore = BTreeMap<String, Vec<u8>>;

/// Per-entry coverage of carried artifact bodies for one session. Honest by
/// construction: every entry is either counted in `entries_with_body` or
/// listed in `hash_only_sequences` — a body is never implied where none is
/// carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCoverage {
    pub entry_count: usize,
    pub entries_with_body: usize,
    /// Sequences of entries with NO carried body (hash-only evidence).
    pub hash_only_sequences: Vec<i64>,
}

impl ArtifactCoverage {
    /// Human-readable coverage line for reports. The full sequence list
    /// lives in the JSON; text output elides after 16.
    pub fn detail(&self) -> String {
        let mut s = format!(
            "{}/{} entries have carried bodies (SHA-256 recomputed against artifact_hash)",
            self.entries_with_body, self.entry_count
        );
        if !self.hash_only_sequences.is_empty() {
            let shown: Vec<String> = self.hash_only_sequences.iter().take(16).map(i64::to_string).collect();
            let more = self.hash_only_sequences.len().saturating_sub(16);
            s.push_str("; hash-only sequences: ");
            s.push_str(&shown.join(", "));
            if more > 0 {
                s.push_str(&format!(" (+{more} more)"));
            }
        }
        s
    }
}

/// Grade artifact-body binding for one session against carried bodies.
///
/// Keyless tier: for every entry whose `artifact_hash` has a carried body,
/// recompute `sha256(body)` and compare. A mismatch is FAILED (the body is
/// not the one the signed entry commits to). Entries with no carried body
/// are reported hash-only — never failed, never implied present. A body
/// under an `artifact_hash_alg` other than sha256 is UNVERIFIABLE.
pub fn grade_artifact_binding(chain: &SessionChain, store: &ArtifactStore) -> (Status, ArtifactCoverage) {
    let mut hash_only_sequences = Vec::new();
    let mut entries_with_body = 0usize;
    let mut failed: Option<String> = None;
    let mut unverifiable: Option<String> = None;
    for e in &chain.entries {
        match store.get(&e.fields.artifact_hash) {
            None => hash_only_sequences.push(e.fields.sequence),
            Some(bytes) => {
                entries_with_body += 1;
                if e.fields.artifact_hash_alg != "sha256" {
                    unverifiable.get_or_insert_with(|| {
                        format!(
                            "entry at sequence {} declares artifact_hash_alg {:?}, which this verifier cannot recompute",
                            e.fields.sequence, e.fields.artifact_hash_alg
                        )
                    });
                } else if crate::hash::sha256_hex(bytes) != e.fields.artifact_hash {
                    failed.get_or_insert_with(|| {
                        format!(
                            "carried body for sequence {} does not hash to its artifact_hash",
                            e.fields.sequence
                        )
                    });
                }
            }
        }
    }
    let status = if let Some(detail) = failed {
        Status::Failed { detail }
    } else if let Some(reason) = unverifiable {
        Status::Unverifiable { reason }
    } else if entries_with_body > 0 {
        Status::Verified
    } else {
        Status::Absent
    };
    let coverage = ArtifactCoverage {
        entry_count: chain.entries.len(),
        entries_with_body,
        hash_only_sequences,
    };
    (status, coverage)
}

// ---------------------------------------------------------------------------
// Referenced-artifact binding — the bytes a record is ABOUT
// ---------------------------------------------------------------------------
//
// `artifact_binding` answers "is the carried record the record the chain
// committed to". It says nothing about the VIDEO that record was written
// about, and until this property existed nothing here did: measured
// 2026-09-04, a byte flipped in a segment mp4 and a byte flipped in a
// validation_results.txt each left this verifier's output byte-identical to
// the untampered run. The tool said as much in its own epilogue —
// "segment_sha256 is a reference this tool does not recompute".
//
// WHICH DIGESTS ARE CITED IS RE-DERIVED FROM THE CARRIED BODIES, never read
// out of the manifest. The manifest is unsigned metadata and says only where
// bytes sit; the bodies are hash-bound and producer-signed, so they are the
// only trustworthy statement of what this evidence commits to. A manifest
// listing a digest no record cites therefore proves nothing, and a manifest
// omitting one a record DOES cite cannot hide it — that citation grades
// ABSENT.
//
// ABSENT STAYS ABSENT. A cited artifact the bundle does not carry was not
// checked, and "not checked" must never share a shape with "verified" — the
// rule the sensor verdict vocabulary was closed for.

/// One referenced artifact as the bundle carries it: where the bytes sit and
/// what they actually hash to, recomputed at read time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CarriedReferenced {
    /// Relative path inside the bundle.
    pub path: String,
    /// SHA-256 recomputed over the file's bytes, compared against the digest
    /// it is filed under — which is what the record cites.
    pub sha256: String,
    pub bytes: u64,
}

/// Why a listed referenced artifact carries no bytes.
///
/// The exporter's two reasons, kept apart because they are different
/// evidence: `not_found` says the artifact was looked for and is not
/// there; `eacces` says a search directory or the file could not be read,
/// so no look happened and the absence proves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotCarried {
    NotFound,
    /// A directory or file the exporter was not permitted to read.
    Inaccessible,
    /// A reason string this verifier does not recognise. Kept verbatim
    /// rather than folded into NotFound: an unknown reason is not a known
    /// absence, and guessing which one it is would be the same collapse
    /// this enum exists to prevent.
    Other(String),
}

impl NotCarried {
    pub fn from_reason(reason: Option<&str>) -> NotCarried {
        match reason {
            None | Some("not_found") => NotCarried::NotFound,
            Some("eacces") => NotCarried::Inaccessible,
            Some(other) => NotCarried::Other(other.to_owned()),
        }
    }

    /// Whether this absence leaves the question OPEN rather than answered.
    /// An inaccessible artifact was never examined; an unrecognised reason
    /// is treated the same way, because this verifier cannot say it was.
    pub fn is_unverifiable(&self) -> bool {
        !matches!(self, NotCarried::NotFound)
    }

    pub fn label(&self) -> String {
        match self {
            NotCarried::NotFound => "not carried".to_owned(),
            NotCarried::Inaccessible => {
                "INACCESSIBLE to the exporter — a search directory or the file could not be read, \
                 so it was never looked at"
                    .to_owned()
            }
            NotCarried::Other(r) => format!("not carried, for a reason this verifier does not know ({r:?})"),
        }
    }
}

/// One referenced artifact as the bundle lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferencedEntry {
    Carried(CarriedReferenced),
    NotCarried(NotCarried),
}

/// Referenced artifacts keyed by the CITED digest they are filed under.
pub type ReferencedStore = BTreeMap<String, ReferencedEntry>;

/// One citation that did not verify, named so a reader can act on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencedDefect {
    /// Chain sequence of the entry whose body carries the citation.
    pub sequence: i64,
    /// `segment_seq` from the body — what an operator recognises.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_seq: Option<i64>,
    /// Field path inside the record that carries the digest.
    pub field: String,
    /// What the record commits to.
    pub cited: String,
    /// What the carried file actually hashes to. `None` when nothing was
    /// carried — the ABSENT case, which is not a mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recomputed: Option<String>,
}

/// Per-session coverage of the referenced artifacts. Honest by construction:
/// every citation lands in exactly one of the three counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferencedCoverage {
    /// Citations found in the carried bodies: two per `/3`-and-later camera
    /// record (segment and validator output), one per earlier one.
    pub citations: usize,
    pub verified: usize,
    pub absent: usize,
    /// Citations the exporter could not look at. NOT folded into `absent`:
    /// a blind look is not a finding.
    #[serde(default)]
    pub inaccessible: usize,
    pub failed: usize,
    /// Mismatches: a file IS carried and hashes to something else.
    pub failures: Vec<ReferencedDefect>,
    /// Citations the bundle carries no bytes for, for any reason.
    pub absences: Vec<ReferencedDefect>,
}

impl ReferencedCoverage {
    /// Human-readable coverage line for reports.
    pub fn detail(&self) -> String {
        if self.citations == 0 {
            return "no camera record in this session cites an artifact by digest".to_owned();
        }
        // Counts only. The specific mismatch rides in the FAILED status,
        // which the report renders after this line — the same split
        // artifact_binding uses, so neither is printed twice.
        let mut s = format!(
            "{}/{} cited artifact(s) recomputed against the citing field",
            self.verified, self.citations
        );
        if self.failed > 0 {
            s.push_str(&format!("; {} mismatched", self.failed));
        }
        if self.absent > 0 {
            s.push_str(&format!("; {} not carried — ABSENT, not a pass", self.absent));
        }
        if self.inaccessible > 0 {
            s.push_str(&format!(
                "; {} INACCESSIBLE to the exporter — never looked at, so not graded absent",
                self.inaccessible
            ));
        }
        s
    }
}

/// Grade whether every artifact the carried camera records cite by digest is
/// present in the bundle and hashes to what the record commits to.
///
/// `store` supplies the bodies the citations are read from; `referenced`
/// supplies what the bundle carries. Either being `None` is ABSENT: with no
/// bodies there is nothing to derive citations from, and with no
/// `referenced_artifacts` section there is nothing to check them against.
pub fn grade_referenced_artifact_binding(
    chain: &SessionChain,
    store: Option<&ArtifactStore>,
    referenced: Option<&ReferencedStore>,
) -> (Status, ReferencedCoverage) {
    let mut cov = ReferencedCoverage {
        citations: 0,
        verified: 0,
        absent: 0,
        inaccessible: 0,
        failed: 0,
        failures: Vec::new(),
        absences: Vec::new(),
    };
    let mut blocked: Option<String> = None;
    let (Some(store), Some(referenced)) = (store, referenced) else {
        return (Status::Absent, cov);
    };

    for e in &chain.entries {
        let Some(bytes) = store.get(&e.fields.artifact_hash) else {
            continue;
        };
        let Ok(body) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            continue;
        };
        let segment_seq = body.get("segment_seq").and_then(serde_json::Value::as_i64);
        for (field, cited) in crate::camera::cited_digests(&body) {
            cov.citations += 1;
            let defect = |recomputed: Option<String>| ReferencedDefect {
                sequence: e.fields.sequence,
                segment_seq,
                field: field.clone(),
                cited: cited.clone(),
                recomputed,
            };
            match referenced.get(&cited) {
                // Listed and carried: the only case that can verify.
                Some(ReferencedEntry::Carried(c)) if c.sha256 == cited => cov.verified += 1,
                Some(ReferencedEntry::Carried(c)) => {
                    cov.failed += 1;
                    cov.failures.push(defect(Some(c.sha256.clone())));
                }
                // Listed as not carried, WITH a reason. An artifact the
                // exporter could not read was never examined, so its
                // absence from the bundle says nothing about the evidence
                // and must not be graded as though it did.
                Some(ReferencedEntry::NotCarried(why)) if why.is_unverifiable() => {
                    cov.inaccessible += 1;
                    blocked.get_or_insert_with(|| {
                        format!(
                            "segment_seq {} cites {} {}, which is {}",
                            segment_seq.unwrap_or(e.fields.sequence),
                            field,
                            cited,
                            why.label()
                        )
                    });
                    cov.absences.push(defect(None));
                }
                // Not there, and demonstrably so.
                Some(ReferencedEntry::NotCarried(_)) | None => {
                    cov.absent += 1;
                    cov.absences.push(defect(None));
                }
            }
        }
    }

    let status = if cov.failed > 0 {
        // The specific mismatch only. `status_line` renders this AFTER the
        // coverage detail, so repeating the counts here would print them
        // twice — the same split artifact_binding already uses.
        let d = &cov.failures[0];
        Status::Failed {
            detail: format!(
                "segment_seq {} cites {} {}, and the carried file hashes to {}",
                d.segment_seq.unwrap_or(d.sequence),
                d.field,
                d.cited,
                d.recomputed.as_deref().unwrap_or("?")
            ),
        }
    } else if let Some(reason) = blocked {
        // UNVERIFIABLE outranks ABSENT: a bundle that could not look at
        // part of the evidence has not established that part is missing.
        Status::Unverifiable { reason }
    } else if cov.citations == 0 || cov.absent > 0 {
        Status::Absent
    } else {
        Status::Verified
    };
    (status, cov)
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Verify one session against the supplied public keys (which may be empty:
/// that is the keyless tier).
pub fn verify_session(chain: &SessionChain, keyring: &Keyring) -> SessionReport {
    let mut props: Vec<PropertyReport> = Vec::with_capacity(property::ALL.len());
    let push = |props: &mut Vec<PropertyReport>, name: &str, status: Status, detail: String| {
        props.push(PropertyReport {
            name: name.to_owned(),
            status,
            detail,
        });
    };

    let n = chain.entries.len();

    // --- keyless tier -----------------------------------------------------

    // Recompute each entry's canonical bytes once; reuse for hash and sig.
    let canonicals: Vec<Vec<u8>> = chain.entries.iter().map(|e| e.fields.canonical_bytes()).collect();
    let computed_hashes: Vec<String> = canonicals.iter().map(|c| crate::hash::sha256_hex(c)).collect();

    // entry_hashes
    {
        let mut status = Status::Verified;
        for (i, e) in chain.entries.iter().enumerate() {
            if !is_hex_digest_64(&e.chain_entry_hash) {
                status = Status::failed(format!(
                    "stored chain_entry_hash at sequence {} is not a 64-hex digest",
                    e.fields.sequence
                ));
                break;
            }
            if computed_hashes[i] != e.chain_entry_hash {
                status = Status::failed(format!("entry hash mismatch at sequence {}", e.fields.sequence));
                break;
            }
            if let Some(c) = &e.canonical_utf8 {
                if c.as_bytes() != canonicals[i].as_slice() {
                    status = Status::failed(format!(
                        "carried canonical_utf8 at sequence {} differs from the canonical rebuilt from its fields",
                        e.fields.sequence
                    ));
                    break;
                }
            }
        }
        if n == 0 {
            status = Status::failed("session has no entries");
        }
        push(
            &mut props,
            property::ENTRY_HASHES,
            status,
            format!("{n} entries recomputed (SHA-256 over canonical bytes)"),
        );
    }

    // contiguity: sequences 0..n, each entry's session_id matches.
    {
        let mut status = Status::Verified;
        if n == 0 {
            status = Status::failed("session has no entries");
        }
        for (i, e) in chain.entries.iter().enumerate() {
            if e.fields.sequence != i as i64 {
                status = Status::failed(format!("sequence gap: expected {}, got {}", i, e.fields.sequence));
                break;
            }
            if e.fields.session_id != chain.session_id {
                status = Status::failed(format!(
                    "entry at sequence {} belongs to session {:?}, not {:?}",
                    e.fields.sequence, e.fields.session_id, chain.session_id
                ));
                break;
            }
        }
        push(
            &mut props,
            property::CONTIGUITY,
            status,
            format!(
                "sequences 0..{} contiguous, all in session {:?}",
                n.saturating_sub(1),
                chain.session_id
            ),
        );
    }

    // genesis
    {
        let expected = genesis_hash_hex(&chain.session_id);
        let status = match chain.entries.first() {
            None => Status::failed("session has no entries"),
            Some(e0) if e0.fields.sequence != 0 => {
                Status::failed(format!("first entry is sequence {}, not 0", e0.fields.sequence))
            }
            Some(e0) if e0.fields.previous_entry_hash != expected => {
                Status::failed("sequence 0 previous_entry_hash is not the session genesis")
            }
            Some(_) => Status::Verified,
        };
        push(
            &mut props,
            property::GENESIS,
            status,
            format!("sha256(\"VIRP_CHAIN_GENESIS:\" + session_id) = {expected}"),
        );
    }

    // links: previous_entry_hash[i] == computed hash[i-1]
    {
        let mut status = Status::Verified;
        for i in 1..n {
            if chain.entries[i].fields.previous_entry_hash != computed_hashes[i - 1] {
                status = Status::failed(format!(
                    "previous hash mismatch at sequence {}",
                    chain.entries[i].fields.sequence
                ));
                break;
            }
        }
        if n == 0 {
            status = Status::failed("session has no entries");
        }
        push(
            &mut props,
            property::LINKS,
            status,
            format!("{} links checked against recomputed hashes", n.saturating_sub(1)),
        );
    }

    // head_commitment: the head names the last recomputed entry.
    // This proves the head and entries AGREE; it does NOT authenticate the
    // head (that is the HMAC / signature's job).
    let head_status = match (&chain.head, chain.entries.last(), computed_hashes.last()) {
        (None, _, _) => Status::failed("head record missing; chain length cannot be authenticated"),
        (Some(_), None, _) | (Some(_), _, None) => Status::failed("head present but session has no entries"),
        (Some(h), Some(last), Some(last_hash)) => {
            if h.fields.session_id != chain.session_id {
                Status::failed(format!(
                    "head belongs to session {:?}, not {:?}",
                    h.fields.session_id, chain.session_id
                ))
            } else if h.fields.last_sequence != last.fields.sequence {
                Status::failed(format!(
                    "head commits to last_sequence {} but last entry is {}",
                    h.fields.last_sequence, last.fields.sequence
                ))
            } else if h.fields.last_entry_hash != *last_hash {
                Status::failed(format!(
                    "head does not match final verified entry at sequence {}",
                    last.fields.sequence
                ))
            } else if h
                .canonical_utf8
                .as_ref()
                .is_some_and(|c| c.as_bytes() != h.fields.canonical_bytes().as_slice())
            {
                Status::failed("carried head canonical_utf8 differs from the canonical rebuilt from its fields")
            } else {
                Status::Verified
            }
        }
    };
    push(
        &mut props,
        property::HEAD_COMMITMENT,
        head_status,
        match &chain.head {
            Some(h) => format!(
                "head commits to sequence {} hash {}",
                h.fields.last_sequence, h.fields.last_entry_hash
            ),
            None => "no head record".to_owned(),
        },
    );

    // --- symmetric tier: NOTE ONLY ----------------------------------------
    // Docket does not hold K_chain. These are graded present/absent and, when
    // present, reported as operator-attested. Never Verified.
    //
    // Coverage is all-or-nothing. A session that carries an HMAC on some
    // entries but not others is NOT operator-attested: the operator attested
    // to the ones that are there and to nothing else, and reporting that with
    // the same status as full coverage is a verdict overstating its evidence.
    //
    // Partial coverage is FAILED rather than a softer status for the same
    // reason a stripped entry signature is (see `SessionKeyError`): the
    // symmetric columns sit OUTSIDE the canonical bytes, so the HMAC is their
    // only integrity protection and its removal leaves no other trace. The
    // producer emits one on every entry or on none — `chain_hmac` is NOT NULL
    // in the chain schema, and the exporter copies the column verbatim — so a
    // partial session is not a shape an honest producer makes.
    //
    // OPEN, deliberately not changed here: 0-of-n entries while the head DOES
    // carry a head_hmac. The same all-or-nothing logic says total stripping
    // under a present head HMAC should also fail, but that would re-grade a
    // case currently reported ABSENT and no real bundle in that shape exists
    // to test against. See SESSION-SUMMARY.md.
    {
        let with = chain.entries.iter().filter(|e| e.chain_hmac.is_some()).count();
        let malformed = chain
            .entries
            .iter()
            .filter(|e| e.chain_hmac.as_deref().is_some_and(|h| !is_hex_digest_64(h)))
            .count();
        let status = if malformed > 0 {
            Status::failed(format!("{malformed} chain_hmac values are not 64-hex digests"))
        } else if with == 0 {
            Status::Absent
        } else if with < n {
            Status::failed(format!(
                "chain_hmac is carried on {with} of {n} entries; {} have none. The symmetric tier is \
                 all-or-nothing — a session carries an HMAC on every entry or on none — and chain_hmac \
                 sits outside the canonical bytes, so nothing else would detect its removal",
                n - with
            ))
        } else {
            Status::OperatorAttested
        };
        push(
            &mut props,
            property::ENTRY_HMACS,
            status,
            format!("{with}/{n} entries carry chain_hmac (HMAC-SHA256 under the operator's K_chain, which this verifier does not hold)"),
        );
    }
    {
        let status = match chain.head.as_ref().and_then(|h| h.head_hmac.as_deref()) {
            None => Status::Absent,
            Some(h) if !is_hex_digest_64(h) => Status::failed("head_hmac is not a 64-hex digest"),
            Some(_) => Status::OperatorAttested,
        };
        push(
            &mut props,
            property::HEAD_HMAC,
            status,
            "HMAC-SHA256 under the operator's K_chain, which this verifier does not hold".to_owned(),
        );
    }

    // --- asymmetric tier --------------------------------------------------
    let head_sig = chain.head.as_ref().and_then(|h| h.signature.as_ref());
    let signing_key_id = head_sig.map(|s| s.signing_key_id.clone());

    // Resolve the session's key (from the HEAD's key id only).
    enum KeyState<'a> {
        UnsignedHead,
        Available(&'a PublicKey),
        Unavailable(String),
        BadScheme(String),
    }
    let key_state = match head_sig {
        None => KeyState::UnsignedHead,
        Some(s) if s.signature_scheme != SCHEME => KeyState::BadScheme(s.signature_scheme.clone()),
        Some(s) => match keyring.get(&s.signing_key_id) {
            Some(pk) => KeyState::Available(pk),
            None => KeyState::Unavailable(s.signing_key_id.clone()),
        },
    };

    // head_signature
    let head_sig_status = match (&key_state, head_sig, &chain.head) {
        (KeyState::UnsignedHead, _, _) => Status::Absent,
        (KeyState::BadScheme(s), _, _) => Status::failed(format!("head signature_scheme {s:?} is not {SCHEME}")),
        (KeyState::Unavailable(kid), _, _) => Status::unverifiable(format!(
            "head is signed under key_id {kid}, which this verifier was not given"
        )),
        (KeyState::Available(pk), Some(sig), Some(head)) => {
            let canonical = head.fields.canonical_bytes();
            match pk.verify_hex(SigDomain::Head, &canonical, &sig.signature_hex) {
                Ok(()) => Status::Verified,
                Err(e) => Status::failed(format!("head Ed25519 signature verification failed ({e})")),
            }
        }
        (KeyState::Available(_), _, _) => Status::failed("internal: key available without a signed head"),
    };
    let head_sig_verified = head_sig_status == Status::Verified;
    let head_sig_summary = head_sig_status.clone();
    push(
        &mut props,
        property::HEAD_SIGNATURE,
        head_sig_status,
        match &signing_key_id {
            Some(k) => format!("{SCHEME} under key_id {k}, domain tag VIRP-CHAIN-HEAD-SIG-v1"),
            None => "head carries no detached signature (unsigned / pre-D-1 session)".to_owned(),
        },
    );

    // session_key_binding — the D-1 rule. Graded whenever the head is
    // signed, even if we lack the key: a stripped or foreign-key entry in a
    // head-signed session is structurally wrong regardless of who verifies.
    let binding = check_session_key_binding(
        signing_key_id.as_deref(),
        chain.entries.iter().map(|e| {
            (
                e.fields.sequence,
                e.signature.as_ref().map(|s| s.signing_key_id.as_str()),
            )
        }),
    );
    let binding_status = match &binding {
        Ok(SessionKeyBinding::Bound { .. }) => Status::Verified,
        Ok(SessionKeyBinding::UnsignedSession { .. }) => Status::Absent,
        Err(e) => Status::failed(e.to_string()),
    };
    let binding_ok = matches!(binding, Ok(SessionKeyBinding::Bound { .. }));
    let binding_summary = binding_status.clone();
    push(
        &mut props,
        property::SESSION_KEY_BINDING,
        binding_status,
        match &binding {
            Ok(SessionKeyBinding::Bound { key_id }) => format!("every entry signed under the head's key_id {key_id}"),
            Ok(SessionKeyBinding::UnsignedSession {
                entries_with_signatures,
            }) => {
                format!("head unsigned; {entries_with_signatures}/{n} entries carry signatures (not graded)")
            }
            Err(_) => "session-granularity key rule violated".to_owned(),
        },
    );

    // entry_signatures
    let entry_sig_status = match &key_state {
        KeyState::UnsignedHead => Status::Absent,
        KeyState::BadScheme(_) => Status::failed("head signature scheme unsupported; entry signatures not graded"),
        KeyState::Unavailable(kid) => Status::unverifiable(format!(
            "entries are signed under key_id {kid}, which this verifier was not given"
        )),
        KeyState::Available(pk) => {
            if !binding_ok {
                Status::failed("session key binding failed; entry signatures cannot be trusted")
            } else {
                let mut status = Status::Verified;
                for (i, e) in chain.entries.iter().enumerate() {
                    // binding_ok guarantees a signature is present with the head's key id.
                    let Some(sig) = e.signature.as_ref() else {
                        status = Status::failed(format!(
                            "internal: missing signature at sequence {} after binding check",
                            e.fields.sequence
                        ));
                        break;
                    };
                    if sig.signature_scheme != SCHEME {
                        status = Status::failed(format!(
                            "entry at sequence {} has signature_scheme {:?}, not {SCHEME}",
                            e.fields.sequence, sig.signature_scheme
                        ));
                        break;
                    }
                    if let Err(err) = pk.verify_hex(SigDomain::Entry, &canonicals[i], &sig.signature_hex) {
                        status = Status::failed(format!(
                            "Ed25519 signature verification failed at sequence {} ({err})",
                            e.fields.sequence
                        ));
                        break;
                    }
                }
                status
            }
        }
    };
    let entry_sigs_verified = entry_sig_status == Status::Verified;
    let entry_sig_summary = entry_sig_status.clone();
    push(
        &mut props,
        property::ENTRY_SIGNATURES,
        entry_sig_status,
        format!("{n} entries, {SCHEME}, domain tag VIRP-CHAIN-ENTRY-SIG-v1"),
    );

    // --- the signer axes --------------------------------------------------
    // Axis 1, signature validity: a roll-up of the three signature
    // properties. A summary, not a new check — the property rows above keep
    // their independent grades and their independent failures.
    let all_sigs_verified = head_sig_verified && binding_ok && entry_sigs_verified;
    let signature_validity = [&head_sig_summary, &binding_summary, &entry_sig_summary]
        .into_iter()
        .find(|s| s.is_failed())
        .or_else(|| {
            [&head_sig_summary, &binding_summary, &entry_sig_summary]
                .into_iter()
                .find(|s| matches!(s, Status::Unverifiable { .. }))
        })
        .cloned()
        .unwrap_or(if all_sigs_verified {
            Status::Verified
        } else {
            Status::Absent
        });

    // Axis 2, signer trust: where the verifying key came from. PINNED only
    // when every signature verifies under a key the examiner supplied out of
    // band; MISMATCH whenever the examiner pinned keys and this session's
    // signatures do not verify under any of them; UNESTABLISHED otherwise —
    // the only key knowledge (if any) came from inside the bundle.
    let (trust, trust_source, trust_detail) = match &signing_key_id {
        None => (
            SignerTrust::Unestablished,
            None,
            "the session is unsigned; there is no signature to check under any key".to_owned(),
        ),
        Some(k) => {
            let source = keyring.source(k);
            match source {
                Some(TrustSource::ExaminerTrustStore) if all_sigs_verified => (
                    SignerTrust::Pinned,
                    source,
                    format!("signatures verify under key_id {k}, supplied by the examiner out of band"),
                ),
                Some(TrustSource::ExaminerTrustStore) => (
                    SignerTrust::Mismatch,
                    source,
                    format!(
                        "an examiner-pinned key matches key_id {k}, but this session's signatures do not \
                         all verify under it"
                    ),
                ),
                _ if keyring.has_pinned() => {
                    let pins: Vec<&str> = keyring.pinned_key_ids().collect();
                    (
                        SignerTrust::Mismatch,
                        source,
                        format!(
                            "the examiner pinned key_id(s) {}, but this session is signed under key_id {k}, \
                             which is not among them",
                            pins.join(", ")
                        ),
                    )
                }
                Some(TrustSource::BundleProvidedKey) => (
                    SignerTrust::Unestablished,
                    source,
                    format!(
                        "the only key for key_id {k} came from inside the bundle being examined; the \
                         signatures prove internal consistency, not who produced the bundle"
                    ),
                ),
                None => (
                    SignerTrust::Unestablished,
                    None,
                    format!("no key for key_id {k} was available from any source"),
                ),
            }
        }
    };
    let signer = SignerReport {
        signature_validity,
        trust,
        trust_source,
        detail: trust_detail,
    };

    // --- verdict ----------------------------------------------------------
    // The top tier requires BOTH axes: valid signatures AND a pinned signer.
    // Valid signatures under a key the examiner did not pin earn only
    // CRYPTOGRAPHICALLY-CONSISTENT — the cryptography held without an
    // examiner-selected trust anchor — so the weakest-link bundle roll-up
    // carries the demotion with no special case.
    let any_failed = props.iter().any(|p| p.status.is_failed());
    let any_operator_attested = props.iter().any(|p| p.status == Status::OperatorAttested);
    let any_unverifiable = props.iter().any(|p| matches!(p.status, Status::Unverifiable { .. }));
    let verdict = if any_failed {
        Verdict::Failed
    } else if all_sigs_verified && trust == SignerTrust::Pinned {
        Verdict::CryptographicallyVerified
    } else if all_sigs_verified {
        Verdict::CryptographicallyConsistent
    } else if any_operator_attested || any_unverifiable {
        Verdict::OperatorAttestedUnverifiable
    } else {
        Verdict::ConsistentUnauthenticated
    };

    debug_assert_eq!(props.len(), property::ALL.len());
    SessionReport {
        session_id: chain.session_id.clone(),
        entry_count: n,
        signing_key_id,
        properties: props,
        signer,
        verdict,
    }
}
