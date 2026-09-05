//! Witness inclusion: was this session's head placed in a third party's
//! append-only log, and does the proof still recompute?
//!
//! A VIRP chain proves internal consistency and a signature. It cannot prove
//! the operator did not build the whole sequence yesterday afternoon. A
//! witness — a transparency log the operator does not control — is what makes
//! that question answerable, and this module grades the answer.
//!
//! # What is re-implemented here, and why
//!
//! The RFC 9162 proof algorithms below are the RECIPIENT's side, transcribed
//! from the RFC: [`verify_inclusion`] is Section 2.1.3.2 and
//! [`verify_consistency`] is Section 2.1.4.2. They are written here rather
//! than pulled from `~/virp-witness`, deliberately. A verifier that checked a
//! witness's proofs with the witness's own code would be asking the log to
//! mark its own homework: one bug, one disagreement about a canonical byte,
//! and both sides would make the same mistake in the same direction and
//! report VERIFIED. The two implementations are held together instead by the
//! witness repository's published golden vectors, which
//! `tests/witness_vectors.rs` runs in full — 8 leaves, 36 inclusion proofs,
//! 36 consistency proofs and 8 signed tree heads.
//!
//! # What this module never does
//!
//! It holds no secret, opens no socket and grades nothing on the strength of
//! anything the witness merely claims about itself. The witness PUBLIC key
//! arrives out of band (`--witness-key`), exactly as `--pin` and `--seal-key`
//! do; the `witness_key_id` a bundle carries is a CLAIM, recorded so a report
//! can say which key the witness said it used, and never a trust anchor.
//!
//! And a witness result can never upgrade a chain verdict. It answers a
//! different question — "was this head in somebody else's log, and when did
//! they say so" — beside the cryptographic verdict, never inside it. The one
//! exception is FAILED: a proof that does not recompute is a cryptographic
//! inconsistency in the bundle, and that does drive the verdict, exactly as a
//! failed artifact binding does.

use serde::{Deserialize, Serialize};

use crate::canonical::HeadFields;
use crate::hash::{is_hex_digest_64, is_hex_key_id_32, sha256, sha256_hex};
use crate::sig::PublicKey;
use crate::verify::{SessionChain, SignerTrust, Status};

/// Domain tag for the bytes the WITNESS signs over a tree head. The trailing
/// NUL is part of the signed input and is never stored — the VIRP-TYPED-OP
/// convention, the same shape as `VIRP-CHAIN-HEAD-SIG-v1`.
pub const TAG_STH: &[u8] = b"VIRP-WITNESS-STH-v1\x00";

/// Domain tag for the bytes a SUBMITTER signs over a leaf.
pub const TAG_LEAF: &[u8] = b"VIRP-WITNESS-LEAF-v1\x00";

/// `v` inside the RFC 9162 leaf data — the bytes the tree actually hashes.
/// Deliberately different from [`V_LEAF`]: one is signed by a submitter and
/// the other is signed by nobody, and the two must never be confusable.
pub const V_ENTRY: &str = "VIRP-WITNESS-ENTRY-v1";
/// `v` inside the submitter-signed canonical bytes.
pub const V_LEAF: &str = "VIRP-WITNESS-LEAF-v1";
/// `v` inside the witness-signed tree head.
pub const V_STH: &str = "VIRP-WITNESS-STH-v1";

/// Version tag of `witness/sth.json`.
pub const STH_FILE_VERSION: &str = "docket-witness-sth/1";
/// Version tag of `witness/<session>.proof.json`.
pub const PROOF_FILE_VERSION: &str = "docket-witness-proof/1";

// ---------------------------------------------------------------------------
// RFC 9162 §2.1.1 — the two hash constructions
// ---------------------------------------------------------------------------

/// `SHA-256(0x00 || leaf_data)` — RFC 9162 Section 2.1.1.
pub fn leaf_hash(leaf_data: &[u8]) -> [u8; 32] {
    let mut v = Vec::with_capacity(1 + leaf_data.len());
    v.push(0x00);
    v.extend_from_slice(leaf_data);
    sha256(&v)
}

/// `SHA-256(0x01 || left || right)` — RFC 9162 Section 2.1.1.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut v = Vec::with_capacity(65);
    v.push(0x01);
    v.extend_from_slice(left);
    v.extend_from_slice(right);
    sha256(&v)
}

/// Why a proof did not hold. Each variant names the specific disagreement,
/// because "the proof failed" is the one thing a reader cannot act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// `leaf_index` is not inside a tree of `tree_size` leaves.
    IndexOutsideTree { leaf_index: u64, tree_size: u64 },
    /// The audit path ran out before the walk reached the root.
    PathTooShort { got: usize },
    /// The walk reached the root with path elements left over.
    PathTooLong { got: usize },
    /// The walk completed and produced a different root.
    RootMismatch { recomputed: String, expected: String },
    /// A hex field was not 64 lowercase hex characters.
    MalformedHash(String),
    /// A consistency proof's tree sizes do not describe a growing log.
    BadRange { first: u64, second: u64 },
    /// A consistency proof was empty (or non-empty) where the RFC requires
    /// the opposite.
    BadProofShape(String),
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexOutsideTree { leaf_index, tree_size } => {
                write!(f, "leaf_index {leaf_index} is outside a tree of {tree_size} leaves")
            }
            Self::PathTooShort { got } => write!(f, "the audit path of {got} node(s) ends before the root"),
            Self::PathTooLong { got } => write!(f, "the audit path of {got} node(s) continues past the root"),
            Self::RootMismatch { recomputed, expected } => write!(
                f,
                "the audit path recomputes to root {recomputed}, and the signed tree head says {expected}"
            ),
            Self::MalformedHash(h) => write!(f, "{h:?} is not 64 lowercase hex characters"),
            Self::BadRange { first, second } => {
                write!(f, "a log does not shrink: consistency asked from {first} to {second}")
            }
            Self::BadProofShape(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ProofError {}

fn hash_from_hex(s: &str) -> Result<[u8; 32], ProofError> {
    if !is_hex_digest_64(s) {
        return Err(ProofError::MalformedHash(s.to_owned()));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| ProofError::MalformedHash(s.to_owned()))?;
    Ok(out)
}

fn hashes_from_hex(path: &[String]) -> Result<Vec<[u8; 32]>, ProofError> {
    path.iter().map(|s| hash_from_hex(s)).collect()
}

// ---------------------------------------------------------------------------
// RFC 9162 §2.1.3.2 — inclusion
// ---------------------------------------------------------------------------

/// Verify an inclusion proof, RFC 9162 Section 2.1.3.2.
///
/// The recipient's algorithm, walking the path with the `fn`/`sn` index
/// bookkeeping and never seeing the tree. Returns the recomputed root so a
/// caller can report it beside the expected one; a mismatch is an `Err`
/// carrying both.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    path: &[String],
    root: &str,
) -> Result<[u8; 32], ProofError> {
    if leaf_index >= tree_size {
        return Err(ProofError::IndexOutsideTree { leaf_index, tree_size });
    }
    let expected = hash_from_hex(root)?;
    let path = hashes_from_hex(path)?;

    let mut fnode = leaf_index;
    let mut snode = tree_size - 1;
    let mut r = *leaf;
    for p in &path {
        if snode == 0 {
            return Err(ProofError::PathTooLong { got: path.len() });
        }
        if fnode % 2 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode != 0 && fnode.is_multiple_of(2) {
                fnode /= 2;
                snode /= 2;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode /= 2;
        snode /= 2;
    }
    if snode != 0 {
        return Err(ProofError::PathTooShort { got: path.len() });
    }
    if r != expected {
        return Err(ProofError::RootMismatch {
            recomputed: hex::encode(r),
            expected: root.to_owned(),
        });
    }
    Ok(r)
}

// ---------------------------------------------------------------------------
// RFC 9162 §2.1.4.2 — consistency
// ---------------------------------------------------------------------------

/// Verify a consistency proof, RFC 9162 Section 2.1.4.2: that the tree of
/// `second` leaves is an extension of the tree of `first` leaves, with
/// nothing rewritten in between.
///
/// This is the check that catches a witness whose own history does not
/// reconcile — a different and worse alarm than a receipt that does not
/// match a head.
pub fn verify_consistency(
    first: u64,
    second: u64,
    proof: &[String],
    first_root: &str,
    second_root: &str,
) -> Result<(), ProofError> {
    if first > second {
        return Err(ProofError::BadRange { first, second });
    }
    let fr_expected = hash_from_hex(first_root)?;
    let sr_expected = hash_from_hex(second_root)?;

    // The RFC's two degenerate cases, both with an empty proof: a tree
    // consistent with itself, and a tree consistent with the empty tree.
    if first == second {
        if !proof.is_empty() {
            return Err(ProofError::BadProofShape(format!(
                "a tree is consistent with itself and the proof must be empty; got {} node(s)",
                proof.len()
            )));
        }
        if fr_expected != sr_expected {
            return Err(ProofError::RootMismatch {
                recomputed: first_root.to_owned(),
                expected: second_root.to_owned(),
            });
        }
        return Ok(());
    }
    if first == 0 {
        if !proof.is_empty() {
            return Err(ProofError::BadProofShape(format!(
                "every tree extends the empty tree and the proof must be empty; got {} node(s)",
                proof.len()
            )));
        }
        return Ok(());
    }

    let path = hashes_from_hex(proof)?;
    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode % 2 == 1 {
        fnode /= 2;
        snode /= 2;
    }

    // When `first` is an exact power of two the first node is the old root
    // itself, and the log omits it from the proof rather than sending back
    // something the recipient already holds.
    let mut it = path.iter();
    let (mut fr, mut sr) = if first & (first - 1) == 0 {
        (fr_expected, fr_expected)
    } else {
        let Some(seed) = it.next() else {
            return Err(ProofError::BadProofShape(
                "a consistency proof from a tree size that is not a power of two must carry the old \
                 subtree root as its first node, and this proof is empty"
                    .to_owned(),
            ));
        };
        (*seed, *seed)
    };

    for c in it {
        if snode == 0 {
            return Err(ProofError::PathTooLong { got: path.len() });
        }
        if fnode % 2 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fnode != 0 && fnode.is_multiple_of(2) {
                fnode /= 2;
                snode /= 2;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode /= 2;
        snode /= 2;
    }

    if snode != 0 {
        return Err(ProofError::PathTooShort { got: path.len() });
    }
    if fr != fr_expected {
        return Err(ProofError::RootMismatch {
            recomputed: hex::encode(fr),
            expected: first_root.to_owned(),
        });
    }
    if sr != sr_expected {
        return Err(ProofError::RootMismatch {
            recomputed: hex::encode(sr),
            expected: second_root.to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The signed tree head
// ---------------------------------------------------------------------------

/// A signed tree head, exactly as `GET /v1/sth` serves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sth {
    pub tree_size: u64,
    /// 64 lowercase hex.
    pub root_hash: String,
    /// RFC 3339 UTC, millisecond precision, `Z`. The WITNESS's clock.
    pub timestamp: String,
    /// 128 lowercase hex: Ed25519 over `TAG_STH || signing_bytes()`.
    pub signature: String,
}

impl Sth {
    /// The bytes the witness signs, WITHOUT the domain tag:
    ///
    /// ```text
    /// {"root_hash":"<64hex>","timestamp":"<RFC3339>","tree_size":<u64>,"v":"VIRP-WITNESS-STH-v1"}
    /// ```
    ///
    /// Rebuilt from the fields rather than taken from the served bytes: the
    /// signature is over this construction, so verifying the served JSON
    /// verbatim would verify whatever framing the server chose to send.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut o = String::with_capacity(200);
        o.push_str("{\"root_hash\":\"");
        o.push_str(&self.root_hash);
        o.push_str("\",\"timestamp\":\"");
        o.push_str(&self.timestamp);
        o.push_str("\",\"tree_size\":");
        o.push_str(&self.tree_size.to_string());
        o.push_str(",\"v\":\"");
        o.push_str(V_STH);
        o.push_str("\"}");
        o.into_bytes()
    }

    /// `TAG_STH || signing_bytes()` — the complete Ed25519 input.
    pub fn signature_input(&self) -> Vec<u8> {
        let mut v = TAG_STH.to_vec();
        v.extend_from_slice(&self.signing_bytes());
        v
    }

    /// Verify this head under one examiner-supplied witness key.
    ///
    /// STRICT Ed25519, as everywhere else in this crate: a non-canonical `S`
    /// or a small-order point is refused. That is deliberately tighter than
    /// the witness's own acceptance rule, and the tighter side is the right
    /// one for a verifier.
    pub fn verify_under(&self, key: &PublicKey) -> bool {
        let Some(sig) = decode_sig(&self.signature) else {
            return false;
        };
        key.verify_raw(&self.signature_input(), &sig).is_ok()
    }
}

fn decode_sig(hex_sig: &str) -> Option<[u8; 64]> {
    if hex_sig.len() != 128 || !hex_sig.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 64];
    hex::decode_to_slice(hex_sig, &mut out).ok()?;
    Some(out)
}

// ---------------------------------------------------------------------------
// The leaf
// ---------------------------------------------------------------------------

/// The RFC 9162 leaf: the five fields a submitter signed, plus the witness's
/// own receive time bound into the hashed bytes.
///
/// The timestamp being INSIDE the leaf is what makes it worth anything: a
/// witness that later wants to claim a different receive time has to produce
/// a different leaf hash, a different root and a different signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessLeaf {
    /// 64 lowercase hex. An opaque chain identifier — the operator picks the
    /// mapping, and the recommended one is `SHA-256(session_id)`. This
    /// verifier reports whether that default holds and never requires it: a
    /// submitter may legitimately use a keyed derivation instead.
    pub chain_id: String,
    /// The chain's sequence at the witnessed head.
    pub sequence: u64,
    /// 64 lowercase hex: SHA-256 over the head canonical bytes. The witness
    /// never sees the head itself.
    pub head_hash: String,
    /// 32 lowercase hex, `sha256-raw-16` of the SUBMITTER's public key.
    pub key_id: String,
    /// 128 lowercase hex: Ed25519 over `TAG_LEAF || leaf signing bytes`.
    pub signature: String,
    /// RFC 3339 UTC, millisecond precision, `Z`. The witness's clock, and a
    /// THIRD clock beside the O-Node's and the producer's.
    pub timestamp: String,
}

impl WitnessLeaf {
    /// The RFC 9162 leaf data — the bytes fed to `SHA-256(0x00 || ...)`.
    /// Keys lexicographic; every field is fixed-width hex, an integer or a
    /// fixed-shape timestamp, so nothing here needs JSON escaping.
    pub fn leaf_data(&self) -> Vec<u8> {
        let mut o = String::with_capacity(480);
        o.push_str("{\"chain_id\":\"");
        o.push_str(&self.chain_id);
        o.push_str("\",\"head_hash\":\"");
        o.push_str(&self.head_hash);
        o.push_str("\",\"key_id\":\"");
        o.push_str(&self.key_id);
        o.push_str("\",\"sequence\":");
        o.push_str(&self.sequence.to_string());
        o.push_str(",\"signature\":\"");
        o.push_str(&self.signature);
        o.push_str("\",\"timestamp\":\"");
        o.push_str(&self.timestamp);
        o.push_str("\",\"v\":\"");
        o.push_str(V_ENTRY);
        o.push_str("\"}");
        o.into_bytes()
    }

    /// `SHA-256(0x00 || leaf_data())`.
    pub fn leaf_hash(&self) -> [u8; 32] {
        leaf_hash(&self.leaf_data())
    }

    /// The bytes the SUBMITTER signed, without the domain tag. The witness's
    /// timestamp is deliberately not here: the submitter could not know it.
    pub fn submitter_signing_bytes(&self) -> Vec<u8> {
        let mut o = String::with_capacity(320);
        o.push_str("{\"chain_id\":\"");
        o.push_str(&self.chain_id);
        o.push_str("\",\"head_hash\":\"");
        o.push_str(&self.head_hash);
        o.push_str("\",\"key_id\":\"");
        o.push_str(&self.key_id);
        o.push_str("\",\"sequence\":");
        o.push_str(&self.sequence.to_string());
        o.push_str(",\"v\":\"");
        o.push_str(V_LEAF);
        o.push_str("\"}");
        o.into_bytes()
    }

    /// Verify the submitter's own signature over this leaf under a key the
    /// examiner pinned. Reported, never graded: see [`grade_witness`].
    pub fn submitter_signature_verifies(&self, key: &PublicKey) -> bool {
        let Some(sig) = decode_sig(&self.signature) else {
            return false;
        };
        let mut input = TAG_LEAF.to_vec();
        input.extend_from_slice(&self.submitter_signing_bytes());
        key.verify_raw(&input, &sig).is_ok()
    }

    fn well_formed(&self) -> Option<String> {
        if !is_hex_digest_64(&self.chain_id) {
            return Some(format!(
                "chain_id {:?} is not 64 lowercase hex characters",
                self.chain_id
            ));
        }
        if !is_hex_digest_64(&self.head_hash) {
            return Some(format!(
                "head_hash {:?} is not 64 lowercase hex characters",
                self.head_hash
            ));
        }
        if !is_hex_key_id_32(&self.key_id) {
            return Some(format!("key_id {:?} is not 32 lowercase hex characters", self.key_id));
        }
        if decode_sig(&self.signature).is_none() {
            return Some("the leaf signature is not 128 lowercase hex characters".to_owned());
        }
        None
    }
}

// ---------------------------------------------------------------------------
// What the bundle carries
// ---------------------------------------------------------------------------

/// `witness/sth.json`: the signed tree head the proofs are against, as the
/// witness served it.
///
/// `sth_served` holds the response BYTES verbatim, so a reader can see
/// exactly what arrived; every check is run against the fields parsed out of
/// those bytes. `witness_key_id` is the id the witness CLAIMED for itself —
/// carried so a report can say whether the examiner's out-of-band key is a
/// key for the same witness, and never a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSthFile {
    pub v: String,
    /// Where the exporter fetched it. Operator context; nothing is graded
    /// from it, and this verifier never contacts it unless asked.
    pub witness_url: String,
    /// The key id the witness claimed for itself. A CLAIM.
    pub witness_key_id: String,
    pub fetched_at: String,
    /// The `GET /v1/sth` response body, byte for byte.
    pub sth_served: String,
}

impl WitnessSthFile {
    /// Parse the served bytes. A file whose `sth_served` is not a well-formed
    /// STH is a defect in the bundle, not a witness result.
    pub fn parse(&self) -> Result<Sth, String> {
        if self.v != STH_FILE_VERSION {
            return Err(format!("unsupported {:?} (want {STH_FILE_VERSION})", self.v));
        }
        let sth: Sth =
            serde_json::from_str(&self.sth_served).map_err(|e| format!("sth_served is not a signed tree head: {e}"))?;
        if !is_hex_digest_64(&sth.root_hash) {
            return Err(format!(
                "root_hash {:?} is not 64 lowercase hex characters",
                sth.root_hash
            ));
        }
        if decode_sig(&sth.signature).is_none() {
            return Err("the tree head signature is not 128 lowercase hex characters".to_owned());
        }
        Ok(sth)
    }
}

/// `witness/<session>.proof.json`: one session's leaf and its inclusion proof
/// against the carried tree head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessProofFile {
    pub v: String,
    pub session_id: String,
    pub leaf: WitnessLeaf,
    pub leaf_index: u64,
    /// The tree the audit path is against — the same size as the carried
    /// signed tree head.
    pub tree_size: u64,
    pub audit_path: Vec<String>,
    /// The `GET /v1/proof` response body, byte for byte. Context for a
    /// reader; the grading uses the fields above, and the root it compares
    /// against comes from the SIGNED head, never from this unsigned body.
    pub proof_served: String,
}

/// The manifest's `witness` section: what the exporter carried, and for every
/// session, whether anything was carried at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestWitness {
    pub witness_url: String,
    /// The witness's claim about its own key id, from `GET /v1/pubkey`.
    #[serde(default)]
    pub witness_key_id: Option<String>,
    /// Relative path to `witness/sth.json`.
    pub sth: String,
    pub tree_size: u64,
    pub sessions: Vec<ManifestWitnessSession>,
}

/// One session's row in the manifest's witness section.
///
/// A head the witness has never seen is `present: false` with a reason, never
/// omitted: "the witness does not have this head" and "nobody asked" must not
/// read the same.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestWitnessSession {
    pub session_id: String,
    pub present: bool,
    /// Relative path to the proof file. Absent when `present` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Why nothing is carried: `not_submitted` (the witness has no leaf for
    /// this head), `unreachable` (the witness did not answer), or
    /// `lookup_failed` (it answered, and the answer could not be turned into
    /// a proof). Three different facts, and only the first says anything
    /// about the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The witness material a bundle carries, read and parsed.
#[derive(Debug, Clone)]
pub struct WitnessMaterial {
    pub manifest: ManifestWitness,
    /// The parsed tree head, or why the carried file could not be parsed.
    pub sth: Result<Sth, String>,
    pub sth_file: WitnessSthFile,
    /// Per session id, in manifest order: the proof file, or `None` when the
    /// row says nothing is carried.
    pub proofs: Vec<(String, Option<WitnessProofFile>)>,
}

impl WitnessMaterial {
    fn row(&self, session_id: &str) -> Option<&ManifestWitnessSession> {
        self.manifest.sessions.iter().find(|s| s.session_id == session_id)
    }

    fn proof(&self, session_id: &str) -> Option<&WitnessProofFile> {
        self.proofs
            .iter()
            .find(|(id, _)| id == session_id)
            .and_then(|(_, p)| p.as_ref())
    }
}

// ---------------------------------------------------------------------------
// The graded result
// ---------------------------------------------------------------------------

/// One session's witness result.
///
/// `status` is the property in the existing five-status vocabulary; `trust`
/// is the SEPARATE axis of whether the key that checked the tree head was the
/// examiner's, kept apart for the same reason `signer_trust` is kept apart
/// from `signature_validity`. A tree head that verifies under a key nobody
/// pinned proves the witness is internally consistent and proves nothing
/// about which witness it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessOutcome {
    /// Flattened, like every other graded property: the object carries
    /// `"status": "verified"` at its own level rather than nesting one. A
    /// FAILED status renames its own text to `failure` for exactly this
    /// reason — two `detail` keys in one object made parsers drop one.
    #[serde(flatten)]
    pub status: Status,
    pub detail: String,
    /// Whether the tree head was checked under an examiner-pinned witness
    /// key. `Unestablished` is the exit-5 case — CRYPTOGRAPHICALLY-CONSISTENT
    /// in the verdict vocabulary — and is never FAILED.
    pub trust: SignerTrust,
    /// The witness's own timestamp on the leaf, when there is a leaf. A THIRD
    /// clock: never merged with the O-Node's or the producer's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_existed_by: Option<String>,
    /// The tree the proof was checked against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u64>,
    /// Whether the submitter's own signature over the leaf verified under a
    /// pinned CHAIN key. Reported, not graded — it is a statement about the
    /// submitter, and the witness property is about the log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter_signature: Option<String>,
}

impl WitnessOutcome {
    fn absent(detail: impl Into<String>) -> WitnessOutcome {
        WitnessOutcome {
            status: Status::Absent,
            detail: detail.into(),
            trust: SignerTrust::Unestablished,
            head_existed_by: None,
            tree_size: None,
            leaf_index: None,
            submitter_signature: None,
        }
    }
}

/// The bundle-level witness roll-up, beside the verdict and never inside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSummary {
    #[serde(flatten)]
    pub status: Status,
    pub detail: String,
    pub verified: usize,
    pub sessions: usize,
}

/// Grade one session's witness property.
///
/// `witness_keys` are the examiner's out-of-band `--witness-key` values;
/// `chain_keys` are the `--pin` keys, used only to report on the submitter's
/// own signature.
pub fn grade_witness(
    chain: &SessionChain,
    material: &WitnessMaterial,
    witness_keys: &[PublicKey],
    chain_keys: &[PublicKey],
) -> WitnessOutcome {
    let Some(row) = material.row(&chain.session_id) else {
        // A bundle carrying a witness section that does not mention this
        // session says nothing about it. Not a failure of the log — a gap in
        // the export, and reported as one.
        return WitnessOutcome::absent(
            "the bundle's witness section does not list this session; nothing was carried for it",
        );
    };
    if !row.present {
        let reason = row.reason.as_deref().unwrap_or("no reason recorded");
        return WitnessOutcome::absent(format!("no witness material for this session — reason: {reason}"));
    }
    let Some(proof) = material.proof(&chain.session_id) else {
        return WitnessOutcome {
            status: Status::failed(
                "the manifest says witness material is present for this session, and the bundle does not carry it"
                    .to_owned(),
            ),
            detail: "manifest and bundle contents disagree".to_owned(),
            trust: SignerTrust::Unestablished,
            head_existed_by: None,
            tree_size: None,
            leaf_index: None,
            submitter_signature: None,
        };
    };

    let leaf = &proof.leaf;
    let existed_by = Some(leaf.timestamp.clone());
    let mut out = WitnessOutcome {
        status: Status::Absent,
        detail: String::new(),
        trust: SignerTrust::Unestablished,
        head_existed_by: existed_by.clone(),
        tree_size: Some(proof.tree_size),
        leaf_index: Some(proof.leaf_index),
        submitter_signature: None,
    };

    if proof.v != PROOF_FILE_VERSION {
        out.status = Status::failed(format!(
            "unsupported proof file version {:?} (want {PROOF_FILE_VERSION})",
            proof.v
        ));
        return out;
    }
    if let Some(bad) = leaf.well_formed() {
        out.status = Status::failed(bad);
        return out;
    }

    // The submitter's own signature, reported beside the property and never
    // folded into it. Checked first so the line is present whatever the
    // inclusion proof does.
    out.submitter_signature = Some(match chain_keys.iter().find(|k| k.key_id() == leaf.key_id) {
        Some(k) if leaf.submitter_signature_verifies(k) => {
            format!("verifies under pinned key_id {}", leaf.key_id)
        }
        Some(_) => format!(
            "DOES NOT verify under pinned key_id {} — the leaf names this key and the signature is not its",
            leaf.key_id
        ),
        None => format!("not checked: no --pin key with key_id {} was supplied", leaf.key_id),
    });

    // --- what the leaf says about THIS session's head ---------------------
    //
    // Before any proof arithmetic. A perfectly valid proof of inclusion for
    // somebody else's head is the failure this check exists to catch, and
    // grading the proof first would let the report lead with VERIFIED
    // arithmetic about the wrong leaf.
    let Some(head) = &chain.head else {
        out.status = Status::unverifiable(
            "this session carries no head record, so there is nothing for the leaf to bind to".to_owned(),
        );
        return out;
    };
    let head_fields = HeadFields {
        session_id: head.fields.session_id.clone(),
        last_sequence: head.fields.last_sequence,
        last_entry_hash: head.fields.last_entry_hash.clone(),
    };
    let our_head_hash = sha256_hex(&head_fields.canonical_bytes());
    if leaf.head_hash != our_head_hash {
        out.status = Status::failed(format!(
            "the leaf names head_hash {}, and this session's head hashes to {} — the witness holds a \
             DIFFERENT head for this chain",
            leaf.head_hash, our_head_hash
        ));
        out.detail = format!("leaf {} of tree {}", proof.leaf_index, proof.tree_size);
        return out;
    }
    if leaf.sequence as i64 != head.fields.last_sequence {
        out.status = Status::failed(format!(
            "the leaf names sequence {}, and this session's head is at sequence {}",
            leaf.sequence, head.fields.last_sequence
        ));
        return out;
    }
    match &head.signature {
        Some(sig) if sig.signing_key_id != leaf.key_id => {
            out.status = Status::failed(format!(
                "the leaf was submitted under key_id {}, and this session's head is signed under key_id {}",
                leaf.key_id, sig.signing_key_id
            ));
            return out;
        }
        Some(_) => {}
        None => {
            out.status = Status::unverifiable(format!(
                "this session's head carries no signature, so there is no signing key_id to compare with the \
                 leaf's {}",
                leaf.key_id
            ));
            return out;
        }
    }

    // --- the tree head, and whose key signed it ---------------------------
    let sth = match &material.sth {
        Ok(s) => s,
        Err(e) => {
            out.status = Status::failed(format!("the carried signed tree head is unreadable: {e}"));
            return out;
        }
    };
    if proof.tree_size != sth.tree_size {
        out.status = Status::failed(format!(
            "the proof is against tree_size {} and the carried signed tree head is at {}",
            proof.tree_size, sth.tree_size
        ));
        return out;
    }
    if witness_keys.is_empty() {
        out.status = Status::unverifiable(
            "no --witness-key was supplied, so the signed tree head was not checked under any key the \
             examiner selected"
                .to_owned(),
        );
        out.detail = format!(
            "leaf {} of tree {}; the bundle says the witness claims key_id {}",
            proof.leaf_index, proof.tree_size, material.sth_file.witness_key_id
        );
        return out;
    }
    let Some(key) = witness_keys.iter().find(|k| sth.verify_under(k)) else {
        // Two very different situations, and collapsing them would be the
        // whole point missed. If the head does not even CLAIM our key, no
        // trust was established and nothing was caught being wrong — the
        // exit-5 case. If it claims our key and does not verify under it,
        // that is a signature that is wrong.
        let claims_ours = witness_keys
            .iter()
            .any(|k| k.key_id() == material.sth_file.witness_key_id);
        if claims_ours {
            out.status = Status::failed(format!(
                "the carried tree head claims witness key_id {}, which the examiner pinned, and its signature \
                 does not verify under that key",
                material.sth_file.witness_key_id
            ));
            out.trust = SignerTrust::Mismatch;
        } else {
            out.status = Status::unverifiable(format!(
                "the carried tree head signs under witness key_id {}, and the examiner pinned {} — trust in \
                 this witness is NOT ESTABLISHED, which is the CRYPTOGRAPHICALLY-CONSISTENT (exit 5) case \
                 and not a failure of the proof",
                material.sth_file.witness_key_id,
                witness_keys
                    .iter()
                    .map(PublicKey::key_id)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            out.trust = SignerTrust::Unestablished;
        }
        return out;
    };
    out.trust = SignerTrust::Pinned;

    // --- the inclusion proof ---------------------------------------------
    let lh = leaf.leaf_hash();
    match verify_inclusion(
        &lh,
        proof.leaf_index,
        proof.tree_size,
        &proof.audit_path,
        &sth.root_hash,
    ) {
        Ok(_) => {
            let chain_id_note = if leaf.chain_id == sha256_hex(chain.session_id.as_bytes()) {
                "chain_id is SHA-256(session_id)"
            } else {
                "chain_id is not SHA-256(session_id) — an operator mapping this verifier cannot check"
            };
            out.status = Status::Verified;
            // Two times, named apart. The tree head's stamp is when the
            // witness signed the tree; the leaf's own stamp — reported as
            // `head existed by` — is when it says it received this head.
            // They are usually close and are never the same statement.
            out.detail = format!(
                "leaf {} of tree {} (tree head stamped {}), signed by witness key_id {}; {}",
                proof.leaf_index,
                proof.tree_size,
                sth.timestamp,
                key.key_id(),
                chain_id_note
            );
        }
        Err(e) => {
            out.status = Status::failed(format!("the inclusion proof does not recompute: {e}"));
            out.detail = format!("leaf {} of tree {}", proof.leaf_index, proof.tree_size);
        }
    }
    out
}

/// `GET /v1/consistency` as the witness serves it.
///
/// Parsed here so the CLI needs no JSON dependency of its own — and so the
/// two roots it carries stay clearly labelled as the WITNESS's claims. The
/// first root a consistency check trusts is the one in the carried SIGNED
/// head, never this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyBody {
    pub first: u64,
    pub second: u64,
    pub first_root: String,
    pub second_root: String,
    pub consistency_proof: Vec<String>,
}

/// Parse a `GET /v1/sth` body.
pub fn parse_sth(text: &str) -> Result<Sth, String> {
    serde_json::from_str(text).map_err(|e| format!("not a signed tree head: {e}"))
}

/// Parse a `GET /v1/consistency` body.
pub fn parse_consistency(text: &str) -> Result<ConsistencyBody, String> {
    serde_json::from_str(text).map_err(|e| format!("not a consistency proof: {e}"))
}

/// A live consistency check's inputs: the fresh head the verifier fetched and
/// the proof from the carried tree to it. Fetched by the CLI — this library
/// opens no socket.
#[derive(Debug, Clone)]
pub struct LiveConsistency {
    /// The `GET /v1/sth` body the verifier fetched just now.
    pub fresh_sth_served: String,
    /// `GET /v1/consistency?first=<carried>&second=<fresh>` — the audit path.
    pub proof: Vec<String>,
    /// The first root as the witness served it. Never used as the trusted
    /// value: the carried SIGNED head's root is.
    pub served_first_root: String,
    pub url: String,
}

/// Grade `witness_consistency`: is the tree the proof was checked against
/// still a prefix of the witness's log as it stands now?
///
/// A network failure is UNVERIFIABLE with the reason. Never a pass — the
/// check did not run — and never FAILED, which would let anyone who can drop
/// a packet manufacture an alarm.
pub fn grade_witness_consistency(
    carried: &Sth,
    live: Result<&LiveConsistency, String>,
    witness_keys: &[PublicKey],
) -> Status {
    let live = match live {
        Ok(l) => l,
        Err(why) => return Status::unverifiable(format!("the witness was not reached, so nothing was checked: {why}")),
    };
    if witness_keys.is_empty() {
        return Status::unverifiable(
            "no --witness-key was supplied, so a freshly fetched tree head could not be checked under any \
             key the examiner selected"
                .to_owned(),
        );
    }
    let fresh: Sth = match serde_json::from_str(&live.fresh_sth_served) {
        Ok(s) => s,
        Err(e) => {
            return Status::unverifiable(format!(
                "{} answered with something that is not a signed tree head: {e}",
                live.url
            ))
        }
    };
    if !witness_keys.iter().any(|k| fresh.verify_under(k)) {
        return Status::unverifiable(format!(
            "the tree head {} serves now does not verify under any pinned witness key — trust in the live \
             endpoint is NOT ESTABLISHED, and this verifier will not call that a failure of the carried proof",
            live.url
        ));
    }
    if fresh.tree_size < carried.tree_size {
        return Status::failed(format!(
            "the witness now advertises tree_size {} and the bundle carries a head at {} — a log does not \
             shrink",
            fresh.tree_size, carried.tree_size
        ));
    }
    match verify_consistency(
        carried.tree_size,
        fresh.tree_size,
        &live.proof,
        &carried.root_hash,
        &fresh.root_hash,
    ) {
        Ok(()) => Status::Verified,
        Err(e) => Status::failed(format!(
            "the log at tree_size {} is NOT an extension of the carried tree at {}: {e}. The witness's own \
             history does not reconcile",
            fresh.tree_size, carried.tree_size
        )),
    }
}

/// Roll the per-session witness results up to one bundle-level line.
///
/// Same weakest-link discipline and the same ranking as referenced
/// artifacts: FAILED outranks UNVERIFIABLE outranks ABSENT outranks VERIFIED.
/// ABSENT is neutral for the VERDICT and never neutral for the summary — a
/// bundle where three of four heads were witnessed is not a witnessed bundle.
pub fn witness_summary(outcomes: &[&WitnessOutcome]) -> WitnessSummary {
    let rank = |st: &Status| match st {
        Status::Failed { .. } => 3,
        Status::Unverifiable { .. } => 2,
        Status::Absent => 1,
        _ => 0,
    };
    let worst = outcomes
        .iter()
        .map(|o| &o.status)
        .max_by_key(|st| rank(st))
        .cloned()
        .unwrap_or(Status::Absent);
    let verified = outcomes.iter().filter(|o| o.status == Status::Verified).count();
    let sessions = outcomes.len();
    let absent = outcomes.iter().filter(|o| o.status == Status::Absent).count();
    let failed = outcomes.iter().filter(|o| o.status.is_failed()).count();
    let mut detail = format!("VERIFIED for {verified} of {sessions} session(s)");
    if absent > 0 {
        detail.push_str(&format!("; {absent} carry no witness material — ABSENT, not a pass"));
    }
    if failed > 0 {
        detail.push_str(&format!("; {failed} carry material that does not hold"));
    }
    WitnessSummary {
        status: worst,
        detail,
        verified,
        sessions,
    }
}
