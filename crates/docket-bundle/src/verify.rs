//! The verifier: walks one session's chain and grades each property.
//!
//! Three tiers, each independent (SECURITY.md "Three verification tiers"):
//!
//! | tier | Docket needs | what it proves |
//! | --- | --- | --- |
//! | keyless | nothing | hash + genesis + prev-link + contiguity + head commitment. The head's length claim is **unauthenticated**. |
//! | symmetric (note only) | `K_chain` — which Docket **never holds** | Docket cannot check `chain_hmac`/`head_hmac`. Their presence is reported as *operator-attested, unverifiable by this verifier*. Never a pass. |
//! | asymmetric | the signer's PUBLIC key | Ed25519 over the head and every entry, under the session-granularity key rule. |
//!
//! The vocabulary is deliberately incapable of collapsing these into one
//! green checkmark: see [`Status`] and [`Verdict`].

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

/// Public keys the verifier may use, addressed by `key_id`.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    keys: BTreeMap<String, PublicKey>,
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring::default()
    }

    /// Add a key. Its `key_id` is DERIVED from the key bytes, never taken on
    /// trust from the bundle — a bundle that labels a key with the wrong id
    /// simply won't find it.
    pub fn insert(&mut self, key: PublicKey) {
        self.keys.insert(key.key_id().to_owned(), key);
    }

    pub fn get(&self, key_id: &str) -> Option<&PublicKey> {
        self.keys.get(key_id)
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
    /// Checked and wrong. Tampering or corruption.
    Failed { detail: String },
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

/// The overall verdict for a session. Four words, never one checkmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// At least one property FAILED. The chain is tampered or corrupt.
    Failed,
    /// Every keyless property holds, and the head plus every entry carry a
    /// valid Ed25519 signature under a supplied public key. This verifier
    /// proved authenticity without any secret.
    CryptographicallyVerified,
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
// The walk
// ---------------------------------------------------------------------------

/// Verify one session against the supplied public keys (which may be empty:
/// that is the keyless tier).
pub fn verify_session(chain: &SessionChain, keyring: &Keyring) -> SessionReport {
    let mut props: Vec<PropertyReport> = Vec::with_capacity(property::ALL.len());
    let push = |props: &mut Vec<PropertyReport>, name: &str, status: Status, detail: String| {
        props.push(PropertyReport { name: name.to_owned(), status, detail });
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
                status = Status::failed(format!("stored chain_entry_hash at sequence {} is not a 64-hex digest", e.fields.sequence));
                break;
            }
            if computed_hashes[i] != e.chain_entry_hash {
                status = Status::failed(format!("entry hash mismatch at sequence {}", e.fields.sequence));
                break;
            }
        }
        if n == 0 {
            status = Status::failed("session has no entries");
        }
        push(&mut props, property::ENTRY_HASHES, status, format!("{n} entries recomputed (SHA-256 over canonical bytes)"));
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
        push(&mut props, property::CONTIGUITY, status, format!("sequences 0..{} contiguous, all in session {:?}", n.saturating_sub(1), chain.session_id));
    }

    // genesis
    {
        let expected = genesis_hash_hex(&chain.session_id);
        let status = match chain.entries.first() {
            None => Status::failed("session has no entries"),
            Some(e0) if e0.fields.sequence != 0 => Status::failed(format!("first entry is sequence {}, not 0", e0.fields.sequence)),
            Some(e0) if e0.fields.previous_entry_hash != expected => Status::failed("sequence 0 previous_entry_hash is not the session genesis"),
            Some(_) => Status::Verified,
        };
        push(&mut props, property::GENESIS, status, format!("sha256(\"VIRP_CHAIN_GENESIS:\" + session_id) = {expected}"));
    }

    // links: previous_entry_hash[i] == computed hash[i-1]
    {
        let mut status = Status::Verified;
        for i in 1..n {
            if chain.entries[i].fields.previous_entry_hash != computed_hashes[i - 1] {
                status = Status::failed(format!("previous hash mismatch at sequence {}", chain.entries[i].fields.sequence));
                break;
            }
        }
        if n == 0 {
            status = Status::failed("session has no entries");
        }
        push(&mut props, property::LINKS, status, format!("{} links checked against recomputed hashes", n.saturating_sub(1)));
    }

    // head_commitment: the head names the last recomputed entry.
    // This proves the head and entries AGREE; it does NOT authenticate the
    // head (that is the HMAC / signature's job).
    let head_status = match (&chain.head, chain.entries.last(), computed_hashes.last()) {
        (None, _, _) => Status::failed("head record missing; chain length cannot be authenticated"),
        (Some(_), None, _) | (Some(_), _, None) => Status::failed("head present but session has no entries"),
        (Some(h), Some(last), Some(last_hash)) => {
            if h.fields.session_id != chain.session_id {
                Status::failed(format!("head belongs to session {:?}, not {:?}", h.fields.session_id, chain.session_id))
            } else if h.fields.last_sequence != last.fields.sequence {
                Status::failed(format!("head commits to last_sequence {} but last entry is {}", h.fields.last_sequence, last.fields.sequence))
            } else if h.fields.last_entry_hash != *last_hash {
                Status::failed(format!("head does not match final verified entry at sequence {}", last.fields.sequence))
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
            Some(h) => format!("head commits to sequence {} hash {}", h.fields.last_sequence, h.fields.last_entry_hash),
            None => "no head record".to_owned(),
        },
    );

    // --- symmetric tier: NOTE ONLY ----------------------------------------
    // Docket does not hold K_chain. These are graded present/absent and, when
    // present, reported as operator-attested. Never Verified.
    {
        let with = chain.entries.iter().filter(|e| e.chain_hmac.is_some()).count();
        let malformed = chain.entries.iter().filter(|e| e.chain_hmac.as_deref().is_some_and(|h| !is_hex_digest_64(h))).count();
        let status = if malformed > 0 {
            Status::failed(format!("{malformed} chain_hmac values are not 64-hex digests"))
        } else if with == 0 {
            Status::Absent
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
        push(&mut props, property::HEAD_HMAC, status, "HMAC-SHA256 under the operator's K_chain, which this verifier does not hold".to_owned());
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
        (KeyState::Unavailable(kid), _, _) => Status::unverifiable(format!("head is signed under key_id {kid}, which this verifier was not given")),
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
        chain.entries.iter().map(|e| (e.fields.sequence, e.signature.as_ref().map(|s| s.signing_key_id.as_str()))),
    );
    let binding_status = match &binding {
        Ok(SessionKeyBinding::Bound { .. }) => Status::Verified,
        Ok(SessionKeyBinding::UnsignedSession { .. }) => Status::Absent,
        Err(e) => Status::failed(e.to_string()),
    };
    let binding_ok = matches!(binding, Ok(SessionKeyBinding::Bound { .. }));
    push(
        &mut props,
        property::SESSION_KEY_BINDING,
        binding_status,
        match &binding {
            Ok(SessionKeyBinding::Bound { key_id }) => format!("every entry signed under the head's key_id {key_id}"),
            Ok(SessionKeyBinding::UnsignedSession { entries_with_signatures }) => {
                format!("head unsigned; {entries_with_signatures}/{n} entries carry signatures (not graded)")
            }
            Err(_) => "session-granularity key rule violated".to_owned(),
        },
    );

    // entry_signatures
    let entry_sig_status = match &key_state {
        KeyState::UnsignedHead => Status::Absent,
        KeyState::BadScheme(_) => Status::failed("head signature scheme unsupported; entry signatures not graded"),
        KeyState::Unavailable(kid) => Status::unverifiable(format!("entries are signed under key_id {kid}, which this verifier was not given")),
        KeyState::Available(pk) => {
            if !binding_ok {
                Status::failed("session key binding failed; entry signatures cannot be trusted")
            } else {
                let mut status = Status::Verified;
                for (i, e) in chain.entries.iter().enumerate() {
                    // binding_ok guarantees a signature is present with the head's key id.
                    let Some(sig) = e.signature.as_ref() else {
                        status = Status::failed(format!("internal: missing signature at sequence {} after binding check", e.fields.sequence));
                        break;
                    };
                    if sig.signature_scheme != SCHEME {
                        status = Status::failed(format!("entry at sequence {} has signature_scheme {:?}, not {SCHEME}", e.fields.sequence, sig.signature_scheme));
                        break;
                    }
                    if let Err(err) = pk.verify_hex(SigDomain::Entry, &canonicals[i], &sig.signature_hex) {
                        status = Status::failed(format!("Ed25519 signature verification failed at sequence {} ({err})", e.fields.sequence));
                        break;
                    }
                }
                status
            }
        }
    };
    let entry_sigs_verified = entry_sig_status == Status::Verified;
    push(
        &mut props,
        property::ENTRY_SIGNATURES,
        entry_sig_status,
        format!("{n} entries, {SCHEME}, domain tag VIRP-CHAIN-ENTRY-SIG-v1"),
    );

    // --- verdict ----------------------------------------------------------
    let any_failed = props.iter().any(|p| p.status.is_failed());
    let any_operator_attested = props.iter().any(|p| p.status == Status::OperatorAttested);
    let any_unverifiable = props.iter().any(|p| matches!(p.status, Status::Unverifiable { .. }));
    let verdict = if any_failed {
        Verdict::Failed
    } else if head_sig_verified && binding_ok && entry_sigs_verified {
        Verdict::CryptographicallyVerified
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
        verdict,
    }
}
