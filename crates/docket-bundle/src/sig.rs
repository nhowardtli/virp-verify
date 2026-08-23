//! Detached Ed25519 signature verification (VIRP D-1, scheme
//! `ed25519-detached-v1`).
//!
//! Construction (normative, DRAFT07-NOTES §2):
//!
//! ```text
//! entry_sig = Ed25519.sign(sk, "VIRP-CHAIN-ENTRY-SIG-v1" 0x00 || canonical_entry_bytes)
//! head_sig  = Ed25519.sign(sk, "VIRP-CHAIN-HEAD-SIG-v1"  0x00 || head_canonical_bytes)
//! ```
//!
//! The tag INCLUDES its terminating NUL. It is prepended to the signature
//! input only; it is never stored and never enters any canonical.
//!
//! This module holds **public keys only**. There is no signing code in
//! Docket and there never will be — see the crate-level boundary.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::hash::key_id_hex;

/// Scheme identifier as it appears in bundles.
pub const SCHEME: &str = "ed25519-detached-v1";

/// Domain tag for entry signatures, including the signed NUL (24 bytes).
pub const ENTRY_SIG_TAG: &[u8] = b"VIRP-CHAIN-ENTRY-SIG-v1\0";
/// Domain tag for head signatures, including the signed NUL (23 bytes).
pub const HEAD_SIG_TAG: &[u8] = b"VIRP-CHAIN-HEAD-SIG-v1\0";

/// Which of the two signed object kinds a signature claims to cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigDomain {
    Entry,
    Head,
}

impl SigDomain {
    pub fn tag(self) -> &'static [u8] {
        match self {
            SigDomain::Entry => ENTRY_SIG_TAG,
            SigDomain::Head => HEAD_SIG_TAG,
        }
    }
}

/// `TAG || canonical` — the exact bytes the signer signed.
pub fn signed_input(domain: SigDomain, canonical: &[u8]) -> Vec<u8> {
    let tag = domain.tag();
    let mut v = Vec::with_capacity(tag.len() + canonical.len());
    v.extend_from_slice(tag);
    v.extend_from_slice(canonical);
    v
}

/// An Ed25519 public key with its derived `key_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    key: VerifyingKey,
    key_id: String,
}

impl PublicKey {
    /// From the 32 raw public-key bytes. Rejects byte strings that are not a
    /// valid compressed Edwards point.
    pub fn from_bytes(raw: &[u8; 32]) -> Result<PublicKey, SigError> {
        let key = VerifyingKey::from_bytes(raw).map_err(|_| SigError::InvalidPublicKey)?;
        Ok(PublicKey {
            key,
            key_id: key_id_hex(raw),
        })
    }

    /// From 64 lowercase/uppercase hex characters.
    pub fn from_hex(hex_str: &str) -> Result<PublicKey, SigError> {
        let bytes = hex::decode(hex_str).map_err(|_| SigError::InvalidPublicKey)?;
        let raw: [u8; 32] = bytes.as_slice().try_into().map_err(|_| SigError::InvalidPublicKey)?;
        PublicKey::from_bytes(&raw)
    }

    /// The raw 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// `sha256-raw-16` key id, 32 lowercase hex chars.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Verify a detached signature over `canonical` under `domain`.
    ///
    /// Uses strict verification (rejects non-canonical `S`, small-order
    /// points). Any valid libsodium/ed25519 signature passes strict
    /// verification; anything malleable does not.
    pub fn verify(&self, domain: SigDomain, canonical: &[u8], signature: &[u8; 64]) -> Result<(), SigError> {
        let sig = Signature::from_bytes(signature);
        let input = signed_input(domain, canonical);
        self.key.verify_strict(&input, &sig).map_err(|_| SigError::BadSignature)
    }

    /// Like [`PublicKey::verify`] but takes the 128-hex-char stored form.
    pub fn verify_hex(&self, domain: SigDomain, canonical: &[u8], signature_hex: &str) -> Result<(), SigError> {
        let sig = signature_from_hex(signature_hex)?;
        self.verify(domain, canonical, &sig)
    }
}

/// Decode a stored 128-hex-char signature.
pub fn signature_from_hex(signature_hex: &str) -> Result<[u8; 64], SigError> {
    let bytes = hex::decode(signature_hex).map_err(|_| SigError::MalformedSignature)?;
    bytes.as_slice().try_into().map_err(|_| SigError::MalformedSignature)
}

/// Signature-layer errors. `BadSignature` is deliberately opaque: the
/// verifier reports *that* it failed, never a hint about how close it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    InvalidPublicKey,
    MalformedSignature,
    BadSignature,
}

impl std::fmt::Display for SigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "public key is not a valid Ed25519 key"),
            Self::MalformedSignature => write!(f, "signature is not 64 bytes of hex"),
            Self::BadSignature => write!(f, "Ed25519 signature verification failed"),
        }
    }
}

impl std::error::Error for SigError {}

// ---------------------------------------------------------------------------
// Session-granularity key binding (D-1, normative)
// ---------------------------------------------------------------------------

/// Outcome of the session-granularity key rule for one session.
///
/// Per-session chains restart at sequence 0, so a session is signed under
/// exactly one key. In a head-signed session every entry MUST carry a
/// signature whose `key_id` equals the head's. A missing entry signature
/// (stripped) or a differing `key_id` is a **failure at tampering
/// severity** — the signature columns sit outside the canonical, so the
/// signature is their only integrity protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyBinding {
    /// The head is unsigned (pre-D-1 session). Entries are counted unsigned;
    /// this is never a failure.
    UnsignedSession { entries_with_signatures: usize },
    /// Head-signed and every entry is signed under the head's key.
    Bound { key_id: String },
}

/// Why the session-granularity rule failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyError {
    /// Head-signed session, but the entry at `sequence` carries no signature.
    StrippedSignature { sequence: i64 },
    /// Head-signed session, but the entry at `sequence` is signed under a
    /// different key than the head.
    KeyIdMismatch {
        sequence: i64,
        entry_key_id: String,
        head_key_id: String,
    },
}

impl std::fmt::Display for SessionKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StrippedSignature { sequence } => write!(
                f,
                "missing Ed25519 signature at sequence {sequence} in a head-signed session (stripped signature)"
            ),
            Self::KeyIdMismatch {
                sequence,
                entry_key_id,
                head_key_id,
            } => write!(
                f,
                "signature key_id mismatch at sequence {sequence} (entry {entry_key_id}, head {head_key_id})"
            ),
        }
    }
}

impl std::error::Error for SessionKeyError {}

/// Apply the session-granularity rule.
///
/// `head_key_id` is the head's `signing_key_id` (None = unsigned head).
/// `entries` yields `(sequence, entry signing_key_id)` in chain order
/// (None = entry carries no signature). The first violation is returned.
pub fn check_session_key_binding<'a, I>(
    head_key_id: Option<&str>,
    entries: I,
) -> Result<SessionKeyBinding, SessionKeyError>
where
    I: IntoIterator<Item = (i64, Option<&'a str>)>,
{
    match head_key_id {
        None => {
            let signed = entries.into_iter().filter(|(_, k)| k.is_some()).count();
            Ok(SessionKeyBinding::UnsignedSession {
                entries_with_signatures: signed,
            })
        }
        Some(head) => {
            for (sequence, entry_key) in entries {
                match entry_key {
                    None => return Err(SessionKeyError::StrippedSignature { sequence }),
                    Some(k) if k != head => {
                        return Err(SessionKeyError::KeyIdMismatch {
                            sequence,
                            entry_key_id: k.to_owned(),
                            head_key_id: head.to_owned(),
                        })
                    }
                    Some(_) => {}
                }
            }
            Ok(SessionKeyBinding::Bound {
                key_id: head.to_owned(),
            })
        }
    }
}
