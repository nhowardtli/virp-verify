//! Minisign VERIFICATION of the D-0 seal's detached signature.
//!
//! Verification only, like everything in this crate: public keys in,
//! signatures graded, nothing signed. The trust story is deliberate and
//! asymmetric with `keys.json`:
//!
//! * the SIGNATURE may travel inside the bundle (a signature is a claim; a
//!   wrong one fails) — or arrive out of band;
//! * the PUBLIC KEY must arrive out of band, never from inside the bundle.
//!   The seal document embeds a `seal_public_key` field; it is ignored, and
//!   the report says so. A bundle that named its own trust root would be
//!   vouching for itself.
//!
//! Wire formats (minisign.pub / .minisig, as produced by jedisct1's
//! minisign; confirmed against minisign 0.11 output):
//!
//! ```text
//! public key file:  "untrusted comment: ..." line, then base64 of
//!                   42 bytes = "Ed" || key_id (8, random) || pubkey (32)
//! signature file:   "untrusted comment: ..." line
//!                   base64 of 74 bytes = alg || key_id (8) || signature (64)
//!                     alg "ED": Ed25519 over BLAKE2b-512(file)  (prehashed;
//!                               what current minisign emits)
//!                     alg "Ed": Ed25519 over the file bytes     (legacy)
//!                   "trusted comment: <text>" line
//!                   base64 of the 64-byte global signature:
//!                     Ed25519 over (signature || trusted comment text)
//! ```
//!
//! The key file parser also accepts a bare base64 line and the
//! `minisign:<base64>` form (the string shape the seal uses for its embedded
//! claim) — the FORM is accepted from a file the operator supplies; the
//! bundle's embedded VALUE is still never read.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use blake2::digest::consts::U64;
use blake2::{Blake2b, Digest as _};
use ed25519_dalek::{Signature, VerifyingKey};

/// The minisign key/signature algorithm tags.
const ALG_ED_LEGACY: [u8; 2] = *b"Ed";
const ALG_ED_PREHASHED: [u8; 2] = *b"ED";

const PUBKEY_BLOB_LEN: usize = 2 + 8 + 32;
const SIG_BLOB_LEN: usize = 2 + 8 + 64;

/// A minisign public key: the 8-byte minisign key id (random, assigned at
/// key generation — NOT Docket's derived `sha256-raw-16`) and the Ed25519
/// verifying key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinisignPublicKey {
    key_id: [u8; 8],
    key: VerifyingKey,
}

/// A parsed minisign signature file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinisignSignature {
    alg: [u8; 2],
    key_id: [u8; 8],
    signature: [u8; 64],
    /// The trusted comment and its global signature, when the file carries
    /// them (current minisign always writes both).
    trusted_comment: Option<(String, [u8; 64])>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinisignError {
    /// The text is not a minisign document of the expected kind.
    Malformed(String),
    /// A key or signature blob names an algorithm this module cannot check.
    UnsupportedAlgorithm(String),
    /// The key bytes are not a valid Ed25519 public key.
    InvalidPublicKey,
    /// The signature names a different minisign key id than the supplied
    /// key. Not graded as tampering by this module: the caller cannot check
    /// anything under this key and reports that, with both ids.
    KeyIdMismatch { signature: String, key: String },
    /// Checked and wrong. Deliberately opaque, like [`crate::sig::SigError`].
    BadSignature,
    /// The trusted comment's global signature is wrong: the comment or the
    /// signature was altered after signing.
    BadGlobalSignature,
}

impl std::fmt::Display for MinisignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "not a minisign document: {d}"),
            Self::UnsupportedAlgorithm(a) => write!(f, "unsupported minisign algorithm {a:?}"),
            Self::InvalidPublicKey => write!(f, "minisign key bytes are not a valid Ed25519 public key"),
            Self::KeyIdMismatch { signature, key } => write!(
                f,
                "signature names minisign key id {signature}, the supplied key is {key}"
            ),
            Self::BadSignature => write!(f, "minisign Ed25519 signature verification failed"),
            Self::BadGlobalSignature => {
                write!(f, "minisign trusted-comment global signature verification failed")
            }
        }
    }
}

impl std::error::Error for MinisignError {}

/// The base64 payload lines of a minisign document: every non-empty line
/// that is not a comment line, in order, with comment texts kept aside.
fn payload_lines(text: &str) -> (Vec<&str>, Option<&str>) {
    let mut lines = Vec::new();
    let mut trusted = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("untrusted comment:") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("trusted comment:") {
            trusted = Some(rest.strip_prefix(' ').unwrap_or(rest));
            continue;
        }
        lines.push(line);
    }
    (lines, trusted)
}

impl MinisignPublicKey {
    /// Parse a minisign public key from file text: a standard `.pub` file,
    /// a bare base64 line, or the `minisign:<base64>` string form.
    pub fn from_text(text: &str) -> Result<MinisignPublicKey, MinisignError> {
        let (lines, _) = payload_lines(text);
        let [line] = lines.as_slice() else {
            return Err(MinisignError::Malformed(format!(
                "expected exactly one base64 key line, found {}",
                lines.len()
            )));
        };
        let line = line.strip_prefix("minisign:").unwrap_or(line);
        let blob = BASE64
            .decode(line)
            .map_err(|e| MinisignError::Malformed(format!("key line is not base64: {e}")))?;
        if blob.len() != PUBKEY_BLOB_LEN {
            return Err(MinisignError::Malformed(format!(
                "key blob is {} bytes, expected {PUBKEY_BLOB_LEN}",
                blob.len()
            )));
        }
        if blob[0..2] != ALG_ED_LEGACY {
            return Err(MinisignError::UnsupportedAlgorithm(
                String::from_utf8_lossy(&blob[0..2]).into_owned(),
            ));
        }
        let key_id: [u8; 8] = blob[2..10].try_into().expect("length checked");
        let raw: [u8; 32] = blob[10..42].try_into().expect("length checked");
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| MinisignError::InvalidPublicKey)?;
        Ok(MinisignPublicKey { key_id, key })
    }

    /// The 8-byte minisign key id as 16 lowercase hex characters.
    pub fn key_id_hex(&self) -> String {
        hex::encode(self.key_id)
    }
}

impl MinisignSignature {
    /// Parse a `.minisig` file: the signature blob line, and the trusted
    /// comment plus global signature when present (each requires the other).
    pub fn from_text(text: &str) -> Result<MinisignSignature, MinisignError> {
        let (lines, trusted) = payload_lines(text);
        let (sig_line, global_line) = match (lines.as_slice(), trusted) {
            ([sig], None) => (sig, None),
            ([sig, global], Some(_)) => (sig, Some(global)),
            ([_], Some(_)) => {
                return Err(MinisignError::Malformed(
                    "trusted comment present but no global signature line follows it".to_owned(),
                ))
            }
            ([_, _], None) => {
                return Err(MinisignError::Malformed(
                    "two base64 lines but no trusted comment between them".to_owned(),
                ))
            }
            (other, _) => {
                return Err(MinisignError::Malformed(format!(
                    "expected 1 or 2 base64 lines, found {}",
                    other.len()
                )))
            }
        };
        let blob = BASE64
            .decode(sig_line)
            .map_err(|e| MinisignError::Malformed(format!("signature line is not base64: {e}")))?;
        if blob.len() != SIG_BLOB_LEN {
            return Err(MinisignError::Malformed(format!(
                "signature blob is {} bytes, expected {SIG_BLOB_LEN}",
                blob.len()
            )));
        }
        let alg: [u8; 2] = blob[0..2].try_into().expect("length checked");
        if alg != ALG_ED_LEGACY && alg != ALG_ED_PREHASHED {
            return Err(MinisignError::UnsupportedAlgorithm(
                String::from_utf8_lossy(&alg).into_owned(),
            ));
        }
        let key_id: [u8; 8] = blob[2..10].try_into().expect("length checked");
        let signature: [u8; 64] = blob[10..74].try_into().expect("length checked");
        let trusted_comment = match (trusted, global_line) {
            (Some(comment), Some(line)) => {
                let g = BASE64
                    .decode(line)
                    .map_err(|e| MinisignError::Malformed(format!("global signature line is not base64: {e}")))?;
                let g: [u8; 64] = g.as_slice().try_into().map_err(|_| {
                    MinisignError::Malformed(format!("global signature is {} bytes, expected 64", g.len()))
                })?;
                Some((comment.to_owned(), g))
            }
            _ => None,
        };
        Ok(MinisignSignature {
            alg,
            key_id,
            signature,
            trusted_comment,
        })
    }

    /// The 8-byte minisign key id the signature names, as lowercase hex.
    pub fn key_id_hex(&self) -> String {
        hex::encode(self.key_id)
    }

    /// `"ED"` (prehashed) or `"Ed"` (legacy), for report detail lines.
    pub fn alg_label(&self) -> &'static str {
        if self.alg == ALG_ED_PREHASHED {
            "prehashed (ED, BLAKE2b-512)"
        } else {
            "legacy (Ed, raw bytes)"
        }
    }

    /// Verify this signature over `file_bytes` under `key`.
    ///
    /// Checks, in order: the signature names the supplied key's id; the
    /// Ed25519 signature over the file (prehashed or legacy per the blob's
    /// algorithm tag); and, when the file carries a trusted comment, the
    /// global signature over (signature || trusted comment). Strict
    /// verification throughout, as for chain signatures.
    pub fn verify(&self, key: &MinisignPublicKey, file_bytes: &[u8]) -> Result<(), MinisignError> {
        if self.key_id != key.key_id {
            return Err(MinisignError::KeyIdMismatch {
                signature: self.key_id_hex(),
                key: key.key_id_hex(),
            });
        }
        let sig = Signature::from_bytes(&self.signature);
        if self.alg == ALG_ED_PREHASHED {
            let digest = Blake2b::<U64>::digest(file_bytes);
            key.key
                .verify_strict(&digest, &sig)
                .map_err(|_| MinisignError::BadSignature)?;
        } else {
            key.key
                .verify_strict(file_bytes, &sig)
                .map_err(|_| MinisignError::BadSignature)?;
        }
        if let Some((comment, global)) = &self.trusted_comment {
            let mut msg = Vec::with_capacity(64 + comment.len());
            msg.extend_from_slice(&self.signature);
            msg.extend_from_slice(comment.as_bytes());
            let gsig = Signature::from_bytes(global);
            key.key
                .verify_strict(&msg, &gsig)
                .map_err(|_| MinisignError::BadGlobalSignature)?;
        }
        Ok(())
    }
}
