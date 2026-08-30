//! Hashing and key identification.

use sha2::{Digest, Sha256};

/// Raw SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Lowercase-hex SHA-256, the form VIRP stores everywhere.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Length of a `key_id` in raw bytes (sha256-raw-16).
pub const KEY_ID_LEN: usize = 16;

/// `sha256-raw-16`: `key_id = SHA-256(32-byte raw Ed25519 public key)[0..16]`,
/// rendered as 32 lowercase hex characters.
pub fn key_id_hex(public_key: &[u8; 32]) -> String {
    hex::encode(&sha256(public_key)[..KEY_ID_LEN])
}

/// True iff `s` is exactly 64 lowercase hex characters (a stored digest).
pub fn is_hex_digest_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// True iff `s` is exactly 32 lowercase hex characters — the rendered form of
/// a `sha256-raw-16` key id. Lowercase is required: key ids are compared
/// byte-for-byte against [`key_id_hex`] output, so an uppercase character
/// makes a value that can never name a key.
pub fn is_hex_key_id_32(s: &str) -> bool {
    s.len() == 2 * KEY_ID_LEN && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
