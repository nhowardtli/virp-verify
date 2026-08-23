//! The D-0 seal (`virp-seal/1`) as an optional anchor.
//!
//! The seal is the operator's signed attestation of every session head as
//! of the snapshot time. Docket uses it two ways:
//!
//! 1. **Internal consistency** — recompute the Merkle root over `sessions[]`
//!    using the seal's own stated leaf/node rules and compare to
//!    `merkle.root`.
//! 2. **Anchoring** — for a session in a bundle, compare the bundle's
//!    verified head (`last_entry_hash`, `last_sequence + 1`) with the seal's
//!    `head_hash` / `entry_count` for that session.
//!
//! What Docket does NOT do (yet): verify the seal's minisign signature or
//! its OpenTimestamps proof. Both are reported as *not checked*.
//!
//! The seal says of itself: it "does not and cannot prove the absence of
//! alteration prior to the seal date". Docket repeats that, it does not
//! launder it.

use serde::{Deserialize, Serialize};

use crate::hash::{is_hex_digest_64, sha256};
use crate::verify::Status;

/// One session as listed in the seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealSession {
    pub session_id: String,
    pub entry_count: u64,
    pub head_hash: String,
    #[serde(default)]
    pub in_flight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealMerkle {
    pub root: String,
    pub leaf_count: u64,
}

/// The subset of the seal document Docket reads. Unknown fields are ignored
/// so the verbatim seal file parses as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub seal_version: String,
    pub created_at: String,
    pub sealed_by: String,
    pub seal_public_key: String,
    pub sessions: Vec<SealSession>,
    pub merkle: SealMerkle,
    #[serde(default)]
    pub residual_disclosure: String,
}

pub const SEAL_VERSION: &str = "virp-seal/1";

#[derive(Debug)]
pub enum SealError {
    Json(serde_json::Error),
    WrongVersion(String),
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "seal is not valid JSON: {e}"),
            Self::WrongVersion(v) => write!(f, "seal_version {v:?} is not {SEAL_VERSION}"),
        }
    }
}

impl std::error::Error for SealError {}

impl Seal {
    pub fn from_slice(bytes: &[u8]) -> Result<Seal, SealError> {
        let seal: Seal = serde_json::from_slice(bytes).map_err(SealError::Json)?;
        if seal.seal_version != SEAL_VERSION {
            return Err(SealError::WrongVersion(seal.seal_version));
        }
        Ok(seal)
    }

    pub fn session(&self, session_id: &str) -> Option<&SealSession> {
        self.sessions.iter().find(|s| s.session_id == session_id)
    }

    /// Recompute the Merkle root from `sessions[]` per the seal's rules:
    ///
    /// * `leaf_i = SHA-256(0x00 || session_id || 0x1F || entry_count || 0x1F || head_hash)`
    ///   over sessions in listed order; `entry_count` decimal ASCII,
    ///   `head_hash` its 64 hex ASCII chars; no length prefixes.
    /// * `node = SHA-256(0x01 || left || right)` over raw 32-byte digests,
    ///   left to right; an odd trailing node is promoted unchanged.
    /// * a single leaf is the root.
    pub fn recompute_merkle_root(&self) -> Option<String> {
        if self.sessions.is_empty() {
            return None;
        }
        let mut level: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .map(|s| {
                let mut buf = Vec::with_capacity(1 + s.session_id.len() + 1 + 20 + 1 + 64);
                buf.push(0x00);
                buf.extend_from_slice(s.session_id.as_bytes());
                buf.push(0x1f);
                buf.extend_from_slice(s.entry_count.to_string().as_bytes());
                buf.push(0x1f);
                buf.extend_from_slice(s.head_hash.as_bytes());
                sha256(&buf)
            })
            .collect();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                if pair.len() == 2 {
                    let mut buf = [0u8; 65];
                    buf[0] = 0x01;
                    buf[1..33].copy_from_slice(&pair[0]);
                    buf[33..].copy_from_slice(&pair[1]);
                    next.push(sha256(&buf));
                } else {
                    next.push(pair[0]);
                }
            }
            level = next;
        }
        Some(hex::encode(level[0]))
    }

    /// Grade the seal's internal consistency: listed order ascending by
    /// session_id (as UTF-8 bytes), leaf_count, well-formed head hashes, and
    /// the recomputed Merkle root.
    pub fn consistency(&self) -> Status {
        if self.sessions.len() as u64 != self.merkle.leaf_count {
            return Status::failed(format!(
                "seal lists {} sessions but merkle.leaf_count is {}",
                self.sessions.len(),
                self.merkle.leaf_count
            ));
        }
        if let Some(bad) = self.sessions.iter().find(|s| !is_hex_digest_64(&s.head_hash)) {
            return Status::failed(format!(
                "seal head_hash for {:?} is not a 64-hex digest",
                bad.session_id
            ));
        }
        if let Some(w) = self
            .sessions
            .windows(2)
            .find(|w| w[0].session_id.as_bytes() >= w[1].session_id.as_bytes())
        {
            return Status::failed(format!(
                "seal sessions are not strictly ascending by session_id at {:?}",
                w[1].session_id
            ));
        }
        match self.recompute_merkle_root() {
            None => Status::failed("seal lists no sessions"),
            Some(root) if root == self.merkle.root => Status::Verified,
            Some(root) => Status::failed(format!(
                "recomputed merkle root {root} != seal merkle.root {}",
                self.merkle.root
            )),
        }
    }

    /// Grade a bundle session's verified head against the seal.
    ///
    /// `last_sequence`/`last_entry_hash` must already have been verified by
    /// the chain walk; this only asks whether the seal attests the same head.
    pub fn anchor(&self, session_id: &str, last_sequence: i64, last_entry_hash: &str) -> Status {
        match self.session(session_id) {
            None => Status::Absent,
            Some(s) => {
                let bundle_count = u64::try_from(last_sequence + 1).unwrap_or(0);
                if s.head_hash == last_entry_hash && s.entry_count == bundle_count {
                    Status::Verified
                } else if s.entry_count < bundle_count && s.in_flight {
                    // The session has grown since the snapshot; the seal
                    // attests a prefix we cannot isolate from the head alone.
                    Status::unverifiable(format!(
                        "seal attests {} entries (head {}) for an in-flight session; bundle has {} — seal covers a prefix only",
                        s.entry_count,
                        &s.head_hash[..16],
                        bundle_count
                    ))
                } else {
                    Status::failed(format!(
                        "seal attests head {} with {} entries; bundle head is {} with {} entries",
                        s.head_hash, s.entry_count, last_entry_hash, bundle_count
                    ))
                }
            }
        }
    }
}
