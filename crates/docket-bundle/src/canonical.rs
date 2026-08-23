//! VIRP canonical byte constructions, re-implemented from the protocol's
//! documented wire facts (DRAFT07-NOTES §2, `include/virp_chain.h`,
//! `build_canonical_json` / `head_canonical` / `compute_genesis_hash`).
//!
//! Nothing here is copied from the C tree. Everything here is proven by
//! reproducing the golden vectors byte-for-byte (see `tests/`).
//!
//! Rules, stated once:
//!
//! * **Entry canonical** — exactly twelve fields in this fixed order, compact
//!   JSON (no whitespace), string values written RAW (the producer does not
//!   escape; neither do we), integers in plain decimal:
//!   `artifact_hash, artifact_hash_alg, artifact_id, artifact_schema_version,
//!   artifact_type, monotonic_ns, previous_entry_hash, sequence, session_id,
//!   signer_node_id, signer_org_id, timestamp_ns`.
//!   `chain_entry_hash`, `chain_hmac` and the D-1 signature columns are NOT
//!   part of the canonical.
//! * **Genesis** — the `previous_entry_hash` of sequence 0 is
//!   `hex(SHA-256("VIRP_CHAIN_GENESIS:" || session_id))`.
//! * **Head canonical** —
//!   `{"last_entry_hash":"…","last_sequence":N,"session_id":"…","v":"VIRP-CHAIN-HEAD-v1"}`.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::hash::sha256_hex;

/// Prefix hashed with the session id to produce the genesis hash.
pub const GENESIS_PREFIX: &str = "VIRP_CHAIN_GENESIS:";

/// Version tag carried inside every head canonical.
pub const HEAD_VERSION_TAG: &str = "VIRP-CHAIN-HEAD-v1";

/// The twelve canonical fields of a VIRP chain entry — the exact inputs to
/// the entry hash, the `chain_hmac`, and the D-1 entry signature.
///
/// Integer widths mirror the producer's: `monotonic_ns`/`timestamp_ns` are
/// unsigned 64-bit (`%llu`), `sequence` is signed 64-bit (`%lld`),
/// `signer_node_id` is unsigned 32-bit (`%u`). Rust's `Display` for these
/// types produces the same decimal text as those printf conversions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFields {
    pub artifact_hash: String,
    pub artifact_hash_alg: String,
    pub artifact_id: String,
    pub artifact_schema_version: String,
    pub artifact_type: String,
    pub monotonic_ns: u64,
    pub previous_entry_hash: String,
    pub sequence: i64,
    pub session_id: String,
    pub signer_node_id: u32,
    pub signer_org_id: String,
    pub timestamp_ns: u64,
}

impl EntryFields {
    /// The canonical bytes: what gets hashed, HMAC'd and (D-1) signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(512);
        // Writing to a String cannot fail; unwrap-free via `let _ =` would
        // hide a logic error, so use expect with a fixed message.
        write!(
            s,
            "{{\"artifact_hash\":\"{}\",\
\"artifact_hash_alg\":\"{}\",\
\"artifact_id\":\"{}\",\
\"artifact_schema_version\":\"{}\",\
\"artifact_type\":\"{}\",\
\"monotonic_ns\":{},\
\"previous_entry_hash\":\"{}\",\
\"sequence\":{},\
\"session_id\":\"{}\",\
\"signer_node_id\":{},\
\"signer_org_id\":\"{}\",\
\"timestamp_ns\":{}}}",
            self.artifact_hash,
            self.artifact_hash_alg,
            self.artifact_id,
            self.artifact_schema_version,
            self.artifact_type,
            self.monotonic_ns,
            self.previous_entry_hash,
            self.sequence,
            self.session_id,
            self.signer_node_id,
            self.signer_org_id,
            self.timestamp_ns,
        )
        .expect("writing to a String is infallible");
        s.into_bytes()
    }

    /// `hex(SHA-256(canonical_bytes))` — the value a faithful producer stores
    /// as `chain_entry_hash`.
    pub fn entry_hash_hex(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }

    /// Strict inverse of [`EntryFields::canonical_bytes`].
    ///
    /// The format is rigid (fixed key order, no whitespace, raw strings), so
    /// it can be scanned deterministically without a general JSON parser:
    /// each string value runs up to the literal start of the next key. A
    /// string value that itself contained such a delimiter would be
    /// inherently ambiguous in the wire format; the round-trip check in the
    /// caller (re-serialise and compare) catches that case rather than
    /// silently accepting it.
    pub fn parse_canonical(bytes: &[u8]) -> Result<EntryFields, CanonicalParseError> {
        let s = std::str::from_utf8(bytes).map_err(|_| CanonicalParseError::NotUtf8)?;
        let mut cur = Cursor { s, pos: 0 };

        cur.expect("{\"artifact_hash\":\"")?;
        let artifact_hash = cur.take_until("\",\"artifact_hash_alg\":\"")?;
        let artifact_hash_alg = cur.take_until("\",\"artifact_id\":\"")?;
        let artifact_id = cur.take_until("\",\"artifact_schema_version\":\"")?;
        let artifact_schema_version = cur.take_until("\",\"artifact_type\":\"")?;
        let artifact_type = cur.take_until("\",\"monotonic_ns\":")?;
        let monotonic_ns = cur.take_until(",\"previous_entry_hash\":\"")?;
        let previous_entry_hash = cur.take_until("\",\"sequence\":")?;
        let sequence = cur.take_until(",\"session_id\":\"")?;
        let session_id = cur.take_until("\",\"signer_node_id\":")?;
        let signer_node_id = cur.take_until(",\"signer_org_id\":\"")?;
        let signer_org_id = cur.take_until("\",\"timestamp_ns\":")?;
        let timestamp_ns = cur.take_until("}")?;
        if cur.pos != s.len() {
            return Err(CanonicalParseError::TrailingBytes);
        }

        let fields = EntryFields {
            artifact_hash: artifact_hash.to_owned(),
            artifact_hash_alg: artifact_hash_alg.to_owned(),
            artifact_id: artifact_id.to_owned(),
            artifact_schema_version: artifact_schema_version.to_owned(),
            artifact_type: artifact_type.to_owned(),
            monotonic_ns: parse_int(monotonic_ns, "monotonic_ns")?,
            previous_entry_hash: previous_entry_hash.to_owned(),
            sequence: parse_int(sequence, "sequence")?,
            session_id: session_id.to_owned(),
            signer_node_id: parse_int(signer_node_id, "signer_node_id")?,
            signer_org_id: signer_org_id.to_owned(),
            timestamp_ns: parse_int(timestamp_ns, "timestamp_ns")?,
        };
        // Round-trip guard: the only way this differs is an ambiguous or
        // non-canonical encoding (e.g. "+1", leading zeros, embedded keys).
        if fields.canonical_bytes() != bytes {
            return Err(CanonicalParseError::NotCanonical);
        }
        Ok(fields)
    }
}

/// `hex(SHA-256("VIRP_CHAIN_GENESIS:" || session_id))` — the expected
/// `previous_entry_hash` of sequence 0.
pub fn genesis_hash_hex(session_id: &str) -> String {
    let mut buf = Vec::with_capacity(GENESIS_PREFIX.len() + session_id.len());
    buf.extend_from_slice(GENESIS_PREFIX.as_bytes());
    buf.extend_from_slice(session_id.as_bytes());
    sha256_hex(&buf)
}

/// The per-session head record's canonical inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadFields {
    pub session_id: String,
    pub last_sequence: i64,
    pub last_entry_hash: String,
}

impl HeadFields {
    /// The head canonical bytes: what gets HMAC'd and (D-1) signed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(192);
        write!(
            s,
            "{{\"last_entry_hash\":\"{}\",\"last_sequence\":{},\"session_id\":\"{}\",\"v\":\"{}\"}}",
            self.last_entry_hash, self.last_sequence, self.session_id, HEAD_VERSION_TAG
        )
        .expect("writing to a String is infallible");
        s.into_bytes()
    }

    /// Strict inverse of [`HeadFields::canonical_bytes`] (same round-trip guard).
    pub fn parse_canonical(bytes: &[u8]) -> Result<HeadFields, CanonicalParseError> {
        let s = std::str::from_utf8(bytes).map_err(|_| CanonicalParseError::NotUtf8)?;
        let mut cur = Cursor { s, pos: 0 };
        cur.expect("{\"last_entry_hash\":\"")?;
        let last_entry_hash = cur.take_until("\",\"last_sequence\":")?;
        let last_sequence = cur.take_until(",\"session_id\":\"")?;
        let session_id = cur.take_until("\",\"v\":\"")?;
        let v = cur.take_until("\"}")?;
        if cur.pos != s.len() {
            return Err(CanonicalParseError::TrailingBytes);
        }
        if v != HEAD_VERSION_TAG {
            return Err(CanonicalParseError::WrongHeadVersion(v.to_owned()));
        }
        let fields = HeadFields {
            session_id: session_id.to_owned(),
            last_sequence: parse_int(last_sequence, "last_sequence")?,
            last_entry_hash: last_entry_hash.to_owned(),
        };
        if fields.canonical_bytes() != bytes {
            return Err(CanonicalParseError::NotCanonical);
        }
        Ok(fields)
    }
}

/// Why a byte string was rejected as a canonical entry/head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalParseError {
    NotUtf8,
    /// Expected literal text was not found at the current position.
    Expected(String),
    /// Bytes remained after the closing brace.
    TrailingBytes,
    /// An integer field did not parse as its declared width.
    BadInteger(&'static str),
    /// The head `v` field is not `VIRP-CHAIN-HEAD-v1`.
    WrongHeadVersion(String),
    /// Parsed fine but does not re-serialise to the same bytes.
    NotCanonical,
}

impl std::fmt::Display for CanonicalParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "canonical bytes are not UTF-8"),
            Self::Expected(lit) => write!(f, "expected literal {lit:?}"),
            Self::TrailingBytes => write!(f, "trailing bytes after canonical object"),
            Self::BadInteger(name) => write!(f, "field {name} is not a valid integer"),
            Self::WrongHeadVersion(v) => write!(f, "head version tag {v:?} is not {HEAD_VERSION_TAG}"),
            Self::NotCanonical => write!(f, "bytes do not round-trip through the canonical encoder"),
        }
    }
}

impl std::error::Error for CanonicalParseError {}

struct Cursor<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn expect(&mut self, lit: &str) -> Result<(), CanonicalParseError> {
        if self.s[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(CanonicalParseError::Expected(lit.to_owned()))
        }
    }

    /// Return the text up to (not including) `delim`, and consume `delim`.
    fn take_until(&mut self, delim: &str) -> Result<&'a str, CanonicalParseError> {
        let rest = &self.s[self.pos..];
        match rest.find(delim) {
            Some(i) => {
                let out = &rest[..i];
                self.pos += i + delim.len();
                Ok(out)
            }
            None => Err(CanonicalParseError::Expected(delim.to_owned())),
        }
    }
}

fn parse_int<T: std::str::FromStr>(text: &str, name: &'static str) -> Result<T, CanonicalParseError> {
    text.parse::<T>().map_err(|_| CanonicalParseError::BadInteger(name))
}
