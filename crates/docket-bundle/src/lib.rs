//! docket-bundle — the bottom layer of Docket.
//!
//! Docket reads VIRP chains and assembles evidence. This crate holds the
//! bundle format types, the VIRP canonical-byte constructions, hashing, and
//! detached-signature verification.
//!
//! Boundary (absolute): this crate never signs anything, never holds a
//! private key, and never executes against a device. It only reads,
//! verifies and reports. `unsafe` is forbidden workspace-wide.
#![forbid(unsafe_code)]

pub mod canonical;
pub mod hash;
pub mod sig;
pub mod verify;

pub use canonical::{genesis_hash_hex, EntryFields, HeadFields, GENESIS_PREFIX, HEAD_VERSION_TAG};
pub use hash::{key_id_hex, sha256, sha256_hex};
pub use sig::{check_session_key_binding, PublicKey, SessionKeyBinding, SessionKeyError, SigDomain, SigError};
pub use verify::{verify_session, ChainEntry, ChainHead, DetachedSignature, Keyring, PropertyReport, SessionChain, SessionReport, Status, Verdict};
