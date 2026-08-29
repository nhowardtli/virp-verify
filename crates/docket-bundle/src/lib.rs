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

pub mod bundle;
pub mod canonical;
pub mod hash;
pub mod limits;
pub mod minisign;
pub mod seal;
pub mod sig;
pub mod verify;

pub use bundle::{read_key_file, Bundle, BundleError, BundleReport, REPORT_VERSION};
pub use canonical::{genesis_hash_hex, EntryFields, HeadFields, GENESIS_PREFIX, HEAD_VERSION_TAG};
pub use hash::{key_id_hex, sha256, sha256_hex};
pub use limits::Limits;
pub use minisign::{MinisignError, MinisignPublicKey, MinisignSignature};
pub use seal::Seal;
pub use sig::{check_session_key_binding, PublicKey, SessionKeyBinding, SessionKeyError, SigDomain, SigError};
pub use verify::{
    grade_artifact_binding, verify_session, ArtifactCoverage, ArtifactStore, ChainEntry, ChainHead, DetachedSignature,
    Keyring, PropertyReport, SessionChain, SessionReport, SignerReport, SignerTrust, Status, TrustSource, Verdict,
};

/// Pretty JSON for a bundle report (kept here so the CLI needs no serde dep).
pub fn report_to_json_pretty(report: &BundleReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
