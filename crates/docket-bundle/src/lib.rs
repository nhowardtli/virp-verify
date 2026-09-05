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
pub mod camera;
pub mod canonical;
pub mod hash;
pub mod limits;
pub mod minisign;
pub mod producer;
pub mod seal;
pub mod sig;
pub mod verify;
pub mod witness;

pub use bundle::{
    bundle_display_name, read_key_file, validate_session_input, BoundaryReport, Bundle, BundleError, BundleReport,
    CaptureSummary, ManifestReferencedArtifact, RedactedEntry, Redaction, RedactionAudit, ReferencedCitation,
    ReferencedSummary, SourceDeviceAnswer, SourceDeviceReport, WitnessCheck, REPORT_VERSION,
};
pub use camera::{
    cited_digests, claimed_camera_ids, grade_capture_completeness, summarise_sensor, CaptureGrade, CaptureOutage,
    CaptureOverlap, CapturePolicy, CaptureReport, ExternalPredecessorGap, SensorSummary, CITED_LEAF, CITED_SEGMENT,
    CITED_VALIDATOR_OUTPUT, SENSOR_CAPTION,
};
pub use canonical::{genesis_hash_hex, EntryFields, HeadFields, GENESIS_PREFIX, HEAD_VERSION_TAG};
pub use hash::{key_id_hex, sha256, sha256_hex};
pub use limits::Limits;
pub use minisign::{MinisignError, MinisignPublicKey, MinisignSignature};
pub use producer::{canonical_json_bytes, grade_producer_signatures, read_producer_key_file, ProducerSignerReport};
pub use seal::Seal;
pub use sig::{check_session_key_binding, PublicKey, SessionKeyBinding, SessionKeyError, SigDomain, SigError};
pub use verify::{
    grade_artifact_binding, grade_referenced_artifact_binding, verify_session, ArtifactCoverage, ArtifactStore,
    CarriedReferenced, ChainEntry, ChainHead, DetachedSignature, Keyring, NotCarried, PropertyReport,
    ReferencedCoverage, ReferencedDefect, ReferencedEntry, ReferencedStore, SessionChain, SessionReport, SignerReport,
    SignerTrust, Status, TrustSource, Verdict,
};
pub use witness::{
    grade_witness, grade_witness_consistency, leaf_hash, node_hash, verify_consistency, verify_inclusion,
    LiveConsistency, ManifestWitness, ManifestWitnessSession, ProofError, Sth, WitnessLeaf, WitnessMaterial,
    WitnessOutcome, WitnessProofFile, WitnessSthFile, WitnessSummary, PROOF_FILE_VERSION, STH_FILE_VERSION, TAG_LEAF,
    TAG_STH,
};
pub use witness::{parse_consistency, parse_sth, ConsistencyBody};

/// Pretty JSON for a bundle report (kept here so the CLI needs no serde dep).
pub fn report_to_json_pretty(report: &BundleReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
