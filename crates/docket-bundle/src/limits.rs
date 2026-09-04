//! Resource ceilings for reading a bundle.
//!
//! The reader loads whole JSON files into memory, deserialises every entry,
//! and builds further vectors of canonical bytes and computed hashes. Nothing
//! about a bundle is trusted, including its size, so every one of those steps
//! needs a bound that does not come from the bundle itself.
//!
//! # How these numbers were chosen
//!
//! A limit that legitimate bundles trip is worse than no limit: it turns a
//! verifier into a thing that refuses real evidence, which is the same
//! outcome an attacker wanted. So the ceilings below are anchored to measured
//! reality and then set far above it.
//!
//! Measured on the live VIRP chain (2026-08-26, WAL-inclusive) and on the
//! reference D-0 seal:
//!
//! | thing | largest real value |
//! | --- | --- |
//! | entries in one session | 3,456 (`autopilot:2026-08-24`) |
//! | entries in the whole chain | 13,864 across 58 sessions |
//! | sessions listed in a seal | 350 (seal file: 57 KB) |
//! | artifact bodies | 13,677, totalling 4.2 MB |
//! | one artifact body | 2,020 bytes |
//! | `session_id` | 42 bytes |
//! | `artifact_id` | 57 bytes |
//! | `artifact_type` | 15 bytes |
//! | `signer_org_id` | 5 bytes |
//! | `artifact_hash_alg` | 6 bytes |
//! | `artifact_schema_version` | 1 byte |
//!
//! A 3,456-entry session serialises to 2.0 MB and verifies in 0.01 s with a
//! 7.1 MB peak RSS; memory amplification over the input is a flat 2.5-3.5×
//! and the walk is linear. Every default below leaves at least an order of
//! magnitude of headroom over the largest measured value, and most leave two
//! or three.
//!
//! # What this does not cover
//!
//! Directory bundles are uncompressed, so there is no decompression ratio to
//! bound. **If `tar` or `zip` bundle support is ever added, ratio limits
//! become necessary and nothing here provides them.**

/// Ceilings applied while reading a bundle. Exceeding any of them is a
/// [`crate::BundleError`], so the outcome is UNREADABLE — the verifier never
/// looked, which is the honest thing to report.
///
/// [`Limits::default`] is the measured-and-generous set documented above.
/// Construct a different one to tighten or relax any field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    // --- file sizes ------------------------------------------------------
    /// `manifest.json`. A 350-session manifest carrying artifact rows is
    /// ~1.5 MB; 100,000 artifact rows would be ~11 MB.
    pub manifest_bytes: u64,
    /// `keys.json`. A key entry is ~200 bytes; real files hold one or two.
    pub keys_bytes: u64,
    /// The D-0 seal document. The 350-session reference seal is 57 KB, about
    /// 166 bytes per listed session, so this allows ~100,000 sessions.
    pub seal_bytes: u64,
    /// The seal's detached `.minisig` file. A real one is ~330 bytes (two
    /// base64 lines and two comment lines).
    pub seal_sig_bytes: u64,
    /// One `sessions/<name>.json`. The largest real session is 2.0 MB.
    pub session_bytes: u64,
    /// One artifact body file. The largest real body is 2,020 bytes.
    pub artifact_body_bytes: u64,
    /// All artifact bodies in one bundle. The whole chain's bodies total
    /// 4.2 MB.
    pub artifact_bytes_total: u64,
    /// One REFERENCED artifact — a file a camera record cites by digest
    /// (segment video, validator output), not a chain body. A different
    /// order of size from bodies, so a separate ceiling: the largest real
    /// segment measured is 217 KB and a validator output ~1 KB, but longer
    /// segments and higher bitrates are legitimate.
    ///
    /// These are never held in memory — the reader streams each file and
    /// keeps only its digest — so this bounds HASHING TIME against a hostile
    /// bundle, not allocation.
    pub referenced_artifact_bytes: u64,
    /// Every referenced artifact in one bundle. Nine records of lab footage
    /// total 1.5 MB; a day of continuous six-second segments would be ~2 GB.
    pub referenced_artifact_bytes_total: u64,

    // --- counts ----------------------------------------------------------
    /// Sessions listed in the manifest. The reference seal lists 350; the
    /// live chain has 58.
    pub sessions: usize,
    /// Entries in one session. The largest real session has 3,456.
    pub entries_per_session: usize,
    /// Entries across every session in the bundle. The whole chain has
    /// 13,864.
    pub entries_total: usize,
    /// Artifact bodies listed in the manifest. The chain has 13,677.
    pub artifact_bodies: usize,

    // --- string field lengths, in bytes ----------------------------------
    // Checked before any canonical bytes are built. The two digest fields
    // (`artifact_hash`, `previous_entry_hash`) are not listed: they are
    // separately required to be 64 lowercase hex characters, which is a
    // tighter bound than any ceiling here.
    /// `session_id`, on entries, heads, the manifest and the seal.
    pub session_id_bytes: usize,
    /// `artifact_id`.
    pub artifact_id_bytes: usize,
    /// `artifact_type`.
    pub artifact_type_bytes: usize,
    /// `artifact_hash_alg`.
    pub artifact_hash_alg_bytes: usize,
    /// `artifact_schema_version`.
    pub artifact_schema_version_bytes: usize,
    /// `signer_org_id`.
    pub signer_org_id_bytes: usize,
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            manifest_bytes: 16 * MIB,
            keys_bytes: MIB,
            seal_bytes: 16 * MIB,
            seal_sig_bytes: 64 * KIB,
            session_bytes: 64 * MIB,
            artifact_body_bytes: 16 * MIB,
            artifact_bytes_total: GIB,
            referenced_artifact_bytes: 4 * GIB,
            referenced_artifact_bytes_total: 64 * GIB,

            sessions: 10_000,
            entries_per_session: 250_000,
            entries_total: 1_000_000,
            artifact_bodies: 200_000,

            session_id_bytes: 512,
            artifact_id_bytes: 1024,
            artifact_type_bytes: 256,
            artifact_hash_alg_bytes: 64,
            artifact_schema_version_bytes: 64,
            signer_org_id_bytes: 256,
        }
    }
}

impl Limits {
    /// Every limit removed. For a caller that has its own bound on the input
    /// — a test, or a reader already working from trusted bytes.
    ///
    /// Not a good idea on a bundle from a stranger.
    pub fn unlimited() -> Limits {
        Limits {
            manifest_bytes: u64::MAX,
            keys_bytes: u64::MAX,
            seal_bytes: u64::MAX,
            seal_sig_bytes: u64::MAX,
            session_bytes: u64::MAX,
            artifact_body_bytes: u64::MAX,
            artifact_bytes_total: u64::MAX,
            referenced_artifact_bytes: u64::MAX,
            referenced_artifact_bytes_total: u64::MAX,
            sessions: usize::MAX,
            entries_per_session: usize::MAX,
            entries_total: usize::MAX,
            artifact_bodies: usize::MAX,
            session_id_bytes: usize::MAX,
            artifact_id_bytes: usize::MAX,
            artifact_type_bytes: usize::MAX,
            artifact_hash_alg_bytes: usize::MAX,
            artifact_schema_version_bytes: usize::MAX,
            signer_org_id_bytes: usize::MAX,
        }
    }
}
