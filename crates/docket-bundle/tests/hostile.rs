//! Hostile-input regression tests.
//!
//! virp-verify is a free tool that reads evidence supplied by other people,
//! including people who want it to lie or to crash. Everything here is input
//! no honest producer emits. The standing rule these tests encode:
//!
//! > Malformed evidence produces UNREADABLE or FAILED. It never terminates
//! > the verifier, and it never makes the verifier state something about the
//! > evidence that it did not compute.
//!
//! A panic in a public verification tool is a correctness failure, not a
//! robustness one: it turns "prove this yourself" into "the tool broke, take
//! my word for it".
//!
//! Each test names the site it guards. Grouped by review finding.

mod common;

use docket_bundle::seal::{Seal, SealMerkle, SealSession};
use docket_bundle::Status;

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

fn hex64(c: char) -> String {
    c.to_string().repeat(64)
}

/// A one-session seal. `head_hash` is written verbatim — including values
/// [`Seal::validate`] rejects — so the anchor path can be exercised on a
/// `Seal` that never went through `from_slice`.
fn seal_listing(session_id: &str, entry_count: u64, head_hash: &str, in_flight: bool) -> Seal {
    let mut s = Seal {
        seal_version: docket_bundle::seal::SEAL_VERSION.to_owned(),
        created_at: "2026-08-26T00:00:00Z".to_owned(),
        sealed_by: "hostile-input fixture".to_owned(),
        seal_public_key: "minisign:not-checked".to_owned(),
        sessions: vec![SealSession {
            session_id: session_id.to_owned(),
            entry_count,
            head_hash: head_hash.to_owned(),
            in_flight,
        }],
        merkle: SealMerkle {
            root: String::new(),
            leaf_count: 1,
        },
        residual_disclosure: "fixture".to_owned(),
    };
    s.merkle.root = s.recompute_merkle_root().unwrap_or_default();
    s
}

/// The rendered text of a status, as a report line would carry it.
fn text(status: &Status) -> String {
    match status {
        Status::Failed { detail } => detail.clone(),
        Status::Unverifiable { reason } => reason.clone(),
        other => other.label().to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Finding 1 — Seal::anchor must be total
// ---------------------------------------------------------------------------

/// `seal.rs` sliced `&s.head_hash[..16]` on a value the bundle's author
/// chooses. Every one of these panicked before the fix.
#[test]
fn short_empty_and_non_boundary_head_hashes_do_not_panic() {
    // Reaching the slicing branch needs the in-flight prefix case:
    // entry_count < bundle_count && in_flight.
    for head_hash in [
        "",                 // empty
        "a",                // 1 byte
        "abcdef0123456",    // 13 bytes, one short of the old index
        "abcdef0123456789", // exactly 16 — the boundary itself
        "not-hex-at-all-but-long-enough-to-slice",
        "aaaaaaaaaaaaaaa\u{00e9}aaaaaaa", // byte 16 is mid-character
        "\u{1F512}\u{1F512}\u{1F512}",    // 4-byte characters throughout
        &hex64('a'),                      // well-formed, for contrast
    ] {
        let s = seal_listing("s", 0, head_hash, true);
        let status = s.anchor("s", 0, "whatever");
        assert!(
            matches!(status, Status::Unverifiable { .. }),
            "head_hash {head_hash:?} produced {status:?}"
        );
    }
}

/// The prefix shown in the in-flight message must be a prefix of the value,
/// never a slice taken at a byte offset the value may not have.
#[test]
fn in_flight_prefix_is_a_real_prefix_of_the_head_hash() {
    for head_hash in ["", "abc", "aaaaaaaaaaaaaaa\u{00e9}aaaaaaa", &hex64('b')] {
        let s = seal_listing("s", 0, head_hash, true);
        let reason = text(&s.anchor("s", 0, "whatever"));
        let shown: String = head_hash.chars().take(16).collect();
        assert!(
            reason.contains(&shown),
            "reason {reason:?} does not carry the prefix {shown:?} of {head_hash:?}"
        );
    }
}

/// The quiet half of finding 1, and the worse half.
///
/// `last_sequence + 1` had two distinct failure modes. In a debug build it
/// panicked: loud, exit 101, no output. In a **release** build it wrapped to
/// `i64::MIN`, failed the unsigned conversion, and `unwrap_or(0)` printed
///
/// ```text
/// seal attests head aaa… with 0 entries; bundle head is 480… with 0 entries
/// ```
///
/// on a bundle whose head commits to `i64::MAX`. Nobody saw a crash. The
/// verifier simply stated a false fact about the evidence — the exact
/// failure mode this project exists to prevent, and invisible where the
/// panic was not.
///
/// The property asserted here is identical in every build profile: when the
/// entry count cannot be computed, the anchor says so and names no count.
#[test]
fn sequence_overflow_never_reports_a_false_entry_count() {
    // Every sequence whose successor is not a representable entry count:
    // i64::MAX overflows the addition, everything below -1 converts to a
    // negative count. `-1` and `i64::MAX - 1` are representable and live in
    // `representable_sequence_boundaries_still_anchor`.
    for last_sequence in [i64::MAX, i64::MIN, i64::MIN + 1, -2, -5] {
        let s = seal_listing("s", 0, &hex64('a'), true);
        let status = s.anchor("s", last_sequence, "whatever");
        assert!(
            matches!(status, Status::Unverifiable { .. }),
            "last_sequence {last_sequence} produced {status:?}"
        );
        let reason = text(&status);
        assert!(
            reason.contains(&last_sequence.to_string()),
            "reason {reason:?} does not name the offending sequence {last_sequence}"
        );
        // The specific lie the old code told.
        assert!(
            !reason.contains("0 entries"),
            "reason {reason:?} claims an entry count it did not compute"
        );
    }
}

/// The boundaries that are NOT errors still behave. `-1` is the empty-chain
/// head (`last_sequence + 1 == 0`) and `0` is a one-entry chain.
#[test]
fn representable_sequence_boundaries_still_anchor() {
    let s = seal_listing("s", 0, &hex64('a'), false);
    assert_eq!(
        s.anchor("s", -1, &hex64('a')),
        Status::Verified,
        "empty chain, 0 entries"
    );

    let s = seal_listing("s", 1, &hex64('a'), false);
    assert_eq!(s.anchor("s", 0, &hex64('a')), Status::Verified, "one entry");

    // `i64::MAX - 1` increments cleanly: its successor is `i64::MAX`, which
    // is a valid u64. It is the largest sequence that is NOT an overflow, so
    // it must still be graded on the merits rather than refused.
    let s = seal_listing("s", 0, &hex64('a'), true);
    let status = s.anchor("s", i64::MAX - 1, &hex64('a'));
    assert!(matches!(status, Status::Unverifiable { .. }), "{status:?}");
    assert!(
        text(&status).contains(&(i64::MAX as u64).to_string()),
        "the in-flight message should carry the real bundle count"
    );

    // A session the seal never listed is Absent regardless of the sequence.
    assert_eq!(s.anchor("absent", i64::MAX, "x"), Status::Absent);
    assert_eq!(s.anchor("absent", i64::MIN, "x"), Status::Absent);
}

/// Every malformed `head_hash` shape is rejected at read time, so a bundle
/// carrying one is UNREADABLE rather than reaching the anchor at all.
#[test]
fn malformed_seal_head_hashes_are_unreadable_at_parse_time() {
    for head_hash in [
        "",                                        // empty
        "ab",                                      // short
        &hex64('a')[..63],                         // one short of 64
        &format!("{}a", hex64('a')),               // one over
        &hex64('A'),                               // uppercase is not the stored form
        &"g".repeat(64),                           // 64 characters, not hex
        &format!("{}\u{00e9}", &hex64('a')[..62]), // 64 chars, one non-ASCII
    ] {
        let json = serde_json::json!({
            "seal_version": "virp-seal/1",
            "created_at": "2026-08-26T00:00:00Z",
            "sealed_by": "hostile-input fixture",
            "seal_public_key": "minisign:not-checked",
            "sessions": [{"session_id": "s", "entry_count": 0, "head_hash": head_hash, "in_flight": true}],
            "merkle": {"root": "00", "leaf_count": 1},
        });
        let err = Seal::from_slice(json.to_string().as_bytes())
            .err()
            .unwrap_or_else(|| panic!("seal with head_hash {head_hash:?} parsed"));
        let msg = err.to_string();
        assert!(msg.contains("head_hash"), "{msg}");
        assert!(msg.contains("\"s\""), "message does not name the session: {msg}");
    }
}

/// Read-time validation must not have narrowed the well-formed case.
#[test]
fn a_well_formed_seal_still_parses() {
    let json = serde_json::json!({
        "seal_version": "virp-seal/1",
        "created_at": "2026-08-26T00:00:00Z",
        "sealed_by": "fixture",
        "seal_public_key": "minisign:x",
        "sessions": [{"session_id": "s", "entry_count": 1, "head_hash": hex64('a'), "in_flight": false}],
        "merkle": {"root": "00", "leaf_count": 1},
    });
    let seal = Seal::from_slice(json.to_string().as_bytes()).expect("well-formed seal parses");
    assert_eq!(seal.sessions.len(), 1);
    // Consistency is a separate, graded question: this root is wrong, and a
    // wrong root is FAILED, not unreadable.
    assert!(seal.consistency().is_failed());
}

/// `entry_count` is `u64` on the wire, so the interesting boundaries are the
/// ends of its range against a valid bundle count.
#[test]
fn extreme_entry_counts_are_graded_not_fatal() {
    for entry_count in [0u64, 1, u64::MAX, u64::MAX - 1] {
        let s = seal_listing("s", entry_count, &hex64('a'), true);
        let status = s.anchor("s", 0, &hex64('a'));
        assert!(
            !matches!(status, Status::Verified) || entry_count == 1,
            "entry_count {entry_count} verified against a 1-entry bundle"
        );
        // Whatever it grades, it must be a grade, not a crash — reaching this
        // line is the assertion.
        let _ = text(&status);
    }
}

// ---------------------------------------------------------------------------
// Finding 5 — partial HMAC coverage must not report as full
// ---------------------------------------------------------------------------

mod hmac {
    use docket_bundle::{genesis_hash_hex, sha256_hex, verify_session, ChainEntry, ChainHead};
    use docket_bundle::{EntryFields, HeadFields, Keyring, SessionChain, Status, Verdict};

    /// A keyless session of `n` entries; `hmac_on(i)` decides which entries
    /// carry a `chain_hmac`. Everything else about the chain is correct, so
    /// the only thing under test is coverage.
    fn chain(n: usize, hmac_on: impl Fn(usize) -> bool) -> SessionChain {
        let session_id = "s".to_owned();
        let mut prev = genesis_hash_hex(&session_id);
        let mut entries = Vec::new();
        for i in 0..n {
            let fields = EntryFields {
                artifact_hash: sha256_hex(format!("body-{i}").as_bytes()),
                artifact_hash_alg: "sha256".to_owned(),
                artifact_id: format!("obs:{i}"),
                artifact_schema_version: "1".to_owned(),
                artifact_type: "observation".to_owned(),
                monotonic_ns: 1_000 + i as u64,
                previous_entry_hash: prev.clone(),
                sequence: i as i64,
                session_id: session_id.clone(),
                signer_node_id: 13,
                signer_org_id: "local".to_owned(),
                timestamp_ns: 1_787_000_000_000_000_000 + i as u64,
            };
            let hash = sha256_hex(&fields.canonical_bytes());
            entries.push(ChainEntry {
                fields,
                chain_entry_hash: hash.clone(),
                canonical_utf8: None,
                chain_hmac: hmac_on(i).then(|| super::hex64('b')),
                signature: None,
            });
            prev = hash;
        }
        SessionChain {
            head: Some(ChainHead {
                fields: HeadFields {
                    session_id: session_id.clone(),
                    last_sequence: n as i64 - 1,
                    last_entry_hash: prev,
                },
                canonical_utf8: None,
                head_hmac: None,
                signature: None,
            }),
            session_id,
            entries,
        }
    }

    fn entry_hmacs(n: usize, hmac_on: impl Fn(usize) -> bool) -> (Status, Verdict) {
        let report = verify_session(&chain(n, hmac_on), &Keyring::new());
        let p = report.property("entry_hmacs").expect("entry_hmacs graded");
        (p.status.clone(), report.verdict)
    }

    /// The overstatement, stated as a test: one HMAC out of a thousand used
    /// to earn the same status and the same verdict as a thousand out of a
    /// thousand. `chain_hmac` sits outside the canonical bytes, so the 999
    /// removals leave no other trace — which is precisely why the verifier
    /// must not wave them through.
    #[test]
    fn one_hmac_in_a_thousand_does_not_report_as_a_thousand() {
        let (partial, partial_verdict) = entry_hmacs(1000, |i| i == 0);
        let (full, full_verdict) = entry_hmacs(1000, |_| true);

        assert!(full == Status::OperatorAttested, "full coverage: {full:?}");
        assert_eq!(full_verdict, Verdict::OperatorAttestedUnverifiable);

        assert!(partial.is_failed(), "partial coverage: {partial:?}");
        assert_eq!(partial_verdict, Verdict::Failed);
        assert_ne!(partial, full, "1/1000 and 1000/1000 grade identically");
    }

    /// Mirrors `stripped_entry_signature_fails_even_keyless_exit_1`: removing
    /// the protection is what fails, at any scale, from either end.
    #[test]
    fn a_single_removed_hmac_fails_the_session() {
        for (n, missing) in [(2usize, 0usize), (2, 1), (10, 4), (1000, 999), (3456, 0)] {
            let (status, verdict) = entry_hmacs(n, |i| i != missing);
            assert!(
                status.is_failed(),
                "n={n} missing={missing} graded {status:?}, not FAILED"
            );
            assert_eq!(verdict, Verdict::Failed, "n={n} missing={missing}");
            if let Status::Failed { detail } = &status {
                assert!(detail.contains(&format!("{} of {n}", n - 1)), "{detail}");
            }
        }
    }

    /// The two legitimate shapes are untouched. An un-HMAC'd session is a
    /// real thing (pre-symmetric-tier chains) and must stay ABSENT, not
    /// become a failure by way of this fix.
    #[test]
    fn all_or_nothing_are_both_still_legitimate() {
        for n in [1usize, 2, 100, 1000] {
            assert_eq!(entry_hmacs(n, |_| false).0, Status::Absent, "n={n} none");
            assert_eq!(entry_hmacs(n, |_| true).0, Status::OperatorAttested, "n={n} all");
        }
        // Nothing at all attests an un-HMAC'd, unsigned session.
        assert_eq!(entry_hmacs(10, |_| false).1, Verdict::ConsistentUnauthenticated);
    }

    /// A malformed HMAC still fails on its own terms, and does so even when
    /// coverage is complete — the two checks are independent.
    #[test]
    fn malformed_hmacs_still_fail_independently_of_coverage() {
        let mut c = chain(4, |_| true);
        c.entries[2].chain_hmac = Some("not-a-digest".to_owned());
        let report = verify_session(&c, &Keyring::new());
        let status = &report.property("entry_hmacs").unwrap().status;
        assert!(status.is_failed(), "{status:?}");
        if let Status::Failed { detail } = status {
            assert!(detail.contains("64-hex"), "{detail}");
        }
    }
}

// ---------------------------------------------------------------------------
// Finding 7 — byte ceilings, at the library boundary
// ---------------------------------------------------------------------------

mod limits {
    use std::path::{Path, PathBuf};

    use docket_bundle::bundle::BundleError;
    use docket_bundle::{Bundle, Limits};
    use serde_json::{json, Value};

    fn write(path: &Path, v: &Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(v).unwrap()).unwrap();
    }

    /// A minimal readable bundle: one session, one entry, correct genesis.
    fn bundle(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("limits-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        let sid = "s";
        let genesis = docket_bundle::genesis_hash_hex(sid);
        let fields = docket_bundle::EntryFields {
            artifact_hash: docket_bundle::sha256_hex(b"body"),
            artifact_hash_alg: "sha256".to_owned(),
            artifact_id: "obs:0".to_owned(),
            artifact_schema_version: "1".to_owned(),
            artifact_type: "observation".to_owned(),
            monotonic_ns: 1,
            previous_entry_hash: genesis,
            sequence: 0,
            session_id: sid.to_owned(),
            signer_node_id: 13,
            signer_org_id: "local".to_owned(),
            timestamp_ns: 1,
        };
        let hash = docket_bundle::sha256_hex(&fields.canonical_bytes());
        let mut entry = serde_json::to_value(&fields).unwrap();
        entry["chain_entry_hash"] = json!(hash);
        write(
            &root.join("sessions/s.json"),
            &json!({
                "session_id": sid,
                "entries": [entry],
                "head": {"session_id": sid, "last_sequence": 0, "last_entry_hash": hash},
            }),
        );
        write(
            &root.join("manifest.json"),
            &json!({
                "docket_bundle_version": "docket-bundle/0.1",
                "chain_format": "v1",
                "sessions": [{"session_id": sid, "path": "sessions/s.json"}],
            }),
        );
        root
    }

    #[test]
    fn every_byte_ceiling_is_enforced() {
        let root = bundle("bytes");
        // Default limits read it.
        assert!(Bundle::read_dir(&root).is_ok());

        for (name, tighten) in [
            ("manifest", (|l: &mut Limits| l.manifest_bytes = 4) as fn(&mut Limits)),
            ("session", |l: &mut Limits| l.session_bytes = 4),
        ] {
            let mut limits = Limits::default();
            tighten(&mut limits);
            let err = Bundle::read_dir_with_limits(&root, &limits)
                .err()
                .unwrap_or_else(|| panic!("{name}: oversized file was accepted"));
            assert!(matches!(err, BundleError::TooLarge { max: 4, .. }), "{name}: {err:?}");
            assert!(err.to_string().contains("exceeds the 4-byte limit"), "{err}");
        }
    }

    /// `Limits::unlimited()` must actually read a bundle the defaults read —
    /// an escape hatch that rejects everything is not an escape hatch.
    #[test]
    fn unlimited_still_reads_a_normal_bundle() {
        let root = bundle("unlimited");
        assert!(Bundle::read_dir_with_limits(&root, &Limits::unlimited()).is_ok());
    }

    /// The documented defaults, asserted so a later edit cannot quietly
    /// tighten one below the largest real bundle. The right-hand values are
    /// the measured maxima from HARDENING-SURVEY.md.
    #[test]
    fn defaults_clear_every_measured_maximum() {
        let l = Limits::default();
        assert!(l.entries_per_session > 3_456, "largest real session");
        assert!(l.entries_total > 13_864, "whole live chain");
        assert!(l.sessions > 350, "largest real seal");
        assert!(l.artifact_bodies > 13_677, "artifact rows on the chain");
        assert!(l.artifact_body_bytes > 2_020, "largest real body");
        assert!(l.artifact_bytes_total > 4_220_073, "all bodies");
        assert!(l.session_bytes > 2_119_935, "largest real session file");
        assert!(l.seal_bytes > 57_155, "reference seal file");
        assert!(l.session_id_bytes > 42, "longest real session_id");
        assert!(l.artifact_id_bytes > 57, "longest real artifact_id");
        assert!(l.artifact_type_bytes > 15, "longest real artifact_type");
        assert!(l.artifact_hash_alg_bytes > 6, "longest real artifact_hash_alg");
        assert!(l.artifact_schema_version_bytes > 1, "longest real schema_version");
        assert!(l.signer_org_id_bytes > 5, "longest real signer_org_id");
    }
}
