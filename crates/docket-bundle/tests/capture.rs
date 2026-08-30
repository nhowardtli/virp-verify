//! Capture-completeness grader tests.
//!
//! These bodies are SYNTHETIC: they exercise Docket's grader arms (the
//! producer's documented semantics), and are deliberately not claimed to be
//! producer output. The producer-made evidence lives in
//! `crates/virp-verify/tests/fixtures/comp-*` (see the README there) and is
//! what the CLI-level tests grade end to end.

use docket_bundle::camera::{claimed_camera_ids, grade_capture_completeness, CaptureGrade};
use docket_bundle::sha256_hex;
use docket_bundle::verify::{ArtifactStore, SessionChain};
use serde_json::{json, Value};

/// A camera_segment/2 body with the given timing, policy and gap.
fn body_v2(cam: &str, seq: i64, start_s: f64, end_s: f64, gap: Value, policy: Value) -> Value {
    json!({
        "schema": "camera_segment/2",
        "camera_id": cam,
        "device": cam,
        "segment_seq": seq,
        "segment_sha256": format!("{:064x}", seq),
        "prev_segment_sha256": if seq == 0 { Value::Null } else { json!(format!("{:064x}", seq - 1)) },
        "byte_len": 1,
        "duration_s": end_s - start_s,
        "capture_start_utc_ns": (start_s * 1e9) as i64,
        "capture_end_utc_ns": (end_s * 1e9) as i64,
        "encoder": "copy",
        "time_source": "file-mtime",
        "mode": "replay",
        "gap": gap,
        "producer_key_id": "00000000000000000000000000000000",
        "capture_policy": policy,
    })
}

fn policy(nominal: f64, jitter: f64, max_gap: f64) -> Value {
    json!({"nominal_segment_s": nominal, "jitter_s": jitter, "max_unexplained_gap_s": max_gap})
}

/// Build a session + store carrying the given bodies (raw bytes; the entry's
/// artifact_hash is the body's real SHA-256, as the exporter writes it).
fn chain_with_bodies(bodies: &[Vec<u8>]) -> (SessionChain, ArtifactStore) {
    let mut store = ArtifactStore::new();
    let mut entries = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        let hash = sha256_hex(b);
        store.insert(hash.clone(), b.clone());
        entries.push(json!({
            "artifact_hash": hash,
            "artifact_hash_alg": "sha256",
            "artifact_id": format!("camseg:test:{i}"),
            "artifact_schema_version": "1",
            "artifact_type": "evidence_item",
            "monotonic_ns": i as u64,
            "previous_entry_hash": "00".repeat(32),
            "sequence": i as i64,
            "session_id": "camera:test:2026-08-29",
            "signer_node_id": 1u32,
            "signer_org_id": "local",
            "timestamp_ns": i as u64,
            "chain_entry_hash": "00".repeat(32),
        }));
    }
    let chain: SessionChain = serde_json::from_value(json!({
        "session_id": "camera:test:2026-08-29",
        "entries": entries,
    }))
    .unwrap();
    (chain, store)
}

fn bodies(vals: &[Value]) -> Vec<Vec<u8>> {
    vals.iter().map(|v| serde_json::to_vec(v).unwrap()).collect()
}

#[test]
fn continuous_within_jitter() {
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 6.1, 12.0, Value::Null, p.clone()),
        body_v2("cam", 2, 12.0, 18.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::Continuous, "{r:?}");
    assert!(r.outages.is_empty());
    assert!(r.overlaps.is_empty());
    assert_eq!(r.camera_records, 3);
    assert_eq!(r.policies.len(), 1);
}

#[test]
fn signed_gap_record_is_accounted_and_never_continuous() {
    // A signed gap record makes an outage ACCOUNTED FOR. It must NEVER make
    // coverage COMPLETE: those are different statements, and collapsing them
    // would defeat the axis.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2(
            "cam",
            1,
            900.0,
            906.0,
            json!({"reason": "driver-restart", "after_seq": 0}),
            p,
        ),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
    assert_ne!(r.grade, CaptureGrade::Continuous);
    assert_eq!(r.outages.len(), 1);
    assert_eq!(r.outages[0].class, "accounted");
    assert_eq!(r.outages[0].gap_reason.as_deref(), Some("driver-restart"));
    assert_eq!(r.outages[0].hole_ms, 894_000);
}

#[test]
fn hole_within_declared_tolerance_is_accounted_as_tolerated() {
    let p = policy(6.0, 2.0, 30.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 16.0, 22.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
    assert_eq!(r.outages[0].class, "tolerated");
    assert_eq!(r.outages[0].gap_reason, None);
}

#[test]
fn unexplained_hole_beyond_policy() {
    let p = policy(6.0, 0.3, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 7.6, 13.6, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.outages[0].class, "unexplained");
    assert_eq!(r.outages[0].hole_ms, 1600);
}

#[test]
fn overlap_beyond_jitter_is_an_observation_never_an_interruption() {
    // The 2026-08-24 hazard: capture windows overlapping by 4-6 s. The
    // producer's grader reports overlaps but never counts them as
    // interruptions — overlapping windows leave no time unrecorded.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 1.0, 7.0, Value::Null, p), // 5 s overlap
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::Continuous, "{r:?}");
    assert!(r.outages.is_empty());
    assert_eq!(r.overlaps.len(), 1);
    assert_eq!(r.overlaps[0].overlap_ms, 5000);
    assert!(r.detail.contains("no uncovered time"), "{}", r.detail);
}

#[test]
fn v1_records_are_unverifiable_never_continuous_never_not_graded() {
    let mut b = body_v2("cam", 0, 0.0, 6.0, Value::Null, Value::Null);
    b["schema"] = json!("camera_segment/1");
    b.as_object_mut().unwrap().remove("capture_policy");
    let (chain, store) = chain_with_bodies(&bodies(&[b]));
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("camera_segment/1"), "{reason}");
    assert!(reason.contains("no capture policy"), "{reason}");
}

#[test]
fn a_single_v1_record_among_v2_makes_the_session_unverifiable() {
    let p = policy(6.0, 2.0, 0.0);
    let mut v1 = body_v2("cam", 1, 6.0, 12.0, Value::Null, Value::Null);
    v1["schema"] = json!("camera_segment/1");
    v1.as_object_mut().unwrap().remove("capture_policy");
    let (chain, store) = chain_with_bodies(&bodies(&[body_v2("cam", 0, 0.0, 6.0, Value::Null, p), v1]));
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("1 of 2"), "{reason}");
}

#[test]
fn unrecognised_camera_segment_schema_is_refused_by_name() {
    let b = body_v2("cam", 0, 0.0, 6.0, Value::Null, policy(6.0, 2.0, 0.0));
    let mut b3 = b;
    b3["schema"] = json!("camera_segment/3");
    let (chain, store) = chain_with_bodies(&bodies(&[b3]));
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("camera_segment/3"), "{reason}");
}

#[test]
fn no_bodies_carried_is_unverifiable_with_the_reason() {
    let (chain, _) = chain_with_bodies(&bodies(&[body_v2(
        "cam",
        0,
        0.0,
        6.0,
        Value::Null,
        policy(6.0, 2.0, 0.0),
    )]));
    let r = grade_capture_completeness(&chain, None);
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("no artifact bodies"), "{reason}");
}

#[test]
fn non_camera_bodies_are_unverifiable_not_continuous() {
    let (chain, store) = chain_with_bodies(&[b"not json at all".to_vec()]);
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("no camera_segment records"), "{reason}");
}

#[test]
fn hash_only_entries_make_the_timeline_unreadable() {
    // One carried camera record plus one hash-only entry: the unread entry
    // may be a camera record, so the timeline cannot be graded in full.
    let body = serde_json::to_vec(&body_v2("cam", 0, 0.0, 6.0, Value::Null, policy(6.0, 2.0, 0.0))).unwrap();
    let (chain, mut store) = chain_with_bodies(&[body, b"hash-only-placeholder".to_vec()]);
    store.remove(&chain.entries[1].fields.artifact_hash);
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Unverifiable { reason } = &r.grade else {
        panic!("want UNVERIFIABLE, got {:?}", r.grade);
    };
    assert!(reason.contains("no carried body"), "{reason}");
}

#[test]
fn v2_without_usable_policy_is_failed() {
    // jitter >= nominal would tolerate a whole missing segment as
    // continuous; the producer refuses to sign it, so a record carrying it
    // is checked and wrong.
    let (chain, store) = chain_with_bodies(&bodies(&[body_v2(
        "cam",
        0,
        0.0,
        6.0,
        Value::Null,
        policy(6.0, 6.0, 0.0),
    )]));
    let r = grade_capture_completeness(&chain, Some(&store));
    let CaptureGrade::Failed { detail } = &r.grade else {
        panic!("want FAILED, got {:?}", r.grade);
    };
    assert!(detail.contains("no usable capture_policy"), "{detail}");
}

#[test]
fn v2_without_timing_fields_is_failed() {
    let mut b = body_v2("cam", 0, 0.0, 6.0, Value::Null, policy(6.0, 2.0, 0.0));
    b.as_object_mut().unwrap().remove("capture_start_utc_ns");
    let (chain, store) = chain_with_bodies(&bodies(&[b]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn the_later_records_policy_grades_the_hole() {
    // The record making the continuity claim is the LATER one; its policy
    // applies, exactly as in the producer's grader.
    let loose = policy(6.0, 2.0, 60.0);
    let tight = policy(6.0, 0.3, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, loose),
        body_v2("cam", 1, 7.0, 13.0, Value::Null, tight),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.policies.len(), 2);
}

#[test]
fn worst_pair_wins_accounted_does_not_mask_unexplained() {
    let p = policy(6.0, 0.3, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2(
            "cam",
            1,
            20.0,
            26.0,
            json!({"after_seq": 0, "reason": "driver-restart"}),
            p.clone(),
        ),
        body_v2("cam", 2, 28.0, 34.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.outages.len(), 2);
}

#[test]
fn empty_gap_object_is_malformed_and_fails() {
    // Under the producer's `if gap:` an empty object is falsy; here a gap
    // must be a WELL-FORMED gap record or the record is checked and wrong —
    // an object with no after_seq/reason accounts for nothing.
    let p = policy(6.0, 0.3, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 7.6, 13.6, json!({}), p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

// ---------------------------------------------------------------------------
// Adversarial gap records. The invariant across all of these: an outage with
// a gap field that fails strict validation grades FAILED (or, absent any gap
// claim, UNEXPLAINED) — NEVER ACCOUNTED. A truthy-but-malformed value must
// not launder an unexplained outage into an accounted one.
// ---------------------------------------------------------------------------

/// Two records with a 894 s hole between them; the second carries `gap`.
fn holey_pair(
    gap: Value,
) -> (
    docket_bundle::verify::SessionChain,
    docket_bundle::verify::ArtifactStore,
) {
    let p = policy(6.0, 2.0, 0.0);
    chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 900.0, 906.0, gap, p),
    ]))
}

#[test]
fn gap_with_wrong_after_seq_fails_never_accounts() {
    // The previous record is segment_seq 0; the gap cites 7 — some other
    // boundary. Laundering attempt.
    let (chain, store) = holey_pair(json!({"after_seq": 7, "reason": "driver-restart"}));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    assert_ne!(r.grade, CaptureGrade::InterruptedAccounted);
}

#[test]
fn gap_missing_after_seq_fails_never_accounts() {
    let (chain, store) = holey_pair(json!({"reason": "driver-restart"}));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn gap_as_nonempty_string_fails_never_accounts() {
    // Truthy in Python; not a gap record.
    let (chain, store) = holey_pair(json!("driver-restart"));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn gap_as_nonempty_array_fails_never_accounts() {
    let (chain, store) = holey_pair(json!(["driver-restart"]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn gap_attached_to_the_wrong_camera_fails_never_accounts() {
    // cam-a has segments 0..=1; cam-b's second record carries a gap citing
    // cam-a's segment_seq 1 across its own 894 s hole. The previous record
    // of CAM-B is segment_seq 10, so the citation is wrong for the boundary
    // it stands on.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam-a", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam-a", 1, 6.0, 12.0, Value::Null, p.clone()),
        body_v2("cam-b", 10, 0.0, 6.0, Value::Null, p.clone()),
        body_v2(
            "cam-b",
            11,
            900.0,
            906.0,
            json!({"after_seq": 1, "reason": "driver-restart"}),
            p,
        ),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    assert_ne!(r.grade, CaptureGrade::InterruptedAccounted);
}

#[test]
fn gap_with_empty_or_oversized_reason_fails() {
    let (chain, store) = holey_pair(json!({"after_seq": 0, "reason": ""}));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");

    let (chain, store) = holey_pair(json!({"after_seq": 0, "reason": "x".repeat(257)}));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

// ---------------------------------------------------------------------------
// Gap records at a sliced export's left boundary. The rule, on each camera's
// FIRST carried record only: a gap citing exactly `segment_seq - 1` (with
// segment_seq >= 1) names the immediate predecessor the export does not
// carry — a property of the export's scope, not a defect in the evidence.
// ACCOUNTED, duration unavailable. Any other citation stays FAILED, and
// every later record keeps the strict previous-carried-record rule.
// ---------------------------------------------------------------------------

#[test]
fn first_record_gap_citing_its_immediate_predecessor_is_accounted_never_failed() {
    // The real 2026-08-30 Reolink case: the export begins at segment 9,
    // whose driver-restart gap record cites after_seq 8 — segment 8 lives
    // in the previous day's session, outside this bundle.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2(
            "cam",
            9,
            0.0,
            6.0,
            json!({"after_seq": 8, "reason": "driver-restart"}),
            p.clone(),
        ),
        body_v2("cam", 10, 6.0, 12.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
    assert_ne!(r.grade, CaptureGrade::Continuous, "accounted is not complete");
    assert!(!matches!(r.grade, CaptureGrade::Failed { .. }));
    assert_eq!(r.external_predecessor_gaps.len(), 1);
    let g = &r.external_predecessor_gaps[0];
    assert_eq!((g.after_seq, g.seq), (8, 9));
    assert_eq!(g.gap_reason, "driver-restart");
    assert!(r.outages.is_empty(), "the boundary gap is not a measured outage: {r:?}");
    assert!(
        r.detail.contains("duration unavailable") && r.detail.contains("predecessor outside bundle"),
        "{}",
        r.detail
    );
}

#[test]
fn first_record_gap_citing_a_non_adjacent_predecessor_stays_failed() {
    // after_seq 3 on first carried segment 9: not the record's own
    // predecessor — a defect in the evidence, not a slicing artifact.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[body_v2(
        "cam",
        9,
        0.0,
        6.0,
        json!({"after_seq": 3, "reason": "driver-restart"}),
        p,
    )]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    assert!(r.external_predecessor_gaps.is_empty());
}

#[test]
fn first_record_at_segment_zero_with_any_predecessor_gap_is_failed() {
    // Segment 0 is the stream's first possible record; no predecessor can
    // exist, inside the bundle or out.
    let p = policy(6.0, 2.0, 0.0);
    for cited in [-1i64, 0, 8] {
        let (chain, store) = chain_with_bodies(&bodies(&[body_v2(
            "cam",
            0,
            0.0,
            6.0,
            json!({"after_seq": cited, "reason": "driver-restart"}),
            p.clone(),
        )]));
        let r = grade_capture_completeness(&chain, Some(&store));
        assert!(
            matches!(r.grade, CaptureGrade::Failed { .. }),
            "after_seq {cited}: {r:?}"
        );
    }
}

#[test]
fn internal_record_gap_keeps_the_strict_previous_record_rule() {
    // Segment 12 citing 8 when the previous carried segment is 11: the
    // boundary exception applies only to a camera's FIRST carried record.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 11, 0.0, 6.0, Value::Null, p.clone()),
        body_v2(
            "cam",
            12,
            900.0,
            906.0,
            json!({"after_seq": 8, "reason": "driver-restart"}),
            p,
        ),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    assert_ne!(r.grade, CaptureGrade::InterruptedAccounted);
}

#[test]
fn external_boundary_gap_with_bad_producer_signature_fails_the_producer_axis_independently() {
    // The boundary exception is a capture-scope statement; it must not
    // launder the producer axis. A first record whose gap is a valid
    // external-predecessor citation but whose producer_sig cannot be an
    // Ed25519 signature: capture grades ACCOUNTED, the producer signature
    // fails on its own axis, independently.
    let p = policy(6.0, 2.0, 0.0);
    let mut b = body_v2(
        "cam",
        9,
        0.0,
        6.0,
        json!({"after_seq": 8, "reason": "driver-restart"}),
        p,
    );
    b["producer_sig"] = json!("deadbeef"); // not 64 bytes of hex
    let (chain, store) = chain_with_bodies(&bodies(&[b]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
    let pr = docket_bundle::grade_producer_signatures(&chain, Some(&store), &[]);
    assert!(
        matches!(pr.signature_validity, docket_bundle::verify::Status::Failed { .. }),
        "{pr:?}"
    );
}

#[test]
fn a_mid_stream_slice_of_a_longer_valid_stream_grades_by_its_own_left_boundary() {
    // The same producer stream, exported whole and exported as a slice.
    // Records 0..=4; record 2 carries a gap record for a real outage at the
    // 1→2 boundary. Whole export: ACCOUNTED with the hole measured. A slice
    // beginning at record 2: the same gap becomes an external-predecessor
    // gap — ACCOUNTED, duration unavailable. A slice beginning at record 3
    // (gap: null on its first record): no left-boundary claim, CONTINUOUS.
    let p = policy(6.0, 2.0, 0.0);
    let all: Vec<Value> = vec![
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 1, 6.0, 12.0, Value::Null, p.clone()),
        body_v2(
            "cam",
            2,
            900.0,
            906.0,
            json!({"after_seq": 1, "reason": "driver-restart"}),
            p.clone(),
        ),
        body_v2("cam", 3, 906.0, 912.0, Value::Null, p.clone()),
        body_v2("cam", 4, 912.0, 918.0, Value::Null, p),
    ];

    let (chain, store) = chain_with_bodies(&bodies(&all));
    let whole = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(whole.grade, CaptureGrade::InterruptedAccounted, "{whole:?}");
    assert_eq!(whole.outages.len(), 1);
    assert!(whole.external_predecessor_gaps.is_empty());

    let (chain, store) = chain_with_bodies(&bodies(&all[2..]));
    let sliced = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(sliced.grade, CaptureGrade::InterruptedAccounted, "{sliced:?}");
    assert!(sliced.outages.is_empty());
    assert_eq!(sliced.external_predecessor_gaps.len(), 1);
    assert_eq!(sliced.external_predecessor_gaps[0].after_seq, 1);

    let (chain, store) = chain_with_bodies(&bodies(&all[3..]));
    let no_claim = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(no_claim.grade, CaptureGrade::Continuous, "{no_claim:?}");
}

#[test]
fn external_boundary_gap_does_not_mask_a_later_unexplained_hole() {
    // Weakest-link discipline: the accounted left-boundary gap must never
    // hide an unexplained hole between carried records.
    let p = policy(6.0, 0.3, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2(
            "cam",
            9,
            0.0,
            6.0,
            json!({"after_seq": 8, "reason": "driver-restart"}),
            p.clone(),
        ),
        body_v2("cam", 10, 7.6, 13.6, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.external_predecessor_gaps.len(), 1);
    assert_eq!(r.outages.len(), 1);
}

// ---------------------------------------------------------------------------
// Malformed capture windows. The invariant: a window that is not shaped like
// time is refused (FAILED) — never graded CONTINUOUS on the manifest's own
// say-so.
// ---------------------------------------------------------------------------

#[test]
fn window_ending_before_or_at_its_start_is_refused() {
    let p = policy(6.0, 2.0, 0.0);
    for (start, end) in [(6.0, 0.0), (6.0, 6.0)] {
        let (chain, store) = chain_with_bodies(&bodies(&[
            body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
            body_v2("cam", 1, start, end, Value::Null, p.clone()),
        ]));
        let r = grade_capture_completeness(&chain, Some(&store));
        assert!(
            matches!(r.grade, CaptureGrade::Failed { .. }),
            "start={start} end={end}: {r:?}"
        );
    }
}

#[test]
fn enormous_window_is_refused_not_graded_continuous() {
    // The laundering this check exists for: a year-long claimed window
    // covers every later boundary, and the old grader would have called the
    // session CONTINUOUS having only accepted the record's own assertion.
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 31_536_000.0, Value::Null, p.clone()),
        body_v2("cam", 1, 999_000.0, 999_006.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    assert_ne!(r.grade, CaptureGrade::Continuous);
}

#[test]
fn negative_segment_seq_is_refused() {
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[body_v2("cam", -1, 0.0, 6.0, Value::Null, p)]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn duplicate_segment_seq_per_camera_is_refused() {
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam", 0, 6.0, 12.0, Value::Null, p.clone()),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");

    // The same seq on DIFFERENT cameras is fine.
    let (chain, store) = chain_with_bodies(&bodies(&[
        body_v2("cam-a", 0, 0.0, 6.0, Value::Null, p.clone()),
        body_v2("cam-b", 0, 0.0, 6.0, Value::Null, p),
    ]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(r.grade, CaptureGrade::Continuous, "{r:?}");
}

#[test]
fn empty_camera_id_is_refused() {
    let p = policy(6.0, 2.0, 0.0);
    let (chain, store) = chain_with_bodies(&bodies(&[body_v2("", 0, 0.0, 6.0, Value::Null, p)]));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn policy_values_beyond_sane_bounds_are_refused() {
    // nominal above a day, and a declared unexplained-gap tolerance above a
    // year: not policies, blanket pardons. Both FAIL via the unusable-policy
    // arm.
    for p in [policy(90_000.0, 2.0, 0.0), policy(6.0, 2.0, 40_000_000.0)] {
        let (chain, store) = chain_with_bodies(&bodies(&[body_v2("cam", 0, 0.0, 6.0, Value::Null, p)]));
        let r = grade_capture_completeness(&chain, Some(&store));
        assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
    }
}

#[test]
fn gap_as_integer_after_seq_float_is_rejected() {
    // after_seq must be an integer; 0.0 is a float claim, not a sequence.
    let (chain, store) = holey_pair(json!({"after_seq": 0.5, "reason": "driver-restart"}));
    let r = grade_capture_completeness(&chain, Some(&store));
    assert!(matches!(r.grade, CaptureGrade::Failed { .. }), "{r:?}");
}

#[test]
fn claimed_camera_ids_come_from_camera_records_only() {
    let p = policy(6.0, 2.0, 0.0);
    let cam = serde_json::to_vec(&body_v2("front-door", 0, 0.0, 6.0, Value::Null, p)).unwrap();
    let other = br#"{"schema": "something_else/1", "camera_id": "not-a-camera-record"}"#.to_vec();
    let (chain, store) = chain_with_bodies(&[cam, other]);
    assert_eq!(claimed_camera_ids(&chain, Some(&store)), vec!["front-door".to_owned()]);
    assert!(claimed_camera_ids(&chain, None).is_empty());
}
