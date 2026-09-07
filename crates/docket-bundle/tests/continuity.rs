//! Cross-session capture continuity.
//!
//! The per-session grader reads one session at a time, so a hole that lands
//! ON a session boundary is invisible to it: the last record of one session
//! and the first record of the next are never compared. Both sides are in
//! the bundle, the hole is measurable, and nothing said so.
//!
//! The real case these tests are shaped from (bundle-blip-20260907, two
//! cameras, three daily sessions each): the Axis stream stops at 2026-09-05
//! 17:55:27Z and resumes 2026-09-06 22:18:15Z, 28.38 hours later, with the
//! resuming record carrying a signed `driver-restart` gap citing exactly the
//! previous session's last segment. The Reolink stream does the same for
//! 10.52 hours with a `capture-discontinuity` gap. Per-session, each of
//! those first records is an ACCOUNTED left-boundary gap of unavailable
//! duration. Across sessions, the duration IS available, and the bundle
//! should say so.
//!
//! Bodies here are SYNTHETIC, exercising the grader's arms; the shapes and
//! the numbers come from that bundle.

use docket_bundle::camera::{
    grade_capture_completeness, grade_capture_continuity, session_capture_bounds, CaptureGrade,
};
use docket_bundle::sha256_hex;
use docket_bundle::verify::{ArtifactStore, SessionChain};
use serde_json::{json, Value};

const AXIS: &str = "axis-m3085v-b8a44fdd572c";
const REO: &str = "reolink-rlc810a-sub";

/// Nanoseconds from a whole number of seconds, so the test numbers read as
/// the wall-clock spans they are.
fn ns(s: f64) -> i64 {
    (s * 1e9) as i64
}

/// A `camera_segment/2` body. The real bundle these numbers come from is
/// `/6`, which additionally requires a full `sensor_signature` object; the
/// timing, policy and gap fields this check reads are the same at both
/// versions, and `/2` keeps the fixtures to what is being tested.
fn body(cam: &str, seq: i64, start_ns: i64, end_ns: i64, gap: Value, policy: Value) -> Value {
    json!({
        "schema": "camera_segment/2",
        "camera_id": cam,
        "device": cam,
        "segment_seq": seq,
        "segment_sha256": format!("{:064x}", seq),
        "prev_segment_sha256": if seq == 0 { Value::Null } else { json!(format!("{:064x}", seq - 1)) },
        "byte_len": 1,
        "duration_s": (end_ns - start_ns) as f64 / 1e9,
        "capture_start_utc_ns": start_ns,
        "capture_end_utc_ns": end_ns,
        "encoder": "copy",
        "time_source": "file-mtime",
        "mode": "live",
        "gap": gap,
        "producer_key_id": "00000000000000000000000000000000",
        "capture_policy": policy,
    })
}

fn axis_policy() -> Value {
    json!({"nominal_segment_s": 6.0, "jitter_s": 1.5, "max_unexplained_gap_s": 0.0})
}

fn reo_policy() -> Value {
    json!({"nominal_segment_s": 10.0, "jitter_s": 0.5, "max_unexplained_gap_s": 0.0})
}

/// One session carrying the given bodies, in order.
fn session(session_id: &str, bodies: &[Value]) -> (SessionChain, ArtifactStore) {
    let mut store = ArtifactStore::new();
    let mut entries = Vec::new();
    for (i, b) in bodies.iter().enumerate() {
        let raw = serde_json::to_vec(b).expect("body");
        let hash = sha256_hex(&raw);
        store.insert(hash.clone(), raw);
        entries.push(json!({
            "artifact_hash": hash,
            "artifact_hash_alg": "sha256",
            "artifact_id": format!("camseg:{session_id}:{i}"),
            "artifact_schema_version": "1",
            "artifact_type": "evidence_item",
            "monotonic_ns": i as u64,
            "previous_entry_hash": "00".repeat(32),
            "sequence": i as i64,
            "session_id": session_id,
            "signer_node_id": 1u32,
            "signer_org_id": "local",
            "timestamp_ns": i as u64,
            "chain_entry_hash": "00".repeat(32),
        }));
    }
    let chain: SessionChain =
        serde_json::from_value(json!({"session_id": session_id, "entries": entries})).expect("chain");
    (chain, store)
}

/// Bounds for a list of (session_id, bodies), as the bundle assembles them.
fn bounds_for(sessions: &[(&str, Vec<Value>)]) -> Vec<docket_bundle::camera::SessionCaptureBounds> {
    let mut out = Vec::new();
    for (sid, bodies) in sessions {
        let (chain, store) = session(sid, bodies);
        out.extend(session_capture_bounds(&chain, Some(&store)));
    }
    out
}

// The 2026-09-05 -> 2026-09-06 Axis crossing, to the second.
fn axis_day_one() -> (&'static str, Vec<Value>) {
    (
        "camera:axis-m3085v-b8a44fdd572c:2026-09-05",
        vec![
            body(AXIS, 7154, ns(0.0), ns(6.0), Value::Null, axis_policy()),
            body(AXIS, 7155, ns(6.0), ns(12.0), Value::Null, axis_policy()),
        ],
    )
}

fn axis_day_two(gap: Value) -> (&'static str, Vec<Value>) {
    // 28.38 h after day one's last capture_end.
    let resume = ns(12.0) + ns(102_168.018);
    (
        "camera:axis-m3085v-b8a44fdd572c:2026-09-06",
        vec![
            body(AXIS, 7156, resume, resume + ns(6.0), gap, axis_policy()),
            body(
                AXIS,
                7157,
                resume + ns(6.0),
                resume + ns(12.0),
                Value::Null,
                axis_policy(),
            ),
        ],
    )
}

#[test]
fn a_hole_on_a_session_boundary_is_measured_and_accounted_by_its_signed_gap() {
    let b = bounds_for(&[
        axis_day_one(),
        axis_day_two(json!({"after_seq": 7155, "reason": "driver-restart"})),
    ]);
    let r = grade_capture_continuity(&b).expect("two sessions of one camera");
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
    assert_eq!(r.crossings.len(), 1, "{r:?}");
    let c = &r.crossings[0];
    assert_eq!(c.camera_id, AXIS);
    assert_eq!((c.after_seq, c.seq), (7155, 7156));
    assert_eq!(c.class, "accounted");
    assert_eq!(c.gap_reason.as_deref(), Some("driver-restart"));
    // The whole point: per-session this duration was unavailable.
    assert_eq!(c.hole_ms, 102_168_018);
    assert!(
        r.detail.contains("28.38 h") || r.detail.contains("102168"),
        "the measured duration must be visible: {}",
        r.detail
    );
}

#[test]
fn accounted_across_a_boundary_is_never_continuous() {
    let b = bounds_for(&[
        axis_day_one(),
        axis_day_two(json!({"after_seq": 7155, "reason": "driver-restart"})),
    ]);
    let r = grade_capture_continuity(&b).expect("report");
    assert_ne!(r.grade, CaptureGrade::Continuous, "accounted for is not complete");
}

#[test]
fn a_hole_on_a_session_boundary_with_no_signed_gap_is_unexplained() {
    let b = bounds_for(&[axis_day_one(), axis_day_two(Value::Null)]);
    let r = grade_capture_continuity(&b).expect("report");
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.crossings[0].class, "unexplained");
    assert_eq!(r.crossings[0].gap_reason, None);
}

#[test]
fn a_gap_citing_anything_but_the_previous_sessions_last_record_is_not_accounted() {
    // Cites 7000, not 7155. It explains some other hole, not this one.
    let b = bounds_for(&[
        axis_day_one(),
        axis_day_two(json!({"after_seq": 7000, "reason": "driver-restart"})),
    ]);
    let r = grade_capture_continuity(&b).expect("report");
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.crossings[0].class, "unexplained");
}

#[test]
fn missing_records_between_two_sessions_are_a_sequence_skip_not_a_measured_hole() {
    // Day two resumes at 7160: 7156..7159 are in neither session. The hole
    // in TIME is not the whole story, and the report must not imply the
    // stream is merely paused.
    let mut day_two = axis_day_two(json!({"after_seq": 7159, "reason": "driver-restart"}));
    let resume = ns(12.0) + ns(102_168.018);
    day_two.1 = vec![body(
        AXIS,
        7160,
        resume,
        resume + ns(6.0),
        json!({"after_seq": 7159, "reason": "driver-restart"}),
        axis_policy(),
    )];
    let b = bounds_for(&[axis_day_one(), day_two]);
    let r = grade_capture_continuity(&b).expect("report");
    assert_eq!(r.grade, CaptureGrade::InterruptedUnexplained, "{r:?}");
    assert_eq!(r.crossings[0].class, "sequence_skip");
    assert!(
        r.detail.contains("7155") && r.detail.contains("7160"),
        "the skipped span must be named: {}",
        r.detail
    );
}

#[test]
fn sessions_that_meet_at_midnight_without_a_hole_are_continuous() {
    // The real 2026-09-06 -> 2026-09-07 crossing: the next session's first
    // capture starts exactly where the previous one's last ended.
    let day_one = (
        "camera:axis-m3085v-b8a44fdd572c:2026-09-06",
        vec![body(AXIS, 8172, ns(0.0), ns(6.0), Value::Null, axis_policy())],
    );
    let day_two = (
        "camera:axis-m3085v-b8a44fdd572c:2026-09-07",
        vec![body(AXIS, 8173, ns(6.0), ns(12.0), Value::Null, axis_policy())],
    );
    let r = grade_capture_continuity(&bounds_for(&[day_one, day_two])).expect("report");
    assert_eq!(r.grade, CaptureGrade::Continuous, "{r:?}");
    assert_eq!(r.crossings[0].class, "covered");
    assert_eq!(r.crossings[0].hole_ms, 0);
}

#[test]
fn a_small_overlap_across_a_boundary_is_covered_not_an_interruption() {
    // The real Reolink midnight crossing overlaps by 21 ms, inside the
    // declared 500 ms jitter. No time is unrecorded.
    let day_one = (
        "camera:reolink-rlc810a-sub:2026-09-06",
        vec![body(REO, 6974, ns(0.0), ns(10.0), Value::Null, reo_policy())],
    );
    let day_two = (
        "camera:reolink-rlc810a-sub:2026-09-07",
        vec![body(
            REO,
            6975,
            ns(10.0) - 21_000_000,
            ns(20.0),
            Value::Null,
            reo_policy(),
        )],
    );
    let r = grade_capture_continuity(&bounds_for(&[day_one, day_two])).expect("report");
    assert_eq!(r.grade, CaptureGrade::Continuous, "{r:?}");
    assert_eq!(r.crossings[0].class, "covered");
    assert!(r.crossings[0].hole_ms <= 0, "{:?}", r.crossings[0]);
}

#[test]
fn one_session_per_camera_produces_no_continuity_claim() {
    // Nothing to cross. A verifier that invented a verdict here would be
    // grading the export's scope, not the evidence.
    assert!(grade_capture_continuity(&bounds_for(&[axis_day_one()])).is_none());
}

#[test]
fn each_camera_is_crossed_against_itself_only() {
    // Two cameras interleaved in one bundle: the Axis crossing is
    // ACCOUNTED, the Reolink crossing is clean, and neither is compared
    // against the other's segments.
    let reo_day_one = (
        "camera:reolink-rlc810a-sub:2026-09-06",
        vec![body(REO, 6974, ns(0.0), ns(10.0), Value::Null, reo_policy())],
    );
    let reo_day_two = (
        "camera:reolink-rlc810a-sub:2026-09-07",
        vec![body(REO, 6975, ns(10.0), ns(20.0), Value::Null, reo_policy())],
    );
    let b = bounds_for(&[
        axis_day_one(),
        reo_day_one,
        axis_day_two(json!({"after_seq": 7155, "reason": "driver-restart"})),
        reo_day_two,
    ]);
    let r = grade_capture_continuity(&b).expect("report");
    assert_eq!(r.crossings.len(), 2, "{r:?}");
    let axis = r.crossings.iter().find(|c| c.camera_id == AXIS).expect("axis crossing");
    let reo = r
        .crossings
        .iter()
        .find(|c| c.camera_id == REO)
        .expect("reolink crossing");
    assert_eq!(axis.class, "accounted");
    assert_eq!(reo.class, "covered");
    // Weakest link across cameras, same discipline as every other roll-up.
    assert_eq!(r.grade, CaptureGrade::InterruptedAccounted, "{r:?}");
}

#[test]
fn the_per_session_grade_is_unchanged_by_the_cross_session_check() {
    // Day two's first record still carries a left-boundary gap citing its
    // immediate predecessor, and per-session that is still ACCOUNTED with
    // the duration unavailable. The cross-session check is a second
    // question, not a re-grade of the first.
    let (chain, store) = session(
        "camera:axis-m3085v-b8a44fdd572c:2026-09-06",
        &axis_day_two(json!({"after_seq": 7155, "reason": "driver-restart"})).1,
    );
    let per_session = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(per_session.grade, CaptureGrade::InterruptedAccounted, "{per_session:?}");
    assert_eq!(per_session.external_predecessor_gaps.len(), 1);
    assert!(
        per_session.detail.contains("duration unavailable"),
        "{}",
        per_session.detail
    );
}
