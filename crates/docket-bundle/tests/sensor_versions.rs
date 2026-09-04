//! `camera_segment/3`, `/4` and `/5`: version-strict field sets, and the
//! sensor-signature summary.
//!
//! Two rules are under test, and they pull in opposite directions on
//! purpose.
//!
//! STRICTNESS. The producer treats a `sensor_signature`'s field set AS the
//! schema one level down — growing the object is a version bump, not a
//! compatible addition. Docket matches that exactly. A record claiming a
//! version it does not structurally match is FAILED with the counts named,
//! never read leniently for the fields we happen to recognise. Reading a
//! subset is precisely how a record of unexpected shape ends up counted
//! inside a clean result, and the live Axis chain already carries four
//! records (`/3` labels on 15-field objects) that only this rule catches.
//!
//! HUMILITY. Everything the summary reports is the PRODUCER'S CLAIM. Docket
//! ran no signed-video validator, holds no camera key, and checked no
//! certificate chain. The summary is presentation: it is not a `Status`, it
//! is not in `properties`, and it must never reach the verdict.
//!
//! The `/5` bodies here are SYNTHETIC, and knowingly so — no producer emits
//! `/5` yet. They pin the field set against the specification so that the
//! first real `/5` bundle meets a verifier that already agrees with it,
//! rather than one that has to be changed to accept whatever arrives. The
//! producer-made evidence remains `crates/virp-verify/tests/fixtures/comp-*`.

use docket_bundle::camera::{grade_capture_completeness, summarise_sensor, CaptureGrade};
use docket_bundle::sha256_hex;
use docket_bundle::verify::{ArtifactStore, SessionChain};
use serde_json::{json, Map, Value};

fn policy() -> Value {
    json!({"nominal_segment_s": 6.0, "jitter_s": 2.0, "max_unexplained_gap_s": 0.0})
}

/// The 13 fields `/3` defines.
fn sensor_v3(verdict: &str) -> Value {
    json!({
        "asserted_first_frame": "Thu 2024-08-15 21:02:44 GMT",
        "asserted_last_frame": "Thu 2024-08-15 21:03:04 GMT",
        "device_firmware": "12.5.68",
        "device_serial": "B8A44FDD572C",
        "gops_invalid": 0,
        "gops_unsigned": 0,
        "gops_valid": 18,
        "gops_valid_with_missing": 0,
        "public_key": "VALID",
        "validator": {"name": "signed-video-framework", "version": "2.3.10"},
        "validator_output_sha256": "aa".repeat(32),
        "vendor": "axis",
        "verdict": verdict,
    })
}

/// `/4` = `/3` + the out-of-band leaf pin.
fn sensor_v4(verdict: &str, pin: &str) -> Value {
    let mut m = sensor_v3(verdict).as_object().unwrap().clone();
    m.insert("public_key_pin".into(), json!(pin));
    m.insert("sensor_key_sha256".into(), json!("bb".repeat(32)));
    Value::Object(m)
}

/// `/5` = `/4` + the chain verified to a root the examiner holds.
fn sensor_v5(verdict: &str, pin: &str, chain_verified: bool, serial_ok: bool) -> Value {
    let mut m = sensor_v4(verdict, pin).as_object().unwrap().clone();
    m.insert(
        "device_chain".into(),
        json!({
            "root_sha256": "cc".repeat(32),
            "root_subject": "O = Axis Communications AB, CN = Axis Edge Vault CA ECC",
            "chain_verified": chain_verified,
            "leaf_serial_matches_device": serial_ok,
            "leaf_not_after": "2033-10-22T20:22:29Z",
        }),
    );
    Value::Object(m)
}

fn body(schema: &str, seq: i64, start_s: f64, end_s: f64, sensor: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("schema".into(), json!(schema));
    m.insert("camera_id".into(), json!("cam"));
    m.insert("device".into(), json!("cam"));
    m.insert("segment_seq".into(), json!(seq));
    m.insert("segment_sha256".into(), json!(format!("{seq:064x}")));
    m.insert(
        "prev_segment_sha256".into(),
        if seq == 0 {
            Value::Null
        } else {
            json!(format!("{:064x}", seq - 1))
        },
    );
    m.insert("byte_len".into(), json!(1));
    m.insert("duration_s".into(), json!(end_s - start_s));
    m.insert("capture_start_utc_ns".into(), json!((start_s * 1e9) as i64));
    m.insert("capture_end_utc_ns".into(), json!((end_s * 1e9) as i64));
    m.insert("encoder".into(), json!("copy"));
    m.insert("time_source".into(), json!("host-clock"));
    m.insert("mode".into(), json!("live"));
    m.insert("gap".into(), Value::Null);
    m.insert("producer_key_id".into(), json!("0".repeat(32)));
    m.insert("capture_policy".into(), policy());
    if let Some(s) = sensor {
        m.insert("sensor_signature".into(), s);
    }
    Value::Object(m)
}

fn chain_with(vals: &[Value]) -> (SessionChain, ArtifactStore) {
    let mut store = ArtifactStore::new();
    let mut entries = Vec::new();
    for (i, v) in vals.iter().enumerate() {
        let b = serde_json::to_vec(v).unwrap();
        let hash = sha256_hex(&b);
        store.insert(hash.clone(), b);
        entries.push(json!({
            "artifact_hash": hash,
            "artifact_hash_alg": "sha256",
            "artifact_id": format!("camseg:test:{i}"),
            "artifact_schema_version": "1",
            "artifact_type": "evidence_item",
            "monotonic_ns": i as u64,
            "previous_entry_hash": "00".repeat(32),
            "sequence": i as i64,
            "session_id": "camera:test:2026-09-03",
            "signer_node_id": 1u32,
            "signer_org_id": "local",
            "timestamp_ns": i as u64,
            "chain_entry_hash": "00".repeat(32),
        }));
    }
    let chain: SessionChain =
        serde_json::from_value(json!({"session_id": "camera:test:2026-09-03", "entries": entries})).unwrap();
    (chain, store)
}

// ---------------------------------------------------------------------------
// Completeness reads /3+ exactly as it reads /2
// ---------------------------------------------------------------------------

#[test]
fn v3_v4_v5_grade_completeness_like_v2() {
    for (schema, sensor) in [
        ("camera_segment/3", sensor_v3("VALID")),
        ("camera_segment/4", sensor_v4("VALID", "MATCH")),
        ("camera_segment/5", sensor_v5("VALID", "MATCH", true, true)),
    ] {
        let (chain, store) = chain_with(&[
            body(schema, 0, 0.0, 6.0, Some(sensor.clone())),
            body(schema, 1, 6.1, 12.0, Some(sensor.clone())),
        ]);
        let r = grade_capture_completeness(&chain, Some(&store));
        assert_eq!(r.grade, CaptureGrade::Continuous, "{schema}: {r:?}");
        assert_eq!(r.camera_records, 2);
    }
}

#[test]
fn an_unknown_version_is_still_unverifiable_and_named() {
    let (chain, store) = chain_with(&[body("camera_segment/9", 0, 0.0, 6.0, Some(sensor_v3("VALID")))]);
    let r = grade_capture_completeness(&chain, Some(&store));
    match r.grade {
        CaptureGrade::Unverifiable { ref reason } => {
            assert!(reason.contains("camera_segment/9"), "{reason}");
            assert!(reason.contains("will not guess"), "{reason}");
        }
        other => panic!("expected UNVERIFIABLE, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Field-set strictness
// ---------------------------------------------------------------------------

#[test]
fn the_live_axis_scar_is_failed_with_the_counts_named() {
    // Exactly the four records on the live chain: a /3 label on the 15-field
    // object. Nothing special-cases them; the general rule catches them.
    let (chain, store) = chain_with(&[body("camera_segment/3", 0, 0.0, 6.0, Some(sensor_v4("VALID", "MATCH")))]);
    let r = grade_capture_completeness(&chain, Some(&store));
    match r.grade {
        CaptureGrade::Failed { ref detail } => {
            assert!(detail.contains("15 field"), "{detail}");
            assert!(detail.contains("13 this version defines"), "{detail}");
            assert!(detail.contains("public_key_pin"), "{detail}");
            assert!(detail.contains("sensor_key_sha256"), "{detail}");
        }
        other => panic!("expected FAILED, got {other:?}"),
    }
}

#[test]
fn a_v4_label_on_a_v3_object_is_failed_too() {
    let (chain, store) = chain_with(&[body("camera_segment/4", 0, 0.0, 6.0, Some(sensor_v3("VALID")))]);
    match grade_capture_completeness(&chain, Some(&store)).grade {
        CaptureGrade::Failed { ref detail } => {
            assert!(detail.contains("13 field"), "{detail}");
            assert!(detail.contains("15 this version defines"), "{detail}");
            assert!(
                detail.contains("missing: [public_key_pin, sensor_key_sha256]"),
                "{detail}"
            );
        }
        other => panic!("expected FAILED, got {other:?}"),
    }
}

#[test]
fn a_v5_label_missing_device_chain_is_failed() {
    let (chain, store) = chain_with(&[body("camera_segment/5", 0, 0.0, 6.0, Some(sensor_v4("VALID", "MATCH")))]);
    match grade_capture_completeness(&chain, Some(&store)).grade {
        CaptureGrade::Failed { ref detail } => assert!(detail.contains("missing: [device_chain]"), "{detail}"),
        other => panic!("expected FAILED, got {other:?}"),
    }
}

#[test]
fn a_version_that_promises_a_sensor_object_and_omits_it_is_failed() {
    let (chain, store) = chain_with(&[body("camera_segment/4", 0, 0.0, 6.0, None)]);
    match grade_capture_completeness(&chain, Some(&store)).grade {
        CaptureGrade::Failed { ref detail } => assert!(detail.contains("carries no sensor_signature"), "{detail}"),
        other => panic!("expected FAILED, got {other:?}"),
    }
}

#[test]
fn v1_and_v2_are_untouched_by_the_sensor_rules() {
    // /2 has no sensor object and must not acquire an expectation of one.
    let (chain, store) = chain_with(&[
        body("camera_segment/2", 0, 0.0, 6.0, None),
        body("camera_segment/2", 1, 6.1, 12.0, None),
    ]);
    assert_eq!(
        grade_capture_completeness(&chain, Some(&store)).grade,
        CaptureGrade::Continuous
    );
}

// ---------------------------------------------------------------------------
// The summary: a claim, reported, never graded
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_verdicts_pins_and_chains() {
    let (chain, store) = chain_with(&[
        body(
            "camera_segment/5",
            0,
            0.0,
            6.0,
            Some(sensor_v5("VALID", "MATCH", true, true)),
        ),
        body(
            "camera_segment/5",
            1,
            6.0,
            12.0,
            Some(sensor_v5("VALID", "MATCH", true, true)),
        ),
        body(
            "camera_segment/5",
            2,
            12.0,
            18.0,
            Some(sensor_v5("UNVERIFIED", "MISMATCH", false, false)),
        ),
    ]);
    let s = summarise_sensor(&chain, Some(&store));
    assert_eq!(s.records, 3);
    assert_eq!(s.vendors, vec!["axis".to_owned()]);
    assert_eq!(s.device_serials, vec!["B8A44FDD572C".to_owned()]);
    assert_eq!(s.verdicts, vec![("VALID".to_owned(), 2), ("UNVERIFIED".to_owned(), 1)]);
    assert_eq!(s.pin_states, vec![("MATCH".to_owned(), 2), ("MISMATCH".to_owned(), 1)]);
    assert_eq!(
        s.chain_states,
        vec![
            ("VERIFIED-TO-HELD-ROOT".to_owned(), 2),
            ("NOT-VERIFIED-TO-HELD-ROOT".to_owned(), 1),
        ]
    );
    assert_eq!(
        s.unverified_reasons,
        vec![("signed by a key that is not the pinned one".to_owned(), 1)]
    );
}

#[test]
fn a_lossy_stream_is_never_rounded_up_to_a_clean_valid() {
    // The producer keeps gops_valid_with_missing precisely so that a VALID
    // carrying missing BUs is not indistinguishable from a clean one here.
    let mut s = sensor_v3("VALID").as_object().unwrap().clone();
    s.insert("gops_valid_with_missing".into(), json!(2));
    let (chain, store) = chain_with(&[body("camera_segment/3", 0, 0.0, 6.0, Some(Value::Object(s)))]);
    let sum = summarise_sensor(&chain, Some(&store));
    assert_eq!(sum.verdicts, vec![("VALID-with-missing".to_owned(), 1)]);
}

#[test]
fn an_unsigning_camera_is_reported_as_none_never_dropped() {
    let mut s = sensor_v3("UNSIGNED").as_object().unwrap().clone();
    s.insert("vendor".into(), Value::Null);
    s.insert("device_serial".into(), Value::Null);
    let (chain, store) = chain_with(&[body("camera_segment/3", 0, 0.0, 6.0, Some(Value::Object(s)))]);
    let sum = summarise_sensor(&chain, Some(&store));
    assert_eq!(sum.vendors, vec!["none".to_owned()]);
    assert_eq!(sum.verdicts, vec![("UNSIGNED".to_owned(), 1)]);
    assert!(sum.device_serials.is_empty());
}

#[test]
fn unverified_reasons_are_distinguished_not_merged() {
    let (chain, store) = chain_with(&[
        body(
            "camera_segment/5",
            0,
            0.0,
            6.0,
            Some(sensor_v5("UNVERIFIED", "PIN_UNREADABLE", true, true)),
        ),
        body(
            "camera_segment/5",
            1,
            6.0,
            12.0,
            Some(sensor_v5("UNVERIFIED", "MATCH", false, true)),
        ),
        body(
            "camera_segment/5",
            2,
            12.0,
            18.0,
            Some(sensor_v5("UNVERIFIED", "MATCH", true, false)),
        ),
    ]);
    let s = summarise_sensor(&chain, Some(&store));
    assert_eq!(s.unverified_reasons.len(), 3, "{:?}", s.unverified_reasons);
    let keys: Vec<&str> = s.unverified_reasons.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"pinned key unreadable"));
    assert!(keys.contains(&"certificate chain does not reach the held root"));
    assert!(keys.contains(&"leaf serial is not this device"));
}

#[test]
fn pre_v3_sessions_summarise_to_nothing_so_old_bundles_are_unchanged() {
    let (chain, store) = chain_with(&[body("camera_segment/2", 0, 0.0, 6.0, None)]);
    let s = summarise_sensor(&chain, Some(&store));
    assert!(s.is_empty());
    assert_eq!(serde_json::to_value(&s).unwrap()["records"], json!(0));
}

#[test]
fn a_hash_only_bundle_summarises_to_nothing() {
    let (chain, _store) = chain_with(&[body("camera_segment/4", 0, 0.0, 6.0, Some(sensor_v4("VALID", "MATCH")))]);
    assert!(summarise_sensor(&chain, None).is_empty());
}
