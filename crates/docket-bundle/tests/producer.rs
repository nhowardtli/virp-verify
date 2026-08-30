//! Producer-signature unit tests: the Python-compatible canonicalizer
//! against vectors produced by the producer's own serialization call
//! (`json.dumps(obj, sort_keys=True, separators=(",", ":"),
//! ensure_ascii=True)` — outputs captured verbatim), and the grader arms
//! that need no signature to exercise. End-to-end verification against real
//! producer output lives in `crates/virp-verify/tests/producer_cli.rs`.

use docket_bundle::canonical_json_bytes;
use docket_bundle::producer::grade_producer_signatures;
use docket_bundle::sha256_hex;
use docket_bundle::verify::{ArtifactStore, SessionChain, SignerTrust, Status};
use serde_json::{json, Value};

fn canon(v: &Value) -> String {
    String::from_utf8(canonical_json_bytes(v)).unwrap()
}

#[test]
fn canonical_bytes_match_python_dumps_vectors() {
    // Captured from python3 json.dumps(..., sort_keys=True,
    // separators=(",", ":"), ensure_ascii=True) on 2026-08-29.
    // (Known, deliberate divergence outside these vectors: the JSON literal
    // `-0`, which Python reads as int 0 and serde_json as float -0.0. No
    // producer emits it, and the divergence can only make a signature FAIL
    // to verify — never verify wrongly.)
    let v: Value = serde_json::from_str(
        r#"{"z": "héllo\n", "a": 1.5, "k": [true, null], "b": 6.0, "n": -5, "g": {"y": 2, "x": 1}}"#,
    )
    .unwrap();
    assert_eq!(
        canon(&v),
        "{\"a\":1.5,\"b\":6.0,\"g\":{\"x\":1,\"y\":2},\"k\":[true,null],\"n\":-5,\"z\":\"h\\u00e9llo\\n\"}"
    );

    // Non-BMP chars become surrogate pairs; the JSON two-char escapes stay.
    let v = json!({"emoji": "😀", "tab": "\t", "quote": "\"q\\"});
    assert_eq!(
        canon(&v),
        "{\"emoji\":\"\\ud83d\\ude00\",\"quote\":\"\\\"q\\\\\",\"tab\":\"\\t\"}"
    );

    // Producer-real magnitudes: ns timestamps as exact integers, policy
    // floats with the trailing .0 Python's repr keeps.
    let v = json!({"i": 1788044588423437477u64, "f": 6.134, "p": {"jitter_s": 2.0, "max_unexplained_gap_s": 0.0}});
    assert_eq!(
        canon(&v),
        r#"{"f":6.134,"i":1788044588423437477,"p":{"jitter_s":2.0,"max_unexplained_gap_s":0.0}}"#
    );
}

/// A minimal camera body; `producer_sig` is deliberately fake hex — these
/// tests exercise the arms that never reach signature verification.
fn cam_body(with_kid: bool, with_sig: bool) -> Value {
    let mut b = json!({
        "schema": "camera_segment/2",
        "camera_id": "cam",
        "segment_seq": 0,
    });
    if with_kid {
        b["producer_key_id"] = json!("00000000000000000000000000000000");
    }
    if with_sig {
        b["producer_sig"] = json!("00".repeat(64));
    }
    b
}

fn chain_with(bodies: &[Value]) -> (SessionChain, ArtifactStore) {
    let mut store = ArtifactStore::new();
    let mut entries = Vec::new();
    for (i, v) in bodies.iter().enumerate() {
        let bytes = serde_json::to_vec(v).unwrap();
        let hash = sha256_hex(&bytes);
        store.insert(hash.clone(), bytes);
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
    let chain: SessionChain =
        serde_json::from_value(json!({"session_id": "camera:test:2026-08-29", "entries": entries})).unwrap();
    (chain, store)
}

#[test]
fn no_bodies_is_unverifiable_and_unestablished() {
    let (chain, _) = chain_with(&[]);
    let r = grade_producer_signatures(&chain, None, &[]);
    assert!(matches!(r.signature_validity, Status::Unverifiable { .. }), "{r:?}");
    assert_eq!(r.trust, SignerTrust::Unestablished);
    assert!(r.trust_source.is_none());
}

#[test]
fn no_camera_records_is_absent() {
    let (chain, store) = chain_with(&[json!({"schema": "other/1"})]);
    let r = grade_producer_signatures(&chain, Some(&store), &[]);
    assert_eq!(r.signature_validity, Status::Absent, "{r:?}");
    assert_eq!(r.trust, SignerTrust::Unestablished);
}

#[test]
fn no_supplied_key_is_unverifiable_never_verified() {
    let (chain, store) = chain_with(&[cam_body(true, true)]);
    let r = grade_producer_signatures(&chain, Some(&store), &[]);
    assert!(matches!(r.signature_validity, Status::Unverifiable { .. }), "{r:?}");
    assert_eq!(r.trust, SignerTrust::Unestablished);
    assert_eq!(r.claimed_key_ids, vec!["00000000000000000000000000000000".to_owned()]);
}

#[test]
fn camera_record_missing_sig_fields_is_failed_even_without_keys() {
    for (with_kid, with_sig) in [(false, true), (true, false)] {
        let (chain, store) = chain_with(&[cam_body(with_kid, with_sig)]);
        let r = grade_producer_signatures(&chain, Some(&store), &[]);
        assert!(r.signature_validity.is_failed(), "kid={with_kid} sig={with_sig}: {r:?}");
    }
}
