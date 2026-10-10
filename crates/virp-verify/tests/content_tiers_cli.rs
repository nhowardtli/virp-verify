use docket_bundle::{sha256_hex, EntryFields};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
fn write_json(path: &Path, v: &Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// A keyless one-session bundle whose single entry carries the given body,
/// with correct hashes, genesis, links and head commitment.
fn bundle_with_body(name: &str, body: &[u8]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("content-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    let session_id = "camera:framing:2026-08-30";
    let body_hash = sha256_hex(body);
    let fields = EntryFields {
        artifact_hash: body_hash.clone(),
        artifact_hash_alg: "sha256".to_owned(),
        artifact_id: "camseg:framing:0".to_owned(),
        artifact_schema_version: "1".to_owned(),
        artifact_type: "evidence_item".to_owned(),
        monotonic_ns: 1_000,
        previous_entry_hash: docket_bundle::genesis_hash_hex(session_id),
        sequence: 0,
        session_id: session_id.to_owned(),
        signer_node_id: 13,
        signer_org_id: "local".to_owned(),
        timestamp_ns: 1_787_000_000_000_000_000,
    };
    let entry_hash = sha256_hex(&fields.canonical_bytes());
    let mut entry = serde_json::to_value(&fields).unwrap();
    entry["chain_entry_hash"] = json!(entry_hash);
    write_json(
        &root.join("sessions/s.json"),
        &json!({
            "session_id": session_id,
            "entries": [entry],
            "head": {
                "session_id": session_id,
                "last_sequence": 0,
                "last_entry_hash": entry_hash,
            },
        }),
    );
    std::fs::create_dir_all(root.join("artifacts")).unwrap();
    std::fs::write(root.join("artifacts").join(&body_hash), body).unwrap();
    write_json(
        &root.join("manifest.json"),
        &json!({
            "docket_bundle_version": "docket-bundle/0.1",
            "chain_format": "v1",
            "sessions": [{"session_id": session_id, "path": "sessions/s.json"}],
            "artifacts": [{"artifact_hash": body_hash, "path": format!("artifacts/{body_hash}")}],
        }),
    );
    root
}
#[test]
fn bound_labels_and_counts_match_text_json_and_tamper_is_unverified() {
    let root = bundle_with_body("labels", br#"{"content_tier":"observed","mode":"tap"}"#);
    let invoke = |json: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_virp-verify"));
        if json {
            c.arg("--json");
        }
        c.arg(&root).output().unwrap()
    };
    let good = invoke(true);
    let v: Value = serde_json::from_slice(&good.stdout).unwrap();
    assert_eq!(v["content"]["tier_counts"]["observed"], 1);
    assert_eq!(v["content"]["entries"][0]["mode"], "tap");
    assert!(
        v["content"].get("producer_summary").is_none(),
        "unsigned chain cannot get signed-by summary"
    );
    assert!(String::from_utf8(invoke(false).stdout)
        .unwrap()
        .contains("content_tier=observed mode=tap"));
    let artifact = std::fs::read_dir(root.join("artifacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::write(artifact, br#"{"content_tier":"self-reported","mode":"witness"}"#).unwrap();
    let bad = invoke(true);
    assert_eq!(bad.status.code(), Some(1));
    let v: Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(v["content"]["entries"][0]["content_tier"], "unverified");
    assert_eq!(v["content"]["entries"][0]["mode"], "unverified");
    assert_eq!(v["content"]["tier_counts"]["unverified"], 1);
    assert!(v["content"]["tier_counts"].get("self-reported").is_none());
    assert!(String::from_utf8(invoke(false).stdout)
        .unwrap()
        .contains("content_tier=unverified mode=unverified"));
    std::fs::remove_dir_all(root).unwrap();
}
