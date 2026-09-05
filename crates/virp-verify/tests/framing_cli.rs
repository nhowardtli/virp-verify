//! Top-line verdict framing: a FAILED boundary result must ride in the
//! OVERALL VERDICT line itself.
//!
//! The tension this guards: the report leads with the verdict, and
//! capture_completeness is a boundary result, not a property — an
//! unmeasurable or defective capture declaration does not weaken the proof
//! of the records that exist, so it never moves the verdict or the exit
//! code. That classification is correct AND it once let a reader quote
//! "OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED" while a result literally
//! named FAILED stood further down the page. The rule now: whenever a
//! boundary result is FAILED, the top line carries that fact; the verdict
//! value, the JSON and the exit code stay untouched.
//!
//! The rule is not capture-specific: it names every result that sits
//! BESIDE the verdict rather than inside it. `producer_signature` FAILED
//! and `producer_trust` MISMATCH are the capture host's key, a different
//! trust boundary from the O-Node chain key — they must never be folded
//! into the chain verdict, and for exactly that reason they must be named
//! in the top line.
//!
//! The bundles are built here, deliberately (no producer emits them): a
//! keyless session whose hashes, genesis and links all hold, carrying a
//! camera_segment/2 body — for the capture case, one whose first-record gap
//! cites a non-adjacent predecessor; for the producer case, a REAL
//! producer-signed comp-clean body with one hex digit flipped inside
//! `producer_sig`, re-hashed into the chain so the artifact binding is
//! intact and the producer signature is the only thing wrong.
//!
//! The keyless chain caps the verdict at CONSISTENT-UNAUTHENTICATED here:
//! altering a producer_sig inside a SIGNED session would break the chain
//! entry hash it commits to, and Docket holds no chain private key to
//! re-sign with. The CRYPTOGRAPHICALLY-VERIFIED rendering of the same rule
//! is asserted as a unit test over `BundleReport::verdict_line` in
//! `docket-bundle/src/bundle.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use docket_bundle::{sha256_hex, EntryFields};
use serde_json::{json, Value};

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_virp-verify"))
        .args(args)
        .arg(dir)
        .output()
        .expect("run virp-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
    )
}

fn write_json(path: &Path, v: &Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// A keyless one-session bundle whose single entry carries the given body,
/// with correct hashes, genesis, links and head commitment.
fn bundle_with_body(name: &str, body: &[u8]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("framing-{name}"));
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

/// A camera_segment/2 body whose first-record gap cites a NON-ADJACENT
/// predecessor: capture_completeness FAILED, on evidence whose keyless
/// cryptography is fully intact.
fn failing_capture_body() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "camera_segment/2",
        "camera_id": "framing-cam",
        "device": "framing-cam",
        "segment_seq": 9,
        "segment_sha256": "11".repeat(32),
        "prev_segment_sha256": "22".repeat(32),
        "byte_len": 1,
        "duration_s": 6.0,
        "capture_start_utc_ns": 0i64,
        "capture_end_utc_ns": 6_000_000_000i64,
        "encoder": "copy",
        "time_source": "file-mtime",
        "mode": "replay",
        "gap": {"after_seq": 3, "reason": "driver-restart"},
        "producer_key_id": "00".repeat(16),
        "producer_sig": "00".repeat(64),
        "capture_policy": {"nominal_segment_s": 6.0, "jitter_s": 2.0, "max_unexplained_gap_s": 0.0},
    }))
    .unwrap()
}

#[test]
fn a_failed_boundary_result_rides_in_the_top_line() {
    let root = bundle_with_body("failed-boundary", &failing_capture_body());
    let (code, out) = run(&root, &[]);

    // The axes stay separate: the verdict and the exit code are exactly
    // what the cryptography alone earns.
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("capture_completeness   FAILED"), "{out}");

    // The top line carries the boundary failure — it cannot be quoted in
    // isolation as a clean result…
    assert!(
        out.contains(
            "OVERALL VERDICT: CONSISTENT-UNAUTHENTICATED — boundary result capture_completeness \
             FAILED (beside this verdict, not inside it)"
        ),
        "{out}"
    );
    // …and the bare form no longer appears as the whole line.
    assert!(!out.contains("OVERALL VERDICT: CONSISTENT-UNAUTHENTICATED\n"), "{out}");
}

#[test]
fn the_failed_boundary_qualifier_changes_neither_json_verdict_nor_exit_code() {
    let root = bundle_with_body("failed-boundary-json", &failing_capture_body());
    let (code, out) = run(&root, &["--json"]);
    assert_eq!(code, 4, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();
    // The JSON verdict is the untouched machine token; the FAILED boundary
    // sits beside it in the same document, as structure rather than prose.
    assert_eq!(v["verdict"], "consistent_unauthenticated");
    assert_eq!(v["boundary"]["capture_completeness"]["grade"], "failed");

    // The opt-in coverage gate still reads the grade beside the verdict.
    let (code, _) = run(&root, &["--fail-on-coverage"]);
    assert_eq!(code, 6);
}

#[test]
fn a_non_failed_boundary_leaves_the_top_line_bare() {
    // The comp-gap fixture: INTERRUPTED / ACCOUNTED is not FAILED, so the
    // verdict line stays exactly the verdict.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/comp-gap-20260829");
    let (code, out) = run(&dir, &[]);
    assert_eq!(code, 5, "{out}");
    assert!(!out.contains("boundary result capture_completeness FAILED"), "{out}");
    assert!(
        out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-CONSISTENT (signer trust not established)\n"),
        "{out}"
    );
}

/// A real producer-signed body with one hex digit flipped inside
/// `producer_sig`, and the chain re-hashed around it: every keyless
/// property holds, the artifact binding is VERIFIED (the body is intact
/// against what the chain commits to), and the ONLY thing wrong is the
/// capture host's signature over the record.
fn altered_producer_sig_body() -> Vec<u8> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/comp-clean-20260829/artifacts");
    let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("comp-clean artifacts")
        .map(|e| e.expect("dir entry").path())
        .collect();
    names.sort();
    let text = std::fs::read_to_string(&names[0]).expect("read producer body");
    let at = text.find("\"producer_sig\":\"").expect("producer_sig present") + "\"producer_sig\":\"".len();
    let old = text.as_bytes()[at] as char;
    let new = if old == '0' { '1' } else { '0' };
    let mut altered = text.clone();
    altered.replace_range(at..at + 1, &new.to_string());
    assert_ne!(altered, text, "the flip must change the bytes");
    altered.into_bytes()
}

fn producer_key_arg() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/producer-keys/comp-clean.pub")
        .to_str()
        .expect("utf-8 path")
        .to_owned()
}

#[test]
fn a_failed_producer_signature_rides_in_the_top_line() {
    let root = bundle_with_body("failed-producer", &altered_producer_sig_body());
    let key = producer_key_arg();
    let (code, out) = run(&root, &["--producer-key", &key]);

    // Untouched: the producer key is not the chain key, so a failure there
    // moves neither the verdict nor the exit code.
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("producer_signature     FAILED"), "{out}");
    // The bodies really are intact — this is not the artifact-binding
    // failure wearing a producer costume.
    assert!(out.contains("artifact_binding"), "{out}");
    assert!(!out.contains("artifact_binding       FAILED"), "{out}");

    // The top line names both producer results.
    let first = out
        .lines()
        .find(|l| l.starts_with("OVERALL VERDICT:"))
        .expect("verdict line");
    assert!(
        first.contains("boundary result producer_signature FAILED (session camera:framing:2026-08-30)"),
        "{first}"
    );
    assert!(
        first.contains("boundary result producer_trust MISMATCH (session camera:framing:2026-08-30)"),
        "{first}"
    );
    assert!(!out.contains("OVERALL VERDICT: CONSISTENT-UNAUTHENTICATED\n"), "{out}");
}

#[test]
fn the_json_headline_carries_the_same_annotation_as_the_page() {
    let root = bundle_with_body("failed-producer-json", &altered_producer_sig_body());
    let key = producer_key_arg();
    let (code, out) = run(&root, &["--json", "--producer-key", &key]);
    assert_eq!(code, 4, "{out}");
    let v: Value = serde_json::from_str(&out).unwrap();

    // `verdict` stays the machine token…
    assert_eq!(v["verdict"], "consistent_unauthenticated");
    assert_eq!(v["sessions"][0]["producer"]["signature_validity"]["status"], "failed");
    assert_eq!(v["sessions"][0]["producer"]["trust"], "mismatch");

    // …and `headline` is the SAME string the rendered page puts on top, so
    // a consumer that quotes a headline cannot quote a cleaner one than a
    // reader sees.
    let headline = v["headline"].as_str().expect("headline field");
    assert!(
        headline.contains("boundary result producer_signature FAILED (session camera:framing:2026-08-30)"),
        "{headline}"
    );
    assert!(
        headline.contains("boundary result producer_trust MISMATCH (session camera:framing:2026-08-30)"),
        "{headline}"
    );
    let (_, text) = run(&root, &["--producer-key", &key]);
    let first = text
        .lines()
        .find(|l| l.starts_with("OVERALL VERDICT:"))
        .expect("verdict line");
    assert_eq!(first, format!("OVERALL VERDICT: {headline}"));
}

/// The clean fixture proves the annotation is evidence-driven, not
/// unconditional: the same bundle with the RIGHT producer key and an
/// unaltered body carries no producer clause at all.
#[test]
fn an_intact_producer_signature_leaves_the_top_line_bare() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/comp-clean-20260829");
    let pin = dir.join("keys.json").to_str().unwrap().to_owned();
    let key = producer_key_arg();
    let (code, out) = run(&dir, &["--pin", &pin, "--producer-key", &key]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED\n"), "{out}");
    assert!(!out.contains("boundary result producer"), "{out}");
}
