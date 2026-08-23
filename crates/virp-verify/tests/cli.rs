//! Step 4: the CLI verifies the synthetic fixture bundle built from the
//! golden vectors, and reports every tampered variant honestly.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inv-lock-bundle")
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_virp-verify"))
        .args(args)
        .output()
        .expect("run virp-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Copy the fixture bundle into a scratch dir under cargo's target tmpdir
/// and apply a text substitution to one file.
fn variant(name: &str, file: &str, from: &str, to: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("virp-verify-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture(), &dir);
    let path = dir.join(file);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{file} does not contain {from:?}");
    std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
    dir
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

const ENTRY_SIG_PREFIX: &str = "9626512b488a795de6156f70a6bf47fd";
const HEAD_SIG_PREFIX: &str = "fa78fc4b10f486b9a47544e90a58751f";

#[test]
fn golden_bundle_is_cryptographically_verified_exit_0() {
    let (code, out, err) = run(&[fixture().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    assert!(out.contains("head_signature         VERIFIED"), "{out}");
    assert!(out.contains("entry_signatures       VERIFIED"), "{out}");
    assert!(out.contains("session_key_binding    VERIFIED"), "{out}");
    assert!(out.contains("seal_anchor            ABSENT"), "{out}");
    assert!(out.contains("consistency            VERIFIED"), "{out}");
    assert!(out.contains("signature              UNVERIFIABLE"), "{out}");
    assert!(out.contains("secrets: none"), "{out}");
    assert!(
        out.contains("cannot prove the absence of alteration prior to the seal date"),
        "{out}"
    );
}

#[test]
fn json_output_is_machine_readable() {
    let (code, out, _) = run(&["--json", fixture().to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["verdict"], "cryptographically_verified");
    assert_eq!(v["sessions"][0]["session_id"], "inv-lock-1");
    assert_eq!(v["sessions"][0]["verdict"], "cryptographically_verified");
    assert_eq!(v["sessions"][0]["seal_anchor"]["status"], "absent");
    assert_eq!(v["seal"]["consistency"]["status"], "verified");
    assert_eq!(v["seal"]["signature"]["status"], "unverifiable");
    let props = v["sessions"][0]["properties"].as_array().unwrap();
    assert_eq!(props.len(), 10);
    assert!(props
        .iter()
        .all(|p| p["status"] == "verified" || p["status"] == "absent"));
}

#[test]
fn without_keys_the_verdict_is_operator_attested_exit_3() {
    let dir = variant("nokeys", "manifest.json", "\"keys\": \"keys.json\",", "");
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("keys:    none supplied"), "{out}");
    assert!(out.contains("head_signature         UNVERIFIABLE"), "{out}");
    assert!(
        out.contains("OVERALL VERDICT: OPERATOR-ATTESTED (unverifiable by this verifier)"),
        "{out}"
    );
    assert!(!out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"));
}

#[test]
fn tampered_entry_signature_fails_exit_1() {
    let dir = variant(
        "tamper-entry-sig",
        "sessions/inv-lock-1.json",
        ENTRY_SIG_PREFIX,
        "9626512b488a795de6156f70a6bf47fe",
    );
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("entry_signatures       FAILED"), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

#[test]
fn tampered_head_signature_fails_exit_1() {
    let dir = variant(
        "tamper-head-sig",
        "sessions/inv-lock-1.json",
        HEAD_SIG_PREFIX,
        "fa78fc4b10f486b9a47544e90a58751e",
    );
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("head_signature         FAILED"), "{out}");
}

#[test]
fn tampered_field_fails_hash_exit_1() {
    let dir = variant(
        "tamper-field",
        "sessions/inv-lock-1.json",
        "\"artifact_id\": \"obs:inv-lock:0001\"",
        "\"artifact_id\": \"obs:inv-lock:0002\"",
    );
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("entry_hashes           FAILED"), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

#[test]
fn json_failed_property_names_failure_without_key_collision() {
    let dir = variant(
        "tamper-field-json",
        "sessions/inv-lock-1.json",
        "\"artifact_id\": \"obs:inv-lock:0001\"",
        "\"artifact_id\": \"obs:inv-lock:0002\"",
    );
    let (code, out, _) = run(&["--json", dir.to_str().unwrap()]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let props = v["sessions"][0]["properties"].as_array().unwrap();
    let p = props.iter().find(|p| p["name"] == "entry_hashes").unwrap();
    assert_eq!(p["status"], "failed");
    // The failure text has its own key; a JSON parser keeps BOTH it and the
    // generic detail (the old duplicate-"detail" collision dropped this).
    assert!(
        p["failure"]
            .as_str()
            .is_some_and(|d| d.contains("entry hash mismatch at sequence 0")),
        "{out}"
    );
    assert!(
        p["detail"].as_str().is_some_and(|d| d.contains("entries recomputed")),
        "{out}"
    );
}

#[test]
fn stripped_entry_signature_fails_even_keyless_exit_1() {
    // Remove the entry's signature object but leave the signed head: the
    // session-granularity rule catches it with or without the key.
    let dir = variant(
        "strip-entry-sig",
        "sessions/inv-lock-1.json",
        &format!("\"signature_hex\": \"{ENTRY_SIG_PREFIX}"),
        &format!("\"signature_hex_stripped\": \"{ENTRY_SIG_PREFIX}"),
    );
    // serde: missing `signature_hex` inside `signature` is a JSON error → unreadable (2).
    // That is the strict reader doing its job; to test the verifier's rule we
    // instead rename the whole signature object.
    let (code, _, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2);

    let dir = variant(
        "strip-entry-sig-2",
        "sessions/inv-lock-1.json",
        "\"signature\": {\n        \"signature_scheme\"",
        "\"signature_removed\": {\n        \"signature_scheme\"",
    );
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("session_key_binding    FAILED"), "{out}");
    assert!(out.contains("stripped signature"), "{out}");
    let nokeys = variant(
        "strip-entry-sig-nokeys",
        "sessions/inv-lock-1.json",
        "\"signature\": {\n        \"signature_scheme\"",
        "\"signature_removed\": {\n        \"signature_scheme\"",
    );
    let manifest = nokeys.join("manifest.json");
    let m = std::fs::read_to_string(&manifest)
        .unwrap()
        .replace("\"keys\": \"keys.json\",", "");
    std::fs::write(&manifest, m).unwrap();
    let (code, out, _) = run(&[nokeys.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("session_key_binding    FAILED"), "{out}");
}

#[test]
fn unsigned_session_without_hmac_is_consistent_unauthenticated_exit_4() {
    // Strip BOTH signatures (the head's too): now nothing attests.
    let dir = variant(
        "unsigned",
        "sessions/inv-lock-1.json",
        "\"signature\": {\n        \"signature_scheme\"",
        "\"signature_removed\": {\n        \"signature_scheme\"",
    );
    let p = dir.join("sessions/inv-lock-1.json");
    let t = std::fs::read_to_string(&p).unwrap().replace(
        "\"signature\": {\n      \"signature_scheme\"",
        "\"signature_removed\": {\n      \"signature_scheme\"",
    );
    std::fs::write(&p, t).unwrap();
    let (code, out, _) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("head_signature         ABSENT"), "{out}");
    assert!(out.contains("OVERALL VERDICT: CONSISTENT-UNAUTHENTICATED"), "{out}");
}

#[test]
fn mislabelled_key_id_is_unreadable_exit_2() {
    let dir = variant(
        "bad-keyid",
        "keys.json",
        "24f6ed6acbfe1009c030d7ca567c33ca",
        "00000000000000000000000000000000",
    );
    let (code, out, err) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2, "{out}");
    assert!(err.contains("claims key_id"), "{err}");
    assert!(err.contains("UNREADABLE"), "{err}");
}

#[test]
fn path_escape_in_manifest_is_rejected_exit_2() {
    let dir = variant(
        "escape",
        "manifest.json",
        "\"path\": \"sessions/inv-lock-1.json\"",
        "\"path\": \"../../../etc/passwd\"",
    );
    let (code, _, err) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("escapes the bundle"), "{err}");
}

#[test]
fn wrong_bundle_version_is_rejected_exit_2() {
    let dir = variant("version", "manifest.json", "docket-bundle/0.1", "docket-bundle/9.9");
    let (code, _, err) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("unsupported docket_bundle_version"), "{err}");
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(run(&[]).0, 2);
    assert_eq!(run(&["--bogus", "x"]).0, 2);
    assert_eq!(run(&["/nonexistent/bundle"]).0, 2);
    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("never signs"));
}
