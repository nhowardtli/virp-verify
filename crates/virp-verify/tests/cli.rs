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

/// The fixture's own keys.json, offered back as an examiner pin. Same file,
/// different provenance: --pin is the out-of-band channel, wherever the
/// bytes happen to live on disk.
fn pin_arg() -> String {
    fixture().join("keys.json").to_str().unwrap().to_owned()
}

#[test]
fn golden_bundle_with_pinned_key_is_cryptographically_verified_exit_0() {
    let (code, out, err) = run(&["--pin", &pin_arg(), fixture().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    assert!(out.contains("head_signature         VERIFIED"), "{out}");
    assert!(out.contains("entry_signatures       VERIFIED"), "{out}");
    assert!(out.contains("session_key_binding    VERIFIED"), "{out}");
    assert!(out.contains("signature_validity     VERIFIED"), "{out}");
    assert!(out.contains("signer_trust           PINNED"), "{out}");
    assert!(out.contains("trust_source           examiner trust store"), "{out}");
    assert!(
        out.contains("examiner-supplied key(s): 24f6ed6acbfe1009c030d7ca567c33ca"),
        "{out}"
    );
    assert!(out.contains("seal_head_match        ABSENT"), "{out}");
    assert!(out.contains("consistency            VERIFIED"), "{out}");
    assert!(out.contains("signature              UNVERIFIABLE"), "{out}");
    assert!(out.contains("secrets: none"), "{out}");
    assert!(
        out.contains("cannot prove the absence of alteration prior to the seal date"),
        "{out}"
    );
}

#[test]
fn golden_bundle_without_a_pin_demotes_to_cryptographically_consistent_exit_5() {
    // The only key came from inside the bundle. The cryptography still
    // verifies — and the top line must say the identity did not.
    let (code, out, err) = run(&[fixture().to_str().unwrap()]);
    assert_eq!(code, 5, "stderr: {err}");
    assert!(
        out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-CONSISTENT (signer trust not established)"),
        "{out}"
    );
    assert!(!out.contains("CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    // Validity is unchanged: every signature property still VERIFIED.
    assert!(out.contains("head_signature         VERIFIED"), "{out}");
    assert!(out.contains("entry_signatures       VERIFIED"), "{out}");
    assert!(out.contains("signature_validity     VERIFIED"), "{out}");
    // Trust is the axis that moved.
    assert!(out.contains("signer_trust           UNESTABLISHED"), "{out}");
    assert!(out.contains("trust_source           bundle-provided key"), "{out}");
    assert!(out.contains("came from inside the bundle being examined"), "{out}");
    assert!(out.contains("signer trust cannot be PINNED"), "{out}");
}

#[test]
fn wrong_pinned_key_is_a_mismatch_distinct_from_unestablished() {
    // A valid Ed25519 key (RFC 8032 test vector) that is NOT the session's
    // signer. The bundle's own key still checks the signatures (validity
    // VERIFIED), but the examiner's stated expectation is unmet: MISMATCH,
    // not merely UNESTABLISHED, in both the text and the JSON.
    let dir = variant("wrong-pin", "manifest.json", "docket-bundle", "docket-bundle");
    let wrong = dir.join("wrong-pin.json");
    std::fs::write(
        &wrong,
        r#"{"keys":[{"key_id":"21fe31dfa154a261626bf854046fd227","algorithm":"ed25519",
           "public_key_hex":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}]}"#,
    )
    .unwrap();
    let (code, out, err) = run(&["--pin", wrong.to_str().unwrap(), dir.to_str().unwrap()]);
    assert_eq!(code, 5, "stdout: {out}\nstderr: {err}");
    assert!(out.contains("signature_validity     VERIFIED"), "{out}");
    assert!(out.contains("signer_trust           MISMATCH"), "{out}");
    assert!(out.contains("which is not among them"), "{out}");
    assert!(!out.contains("signer_trust           UNESTABLISHED"), "{out}");

    let (jcode, json, _) = run(&["--json", "--pin", wrong.to_str().unwrap(), dir.to_str().unwrap()]);
    assert_eq!(jcode, 5);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["sessions"][0]["signer"]["trust"], "mismatch");
    assert_eq!(v["sessions"][0]["signer"]["signature_validity"]["status"], "verified");
    assert_eq!(v["pinned_key_ids"][0], "21fe31dfa154a261626bf854046fd227");
}

#[test]
fn json_output_is_machine_readable() {
    // Unpinned: the demoted shape, with the new versioned schema fields.
    let (code, out, _) = run(&["--json", fixture().to_str().unwrap()]);
    assert_eq!(code, 5);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["docket_report_version"], "docket-report/0.2");
    assert_eq!(v["verdict"], "cryptographically_consistent");
    assert_eq!(v["sessions"][0]["session_id"], "inv-lock-1");
    assert_eq!(v["sessions"][0]["verdict"], "cryptographically_consistent");
    assert_eq!(v["sessions"][0]["signer"]["signature_validity"]["status"], "verified");
    assert_eq!(v["sessions"][0]["signer"]["trust"], "unestablished");
    assert_eq!(v["sessions"][0]["signer"]["trust_source"], "bundle_provided_key");
    assert_eq!(v["sessions"][0]["seal_head_match"]["status"], "absent");
    assert_eq!(v["bundle_key_ids"][0], "24f6ed6acbfe1009c030d7ca567c33ca");
    assert!(v["pinned_key_ids"].as_array().unwrap().is_empty());
    assert_eq!(v["seal"]["consistency"]["status"], "verified");
    assert_eq!(v["seal"]["signature"]["status"], "unverifiable");
    let props = v["sessions"][0]["properties"].as_array().unwrap();
    assert_eq!(props.len(), 10);
    assert!(props
        .iter()
        .all(|p| p["status"] == "verified" || p["status"] == "absent"));

    // Pinned: full strength.
    let (code, out, _) = run(&["--json", "--pin", &pin_arg(), fixture().to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    assert_eq!(v["verdict"], "cryptographically_verified");
    assert_eq!(v["sessions"][0]["signer"]["trust"], "pinned");
    assert_eq!(v["sessions"][0]["signer"]["trust_source"], "examiner_trust_store");
    assert_eq!(v["pinned_key_ids"][0], "24f6ed6acbfe1009c030d7ca567c33ca");
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

/// The seal-derived property is named `seal_head_match`, in both the text
/// report and the JSON, and the old name `seal_anchor` appears in neither.
///
/// The old name was retired because it overclaimed. Docket compares a
/// verified session head against the seal's row for that session and checks
/// the seal's internal Merkle consistency; it does not verify the seal's
/// minisign signature (see `seal.signature`, reported UNVERIFIABLE). A
/// reader who saw `seal_anchor VERIFIED` could reasonably take it to mean
/// "an authentic dated seal was verified", when it means only "the bundle
/// agrees with the seal file sitting next to it". The status still says
/// whether the match held; only the property name changed, so that the name
/// states what was checked and the status states whether it held.
///
/// This test exists so the old string cannot come back by accident — a
/// mechanical rename elsewhere, or a revert, must fail here.
#[test]
fn seal_property_is_named_seal_head_match_not_seal_anchor() {
    let (_, out, _) = run(&[fixture().to_str().unwrap()]);
    assert!(out.contains("seal_head_match"), "text report: {out}");
    assert!(
        !out.contains("seal_anchor"),
        "old name is back in the text report: {out}"
    );

    let (_, json, _) = run(&["--json", fixture().to_str().unwrap()]);
    assert!(!json.contains("seal_anchor"), "old name is back in the JSON: {json}");
    let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let session = &v["sessions"][0];
    assert!(session.get("seal_anchor").is_none(), "old JSON key is back: {session}");
    assert!(
        session.get("seal_head_match").is_some(),
        "seal_head_match key is missing: {session}"
    );

    // The rename must not have moved the seal's own signature line, which is
    // what keeps the head match from reading as an authenticity claim.
    assert_eq!(v["seal"]["signature"]["status"], "unverifiable");
}

// ---------------------------------------------------------------------------
// Seal minisign signature (--seal-key / --seal-sig)
// ---------------------------------------------------------------------------
//
// The vector .minisig is a TEST signature over the fixture seal's bytes by a
// throwaway key (docket-bundle/tests/vectors/README.md) — not the operator's
// signature. The seal key is not a chain-signing key; no role overlap.

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docket-bundle/tests/vectors")
}

fn seal_key_arg() -> String {
    vectors().join("minisign-test.pub").to_str().unwrap().to_owned()
}

/// The fixture bundle plus the vector .minisig carried in-band, with the
/// manifest pointing at it.
fn bundle_with_carried_seal_sig(name: &str) -> PathBuf {
    let dir = variant(
        name,
        "manifest.json",
        "\"seal\": \"seal/seal-2026-08.json\"",
        "\"seal\": \"seal/seal-2026-08.json\",\n  \"seal_signature\": \"seal/seal-2026-08.json.test.minisig\"",
    );
    std::fs::copy(
        vectors().join("seal-2026-08.json.test.minisig"),
        dir.join("seal/seal-2026-08.json.test.minisig"),
    )
    .unwrap();
    dir
}

/// A second throwaway TEST public key (different minisign key id). Nothing
/// is signed under it; it exists to exercise the wrong-key grade.
const OTHER_PUB: &str = "untrusted comment: minisign public key 8D04332BB3D74D83\n\
                         RWSDTdezKzMEjc+b6zv5s53fBvOd+Bssq5m48CsB+SklPW9zu1O2NSPN\n";

#[test]
fn seal_key_with_carried_signature_verifies_and_names_the_ignored_embedded_claim() {
    let dir = bundle_with_carried_seal_sig("sealsig-carried");
    let (code, out, err) = run(&[
        "--pin",
        &pin_arg(),
        "--seal-key",
        &seal_key_arg(),
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(out.contains("signature              VERIFIED"), "{out}");
    assert!(out.contains("signature carried in the bundle"), "{out}");
    assert!(out.contains("key supplied out of band"), "{out}");
    assert!(out.contains("seal_public_key claim is ignored"), "{out}");
    // The two seal facts stay two lines: the signature line must not have
    // absorbed or replaced the per-session head match (split 2026-08-26).
    assert!(out.contains("seal_head_match"), "{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");

    let (jcode, json, _) = run(&[
        "--json",
        "--pin",
        &pin_arg(),
        "--seal-key",
        &seal_key_arg(),
        dir.to_str().unwrap(),
    ]);
    assert_eq!(jcode, 0);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["seal"]["signature"]["status"], "verified");
    assert!(v["seal"]["signature_detail"]
        .as_str()
        .unwrap()
        .contains("seal_public_key claim is ignored"));
}

#[test]
fn seal_sig_supplied_out_of_band_verifies_without_a_carried_signature() {
    // Unmodified fixture: no seal_signature in the manifest.
    let sig = vectors().join("seal-2026-08.json.test.minisig");
    let (code, out, _) = run(&[
        "--pin",
        &pin_arg(),
        "--seal-key",
        &seal_key_arg(),
        "--seal-sig",
        sig.to_str().unwrap(),
        fixture().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("signature              VERIFIED"), "{out}");
    assert!(out.contains("signature supplied out of band"), "{out}");
}

#[test]
fn tampered_seal_fails_the_signature_and_the_overall_verdict_exit_1() {
    // Flip seal content under a carried signature: the minisign check must
    // FAIL and drag the overall verdict down, even though every session
    // still verifies. (`sealed_by` is outside merkle/sessions, so seal
    // consistency still VERIFIES — the signature alone catches this edit.)
    let dir = bundle_with_carried_seal_sig("sealsig-tampered");
    let seal_path = dir.join("seal/seal-2026-08.json");
    let text = std::fs::read_to_string(&seal_path).unwrap();
    let tampered = text.replace("Nathan Howard", "Someone Else");
    assert_ne!(text, tampered);
    std::fs::write(&seal_path, tampered).unwrap();

    let (code, out, _) = run(&["--seal-key", &seal_key_arg(), dir.to_str().unwrap()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("signature              FAILED"), "{out}");
    assert!(out.contains("consistency            VERIFIED"), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
    // The sessions themselves still verified — the seal is what failed.
    assert!(out.contains("head_signature         VERIFIED"), "{out}");
}

#[test]
fn wrong_seal_key_is_unverifiable_with_both_ids_named_not_failed() {
    let dir = bundle_with_carried_seal_sig("sealsig-wrongkey");
    let other = dir.join("other.pub");
    std::fs::write(&other, OTHER_PUB).unwrap();
    let (code, out, _) = run(&[
        "--pin",
        &pin_arg(),
        "--seal-key",
        other.to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    // Wrong key = nothing checked, not tampering: verdict path untouched.
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("signature              UNVERIFIABLE"), "{out}");
    // Both ids in raw stored-byte order (minisign's comment line shows the
    // same 8 bytes reversed; Docket prints them one way, consistently).
    assert!(out.contains("592902d0ec4a755a"), "{out}"); // id the signature names
    assert!(out.contains("834dd7b32b33048d"), "{out}"); // id of the supplied key
    assert!(out.contains("nothing was checked under the supplied key"), "{out}");
}

#[test]
fn without_seal_key_output_is_unverifiable_as_before_even_with_a_carried_sig() {
    let dir = bundle_with_carried_seal_sig("sealsig-nokey");
    let (code, out, _) = run(&["--pin", &pin_arg(), dir.to_str().unwrap()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("signature              UNVERIFIABLE"), "{out}");
    assert!(
        out.contains("must arrive out of band, never from inside the bundle"),
        "{out}"
    );
    assert!(!out.contains("signature              VERIFIED"), "{out}");
}

#[test]
fn seal_key_without_any_signature_is_unverifiable_and_says_what_is_missing() {
    // Unmodified fixture (no carried sig), key supplied, no --seal-sig.
    let (code, out, _) = run(&[
        "--pin",
        &pin_arg(),
        "--seal-key",
        &seal_key_arg(),
        fixture().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("signature              UNVERIFIABLE"), "{out}");
    assert!(out.contains("no signature to check"), "{out}");
    assert!(out.contains("no --seal-sig was given"), "{out}");
}

#[test]
fn seal_flag_usage_errors_exit_2() {
    // --seal-sig without --seal-key can check nothing: usage error.
    let sig = vectors().join("seal-2026-08.json.test.minisig");
    let (code, _, err) = run(&["--seal-sig", sig.to_str().unwrap(), fixture().to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("--seal-sig is only meaningful with --seal-key"), "{err}");

    // Unreadable / malformed operator files: exit 2, nothing verified.
    let (code, _, err) = run(&["--seal-key", "/nonexistent.pub", fixture().to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(err.contains("--seal-key"), "{err}");
    let (code, _, err) = run(&[
        "--seal-key",
        &seal_key_arg(),
        "--seal-sig",
        &seal_key_arg(), // a public key is not a signature
        fixture().to_str().unwrap(),
    ]);
    assert_eq!(code, 2);
    assert!(err.contains("--seal-sig"), "{err}");
    assert!(err.contains("not a minisign document"), "{err}");
}

#[test]
fn carried_seal_signature_that_is_garbage_is_unreadable_exit_2() {
    // A carried file the reader cannot interpret at all is UNREADABLE —
    // distinct from a parseable signature that fails cryptographically.
    let dir = bundle_with_carried_seal_sig("sealsig-garbage");
    std::fs::write(dir.join("seal/seal-2026-08.json.test.minisig"), "not a minisig\n").unwrap();
    let (code, _, err) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("seal signature"), "{err}");
}

#[test]
fn manifest_seal_signature_without_a_seal_is_unreadable_exit_2() {
    let dir = variant(
        "sealsig-noseal",
        "manifest.json",
        "\"seal\": \"seal/seal-2026-08.json\"",
        "\"seal_signature\": \"seal/seal-2026-08.json.test.minisig\"",
    );
    std::fs::copy(
        vectors().join("seal-2026-08.json.test.minisig"),
        dir.join("seal/seal-2026-08.json.test.minisig"),
    )
    .unwrap();
    let (code, _, err) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("but no seal document"), "{err}");
}

#[test]
fn seal_key_against_a_bundle_with_no_seal_says_it_checked_nothing() {
    let dir = variant(
        "sealsig-sealless",
        "manifest.json",
        "\"seal\": \"seal/seal-2026-08.json\"",
        "\"x_no_seal\": null",
    );
    let (code, out, _) = run(&[
        "--pin",
        &pin_arg(),
        "--seal-key",
        &seal_key_arg(),
        dir.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("the supplied --seal-key checked nothing"), "{out}");
}
