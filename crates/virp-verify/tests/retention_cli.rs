//! End-to-end: what an examiner sees when a bundle carries a
//! `camera_retention/1` record.
//!
//! `tests/fixtures/retention-scratch` is a REAL bundle, exported from the
//! O-node at 10.0.0.13 on 2026-09-05 for the session
//! `camera-retention:retention-test-0905:2026-09-05` — one record, written
//! and signed by `virp_camera.py retention` on the Spark capture host and
//! appended through the daemon. The producer key beside it is the PUBLIC
//! half of the scratch key that signed it; the private half was destroyed
//! after the run, and the key is deliberately NOT in any pin store — it is
//! supplied on the command line, out of band, exactly as an examiner would.

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .to_str()
        .expect("utf-8 path")
        .to_owned()
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_virp-verify"))
        .args(args)
        .output()
        .expect("run virp-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
    )
}

fn bundle() -> String {
    fixture("retention-scratch")
}

fn producer() -> String {
    fixture("producer-keys/producer-retention-test-0905.pub")
}

#[test]
fn the_retention_record_producer_signature_verifies_out_of_band() {
    let (_, out) = run(&["--producer-key", &producer(), &bundle()]);
    assert!(
        out.contains("producer_signature     VERIFIED"),
        "a camera_retention/1 body is producer-signed and must be graded as one:\n{out}"
    );
    assert!(out.contains("c6c25fdc2aefa10338933b2bbd519515"), "{out}");
}

#[test]
fn without_the_key_it_is_unverifiable_not_absent() {
    let (_, out) = run(&[&bundle()]);
    assert!(
        out.contains("producer_signature     UNVERIFIABLE"),
        "a record this verifier DOES examine, with no key supplied, is an open \
         question — not an absence:\n{out}"
    );
    assert!(!out.contains("producer_signature     VERIFIED"), "{out}");
}

#[test]
fn the_declaration_is_listed_with_its_policy_and_count() {
    let (_, out) = run(&["--producer-key", &producer(), &bundle()]);
    assert!(out.contains("retention declaration"), "{out}");
    assert!(out.contains("policy_days 30"), "{out}");
    assert!(out.contains("removed_count 6"), "{out}");
    assert!(out.contains("capture-host"), "{out}");
}

#[test]
fn a_retention_record_never_becomes_capture_coverage() {
    let (_, out) = run(&["--producer-key", &producer(), &bundle()]);
    // The declaration is listed, and coverage still refuses to grade a
    // session with no segments. A deletion is not capture.
    assert!(out.contains("capture_completeness   UNVERIFIABLE"), "{out}");
    assert!(
        out.contains("no camera_segment records among the carried bodies"),
        "{out}"
    );
}

#[test]
fn the_verdict_is_unchanged_by_the_new_grading() {
    // Chain-structural verdict is a separate axis and must not move because
    // a producer key was or was not supplied.
    let (rc_with, with) = run(&["--producer-key", &producer(), &bundle()]);
    let (rc_without, without) = run(&[&bundle()]);
    assert_eq!(rc_with, rc_without, "a producer key must not move the exit code");
    for out in [&with, &without] {
        assert!(
            out.contains("OPERATOR-ATTESTED") || out.contains("CRYPTOGRAPHICALLY-VERIFIED"),
            "{out}"
        );
    }
}
