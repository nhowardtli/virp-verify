//! End-to-end capture-completeness tests over PRODUCER-MADE evidence.
//!
//! The three comp-* fixtures were produced by the real camera producer
//! (`virp_camera.py replay`) against a real scratch O-node daemon and
//! exported by `tools/export/export_bundle.py --artifacts --keys` — never
//! hand-written. Provenance, commands and the producer's own audit output
//! are recorded in `tests/fixtures/README-comp-fixtures.md`. The producer's
//! grader graded these sessions CONTINUOUS, INTERRUPTED / ACCOUNTED and
//! INTERRUPTED / UNEXPLAINED respectively; Docket must agree.

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
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

fn run_pinned(name: &str, json: bool) -> (i32, String) {
    let dir = fixture(name);
    let pin = dir.join("keys.json");
    let mut args: Vec<&str> = Vec::new();
    if json {
        args.push("--json");
    }
    let pin_s = pin.to_str().unwrap().to_owned();
    let dir_s = dir.to_str().unwrap().to_owned();
    let mut v: Vec<&str> = args;
    v.extend(["--pin", &pin_s, &dir_s].iter().copied());
    run(&v)
}

#[test]
fn clean_session_is_continuous_and_overlaps_are_not_interruptions() {
    let (code, out) = run_pinned("comp-clean-20260829", false);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("capture_completeness   CONTINUOUS"), "{out}");
    // The producer's finalize overlap is reported as an observation…
    assert!(out.contains("windows overlap"), "{out}");
    // …and never graded as an interruption: every capture_completeness
    // RESULT line (session and boundary) says CONTINUOUS. The legend below
    // them legitimately names the INTERRUPTED grades.
    for line in out
        .lines()
        .filter(|l| l.trim_start().starts_with("capture_completeness"))
    {
        assert!(line.contains("CONTINUOUS"), "{line}");
        assert!(!line.contains("INTERRUPTED"), "{line}");
    }
}

#[test]
fn signed_gap_is_accounted_and_never_described_as_complete() {
    let (code, out) = run_pinned("comp-gap-20260829", false);
    // Completeness never moves the verdict or the exit code.
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("capture_completeness   INTERRUPTED / ACCOUNTED"), "{out}");
    assert!(out.contains("gap record: driver-restart"), "{out}");
    // ACCOUNTED must never collapse into CONTINUOUS or read as complete.
    assert!(!out.contains("capture_completeness   CONTINUOUS"), "{out}");
    assert!(!out.to_uppercase().contains("COMPLETE\n"), "{out}");
    assert!(out.contains("Accounted for is not complete"), "{out}");
}

#[test]
fn unexplained_interruption_is_loud_even_at_full_cryptographic_strength() {
    let (code, out) = run_pinned("comp-ux-20260829", false);
    // The signatures verify under a pinned key — and the capture axis still
    // reports the outage. Independent axes, both visible.
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    assert!(
        out.contains("capture_completeness   INTERRUPTED / UNEXPLAINED"),
        "{out}"
    );
    assert!(out.contains("gap record: none"), "{out}");
}

#[test]
fn json_carries_the_boundary_and_per_session_grades() {
    for (name, grade) in [
        ("comp-clean-20260829", "continuous"),
        ("comp-gap-20260829", "interrupted_accounted"),
        ("comp-ux-20260829", "interrupted_unexplained"),
    ] {
        let (code, out) = run_pinned(name, true);
        assert_eq!(code, 0, "{name}: {out}");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
        assert_eq!(v["boundary"]["capture_completeness"]["grade"], grade, "{name}");
        assert_eq!(v["sessions"][0]["capture_completeness"]["grade"], grade, "{name}");
        assert_eq!(v["boundary"]["source_device_established"]["answer"], "no", "{name}");
        let detail = v["boundary"]["source_device_established"]["detail"].as_str().unwrap();
        assert!(
            detail.contains("no independently trusted device credential"),
            "{detail}"
        );
    }
}

#[test]
fn source_device_is_no_even_on_a_bundle_that_verifies_at_full_strength() {
    let (code, out) = run_pinned("comp-clean-20260829", false);
    assert_eq!(code, 0);
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    assert!(out.contains("source_device_established    NO"), "{out}");
    assert!(
        out.contains("the signed producer identifies the source as \"comp-clean\""),
        "{out}"
    );
}

#[test]
fn unexplained_gap_details_name_the_hole() {
    let (_, out) = run_pinned("comp-ux-20260829", true);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let outages = v["sessions"][0]["capture_completeness"]["outages"].as_array().unwrap();
    assert_eq!(outages.len(), 1);
    assert_eq!(outages[0]["class"], "unexplained");
    assert_eq!(outages[0]["after_seq"], 3);
    assert_eq!(outages[0]["seq"], 4);
    let hole = outages[0]["hole_ms"].as_i64().unwrap();
    assert!((1000..2000).contains(&hole), "hole_ms {hole}");
    // The signed policy travels into the report.
    let pol = &v["sessions"][0]["capture_completeness"]["policies"][0];
    assert_eq!(pol["jitter_ms"], 300);
    assert_eq!(pol["max_unexplained_gap_ms"], 0);
}
