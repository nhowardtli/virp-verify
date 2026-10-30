//! Cross-identity refusal detection (EVADED_REFUSAL) at the CLI.
//!
//! Fixtures under `tests/fixtures/refusal-*-bundle/` were exported with the
//! stock exporter (`tools/export/export_bundle.py --all-sessions --artifacts`)
//! from two chain databases the NEW O-Node wrote in its own test suite
//! (virp `tests/fixtures/cross_uid_refusal/synthetic-*.db`,
//! feat/cross-uid-refusal). Nothing in them is hand-made:
//!
//! * `refusal-evaded-bundle`: a keyed `gate_rejection/2` for uid 5101
//!   (`configure terminal` on `R-CUR`), then the same operation admitted for
//!   uid 5102 seconds later — the shape of the 2026-10-29 bypass as the new
//!   daemon chains it. MUST report EVADED_REFUSAL.
//! * `refusal-clean-bundle`: an execute refusal lifted by a valid owner-signed
//!   `refusal_lifted/1` before uid 5102's retry, a chain_append-side refusal
//!   whose cross-uid retry the daemon itself blocked (`refusal_evaded/1`), and
//!   an unrelated operation. MUST be silent with the approver key, and MUST
//!   fail closed without it.
//! * `refusal-approver.pub`: the PUBLIC half of the test approver key those
//!   fixtures were lifted with (raw Ed25519, hex). Test material only.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

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

fn arg(p: PathBuf) -> String {
    p.to_str().unwrap().to_owned()
}

fn refusal_report(json: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(json).expect("json report");
    v["boundary"].get("cross_identity_refusal").cloned()
}

#[test]
fn evaded_bundle_reports_evaded_refusal_with_both_hashes() {
    let (code, out) = run(&[arg(fixture("refusal-evaded-bundle")).as_str()]);
    assert!(out.contains("EVADED_REFUSAL"), "{out}");
    assert!(out.contains("cross_identity_refusal       FAILED"), "{out}");
    assert!(out.contains("refused_uid=5101"), "{out}");
    assert!(out.contains("retry_uid=5102"), "{out}");
    assert!(out.contains("kind=execute"), "{out}");
    // Beside the verdict: the chain itself is intact, so the verdict is not
    // FAILED — but the top line must name the result.
    assert!(out.contains("boundary result cross_identity_refusal FAILED"), "{out}");
    assert_ne!(code, 1, "the chain bytes are intact; evasion is not tampering: {out}");
}

#[test]
fn evaded_bundle_json_carries_the_finding_and_the_op_key_recomputes() {
    let (_code, out) = run(&["--json", arg(fixture("refusal-evaded-bundle")).as_str()]);
    let r = refusal_report(&out).expect("cross_identity_refusal present");
    assert_eq!(r["status"]["status"], "failed", "{r}");
    assert!(r["keyed_refusals"].as_u64().unwrap() >= 1);
    assert!(r["expired_retries"].as_u64().unwrap() >= 1);
    let f = &r["findings"][0];
    assert_eq!(f["refused_uid"], 5101);
    assert_eq!(f["retry_uid"], 5102);
    assert_eq!(f["op_kind"], "execute");
    assert_eq!(
        f["op_key"],
        docket_bundle::op_key_execute("R-CUR", "configure terminal"),
        "the finding's key is what this crate derives from the body it names"
    );
    assert_eq!(f["refusal_entry_hash"].as_str().unwrap().len(), 64);
    assert_eq!(f["accepted_entry_hash"].as_str().unwrap().len(), 64);
}

#[test]
fn fail_on_evasion_exits_7_only_when_asked() {
    let (code, _) = run(&["--fail-on-evasion", arg(fixture("refusal-evaded-bundle")).as_str()]);
    assert_eq!(code, 7);
    let (code, _) = run(&[
        "--fail-on-evasion",
        "--approver-key",
        arg(fixture("refusal-approver.pub")).as_str(),
        arg(fixture("refusal-clean-bundle")).as_str(),
    ]);
    assert_ne!(code, 7);
}

#[test]
fn clean_bundle_with_approver_key_is_silent_and_counts_the_lift() {
    let (_code, out) = run(&[
        "--json",
        "--approver-key",
        arg(fixture("refusal-approver.pub")).as_str(),
        arg(fixture("refusal-clean-bundle")).as_str(),
    ]);
    let r = refusal_report(&out).expect("present");
    assert_eq!(r["status"]["status"], "verified", "{r}");
    assert_eq!(r["findings"].as_array().unwrap().len(), 0);
    assert_eq!(r["lifts_valid"], 1);
    assert!(r["daemon_blocked"].as_u64().unwrap() >= 1);
}

#[test]
fn clean_bundle_without_approver_key_fails_closed_on_the_lift() {
    let (_code, out) = run(&[arg(fixture("refusal-clean-bundle")).as_str()]);
    assert!(out.contains("EVADED_REFUSAL"), "{out}");
    assert!(out.contains("lift present but unverifiable"), "{out}");
    assert!(out.contains("lifts_unverifiable=1"), "{out}");
}

#[test]
fn wrong_approver_key_does_not_clear_the_lift() {
    // A real key, but not the one that signed the lift: the lift is INVALID,
    // the refusal stands, and the retry is reported.
    let (_code, out) = run(&[
        "--json",
        "--approver-key",
        arg(fixture("producer-keys").join("comp-clean.pub")).as_str(),
        arg(fixture("refusal-clean-bundle")).as_str(),
    ]);
    let r = refusal_report(&out).expect("present");
    assert_eq!(r["lifts_invalid"], 1, "{r}");
    assert_eq!(r["lifts_valid"], 0);
    assert_eq!(r["status"]["status"], "failed");
}

#[test]
fn bundle_without_refusals_has_no_section_and_serializes_unchanged() {
    let (_code, out) = run(&["--json", arg(fixture("inv-lock-bundle")).as_str()]);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert!(v["boundary"].get("cross_identity_refusal").is_none(), "{out}");
    let (_code, text) = run(&[arg(fixture("inv-lock-bundle")).as_str()]);
    assert!(!text.contains("cross_identity_refusal"), "{text}");
}
