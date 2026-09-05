//! Which build produced this report.
//!
//! "0.1.0" does not identify a verifier during development: every build
//! between two releases carries it. The commit does, and the dirty flag
//! answers whether the working tree held changes that commit does not
//! describe. An examiner comparing two reports, or reproducing one, needs
//! that before anything else in the report means much — so it leads the
//! report and it closes the "Reproduce this report" line.
//!
//! What is deliberately NOT tested here is an exact string. The commit
//! changes with every commit and the profile changes with the build, so a
//! test that pinned either would pin this file to one machine-minute. What
//! is pinned is the SHAPE, and the invariant that the same identity appears
//! everywhere it is claimed to appear.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_virp-verify")
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(bin()).args(args).output().expect("run virp-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
    )
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/comp-clean-20260829")
}

fn fixture_pin() -> String {
    fixture().join("keys.json").to_str().expect("utf-8 path").to_owned()
}

fn report(dir: &Path, args: &[&str]) -> String {
    let out = Command::new(bin())
        .args(args)
        .arg(dir)
        .output()
        .expect("run virp-verify");
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

/// `virp-verify 0.1.0 (commit <7 hex>, clean, release)` and its variants.
/// Returns the parts so each test can assert on one of them.
fn parse_identity(line: &str) -> (String, String) {
    let rest = line
        .strip_prefix("virp-verify ")
        .unwrap_or_else(|| panic!("identity must name the binary: {line:?}"));
    let (version, tail) = rest.split_once(" (").unwrap_or_else(|| panic!("{line:?}"));
    let inner = tail
        .strip_suffix(')')
        .unwrap_or_else(|| panic!("identity must close its parenthesis: {line:?}"));
    (version.to_owned(), inner.to_owned())
}

#[test]
fn version_flag_reports_the_crate_version() {
    for flag in ["--version", "-V"] {
        let (code, out) = run(&[flag]);
        assert_eq!(code, 0, "{flag}: {out}");
        let line = out.lines().next().expect("one line");
        let (version, _) = parse_identity(line);
        assert_eq!(version, env!("CARGO_PKG_VERSION"), "{flag}: {line}");
    }
}

#[test]
fn the_identity_names_the_commit_the_tree_state_and_the_profile() {
    let (_, out) = run(&["--version"]);
    let line = out.lines().next().expect("one line");
    let (_, inner) = parse_identity(line);

    // Commit: either seven lowercase hex, or a named absence. Never blank,
    // and never an invented-looking value.
    assert!(inner.starts_with("commit "), "{line}");
    if inner.starts_with("commit unknown") {
        assert!(
            inner.contains("built outside a git checkout"),
            "an unknown commit must say why: {line}"
        );
        // Nothing is known about a tree that was never found, so no claim
        // about it may be made — "clean" here would be a lie of omission.
        assert!(!inner.contains("clean"), "{line}");
    } else {
        let commit = inner["commit ".len()..].split([',', ')']).next().expect("commit");
        assert_eq!(commit.len(), 7, "short commit: {line}");
        assert!(
            commit.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "commit must be lowercase hex: {line}"
        );
        // A known commit always states the tree it was built against.
        assert!(
            inner.contains(", clean,") || inner.contains(", DIRTY ("),
            "a known commit must state the tree state: {line}"
        );
    }

    // Profile: the last field, and one cargo actually produces. A report
    // that does not say which invites comparing a debug run against a
    // release run as though they were the same binary.
    let profile = inner.rsplit(", ").next().expect("profile");
    assert!(
        ["debug", "release", "unknown"].contains(&profile),
        "profile {profile:?} in {line}"
    );
    // These tests are themselves a debug build unless told otherwise, so the
    // profile is not merely present, it is right.
    assert_eq!(
        profile,
        if cfg!(debug_assertions) { "debug" } else { "release" },
        "{line}"
    );
}

#[test]
fn a_dirty_tree_is_named_as_dirty_not_implied_by_silence() {
    let (_, out) = run(&["--version"]);
    let (_, inner) = parse_identity(out.lines().next().expect("one line"));
    // Whichever state this checkout is in, exactly one claim is made.
    let clean = inner.contains(", clean,");
    let dirty = inner.contains("DIRTY (uncommitted changes at build time)");
    assert!(!(clean && dirty), "both claims at once: {inner}");
    if dirty {
        assert!(
            inner.contains("uncommitted changes"),
            "DIRTY must say what it means: {inner}"
        );
    }
}

#[test]
fn the_identity_is_the_first_line_of_a_text_report() {
    let (_, version_out) = run(&["--version"]);
    let identity = version_out.lines().next().expect("identity").to_owned();

    for args in [vec![], vec!["--pin".to_owned(), fixture_pin()]] {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let text = report(&fixture(), &refs);
        let first = text.lines().next().expect("first line");
        assert!(
            first.starts_with(&identity),
            "report must lead with the build identity\n  want prefix: {identity}\n  got:         {first}"
        );
        // The descriptive banner is not lost to the version; it follows on
        // the same line, so the report still says what the tool is.
        assert!(first.ends_with("— Docket standalone VIRP chain verifier"), "{first}");
    }
}

#[test]
fn the_reproduce_line_names_the_build_that_produced_the_report() {
    let (_, version_out) = run(&["--version"]);
    let identity = version_out.lines().next().expect("identity");

    let text = report(&fixture(), &["--pin", &fixture_pin()]);
    let repro = text
        .lines()
        .find(|l| l.starts_with("Reproduce this report:"))
        .expect("reproduce line");
    assert!(repro.contains(identity), "\n  want: {identity}\n  in:   {repro}");
    // The command itself survives: the instruction someone acts on is still
    // the first thing in the line, not buried behind the identity.
    assert!(
        repro.contains("(add --pin <examiner-key.json> to establish signer trust)"),
        "{repro}"
    );
}

#[test]
fn the_same_identity_appears_on_every_surface_that_claims_it() {
    let (_, version_out) = run(&["--version"]);
    let identity = version_out.lines().next().expect("identity");
    let text = report(&fixture(), &["--pin", &fixture_pin()]);
    // One build_identity(), so a reader cannot be shown two answers to
    // "which binary wrote this" from one run.
    assert_eq!(
        text.matches(identity).count(),
        2,
        "identity must appear exactly twice (first line, reproduce line):\n{text}"
    );
}

/// The machine-readable report is a versioned schema describing EVIDENCE.
/// A build identity is a fact about the tool, and `docket view` serves this
/// same JSON byte-for-byte from the same serializer — so it stays out, and
/// the schema version stays where it was.
#[test]
fn the_json_report_does_not_carry_the_build_identity() {
    let json = report(&fixture(), &["--json", "--pin", &fixture_pin()]);
    let v: Value = serde_json::from_str(&json).expect("valid json");
    let obj = v.as_object().expect("object");
    for absent in ["build", "version", "verifier", "commit", "profile"] {
        assert!(!obj.contains_key(absent), "--json gained a {absent:?} field:\n{json}");
    }
    assert!(!json.contains("virp-verify 0."), "identity leaked into --json:\n{json}");
    assert!(obj.contains_key("docket_report_version"), "{json}");
}

#[test]
fn the_help_text_documents_the_flag() {
    let (code, out) = run(&["--help"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("-V, --version"), "{out}");
}
