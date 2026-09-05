//! Build-time capture of the commit this binary was built from.
//!
//! An examiner reading a report needs to know which verifier produced it,
//! and "0.1.0" does not answer that during development: every build between
//! two releases carries the same crate version. The commit does answer it,
//! and the dirty flag answers the follow-up question — whether the working
//! tree had changes the commit does not describe.
//!
//! Nothing here may fail the build. A source tarball with no `.git`, a
//! checkout with no `git` on PATH, and a git that errors all produce
//! `unknown`, which is a truthful answer and a better one than a build
//! error or an invented hash.

use std::process::Command;

fn main() {
    // Re-run when HEAD moves or the index changes, so the embedded commit
    // does not go stale behind an otherwise-warm build cache. These paths
    // are advisory: if .git is absent they simply never fire.
    for p in [".git/HEAD", ".git/index"] {
        println!("cargo:rerun-if-changed=../../{p}");
    }
    println!("cargo:rerun-if-env-changed=PROFILE");

    let (commit, dirty) = git_identity();
    println!("cargo:rustc-env=VIRP_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=VIRP_GIT_DIRTY={dirty}");

    // Cargo sets PROFILE to "debug" or "release" for the build script. A
    // report that does not say which one it came from invites comparing a
    // debug run's output against a release run's as though they were the
    // same binary.
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=VIRP_BUILD_PROFILE={profile}");
}

/// `(short commit or "unknown", "true" | "false" | "unknown")`.
///
/// Dirty is only meaningful when the commit is known: outside a checkout
/// there is no tree to compare against, so it reports `unknown` rather than
/// the reassuring-looking `false`.
fn git_identity() -> (String, String) {
    let Some(commit) = git(&["rev-parse", "--short=7", "HEAD"]) else {
        return ("unknown".to_owned(), "unknown".to_owned());
    };
    // `--porcelain` prints one line per changed path and nothing at all for
    // a clean tree, so emptiness is the test. Untracked files count: a
    // verifier built beside an uncommitted source file is not the commit.
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) => (!s.is_empty()).to_string(),
        None => "unknown".to_owned(),
    };
    (commit, dirty)
}

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_owned())
}
