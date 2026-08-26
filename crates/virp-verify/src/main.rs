//! virp-verify — standalone VIRP chain verifier (Docket).
//!
//! Reads an evidence bundle, recomputes hashes, links and detached Ed25519
//! signatures, and prints a per-property report with an honest verdict.
//! Never signs, never holds secret material, never executes anything.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use docket_bundle::bundle::{Bundle, BundleReport};
use docket_bundle::verify::{Status, Verdict};
use docket_bundle::Limits;

const USAGE: &str = "\
virp-verify — Docket standalone VIRP chain verifier

USAGE:
    virp-verify [--json] [--max-sessions N] [--max-entries N] <bundle-dir>

ARGS:
    <bundle-dir>   a Docket evidence bundle directory (manifest.json at its root)

OPTIONS:
    --json               print the full report as JSON instead of text
    --max-sessions N     reject a bundle listing more than N sessions (default 10000)
    --max-entries N      reject a bundle carrying more than N entries in total (default 1000000)
    -h, --help           show this help

RESOURCE LIMITS:
    A bundle is supplied by whoever wants it verified, so its size is not
    trusted. File sizes, session and entry counts, artifact-body sizes and
    string field lengths all have ceilings; exceeding one is UNREADABLE (2),
    never a verdict. The defaults sit orders of magnitude above the largest
    real bundle observed (3456 entries in a session, 350 sessions in a seal).
    The two counts above are adjustable for a bundle that legitimately
    exceeds them.

EXIT CODES (deliberately NOT collapsed into pass/fail):
    0   CRYPTOGRAPHICALLY-VERIFIED  every session signed and verified under a supplied public key
    1   FAILED                      at least one property failed: tampering or corruption
    2   bundle unreadable / usage error (nothing was verified)
    3   OPERATOR-ATTESTED           consistent, but authenticity rests on material this
                                    verifier cannot check (operator HMAC and/or an unknown key)
    4   CONSISTENT-UNAUTHENTICATED  consistent, and nothing at all attests authenticity

virp-verify never signs, never holds a private key, and never executes anything.
";

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<PathBuf> = None;
    let mut limits = Limits::default();
    let mut pending: Option<&'static str> = None;
    for arg in std::env::args_os().skip(1) {
        // A value expected by the previous flag. Taken before anything else
        // so that a numeric value is never mistaken for a bundle path.
        if let Some(flag) = pending.take() {
            let Some(n) = arg.to_str().and_then(|s| s.parse::<usize>().ok()) else {
                eprintln!("virp-verify: {flag} needs a non-negative integer\n");
                eprint!("{USAGE}");
                return ExitCode::from(2);
            };
            match flag {
                "--max-sessions" => limits.sessions = n,
                _ => limits.entries_total = n,
            }
            continue;
        }
        match arg.to_str() {
            Some("--json") => json = true,
            Some(f @ ("--max-sessions" | "--max-entries")) => {
                // Borrowed from USAGE rather than from `arg`, so the flag name
                // outlives this iteration without an allocation.
                pending = Some(if f == "--max-sessions" {
                    "--max-sessions"
                } else {
                    "--max-entries"
                });
            }
            Some("-h" | "--help") => {
                print!("{USAGE}");
                return ExitCode::from(0);
            }
            Some(s) if s.starts_with('-') => {
                eprintln!("virp-verify: unknown option {s:?}\n");
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
            _ if path.is_none() => path = Some(PathBuf::from(arg)),
            _ => {
                eprintln!("virp-verify: more than one bundle path given\n");
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    if let Some(flag) = pending {
        eprintln!("virp-verify: {flag} needs a value\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }
    let Some(path) = path else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };

    let bundle = match Bundle::read_dir_with_limits(&path, &limits) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("virp-verify: cannot read bundle {}: {e}", path.display());
            eprintln!("verdict: UNREADABLE (nothing was verified)");
            return ExitCode::from(2);
        }
    };
    let report = bundle.verify();

    if json {
        match serde_json_string(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("virp-verify: cannot serialise report: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", render_text(&path, &bundle, &report));
    }

    ExitCode::from(exit_code(report.verdict))
}

fn exit_code(v: Verdict) -> u8 {
    match v {
        Verdict::CryptographicallyVerified => 0,
        Verdict::Failed => 1,
        Verdict::OperatorAttestedUnverifiable => 3,
        Verdict::ConsistentUnauthenticated => 4,
    }
}

fn serde_json_string(report: &BundleReport) -> Result<String, String> {
    docket_bundle::report_to_json_pretty(report).map_err(|e| e.to_string())
}

fn status_line(name: &str, status: &Status, detail: &str) -> String {
    let extra = match status {
        Status::Failed { detail: d } => format!(" — {d}"),
        Status::Unverifiable { reason } => format!(" — {reason}"),
        _ => String::new(),
    };
    format!("  {name:<22} {:<38} {detail}{extra}\n", status.label())
}

fn render_text(path: &std::path::Path, bundle: &Bundle, report: &BundleReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "virp-verify — Docket standalone VIRP chain verifier");
    let _ = writeln!(
        out,
        "bundle:  {}  ({}, chain_format {})",
        path.display(),
        report.bundle_version,
        report.chain_format
    );
    if report.key_ids.is_empty() {
        let _ = writeln!(
            out,
            "keys:    none supplied — KEYLESS tier only; signatures cannot be checked"
        );
    } else {
        let _ = writeln!(
            out,
            "keys:    {} public key(s): {}",
            report.key_ids.len(),
            report.key_ids.join(", ")
        );
    }
    let _ = writeln!(out, "secrets: none — this verifier holds no K_chain and no private key");
    let _ = writeln!(out);

    for s in &report.sessions {
        let r = &s.report;
        let _ = write!(out, "session {}  ({} entries)", r.session_id, r.entry_count);
        if let Some(k) = &r.signing_key_id {
            let _ = write!(out, "  signed under key_id {k}");
        }
        let _ = writeln!(out);
        for p in &r.properties {
            out.push_str(&status_line(&p.name, &p.status, &p.detail));
        }
        if let Some(anchor) = &s.seal_anchor {
            let detail = match anchor {
                Status::Verified => "seal attests this exact head".to_owned(),
                Status::Absent => "session not listed in the seal (post-seal or never sealed)".to_owned(),
                _ => String::new(),
            };
            out.push_str(&status_line("seal_anchor", anchor, &detail));
        }
        if let Some(binding) = &s.artifact_binding {
            let detail = s
                .artifact_coverage
                .as_ref()
                .map(docket_bundle::ArtifactCoverage::detail)
                .unwrap_or_default();
            out.push_str(&status_line("artifact_binding", binding, &detail));
        }
        let _ = writeln!(out, "  verdict: {}", r.verdict.label());
        let _ = writeln!(out);
    }

    if let Some(seal) = &report.seal {
        let _ = writeln!(
            out,
            "seal {}  created {}  sealed by {}",
            seal.seal_version, seal.created_at, seal.sealed_by
        );
        out.push_str(&status_line(
            "consistency",
            &seal.consistency,
            &format!("merkle root recomputed over {} listed sessions", seal.session_count),
        ));
        out.push_str(&status_line("signature", &seal.signature, ""));
        let _ = writeln!(out, "  the seal says of itself: {}", seal.residual_disclosure);
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "OVERALL VERDICT: {}", report.verdict.label());
    let _ = writeln!(out);
    let _ = writeln!(out, "What this verdict means:");
    let _ = writeln!(
        out,
        "  VERIFIED            proved by this verifier from public inputs (SHA-256 chain, genesis, Ed25519 under the supplied public key)"
    );
    let _ = writeln!(out, "  OPERATOR-ATTESTED   present, but rests on the operator's secret K_chain; this verifier cannot check it and does not pretend to");
    let _ = writeln!(
        out,
        "  UNVERIFIABLE        could not be checked here for the stated reason; other tiers still apply"
    );
    let _ = writeln!(out, "  ABSENT              the property is not present in the evidence");
    let _ = writeln!(out, "  FAILED              checked and wrong");
    let _ = writeln!(
        out,
        "Not checked by this tool: the seal's minisign signature, the seal's OpenTimestamps proof,"
    );
    let _ = writeln!(
        out,
        "  milestones (unsigned in D-1), artifact bodies the bundle does not carry, and anything before the chain's capture boundary."
    );
    let _ = writeln!(out, "bundle root: {}", bundle.root.display());
    out
}
