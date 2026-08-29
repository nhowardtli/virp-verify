//! virp-verify — standalone VIRP chain verifier (Docket).
//!
//! Reads an evidence bundle, recomputes hashes, links and detached Ed25519
//! signatures, and prints a per-property report with an honest verdict.
//! Never signs, never holds secret material, never executes anything.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use docket_bundle::bundle::{Bundle, BundleReport, SealKeyCheck};
use docket_bundle::verify::{Status, Verdict};
use docket_bundle::{Limits, MinisignPublicKey, MinisignSignature};

const USAGE: &str = "\
virp-verify — Docket standalone VIRP chain verifier

USAGE:
    virp-verify [--json] [--pin FILE]... [--max-sessions N] [--max-entries N]
                [--seal-key FILE [--seal-sig FILE]] <bundle-dir>

ARGS:
    <bundle-dir>   a Docket evidence bundle directory (manifest.json at its root)

OPTIONS:
    --json               print the full report as JSON instead of text
    --pin FILE           examiner-trusted PUBLIC key(s), docket keys.json format
                         (what `export --keys` emits). Repeatable. Must arrive
                         OUT OF BAND: only a pinned key can establish who signed
                         (SIGNER TRUST: PINNED). A bundle's own keys.json still
                         checks signatures, but proves internal consistency
                         only — anyone can generate a keypair, sign fabricated
                         evidence, and ship the public half alongside.
    --max-sessions N     reject a bundle listing more than N sessions (default 10000)
    --max-entries N      reject a bundle carrying more than N entries in total (default 1000000)
    --seal-key FILE      minisign PUBLIC key to check the seal's signature under.
                         Must arrive OUT OF BAND: the verifier never takes the seal
                         key from inside the bundle, and ignores the seal's own
                         seal_public_key field. Without this flag the seal signature
                         is reported UNVERIFIABLE, as before.
    --seal-sig FILE      detached .minisig over the seal file, for bundles that do
                         not carry one (overrides a carried signature). Only
                         meaningful with --seal-key.
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
    0   CRYPTOGRAPHICALLY-VERIFIED  every session signed and verified under an examiner-pinned
                                    public key: cryptography AND signer identity both held
    1   FAILED                      at least one property failed: tampering or corruption
    2   bundle unreadable / usage error (nothing was verified)
    3   OPERATOR-ATTESTED           consistent, but authenticity rests on material this
                                    verifier cannot check (operator HMAC and/or an unknown key)
    4   CONSISTENT-UNAUTHENTICATED  consistent, and nothing at all attests authenticity
    5   CRYPTOGRAPHICALLY-CONSISTENT  every signature verifies, but only under a key that
                                    establishes no identity (bundle-provided, or outside the
                                    examiner's pins): the cryptography held, the identity did not

virp-verify never signs, never holds a private key, and never executes anything.
";

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<PathBuf> = None;
    let mut limits = Limits::default();
    let mut pin_paths: Vec<PathBuf> = Vec::new();
    let mut seal_key_path: Option<PathBuf> = None;
    let mut seal_sig_path: Option<PathBuf> = None;
    let mut pending: Option<&'static str> = None;
    for arg in std::env::args_os().skip(1) {
        // A value expected by the previous flag. Taken before anything else
        // so that a flag's value is never mistaken for a bundle path.
        if let Some(flag) = pending.take() {
            match flag {
                "--pin" => {
                    pin_paths.push(PathBuf::from(&arg));
                    continue;
                }
                "--seal-key" => {
                    seal_key_path = Some(PathBuf::from(&arg));
                    continue;
                }
                "--seal-sig" => {
                    seal_sig_path = Some(PathBuf::from(&arg));
                    continue;
                }
                _ => {}
            }
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
            Some(f @ ("--max-sessions" | "--max-entries" | "--pin" | "--seal-key" | "--seal-sig")) => {
                // Borrowed from USAGE rather than from `arg`, so the flag name
                // outlives this iteration without an allocation.
                pending = Some(match f {
                    "--max-sessions" => "--max-sessions",
                    "--max-entries" => "--max-entries",
                    "--pin" => "--pin",
                    "--seal-key" => "--seal-key",
                    _ => "--seal-sig",
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
    if seal_sig_path.is_some() && seal_key_path.is_none() {
        eprintln!("virp-verify: --seal-sig is only meaningful with --seal-key\n");
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    // Out-of-band operator material (pins, seal key/sig) is read BEFORE the
    // bundle: a bad operator file is a usage problem (exit 2), never a
    // verdict about the evidence.
    let mut pins = Vec::new();
    for p in &pin_paths {
        match docket_bundle::read_key_file(p, &limits) {
            Ok(keys) => pins.extend(keys),
            Err(e) => {
                eprintln!("virp-verify: --pin: {}: {e}", p.display());
                return ExitCode::from(2);
            }
        }
    }
    let seal_key = match &seal_key_path {
        None => None,
        Some(p) => match read_minisign(p, "--seal-key", MinisignPublicKey::from_text) {
            Ok(k) => Some(k),
            Err(code) => return code,
        },
    };
    let seal_sig = match &seal_sig_path {
        None => None,
        Some(p) => match read_minisign(p, "--seal-sig", MinisignSignature::from_text) {
            Ok(s) => Some(s),
            Err(code) => return code,
        },
    };

    let mut bundle = match Bundle::read_dir_with_limits(&path, &limits) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("virp-verify: cannot read bundle {}: {e}", path.display());
            eprintln!("verdict: UNREADABLE (nothing was verified)");
            return ExitCode::from(2);
        }
    };
    // Pins go into the same keyring as the bundle's keys, tagged with their
    // provenance; a pinned key outranks a bundle copy of itself.
    for pk in pins {
        bundle.keyring.insert_pinned(pk);
    }
    let check = seal_key.as_ref().map(|key| SealKeyCheck {
        key,
        signature: seal_sig.as_ref(),
    });
    let report = bundle.verify_with_seal_key(check.as_ref());

    if json {
        match serde_json_string(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("virp-verify: cannot serialise report: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", render_text(&path, &bundle, &report, seal_key.is_some()));
    }

    ExitCode::from(exit_code(report.verdict))
}

/// Read and parse an out-of-band minisign file named by `flag`. Any problem
/// is reported with the path and exits 2: nothing was verified.
fn read_minisign<T>(
    path: &std::path::Path,
    flag: &str,
    parse: impl Fn(&str) -> Result<T, docket_bundle::MinisignError>,
) -> Result<T, ExitCode> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        eprintln!("virp-verify: {flag}: cannot read {}: {e}", path.display());
        ExitCode::from(2)
    })?;
    parse(&text).map_err(|e| {
        eprintln!("virp-verify: {flag}: {}: {e}", path.display());
        ExitCode::from(2)
    })
}

fn exit_code(v: Verdict) -> u8 {
    match v {
        Verdict::CryptographicallyVerified => 0,
        Verdict::Failed => 1,
        Verdict::OperatorAttestedUnverifiable => 3,
        Verdict::ConsistentUnauthenticated => 4,
        Verdict::CryptographicallyConsistent => 5,
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

fn render_text(path: &std::path::Path, bundle: &Bundle, report: &BundleReport, seal_key_supplied: bool) -> String {
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
        if !report.bundle_key_ids.is_empty() {
            let _ = writeln!(
                out,
                "keys:    {} bundle-provided key(s): {} — carried inside the bundle; can establish \
                 internal consistency, never identity",
                report.bundle_key_ids.len(),
                report.bundle_key_ids.join(", ")
            );
        }
        if report.pinned_key_ids.is_empty() {
            let _ = writeln!(
                out,
                "pinned:  none supplied — signer trust cannot be PINNED without an examiner key (--pin)"
            );
        } else {
            let _ = writeln!(
                out,
                "pinned:  {} examiner-supplied key(s): {}",
                report.pinned_key_ids.len(),
                report.pinned_key_ids.join(", ")
            );
        }
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
        if let Some(anchor) = &s.seal_head_match {
            let detail = match anchor {
                Status::Verified => "this head appears in the bundled seal".to_owned(),
                Status::Absent => "session not listed in the seal (post-seal or never sealed)".to_owned(),
                _ => String::new(),
            };
            out.push_str(&status_line("seal_head_match", anchor, &detail));
        }
        if let Some(binding) = &s.artifact_binding {
            let detail = s
                .artifact_coverage
                .as_ref()
                .map(docket_bundle::ArtifactCoverage::detail)
                .unwrap_or_default();
            out.push_str(&status_line("artifact_binding", binding, &detail));
        }
        // The two signer axes, rendered separately and never merged: whether
        // the cryptography held, and whether the key that checked it
        // establishes who signed.
        out.push_str(&status_line(
            "signature_validity",
            &r.signer.signature_validity,
            "summary of head_signature, session_key_binding, entry_signatures",
        ));
        let _ = writeln!(
            out,
            "  {:<22} {:<38} {}",
            "signer_trust",
            r.signer.trust.label(),
            r.signer.detail
        );
        let _ = writeln!(
            out,
            "  {:<22} {}",
            "trust_source",
            r.signer
                .trust_source
                .map_or("none — no key was available for this session", |s| s.label())
        );
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
        out.push_str(&status_line("signature", &seal.signature, &seal.signature_detail));
        let _ = writeln!(out, "  the seal says of itself: {}", seal.residual_disclosure);
        let _ = writeln!(out);
    } else if seal_key_supplied {
        let _ = writeln!(
            out,
            "seal: none in this bundle; the supplied --seal-key checked nothing"
        );
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
        "What signer trust means (a separate axis from signature validity):"
    );
    let _ = writeln!(
        out,
        "  PINNED              the key that verified the signatures was supplied by the examiner out of band (--pin) and matches"
    );
    let _ = writeln!(
        out,
        "  UNESTABLISHED       the only key available came from inside the bundle being examined; valid signatures prove internal consistency, not who produced it"
    );
    let _ = writeln!(
        out,
        "  MISMATCH            the examiner pinned keys and this session's signatures do not verify under any of them"
    );
    // Without --seal-key this line is verbatim what it always was — the
    // docket viewer's page asserts parity with it (crates/docket/tests).
    // With the key, claiming the minisign signature went unchecked would be
    // false, so the clause is dropped.
    if seal_key_supplied {
        let _ = writeln!(out, "Not checked by this tool: the seal's OpenTimestamps proof,");
    } else {
        let _ = writeln!(
            out,
            "Not checked by this tool: the seal's minisign signature, the seal's OpenTimestamps proof,"
        );
    }
    let _ = writeln!(
        out,
        "  milestones (unsigned in D-1), artifact bodies the bundle does not carry, and anything before the chain's capture boundary."
    );
    let _ = writeln!(out, "bundle root: {}", bundle.root.display());
    out
}
