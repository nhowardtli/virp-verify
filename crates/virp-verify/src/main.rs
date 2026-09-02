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
    virp-verify [--json] [--pin FILE]... [--producer-key FILE]...
                [--fail-on-coverage] [--max-sessions N] [--max-entries N]
                [--seal-key FILE [--seal-sig FILE]] <bundle-dir>

ARGS:
    <bundle-dir>   a Docket evidence bundle directory (manifest.json at its root)

OPTIONS:
    --json               print the full report as JSON instead of text
    --pin FILE           examiner-trusted PUBLIC key(s). Two forms, the same two
                         the exporter's `--keys` reads: 64 hex characters (the
                         raw Ed25519 public key as it lives on the daemon host,
                         trailing newline fine) or a docket keys.json object
                         (what `export --keys` emits). The key_id is derived
                         from the bytes in both; a stated one is cross-checked
                         and never taken on faith. Raw 32-byte binary is not
                         accepted — hex it first (xxd -p -c 64).
                         Repeatable. Must arrive
                         OUT OF BAND: SIGNER TRUST: PINNED means the signatures
                         matched an examiner-pinned key; who holds that key, and
                         why it is trusted, is the examiner's decision, outside
                         this tool. A bundle's own keys.json still
                         checks signatures, but proves internal consistency
                         only — anyone can generate a keypair, sign fabricated
                         evidence, and ship the public half alongside.
    --producer-key FILE  producer PUBLIC key (the capture host's producer.pub:
                         32 raw bytes, or 64 hex chars). Repeatable for
                         multi-camera bundles; each camera record is checked
                         against the key matching its producer_key_id. Must
                         arrive OUT OF BAND: the bundle carries only the key
                         id, never the key. A SEPARATE trust boundary from the
                         O-Node chain key (--pin) — one never stands in for
                         the other. Without this flag the producer signature
                         is UNVERIFIABLE and producer trust UNESTABLISHED.
    --fail-on-coverage   also exit nonzero (6) when the bundle-level capture
                         completeness grades INTERRUPTED / UNEXPLAINED or
                         FAILED — matching the producer's own opt-in flag.
                         Chain integrity and coverage stay separate
                         properties; by default only the verdict drives the
                         exit code, and a FAILED verdict still exits 1.
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
                                    public key: cryptography held under an examiner-selected
                                    trust anchor
    1   FAILED                      at least one property failed: tampering or corruption
    2   bundle unreadable / usage error (nothing was verified)
    3   OPERATOR-ATTESTED           consistent, but authenticity rests on material this
                                    verifier cannot check (operator HMAC and/or an unknown key)
    4   CONSISTENT-UNAUTHENTICATED  consistent, and nothing at all attests authenticity
    5   CRYPTOGRAPHICALLY-CONSISTENT  every signature verifies, but under no examiner-pinned
                                    key (bundle-provided, or outside the examiner's pins): the
                                    cryptography held without an examiner-selected trust anchor
    6   coverage failure (--fail-on-coverage only): capture completeness graded
                                    INTERRUPTED / UNEXPLAINED or FAILED while the cryptographic
                                    verdict did not fail; without the flag the same bundle keeps
                                    its verdict exit code

virp-verify never signs, never holds a private key, and never executes anything.
";

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<PathBuf> = None;
    let mut limits = Limits::default();
    let mut pin_paths: Vec<PathBuf> = Vec::new();
    let mut producer_key_paths: Vec<PathBuf> = Vec::new();
    let mut seal_key_path: Option<PathBuf> = None;
    let mut seal_sig_path: Option<PathBuf> = None;
    let mut fail_on_coverage = false;
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
                "--producer-key" => {
                    producer_key_paths.push(PathBuf::from(&arg));
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
            Some("--fail-on-coverage") => fail_on_coverage = true,
            Some(
                f @ ("--max-sessions" | "--max-entries" | "--pin" | "--producer-key" | "--seal-key" | "--seal-sig"),
            ) => {
                // Borrowed from USAGE rather than from `arg`, so the flag name
                // outlives this iteration without an allocation.
                pending = Some(match f {
                    "--max-sessions" => "--max-sessions",
                    "--max-entries" => "--max-entries",
                    "--pin" => "--pin",
                    "--producer-key" => "--producer-key",
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
    let mut producer_keys = Vec::new();
    for p in &producer_key_paths {
        match docket_bundle::read_producer_key_file(p) {
            Ok(k) => producer_keys.push(k),
            Err(e) => {
                eprintln!("virp-verify: --producer-key: {e}");
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
    let report = bundle.verify_with(check.as_ref(), &producer_keys);

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

    let mut code = exit_code(report.verdict);
    // Opt-in only, and integrity always wins: a FAILED verdict keeps exit 1
    // (mirroring the producer, where integrity failures return before the
    // coverage gate). Coverage never feeds the VERDICT either way — this
    // gate reads the grade beside it, exactly as an integration would.
    if fail_on_coverage && code != 1 {
        use docket_bundle::CaptureGrade;
        if matches!(
            report.boundary.capture_completeness.grade,
            CaptureGrade::InterruptedUnexplained | CaptureGrade::Failed { .. }
        ) {
            code = 6;
        }
    }
    ExitCode::from(code)
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
                "keys:    {} bundle-provided key(s): {} — carried inside the bundle; can prove \
                 internal consistency, never stand as an examiner-selected trust anchor",
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
    if !report.producer_key_ids.is_empty() {
        let _ = writeln!(
            out,
            "producer: {} examiner-supplied producer key(s): {}",
            report.producer_key_ids.len(),
            report.producer_key_ids.join(", ")
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
        // the cryptography held, and whether the key that checked it was
        // examiner-pinned.
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
        // The producer's own key: a third result beside chain-signature
        // validity and signer trust — the O-Node chain key never stands in
        // for the capture host's producer key.
        out.push_str(&status_line(
            "producer_signature",
            &s.producer.signature_validity,
            &s.producer.detail,
        ));
        let _ = writeln!(
            out,
            "  {:<22} {:<38} {}",
            "producer_trust",
            s.producer.trust.label(),
            s.producer
                .trust_source
                .map_or("none — no producer key was available for this session", |t| t.label())
        );
        // Capture completeness: a separate axis from every property above.
        // It never feeds the verdict; the verdict never implies it.
        let cc = &s.capture_completeness;
        let extra = cc.grade.extra().map(|e| format!(" — {e}")).unwrap_or_default();
        let _ = writeln!(
            out,
            "  {:<22} {:<38} {}{extra}",
            "capture_completeness",
            cc.grade.label(),
            cc.detail
        );
        for g in &cc.external_predecessor_gaps {
            let _ = writeln!(
                out,
                "      {:<12} seq {}→{}  duration unavailable: predecessor outside bundle  gap record: {}",
                "boundary", g.after_seq, g.seq, g.gap_reason
            );
        }
        for o in &cc.outages {
            let _ = writeln!(
                out,
                "      {:<12} seq {}→{}  hole {:.1} s  gap record: {}",
                o.class,
                o.after_seq,
                o.seq,
                o.hole_ms as f64 / 1000.0,
                o.gap_reason.as_deref().unwrap_or("none")
            );
        }
        for o in &cc.overlaps {
            let _ = writeln!(
                out,
                "      {:<12} seq {}→{}  windows overlap {:.1} s (no time uncovered)",
                "overlap",
                o.after_seq,
                o.seq,
                o.overlap_ms as f64 / 1000.0
            );
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

    // Boundary results: computed from the evidence, not stated as copy, so
    // the report changes when the evidence changes rather than when the
    // wording is edited. Questions with answers — not verdict tiers.
    let _ = writeln!(
        out,
        "BOUNDARY RESULTS (questions this verifier answers about its own limits, computed from this bundle):"
    );
    let b = &report.boundary;
    let _ = writeln!(
        out,
        "  {:<28} {:<28} {}",
        "source_device_established",
        b.source_device_established.answer.label(),
        b.source_device_established.detail
    );
    let cc_extra = b
        .capture_completeness
        .grade
        .extra()
        .map(|e| format!(" — {e}"))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "  {:<28} {:<28} {}{cc_extra}",
        "capture_completeness",
        b.capture_completeness.grade.label(),
        b.capture_completeness.detail
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "OVERALL VERDICT: {}", report.verdict_line());
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
    let _ = writeln!(
        out,
        "What the producer signature means (the capture host's own key over each camera record body, minus producer_sig — a separate trust boundary from the O-Node chain key; neither key ever stands in for the other):"
    );
    let _ = writeln!(
        out,
        "  The bundle carries only each record's producer_key_id, never the producer key: the key must arrive out of band (--producer-key), and producer trust uses the signer-trust vocabulary above, applied to the producer key."
    );
    let _ = writeln!(
        out,
        "What capture completeness means (a separate axis from cryptographic verification — chain contiguity proves no missing sequence number, not no missing time):"
    );
    let _ = writeln!(
        out,
        "  CONTINUOUS                 every uncovered interval between capture windows is within the capture policy carried inside the chain-signed camera record"
    );
    let _ = writeln!(
        out,
        "  INTERRUPTED / ACCOUNTED    an interval is not covered, and a gap record inside a producer-signed camera manifest — or the signed policy's stated tolerance — accounts for it. Accounted for is not complete."
    );
    let _ = writeln!(
        out,
        "  INTERRUPTED / UNEXPLAINED  an interval is not covered, no gap record inside a producer-signed camera manifest explains it, and it exceeds the signed policy"
    );
    let _ = writeln!(
        out,
        "  UNVERIFIABLE               the evidence does not carry what the check needs (no bodies carried, or camera_segment/1 records with no declared cadence)"
    );
    let _ = writeln!(
        out,
        "Docket verifies DECLARED capture continuity between authenticated camera records. It does not inspect the referenced video to prove each declared window contains footage; segment_sha256 is a reference this tool does not recompute."
    );
    let _ = writeln!(
        out,
        "A report with no boundary results comes from a verifier that does not implement these checks (NOT GRADED) — a different statement from UNVERIFIABLE, which is graded from the evidence."
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
