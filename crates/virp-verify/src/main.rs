//! virp-verify — standalone VIRP chain verifier (Docket).
//!
//! Reads an evidence bundle, recomputes hashes, links and detached Ed25519
//! signatures, and prints a per-property report with an honest verdict.
//! Never signs, never holds secret material, never executes anything.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use docket_bundle::bundle::{Bundle, BundleReport, SealKeyCheck, WitnessCheck};
use docket_bundle::verify::{Status, Verdict};
use docket_bundle::witness::{LiveConsistency, WitnessOutcome};
use docket_bundle::{Limits, MinisignPublicKey, MinisignSignature};

mod witness_http;

const USAGE: &str = "\
virp-verify — Docket standalone VIRP chain verifier

USAGE:
    virp-verify [--json] [--pin FILE]... [--producer-key FILE]...
                [--witness-key FILE]... [--witness-url URL]
                [--fail-on-coverage] [--show-path] [--max-sessions N]
                [--max-entries N] [--seal-key FILE [--seal-sig FILE]] <bundle-dir>

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
    --witness-key FILE   witness PUBLIC key, for a bundle carrying witness
                         material (exporter --witness). Two forms, the same two
                         --pin reads: 64 hex characters, or a docket keys.json
                         object. Repeatable, for a bundle witnessed by more
                         than one witness. Must arrive OUT OF BAND: the bundle
                         records the key id the WITNESS CLAIMED for itself, and
                         a dishonest witness claims whatever it signed with, so
                         nothing inside a bundle can establish which key is the
                         right one. Without this flag the witness property is
                         UNVERIFIABLE and witness trust UNESTABLISHED.
    --witness-url URL    OFF BY DEFAULT. Fetch a fresh signed tree head and a
                         consistency proof from the carried tree_size to the
                         current one, and report witness_consistency: is the
                         tree the carried proof was checked against still a
                         prefix of that log? This is the ONLY flag that makes
                         this verifier touch a network; witness: VERIFIED needs
                         no network and never gets one. A witness that cannot
                         be reached is UNVERIFIABLE with the reason — never a
                         pass, and never a failure, because anyone who can drop
                         a packet must not be able to manufacture an alarm.
                         PLAIN HTTP ONLY (no TLS stack travels in this binary):
                         for an https witness, point this at a local terminator
                         or tunnel.
    --fail-on-coverage   also exit nonzero (6) when the bundle-level capture
                         completeness grades INTERRUPTED / UNEXPLAINED or
                         FAILED — matching the producer's own opt-in flag.
                         Chain integrity and coverage stay separate
                         properties; by default only the verdict drives the
                         exit code, and a FAILED verdict still exits 1.
    --show-path          also print the bundle's filesystem path. OFF by default:
                         a report names the bundle by its directory name and the
                         SHA-256 of its manifest.json, which identify the evidence
                         without carrying the producer's directory layout into
                         every copy of the report. Local convenience only; the
                         digest is the identifier an examiner checks.
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
    1   FAILED                      at least one checked property is wrong: the evidence is
                                    cryptographically inconsistent, and this verifier does not
                                    determine why
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

WHAT IS RECOMPUTED, AND WHAT IS NOT:
    Every hash, link, HMAC-shaped field and signature in the chain, plus each
    carried artifact BODY against its artifact_hash. When a bundle carries the
    REFERENCED artifacts (exporter --referenced-artifacts), the digests a
    camera record cites are recomputed too and reported as
    referenced_artifact_binding: segment_sha256 over the segment video,
    sensor_signature.validator_output_sha256 over the validator's output, and
    from /6 sensor_signature.device_chain.leaf_sha256 over the device leaf
    certificate in DER. Which digests are cited comes from the signed BODIES,
    never from the unsigned manifest. A bundle that does not carry them grades
    ABSENT, which is not a pass.

    When a bundle carries WITNESS material (exporter --witness), the leaf's
    RFC 9162 inclusion proof is recomputed to the root of the carried signed
    tree head, and that head's Ed25519 signature is checked under the witness
    key supplied out of band. What that proves is bounded and stated in full
    beside the report: the head was in that log, at that tree size, at the
    time the witness stamped it, under that key. It says nothing about whether
    the entries are true, and it never upgrades the chain verdict.

    Still NOT recomputed: prev_segment_sha256 as a chain of files;
    sensor_key_sha256, whose digest is over the key as the SEI presents it;
    and device_chain.anchor_sha256, whose preimage is the examiner's own
    out-of-band CA file and never travels inside the evidence it anchors. No
    frame is ever decoded either, so nothing here judges what the video SHOWS.

virp-verify never signs, never holds a private key, and never executes anything.
";

/// The producer's sensor claim, rendered DELIBERATELY UNLIKE the property
/// ladder above it: indented under a `claims:` marker, lower-case keys, no
/// VERIFIED/FAILED vocabulary, and a caption on every rendering. A reader
/// skimming for Docket's verdict must not be able to mistake this block for
/// one — Docket ran no validator and holds no camera key.
fn render_sensor_summary(out: &mut String, sensor: &docket_bundle::SensorSummary) {
    use std::fmt::Write as _;
    if sensor.is_empty() {
        return;
    }
    let counts = |v: &[(String, usize)]| v.iter().map(|(k, n)| format!("{k}={n}")).collect::<Vec<_>>().join(" ");
    let _ = writeln!(
        out,
        "  claims: sensor_signature ({} record(s)) — {}",
        sensor.records,
        docket_bundle::SENSOR_CAPTION
    );
    let _ = writeln!(
        out,
        "      vendor={}  serial={}",
        if sensor.vendors.is_empty() {
            "—".to_owned()
        } else {
            sensor.vendors.join(",")
        },
        if sensor.device_serials.is_empty() {
            "—".to_owned()
        } else {
            sensor.device_serials.join(",")
        }
    );
    let _ = writeln!(out, "      producer verdicts: {}", counts(&sensor.verdicts));
    if !sensor.unverified_reasons.is_empty() {
        let _ = writeln!(out, "      unverified because: {}", counts(&sensor.unverified_reasons));
    }
    if !sensor.pin_states.is_empty() {
        let _ = writeln!(out, "      leaf key pin:      {}", counts(&sensor.pin_states));
    }
    if !sensor.chain_states.is_empty() {
        let _ = writeln!(out, "      device chain:      {}", counts(&sensor.chain_states));
    }
}

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<PathBuf> = None;
    let mut limits = Limits::default();
    let mut pin_paths: Vec<PathBuf> = Vec::new();
    let mut producer_key_paths: Vec<PathBuf> = Vec::new();
    let mut seal_key_path: Option<PathBuf> = None;
    let mut seal_sig_path: Option<PathBuf> = None;
    let mut witness_key_paths: Vec<PathBuf> = Vec::new();
    let mut witness_url: Option<String> = None;
    let mut fail_on_coverage = false;
    let mut show_path = false;
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
                "--witness-key" => {
                    witness_key_paths.push(PathBuf::from(&arg));
                    continue;
                }
                "--witness-url" => {
                    let Some(u) = arg.to_str() else {
                        eprintln!("virp-verify: --witness-url is not valid UTF-8\n");
                        eprint!("{USAGE}");
                        return ExitCode::from(2);
                    };
                    witness_url = Some(u.to_owned());
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
            Some("--show-path") => show_path = true,
            Some(
                f @ ("--max-sessions" | "--max-entries" | "--pin" | "--producer-key" | "--seal-key" | "--seal-sig"
                | "--witness-key" | "--witness-url"),
            ) => {
                // Borrowed from USAGE rather than from `arg`, so the flag name
                // outlives this iteration without an allocation.
                pending = Some(match f {
                    "--max-sessions" => "--max-sessions",
                    "--max-entries" => "--max-entries",
                    "--pin" => "--pin",
                    "--producer-key" => "--producer-key",
                    "--seal-key" => "--seal-key",
                    "--witness-key" => "--witness-key",
                    "--witness-url" => "--witness-url",
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
    let mut witness_keys = Vec::new();
    for p in &witness_key_paths {
        match docket_bundle::read_key_file(p, &limits) {
            Ok(keys) => witness_keys.extend(keys),
            Err(e) => {
                eprintln!("virp-verify: --witness-key: {}: {e}", p.display());
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
    // The one place this binary touches a network, and only when asked. The
    // fetch happens AFTER the bundle is read and graded-in-principle, so an
    // unreachable witness can never stop a bundle being verified — it can
    // only leave one extra row UNVERIFIABLE with the reason.
    let live = witness_url.as_deref().map(|url| fetch_consistency(url, &bundle));
    let report = bundle.verify_with_witness(
        check.as_ref(),
        &producer_keys,
        &WitnessCheck {
            keys: &witness_keys,
            live: live.as_ref(),
        },
    );

    if json {
        match serde_json_string(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("virp-verify: cannot serialise report: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!(
            "{}",
            render_text(
                &path,
                &bundle,
                &report,
                seal_key.is_some(),
                !witness_keys.is_empty(),
                show_path
            )
        );
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

/// Ask the witness for a head as it stands NOW, and for the proof that the
/// tree the bundle carries is a prefix of it.
///
/// Every failure returns the reason as a `String`, which the grading reports
/// verbatim as UNVERIFIABLE. Nothing here can produce a pass, and nothing here
/// can produce a failure: an endpoint that is down, slow or lying about its
/// own key must not be able to change what the carried proof already says.
fn fetch_consistency(url: &str, bundle: &Bundle) -> Result<LiveConsistency, String> {
    let Some(material) = &bundle.witness else {
        return Err("this bundle carries no witness material, so there is no tree to check against".to_owned());
    };
    let carried = material.sth.as_ref().map_err(String::clone)?;
    let fresh_sth_served = witness_http::get(url, "/v1/sth")?;
    let fresh = docket_bundle::parse_sth(&fresh_sth_served).map_err(|e| format!("{url}/v1/sth: {e}"))?;
    let body = witness_http::get(
        url,
        &format!("/v1/consistency?first={}&second={}", carried.tree_size, fresh.tree_size),
    )?;
    let parsed = docket_bundle::parse_consistency(&body).map_err(|e| format!("{url}/v1/consistency: {e}"))?;
    if parsed.first != carried.tree_size || parsed.second != fresh.tree_size {
        return Err(format!(
            "{url}/v1/consistency answered about {} -> {} when asked about {} -> {}",
            parsed.first, parsed.second, carried.tree_size, fresh.tree_size
        ));
    }
    Ok(LiveConsistency {
        fresh_sth_served,
        proof: parsed.consistency_proof,
        served_first_root: parsed.first_root,
        url: url.to_owned(),
    })
}

/// The witness's own clock on a session's head, rendered as a THIRD time and
/// never merged with either of the others.
///
/// The O-Node's clock is on the entries and is the operator's machine. The
/// witness's is a third party's assertion about when it first saw the head.
/// They answer different questions, they can disagree, and a report that
/// averaged them or picked one would have destroyed the only interesting
/// thing about having two.
fn render_times(out: &mut String, chain_last_ns: Option<u64>, w: Option<&WitnessOutcome>) {
    use std::fmt::Write as _;
    let existed_by = w.and_then(|w| w.head_existed_by.as_deref());
    if chain_last_ns.is_none() && existed_by.is_none() {
        return;
    }
    let onode = match chain_last_ns {
        Some(ns) => format!("O-Node clock {}", rfc3339_from_ns(ns)),
        None => "O-Node clock unavailable".to_owned(),
    };
    let witness = match existed_by {
        Some(t) => format!("head existed by {t} (witness clock)"),
        None => "no witness time".to_owned(),
    };
    let _ = writeln!(out, "  {:<22} {onode} | {witness}", "times");
}

/// Nanoseconds since the epoch as RFC 3339 UTC, without a date library.
///
/// Civil-date arithmetic from the days-since-epoch, valid across the whole
/// range a `u64` of nanoseconds can express (1970 to 2554). Written out
/// rather than pulled in: one dependency for one line of output would be a
/// poor trade in a binary whose dependency tree is the thing it advertises.
fn rfc3339_from_ns(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let millis = (ns % 1_000_000_000) / 1_000_000;
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    // Howard Hinnant's civil_from_days, era-based.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn render_text(
    path: &std::path::Path,
    bundle: &Bundle,
    report: &BundleReport,
    seal_key_supplied: bool,
    witness_key_supplied: bool,
    show_path: bool,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "virp-verify — Docket standalone VIRP chain verifier");
    // The bundle is named by its directory name and its manifest digest, not
    // by where it happened to sit on the machine that ran the verifier. The
    // path says nothing about the evidence and travels with every copy of
    // the report; the digest identifies it and anyone holding the bundle can
    // recompute it.
    let _ = writeln!(
        out,
        "bundle:  {}  ({}, chain_format {})",
        docket_bundle::bundle_display_name(path),
        report.bundle_version,
        report.chain_format
    );
    let _ = writeln!(
        out,
        "manifest: sha256 {}  (sha256sum manifest.json)",
        bundle.manifest_sha256
    );
    if show_path {
        let _ = writeln!(out, "path:    {}  (--show-path)", path.display());
    }
    // A redacted export withholds bodies it would otherwise carry. Say so
    // once, at the top: an examiner must not read "hash-only" as "the daemon
    // never had this".
    //
    // The manifest's redaction block is metadata — outside every canonical
    // byte, hashed by nothing, signed by nothing. So the COUNT is recomputed
    // from the bundle's own hash-only entries rather than read, and the
    // POLICY NAME is repeated as a claim and never verified: nothing in a
    // bundle could establish which patterns actually ran. Neither number
    // touches a verdict — a withheld body grades exactly as an absent one,
    // which is why this is context and not a property.
    if let Some(a) = bundle.audit_redaction() {
        let _ = writeln!(
            out,
            "redaction: {} (declared, unsigned), {} withheld (recomputed)",
            a.policy_claimed, a.recomputed
        );
        let _ = writeln!(
            out,
            "           those entries are hash-only HERE by choice, not because no body existed. Every \
             artifact_hash still commits to the original bytes and no verdict below is affected. The \
             policy name above is a CLAIM repeated from the manifest — nothing in a bundle can prove \
             which patterns ran."
        );
        if a.declared != a.recomputed {
            let _ = writeln!(
                out,
                "           INCONSISTENT: the manifest declares {} withheld; the bundle supports {}. The \
                 recomputed number is the one to trust — the manifest block is unsigned.",
                a.declared, a.recomputed
            );
        }
        if !a.carried_anyway.is_empty() {
            let _ = writeln!(
                out,
                "           INCONSISTENT: {} artifact_hash(es) are named as withheld but their bodies ARE \
                 carried in this bundle: {}",
                a.carried_anyway.len(),
                a.carried_anyway.join(", ")
            );
        }
        if !a.not_in_chain.is_empty() {
            let _ = writeln!(
                out,
                "           INCONSISTENT: {} artifact_hash(es) are named as withheld but no entry in this \
                 bundle references them: {}",
                a.not_in_chain.len(),
                a.not_in_chain.join(", ")
            );
        }
    }
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
    // Named only when the bundle actually carries witness material, so a
    // report on an unwitnessed bundle reads exactly as it did before this
    // feature existed.
    if let Some(w) = &bundle.witness {
        let _ = writeln!(
            out,
            "witness: {} claims key_id {} — a CLAIM carried in the bundle, never a trust anchor",
            w.manifest.witness_url, w.sth_file.witness_key_id
        );
        if witness_key_supplied {
            let _ = writeln!(
                out,
                "         checked under {} examiner-supplied witness key(s)",
                report.witness_key_ids.len()
            );
        } else {
            let _ = writeln!(
                out,
                "         none supplied — witness trust cannot be established without an examiner key \
                 (--witness-key)"
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
        // The bytes the records are ABOUT, next to the records themselves —
        // a different question, and deliberately its own row: a verified
        // body says nothing about the video it describes.
        if let Some(binding) = &s.referenced_artifact_binding {
            let detail = s
                .referenced_coverage
                .as_ref()
                .map(docket_bundle::ReferencedCoverage::detail)
                .unwrap_or_default();
            out.push_str(&status_line("referenced_artifact_binding", binding, &detail));
        }
        // A third party's log, and the third clock that comes with it. Its
        // own rows, deliberately: nothing here is a statement about the
        // chain's bytes, and nothing here can answer for them.
        if let Some(w) = &s.witness {
            out.push_str(&status_line("witness", &w.status, &w.detail));
            // Only when there IS material. A bundle the witness never saw has
            // no tree head to have trusted or not trusted, and a row reading
            // "UNESTABLISHED" beside an ABSENT property would invite the
            // reading that something was checked and came up short.
            if !matches!(w.status, Status::Absent) {
                let _ = writeln!(
                    out,
                    "  {:<22} {:<38} {}",
                    "witness_trust",
                    w.trust.label(),
                    w.submitter_signature
                        .as_deref()
                        .map(|d| format!("submitter signature over the leaf: {d}"))
                        .unwrap_or_default()
                );
            }
            if let Some(c) = &s.witness_consistency {
                out.push_str(&status_line("witness_consistency", c, "carried tree vs the log now"));
            }
        }
        // The O-Node's own clock, read from the last entry of this session's
        // chain — the newest thing the operator's machine stamped, which is
        // the moment the witness's timestamp is worth comparing against.
        let onode_ns = bundle
            .sessions
            .iter()
            .find(|c| c.session_id == r.session_id)
            .and_then(|c| c.entries.last())
            .map(|e| e.fields.timestamp_ns);
        render_times(&mut out, onode_ns, s.witness.as_ref());
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
        render_sensor_summary(&mut out, &s.sensor);
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
    // One line per distinct (grade, reason), not one per session: the
    // reason rides inside each group line, so the `— extra` suffix used
    // elsewhere would only repeat the worst group's reason back.
    let cc = &b.capture_completeness;
    match cc.groups.split_first() {
        None => {
            let extra = cc.grade.extra().map(|e| format!(" — {e}")).unwrap_or_default();
            let _ = writeln!(
                out,
                "  {:<28} {:<28} {}{extra}",
                "capture_completeness",
                cc.grade.label(),
                cc.detail
            );
        }
        Some((first, rest)) => {
            let _ = writeln!(out, "  {:<28} {:<28} {first}", "capture_completeness", cc.grade.label());
            for g in rest {
                let _ = writeln!(out, "  {:<28} {:<28} {g}", "", "");
            }
        }
    }
    // Bytes, not identity. Kept apart from source_device_established on
    // purpose: every cited artifact can verify and still say nothing about
    // which physical camera produced them.
    if let Some(ra) = &b.referenced_artifact_binding {
        let _ = writeln!(
            out,
            "  {:<28} {:<28} {}",
            "referenced_artifact_binding",
            ra.status.label(),
            ra.detail
        );
    }
    // Beside the verdict, never inside it. A chain nobody witnessed is
    // exactly as internally consistent as it was before witnessing existed.
    if let Some(w) = &b.witness {
        let _ = writeln!(out, "  {:<28} {:<28} {}", "witness", w.status.label(), w.detail);
    }
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
        "Docket verifies DECLARED capture continuity between authenticated camera records. It does not inspect the referenced video to prove each declared window contains footage — no frame is decoded and no scene is judged."
    );
    let _ = writeln!(
        out,
        "What referenced_artifact_binding covers: the artifacts a camera record cites by digest — the segment video (segment_sha256), the validator's own output about it (sensor_signature.validator_output_sha256), and from /6 the device leaf certificate in DER (sensor_signature.device_chain.leaf_sha256). When the bundle carries them, this verifier recomputes SHA-256 over the carried bytes and compares against the citing field; which digests are cited is re-derived from the signed bodies, never read from the unsigned manifest. It grades ABSENT — never a pass — for a citation whose file the bundle does not carry. Still NOT recomputed here: prev_segment_sha256 as a chain of files, sensor_key_sha256 (the digest is over the key as the SEI presents it, which the bundle does not carry), and device_chain.anchor_sha256 (the pinned CA is the examiner's own file, held out of band, never shipped inside the evidence it anchors)."
    );
    // Stated in full, and stated even when nothing was witnessed: a reader
    // who sees "witness VERIFIED" somewhere must be able to find here exactly
    // how much that word is carrying.
    let _ = writeln!(
        out,
        "What witness VERIFIED means, exactly: this session's head was present in the named witness's append-only log at tree_size N, at the time that witness stamped on the leaf, under the witness key you supplied out of band. The inclusion proof was recomputed here (RFC 9162) to the root of a tree head whose Ed25519 signature verified under that key, and the leaf's head_hash, sequence and key_id were compared against this session's own head."
    );
    let _ = writeln!(
        out,
        "  It says NOTHING about whether the entries under that head are true, or about what the video shows, or about which physical device produced any of it. It does not replace the chain verdict and cannot raise it: a witnessed chain and an unwitnessed one are equally consistent internally, and the witness result reports beside the verdict, never inside it. The one exception is FAILED — a proof that does not recompute is a cryptographic inconsistency in the bundle, and that does make the verdict FAILED."
    );
    let _ = writeln!(
        out,
        "  ABSENT means the witness has no leaf for this head (the manifest's reason says why) and is not a failure of anything. UNVERIFIABLE means either that no --witness-key was supplied, or that the carried tree head signs under a key other than the one you pinned — the second is the trust-not-established case, the CRYPTOGRAPHICALLY-CONSISTENT (exit 5) situation applied to the witness, and deliberately not FAILED."
    );
    let _ = writeln!(
        out,
        "  The witness's timestamp is the WITNESS'S ASSERTION about when it first saw the head. It is reported as a third clock beside the O-Node's and never merged with it. What would bound a witness that lies about time is publication of its tree heads somewhere it cannot retract them, and a second witness; neither is checked here. witness_consistency (--witness-url) checks only that the carried tree is still a prefix of the log that endpoint serves now."
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
    // How a reader reproduces this report. Named last because it is the
    // instruction someone acts on after reading everything above it.
    // The instruction someone acts on after reading everything above it, so
    // it names every out-of-band file THIS bundle actually needs — a bundle
    // carrying witness material and a bundle carrying none should not be
    // told to run the same command.
    let mut reproduce = format!(
        "Reproduce this report: virp-verify {}",
        docket_bundle::bundle_display_name(path)
    );
    let mut wanted = vec!["--pin <examiner-key.json> to establish signer trust"];
    if bundle.witness.is_some() && !witness_key_supplied {
        wanted.push("--witness-key <witness.pub> to check the witness's signed tree head");
    }
    reproduce.push_str(&format!(" (add {})", wanted.join("; ")));
    let _ = writeln!(out, "{reproduce}");
    if show_path {
        let _ = writeln!(out, "bundle root: {}", bundle.root.display());
    }
    out
}
