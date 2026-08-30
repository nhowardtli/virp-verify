//! Producer-signature tests over PRODUCER-MADE evidence.
//!
//! The comp-* fixtures are real producer output (see
//! `tests/fixtures/README-comp-fixtures.md`); the keys under
//! `tests/fixtures/producer-keys/` are the PUBLIC halves of the producer
//! keypairs that made them, copied from the capture data_dirs on
//! 10.0.0.13:~/capture-completeness-evidence (prod-clean/-gap/-ux) on
//! 2026-08-29. Public keys only — Docket holds no private key material.
//!
//! The canonical-agreement test is the load-bearing one: the ONLY accepted
//! proof that Docket's re-implemented canonicalization matches the
//! producer's is byte-equality with real producer output, and VERIFIED on
//! these fixtures is only meaningful because of it.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use docket_bundle::canonical_json_bytes;
use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn producer_key(name: &str) -> String {
    fixture("producer-keys").join(name).to_str().unwrap().to_owned()
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

fn run_on(name: &str, extra: &[&str]) -> (i32, String) {
    let dir = fixture(name);
    let pin = dir.join("keys.json").to_str().unwrap().to_owned();
    let dir_s = dir.to_str().unwrap().to_owned();
    let mut args: Vec<&str> = vec!["--pin", &pin];
    args.extend_from_slice(extra);
    args.push(&dir_s);
    run(&args)
}

/// Every stored body of every /2 fixture re-canonicalizes to its exact
/// stored bytes. This is the agreement proof with the producer's
/// serializer: the producer wrote those bytes with its own canonical dump,
/// and Docket's independent re-implementation must reproduce them
/// byte-for-byte or the producer check may not ship.
#[test]
fn canonicalizer_agrees_with_real_producer_output_byte_for_byte() {
    let mut checked = 0usize;
    for bundle in ["comp-clean-20260829", "comp-gap-20260829", "comp-ux-20260829"] {
        let dir = fixture(bundle).join("artifacts");
        for entry in fs::read_dir(&dir).expect("artifacts dir") {
            let raw = fs::read(entry.expect("dir entry").path()).expect("read body");
            let v: Value = serde_json::from_slice(&raw).expect("fixture bodies are JSON");
            assert_eq!(
                canonical_json_bytes(&v),
                raw,
                "stored producer bytes are not reproduced by Docket's canonicalizer in {bundle}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 24, "expected all 24 producer-made bodies");
}

#[test]
fn correct_producer_key_verifies_and_pins_producer_trust() {
    for (bundle, key) in [
        ("comp-clean-20260829", "comp-clean.pub"),
        ("comp-gap-20260829", "comp-gap.pub"),
        ("comp-ux-20260829", "comp-ux.pub"),
    ] {
        let k = producer_key(key);
        let (code, out) = run_on(bundle, &["--producer-key", &k]);
        assert_eq!(code, 0, "{bundle}: {out}");
        assert!(out.contains("producer_signature     VERIFIED"), "{bundle}: {out}");
        assert!(out.contains("producer_trust         PINNED"), "{bundle}: {out}");
        assert!(out.contains("8 producer signature(s) verified"), "{bundle}: {out}");
    }
}

#[test]
fn no_producer_key_is_unverifiable_and_unestablished() {
    let (code, out) = run_on("comp-clean-20260829", &[]);
    // The producer axis never moves the verdict or the exit code.
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("producer_signature     UNVERIFIABLE"), "{out}");
    assert!(out.contains("producer_trust         UNESTABLISHED"), "{out}");
    assert!(out.contains("no producer public key was supplied"), "{out}");
    assert!(!out.contains("producer_signature     VERIFIED"), "{out}");
}

#[test]
fn wrong_producer_key_is_a_mismatch_and_exit_code_is_unchanged() {
    // comp-gap's real key is a WRONG key for comp-clean's records.
    let k = producer_key("comp-gap.pub");
    let (code, out) = run_on("comp-clean-20260829", &["--producer-key", &k]);
    assert_eq!(code, 0, "the producer axis never moves the exit code: {out}");
    assert!(out.contains("producer_trust         MISMATCH"), "{out}");
    assert!(out.contains("not among the supplied producer key(s)"), "{out}");
    assert!(!out.contains("producer_signature     VERIFIED"), "{out}");
}

#[test]
fn json_reports_all_three_producer_results_distinctly() {
    let k = producer_key("comp-clean.pub");
    let wrong = producer_key("comp-ux.pub");
    let cases: [(&str, Vec<&str>, &str, &str); 3] = [
        ("verified", vec!["--producer-key", &k], "verified", "pinned"),
        ("unestablished", vec![], "unverifiable", "unestablished"),
        ("mismatch", vec!["--producer-key", &wrong], "unverifiable", "mismatch"),
    ];
    for (label, extra, want_validity, want_trust) in cases {
        let mut args = vec!["--json"];
        args.extend(extra);
        let dir = fixture("comp-clean-20260829");
        let dir_s = dir.to_str().unwrap().to_owned();
        args.push(&dir_s);
        let (_, out) = run(&args);
        let v: Value = serde_json::from_str(&out).expect("json report");
        assert_eq!(v["docket_report_version"], "docket-report/0.5", "{label}");
        let p = &v["sessions"][0]["producer"];
        assert_eq!(p["signature_validity"]["status"], want_validity, "{label}: {p}");
        assert_eq!(p["trust"], want_trust, "{label}: {p}");
        assert_eq!(
            p["claimed_key_ids"][0], "bedbdfb841ecb35afaa158369072e48e",
            "{label}: the records' claimed producer_key_id is named"
        );
    }
}

/// A record whose producer_sig was altered fails under the RIGHT key —
/// FAILED (checked and wrong), a different result from MISMATCH (wrong
/// key). The tamper also breaks the artifact binding, and both failures
/// stay independent.
#[test]
fn altered_producer_sig_fails_under_the_correct_key() {
    let src = fixture("comp-clean-20260829");
    let dst = std::env::temp_dir().join(format!("docket-producer-tamper-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dst);
    copy_dir(&src, &dst);
    // Flip one hex digit inside one body's producer_sig, leaving the file
    // name (the manifest's claimed hash) alone.
    let artifacts = dst.join("artifacts");
    let victim = fs::read_dir(&artifacts).unwrap().next().unwrap().unwrap().path();
    let text = fs::read_to_string(&victim).unwrap();
    let pos = text.find("\"producer_sig\":\"").expect("producer_sig present") + "\"producer_sig\":\"".len();
    let old = text.as_bytes()[pos] as char;
    let new = if old == '0' { '1' } else { '0' };
    let mut altered = text.clone();
    altered.replace_range(pos..pos + 1, &new.to_string());
    fs::write(&victim, altered).unwrap();

    let k = producer_key("comp-clean.pub");
    let dst_s = dst.to_str().unwrap().to_owned();
    let (code, out) = run(&["--producer-key", &k, &dst_s]);
    assert_eq!(code, 1, "the altered body breaks the artifact binding: {out}");
    assert!(out.contains("producer_signature     FAILED"), "{out}");
    assert!(out.contains("does not verify"), "{out}");
    assert!(out.contains("producer_trust         MISMATCH"), "{out}");
    let _ = fs::remove_dir_all(&dst);
}

/// A session holding one carried camera record whose producer signature is
/// GENUINELY VALID under the supplied key, plus one hash-only entry, must
/// not report session-level VERIFIED: the absent body may be a camera
/// record whose producer signature was never seen. Same weakest-link rule
/// as capture completeness. Built from real producer-signed fixture bodies
/// because only those can reach the success path at all.
#[test]
fn uncarried_body_beside_a_verified_camera_record_is_unverifiable_not_verified() {
    use docket_bundle::producer::{grade_producer_signatures, read_producer_key_file};
    use docket_bundle::sha256_hex;
    use docket_bundle::verify::{ArtifactStore, SessionChain, SignerTrust, Status};

    let dir = fixture("comp-clean-20260829").join("artifacts");
    let mut bodies: Vec<Vec<u8>> = fs::read_dir(&dir)
        .expect("artifacts dir")
        .map(|e| fs::read(e.expect("dir entry").path()).expect("read body"))
        .collect();
    bodies.truncate(2);
    assert_eq!(bodies.len(), 2, "need two real producer-signed bodies");

    let mut store = ArtifactStore::new();
    let mut entries = Vec::new();
    for (i, raw) in bodies.iter().enumerate() {
        let hash = sha256_hex(raw);
        store.insert(hash.clone(), raw.clone());
        entries.push(serde_json::json!({
            "artifact_hash": hash,
            "artifact_hash_alg": "sha256",
            "artifact_id": format!("camseg:test:{i}"),
            "artifact_schema_version": "1",
            "artifact_type": "evidence_item",
            "monotonic_ns": i as u64,
            "previous_entry_hash": "00".repeat(32),
            "sequence": i as i64,
            "session_id": "camera:test:2026-08-29",
            "signer_node_id": 1u32,
            "signer_org_id": "local",
            "timestamp_ns": i as u64,
            "chain_entry_hash": "00".repeat(32),
        }));
    }
    let chain: SessionChain =
        serde_json::from_value(serde_json::json!({"session_id": "camera:test:2026-08-29", "entries": entries}))
            .unwrap();
    let key = read_producer_key_file(&fixture("producer-keys").join("comp-clean.pub")).unwrap();

    // Sanity: with both bodies carried, the real signatures verify.
    let full = grade_producer_signatures(&chain, Some(&store), std::slice::from_ref(&key));
    assert_eq!(full.signature_validity, Status::Verified, "{full:?}");
    assert_eq!(full.trust, SignerTrust::Pinned);

    // Drop one body: same chain, same key, but the session is no longer
    // fully readable — UNVERIFIABLE with both facts stated.
    store.remove(&chain.entries[1].fields.artifact_hash);
    let partial = grade_producer_signatures(&chain, Some(&store), std::slice::from_ref(&key));
    let Status::Unverifiable { reason } = &partial.signature_validity else {
        panic!("want UNVERIFIABLE, got {:?}", partial.signature_validity);
    };
    assert!(reason.contains("1 of 2 entries have no carried body"), "{reason}");
    assert!(
        reason.contains("1 carried camera record signature(s) verified"),
        "{reason}"
    );
    assert_eq!(partial.trust, SignerTrust::Unestablished, "{partial:?}");
}

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}
