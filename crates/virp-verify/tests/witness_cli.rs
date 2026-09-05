//! `witness`: was this head placed in somebody else's log, and does the proof
//! still recompute?
//!
//! Four cases, which are the four things the property can say. Each runs the
//! real binary against a real bundle on disk.
//!
//! | case | what it exercises |
//! | --- | --- |
//! | verified | the whole chain of checks holds under a pinned witness key |
//! | absent | a bundle carrying no witness material, and one whose row says the witness never saw the head |
//! | failed | one byte flipped in one audit-path node |
//! | unverifiable | material carried, no `--witness-key`; and a head signed by a key nobody pinned |
//!
//! THE FIXTURE. `tests/fixtures/witness-bundle` is built by
//! `tests/fixtures/make-witness-fixture.py` against a real `virp-witness`
//! server: real Ed25519, real submissions, real receipts, real RFC 9162 audit
//! paths. Its chain is signed by the PUBLISHED TEST KEY (seed public in
//! `chain-signing-v1.json`) rather than by a real O-Node key, and the
//! generator's docstring says at length why it has to be: `witness: VERIFIED`
//! binds the leaf's key_id to the head's signing key_id, so producing one
//! requires the chain's private key, and Docket holds none.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/witness-bundle")
}

/// The witness's public key, as the examiner would hold it: out of band, in
/// its own file, never from inside the bundle.
fn witness_key() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/witness-bundle.witness.pub")
}

/// The session under test. Named rather than derived, so a test that stops
/// testing what it says it tests fails loudly.
const SESSION: &str = "docket-witness:fixture-1";
const PROOF: &str = "witness/docket-witness_fixture-1.proof.json";

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_virp-verify"))
        .args(args)
        .output()
        .expect("run virp-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// A working copy under `target/tmp`, like the other CLI tests: the committed
/// fixture is never written to.
fn copy_of(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tmp")
        .join(format!("virp-verify-{name}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    copy_dir(&fixture(), &dir);
    dir
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, v: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

/// The session's block of the text report — from its `session ` line to the
/// blank line after its verdict.
fn session_block<'a>(stdout: &'a str, session: &str) -> &'a str {
    let start = stdout
        .find(&format!("session {session}  "))
        .unwrap_or_else(|| panic!("no block for {session} in:\n{stdout}"));
    let rest = &stdout[start..];
    let end = rest.find("\n\n").unwrap_or(rest.len());
    &rest[..end]
}

fn pin() -> String {
    fixture().join("keys.json").to_str().unwrap().to_owned()
}

// --- 1. verified ------------------------------------------------------------

#[test]
fn verified_when_the_proof_recomputes_under_a_pinned_witness_key() {
    let dir = fixture();
    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(
        block.contains("witness                VERIFIED"),
        "expected witness VERIFIED:\n{block}"
    );
    assert!(block.contains("witness_trust          PINNED"), "{block}");
    // The claim is bounded, and the line says exactly how: which leaf, which
    // tree, which key.
    assert!(
        block.contains("of tree 3"),
        "the detail must name the tree size:\n{block}"
    );
    assert!(
        block.contains("signed by witness key_id"),
        "the detail must name the key that checked the head:\n{block}"
    );
    // The third clock, beside the O-Node's and never merged with it.
    assert!(
        block.contains("O-Node clock") && block.contains("head existed by"),
        "both clocks must be reported, separately:\n{block}"
    );
    // Beside the verdict, never inside it: a witnessed bundle's verdict is
    // whatever the cryptography said, unchanged.
    assert_eq!(code, 0, "witness VERIFIED must not change the verdict\n{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    assert!(
        out.contains("witness                      VERIFIED                     VERIFIED for 3 of 3 session(s)"),
        "boundary roll-up:\n{out}"
    );
    // And the epilogue states what the word is carrying.
    assert!(
        out.contains("What witness VERIFIED means, exactly:")
            && out.contains("It says NOTHING about whether the entries under that head are true"),
        "the epilogue must bound the claim:\n{out}"
    );
}

/// The submitter's own signature over the leaf is REPORTED, not graded: it is
/// a statement about who asked the witness to log this head, which is a
/// different question from whether the log holds it.
#[test]
fn the_submitter_signature_over_the_leaf_is_reported_beside_the_property() {
    let (_, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        fixture().to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(
        block.contains("submitter signature over the leaf: verifies under pinned key_id"),
        "{block}"
    );
}

// --- 2. absent --------------------------------------------------------------

/// A bundle with no witness section at all — every bundle exported before
/// `--witness` existed. It must read exactly as it did before: no witness
/// row anywhere, no boundary line, and the same verdict.
#[test]
fn a_bundle_exported_without_witness_says_nothing_about_a_witness() {
    let dir = copy_of("witness-none");
    let mut m = read_json(&dir.join("manifest.json"));
    m.as_object_mut().unwrap().remove("witness");
    write_json(&dir.join("manifest.json"), &m);
    std::fs::remove_dir_all(dir.join("witness")).unwrap();

    let (code, out, _) = run(&["--pin", &pin(), dir.to_str().unwrap()]);
    assert!(
        !out.contains("  witness "),
        "a bundle that was never offered to a witness must not grow a witness row:\n{out}"
    );
    assert_eq!(code, 0, "{out}");
}

/// A head the witness has never seen: `present: false`, and the manifest's
/// reason reported verbatim. Not a failure of anything, and not silence.
#[test]
fn absent_with_the_reason_when_the_witness_never_saw_the_head() {
    let dir = copy_of("witness-not-submitted");
    let mut m = read_json(&dir.join("manifest.json"));
    {
        let sessions = m["witness"]["sessions"].as_array_mut().unwrap();
        let row = sessions
            .iter_mut()
            .find(|r| r["session_id"] == SESSION)
            .expect("the session's witness row");
        *row = serde_json::json!({"session_id": SESSION, "present": false, "reason": "not_submitted"});
    }
    write_json(&dir.join("manifest.json"), &m);
    std::fs::remove_file(dir.join(PROOF)).unwrap();

    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                ABSENT"), "{block}");
    assert!(
        block.contains("reason: not_submitted"),
        "the manifest's reason must be reported verbatim:\n{block}"
    );
    // ABSENT never moves the verdict.
    assert_eq!(code, 0, "{out}");
    // But it is not a pass either: the roll-up says so.
    assert!(
        out.contains("VERIFIED for 2 of 3 session(s); 1 carry no witness material — ABSENT, not a pass"),
        "boundary roll-up:\n{out}"
    );
}

/// The three reasons are three different facts, and the report must not blur
/// them: `unreachable` is about this export run, not about the evidence.
#[test]
fn an_unreachable_witness_reports_its_own_reason_not_not_submitted() {
    let dir = copy_of("witness-unreachable");
    let mut m = read_json(&dir.join("manifest.json"));
    {
        let sessions = m["witness"]["sessions"].as_array_mut().unwrap();
        for row in sessions.iter_mut() {
            *row = serde_json::json!({
                "session_id": row["session_id"].clone(), "present": false, "reason": "unreachable"
            });
        }
    }
    write_json(&dir.join("manifest.json"), &m);
    std::fs::remove_dir_all(dir.join("witness")).unwrap();
    std::fs::create_dir(dir.join("witness")).unwrap();
    // The tree head file is still named by the manifest and must still exist.
    std::fs::copy(fixture().join("witness/sth.json"), dir.join("witness/sth.json")).unwrap();

    let (code, out, _) = run(&["--pin", &pin(), dir.to_str().unwrap()]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                ABSENT"), "{block}");
    assert!(block.contains("reason: unreachable"), "{block}");
    assert_eq!(code, 0, "an unreachable witness must not change a verdict\n{out}");
}

// --- 3. failed --------------------------------------------------------------

/// One byte in one audit-path node. The proof stops recomputing, and because
/// that is a cryptographic inconsistency in the bundle — the carried leaf,
/// the carried path and the signed head no longer agree — it drives the
/// verdict, exactly as a mismatched artifact body does.
#[test]
fn failed_when_one_byte_of_the_audit_path_moves() {
    let dir = copy_of("witness-flipped-path");
    let path = dir.join(PROOF);
    let mut proof = read_json(&path);
    {
        let audit = proof["audit_path"].as_array_mut().unwrap();
        assert!(
            !audit.is_empty(),
            "the fixture must have a non-empty audit path or this test proves nothing"
        );
        let node = audit[0].as_str().unwrap().to_owned();
        let last = node.chars().last().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        audit[0] = serde_json::Value::String(format!("{}{}", &node[..node.len() - 1], flipped));
    }
    write_json(&path, &proof);

    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                FAILED"), "{block}");
    assert!(
        block.contains("does not recompute") && block.contains("recomputes to root"),
        "the failure must name both roots, not just say no:\n{block}"
    );
    assert_eq!(code, 1, "a proof that does not recompute is FAILED\n{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

/// A proof that recomputes perfectly, for somebody else's head. The
/// arithmetic is not the check — the binding to THIS session's head is.
#[test]
fn failed_when_the_leaf_names_a_different_head() {
    let dir = copy_of("witness-other-head");
    let path = dir.join(PROOF);
    let mut proof = read_json(&path);
    let head = proof["leaf"]["head_hash"].as_str().unwrap().to_owned();
    let last = head.chars().last().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    proof["leaf"]["head_hash"] = serde_json::Value::String(format!("{}{}", &head[..head.len() - 1], flipped));
    write_json(&path, &proof);

    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                FAILED"), "{block}");
    assert!(
        block.contains("the witness holds a DIFFERENT head for this chain"),
        "{block}"
    );
    assert_eq!(code, 1, "{out}");
}

// --- 4. unverifiable --------------------------------------------------------

/// Material carried, no examiner key. Nothing was checked and nothing is
/// claimed — and the verdict does not move, in either direction.
#[test]
fn unverifiable_without_a_witness_key() {
    let (code, out, _) = run(&["--pin", &pin(), fixture().to_str().unwrap()]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                UNVERIFIABLE"), "{block}");
    assert!(
        block.contains("no --witness-key was supplied"),
        "the reason must say what is missing:\n{block}"
    );
    assert!(block.contains("witness_trust          UNESTABLISHED"), "{block}");
    assert_eq!(code, 0, "a missing witness key must not change the verdict\n{out}");
    // And the reproduce line tells the reader what to add.
    assert!(
        out.contains("--witness-key <witness.pub> to check the witness's signed tree head"),
        "the reproduce line must name the missing file:\n{out}"
    );
}

/// The tree head signs under a key the examiner did NOT pin. Trust was never
/// established — the exit-5 situation applied to the witness — and calling
/// that FAILED would say something false about the proof.
#[test]
fn unverifiable_when_the_tree_head_signs_under_an_unpinned_key() {
    let other = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/virp-verify-witness-otherkey.pub");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    // Any valid Ed25519 public key that is not the witness's. The chain's own
    // published test key is one, and it is already in the tree.
    std::fs::write(
        &other,
        "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7\n",
    )
    .unwrap();

    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        other.to_str().unwrap(),
        fixture().to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                UNVERIFIABLE"), "{block}");
    assert!(block.contains("trust in this witness is NOT ESTABLISHED"), "{block}");
    assert!(
        block.contains("CRYPTOGRAPHICALLY-CONSISTENT (exit 5)"),
        "the trust-not-established case must use the exit-5 vocabulary, not FAILED:\n{block}"
    );
    assert!(block.contains("witness_trust          UNESTABLISHED"), "{block}");
    assert_eq!(code, 0, "an unpinned witness key must not change the verdict\n{out}");
}

/// The other half of that split: a head that CLAIMS the pinned key and does
/// not verify under it is a signature that is wrong, and is FAILED.
#[test]
fn failed_when_the_head_claims_the_pinned_key_and_does_not_verify() {
    let dir = copy_of("witness-bad-sth-sig");
    let path = dir.join("witness/sth.json");
    let mut sth_file = read_json(&path);
    let served = sth_file["sth_served"].as_str().unwrap().to_owned();
    let mut sth: serde_json::Value = serde_json::from_str(&served).unwrap();
    let sig = sth["signature"].as_str().unwrap().to_owned();
    let last = sig.chars().last().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    sth["signature"] = serde_json::Value::String(format!("{}{}", &sig[..sig.len() - 1], flipped));
    sth_file["sth_served"] = serde_json::Value::String(serde_json::to_string(&sth).unwrap());
    write_json(&path, &sth_file);

    let (code, out, _) = run(&[
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        dir.to_str().unwrap(),
    ]);
    let block = session_block(&out, SESSION);
    assert!(block.contains("witness                FAILED"), "{block}");
    assert!(block.contains("does not verify under that key"), "{block}");
    assert_eq!(code, 1, "{out}");
}

// --- the JSON surface -------------------------------------------------------

/// Everything the text report says, a consumer must be able to branch on.
#[test]
fn the_json_report_carries_the_witness_result() {
    let (_, out, _) = run(&[
        "--json",
        "--pin",
        &pin(),
        "--witness-key",
        witness_key().to_str().unwrap(),
        fixture().to_str().unwrap(),
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("report json");
    assert_eq!(v["docket_report_version"], "docket-report/0.8");
    assert!(!v["witness_key_ids"].as_array().unwrap().is_empty());
    let s = v["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["session_id"] == SESSION)
        .expect("the session");
    assert_eq!(s["witness"]["status"], "verified");
    assert_eq!(s["witness"]["trust"], "pinned");
    assert!(s["witness"]["head_existed_by"].is_string());
    assert_eq!(s["witness"]["tree_size"], 3);
    assert_eq!(v["boundary"]["witness"]["verified"], 3);
    // Off by default: no live check was asked for, so nothing is claimed
    // about the log as it stands now.
    assert!(s["witness_consistency"].is_null(), "witness_consistency must be absent");
}

/// A report on a bundle with no witness section must serialize exactly as it
/// did before this feature: no new keys anywhere.
#[test]
fn a_pre_witness_bundle_gains_no_witness_keys_in_json() {
    let dir = copy_of("witness-none-json");
    let mut m = read_json(&dir.join("manifest.json"));
    m.as_object_mut().unwrap().remove("witness");
    write_json(&dir.join("manifest.json"), &m);
    std::fs::remove_dir_all(dir.join("witness")).unwrap();

    let (_, out, _) = run(&["--json", "--pin", &pin(), dir.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("report json");
    for s in v["sessions"].as_array().unwrap() {
        assert!(s.get("witness").is_none(), "session gained a witness key: {s}");
        assert!(s.get("witness_consistency").is_none(), "{s}");
    }
    assert!(v["boundary"].get("witness").is_none(), "{}", v["boundary"]);
}
