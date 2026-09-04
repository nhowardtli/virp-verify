//! `referenced_artifact_binding`: the bytes a camera record is ABOUT.
//!
//! The fixture is the 2026-09-04 Axis session from the two-point tamper pass
//! (virp `camera/TAMPER-PASS-2026-09-04.md`), re-exported with
//! `--referenced-artifacts` so the nine records' eighteen cited files travel
//! with it. Real Axis-signed footage rather than a synthetic: the whole
//! feature exists because a byte flipped in exactly these files used to leave
//! this verifier's output byte-identical to the untampered run, and a
//! fabricated fixture is the least likely thing to reproduce that honestly.
//!
//! The three tamper points are derived here, one byte each, exactly as the
//! `tamper-*` cases in cli.rs derive theirs:
//!
//! | copy | flip | fails |
//! | --- | --- | --- |
//! | A | seq-24 segment mp4 | `referenced_artifact_binding` on `segment_sha256` |
//! | B | seq-26 validator output | `referenced_artifact_binding` on `sensor_signature.validator_output_sha256` |
//! | C | the seq-24 carried BODY | `artifact_binding`, while the payload verifies |

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/axis-referenced-bundle")
}

/// The session's own key, offered back as an examiner pin — same file,
/// different provenance, as in cli.rs.
fn pin_arg() -> String {
    fixture().join("keys.json").to_str().unwrap().to_owned()
}

/// Digests the fixture's records cite, used to name the files to tamper with.
/// Written out rather than looked up so a test that stops testing what it
/// says it tests fails loudly instead of quietly re-deriving its own target.
const SEQ24_SEGMENT: &str = "77e87adfbb27c92f797f893782f4c43112d727f5b9c0a7e022a72c9aaeef6c3d";
const SEQ26_VALIDATOR: &str = "33a7cc6d19b5c0cbcc23390b457ee3a525bd4dd198ea9b1ac97959b5c9992571";
const SEQ24_BODY: &str = "d489b652e6a27d6f6c675b2676f864f077e2d662859abfd91c56b7341662a50a";

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

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("virp-verify-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&fixture(), &dir);
    dir
}

/// Flip ONE byte in a carried file — the tamper the pass actually performed,
/// on bytes that are not text and cannot be substituted as a string.
fn flip_byte(name: &str, file: &str) -> PathBuf {
    let dir = scratch(name);
    let path = dir.join(file);
    let mut bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.is_empty(), "{file} is empty");
    let at = bytes.len() / 2;
    bytes[at] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();
    dir
}

fn verify(dir: &Path) -> (i32, String) {
    let (code, out, err) = run(&["--pin", &pin_arg(), dir.to_str().unwrap()]);
    assert!(err.is_empty() || code == 2, "stderr: {err}");
    (code, out)
}

/// Every property the chain walk grades, which must stay VERIFIED while a
/// payload fails: a tampered mp4 says nothing about the chain.
fn assert_chain_properties_verified(out: &str) {
    for line in [
        "entry_hashes           VERIFIED",
        "contiguity             VERIFIED",
        "genesis                VERIFIED",
        "links                  VERIFIED",
        "head_commitment        VERIFIED",
        "head_signature         VERIFIED",
        "session_key_binding    VERIFIED",
        "entry_signatures       VERIFIED",
        "signature_validity     VERIFIED",
        "artifact_binding       VERIFIED",
        "signer_trust           PINNED",
    ] {
        assert!(out.contains(line), "missing {line:?} in:\n{out}");
    }
}

#[test]
fn the_untampered_export_verifies_every_cited_artifact() {
    let (code, out) = verify(&fixture());
    assert_eq!(code, 0, "{out}");
    assert_chain_properties_verified(&out);
    assert!(out.contains("referenced_artifact_binding VERIFIED"), "{out}");
    assert!(
        out.contains("18/18 cited artifact(s) recomputed against the citing field"),
        "{out}"
    );
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
    // The boundary summary restates it, and never as an identity claim.
    assert!(out.contains("referenced_artifact_binding  VERIFIED"), "{out}");
    assert!(out.contains("source_device_established    NO"), "{out}");
}

#[test]
fn copy_a_flipped_segment_mp4_fails_on_segment_sha256() {
    let dir = flip_byte("ref-copy-a", &format!("artifacts/{SEQ24_SEGMENT}"));
    let (code, out) = verify(&dir);
    assert_eq!(code, 1, "{out}");
    // The chain is untouched, and says so.
    assert_chain_properties_verified(&out);
    assert!(out.contains("referenced_artifact_binding FAILED"), "{out}");
    assert!(out.contains("segment_seq 24 cites segment_sha256"), "{out}");
    assert!(out.contains(SEQ24_SEGMENT), "{out}");
    assert!(out.contains("17/18 cited artifact(s)"), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

#[test]
fn copy_b_flipped_validator_output_fails_on_the_other_field() {
    let dir = flip_byte("ref-copy-b", &format!("artifacts/{SEQ26_VALIDATOR}"));
    let (code, out) = verify(&dir);
    assert_eq!(code, 1, "{out}");
    assert_chain_properties_verified(&out);
    assert!(out.contains("referenced_artifact_binding FAILED"), "{out}");
    assert!(
        out.contains("segment_seq 26 cites sensor_signature.validator_output_sha256"),
        "{out}"
    );
    assert!(out.contains(SEQ26_VALIDATOR), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

/// The requirement the original pass could not meet: two points, two
/// DIFFERENT properties. Here they are two different fields of the same
/// property on two different records, which is the honest form of it — one
/// tamper is a video, the other is a note about a video.
#[test]
fn the_two_points_fail_on_different_records_and_different_fields() {
    let (_, a) = verify(&flip_byte("ref-diff-a", &format!("artifacts/{SEQ24_SEGMENT}")));
    let (_, b) = verify(&flip_byte("ref-diff-b", &format!("artifacts/{SEQ26_VALIDATOR}")));
    assert!(a.contains("segment_seq 24 cites segment_sha256"), "{a}");
    assert!(!a.contains("validator_output_sha256 33a7cc6d"), "{a}");
    assert!(
        b.contains("segment_seq 26 cites sensor_signature.validator_output_sha256"),
        "{b}"
    );
    assert!(!b.contains("cites segment_sha256 77e87adf"), "{b}");
    assert_ne!(a, b);
}

#[test]
fn copy_c_flipped_body_fails_artifact_binding_while_the_payload_verifies() {
    let dir = flip_byte("ref-copy-c", &format!("artifacts/{SEQ24_BODY}"));
    let (code, out) = verify(&dir);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("artifact_binding       FAILED"), "{out}");
    // The files on disk were not touched, and the report does not pretend
    // otherwise. The two axes disagree in the opposite direction from A and B.
    assert!(out.contains("referenced_artifact_binding VERIFIED"), "{out}");
    assert!(out.contains("OVERALL VERDICT: FAILED"), "{out}");
}

// --- absent is never a pass ------------------------------------------------

#[test]
fn a_cited_artifact_the_bundle_does_not_carry_is_absent_not_verified() {
    let dir = scratch("ref-absent-file");
    // Drop one carried file and mark its row not present — the shape the
    // exporter writes when it could not find the file.
    std::fs::remove_file(dir.join(format!("artifacts/{SEQ24_SEGMENT}"))).unwrap();
    let manifest = dir.join("manifest.json");
    let mut value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    let row = value["referenced_artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["sha256"] == SEQ24_SEGMENT)
        .expect("the fixture cites the seq-24 segment");
    let obj = row.as_object_mut().unwrap();
    obj.remove("path");
    obj.insert("present".to_owned(), serde_json::Value::Bool(false));
    std::fs::write(&manifest, serde_json::to_string_pretty(&value).unwrap()).unwrap();

    let (code, out) = verify(&dir);
    assert!(out.contains("referenced_artifact_binding ABSENT"), "{out}");
    assert!(!out.contains("referenced_artifact_binding VERIFIED"), "{out}");
    assert!(out.contains("1 not carried — ABSENT, not a pass"), "{out}");
    // ABSENT is neutral: it is not a wrong bundle, only an incomplete one.
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
}

#[test]
fn a_bundle_with_no_referenced_section_says_nothing_about_the_property() {
    let dir = scratch("ref-no-section");
    let manifest = dir.join("manifest.json");
    let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    let mut map = value.as_object().unwrap().clone();
    map.remove("referenced_artifacts");
    std::fs::write(
        &manifest,
        serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap(),
    )
    .unwrap();

    let (code, out) = verify(&dir);
    assert_eq!(code, 0, "{out}");
    // Every bundle exported before the exporter could carry these looks like
    // this, and none of them grows a property ROW it cannot answer. (The
    // legend still names the property — describing a check is not claiming
    // to have run it.)
    assert!(!out.contains("  referenced_artifact_binding "), "{out}");
    assert!(out.contains("artifact_binding       VERIFIED"), "{out}");
    assert!(out.contains("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED"), "{out}");
}

// --- the manifest is not trusted to say what is cited ----------------------

#[test]
fn a_manifest_row_for_a_digest_no_record_cites_changes_nothing() {
    let dir = scratch("ref-extra-row");
    let manifest = dir.join("manifest.json");
    let mut value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();
    let extra = serde_json::json!({
        "sha256": "aa".repeat(32),
        "cited_by": [{"session_id": "made:up", "segment_seq": 99, "field": "segment_sha256"}],
        "present": false
    });
    value["referenced_artifacts"].as_array_mut().unwrap().push(extra);
    std::fs::write(&manifest, serde_json::to_string_pretty(&value).unwrap()).unwrap();

    let (code, out) = verify(&dir);
    assert_eq!(code, 0, "{out}");
    // Citations come from the SIGNED bodies: an invented row is not one.
    assert!(
        out.contains("18/18 cited artifact(s) recomputed against the citing field"),
        "{out}"
    );
    assert!(out.contains("referenced_artifact_binding VERIFIED"), "{out}");
}

#[test]
fn a_manifest_digest_that_is_not_hex_is_unreadable_never_a_verdict() {
    let dir = scratch("ref-bad-digest");
    let manifest = dir.join("manifest.json");
    let text = std::fs::read_to_string(&manifest)
        .unwrap()
        .replacen(SEQ24_SEGMENT, "not-a-digest", 1);
    std::fs::write(&manifest, &text).unwrap();
    let (code, out, err) = run(&["--pin", &pin_arg(), dir.to_str().unwrap()]);
    assert_eq!(code, 2, "{out}{err}");
    assert!(err.contains("not a 64-hex digest"), "{err}");
    assert!(err.contains("nothing was verified"), "{err}");
}

// --- the epilogue says what is recomputed and what is not ------------------

#[test]
fn the_epilogue_states_the_new_reach_and_its_remaining_limits() {
    let (_, out) = verify(&fixture());
    assert!(out.contains("What referenced_artifact_binding covers:"), "{out}");
    assert!(
        out.contains("re-derived from the signed bodies, never read from the unsigned manifest"),
        "{out}"
    );
    // The leaf came OFF the not-recomputed list when it started travelling;
    // the other two stay on it, and the epilogue now says why each one does.
    assert!(out.contains("sensor_signature.device_chain.leaf_sha256"), "{out}");
    assert!(
        out.contains("Still NOT recomputed here: prev_segment_sha256 as a chain of files, sensor_key_sha256"),
        "{out}"
    );
    assert!(out.contains("device_chain.anchor_sha256"), "{out}");
    assert!(
        !out.contains("Still NOT recomputed here: prev_segment_sha256 as a chain of files, sensor_key_sha256, and device_chain.anchor_sha256."),
        "the leaf must no longer be implied absent from the recomputed set: {out}"
    );
    // The old claim is gone, and what replaced it does not overstate: no
    // frame is decoded either way.
    assert!(
        !out.contains("segment_sha256 is a reference this tool does not recompute"),
        "{out}"
    );
    assert!(out.contains("no frame is decoded and no scene is judged"), "{out}");
}

/// The property is about BYTES. Identity is a different boundary question and
/// keeps its own answer — a bundle whose every cited artifact verifies still
/// does not establish which physical camera produced them.
#[test]
fn verified_payload_does_not_move_source_device_established() {
    let (_, out) = verify(&fixture());
    assert!(out.contains("referenced_artifact_binding  VERIFIED"), "{out}");
    assert!(out.contains("source_device_established    NO"), "{out}");
    assert!(
        out.contains("no independently trusted device credential establishes that identity"),
        "{out}"
    );
}
