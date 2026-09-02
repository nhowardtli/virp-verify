//! One key format on both sides of Docket.
//!
//! The exporter's `--keys` took the D-1 public half as a bare hex file; the
//! verifier's `--pin` took only a docket keys.json and answered "invalid
//! JSON" for the same file. An operator holding one key file had to know
//! which half of the tool they were talking to. Both now read both forms,
//! and the key_id is derived from the bytes either way.

use std::path::PathBuf;
use std::process::Command;

/// The bundle's own key, offered back as an examiner pin — the same file,
/// different provenance.
const FIXTURE_KEY_HEX: &str = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
const FIXTURE_KEY_ID: &str = "24f6ed6acbfe1009c030d7ca567c33ca";
/// A different, valid Ed25519 public key (the comp-clean fixture's).
const OTHER_KEY_HEX: &str = "9c7576bec88061db32761eddaa35469f65ee4b1758ccbae8bab3f17fb52cdea2";

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inv-lock-bundle")
}

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

fn write_key(name: &str, bytes: &[u8]) -> String {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("key-format");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}

fn pin(path: &str) -> (i32, String, String) {
    run(&["--pin", path, fixture().to_str().unwrap()])
}

/// The form an operator actually has: the public half as it sits on the
/// daemon host, 64 hex characters and a newline.
#[test]
fn a_bare_hex_key_file_pins_exactly_as_the_keys_json_does() {
    let hex = write_key("chain.hex", format!("{FIXTURE_KEY_HEX}\n").as_bytes());
    let json = fixture().join("keys.json").to_str().unwrap().to_owned();

    let (hex_code, hex_out, _) = pin(&hex);
    let (json_code, json_out, _) = pin(&json);

    assert_eq!(hex_code, 0, "{hex_out}");
    assert_eq!(hex_code, json_code);
    assert_eq!(hex_out, json_out, "the two forms must produce the same report");
    assert!(
        hex_out.contains("SIGNER TRUST: PINNED") || hex_out.contains("PINNED"),
        "{hex_out}"
    );
    assert!(hex_out.contains(FIXTURE_KEY_ID), "{hex_out}");
}

/// Whitespace around the hex, and either casing, are the shapes real files
/// come in. The exporter already lowercased; so does this.
#[test]
fn hex_is_read_in_either_casing_and_with_surrounding_whitespace() {
    let upper = write_key("chain-upper.hex", FIXTURE_KEY_HEX.to_uppercase().as_bytes());
    let padded = write_key("chain-padded.hex", format!("  {FIXTURE_KEY_HEX}  \n\n").as_bytes());
    let plain = write_key("chain-plain.hex", FIXTURE_KEY_HEX.as_bytes());

    let (_, baseline, _) = pin(&plain);
    for path in [&upper, &padded] {
        let (code, out, err) = pin(path);
        assert_eq!(code, 0, "{path}: {out}{err}");
        assert_eq!(out, baseline, "{path} produced a different report");
    }
}

/// There is no key_id in the hex form to trust, and the id the verifier
/// reports is the one sha256-raw-16 derives from the bytes.
#[test]
fn the_key_id_is_derived_from_the_bytes() {
    let hex = write_key("derive.hex", FIXTURE_KEY_HEX.as_bytes());
    let (code, out, _) = pin(&hex);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains(&format!("pinned:  1 examiner-supplied key(s): {FIXTURE_KEY_ID}")),
        "{out}"
    );
}

/// A different valid key is a MISMATCH, not an error and not a silent
/// UNESTABLISHED: the examiner pinned something, and it does not match.
#[test]
fn a_different_valid_key_in_either_form_is_a_mismatch() {
    let hex = write_key("other.hex", format!("{OTHER_KEY_HEX}\n").as_bytes());
    let json = write_key(
        "other.json",
        br#"{"keys":[{"key_id":"9cc09cfd5afb42849cfde5db340abfd4","algorithm":"ed25519","public_key_hex":"9c7576bec88061db32761eddaa35469f65ee4b1758ccbae8bab3f17fb52cdea2"}]}"#,
    );
    let (hex_code, hex_out, _) = pin(&hex);
    let (json_code, json_out, _) = pin(&json);
    assert!(hex_out.contains("MISMATCH"), "{hex_out}");
    assert_eq!(hex_out, json_out, "the two forms must produce the same report");
    assert_eq!(hex_code, json_code);
}

/// Raw 32-byte binary is refused on both sides, and the refusal names the
/// two forms that are accepted rather than leaving the operator guessing.
#[test]
fn raw_binary_is_refused_and_the_message_names_both_accepted_forms() {
    let raw: Vec<u8> = (0..32u8).collect();
    let short: Vec<u8> = (0..31u8).collect();
    for (name, bytes) in [("raw32.bin", &raw), ("raw31.bin", &short)] {
        let path = write_key(name, bytes);
        let (code, _, err) = pin(&path);
        assert_eq!(code, 2, "{name} must be a usage error, not a verdict");
        assert!(err.contains("64 hex characters"), "{name}: {err}");
        assert!(err.contains("keys.json"), "{name}: {err}");
        assert!(err.contains("Raw 32-byte binary is not accepted"), "{name}: {err}");
    }
}

/// Hex that is the right characters but the wrong length is not a key file
/// and not JSON either; the same message names both forms.
#[test]
fn hex_of_the_wrong_length_is_refused_with_the_same_message() {
    let path = write_key("short.hex", b"deadbeef\n");
    let (code, _, err) = pin(&path);
    assert_eq!(code, 2);
    assert!(
        err.contains("neither 64 hex characters nor a readable keys.json"),
        "{err}"
    );
}
