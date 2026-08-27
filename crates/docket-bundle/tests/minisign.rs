//! Minisign seal-signature verification against the committed TEST vector:
//! a throwaway key's signature over the real D-0 seal document bytes (see
//! tests/vectors/README.md — it is NOT the operator's signature, and the
//! seal key is not a chain-signing key; no role overlap may be inferred).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use docket_bundle::{MinisignError, MinisignPublicKey, MinisignSignature};

fn vector(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn pub_text() -> String {
    std::fs::read_to_string(vector("minisign-test.pub")).unwrap()
}

fn sig_text() -> String {
    std::fs::read_to_string(vector("seal-2026-08.json.test.minisig")).unwrap()
}

fn seal_bytes() -> Vec<u8> {
    std::fs::read(vector("seal-2026-08.json")).unwrap()
}

const TEST_KEY_ID: &str = "592902d0ec4a755a";

/// A second throwaway TEST public key (different minisign key id), for
/// wrong-key grading. Its secret is discarded; nothing is signed under it.
const OTHER_PUB: &str = "untrusted comment: minisign public key 8D04332BB3D74D83\n\
                         RWSDTdezKzMEjc+b6zv5s53fBvOd+Bssq5m48CsB+SklPW9zu1O2NSPN\n";

#[test]
fn public_key_parses_from_all_three_accepted_forms() {
    let from_file = MinisignPublicKey::from_text(&pub_text()).unwrap();
    assert_eq!(from_file.key_id_hex(), TEST_KEY_ID);

    // Bare base64 line (no comment).
    let b64 = pub_text().lines().nth(1).unwrap().to_owned();
    assert_eq!(MinisignPublicKey::from_text(&b64).unwrap(), from_file);

    // The `minisign:<base64>` string form — the SHAPE the seal uses for its
    // embedded claim. Accepting the shape from an operator-supplied file is
    // not reading the bundle's value.
    let prefixed = format!("minisign:{b64}");
    assert_eq!(MinisignPublicKey::from_text(&prefixed).unwrap(), from_file);
}

#[test]
fn vector_signature_verifies_over_the_seal_bytes() {
    let key = MinisignPublicKey::from_text(&pub_text()).unwrap();
    let sig = MinisignSignature::from_text(&sig_text()).unwrap();
    assert_eq!(sig.key_id_hex(), TEST_KEY_ID);
    assert_eq!(sig.alg_label(), "prehashed (ED, BLAKE2b-512)");
    sig.verify(&key, &seal_bytes()).unwrap();
}

#[test]
fn one_flipped_seal_byte_fails_the_signature() {
    let key = MinisignPublicKey::from_text(&pub_text()).unwrap();
    let sig = MinisignSignature::from_text(&sig_text()).unwrap();
    let mut bytes = seal_bytes();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    assert_eq!(sig.verify(&key, &bytes), Err(MinisignError::BadSignature));
}

#[test]
fn tampered_trusted_comment_fails_the_global_signature() {
    // The file signature still verifies (it covers the seal, not the
    // comment); the trusted comment's own global signature must catch the
    // edit. minisign -V behaves the same way.
    let key = MinisignPublicKey::from_text(&pub_text()).unwrap();
    let tampered = sig_text().replace("throwaway key", "THROWAWAY KEY");
    let sig = MinisignSignature::from_text(&tampered).unwrap();
    assert_eq!(sig.verify(&key, &seal_bytes()), Err(MinisignError::BadGlobalSignature));
}

#[test]
fn wrong_key_is_a_key_id_mismatch_not_a_bad_signature() {
    let other = MinisignPublicKey::from_text(OTHER_PUB).unwrap();
    let sig = MinisignSignature::from_text(&sig_text()).unwrap();
    match sig.verify(&other, &seal_bytes()) {
        Err(MinisignError::KeyIdMismatch { signature, key }) => {
            assert_eq!(signature, TEST_KEY_ID);
            assert_eq!(key, other.key_id_hex());
        }
        other => panic!("expected KeyIdMismatch, got {other:?}"),
    }
}

#[test]
fn corrupted_signature_bytes_still_parse_and_fail_cryptographically() {
    // Flip one bit inside the 64 signature bytes, re-encode: the file is
    // structurally fine, so it parses — and then FAILS, which is the grade
    // a tampered signature must get (never "unreadable").
    let key = MinisignPublicKey::from_text(&pub_text()).unwrap();
    let text = sig_text();
    let sig_line = text.lines().nth(1).unwrap();
    let mut blob = BASE64.decode(sig_line).unwrap();
    blob[20] ^= 0x01; // inside the signature, not the alg/key_id header
    let tampered = text.replace(sig_line, &BASE64.encode(&blob));
    let sig = MinisignSignature::from_text(&tampered).unwrap();
    assert_eq!(sig.verify(&key, &seal_bytes()), Err(MinisignError::BadSignature));
}

#[test]
fn malformed_documents_are_named_malformed() {
    // Truncated blob.
    let short = BASE64.encode(b"Ed too short");
    assert!(matches!(
        MinisignPublicKey::from_text(&short),
        Err(MinisignError::Malformed(_))
    ));
    // Not base64 at all.
    assert!(matches!(
        MinisignPublicKey::from_text("untrusted comment: x\n!!!!\n"),
        Err(MinisignError::Malformed(_))
    ));
    // A signature blob with an unknown algorithm tag.
    let text = sig_text();
    let sig_line = text.lines().nth(1).unwrap();
    let mut blob = BASE64.decode(sig_line).unwrap();
    blob[0] = b'X';
    let bad_alg = text.replace(sig_line, &BASE64.encode(&blob));
    assert!(matches!(
        MinisignSignature::from_text(&bad_alg),
        Err(MinisignError::UnsupportedAlgorithm(_))
    ));
    // A trusted comment with no global signature line after it.
    let no_global = format!("untrusted comment: x\n{sig_line}\ntrusted comment: y\n");
    assert!(matches!(
        MinisignSignature::from_text(&no_global),
        Err(MinisignError::Malformed(_))
    ));
    // A public key is not a signature.
    assert!(matches!(
        MinisignSignature::from_text(&pub_text()),
        Err(MinisignError::Malformed(_))
    ));
}
