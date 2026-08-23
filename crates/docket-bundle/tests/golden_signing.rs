//! Step 2 golden tests: every signature in chain-signing-v1.json reproduced
//! from the PUBLIC key alone, the domain tags, negative cases, and the
//! session-granularity key rule.

mod common;

use common::*;
use docket_bundle::sig::{signature_from_hex, signed_input, ENTRY_SIG_TAG, HEAD_SIG_TAG, SCHEME};
use docket_bundle::{check_session_key_binding, sha256_hex, PublicKey, SessionKeyBinding, SessionKeyError, SigDomain, SigError};

fn test_pubkey() -> PublicKey {
    let vx = load_json("chain-signing-v1.json");
    PublicKey::from_hex(str_of(&vx["test_key"], "public_key_hex")).expect("valid test public key")
}

fn domain_of(tag: &str) -> SigDomain {
    match tag {
        "entry" => SigDomain::Entry,
        "head" => SigDomain::Head,
        other => panic!("unknown tag {other}"),
    }
}

/// RFC 8032 §7.1 test 1 public key — a valid Ed25519 key that is NOT the
/// VIRP test key. Used as the "wrong key" in negative tests.
const RFC8032_PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn vector_file_declares_the_scheme_we_implement() {
    let vx = load_json("chain-signing-v1.json");
    assert_eq!(str_of(&vx, "scheme"), SCHEME);
    assert_eq!(str_of(&vx, "vector_set"), "virp-chain-signing/1");
}

#[test]
fn domain_tags_match_vector_bytes_and_lengths() {
    let vx = load_json("chain-signing-v1.json");
    let tags = &vx["tags"];
    assert_eq!(ENTRY_SIG_TAG, unhex(str_of(&tags["entry"], "bytes_hex")).as_slice());
    assert_eq!(ENTRY_SIG_TAG.len() as i64, i64_of(&tags["entry"], "length"));
    assert_eq!(HEAD_SIG_TAG, unhex(str_of(&tags["head"], "bytes_hex")).as_slice());
    assert_eq!(HEAD_SIG_TAG.len() as i64, i64_of(&tags["head"], "length"));
    // The NUL is part of the tag.
    assert_eq!(ENTRY_SIG_TAG.last(), Some(&0u8));
    assert_eq!(HEAD_SIG_TAG.last(), Some(&0u8));
    assert_eq!(&ENTRY_SIG_TAG[..23], str_of(&tags["entry"], "ascii").as_bytes());
    assert_eq!(&HEAD_SIG_TAG[..22], str_of(&tags["head"], "ascii").as_bytes());
}

#[test]
fn test_key_id_matches() {
    let vx = load_json("chain-signing-v1.json");
    assert_eq!(test_pubkey().key_id(), str_of(&vx["test_key"], "key_id_hex"));
}

#[test]
fn signed_input_hashes_reproduce() {
    let vx = load_json("chain-signing-v1.json");
    for v in vx["vectors"].as_array().unwrap() {
        let name = str_of(v, "name");
        let input = signed_input(domain_of(str_of(v, "tag")), str_of(v, "message_utf8").as_bytes());
        assert_eq!(sha256_hex(&input), str_of(v, "signed_input_sha256"), "{name}: signed_input_sha256");
    }
}

#[test]
fn every_vector_signature_verifies_under_its_own_tag_with_public_key_only() {
    let vx = load_json("chain-signing-v1.json");
    let pk = test_pubkey();
    let vectors = vx["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for v in vectors {
        let name = str_of(v, "name");
        let domain = domain_of(str_of(v, "tag"));
        let msg = str_of(v, "message_utf8").as_bytes();
        pk.verify_hex(domain, msg, str_of(v, "signature_hex"))
            .unwrap_or_else(|e| panic!("{name}: golden signature did not verify: {e}"));
        // Also via the hex-bytes form of the message.
        pk.verify_hex(domain, &unhex(str_of(v, "message_hex")), str_of(v, "signature_hex"))
            .unwrap_or_else(|e| panic!("{name}: golden signature (hex form) did not verify: {e}"));
    }
}

#[test]
fn entry_signature_must_not_validate_under_head_tag_and_vice_versa() {
    let vx = load_json("chain-signing-v1.json");
    let pk = test_pubkey();
    for v in vx["vectors"].as_array().unwrap() {
        let name = str_of(v, "name");
        let wrong = match domain_of(str_of(v, "tag")) {
            SigDomain::Entry => SigDomain::Head,
            SigDomain::Head => SigDomain::Entry,
        };
        let r = pk.verify_hex(wrong, str_of(v, "message_utf8").as_bytes(), str_of(v, "signature_hex"));
        assert_eq!(r, Err(SigError::BadSignature), "{name}: validated under the wrong domain tag");
        // And with no tag at all (the raw canonical) it must also fail —
        // the tag is load-bearing.
        let sig = signature_from_hex(str_of(v, "signature_hex")).unwrap();
        let raw_input_key = pk.clone();
        let ok_raw = ed25519_strict_raw(&raw_input_key, str_of(v, "message_utf8").as_bytes(), &sig);
        assert!(!ok_raw, "{name}: validated over the untagged canonical");
    }
}

/// Helper: verify over exactly `msg` with no tag, via the public API by
/// constructing an input whose tag-stripped form is `msg`. We can't bypass
/// the tag through `PublicKey::verify`, which is the point — so instead
/// check using ed25519-dalek directly on the raw bytes.
fn ed25519_strict_raw(pk: &PublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&pk.to_bytes()).unwrap();
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

#[test]
fn every_single_byte_mutation_of_message_is_rejected() {
    let vx = load_json("chain-signing-v1.json");
    let pk = test_pubkey();
    for v in vx["vectors"].as_array().unwrap() {
        let name = str_of(v, "name");
        let domain = domain_of(str_of(v, "tag"));
        let msg = str_of(v, "message_utf8").as_bytes().to_vec();
        let sig = signature_from_hex(str_of(v, "signature_hex")).unwrap();
        assert!(pk.verify(domain, &msg, &sig).is_ok());
        for i in 0..msg.len() {
            let mut m = msg.clone();
            m[i] ^= 0x01;
            assert_eq!(pk.verify(domain, &m, &sig), Err(SigError::BadSignature), "{name}: byte {i} mutation accepted");
        }
        // Truncation and extension are also rejected.
        assert!(pk.verify(domain, &msg[..msg.len() - 1], &sig).is_err(), "{name}: truncated message accepted");
        let mut ext = msg.clone();
        ext.push(b' ');
        assert!(pk.verify(domain, &ext, &sig).is_err(), "{name}: extended message accepted");
    }
}

#[test]
fn every_single_byte_mutation_of_signature_is_rejected() {
    let vx = load_json("chain-signing-v1.json");
    let pk = test_pubkey();
    for v in vx["vectors"].as_array().unwrap() {
        let name = str_of(v, "name");
        let domain = domain_of(str_of(v, "tag"));
        let msg = str_of(v, "message_utf8").as_bytes();
        let sig = signature_from_hex(str_of(v, "signature_hex")).unwrap();
        for i in 0..64 {
            let mut s = sig;
            s[i] ^= 0x01;
            assert!(pk.verify(domain, msg, &s).is_err(), "{name}: signature byte {i} mutation accepted");
        }
    }
}

#[test]
fn wrong_public_key_is_rejected() {
    let vx = load_json("chain-signing-v1.json");
    let wrong = PublicKey::from_hex(RFC8032_PK_HEX).expect("RFC 8032 key is valid");
    assert_ne!(wrong.key_id(), test_pubkey().key_id());
    for v in vx["vectors"].as_array().unwrap() {
        let name = str_of(v, "name");
        let r = wrong.verify_hex(domain_of(str_of(v, "tag")), str_of(v, "message_utf8").as_bytes(), str_of(v, "signature_hex"));
        assert_eq!(r, Err(SigError::BadSignature), "{name}: verified under a foreign key");
    }
    // And a pubkey with a flipped byte is either invalid or rejects every vector.
    let mut raw = test_pubkey().to_bytes();
    raw[0] ^= 0x01;
    if let Ok(near) = PublicKey::from_bytes(&raw) {
        for v in vx["vectors"].as_array().unwrap() {
            let r = near.verify_hex(domain_of(str_of(v, "tag")), str_of(v, "message_utf8").as_bytes(), str_of(v, "signature_hex"));
            assert!(r.is_err());
        }
    }
}

#[test]
fn malformed_inputs_are_rejected_cleanly() {
    assert_eq!(PublicKey::from_hex("zz").unwrap_err(), SigError::InvalidPublicKey);
    assert_eq!(PublicKey::from_hex("00").unwrap_err(), SigError::InvalidPublicKey);
    // Wrong lengths are rejected before any curve work.
    assert_eq!(PublicKey::from_hex(&"00".repeat(31)).unwrap_err(), SigError::InvalidPublicKey);
    assert_eq!(PublicKey::from_hex(&"00".repeat(33)).unwrap_err(), SigError::InvalidPublicKey);
    assert_eq!(signature_from_hex("abcd").unwrap_err(), SigError::MalformedSignature);
    assert_eq!(signature_from_hex(&"0".repeat(130)).unwrap_err(), SigError::MalformedSignature);
    let pk = test_pubkey();
    assert_eq!(pk.verify_hex(SigDomain::Entry, b"x", "not-hex").unwrap_err(), SigError::MalformedSignature);
    // A zero signature is rejected (not a panic).
    assert_eq!(pk.verify(SigDomain::Entry, b"x", &[0u8; 64]).unwrap_err(), SigError::BadSignature);
}

// ---------------------------------------------------------------------------
// Session-granularity key rule
// ---------------------------------------------------------------------------

#[test]
fn session_key_rule_bound_when_all_entries_match_head() {
    let k = "24f6ed6acbfe1009c030d7ca567c33ca";
    let r = check_session_key_binding(Some(k), [(0, Some(k)), (1, Some(k)), (2, Some(k))]);
    assert_eq!(r, Ok(SessionKeyBinding::Bound { key_id: k.to_owned() }));
}

#[test]
fn session_key_rule_mismatch_is_a_failure_not_a_skip() {
    let head = "24f6ed6acbfe1009c030d7ca567c33ca";
    let other = "ffffffffffffffffffffffffffffffff";
    let r = check_session_key_binding(Some(head), [(0, Some(head)), (1, Some(other)), (2, Some(head))]);
    assert_eq!(
        r,
        Err(SessionKeyError::KeyIdMismatch { sequence: 1, entry_key_id: other.to_owned(), head_key_id: head.to_owned() })
    );
}

#[test]
fn session_key_rule_stripped_signature_is_a_failure() {
    let head = "24f6ed6acbfe1009c030d7ca567c33ca";
    let r = check_session_key_binding(Some(head), [(0, Some(head)), (1, None)]);
    assert_eq!(r, Err(SessionKeyError::StrippedSignature { sequence: 1 }));
    // Even when it is the only entry.
    let r = check_session_key_binding(Some(head), [(0, None)]);
    assert_eq!(r, Err(SessionKeyError::StrippedSignature { sequence: 0 }));
}

#[test]
fn session_key_rule_unsigned_head_never_fails() {
    let k = "24f6ed6acbfe1009c030d7ca567c33ca";
    let r = check_session_key_binding(None, [(0, None), (1, Some(k)), (2, None)]);
    assert_eq!(r, Ok(SessionKeyBinding::UnsignedSession { entries_with_signatures: 1 }));
    let r = check_session_key_binding(None, std::iter::empty());
    assert_eq!(r, Ok(SessionKeyBinding::UnsignedSession { entries_with_signatures: 0 }));
}

#[test]
fn session_key_rule_reports_first_violation_in_chain_order() {
    let head = "24f6ed6acbfe1009c030d7ca567c33ca";
    let r = check_session_key_binding(Some(head), [(0, Some(head)), (1, None), (2, Some("00000000000000000000000000000000"))]);
    assert_eq!(r, Err(SessionKeyError::StrippedSignature { sequence: 1 }));
}

// ---------------------------------------------------------------------------
// Boundary: no secret material, no signing code, anywhere in the crate.
// ---------------------------------------------------------------------------

#[test]
fn crate_source_contains_no_signing_or_secret_material() {
    let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    // `unsafe_code` (the forbid lint) is allowed; actual unsafe syntax is not.
    let forbidden = ["SigningKey", "secret_key", "seed_hex", "unsafe {", "unsafe fn", "unsafe impl", "unsafe extern"];
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for needle in forbidden {
            assert!(!text.contains(needle), "{} mentions forbidden token {needle:?}", path.display());
        }
    }
}
