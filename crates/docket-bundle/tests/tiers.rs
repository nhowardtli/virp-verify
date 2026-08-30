//! Step 3: the three verification tiers and the verdict vocabulary.
//!
//! The signed session under test is assembled entirely from golden vectors:
//! `inv-lock-entry-0` + `inv-lock-head-0` form a complete one-entry session
//! (`inv-lock-1`) with real Ed25519 signatures over both objects.

mod common;

use common::*;
use docket_bundle::verify::property;
use docket_bundle::{
    verify_session, ChainEntry, ChainHead, DetachedSignature, EntryFields, HeadFields, Keyring, PublicKey,
    SessionChain, SignerTrust, Status, TrustSource, Verdict,
};

const SCHEME: &str = "ed25519-detached-v1";

/// Placeholder HMAC value. Docket cannot verify HMACs, so any well-formed
/// 64-hex string exercises the "present → operator-attested" path. This is
/// NOT a real HMAC and the tests never claim it is.
const PLACEHOLDER_HMAC: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn test_pubkey() -> PublicKey {
    let vx = load_json("chain-signing-v1.json");
    PublicKey::from_hex(str_of(&vx["test_key"], "public_key_hex")).unwrap()
}

fn keyring_with_test_key() -> Keyring {
    let mut k = Keyring::new();
    k.insert_pinned(test_pubkey());
    k
}

fn vector(name: &str) -> serde_json::Value {
    let vx = load_json("chain-signing-v1.json");
    vx["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| str_of(v, "name") == name)
        .cloned()
        .unwrap()
}

/// The golden one-entry signed session.
fn inv_lock_session() -> SessionChain {
    let key_id = test_pubkey().key_id().to_owned();
    let ev = vector("inv-lock-entry-0");
    let hv = vector("inv-lock-head-0");
    let fields = EntryFields::parse_canonical(str_of(&ev, "message_utf8").as_bytes()).unwrap();
    let head_fields = HeadFields::parse_canonical(str_of(&hv, "message_utf8").as_bytes()).unwrap();
    SessionChain {
        session_id: "inv-lock-1".into(),
        entries: vec![ChainEntry {
            chain_entry_hash: fields.entry_hash_hex(),
            canonical_utf8: Some(str_of(&ev, "message_utf8").into()),
            fields,
            chain_hmac: Some(PLACEHOLDER_HMAC.into()),
            signature: Some(DetachedSignature {
                signature_scheme: SCHEME.into(),
                signing_key_id: key_id.clone(),
                signature_hex: str_of(&ev, "signature_hex").into(),
            }),
        }],
        head: Some(ChainHead {
            fields: head_fields,
            canonical_utf8: Some(str_of(&hv, "message_utf8").into()),
            head_hmac: Some(PLACEHOLDER_HMAC.into()),
            signature: Some(DetachedSignature {
                signature_scheme: SCHEME.into(),
                signing_key_id: key_id,
                signature_hex: str_of(&hv, "signature_hex").into(),
            }),
        }),
    }
}

/// A synthetic unsigned chain of `n` entries in session `sid`, hashes
/// computed by this crate (the primitives are proven elsewhere).
fn synthetic_session(sid: &str, n: usize, with_hmac: bool) -> SessionChain {
    let mut entries = Vec::new();
    let mut prev = docket_bundle::genesis_hash_hex(sid);
    for i in 0..n {
        let fields = EntryFields {
            artifact_hash: format!("{:064x}", i + 1),
            artifact_hash_alg: "sha256".into(),
            artifact_id: format!("obs:synthetic:{i}"),
            artifact_schema_version: "1".into(),
            artifact_type: "observation".into(),
            monotonic_ns: 1_000 + i as u64,
            previous_entry_hash: prev.clone(),
            sequence: i as i64,
            session_id: sid.into(),
            signer_node_id: 1,
            signer_org_id: "local".into(),
            timestamp_ns: 1_787_000_000_000_000_000 + i as u64,
        };
        let h = fields.entry_hash_hex();
        entries.push(ChainEntry {
            fields,
            chain_entry_hash: h.clone(),
            canonical_utf8: None,
            chain_hmac: with_hmac.then(|| PLACEHOLDER_HMAC.into()),
            signature: None,
        });
        prev = h;
    }
    SessionChain {
        session_id: sid.into(),
        head: Some(ChainHead {
            fields: HeadFields {
                session_id: sid.into(),
                last_sequence: n as i64 - 1,
                last_entry_hash: prev,
            },
            canonical_utf8: None,
            head_hmac: with_hmac.then(|| PLACEHOLDER_HMAC.into()),
            signature: None,
        }),
        entries,
    }
}

fn status_of<'a>(r: &'a docket_bundle::SessionReport, name: &str) -> &'a Status {
    r.status(name).unwrap_or_else(|| panic!("report lacks property {name}"))
}

// ---------------------------------------------------------------------------
// Asymmetric tier — golden session
// ---------------------------------------------------------------------------

#[test]
fn golden_signed_session_is_cryptographically_verified_with_public_key() {
    let r = verify_session(&inv_lock_session(), &keyring_with_test_key());
    for p in &r.properties {
        match p.name.as_str() {
            property::ENTRY_HMACS | property::HEAD_HMAC => assert_eq!(p.status, Status::OperatorAttested, "{}", p.name),
            _ => assert_eq!(p.status, Status::Verified, "{}: {:?}", p.name, p.status),
        }
    }
    assert_eq!(r.verdict, Verdict::CryptographicallyVerified);
    assert_eq!(r.signing_key_id.as_deref(), Some("24f6ed6acbfe1009c030d7ca567c33ca"));
    assert_eq!(r.entry_count, 1);
    assert_eq!(r.properties.len(), property::ALL.len());
    assert_eq!(
        r.properties.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        property::ALL.to_vec()
    );
}

#[test]
fn golden_signed_session_without_key_is_unverifiable_not_verified() {
    let r = verify_session(&inv_lock_session(), &Keyring::new());
    assert!(matches!(
        status_of(&r, property::HEAD_SIGNATURE),
        Status::Unverifiable { .. }
    ));
    assert!(matches!(
        status_of(&r, property::ENTRY_SIGNATURES),
        Status::Unverifiable { .. }
    ));
    // The key rule is structural and is still graded without the key.
    assert_eq!(status_of(&r, property::SESSION_KEY_BINDING), &Status::Verified);
    assert_eq!(status_of(&r, property::ENTRY_HASHES), &Status::Verified);
    assert_eq!(r.verdict, Verdict::OperatorAttestedUnverifiable);
}

#[test]
fn golden_signed_session_with_wrong_key_in_keyring_is_unverifiable() {
    // RFC 8032 key: valid, but not the session's key_id → unverifiable (soft), not failed.
    let mut k = Keyring::new();
    k.insert_pinned(PublicKey::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap());
    let r = verify_session(&inv_lock_session(), &k);
    assert!(matches!(
        status_of(&r, property::HEAD_SIGNATURE),
        Status::Unverifiable { .. }
    ));
    assert_eq!(r.verdict, Verdict::OperatorAttestedUnverifiable);
    // The examiner stated an expectation and the session's signer is not in
    // it: MISMATCH, with no key available for the check.
    assert_eq!(r.signer.trust, SignerTrust::Mismatch);
    assert_eq!(r.signer.trust_source, None);
}

// ---------------------------------------------------------------------------
// The signer-trust axis: validity and trust are separate results
// ---------------------------------------------------------------------------

fn keyring_with_bundle_key() -> Keyring {
    let mut k = Keyring::new();
    k.insert_bundle(test_pubkey());
    k
}

#[test]
fn bundle_provided_key_verifies_but_demotes_to_cryptographically_consistent() {
    let r = verify_session(&inv_lock_session(), &keyring_with_bundle_key());
    // Axis 1: the cryptography held, exactly as under a pinned key.
    assert_eq!(status_of(&r, property::HEAD_SIGNATURE), &Status::Verified);
    assert_eq!(status_of(&r, property::ENTRY_SIGNATURES), &Status::Verified);
    assert_eq!(r.signer.signature_validity, Status::Verified);
    // Axis 2: signer trust was not established.
    assert_eq!(r.signer.trust, SignerTrust::Unestablished);
    assert_eq!(r.signer.trust_source, Some(TrustSource::BundleProvidedKey));
    // And the top line says so: NOT cryptographically verified.
    assert_eq!(r.verdict, Verdict::CryptographicallyConsistent);
}

#[test]
fn pinned_key_establishes_trust_and_the_full_verdict() {
    let r = verify_session(&inv_lock_session(), &keyring_with_test_key());
    assert_eq!(r.signer.signature_validity, Status::Verified);
    assert_eq!(r.signer.trust, SignerTrust::Pinned);
    assert_eq!(r.signer.trust_source, Some(TrustSource::ExaminerTrustStore));
    assert_eq!(r.verdict, Verdict::CryptographicallyVerified);
}

#[test]
fn pinned_key_beside_bundle_copy_stays_pinned() {
    // The bundle carries the same key the examiner pinned: the examiner's
    // provenance wins, in either insertion order.
    for pinned_first in [true, false] {
        let mut k = Keyring::new();
        if pinned_first {
            k.insert_pinned(test_pubkey());
            k.insert_bundle(test_pubkey());
        } else {
            k.insert_bundle(test_pubkey());
            k.insert_pinned(test_pubkey());
        }
        assert_eq!(k.len(), 1);
        let r = verify_session(&inv_lock_session(), &k);
        assert_eq!(r.signer.trust, SignerTrust::Pinned, "pinned_first={pinned_first}");
        assert_eq!(r.verdict, Verdict::CryptographicallyVerified);
    }
}

#[test]
fn wrong_pin_beside_the_bundle_key_is_mismatch_with_validity_intact() {
    // The bundle's own key checks the signatures (validity VERIFIED); the
    // examiner pinned someone else. MISMATCH, not UNESTABLISHED — and the
    // verdict is demoted, never upgraded, by the pin.
    let mut k = keyring_with_bundle_key();
    k.insert_pinned(PublicKey::from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap());
    let r = verify_session(&inv_lock_session(), &k);
    assert_eq!(r.signer.signature_validity, Status::Verified);
    assert_eq!(r.signer.trust, SignerTrust::Mismatch);
    assert_eq!(r.signer.trust_source, Some(TrustSource::BundleProvidedKey));
    assert_eq!(r.verdict, Verdict::CryptographicallyConsistent);
}

#[test]
fn tampered_signature_under_a_pinned_key_fails_and_leaves_other_properties_verified() {
    // Failure independence across the axes: a corrupted signature FAILS
    // validity (and trust cannot be PINNED — nothing verified under the
    // pin), while hashes, links and the key binding stay VERIFIED.
    let mut s = inv_lock_session();
    let sig = &mut s.entries[0].signature.as_mut().unwrap().signature_hex;
    let mut bytes = hex::decode(&*sig).unwrap();
    bytes[0] ^= 0x01;
    *sig = hex::encode(bytes);
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(r.signer.signature_validity.is_failed());
    assert_eq!(r.signer.trust, SignerTrust::Mismatch);
    assert_eq!(status_of(&r, property::ENTRY_HASHES), &Status::Verified);
    assert_eq!(status_of(&r, property::LINKS), &Status::Verified);
    assert_eq!(status_of(&r, property::SESSION_KEY_BINDING), &Status::Verified);
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn unsigned_session_has_no_signer_to_establish() {
    let r = verify_session(&synthetic_session("docket-synth-t", 3, false), &keyring_with_test_key());
    assert_eq!(r.signer.signature_validity, Status::Absent);
    assert_eq!(r.signer.trust, SignerTrust::Unestablished);
    assert_eq!(r.signer.trust_source, None);
}

#[test]
fn signed_session_with_no_key_anywhere_is_unestablished_with_no_source() {
    let r = verify_session(&inv_lock_session(), &Keyring::new());
    assert!(matches!(r.signer.signature_validity, Status::Unverifiable { .. }));
    assert_eq!(r.signer.trust, SignerTrust::Unestablished);
    assert_eq!(r.signer.trust_source, None);
}

#[test]
fn keyring_derives_key_id_from_bytes_not_labels() {
    let mut k = Keyring::new();
    k.insert_pinned(test_pubkey());
    assert!(k.get("24f6ed6acbfe1009c030d7ca567c33ca").is_some());
    assert!(k.get("ffffffffffffffffffffffffffffffff").is_none());
    assert_eq!(k.len(), 1);
}

#[test]
fn tampered_head_signature_fails() {
    let mut s = inv_lock_session();
    let sig = &mut s.head.as_mut().unwrap().signature.as_mut().unwrap().signature_hex;
    let mut bytes = hex::decode(&*sig).unwrap();
    bytes[10] ^= 0x01;
    *sig = hex::encode(bytes);
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::HEAD_SIGNATURE).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn tampered_entry_signature_fails() {
    let mut s = inv_lock_session();
    let sig = &mut s.entries[0].signature.as_mut().unwrap().signature_hex;
    let mut bytes = hex::decode(&*sig).unwrap();
    bytes[63] ^= 0x01;
    *sig = hex::encode(bytes);
    let r = verify_session(&s, &keyring_with_test_key());
    assert_eq!(status_of(&r, property::HEAD_SIGNATURE), &Status::Verified);
    assert!(status_of(&r, property::ENTRY_SIGNATURES).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn head_and_entry_signatures_swapped_fail() {
    // An entry signature presented as the head signature (and vice versa)
    // must not validate: the domain tags differ.
    let mut s = inv_lock_session();
    let e = s.entries[0].signature.clone().unwrap();
    let h = s.head.as_ref().unwrap().signature.clone().unwrap();
    s.entries[0].signature = Some(h);
    s.head.as_mut().unwrap().signature = Some(e);
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::HEAD_SIGNATURE).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn stripped_entry_signature_in_signed_session_fails_even_without_key() {
    let mut s = inv_lock_session();
    s.entries[0].signature = None;
    for keyring in [Keyring::new(), keyring_with_test_key()] {
        let r = verify_session(&s, &keyring);
        let st = status_of(&r, property::SESSION_KEY_BINDING);
        assert!(st.is_failed(), "{st:?}");
        assert_eq!(r.verdict, Verdict::Failed);
    }
}

#[test]
fn entry_key_id_mismatch_in_signed_session_fails() {
    let mut s = inv_lock_session();
    s.entries[0].signature.as_mut().unwrap().signing_key_id = "00000000000000000000000000000000".into();
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::SESSION_KEY_BINDING).is_failed());
    assert!(status_of(&r, property::ENTRY_SIGNATURES).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn unknown_signature_scheme_fails() {
    let mut s = inv_lock_session();
    s.head.as_mut().unwrap().signature.as_mut().unwrap().signature_scheme = "ed25519-detached-v2".into();
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::HEAD_SIGNATURE).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn carried_canonical_must_match_rebuilt_canonical() {
    // A bundle that carries the signed bytes verbatim is checked against the
    // bytes rebuilt from its fields, both ways.
    let mut s = inv_lock_session();
    s.entries[0].canonical_utf8.as_mut().unwrap().push(' ');
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::ENTRY_HASHES).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
    let mut s = inv_lock_session();
    s.head.as_mut().unwrap().canonical_utf8 = Some("{}".into());
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::HEAD_COMMITMENT).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn tampered_canonical_field_fails_hash_and_signature() {
    let mut s = inv_lock_session();
    s.entries[0].fields.artifact_id.push('x');
    let r = verify_session(&s, &keyring_with_test_key());
    assert!(status_of(&r, property::ENTRY_HASHES).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
    // Even if the attacker also fixes up the stored hash, the carried
    // canonical and the head, the signatures still catch it.
    s.entries[0].chain_entry_hash = s.entries[0].fields.entry_hash_hex();
    s.entries[0].canonical_utf8 = Some(String::from_utf8(s.entries[0].fields.canonical_bytes()).unwrap());
    s.head.as_mut().unwrap().canonical_utf8 = None;
    s.head.as_mut().unwrap().fields.last_entry_hash = s.entries[0].chain_entry_hash.clone();
    let r = verify_session(&s, &keyring_with_test_key());
    assert_eq!(status_of(&r, property::ENTRY_HASHES), &Status::Verified);
    assert_eq!(status_of(&r, property::HEAD_COMMITMENT), &Status::Verified);
    assert!(status_of(&r, property::HEAD_SIGNATURE).is_failed());
    assert!(status_of(&r, property::ENTRY_SIGNATURES).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
    // And without the key, the fixed-up forgery is merely "unverifiable" —
    // which is exactly why that verdict must never read as a pass.
    let r = verify_session(&s, &Keyring::new());
    assert_eq!(r.verdict, Verdict::OperatorAttestedUnverifiable);
}

// ---------------------------------------------------------------------------
// Keyless tier — synthetic chains
// ---------------------------------------------------------------------------

#[test]
fn synthetic_unsigned_chain_with_hmacs_is_operator_attested() {
    let r = verify_session(&synthetic_session("docket-synth-1", 5, true), &Keyring::new());
    for name in [
        property::ENTRY_HASHES,
        property::GENESIS,
        property::LINKS,
        property::CONTIGUITY,
        property::HEAD_COMMITMENT,
    ] {
        assert_eq!(status_of(&r, name), &Status::Verified, "{name}");
    }
    assert_eq!(status_of(&r, property::ENTRY_HMACS), &Status::OperatorAttested);
    assert_eq!(status_of(&r, property::HEAD_HMAC), &Status::OperatorAttested);
    assert_eq!(status_of(&r, property::HEAD_SIGNATURE), &Status::Absent);
    assert_eq!(status_of(&r, property::SESSION_KEY_BINDING), &Status::Absent);
    assert_eq!(status_of(&r, property::ENTRY_SIGNATURES), &Status::Absent);
    assert_eq!(r.verdict, Verdict::OperatorAttestedUnverifiable);
    assert_eq!(r.signing_key_id, None);
}

#[test]
fn synthetic_unsigned_chain_without_hmacs_is_consistent_but_unauthenticated() {
    let r = verify_session(&synthetic_session("docket-synth-2", 3, false), &Keyring::new());
    assert_eq!(status_of(&r, property::ENTRY_HMACS), &Status::Absent);
    assert_eq!(r.verdict, Verdict::ConsistentUnauthenticated);
    // Supplying a public key changes nothing for an unsigned session.
    let r = verify_session(&synthetic_session("docket-synth-2", 3, false), &keyring_with_test_key());
    assert_eq!(r.verdict, Verdict::ConsistentUnauthenticated);
}

#[test]
fn tampered_artifact_hash_breaks_entry_hash_and_link() {
    let mut s = synthetic_session("docket-synth-3", 4, true);
    s.entries[1].fields.artifact_hash = format!("{:064x}", 0xdead);
    let r = verify_session(&s, &Keyring::new());
    assert_eq!(
        status_of(&r, property::ENTRY_HASHES),
        &Status::failed("entry hash mismatch at sequence 1")
    );
    assert_eq!(
        status_of(&r, property::LINKS),
        &Status::failed("previous hash mismatch at sequence 2")
    );
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn deleted_entry_breaks_contiguity() {
    let mut s = synthetic_session("docket-synth-4", 4, true);
    s.entries.remove(2);
    let r = verify_session(&s, &Keyring::new());
    assert_eq!(
        status_of(&r, property::CONTIGUITY),
        &Status::failed("sequence gap: expected 2, got 3")
    );
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn deleted_tail_is_caught_by_head_commitment() {
    let mut s = synthetic_session("docket-synth-5", 4, true);
    s.entries.pop();
    let r = verify_session(&s, &Keyring::new());
    // hashes, genesis, links, contiguity all still hold on the truncated prefix...
    assert_eq!(status_of(&r, property::CONTIGUITY), &Status::Verified);
    assert_eq!(status_of(&r, property::LINKS), &Status::Verified);
    // ...only the head catches it.
    assert!(status_of(&r, property::HEAD_COMMITMENT).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn deleted_head_fails() {
    let mut s = synthetic_session("docket-synth-6", 2, true);
    s.head = None;
    let r = verify_session(&s, &Keyring::new());
    assert!(status_of(&r, property::HEAD_COMMITMENT).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn wrong_genesis_fails() {
    let mut s = synthetic_session("docket-synth-7", 2, true);
    s.entries[0].fields.previous_entry_hash = docket_bundle::genesis_hash_hex("some-other-session");
    s.entries[0].chain_entry_hash = s.entries[0].fields.entry_hash_hex();
    s.entries[1].fields.previous_entry_hash = s.entries[0].chain_entry_hash.clone();
    s.entries[1].chain_entry_hash = s.entries[1].fields.entry_hash_hex();
    s.head.as_mut().unwrap().fields.last_entry_hash = s.entries[1].chain_entry_hash.clone();
    let r = verify_session(&s, &Keyring::new());
    assert_eq!(status_of(&r, property::ENTRY_HASHES), &Status::Verified);
    assert_eq!(status_of(&r, property::LINKS), &Status::Verified);
    assert!(status_of(&r, property::GENESIS).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn entry_from_another_session_fails_contiguity() {
    let mut s = synthetic_session("docket-synth-8", 2, true);
    s.entries[1].fields.session_id = "docket-synth-9".into();
    s.entries[1].chain_entry_hash = s.entries[1].fields.entry_hash_hex();
    s.head.as_mut().unwrap().fields.last_entry_hash = s.entries[1].chain_entry_hash.clone();
    let r = verify_session(&s, &Keyring::new());
    assert!(status_of(&r, property::CONTIGUITY).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn empty_session_fails() {
    let s = SessionChain {
        session_id: "empty".into(),
        entries: vec![],
        head: None,
    };
    let r = verify_session(&s, &Keyring::new());
    assert_eq!(r.verdict, Verdict::Failed);
}

#[test]
fn malformed_hmac_is_failed_not_attested() {
    let mut s = synthetic_session("docket-synth-10", 2, true);
    s.entries[0].chain_hmac = Some("not-a-digest".into());
    let r = verify_session(&s, &Keyring::new());
    assert!(status_of(&r, property::ENTRY_HMACS).is_failed());
    assert_eq!(r.verdict, Verdict::Failed);
}

// ---------------------------------------------------------------------------
// The vocabulary never collapses
// ---------------------------------------------------------------------------

#[test]
fn operator_attested_is_never_verified() {
    // Across every session shape in this file, an HMAC property is never VERIFIED.
    let sessions = vec![
        inv_lock_session(),
        synthetic_session("v-1", 3, true),
        synthetic_session("v-2", 3, false),
    ];
    for s in &sessions {
        for keyring in [Keyring::new(), keyring_with_test_key()] {
            let r = verify_session(s, &keyring);
            for name in [property::ENTRY_HMACS, property::HEAD_HMAC] {
                assert_ne!(
                    status_of(&r, name),
                    &Status::Verified,
                    "{name} reported VERIFIED — Docket holds no K_chain"
                );
            }
        }
    }
}

#[test]
fn verdict_labels_are_distinct_and_honest() {
    let labels: Vec<&str> = [
        Verdict::Failed,
        Verdict::CryptographicallyVerified,
        Verdict::CryptographicallyConsistent,
        Verdict::OperatorAttestedUnverifiable,
        Verdict::ConsistentUnauthenticated,
    ]
    .iter()
    .map(|v| v.label())
    .collect();
    let mut dedup = labels.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), labels.len());
    assert!(Verdict::OperatorAttestedUnverifiable.label().contains("unverifiable"));
    assert!(Verdict::CryptographicallyConsistent
        .label()
        .contains("signer trust not established"));
    assert!(Verdict::ConsistentUnauthenticated.label().contains("UNAUTHENTICATED"));
    assert!(Status::OperatorAttested.label().contains("unverifiable"));
}

#[test]
fn report_round_trips_through_json() {
    let r = verify_session(&inv_lock_session(), &keyring_with_test_key());
    let json = serde_json::to_string_pretty(&r).unwrap();
    let back: docket_bundle::SessionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
    assert!(json.contains("\"verdict\": \"cryptographically_verified\""));
    assert!(json.contains("\"status\": \"operator_attested\""));
}

#[test]
fn session_chain_round_trips_through_json() {
    let s = inv_lock_session();
    let json = serde_json::to_string_pretty(&s).unwrap();
    let back: SessionChain = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
    // Canonical fields are flattened into the entry object.
    assert!(json.contains("\"artifact_id\": \"obs:inv-lock:0001\""));
}
