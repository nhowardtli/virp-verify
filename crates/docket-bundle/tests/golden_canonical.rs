//! Step 1 golden tests: canonical bytes, entry hash, genesis, head canonical,
//! key_id — every value reproduced from the VIRP fixtures, plus the
//! one-byte-mutation discipline (every mutation must be detected).

mod common;

use common::*;
use docket_bundle::{genesis_hash_hex, key_id_hex, sha256_hex, EntryFields, HeadFields};

#[test]
fn appendix_a_fixture_file_is_the_one_the_seal_anchors() {
    let bytes = load_bytes("fixtures-appendix-a.json");
    assert_eq!(sha256_hex(&bytes), FIXTURES_APPENDIX_A_SHA256);
}

#[test]
fn appendix_a_entries_reproduce_canonical_bytes_and_hash() {
    let fx = load_json("fixtures-appendix-a.json");
    let entries = fx["entries"].as_object().expect("entries object");
    assert_eq!(entries.len(), 5, "Appendix A has five entries");
    for (name, e) in entries {
        let canonical_utf8 = str_of(e, "canonical_utf8");
        let fields = EntryFields::parse_canonical(canonical_utf8.as_bytes())
            .unwrap_or_else(|err| panic!("fixture {name}: parse: {err}"));
        let rebuilt = fields.canonical_bytes();
        assert_eq!(rebuilt, canonical_utf8.as_bytes(), "fixture {name}: canonical bytes");
        assert_eq!(rebuilt.len() as i64, i64_of(e, "canonical_len"), "fixture {name}: canonical_len");
        let canonical_hex = str_of(e, "canonical_hex");
        if !canonical_hex.is_empty() {
            assert_eq!(rebuilt, unhex(canonical_hex), "fixture {name}: canonical_hex");
        }
        assert_eq!(fields.entry_hash_hex(), str_of(e, "chain_entry_hash"), "fixture {name}: chain_entry_hash");
        assert_eq!(fields.sequence, i64_of(e, "sequence"));
        assert_eq!(fields.session_id, str_of(e, "session_id"));
        assert_eq!(fields.artifact_type, str_of(e, "type_note"));
    }
}

#[test]
fn appendix_a_genesis_rule() {
    let fx = load_json("fixtures-appendix-a.json");
    // Explicit genesis value for approval:clab-frr-ospf-frr1.
    let g0 = &fx["genesis"][0];
    assert_eq!(str_of(g0, "session_id"), "approval:clab-frr-ospf-frr1");
    assert_eq!(genesis_hash_hex("approval:clab-frr-ospf-frr1"), str_of(g0, "genesis_hash"));
    // Fixture A is sequence 0 of autopilot:2026-08-22; its previous_entry_hash
    // must be that session's genesis.
    let a = EntryFields::parse_canonical(str_of(&fx["entries"]["A"], "canonical_utf8").as_bytes()).unwrap();
    assert_eq!(a.sequence, 0);
    assert_eq!(genesis_hash_hex(&a.session_id), a.previous_entry_hash);
}

#[test]
fn appendix_a_entries_link_d_b_c() {
    // D (seq 81) -> B (seq 82) -> C (seq 83) in approval:clab-frr-ospf-frr1.
    let fx = load_json("fixtures-appendix-a.json");
    let get = |n: &str| EntryFields::parse_canonical(str_of(&fx["entries"][n], "canonical_utf8").as_bytes()).unwrap();
    let (d, b, c) = (get("D"), get("B"), get("C"));
    assert_eq!((d.sequence, b.sequence, c.sequence), (81, 82, 83));
    assert_eq!(b.previous_entry_hash, d.entry_hash_hex());
    assert_eq!(c.previous_entry_hash, b.entry_hash_hex());
}

#[test]
fn appendix_a_head_canonical() {
    let fx = load_json("fixtures-appendix-a.json");
    let h = &fx["head"];
    let head = HeadFields {
        session_id: str_of(h, "session_id").to_owned(),
        last_sequence: i64_of(h, "last_sequence"),
        last_entry_hash: str_of(h, "last_entry_hash").to_owned(),
    };
    let bytes = head.canonical_bytes();
    assert_eq!(bytes, str_of(h, "canonical_utf8").as_bytes());
    assert_eq!(bytes, unhex(str_of(h, "canonical_hex")));
    assert_eq!(HeadFields::parse_canonical(&bytes).unwrap(), head);
}

#[test]
fn signing_vectors_messages_reproduce() {
    let vx = load_json("chain-signing-v1.json");
    let vectors = vx["vectors"].as_array().expect("vectors");
    assert_eq!(vectors.len(), 4);
    let mut inv_entry_hash = None;
    let mut inv_head = None;
    for v in vectors {
        let name = str_of(v, "name");
        let msg = str_of(v, "message_utf8");
        let msg_hex = unhex(str_of(v, "message_hex"));
        assert_eq!(msg.as_bytes(), msg_hex.as_slice(), "{name}: message_utf8 vs message_hex");
        match str_of(v, "tag") {
            "entry" => {
                let f = EntryFields::parse_canonical(msg.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(f.canonical_bytes(), msg_hex, "{name}: rebuilt entry canonical");
                if name == "inv-lock-entry-0" {
                    assert_eq!(f.sequence, 0);
                    assert_eq!(genesis_hash_hex(&f.session_id), f.previous_entry_hash, "{name}: genesis");
                    inv_entry_hash = Some(f.entry_hash_hex());
                }
            }
            "head" => {
                let h = HeadFields::parse_canonical(msg.as_bytes()).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(h.canonical_bytes(), msg_hex, "{name}: rebuilt head canonical");
                if name == "inv-lock-head-0" {
                    inv_head = Some(h);
                }
            }
            other => panic!("{name}: unknown tag {other}"),
        }
    }
    // Cross-check: the inv-lock head commits to the hash of the inv-lock entry.
    let head = inv_head.expect("inv-lock-head-0 present");
    assert_eq!(head.last_sequence, 0);
    assert_eq!(head.session_id, "inv-lock-1");
    assert_eq!(Some(head.last_entry_hash), inv_entry_hash, "head commits to entry hash");
}

#[test]
fn key_id_sha256_raw_16() {
    let vx = load_json("chain-signing-v1.json");
    let pk = unhex(str_of(&vx["test_key"], "public_key_hex"));
    let pk: [u8; 32] = pk.as_slice().try_into().expect("32-byte public key");
    assert_eq!(key_id_hex(&pk), str_of(&vx["test_key"], "key_id_hex"));
    assert_eq!(str_of(&vx, "key_id_scheme").split(':').next(), Some("sha256-raw-16"));
}

// ---------------------------------------------------------------------------
// Mutation discipline: any single-byte change must be detected.
// ---------------------------------------------------------------------------

#[test]
fn every_single_byte_mutation_of_a_canonical_changes_the_hash() {
    let fx = load_json("fixtures-appendix-a.json");
    for (name, e) in fx["entries"].as_object().unwrap() {
        let canonical = str_of(e, "canonical_utf8").as_bytes().to_vec();
        let expected = str_of(e, "chain_entry_hash");
        assert_eq!(sha256_hex(&canonical), expected);
        for i in 0..canonical.len() {
            let mut m = canonical.clone();
            m[i] ^= 0x01;
            assert_ne!(sha256_hex(&m), expected, "fixture {name}: flipped bit at byte {i} went undetected");
        }
    }
}

#[test]
fn every_field_mutation_changes_canonical_and_hash() {
    let fx = load_json("fixtures-appendix-a.json");
    let base = EntryFields::parse_canonical(str_of(&fx["entries"]["B"], "canonical_utf8").as_bytes()).unwrap();
    let base_hash = base.entry_hash_hex();
    let mutants: Vec<(&str, EntryFields)> = vec![
        ("artifact_hash", EntryFields { artifact_hash: flip_last(&base.artifact_hash), ..base.clone() }),
        ("artifact_hash_alg", EntryFields { artifact_hash_alg: "sha512".into(), ..base.clone() }),
        ("artifact_id", EntryFields { artifact_id: format!("{}x", base.artifact_id), ..base.clone() }),
        ("artifact_schema_version", EntryFields { artifact_schema_version: "2".into(), ..base.clone() }),
        ("artifact_type", EntryFields { artifact_type: "outcome".into(), ..base.clone() }),
        ("monotonic_ns", EntryFields { monotonic_ns: base.monotonic_ns + 1, ..base.clone() }),
        ("previous_entry_hash", EntryFields { previous_entry_hash: flip_last(&base.previous_entry_hash), ..base.clone() }),
        ("sequence", EntryFields { sequence: base.sequence + 1, ..base.clone() }),
        ("session_id", EntryFields { session_id: format!("{}2", base.session_id), ..base.clone() }),
        ("signer_node_id", EntryFields { signer_node_id: base.signer_node_id + 1, ..base.clone() }),
        ("signer_org_id", EntryFields { signer_org_id: "remote".into(), ..base.clone() }),
        ("timestamp_ns", EntryFields { timestamp_ns: base.timestamp_ns - 1, ..base.clone() }),
    ];
    assert_eq!(mutants.len(), 12, "one mutant per canonical field");
    for (field, m) in mutants {
        assert_ne!(m.canonical_bytes(), base.canonical_bytes(), "{field}: canonical unchanged");
        assert_ne!(m.entry_hash_hex(), base_hash, "{field}: hash unchanged");
    }
}

#[test]
fn head_mutations_change_canonical() {
    let fx = load_json("fixtures-appendix-a.json");
    let h = &fx["head"];
    let base = HeadFields {
        session_id: str_of(h, "session_id").to_owned(),
        last_sequence: i64_of(h, "last_sequence"),
        last_entry_hash: str_of(h, "last_entry_hash").to_owned(),
    };
    let b = base.canonical_bytes();
    assert_ne!(HeadFields { last_sequence: base.last_sequence + 1, ..base.clone() }.canonical_bytes(), b);
    assert_ne!(HeadFields { last_entry_hash: flip_last(&base.last_entry_hash), ..base.clone() }.canonical_bytes(), b);
    assert_ne!(HeadFields { session_id: "approval:clab-frr-ospf-frr2".into(), ..base.clone() }.canonical_bytes(), b);
    // And the tag is load-bearing: a head with a different version tag does not parse.
    let tampered = String::from_utf8(b.clone()).unwrap().replace("VIRP-CHAIN-HEAD-v1", "VIRP-CHAIN-HEAD-v2");
    assert!(HeadFields::parse_canonical(tampered.as_bytes()).is_err());
}

#[test]
fn every_public_key_byte_mutation_changes_key_id() {
    let vx = load_json("chain-signing-v1.json");
    let pk: [u8; 32] = unhex(str_of(&vx["test_key"], "public_key_hex")).as_slice().try_into().unwrap();
    let kid = key_id_hex(&pk);
    for i in 0..32 {
        let mut m = pk;
        m[i] ^= 0x80;
        assert_ne!(key_id_hex(&m), kid, "pubkey byte {i} mutation went undetected in key_id");
    }
}

#[test]
fn genesis_depends_on_every_byte_of_session_id_and_prefix() {
    let g = genesis_hash_hex("inv-lock-1");
    assert_ne!(g, genesis_hash_hex("inv-lock-2"));
    assert_ne!(g, genesis_hash_hex("inv-lock-1 "));
    assert_ne!(g, genesis_hash_hex(""));
    // The prefix is part of the hash: a bare sha256 of the session id is NOT the genesis.
    assert_ne!(g, sha256_hex(b"inv-lock-1"));
}

#[test]
fn parser_rejects_non_canonical_encodings() {
    let fx = load_json("fixtures-appendix-a.json");
    let c = str_of(&fx["entries"]["A"], "canonical_utf8").to_owned();
    // Whitespace, reordered keys, leading zeros, a plus sign, trailing bytes.
    assert!(EntryFields::parse_canonical(c.replace(",\"sequence\":0,", ",\"sequence\": 0,").as_bytes()).is_err());
    assert!(EntryFields::parse_canonical(c.replace(",\"sequence\":0,", ",\"sequence\":00,").as_bytes()).is_err());
    assert!(EntryFields::parse_canonical(c.replace(",\"sequence\":0,", ",\"sequence\":+0,").as_bytes()).is_err());
    assert!(EntryFields::parse_canonical(format!("{c}\n").as_bytes()).is_err());
    assert!(EntryFields::parse_canonical(&c.as_bytes()[..c.len() - 1]).is_err());
    assert!(EntryFields::parse_canonical(b"{}").is_err());
    assert!(EntryFields::parse_canonical(&[0xff, 0xfe]).is_err());
}

fn flip_last(hex_digest: &str) -> String {
    let mut s = hex_digest.to_owned();
    let last = s.pop().expect("non-empty");
    s.push(if last == '0' { '1' } else { '0' });
    s
}
