//! The witness repository's published golden vectors, run against Docket's
//! own RFC 9162 implementation.
//!
//! This is the whole reason `docket-bundle::witness` may re-implement the
//! proof algorithms rather than call the witness's crate: the two sides are
//! written independently and held together by a third artifact neither of
//! them produced at test time. A canonical-byte disagreement, a leaf-prefix
//! slip, an off-by-one in the `fn`/`sn` walk — each shows up here as a
//! failing vector rather than as two tools agreeing on the wrong answer.
//!
//! `tests/vectors/witness-v1.json` is a verbatim copy of
//! `~/virp-witness/tests/vectors/witness-v1.json`. Re-copy it when the
//! witness publishes a new set; never hand-edit it.

use docket_bundle::witness::{leaf_hash, verify_consistency, verify_inclusion, Sth, WitnessLeaf};
use docket_bundle::PublicKey;
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/witness-v1.json"))
        .expect("witness golden vectors");
    serde_json::from_str(&text).expect("witness golden vectors parse")
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex_decode(s, &mut out);
    out
}

fn hex_decode(s: &str, out: &mut [u8]) {
    assert_eq!(s.len(), out.len() * 2, "hex width");
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|x| x.as_str().expect("hex string").to_owned())
        .collect()
}

/// The leaf data and leaf hash Docket builds must be byte-identical to the
/// ones the witness published. If this drifts, every proof below is checking
/// arithmetic over the wrong bytes.
#[test]
fn leaf_canonical_bytes_and_hash_match_the_vectors() {
    let v = vectors();
    let leaves = v["leaves"].as_array().expect("leaves");
    assert_eq!(leaves.len(), 8, "the published set is 8 leaves");
    for l in leaves {
        let leaf = WitnessLeaf {
            chain_id: l["chain_id"].as_str().unwrap().to_owned(),
            sequence: l["sequence"].as_u64().unwrap(),
            head_hash: l["head_hash"].as_str().unwrap().to_owned(),
            key_id: l["key_id"].as_str().unwrap().to_owned(),
            signature: l["signature_hex"].as_str().unwrap().to_owned(),
            timestamp: l["timestamp"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            String::from_utf8(leaf.leaf_data()).unwrap(),
            l["leaf_data_utf8"].as_str().unwrap(),
            "leaf {} data",
            l["leaf_index"]
        );
        assert_eq!(
            hex::encode(leaf.leaf_hash()),
            l["leaf_hash"].as_str().unwrap(),
            "leaf {} hash",
            l["leaf_index"]
        );
        assert_eq!(
            hex::encode(leaf_hash(&leaf.leaf_data())),
            l["leaf_hash"].as_str().unwrap()
        );
    }
}

/// The submitter's own signature over each published leaf, under the
/// published submitter key. Reported by `grade_witness`, so it has to be
/// right even though it never moves a grade.
#[test]
fn submitter_signatures_verify_under_the_published_submitter_key() {
    let v = vectors();
    let key = PublicKey::from_hex(v["submitter_key"]["public_key_hex"].as_str().unwrap()).expect("submitter key");
    assert_eq!(key.key_id(), v["submitter_key"]["key_id_hex"].as_str().unwrap());
    for l in v["leaves"].as_array().unwrap() {
        let leaf = WitnessLeaf {
            chain_id: l["chain_id"].as_str().unwrap().to_owned(),
            sequence: l["sequence"].as_u64().unwrap(),
            head_hash: l["head_hash"].as_str().unwrap().to_owned(),
            key_id: l["key_id"].as_str().unwrap().to_owned(),
            signature: l["signature_hex"].as_str().unwrap().to_owned(),
            timestamp: l["timestamp"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            String::from_utf8(leaf.submitter_signing_bytes()).unwrap(),
            l["leaf_signing_bytes_utf8"].as_str().unwrap(),
            "leaf {} signing bytes",
            l["leaf_index"]
        );
        assert!(
            leaf.submitter_signature_verifies(&key),
            "leaf {} submitter signature",
            l["leaf_index"]
        );
    }
}

/// All 36 published inclusion proofs, every (leaf_index, tree_size) pair.
#[test]
fn every_published_inclusion_proof_recomputes() {
    let v = vectors();
    let proofs = v["inclusion_proofs"].as_array().expect("inclusion_proofs");
    assert_eq!(proofs.len(), 36, "the published set is 36 inclusion proofs");
    for p in proofs {
        let leaf = hex32(p["leaf_hash"].as_str().unwrap());
        let got = verify_inclusion(
            &leaf,
            p["leaf_index"].as_u64().unwrap(),
            p["tree_size"].as_u64().unwrap(),
            &strings(&p["proof"]),
            p["root_hash"].as_str().unwrap(),
        );
        assert!(
            got.is_ok(),
            "leaf {} in tree {}: {:?}",
            p["leaf_index"],
            p["tree_size"],
            got.err()
        );
    }
}

/// A proof that recomputes must stop recomputing when anything in it moves.
/// One flipped bit in one audit-path node is the `failed` fixture's shape,
/// and it must be caught for every proof that has a path at all.
#[test]
fn a_flipped_audit_path_node_is_refused() {
    let v = vectors();
    let mut checked = 0;
    for p in v["inclusion_proofs"].as_array().unwrap() {
        let mut path = strings(&p["proof"]);
        if path.is_empty() {
            continue;
        }
        // Flip the low nibble of the first node.
        let first = path[0].clone();
        let last = first.chars().last().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        path[0] = format!("{}{}", &first[..first.len() - 1], flipped);
        let leaf = hex32(p["leaf_hash"].as_str().unwrap());
        assert!(
            verify_inclusion(
                &leaf,
                p["leaf_index"].as_u64().unwrap(),
                p["tree_size"].as_u64().unwrap(),
                &path,
                p["root_hash"].as_str().unwrap(),
            )
            .is_err(),
            "a flipped node in leaf {}'s proof still recomputed",
            p["leaf_index"]
        );
        checked += 1;
    }
    assert!(
        checked >= 20,
        "expected many proofs with a non-empty path, got {checked}"
    );
}

/// A proof for the wrong leaf index must not recompute either — the tampering
/// that moves an index rather than a hash.
#[test]
fn a_proof_replayed_at_the_wrong_index_is_refused() {
    let v = vectors();
    let mut checked = 0;
    for p in v["inclusion_proofs"].as_array().unwrap() {
        let index = p["leaf_index"].as_u64().unwrap();
        let size = p["tree_size"].as_u64().unwrap();
        if size < 2 {
            continue;
        }
        let wrong = if index == 0 { 1 } else { index - 1 };
        let leaf = hex32(p["leaf_hash"].as_str().unwrap());
        assert!(
            verify_inclusion(
                &leaf,
                wrong,
                size,
                &strings(&p["proof"]),
                p["root_hash"].as_str().unwrap()
            )
            .is_err(),
            "leaf {index}'s proof recomputed at index {wrong} in tree {size}"
        );
        checked += 1;
    }
    assert!(checked >= 20, "expected many multi-leaf proofs, got {checked}");
}

/// All 36 published consistency proofs, every (first, second) pair.
#[test]
fn every_published_consistency_proof_holds() {
    let v = vectors();
    let proofs = v["consistency_proofs"].as_array().expect("consistency_proofs");
    assert_eq!(proofs.len(), 36, "the published set is 36 consistency proofs");
    for p in proofs {
        let got = verify_consistency(
            p["first"].as_u64().unwrap(),
            p["second"].as_u64().unwrap(),
            &strings(&p["proof"]),
            p["first_root"].as_str().unwrap(),
            p["second_root"].as_str().unwrap(),
        );
        assert!(
            got.is_ok(),
            "consistency {} -> {}: {:?}",
            p["first"],
            p["second"],
            got.err()
        );
    }
}

/// A consistency proof presented against a root the log never had is the
/// "the witness rewrote its own history" alarm.
#[test]
fn a_consistency_proof_to_the_wrong_root_is_refused() {
    let v = vectors();
    // Indexed BY tree size: element n is the root over the first n leaves,
    // so element 0 is the empty-tree root.
    let roots = strings(&v["roots_by_tree_size"]);
    let mut checked = 0;
    for p in v["consistency_proofs"].as_array().unwrap() {
        let first = p["first"].as_u64().unwrap();
        let second = p["second"].as_u64().unwrap();
        if first == second {
            continue;
        }
        // Any published root that is not this pair's second root.
        let other = roots
            .iter()
            .find(|r| r.as_str() != p["second_root"].as_str().unwrap())
            .expect("another root");
        assert!(
            verify_consistency(
                first,
                second,
                &strings(&p["proof"]),
                p["first_root"].as_str().unwrap(),
                other
            )
            .is_err(),
            "consistency {first} -> {second} held against a root the log never had at that size"
        );
        checked += 1;
    }
    assert!(checked >= 20, "expected many growing pairs, got {checked}");
}

/// Every published signed tree head, under the published witness key: the
/// canonical bytes, the domain tag and the Ed25519 all at once.
#[test]
fn every_published_tree_head_verifies_under_the_published_witness_key() {
    let v = vectors();
    let key = PublicKey::from_hex(v["witness_key"]["public_key_hex"].as_str().unwrap()).expect("witness key");
    assert_eq!(key.key_id(), v["witness_key"]["key_id_hex"].as_str().unwrap());
    let heads = v["signed_tree_heads"].as_array().expect("signed_tree_heads");
    assert_eq!(heads.len(), 8);
    for h in heads {
        let sth = Sth {
            tree_size: h["tree_size"].as_u64().unwrap(),
            root_hash: h["root_hash"].as_str().unwrap().to_owned(),
            timestamp: h["timestamp"].as_str().unwrap().to_owned(),
            signature: h["signature"].as_str().unwrap().to_owned(),
        };
        assert_eq!(
            String::from_utf8(sth.signing_bytes()).unwrap(),
            h["signing_bytes_utf8"].as_str().unwrap(),
            "tree {} signing bytes",
            h["tree_size"]
        );
        assert!(sth.verify_under(&key), "tree {} signature", h["tree_size"]);
    }
}

/// A tree head must not verify under a key that is not the witness's — the
/// case `--witness-key` exists to make visible.
#[test]
fn a_tree_head_does_not_verify_under_a_different_key() {
    let v = vectors();
    let other = PublicKey::from_hex(v["submitter_key"]["public_key_hex"].as_str().unwrap()).expect("submitter key");
    for h in v["signed_tree_heads"].as_array().unwrap() {
        let sth = Sth {
            tree_size: h["tree_size"].as_u64().unwrap(),
            root_hash: h["root_hash"].as_str().unwrap().to_owned(),
            timestamp: h["timestamp"].as_str().unwrap().to_owned(),
            signature: h["signature"].as_str().unwrap().to_owned(),
        };
        assert!(
            !sth.verify_under(&other),
            "tree {} verified under the SUBMITTER's key",
            h["tree_size"]
        );
    }
}

/// The empty-tree root the RFC fixes as `SHA-256("")`, and the published
/// per-size roots, recomputed from the published leaf hashes.
#[test]
fn published_roots_recompute_from_the_published_leaves() {
    use docket_bundle::witness::node_hash;

    fn split(n: usize) -> usize {
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        k
    }
    fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves.len() {
            0 => docket_bundle::sha256(b""),
            1 => leaves[0],
            n => {
                let k = split(n);
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    let v = vectors();
    assert_eq!(
        hex::encode(docket_bundle::sha256(b"")),
        v["empty_tree_root"].as_str().unwrap()
    );
    let hashes: Vec<[u8; 32]> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| hex32(l["leaf_hash"].as_str().unwrap()))
        .collect();
    let roots = strings(&v["roots_by_tree_size"]);
    assert_eq!(roots.len(), hashes.len() + 1, "one root per tree size, 0 included");
    for (n, root) in roots.iter().enumerate() {
        assert_eq!(hex::encode(mth(&hashes[..n])), *root, "root at tree_size {n}");
    }
}
