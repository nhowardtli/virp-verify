//! The D-0 seal as an anchor: recompute its Merkle root over all 350 listed
//! sessions, and anchor the Appendix A head against it.

mod common;

use common::*;
use docket_bundle::{HeadFields, Seal, Status};

fn seal() -> Seal {
    Seal::from_slice(&load_bytes("seal-2026-08.json")).expect("seal parses")
}

#[test]
fn seal_parses_and_identifies_itself() {
    let s = seal();
    assert_eq!(s.seal_version, "virp-seal/1");
    assert_eq!(s.sessions.len(), 350);
    assert_eq!(s.merkle.leaf_count, 350);
    assert!(s.seal_public_key.starts_with("minisign:"));
    assert!(s
        .residual_disclosure
        .contains("cannot prove the absence of alteration prior to the seal date"));
}

#[test]
fn seal_merkle_root_reproduces_over_all_350_sessions() {
    let s = seal();
    assert_eq!(s.recompute_merkle_root().as_deref(), Some(s.merkle.root.as_str()));
    assert_eq!(
        s.merkle.root,
        "6dbd97eb098a13ef65f3b19975ad3807ef98b7c80908d1312ede24b3b265d76f"
    );
    assert_eq!(s.consistency(), Status::Verified);
}

#[test]
fn seal_merkle_root_detects_any_single_session_change() {
    let base = seal();
    for i in [0usize, 1, 174, 348, 349] {
        let mut s = base.clone();
        s.sessions[i].entry_count += 1;
        assert!(s.consistency().is_failed(), "entry_count change at {i} undetected");
        let mut s = base.clone();
        let mut h = s.sessions[i].head_hash.clone();
        h.replace_range(63..64, if &h[63..] == "0" { "1" } else { "0" });
        s.sessions[i].head_hash = h;
        assert!(s.consistency().is_failed(), "head_hash change at {i} undetected");
    }
    // Dropping a session changes leaf_count and the root.
    let mut s = base.clone();
    s.sessions.pop();
    assert!(s.consistency().is_failed());
    s.merkle.leaf_count -= 1;
    assert!(s.consistency().is_failed());
    // Reordering two sessions breaks the ascending rule.
    let mut s = base.clone();
    s.sessions.swap(10, 11);
    assert!(s.consistency().is_failed());
}

#[test]
fn appendix_a_head_anchors_to_the_seal() {
    // The Appendix A head record (approval:clab-frr-ospf-frr1, seq 272) is
    // exactly the head the seal attests for that session (273 entries).
    let fx = load_json("fixtures-appendix-a.json");
    let h = &fx["head"];
    let head = HeadFields {
        session_id: str_of(h, "session_id").to_owned(),
        last_sequence: i64_of(h, "last_sequence"),
        last_entry_hash: str_of(h, "last_entry_hash").to_owned(),
    };
    let s = seal();
    let listed = s.session(&head.session_id).expect("session in seal");
    assert_eq!(listed.entry_count, 273);
    assert_eq!(
        s.anchor(&head.session_id, head.last_sequence, &head.last_entry_hash),
        Status::Verified
    );
    // A different head for the same session is a failure, not a shrug.
    let mut other = head.last_entry_hash.clone();
    other.replace_range(0..1, "f");
    assert!(s.anchor(&head.session_id, head.last_sequence, &other).is_failed());
    assert!(s
        .anchor(&head.session_id, head.last_sequence - 1, &head.last_entry_hash)
        .is_failed());
    // A session the seal never saw is Absent (post-seal sessions are expected).
    assert_eq!(s.anchor("inv-lock-1", 0, &head.last_entry_hash), Status::Absent);
}

#[test]
fn in_flight_session_that_grew_is_unverifiable_not_failed() {
    let s = seal();
    let listed = s.session("approval:clab-frr-ospf-frr1").unwrap();
    assert!(listed.in_flight);
    // Same session, more entries than the seal saw: the seal covers a prefix.
    let r = s.anchor("approval:clab-frr-ospf-frr1", 300, &"0".repeat(64));
    assert!(matches!(r, Status::Unverifiable { .. }), "{r:?}");
    // Fewer entries than the seal saw is a failure (a truncated chain).
    assert!(s
        .anchor("approval:clab-frr-ospf-frr1", 100, &"0".repeat(64))
        .is_failed());
}

#[test]
fn wrong_seal_version_is_rejected() {
    let text = String::from_utf8(load_bytes("seal-2026-08.json"))
        .unwrap()
        .replace("\"virp-seal/1\"", "\"virp-seal/2\"");
    assert!(Seal::from_slice(text.as_bytes()).is_err());
}
