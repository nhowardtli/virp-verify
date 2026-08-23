//! Carried artifact bodies (`manifest.artifacts`): the bundle can carry the
//! exact bytes each entry's `artifact_hash` commits to, and the verifier
//! grades `artifact_binding` per session — VERIFIED only by recomputing
//! SHA-256, FAILED on mismatch, honest per-entry coverage, and no grading at
//! all (key absent from the report) for hash-only bundles.

mod common;

use std::path::{Path, PathBuf};

use docket_bundle::bundle::{Bundle, BundleError};
use docket_bundle::{sha256_hex, ChainEntry, ChainHead, EntryFields, HeadFields, SessionChain, Status, Verdict};

/// Bodies for the synthetic session. One is deliberately binary and one
/// carries a redaction marker — the store is bytes, not text.
const BODIES: [&[u8]; 3] = [
    b"pve-lab$ qm list\n 100 DC01 stopped\n",
    b"\x01\x01\x02!\x0abinary frame prefix\xffthen text",
    b"show running-config\npassword [REDACTED]\n",
];

/// A three-entry unsigned session whose `artifact_hash` values really are
/// the SHA-256 of `BODIES` — carried bodies can therefore hash-match.
fn session_with_real_hashes(sid: &str) -> SessionChain {
    let mut entries = Vec::new();
    let mut prev = docket_bundle::genesis_hash_hex(sid);
    for (i, body) in BODIES.iter().enumerate() {
        let fields = EntryFields {
            artifact_hash: sha256_hex(body),
            artifact_hash_alg: "sha256".into(),
            artifact_id: format!("obs:artifacts-test:{i}"),
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
            chain_hmac: None,
            signature: None,
        });
        prev = h;
    }
    SessionChain {
        session_id: sid.into(),
        head: Some(ChainHead {
            fields: HeadFields {
                session_id: sid.into(),
                last_sequence: BODIES.len() as i64 - 1,
                last_entry_hash: prev,
            },
            canonical_utf8: None,
            head_hmac: None,
            signature: None,
        }),
        entries,
    }
}

/// Write a bundle directory carrying `bodies` (as `artifacts/<hash>` files
/// named in the manifest); `bodies` may cover only some entries.
fn write_bundle(name: &str, chain: &SessionChain, bodies: Option<&[(&str, &[u8])]>) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("artifacts-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    std::fs::write(dir.join("sessions/s.json"), serde_json::to_vec_pretty(chain).unwrap()).unwrap();
    let mut manifest = serde_json::json!({
        "docket_bundle_version": "docket-bundle/0.1",
        "chain_format": "v1",
        "producer": "artifacts.rs test",
        "sessions": [{"session_id": chain.session_id, "path": "sessions/s.json"}],
    });
    if let Some(bodies) = bodies {
        std::fs::create_dir_all(dir.join("artifacts")).unwrap();
        let mut list = Vec::new();
        for (hash, bytes) in bodies {
            std::fs::write(dir.join("artifacts").join(hash), bytes).unwrap();
            list.push(serde_json::json!({"artifact_hash": hash, "path": format!("artifacts/{hash}")}));
        }
        manifest["artifacts"] = serde_json::Value::Array(list);
    }
    std::fs::write(dir.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    dir
}

fn edit_artifacts(dir: &Path, f: impl FnOnce(&mut Vec<serde_json::Value>)) {
    let p = dir.join("manifest.json");
    let mut m: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    let list = m["artifacts"].as_array_mut().expect("manifest has artifacts");
    f(list);
    std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

fn body_entries(chain: &SessionChain) -> Vec<(String, &'static [u8])> {
    chain
        .entries
        .iter()
        .zip(BODIES)
        .map(|(e, b)| (e.fields.artifact_hash.clone(), b))
        .collect()
}

#[test]
fn carried_bodies_verify_and_do_not_change_the_verdict() {
    let chain = session_with_real_hashes("artifacts-1");
    let owned = body_entries(&chain);
    let bodies: Vec<(&str, &[u8])> = owned.iter().map(|(h, b)| (h.as_str(), *b)).collect();

    let with = write_bundle("full", &chain, Some(&bodies));
    let without = write_bundle("hashonly", &chain, None);

    let rw = Bundle::read_dir(&with).unwrap().verify();
    let ro = Bundle::read_dir(&without).unwrap().verify();

    // Bodies change what can be SHOWN, never what the chain verdict is.
    assert_eq!(rw.verdict, ro.verdict);
    assert_eq!(rw.sessions[0].report, ro.sessions[0].report);
    assert_eq!(rw.verdict, Verdict::ConsistentUnauthenticated);

    let s = &rw.sessions[0];
    assert_eq!(s.artifact_binding, Some(Status::Verified));
    let c = s.artifact_coverage.as_ref().unwrap();
    assert_eq!((c.entry_count, c.entries_with_body), (3, 3));
    assert!(c.hash_only_sequences.is_empty());

    // The exact bytes round-trip through the store.
    let bundle = Bundle::read_dir(&with).unwrap();
    let store = bundle.artifacts.as_ref().unwrap();
    for (h, b) in &bodies {
        assert_eq!(store.get(*h).unwrap().as_slice(), *b);
    }
}

#[test]
fn partial_coverage_is_reported_per_entry_never_implied() {
    let chain = session_with_real_hashes("artifacts-2");
    let owned = body_entries(&chain);
    // Carry only the middle entry's body.
    let bodies: Vec<(&str, &[u8])> = vec![(owned[1].0.as_str(), owned[1].1)];
    let dir = write_bundle("partial", &chain, Some(&bodies));
    let report = Bundle::read_dir(&dir).unwrap().verify();
    let s = &report.sessions[0];
    assert_eq!(s.artifact_binding, Some(Status::Verified));
    let c = s.artifact_coverage.as_ref().unwrap();
    assert_eq!((c.entry_count, c.entries_with_body), (3, 1));
    assert_eq!(c.hash_only_sequences, vec![0, 2]);
    assert!(c.detail().contains("1/3 entries have carried bodies"));
    assert!(c.detail().contains("hash-only sequences: 0, 2"));
}

#[test]
fn tampered_body_fails_the_bundle_with_the_sequence_named() {
    let chain = session_with_real_hashes("artifacts-3");
    let owned = body_entries(&chain);
    let tampered = b"pve-lab$ qm list\n 100 DC01 RUNNING\n"; // not what was signed
    let bodies: Vec<(&str, &[u8])> = vec![(owned[0].0.as_str(), tampered), (owned[1].0.as_str(), owned[1].1)];
    let dir = write_bundle("tampered", &chain, Some(&bodies));
    let report = Bundle::read_dir(&dir).unwrap().verify();
    let s = &report.sessions[0];
    match &s.artifact_binding {
        Some(Status::Failed { detail }) => {
            assert!(detail.contains("sequence 0"), "{detail}");
            assert!(detail.contains("does not hash to its artifact_hash"), "{detail}");
        }
        other => panic!("expected failed artifact_binding, got {other:?}"),
    }
    // The chain itself still walks clean; the BUNDLE fails (weakest link).
    assert_ne!(s.report.verdict, Verdict::Failed);
    assert_eq!(report.verdict, Verdict::Failed);
}

#[test]
fn hash_only_bundle_reports_no_artifact_binding_at_all() {
    let chain = session_with_real_hashes("artifacts-4");
    let dir = write_bundle("none", &chain, None);
    let bundle = Bundle::read_dir(&dir).unwrap();
    assert!(bundle.artifacts.is_none());
    let report = bundle.verify();
    assert_eq!(report.sessions[0].artifact_binding, None);
    assert_eq!(report.sessions[0].artifact_coverage, None);
    // And the serialized report does not even carry the keys — an old-style
    // bundle's JSON is unchanged by this feature.
    let json = docket_bundle::report_to_json_pretty(&report).unwrap();
    assert!(!json.contains("artifact_binding"), "{json}");
    assert!(!json.contains("artifact_coverage"), "{json}");
}

#[test]
fn unreferenced_body_is_unreadable() {
    let chain = session_with_real_hashes("artifacts-5");
    let orphan_bytes: &[u8] = b"content no entry commits to";
    let orphan_hash = sha256_hex(orphan_bytes);
    let bodies: Vec<(&str, &[u8])> = vec![(orphan_hash.as_str(), orphan_bytes)];
    let dir = write_bundle("orphan", &chain, Some(&bodies));
    match Bundle::read_dir(&dir) {
        Err(BundleError::UnreferencedArtifact(h)) => assert_eq!(h, orphan_hash),
        other => panic!("expected UnreferencedArtifact, got {other:?}"),
    }
}

#[test]
fn duplicate_and_malformed_artifact_rows_are_unreadable() {
    let chain = session_with_real_hashes("artifacts-6");
    let owned = body_entries(&chain);
    let bodies: Vec<(&str, &[u8])> = vec![(owned[0].0.as_str(), owned[0].1)];

    let dup = write_bundle("dup", &chain, Some(&bodies));
    edit_artifacts(&dup, |list| {
        let row = list[0].clone();
        list.push(row);
    });
    assert!(matches!(Bundle::read_dir(&dup), Err(BundleError::DuplicateArtifact(_))));

    let bad = write_bundle("badhash", &chain, Some(&bodies));
    edit_artifacts(&bad, |list| list[0]["artifact_hash"] = "zz".into());
    assert!(matches!(
        Bundle::read_dir(&bad),
        Err(BundleError::MalformedArtifactHash(_))
    ));

    let escape = write_bundle("escape", &chain, Some(&bodies));
    edit_artifacts(&escape, |list| list[0]["path"] = "../outside".into());
    assert!(matches!(Bundle::read_dir(&escape), Err(BundleError::UnsafePath(_))));
}

#[test]
fn unsupported_hash_alg_with_a_carried_body_is_unverifiable() {
    let mut chain = session_with_real_hashes("artifacts-7");
    // Rebuild entry 0 with a foreign alg; keep the chain internally valid.
    chain.entries[0].fields.artifact_hash_alg = "sha512".into();
    chain.entries[0].chain_entry_hash = chain.entries[0].fields.entry_hash_hex();
    let mut prev = chain.entries[0].chain_entry_hash.clone();
    for i in 1..chain.entries.len() {
        chain.entries[i].fields.previous_entry_hash = prev.clone();
        chain.entries[i].chain_entry_hash = chain.entries[i].fields.entry_hash_hex();
        prev = chain.entries[i].chain_entry_hash.clone();
    }
    chain.head.as_mut().unwrap().fields.last_entry_hash = prev;

    let owned = body_entries(&chain);
    let bodies: Vec<(&str, &[u8])> = vec![(owned[0].0.as_str(), owned[0].1)];
    let dir = write_bundle("alg", &chain, Some(&bodies));
    let report = Bundle::read_dir(&dir).unwrap().verify();
    match &report.sessions[0].artifact_binding {
        Some(Status::Unverifiable { reason }) => assert!(reason.contains("sha512"), "{reason}"),
        other => panic!("expected unverifiable artifact_binding, got {other:?}"),
    }
    assert_ne!(report.verdict, Verdict::Failed);
}

#[test]
fn failed_status_serializes_failure_key_and_round_trips() {
    let s = Status::failed("something checked and wrong");
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(json, r#"{"status":"failed","failure":"something checked and wrong"}"#);
    let back: Status = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}
