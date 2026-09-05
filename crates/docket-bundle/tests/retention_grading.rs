//! Retention grading: `camera_retention/1` under producer_signature, the
//! `absent_by_declared_policy` citation path, and the declarations listing.
//!
//! The retention body under `tests/fixtures/retention/` is REAL producer
//! output — written and signed by `virp_camera.py retention` on the Spark
//! capture host on 2026-09-05, lifted verbatim from its outbox, with the
//! PUBLIC half of the scratch producer key beside it. Nothing here is
//! hand-rolled: a signature that verifies in these tests verifies over
//! bytes a producer actually made, which is the only proof this crate
//! accepts that its canonicalizer agrees with the producer's.
//!
//! The scratch private key was destroyed after that run. These fixtures can
//! be read and checked; nothing can mint another.

use std::fs;
use std::path::PathBuf;

use docket_bundle::producer::grade_producer_signatures;
use docket_bundle::verify::{
    grade_referenced_artifact_binding, ArtifactStore, NotCarried, ReferencedEntry, ReferencedStore, RetentionEvidence,
    SessionChain, SignerTrust, Status,
};
use docket_bundle::{read_producer_key_file, retention_declarations, sha256_hex, PublicKey};
use serde_json::{json, Value};

const RETENTION_SESSION: &str = "camera-retention:retention-test-0905:2026-09-05";
const CAMERA_SESSION: &str = "camera:retention-test-0905:2026-09-05";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/retention")
        .join(name)
}

fn retention_body_bytes() -> Vec<u8> {
    fs::read(fixture("camera_retention_1.body")).expect("retention fixture")
}

fn scratch_key() -> PublicKey {
    read_producer_key_file(&fixture("producer-retention-test-0905.pub")).expect("scratch producer key")
}

/// A digest the real record declares removed.
fn declared_digest() -> String {
    let body: Value = serde_json::from_slice(&retention_body_bytes()).unwrap();
    body["removed"][0]["sha256"].as_str().unwrap().to_owned()
}

/// Build a session chain over raw body bytes, filed by their true digests.
fn chain_of(session_id: &str, bodies: &[Vec<u8>], store: &mut ArtifactStore) -> SessionChain {
    let mut entries = Vec::new();
    for (i, bytes) in bodies.iter().enumerate() {
        let hash = sha256_hex(bytes);
        store.insert(hash.clone(), bytes.clone());
        entries.push(json!({
            "artifact_hash": hash,
            "artifact_hash_alg": "sha256",
            "artifact_id": format!("test:{session_id}:{i}"),
            "artifact_schema_version": "1",
            "artifact_type": "evidence_item",
            "monotonic_ns": i as u64,
            "previous_entry_hash": "00".repeat(32),
            "sequence": i as i64,
            "session_id": session_id,
            "signer_node_id": 1u32,
            "signer_org_id": "local",
            "timestamp_ns": i as u64,
            "chain_entry_hash": "00".repeat(32),
        }));
    }
    serde_json::from_value(json!({"session_id": session_id, "entries": entries})).unwrap()
}

/// A camera_segment body citing `digest` as its segment. Its own producer
/// signature is irrelevant here — referenced_artifact_binding grades the
/// artifacts a record points at, not the record's signature.
fn citing_segment(digest: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "camera_segment/2",
        "camera_id": "retention-test-0905",
        "segment_seq": 7,
        "segment_sha256": digest,
        "producer_key_id": "c6c25fdc2aefa10338933b2bbd519515",
        "producer_sig": "00".repeat(64),
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// 1. producer_signature covers camera_retention/1
// ---------------------------------------------------------------------------

#[test]
fn a_real_retention_record_verifies_under_its_producer_key() {
    let mut store = ArtifactStore::new();
    let chain = chain_of(RETENTION_SESSION, &[retention_body_bytes()], &mut store);
    let r = grade_producer_signatures(&chain, Some(&store), &[scratch_key()]);
    assert_eq!(r.signature_validity, Status::Verified, "{r:?}");
    assert_eq!(r.trust, SignerTrust::Pinned, "{r:?}");
    assert_eq!(r.claimed_key_ids, vec!["c6c25fdc2aefa10338933b2bbd519515"], "{r:?}");
}

#[test]
fn a_retention_record_without_a_key_is_unverifiable_not_absent() {
    let mut store = ArtifactStore::new();
    let chain = chain_of(RETENTION_SESSION, &[retention_body_bytes()], &mut store);
    let r = grade_producer_signatures(&chain, Some(&store), &[]);
    assert!(
        matches!(r.signature_validity, Status::Unverifiable { .. }),
        "a record this verifier DOES examine, with no key, is an open question: {r:?}"
    );
    assert_eq!(r.trust, SignerTrust::Unestablished, "{r:?}");
}

#[test]
fn a_tampered_retention_record_is_failed() {
    // Flip a declared byte count. The signature covers the canonical body
    // minus producer_sig, so any edit inside `removed[]` breaks it.
    let mut body: Value = serde_json::from_slice(&retention_body_bytes()).unwrap();
    body["removed"][0]["byte_len"] = json!(48);
    let mut store = ArtifactStore::new();
    let chain = chain_of(RETENTION_SESSION, &[serde_json::to_vec(&body).unwrap()], &mut store);
    let r = grade_producer_signatures(&chain, Some(&store), &[scratch_key()]);
    assert!(matches!(r.signature_validity, Status::Failed { .. }), "{r:?}");
    assert_eq!(r.trust, SignerTrust::Mismatch, "{r:?}");
}

#[test]
fn an_unknown_schema_is_absent_and_says_it_was_not_examined() {
    let body = serde_json::to_vec(&json!({"schema": "tacacs_accounting/1", "whatever": true})).unwrap();
    let mut store = ArtifactStore::new();
    let chain = chain_of("something:else:2026-09-05", &[body], &mut store);
    let r = grade_producer_signatures(&chain, Some(&store), &[scratch_key()]);
    assert_eq!(r.signature_validity, Status::Absent, "{r:?}");
    assert!(
        r.detail.contains("schema not examined by this verifier"),
        "an unexamined body must SAY it was unexamined: {r:?}"
    );
    assert!(r.detail.contains("tacacs_accounting/1"), "{r:?}");
    // The load-bearing half: never a pass.
    assert_ne!(r.signature_validity, Status::Verified);
    assert_eq!(r.trust, SignerTrust::Unestablished, "{r:?}");
}

// ---------------------------------------------------------------------------
// 2. absent_by_declared_policy
// ---------------------------------------------------------------------------

/// (camera chain, retention chain, store, referenced store) for a citation
/// the real record declares.
fn declared_setup() -> (SessionChain, SessionChain, ArtifactStore, ReferencedStore, String) {
    let digest = declared_digest();
    let mut store = ArtifactStore::new();
    let cam = chain_of(CAMERA_SESSION, &[citing_segment(&digest)], &mut store);
    let ret = chain_of(RETENTION_SESSION, &[retention_body_bytes()], &mut store);
    let mut referenced = ReferencedStore::new();
    referenced.insert(
        digest.clone(),
        ReferencedEntry::NotCarried(NotCarried::AbsentByDeclaredPolicy {
            retention_sequence: 0,
            retention_session: RETENTION_SESSION.to_owned(),
        }),
    );
    (cam, ret, store, referenced, digest)
}

#[test]
fn a_verified_declaration_is_counted_and_is_still_absent() {
    let (cam, ret, store, referenced, _) = declared_setup();
    let chains = vec![cam.clone(), ret];
    let key = scratch_key();
    let evidence = RetentionEvidence {
        chains: &chains,
        producer_keys: std::slice::from_ref(&key),
    };
    let (status, cov) = grade_referenced_artifact_binding(&cam, Some(&store), Some(&referenced), Some(&evidence));
    assert_eq!(cov.citations, 1);
    assert_eq!(cov.absent, 1, "a declared deletion is still an absence");
    assert_eq!(cov.absent_declared, 1, "and it is counted as declared");
    assert!(cov.declaration_failures.is_empty(), "{cov:?}");
    // NEVER a pass. This is the whole point of the feature.
    assert_eq!(status, Status::Absent, "{status:?}");
    assert!(cov.detail().contains("1 declared"), "{}", cov.detail());
    assert!(cov.detail().contains("0 undeclared"), "{}", cov.detail());
}

#[test]
fn a_declaration_is_not_honoured_without_a_producer_key() {
    let (cam, ret, store, referenced, _) = declared_setup();
    let chains = vec![cam.clone(), ret];
    let evidence = RetentionEvidence {
        chains: &chains,
        producer_keys: &[],
    };
    let (status, cov) = grade_referenced_artifact_binding(&cam, Some(&store), Some(&referenced), Some(&evidence));
    assert_eq!(cov.absent, 1);
    assert_eq!(cov.absent_declared, 0, "an unverified signature is not a declaration");
    assert_eq!(cov.declaration_failures.len(), 1, "{cov:?}");
    assert!(cov.declaration_failures[0].why.contains("no producer key"), "{cov:?}");
    assert_eq!(status, Status::Absent);
}

#[test]
fn a_declaration_that_does_not_name_the_digest_is_not_honoured() {
    let (cam_ignored, ret, mut store, _, _) = declared_setup();
    let _ = cam_ignored;
    // A citation for a digest the record does NOT list.
    let other = "11".repeat(32);
    let cam = chain_of(CAMERA_SESSION, &[citing_segment(&other)], &mut store);
    let mut referenced = ReferencedStore::new();
    referenced.insert(
        other.clone(),
        ReferencedEntry::NotCarried(NotCarried::AbsentByDeclaredPolicy {
            retention_sequence: 0,
            retention_session: RETENTION_SESSION.to_owned(),
        }),
    );
    let chains = vec![cam.clone(), ret];
    let key = scratch_key();
    let evidence = RetentionEvidence {
        chains: &chains,
        producer_keys: std::slice::from_ref(&key),
    };
    let (status, cov) = grade_referenced_artifact_binding(&cam, Some(&store), Some(&referenced), Some(&evidence));
    assert_eq!(cov.absent_declared, 0);
    assert_eq!(cov.declaration_failures.len(), 1, "{cov:?}");
    assert!(cov.declaration_failures[0].why.contains("does not list"), "{cov:?}");
    assert_eq!(status, Status::Absent);
}

#[test]
fn a_declaration_naming_a_session_the_bundle_lacks_is_not_honoured() {
    let (cam, _ret, store, _, digest) = declared_setup();
    let mut referenced = ReferencedStore::new();
    referenced.insert(
        digest,
        ReferencedEntry::NotCarried(NotCarried::AbsentByDeclaredPolicy {
            retention_sequence: 0,
            retention_session: "camera-retention:not-in-this-bundle:2026-09-05".to_owned(),
        }),
    );
    let chains = vec![cam.clone()];
    let key = scratch_key();
    let evidence = RetentionEvidence {
        chains: &chains,
        producer_keys: std::slice::from_ref(&key),
    };
    let (status, cov) = grade_referenced_artifact_binding(&cam, Some(&store), Some(&referenced), Some(&evidence));
    assert_eq!(cov.absent_declared, 0);
    assert!(
        cov.declaration_failures[0].why.contains("carries no session"),
        "{cov:?}"
    );
    assert_eq!(status, Status::Absent);
}

#[test]
fn a_declared_absence_is_never_unverifiable() {
    // INACCESSIBLE leaves the question open; a declaration answers it.
    let d = NotCarried::AbsentByDeclaredPolicy {
        retention_sequence: 0,
        retention_session: RETENTION_SESSION.to_owned(),
    };
    assert!(!d.is_unverifiable());
    assert!(
        d.label().contains("declared by retention record seq 0"),
        "{}",
        d.label()
    );
}

/// §5: retention_session and retention_sequence are a REQUIRED PAIR. A
/// citation carrying one without the other is MALFORMED — the exporter
/// wrote a declaration it cannot substantiate — not merely unresolved, and
/// it grades ABSENT naming the field that is missing. Never UNVERIFIABLE:
/// this is a defect in the manifest, not an open question about evidence.
#[test]
fn a_declaration_missing_its_session_grades_absent_naming_the_field() {
    let (cam, ret, store, _, digest) = declared_setup();
    let mut referenced = ReferencedStore::new();
    referenced.insert(
        digest,
        ReferencedEntry::NotCarried(NotCarried::from_manifest(
            Some("absent_by_declared_policy"),
            Some(0),
            None, // the session is missing
        )),
    );
    let chains = vec![cam.clone(), ret];
    let key = scratch_key();
    let evidence = RetentionEvidence {
        chains: &chains,
        producer_keys: std::slice::from_ref(&key),
    };
    let (status, cov) = grade_referenced_artifact_binding(&cam, Some(&store), Some(&referenced), Some(&evidence));
    assert_eq!(
        status,
        Status::Absent,
        "malformed is a definite absence, not an open question"
    );
    assert_eq!(cov.absent, 1);
    assert_eq!(cov.inaccessible, 0, "must NOT land in the never-looked-at bucket");
    assert_eq!(cov.absent_declared, 0, "a malformed declaration declares nothing");
    assert_eq!(cov.declaration_failures.len(), 1, "{cov:?}");
    assert!(
        cov.declaration_failures[0].why.contains("retention_session"),
        "the missing field must be named: {cov:?}"
    );
}

#[test]
fn a_declaration_missing_its_sequence_grades_absent_naming_the_field() {
    let n = NotCarried::from_manifest(Some("absent_by_declared_policy"), None, Some(RETENTION_SESSION));
    assert!(!n.is_unverifiable(), "malformed is ABSENT-family, never UNVERIFIABLE");
    assert!(n.label().contains("retention_sequence"), "{}", n.label());
}

#[test]
fn a_declaration_missing_both_fields_names_both() {
    let n = NotCarried::from_manifest(Some("absent_by_declared_policy"), None, None);
    assert!(!n.is_unverifiable());
    assert!(n.label().contains("retention_session"), "{}", n.label());
    assert!(n.label().contains("retention_sequence"), "{}", n.label());
}

/// A reason this verifier does not recognise is still UNVERIFIABLE: it may
/// name a look that never happened, and guessing which known absence it is
/// would be the collapse the enum exists to prevent. Distinct from a
/// MALFORMED declaration, which is a reason we DO know, written wrongly.
#[test]
fn an_unrecognised_reason_still_leaves_the_question_open() {
    let n = NotCarried::from_manifest(Some("some_future_reason"), None, None);
    assert!(matches!(n, NotCarried::Other(_)), "{n:?}");
    assert!(n.is_unverifiable(), "an unknown reason is not a known absence");
    // And a malformed declaration is NOT folded in with it.
    let m = NotCarried::from_manifest(Some("absent_by_declared_policy"), None, None);
    assert!(matches!(m, NotCarried::MalformedDeclaration { .. }), "{m:?}");
    assert!(!m.is_unverifiable());
}

// ---------------------------------------------------------------------------
// 3. declarations are listed, never counted as capture
// ---------------------------------------------------------------------------

#[test]
fn retention_records_are_listed_with_policy_and_count() {
    let mut store = ArtifactStore::new();
    let chain = chain_of(RETENTION_SESSION, &[retention_body_bytes()], &mut store);
    let decls = retention_declarations(&chain, Some(&store));
    assert_eq!(decls.len(), 1, "{decls:?}");
    let d = &decls[0];
    assert_eq!(d.sequence, 0);
    assert_eq!(d.camera_id.as_deref(), Some("retention-test-0905"));
    assert_eq!(d.tier.as_deref(), Some("capture-host"));
    assert_eq!(d.policy_days, Some(30));
    assert_eq!(d.removed_count, Some(6));
}

#[test]
fn a_retention_record_is_not_a_segment_for_coverage() {
    use docket_bundle::grade_capture_completeness;
    let mut store = ArtifactStore::new();
    let chain = chain_of(RETENTION_SESSION, &[retention_body_bytes()], &mut store);
    let cc = grade_capture_completeness(&chain, Some(&store));
    assert_eq!(
        cc.camera_records, 0,
        "a deletion declaration must never be counted as capture: {cc:?}"
    );
    // And a camera session carrying no retention record lists none.
    let mut s2 = ArtifactStore::new();
    let seg = chain_of(CAMERA_SESSION, &[citing_segment(&declared_digest())], &mut s2);
    assert!(retention_declarations(&seg, Some(&s2)).is_empty());
}
