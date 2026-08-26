//! Hostile-input regression tests at the binary boundary.
//!
//! `tests/hostile.rs` in `docket-bundle` proves the library functions are
//! total. This file proves the thing a stranger actually runs never dies:
//! every bundle here is input no honest producer emits, and every one of
//! them must produce a verdict and one of the documented exit codes.
//!
//! Exit 101 is the assertion that matters. It is what a Rust panic produces,
//! it is not in the documented set (0, 1, 2, 3, 4), and it comes with no
//! report at all — the "prove this yourself" promise replaced by "the tool
//! broke, take my word for it".
//!
//! Bundles are built here rather than checked in, so the integer boundaries
//! are visible as boundaries instead of buried in fixture JSON.

use std::path::{Path, PathBuf};
use std::process::Command;

use docket_bundle::{genesis_hash_hex, sha256_hex, EntryFields};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Run {
    /// The invariant every test in this file shares.
    fn never_crashed(&self, what: &str) -> &Run {
        assert_ne!(
            self.code, 101,
            "{what}: the verifier PANICKED (exit 101)\nstderr: {}",
            self.err
        );
        assert!(
            !self.err.contains("panicked"),
            "{what}: panic message on stderr\n{}",
            self.err
        );
        assert!(
            matches!(self.code, 0..=4),
            "{what}: exit {} is not one of the documented codes 0-4\nstderr: {}",
            self.code,
            self.err
        );
        self
    }
}

fn run(dir: &Path, args: &[&str]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_virp-verify"));
    cmd.args(args).arg(dir);
    let out = cmd.output().expect("run virp-verify");
    Run {
        code: out.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&out.stdout).into_owned(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A fresh scratch bundle root under cargo's target tmpdir.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("hostile-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    dir
}

fn write_json(path: &Path, v: &Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn hex64(c: char) -> String {
    c.to_string().repeat(64)
}

/// Build a keyless session whose hashes, genesis and links are all correct,
/// so that anything the verifier objects to is the hostile part and not
/// incidental breakage. `first_sequence` lets a test place the chain at an
/// arbitrary sequence: contiguity will object, but `head_commitment` still
/// verifies, which is what puts the head's `last_sequence` on the seal-anchor
/// path.
fn session_json(session_id: &str, n: usize, first_sequence: i64) -> Value {
    let mut prev = genesis_hash_hex(session_id);
    let mut entries = Vec::new();
    for i in 0..n {
        let fields = EntryFields {
            artifact_hash: sha256_hex(format!("body-{i}").as_bytes()),
            artifact_hash_alg: "sha256".to_owned(),
            artifact_id: format!("obs:{i}"),
            artifact_schema_version: "1".to_owned(),
            artifact_type: "observation".to_owned(),
            monotonic_ns: 1_000 + i as u64,
            previous_entry_hash: prev.clone(),
            sequence: first_sequence.wrapping_add(i as i64),
            session_id: session_id.to_owned(),
            signer_node_id: 13,
            signer_org_id: "local".to_owned(),
            timestamp_ns: 1_787_000_000_000_000_000 + i as u64,
        };
        let hash = sha256_hex(&fields.canonical_bytes());
        let mut e = serde_json::to_value(&fields).unwrap();
        e["chain_entry_hash"] = json!(hash);
        entries.push(e);
        prev = hash;
    }
    json!({
        "session_id": session_id,
        "entries": entries,
        "head": {
            "session_id": session_id,
            "last_sequence": first_sequence.wrapping_add(n as i64 - 1),
            "last_entry_hash": prev,
        },
    })
}

fn manifest(sessions: Vec<Value>) -> Value {
    json!({
        "docket_bundle_version": "docket-bundle/0.1",
        "chain_format": "v1",
        "sessions": sessions,
    })
}

/// A one-session bundle plus a seal that lists that session with the given
/// head hash and entry count. The seal's Merkle root is deliberately wrong —
/// consistency is a separate graded property and no test here depends on it.
fn bundle_with_seal(
    name: &str,
    session: Value,
    seal_head_hash: &str,
    seal_entry_count: u64,
    in_flight: bool,
) -> PathBuf {
    let root = scratch(name);
    let sid = session["session_id"].as_str().unwrap().to_owned();
    write_json(&root.join("sessions/s.json"), &session);
    write_json(
        &root.join("seal/seal.json"),
        &json!({
            "seal_version": "virp-seal/1",
            "created_at": "2026-08-26T00:00:00Z",
            "sealed_by": "hostile-input fixture",
            "seal_public_key": "minisign:not-checked",
            "residual_disclosure": "fixture",
            "sessions": [{
                "session_id": sid,
                "entry_count": seal_entry_count,
                "head_hash": seal_head_hash,
                "in_flight": in_flight,
            }],
            "merkle": {"root": hex64('0'), "leaf_count": 1},
        }),
    );
    let mut m = manifest(vec![json!({"session_id": sid, "path": "sessions/s.json"})]);
    m["seal"] = json!("seal/seal.json");
    write_json(&root.join("manifest.json"), &m);
    root
}

// ---------------------------------------------------------------------------
// Finding 1 — the verifier must survive a malformed seal
// ---------------------------------------------------------------------------

/// Before the fix this reached `&s.head_hash[..16]` and killed the process:
/// exit 101, no report, no verdict, on both the text and `--json` paths.
#[test]
fn short_head_hash_in_seal_is_unreadable_not_a_crash() {
    for (name, head_hash) in [
        ("empty", ""),
        ("short", "ab"),
        ("nonhex", "zzzzzzzzzzzzzzzzzzzz"),
        ("multibyte", "aaaaaaaaaaaaaaa\u{00e9}aaaaaaa"),
        ("63", &hex64('a')[..63]),
    ] {
        let dir = bundle_with_seal(&format!("seal-{name}"), session_json("s", 1, 0), head_hash, 0, true);

        let r = run(&dir, &[]);
        r.never_crashed(name);
        assert_eq!(r.code, 2, "{name}: expected UNREADABLE\nstdout: {}", r.out);
        assert!(r.err.contains("head_hash"), "{name}: {}", r.err);
        assert!(r.err.contains("UNREADABLE"), "{name}: {}", r.err);

        // The JSON path must fail the same way, not differently.
        run(&dir, &["--json"]).never_crashed(&format!("{name} --json"));
        assert_eq!(run(&dir, &["--json"]).code, 2, "{name} --json");
    }
}

/// The quiet defect, at the binary boundary.
///
/// A debug build panicked here. A **release** build did not: it wrapped
/// `i64::MAX + 1` to `i64::MIN`, failed the unsigned conversion, and printed
/// `unwrap_or(0)` — reporting `bundle head is 4807262… with 0 entries` for a
/// head that commits to sequence `i64::MAX`. Exit 1, a full report, and a
/// false statement inside it.
///
/// So this test asserts two things, and the second is the important one:
/// the process survived, and no line of its output claims an entry count the
/// verifier never computed.
#[test]
fn head_sequence_overflow_never_claims_a_false_entry_count() {
    for (name, first_sequence) in [
        ("i64max", i64::MAX),
        ("i64max-1", i64::MAX - 1),
        ("i64min", i64::MIN),
        ("negative", -5_i64),
    ] {
        // A single entry placed at `first_sequence`: contiguity objects, but
        // the head still commits to the entry, which is what reaches the
        // anchor.
        let dir = bundle_with_seal(
            &format!("seq-{name}"),
            session_json("s", 1, first_sequence),
            &hex64('a'),
            0,
            true,
        );
        let r = run(&dir, &[]);
        r.never_crashed(name);

        assert!(
            r.out.contains("seal_anchor"),
            "{name}: the anchor line is missing entirely\n{}",
            r.out
        );
        // The exact shape of the old lie: a count of 0 for a head that
        // commits to something else.
        if first_sequence != 0 && first_sequence != -1 {
            assert!(
                !r.out.contains("bundle head is") || !r.out.contains("with 0 entries"),
                "{name}: the report claims 0 entries for a head at sequence {first_sequence}\n{}",
                r.out
            );
        }
    }
}

/// A well-formed seal over a well-formed bundle still anchors. The hostile
/// fixtures above must not have been bought with a verifier that now refuses
/// everything.
#[test]
fn a_well_formed_seal_still_anchors() {
    let session = session_json("s", 3, 0);
    let head_hash = session["head"]["last_entry_hash"].as_str().unwrap().to_owned();
    let dir = bundle_with_seal("seal-good", session, &head_hash, 3, false);
    let r = run(&dir, &[]);
    r.never_crashed("well-formed");
    assert!(r.out.contains("seal_anchor            VERIFIED"), "{}", r.out);
}
