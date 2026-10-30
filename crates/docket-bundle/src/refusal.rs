//! Cross-identity refusal detection (EVADED_REFUSAL).
//!
//! Doctrine (the operator's, 2026-10-29): a refusal from VIRP is a stop, not
//! an obstacle; an operation refused under one identity is not retried under
//! another. From 2026-10-30 the O-Node chains every refusal as a
//! `gate_rejection/2` body carrying `refused_uid`, a canonical operation key
//! and the refusal's own TTL, refuses a different uid's retry of the same
//! operation while that taint is live, and clears a taint only through an
//! owner-signed `refusal_lifted/1` entry. This module is the independent
//! reading of those bytes: it recomputes the operation keys with its own
//! code and reports an accepted entry that matches an earlier keyed refusal
//! under a different uid, inside the refusal's window, with no VALID lift
//! between them.
//!
//! It reads only what the bundle carries — entries and artifact bodies —
//! and never the daemon's own taint index. A hash-only bundle (no bodies)
//! cannot be graded and says so. A lift whose approver key the examiner did
//! not supply (`--approver-key`) is UNVERIFIABLE and does not clear a
//! refusal: fail closed, and the finding says why.
//!
//! Operation keys (must equal the daemon's `virp_refusal_op_key_*`; pinned by
//! vectors in this module's tests and in the daemon's suite):
//!
//! ```text
//! execute       SHA256("VIRP-REFUSAL-OP/execute\0" || device || "\0" || canonical(command))
//! chain_append  SHA256("VIRP-REFUSAL-OP/chain_append\0" || artifact_type || "\0" || session_id || "\0" || artifact_hash)
//! ```
//!
//! `canonical()` trims leading whitespace, drops CR, collapses runs of
//! space/tab to one space and trims trailing spaces — the O-Node's v2 command
//! canonicalization, re-stated here.
//!
//! Lift canonical bytes (what the approver key signs, no domain tag):
//!
//! ```text
//! "VRL1" || refusal_entry_hash(32) || op_key(32) || be64 refused_uid || be64 lifted_at_ns   (84 bytes)
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::hash::sha256_hex;
use crate::sig::PublicKey;
use crate::verify::{ArtifactStore, SessionChain, Status};

/// One accepted entry that finished an operation another identity had been
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvadedRefusal {
    pub refusal_entry_hash: String,
    pub accepted_entry_hash: String,
    pub op_kind: String,
    pub op_key: String,
    pub refused_uid: i64,
    /// `None` when the accepted entry carries no uid in chain bytes (every
    /// externally submitted type does not). Reported as unknown, never
    /// assumed equal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_uid: Option<i64>,
    pub refusal_session: String,
    pub accepted_session: String,
    pub accepted_type: String,
    pub refused_at_ns: u64,
    pub accepted_at_ns: u64,
    pub ttl_s: u32,
    /// Why a lift that was present did not count, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lift_note: Option<String>,
}

/// The bundle-level result. Omitted from a report (as `None`) when the
/// bundle carries no refusal-class entry at all, so pre-feature bundles
/// serialize unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusalEvasionReport {
    /// VERIFIED: bodies read, keys recomputed, no evasion. FAILED: at least
    /// one EVADED_REFUSAL. UNVERIFIABLE: refusals exist but their bodies are
    /// not carried (hash-only bundle), so nothing could be keyed.
    pub status: Status,
    pub keyed_refusals: usize,
    /// `gate_rejection/1` entries: no uid, no key — a retry of one of these
    /// is not detectable from chain bytes, and this count says so.
    pub legacy_unkeyed: usize,
    pub lifts_valid: usize,
    pub lifts_invalid: usize,
    pub lifts_unverifiable: usize,
    /// `refusal_evaded/1` entries: evasions the daemon itself caught.
    pub daemon_blocked: usize,
    /// `refusal_expired/1` entries: retries admitted after the window.
    pub expired_retries: usize,
    pub body_mismatch: usize,
    pub findings: Vec<EvadedRefusal>,
    pub detail: String,
}

/// `virp_canonicalize_command`, re-stated.
pub fn canonical_command(cmd: &str) -> String {
    let b = cmd.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut last_space = false;
    while i < b.len() {
        let c = b[i];
        i += 1;
        if c == b'\r' {
            continue;
        }
        if c == b' ' || c == b'\t' {
            if !last_space && !out.is_empty() {
                out.push(b' ');
                last_space = true;
            }
            continue;
        }
        last_space = false;
        out.push(c);
    }
    while out.last() == Some(&b' ') {
        out.pop();
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn keyed(tag: &str, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(tag.as_bytes());
    h.update([0u8]);
    for (i, p) in parts.iter().enumerate() {
        h.update(p.as_bytes());
        if i + 1 < parts.len() {
            h.update([0u8]);
        }
    }
    hex::encode(h.finalize())
}

/// Operation key of an execute: device name plus canonical command.
pub fn op_key_execute(device: &str, command: &str) -> String {
    let canon = canonical_command(command);
    keyed("VIRP-REFUSAL-OP/execute", &[device, &canon])
}

/// Operation key of a chain_append: the exact (type, session, bytes).
pub fn op_key_append(artifact_type: &str, session_id: &str, artifact_hash: &str) -> String {
    keyed(
        "VIRP-REFUSAL-OP/chain_append",
        &[artifact_type, session_id, artifact_hash],
    )
}

/// The 84 lift canonical bytes, or `None` when a hex field is malformed.
pub fn lift_canonical(refusal_hash: &str, op_key: &str, refused_uid: u64, lifted_at_ns: u64) -> Option<Vec<u8>> {
    let r = hex::decode(refusal_hash).ok().filter(|v| v.len() == 32)?;
    let k = hex::decode(op_key).ok().filter(|v| v.len() == 32)?;
    if !is_lower_hex(refusal_hash) || !is_lower_hex(op_key) {
        return None;
    }
    let mut v = Vec::with_capacity(84);
    v.extend_from_slice(b"VRL1");
    v.extend_from_slice(&r);
    v.extend_from_slice(&k);
    v.extend_from_slice(&refused_uid.to_be_bytes());
    v.extend_from_slice(&lifted_at_ns.to_be_bytes());
    Some(v)
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

const REFUSAL_TYPES: [&str; 4] = ["gate_rejection", "refusal_lifted", "refusal_evaded", "refusal_expired"];
const DAEMON_MINTED_NON_OPS: [&str; 5] = ["approval", "proposal", "outcome", "node_config", "validation"];
const EXTERNAL_TYPES: [&str; 13] = [
    "observation",
    "evidence_item",
    "no_drift",
    "baseline_set",
    "drift_alert",
    "fed_request",
    "fed_observation",
    "fed_outcome",
    "fed_error",
    "comparator_verdict",
    "comparator_verd",
    "chainwalk_summary",
    "chainwalk_summa",
];

struct Refusal {
    hash: String,
    session: String,
    ts: u64,
    op_kind: String,
    op_key: String,
    refused_uid: i64,
    ttl_s: u32,
}

struct Lift {
    ts: u64,
    refusal_hash: String,
    valid: bool,
    note: String,
}

fn body_of<'a>(store: Option<&'a ArtifactStore>, hash: &str) -> Option<&'a [u8]> {
    store.and_then(|s| s.get(hash)).map(Vec::as_slice)
}

fn jstr<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn jint(v: &Value, k: &str) -> Option<i64> {
    v.get(k).and_then(Value::as_i64)
}

/// Grade the bundle. `None` when no refusal-class entry exists anywhere in it.
pub fn grade_refusal_evasion(
    chains: &[SessionChain],
    store: Option<&ArtifactStore>,
    approver_keys: &[PublicKey],
) -> Option<RefusalEvasionReport> {
    let has_any = chains
        .iter()
        .flat_map(|c| c.entries.iter())
        .any(|e| REFUSAL_TYPES.contains(&e.fields.artifact_type.as_str()));
    if !has_any {
        return None;
    }
    let mut rep = RefusalEvasionReport {
        status: Status::Verified,
        keyed_refusals: 0,
        legacy_unkeyed: 0,
        lifts_valid: 0,
        lifts_invalid: 0,
        lifts_unverifiable: 0,
        daemon_blocked: 0,
        expired_retries: 0,
        body_mismatch: 0,
        findings: Vec::new(),
        detail: String::new(),
    };

    // Pass 1: refusals and lifts, in bundle-wide timestamp order.
    let mut all: Vec<(&SessionChain, &crate::verify::ChainEntry)> = chains
        .iter()
        .flat_map(|c| c.entries.iter().map(move |e| (c, e)))
        .collect();
    all.sort_by_key(|(_, e)| (e.fields.timestamp_ns, e.fields.sequence));

    let mut refusals: Vec<Refusal> = Vec::new();
    let mut lifts: Vec<Lift> = Vec::new();
    let mut bodies_missing = 0usize;
    for (_c, e) in &all {
        let t = e.fields.artifact_type.as_str();
        match t {
            "refusal_evaded" => rep.daemon_blocked += 1,
            "refusal_expired" => rep.expired_retries += 1,
            "gate_rejection" | "refusal_lifted" => {
                let Some(body) = body_of(store, &e.fields.artifact_hash) else {
                    if t == "gate_rejection" {
                        rep.legacy_unkeyed += 1;
                    }
                    bodies_missing += 1;
                    continue;
                };
                if sha256_hex(body) != e.fields.artifact_hash {
                    rep.body_mismatch += 1;
                    continue;
                }
                let Ok(v) = serde_json::from_slice::<Value>(body) else {
                    rep.body_mismatch += 1;
                    continue;
                };
                if t == "gate_rejection" {
                    let keyed_ok = jstr(&v, "schema") == Some("gate_rejection/2");
                    let (Some(kind), Some(key), Some(uid), Some(ttl)) = (
                        jstr(&v, "op_kind"),
                        jstr(&v, "op_key"),
                        jint(&v, "refused_uid"),
                        jint(&v, "refusal_ttl_s"),
                    ) else {
                        rep.legacy_unkeyed += 1;
                        continue;
                    };
                    if !keyed_ok || key.len() != 64 || ttl <= 0 {
                        rep.legacy_unkeyed += 1;
                        continue;
                    }
                    rep.keyed_refusals += 1;
                    refusals.push(Refusal {
                        hash: e.chain_entry_hash.clone(),
                        session: e.fields.session_id.clone(),
                        ts: e.fields.timestamp_ns,
                        op_kind: kind.to_owned(),
                        op_key: key.to_owned(),
                        refused_uid: uid,
                        ttl_s: ttl as u32,
                    });
                } else {
                    let mut l = Lift {
                        ts: e.fields.timestamp_ns,
                        refusal_hash: jstr(&v, "refusal_entry_hash").unwrap_or("").to_owned(),
                        valid: false,
                        note: String::new(),
                    };
                    let fields = (
                        jstr(&v, "refusal_entry_hash"),
                        jstr(&v, "op_key"),
                        jint(&v, "refused_uid"),
                        jstr(&v, "lifted_at_ns").and_then(|s| s.parse::<u64>().ok()),
                        jstr(&v, "approver_key_id"),
                        jstr(&v, "approver_signature"),
                    );
                    let (Some(r), Some(k), Some(uid), Some(at), Some(kid), Some(sig)) = fields else {
                        l.note = "malformed lift body".to_owned();
                        rep.lifts_invalid += 1;
                        lifts.push(l);
                        continue;
                    };
                    if approver_keys.is_empty() {
                        l.note = "lift present but unverifiable (no --approver-key)".to_owned();
                        rep.lifts_unverifiable += 1;
                        lifts.push(l);
                        continue;
                    }
                    let Some(pk) = approver_keys.iter().find(|p| p.key_id() == kid) else {
                        l.note = format!("lift signed by key_id {kid} not among the supplied approver keys");
                        rep.lifts_invalid += 1;
                        lifts.push(l);
                        continue;
                    };
                    let canon = lift_canonical(r, k, uid as u64, at);
                    let sig_ok = match (canon, hex::decode(sig).ok()) {
                        (Some(c), Some(s)) if s.len() == 64 => {
                            let arr: [u8; 64] = s.as_slice().try_into().expect("length checked");
                            pk.verify_raw(&c, &arr).is_ok()
                        }
                        _ => false,
                    };
                    if !sig_ok {
                        l.note = "lift signature does not verify".to_owned();
                        rep.lifts_invalid += 1;
                        lifts.push(l);
                        continue;
                    }
                    let names_refusal = refusals
                        .iter()
                        .any(|x| x.hash == r && x.op_key == k && x.refused_uid == uid);
                    if !names_refusal {
                        l.note = "lift names no matching keyed refusal".to_owned();
                        rep.lifts_invalid += 1;
                        lifts.push(l);
                        continue;
                    }
                    l.valid = true;
                    rep.lifts_valid += 1;
                    lifts.push(l);
                }
            }
            _ => {}
        }
    }

    if rep.keyed_refusals == 0 {
        if store.is_none() || bodies_missing > 0 {
            rep.status = Status::unverifiable(format!(
                "{} refusal entr{} carried without bodies (hash-only bundle); refusals cannot be keyed, so a \
                 cross-identity retry cannot be checked",
                rep.legacy_unkeyed,
                if rep.legacy_unkeyed == 1 { "y" } else { "ies" }
            ));
        }
        rep.detail = summary(&rep);
        return Some(rep);
    }

    // Pass 2: accepted entries, matched against refusals inside their window.
    let mut reported_intents: Vec<String> = Vec::new();
    for (_c, e) in &all {
        let t = e.fields.artifact_type.as_str();
        if REFUSAL_TYPES.contains(&t) || DAEMON_MINTED_NON_OPS.contains(&t) {
            continue;
        }
        let (kind, key, uid, intent_ref): (&str, String, Option<i64>, Option<String>) =
            if t == "gate_intent" || t == "gate_execution" {
                let Some(body) = body_of(store, &e.fields.artifact_hash) else {
                    continue;
                };
                if sha256_hex(body) != e.fields.artifact_hash {
                    rep.body_mismatch += 1;
                    continue;
                }
                let Ok(v) = serde_json::from_slice::<Value>(body) else {
                    rep.body_mismatch += 1;
                    continue;
                };
                let (Some(dev), Some(cmd)) = (jstr(&v, "device"), jstr(&v, "command")) else {
                    continue;
                };
                (
                    "execute",
                    op_key_execute(dev, cmd),
                    jint(&v, "uid"),
                    jstr(&v, "intent_entry_hash")
                        .filter(|s| s.len() == 64)
                        .map(str::to_owned),
                )
            } else if EXTERNAL_TYPES.contains(&t) {
                (
                    "chain_append",
                    op_key_append(t, &e.fields.session_id, &e.fields.artifact_hash),
                    None,
                    None,
                )
            } else {
                continue;
            };
        for r in &refusals {
            if r.op_kind != kind || r.op_key != key {
                continue;
            }
            let ts = e.fields.timestamp_ns;
            if ts <= r.ts || ts > r.ts + u64::from(r.ttl_s) * 1_000_000_000 {
                continue;
            }
            if uid == Some(r.refused_uid) {
                continue; // same uid: outside this check's scope
            }
            if let Some(ir) = &intent_ref {
                if reported_intents.contains(ir) {
                    continue; // its intent was already reported for this refusal
                }
            }
            let mut note: Option<String> = None;
            let mut lifted = false;
            for l in &lifts {
                if l.refusal_hash != r.hash || l.ts <= r.ts || l.ts >= ts {
                    continue;
                }
                if l.valid {
                    lifted = true;
                    break;
                }
                note = Some(l.note.clone());
            }
            if lifted {
                continue;
            }
            if t == "gate_intent" {
                reported_intents.push(e.chain_entry_hash.clone());
            }
            rep.findings.push(EvadedRefusal {
                refusal_entry_hash: r.hash.clone(),
                accepted_entry_hash: e.chain_entry_hash.clone(),
                op_kind: kind.to_owned(),
                op_key: key.clone(),
                refused_uid: r.refused_uid,
                retry_uid: uid,
                refusal_session: r.session.clone(),
                accepted_session: e.fields.session_id.clone(),
                accepted_type: t.to_owned(),
                refused_at_ns: r.ts,
                accepted_at_ns: ts,
                ttl_s: r.ttl_s,
                lift_note: note,
            });
        }
    }
    if !rep.findings.is_empty() {
        rep.status = Status::failed(format!(
            "{} accepted entr{} finished an operation another identity had been refused, inside the \
             refusal's window, with no valid owner lift",
            rep.findings.len(),
            if rep.findings.len() == 1 { "y" } else { "ies" }
        ));
    }
    rep.detail = summary(&rep);
    Some(rep)
}

fn summary(r: &RefusalEvasionReport) -> String {
    format!(
        "keyed={} legacy_unkeyed={} lifts_valid={} lifts_invalid={} lifts_unverifiable={} daemon_blocked={} \
         expired_retries={} body_mismatch={} evaded={}",
        r.keyed_refusals,
        r.legacy_unkeyed,
        r.lifts_valid,
        r.lifts_invalid,
        r.lifts_unverifiable,
        r.daemon_blocked,
        r.expired_retries,
        r.body_mismatch,
        r.findings.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors the O-Node pins in tests/test_onode.c
    /// (test_refusal_op_key_vectors) and the Python suite pins in
    /// tests/test_cross_uid_refusal_verify.py. Three implementations, one
    /// answer.
    #[test]
    fn op_key_vectors_match_the_daemon() {
        assert_eq!(
            op_key_execute("R1", "show clock"),
            "82ba801ea132ec5139efb80ef44b1f016ea1e4c81907b5fdb78e09d38c270f6d"
        );
        assert_eq!(
            op_key_execute("R1", "  show   clock "),
            "82ba801ea132ec5139efb80ef44b1f016ea1e4c81907b5fdb78e09d38c270f6d"
        );
        assert_eq!(
            op_key_execute("R-CUR", "configure terminal"),
            "937138fe6fbb1a6844c67c4f0850cee3858136db79a6f570f081be3b11a93081"
        );
        assert_eq!(
            op_key_append(
                "evidence_item",
                "kestrel-verified:da79796faa8f434e88fe64898104a3e6-0",
                "d5cc4f478669c63823fce3a261e3c9bb846739f19fcaf84b132125bd406a9df8"
            ),
            "82cbfbfcd37a4b5a96dc0d0a7771004651512127196286c85da0009fb2c2dd3a"
        );
        assert_ne!(op_key_execute("R2", "show clock"), op_key_execute("R1", "show clock"));
    }

    #[test]
    fn canonical_command_matches_the_daemon() {
        // Only SPACES are stripped at the end, exactly as the daemon does:
        // a trailing newline (and the space before it) survive. The daemon
        // refuses embedded newlines at ingress; the key must still agree.
        assert_eq!(canonical_command("  show   clock \r\n"), "show clock \n");
        assert_eq!(canonical_command("  show   clock  "), "show clock");
        assert_eq!(canonical_command("a\tb"), "a b");
        assert_eq!(canonical_command(""), "");
        // newlines inside are kept (the daemon refuses them elsewhere)
        assert_eq!(canonical_command("a\nb"), "a\nb");
    }

    #[test]
    fn lift_canonical_is_84_bytes_with_magic() {
        let r = "ab".repeat(32);
        let k = "11".repeat(32);
        let c = lift_canonical(&r, &k, 5101, 1_793_307_527_000_000_000).unwrap();
        assert_eq!(c.len(), 84);
        assert_eq!(&c[..4], b"VRL1");
        assert_eq!(&c[68..76], &5101u64.to_be_bytes());
        assert!(lift_canonical("zz", &k, 0, 0).is_none());
        assert!(lift_canonical(&r.to_uppercase(), &k, 0, 0).is_none());
    }
}
