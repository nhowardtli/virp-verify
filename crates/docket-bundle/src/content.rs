//! Labels are body claims, exposed only after exact artifact-hash binding.
use crate::bundle::SessionOutcome;
use crate::{Bundle, Status, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReport {
    pub entries: Vec<EntryContent>,
    pub tier_counts: BTreeMap<String, usize>,
    pub mode_counts: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_summary: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryContent {
    pub session_id: String,
    pub sequence: i64,
    pub content_tier: String,
    pub mode: String,
}
fn label(body: &serde_json::Value, field: &str) -> String {
    match body.get(field) {
        None => "absent".into(),
        Some(serde_json::Value::String(s))
            if match field {
                "content_tier" => matches!(s.as_str(), "observed" | "self-reported"),
                "mode" => matches!(s.as_str(), "tap" | "witness"),
                _ => false,
            } =>
        {
            s.clone()
        }
        _ => "unknown".into(),
    }
}
pub fn labels(bytes: Option<&[u8]>, expected_hash: &str) -> (String, String) {
    let body = bytes
        .filter(|b| crate::sha256_hex(b) == expected_hash)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
    match body {
        Some(v) if v.is_object() => (label(&v, "content_tier"), label(&v, "mode")),
        _ => ("unverified".into(), "unverified".into()),
    }
}
pub fn grade(bundle: &Bundle, sessions: &[SessionOutcome]) -> ContentReport {
    let mut out = ContentReport::default();
    let mut ids = BTreeSet::new();
    let mut summary_ok = !sessions.is_empty()
        && sessions.iter().all(|s| {
            s.report.verdict != Verdict::Failed
                && s.producer.signature_validity == Status::Absent
                && s.report
                    .properties
                    .iter()
                    .any(|p| p.name == "entry_signatures" && p.status == Status::Verified)
        });
    for chain in &bundle.sessions {
        if chain.entries.is_empty() {
            summary_ok = false;
        }
        for entry in &chain.entries {
            let bytes = bundle
                .artifacts
                .as_ref()
                .and_then(|s| s.get(&entry.fields.artifact_hash));
            let (content_tier, mode) = labels(bytes.map(Vec::as_slice), &entry.fields.artifact_hash);
            *out.tier_counts.entry(content_tier.clone()).or_default() += 1;
            *out.mode_counts.entry(mode.clone()).or_default() += 1;
            out.entries.push(EntryContent {
                session_id: chain.session_id.clone(),
                sequence: entry.fields.sequence,
                content_tier,
                mode,
            });
            match &entry.signature {
                Some(sig) if bundle.keyring.was_carried(&sig.signing_key_id) => {
                    ids.insert(sig.signing_key_id.clone());
                }
                _ => summary_ok = false,
            }
            // An absent producer verdict must not hide a partial declaration.
            match bytes
                .filter(|b| crate::sha256_hex(b) == entry.fields.artifact_hash)
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            {
                Some(v) if v.is_object() && v.get("producer_key_id").is_none() && v.get("producer_sig").is_none() => {}
                _ => summary_ok = false,
            }
        }
    }
    if summary_ok && !ids.is_empty() {
        out.producer_summary = Some(format!(
            "producer: ABSENT  no producer key declared; chain signed by key {}",
            ids.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    out
}
