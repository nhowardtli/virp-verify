//! Producer-signature verification — the CAPTURE HOST's trust boundary.
//!
//! A `camera_segment/*` body carries `producer_sig`: raw Ed25519 (no domain
//! tag) by the capture host's own producer key over the canonical body minus
//! `producer_sig`. That is a DIFFERENT trust boundary from the O-Node chain
//! signature: the chain key proves the O-Node committed to these bytes; the
//! producer key proves the capture host built and signed them. Neither key
//! may ever stand in for the other — that substitution is exactly what the
//! signer-trust axis exists to prevent.
//!
//! The bundle never carries a producer public key, only each record's
//! `producer_key_id` (`sha256(pub)[..16]` hex — the same convention as the
//! chain keys). The key must arrive OUT OF BAND (`--producer-key`); without
//! it the producer signature is UNVERIFIABLE and producer trust
//! UNESTABLISHED. Validity and trust are reported as separate results,
//! exactly as they are for the chain key.
//!
//! Canonical form, re-implemented here from the producer's documented
//! format (nothing imported, nothing vendored): one line, keys sorted,
//! separators `,` and `:` with no whitespace, ASCII-only with `\uXXXX`
//! escapes — Python's `json.dumps(obj, sort_keys=True,
//! separators=(",", ":"), ensure_ascii=True)`. Correctness is proven by
//! byte-equality against real producer output: every stored fixture body
//! re-canonicalizes to its exact stored bytes (see the canonical-agreement
//! tests). Number formatting follows serde_json's shortest-roundtrip float
//! text, which matches Python's for every value real producers emit; a
//! divergence (extreme exponents Python spells `1e+16`) can only make a
//! genuine signature FAIL to verify, never make a forged one verify.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sig::PublicKey;
use crate::verify::{ArtifactStore, SessionChain, SignerTrust, Status, TrustSource};

/// Python-compatible canonical JSON bytes: sorted keys, compact separators,
/// ASCII-only. The producer hashes, signs, submits and stores exactly these
/// bytes — there is no second serialization on its side either.
pub fn canonical_json_bytes(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        // serde_json's own number text: exact decimal for integers,
        // shortest-roundtrip for floats (e.g. `6.134`, `2.0`) — the same
        // digits Python's repr-based dumps produces for producer-real values.
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_ascii_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(o) => {
            // Explicit sort, independent of serde_json's map backing. UTF-8
            // byte order equals code-point order, which is Python's str sort.
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_ascii_string(k, out);
                out.push(b':');
                write_canonical(&o[k.as_str()], out);
            }
            out.push(b'}');
        }
    }
}

/// `ensure_ascii=True` string escaping: printable ASCII raw, the two-char
/// escapes JSON names, everything else `\uXXXX` (lowercase hex, surrogate
/// pairs beyond the BMP) — Python escapes every char outside `0x20..=0x7e`.
fn write_ascii_string(s: &str, out: &mut Vec<u8>) {
    use std::io::Write as _;
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\u{20}'..='\u{7e}' => out.push(c as u8),
            c => {
                let n = c as u32;
                if n < 0x10000 {
                    let _ = write!(out, "\\u{n:04x}");
                } else {
                    let n = n - 0x10000;
                    let _ = write!(out, "\\u{:04x}\\u{:04x}", 0xd800 + (n >> 10), 0xdc00 + (n & 0x3ff));
                }
            }
        }
    }
    out.push(b'"');
}

/// Read a producer PUBLIC key file: the 32 raw bytes the producer's keygen
/// writes as `producer.pub` (also accepted as 64 hex chars, optionally
/// newline-terminated). Anything else is refused with the expectation named —
/// an operator-input problem, never a verdict about the evidence.
pub fn read_producer_key_file(path: &std::path::Path) -> Result<PublicKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let raw: [u8; 32] = if bytes.len() == 32 {
        bytes.as_slice().try_into().expect("length checked")
    } else if let Some(hex_str) = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .filter(|s| s.len() == 64)
    {
        let decoded = hex::decode(hex_str).map_err(|_| {
            format!(
                "{}: 64 characters but not hex; expected a raw 32-byte Ed25519 public key \
                 (producer.pub) or 64 hex chars",
                path.display()
            )
        })?;
        decoded.as_slice().try_into().expect("64 hex chars decode to 32 bytes")
    } else {
        return Err(format!(
            "{}: {} bytes; expected a raw 32-byte Ed25519 public key (producer.pub) or 64 hex chars",
            path.display(),
            bytes.len()
        ));
    };
    PublicKey::from_bytes(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

/// The two-axis producer-signature summary for one session: validity (did
/// the producer signature verify over the recomputed canonical body) and
/// trust (does the signature verify under the examiner-pinned producer
/// key?). Two results, rendered separately, never collapsed — mirroring
/// [`crate::verify::SignerReport`] for the chain key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerSignerReport {
    pub signature_validity: Status,
    pub trust: SignerTrust,
    /// Provenance of the key(s) used. Always the examiner trust store when
    /// present: the bundle carries producer key IDS, never producer keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_source: Option<TrustSource>,
    pub detail: String,
    /// `producer_key_id` values the carried camera records name, in order of
    /// first appearance. Claims from inside the evidence — named, not
    /// endorsed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claimed_key_ids: Vec<String>,
}

impl ProducerSignerReport {
    fn unverifiable(reason: &str, claimed: Vec<String>) -> ProducerSignerReport {
        ProducerSignerReport {
            signature_validity: Status::unverifiable(reason),
            trust: SignerTrust::Unestablished,
            trust_source: None,
            // The reason rides on the status; renderers print it there.
            detail: String::new(),
            claimed_key_ids: claimed,
        }
    }
}

/// Grade the producer signatures of one session's carried camera records.
///
/// `keys` are the examiner-supplied producer public keys (`--producer-key`),
/// each matched to records by its derived key id. Empty means none were
/// supplied: UNVERIFIABLE / UNESTABLISHED, stated per session. Both
/// `camera_segment/1` and `/2` carry `producer_sig`; a camera record missing
/// the field is checked and wrong (FAILED), whatever keys were supplied.
pub fn grade_producer_signatures(
    chain: &SessionChain,
    store: Option<&ArtifactStore>,
    keys: &[PublicKey],
) -> ProducerSignerReport {
    let Some(store) = store else {
        return ProducerSignerReport::unverifiable(
            "the bundle carries no artifact bodies (exported without --artifacts), so no \
             producer-signed camera record can be read",
            Vec::new(),
        );
    };

    // Carried bodies that parse as camera records: (chain sequence, body).
    // Entries whose bodies are NOT carried are counted, exactly as the
    // capture-completeness grader counts them — an uncarried body may be a
    // camera record this grader cannot see, so its presence makes the
    // session's producer coverage unreadable rather than silently smaller.
    let mut hash_only = 0usize;
    let mut cam_bodies: Vec<(i64, Value)> = Vec::new();
    for e in &chain.entries {
        match store.get(&e.fields.artifact_hash) {
            None => hash_only += 1,
            Some(bytes) => {
                if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
                    let is_cam = v
                        .get("schema")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s.starts_with("camera_segment/"));
                    if is_cam {
                        cam_bodies.push((e.fields.sequence, v));
                    }
                }
            }
        }
    }
    if cam_bodies.is_empty() {
        // ABSENT is a statement about the whole session, so it needs the
        // whole session to be readable: with uncarried bodies in the chain,
        // "no camera records" is not a fact this grader can state.
        if hash_only > 0 {
            return ProducerSignerReport::unverifiable(
                &format!(
                    "{hash_only} of {} entries have no carried body; whether any of them is a \
                     producer-signed camera record cannot be seen",
                    chain.entries.len()
                ),
                Vec::new(),
            );
        }
        return ProducerSignerReport {
            signature_validity: Status::Absent,
            trust: SignerTrust::Unestablished,
            trust_source: None,
            detail: "no camera_segment records among the carried bodies; there is no producer \
                     signature to check"
                .to_owned(),
            claimed_key_ids: Vec::new(),
        };
    }

    let mut claimed: Vec<String> = Vec::new();
    for (_, body) in &cam_bodies {
        if let Some(kid) = body.get("producer_key_id").and_then(Value::as_str) {
            if !claimed.iter().any(|k| k == kid) {
                claimed.push(kid.to_owned());
            }
        }
    }

    // Structural check first: a camera record without a named key id and a
    // signature is wrong whether or not a key was supplied — and so is one
    // whose fields exist but cannot be what they claim. No public key is
    // needed to see that a key id is not 32 hex characters or that an
    // Ed25519 signature is not 64 bytes of hex: those are facts about the
    // record. "This is not a syntactically valid signature" (FAILED) is a
    // different statement from "I cannot check this signature"
    // (UNVERIFIABLE), and the no-key return below must never absorb it.
    // Case handling: key ids must be lowercase hex (they are compared
    // byte-for-byte against derived lowercase ids, so uppercase can never
    // name a key); signature hex is accepted in either case, matching what
    // `signature_from_hex` has always accepted on the keyed path.
    for (seq, body) in &cam_bodies {
        let kid = body.get("producer_key_id").and_then(Value::as_str);
        let sig = body.get("producer_sig").and_then(Value::as_str);
        let structural_failure: Option<(String, &str)> = if kid.is_none() || sig.is_none() {
            let missing = if kid.is_some() {
                "producer_sig"
            } else {
                "producer_key_id"
            };
            Some((
                format!("camera record at chain sequence {seq} carries no {missing}"),
                "a camera record does not carry the producer signature fields its schema requires",
            ))
        } else if !kid.is_some_and(crate::hash::is_hex_key_id_32) {
            Some((
                format!(
                    "producer_key_id at chain sequence {seq} is not a key id: expected exactly 32 \
                     lowercase hex characters (sha256-raw-16)"
                ),
                "a camera record's producer_key_id is malformed; checked and wrong, with or \
                 without a supplied key",
            ))
        } else if !sig.is_some_and(|s| crate::sig::signature_from_hex(s).is_ok()) {
            Some((
                format!(
                    "producer_sig at chain sequence {seq} is not an Ed25519 signature: expected \
                     exactly 128 hex characters decoding to 64 bytes"
                ),
                "a camera record's producer_sig is malformed; checked and wrong, with or without \
                 a supplied key",
            ))
        } else {
            None
        };
        if let Some((failure, detail)) = structural_failure {
            return ProducerSignerReport {
                signature_validity: Status::failed(failure),
                trust: if keys.is_empty() {
                    SignerTrust::Unestablished
                } else {
                    SignerTrust::Mismatch
                },
                trust_source: None,
                detail: detail.to_owned(),
                claimed_key_ids: claimed,
            };
        }
    }

    if keys.is_empty() {
        let mut reason = "producer signature not checked: no producer public key was supplied \
                          (--producer-key; the key must arrive out of band — the bundle carries \
                          each record's producer_key_id, never the producer key)"
            .to_owned();
        if hash_only > 0 {
            reason.push_str(&format!(
                "; additionally, {hash_only} of {} entries have no carried body, so the \
                 session's producer coverage could not be read in full even with a key",
                chain.entries.len()
            ));
        }
        return ProducerSignerReport::unverifiable(&reason, claimed);
    }

    let supplied_ids: Vec<&str> = keys.iter().map(PublicKey::key_id).collect();
    let mut verified = 0usize;
    let mut unmatched: Vec<&str> = Vec::new();
    for (seq, body) in &cam_bodies {
        // Both fields exist as strings: the structural pass above returned
        // otherwise.
        let kid = body.get("producer_key_id").and_then(Value::as_str).unwrap_or_default();
        let sig_hex = body.get("producer_sig").and_then(Value::as_str).unwrap_or_default();
        let Some(key) = keys.iter().find(|k| k.key_id() == kid) else {
            if !unmatched.contains(&kid) {
                unmatched.push(kid);
            }
            continue;
        };
        let Ok(sig) = crate::sig::signature_from_hex(sig_hex) else {
            return ProducerSignerReport {
                signature_validity: Status::failed(format!(
                    "producer_sig at chain sequence {seq} is not 64 bytes of hex"
                )),
                trust: SignerTrust::Mismatch,
                trust_source: Some(TrustSource::ExaminerTrustStore),
                detail: "a producer signature is malformed".to_owned(),
                claimed_key_ids: claimed,
            };
        };
        let Some(obj) = body.as_object() else {
            unreachable!("camera body parsed as object fields")
        };
        let mut stripped = obj.clone();
        stripped.remove("producer_sig");
        let payload = canonical_json_bytes(&Value::Object(stripped));
        if key.verify_raw(&payload, &sig).is_err() {
            // Canary: if the FULL body does not re-canonicalize to the exact
            // stored bytes either, say so — a re-serialized body (or a number
            // this canonicalizer spells differently) is a different fact
            // from a signature that failed over bytes proven canonical.
            let stored_is_canonical = chain.entries.iter().any(|e| {
                e.fields.sequence == *seq
                    && store
                        .get(&e.fields.artifact_hash)
                        .is_some_and(|raw| canonical_json_bytes(body) == *raw)
            });
            let detail = if stored_is_canonical {
                format!(
                    "producer_sig at chain sequence {seq} does not verify under supplied producer \
                     key {kid} (body bytes proven canonical)"
                )
            } else {
                format!(
                    "producer_sig at chain sequence {seq} does not verify, and the stored body is \
                     not in the canonical form this verifier reproduces (re-serialized body, or \
                     number formatting this canonicalizer does not spell the producer's way)"
                )
            };
            return ProducerSignerReport {
                signature_validity: Status::failed(detail),
                trust: SignerTrust::Mismatch,
                trust_source: Some(TrustSource::ExaminerTrustStore),
                detail: format!(
                    "checked against {} supplied producer key(s): {}",
                    keys.len(),
                    supplied_ids.join(", ")
                ),
                claimed_key_ids: claimed,
            };
        }
        verified += 1;
    }

    if !unmatched.is_empty() {
        return ProducerSignerReport {
            signature_validity: Status::unverifiable(format!(
                "records name producer_key_id {} — not among the supplied producer key(s) {}",
                unmatched.join(", "),
                supplied_ids.join(", ")
            )),
            trust: SignerTrust::Mismatch,
            trust_source: Some(TrustSource::ExaminerTrustStore),
            detail: format!(
                "the examiner supplied {} producer key(s) and {} of {} camera record(s) name a \
                 producer_key_id outside that set",
                keys.len(),
                cam_bodies.len() - verified,
                cam_bodies.len()
            ),
            claimed_key_ids: claimed,
        };
    }

    // Session-level VERIFIED requires the whole session to be readable, the
    // same rule capture completeness applies: an uncarried body may be a
    // camera record whose producer signature was never seen, and "every
    // carried signature verified" must not be worded as "the session's
    // producer signatures verified". The carried checks above still ran in
    // full — a checked-and-wrong signature returns FAILED before this point
    // whatever the coverage.
    if hash_only > 0 {
        return ProducerSignerReport {
            signature_validity: Status::unverifiable(format!(
                "{hash_only} of {} entries have no carried body, so whether they are camera \
                 records with producer signatures cannot be seen; the {verified} carried camera \
                 record signature(s) verified under the supplied key(s), but session-level \
                 producer verification cannot be claimed over records this verifier cannot read",
                chain.entries.len()
            )),
            trust: SignerTrust::Unestablished,
            trust_source: Some(TrustSource::ExaminerTrustStore),
            detail: format!(
                "{verified} carried producer signature(s) verified against {} supplied key(s); \
                 {hash_only} entry body(ies) absent from the bundle",
                keys.len()
            ),
            claimed_key_ids: claimed,
        };
    }

    ProducerSignerReport {
        signature_validity: Status::Verified,
        trust: SignerTrust::Pinned,
        trust_source: Some(TrustSource::ExaminerTrustStore),
        detail: format!(
            "{verified} producer signature(s) verified against {} supplied key(s), each over the \
             recomputed canonical body minus producer_sig",
            keys.len()
        ),
        claimed_key_ids: claimed,
    }
}
