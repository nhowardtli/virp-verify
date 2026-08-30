//! Capture completeness — a SEPARATE axis from cryptographic verification.
//!
//! Chain contiguity (the `contiguity` property) proves no sequence number is
//! missing from the exported session. It cannot prove the camera was
//! recording the whole time: a producer that stops for fourteen minutes and
//! resumes leaves a perfectly contiguous chain with real time missing.
//!
//! `camera_segment/2` bodies carry the `capture_policy` inside the
//! chain-signed camera record — nominal segment duration, permitted boundary
//! jitter, and the largest hole tolerated without a signed gap record. The
//! policy is inside the chain-signed bytes so that no one, operator included, can
//! loosen the tolerance afterwards to make a bad window look clean. Only
//! against that declaration can observed segment timing be graded.
//!
//! The grades (mirroring the producer's own coverage grader, which is the
//! reference for these semantics):
//!
//! * `CONTINUOUS` — every uncovered interval between adjacent capture
//!   windows is within the declared jitter.
//! * `INTERRUPTED / ACCOUNTED` — an interval is not covered, and a signed
//!   gap record (or the signed policy's own stated tolerance) accounts for
//!   it. **Accounted for is not complete**: this grade never collapses into
//!   `CONTINUOUS`, because "the outage is explained" and "there was no
//!   outage" are different statements.
//! * `INTERRUPTED / UNEXPLAINED` — an interval is not covered, no signed gap
//!   record explains it, and it exceeds the signed policy.
//! * `UNVERIFIABLE` — the evidence does not carry what the check needs: no
//!   artifact bodies, no camera records, or records that declare no cadence
//!   (`camera_segment/1`). Never guessed around; the missing input is named.
//! * `FAILED` — a record that claims `camera_segment/2` but does not carry a
//!   usable policy or its own timing fields: checked and wrong.
//!
//! Overlapping capture windows (negative holes) are the producer's routine
//! keyframe-aligned behaviour. An overlap deeper than the declared jitter is
//! reported as a timing observation and is NEVER an interruption:
//! overlapping windows leave no time unrecorded.
//!
//! This axis never feeds the session or bundle verdict, in either
//! direction — like signer trust, it is reported beside the cryptography,
//! not inside it. An unexplained gap does not mean the signatures failed,
//! and a verified signature does not mean the camera kept recording.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::verify::{ArtifactStore, SessionChain};

/// Schema tags this grader understands. Any other `camera_segment/N` is
/// refused loudly (UNVERIFIABLE with the schema named), never skipped in
/// silence — skipping is exactly how an unverified record ends up counted
/// inside a clean grade.
const SCHEMA_V1: &str = "camera_segment/1";
const SCHEMA_V2: &str = "camera_segment/2";

/// The capture-completeness grade for one session (or, rolled up
/// weakest-first, for a bundle). A separate vocabulary from [`crate::verify::Status`],
/// deliberately: these are answers about coverage in time, not about
/// cryptographic properties, and merging the two vocabularies is how
/// "accounted for" would one day read as "verified".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "grade", rename_all = "snake_case")]
pub enum CaptureGrade {
    /// Every boundary within the capture policy carried inside the
    /// chain-signed camera record. Says nothing about the signatures or the
    /// keys behind them — those are the cryptographic axes' statement.
    Continuous,
    /// Not covered, and accounted for by a signed gap record or the signed
    /// policy's stated tolerance. NOT complete.
    InterruptedAccounted,
    /// Not covered, no signed gap record, beyond the signed policy.
    InterruptedUnexplained,
    /// The evidence does not carry what this check needs. Distinct from a
    /// verifier that does not implement the check at all: a report with no
    /// completeness result is NOT GRADED; this grade means the check ran and
    /// names the missing input.
    Unverifiable { reason: String },
    /// A record claiming `camera_segment/2` that does not carry a usable
    /// policy or its own timing fields: checked and wrong.
    Failed {
        #[serde(rename = "failure")]
        detail: String,
    },
}

impl CaptureGrade {
    pub fn label(&self) -> &'static str {
        match self {
            CaptureGrade::Continuous => "CONTINUOUS",
            CaptureGrade::InterruptedAccounted => "INTERRUPTED / ACCOUNTED",
            CaptureGrade::InterruptedUnexplained => "INTERRUPTED / UNEXPLAINED",
            CaptureGrade::Unverifiable { .. } => "UNVERIFIABLE",
            CaptureGrade::Failed { .. } => "FAILED",
        }
    }

    /// The stated reason/failure that must stay visible next to the label.
    pub fn extra(&self) -> Option<&str> {
        match self {
            CaptureGrade::Unverifiable { reason } => Some(reason),
            CaptureGrade::Failed { detail } => Some(detail),
            _ => None,
        }
    }

    /// Weakest-link rank for the bundle roll-up. UNVERIFIABLE outranks
    /// UNEXPLAINED (matching the producer's coverage axis): a stream that
    /// cannot be graded must not hide behind a sibling's grade. FAILED is
    /// worst.
    fn rank(&self) -> u8 {
        match self {
            CaptureGrade::Continuous => 0,
            CaptureGrade::InterruptedAccounted => 1,
            CaptureGrade::InterruptedUnexplained => 2,
            CaptureGrade::Unverifiable { .. } => 3,
            CaptureGrade::Failed { .. } => 4,
        }
    }

    pub fn worst<'a>(grades: impl IntoIterator<Item = &'a CaptureGrade>) -> Option<&'a CaptureGrade> {
        grades.into_iter().max_by_key(|g| g.rank())
    }
}

/// A declared capture policy, in integer milliseconds.
///
/// Milliseconds rather than seconds-as-float, so the report type stays `Eq`
/// and serializes without float formatting questions. Exact: the producer
/// rounds every policy value to 3 decimals before signing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePolicy {
    pub nominal_segment_ms: i64,
    pub jitter_ms: i64,
    pub max_unexplained_gap_ms: i64,
}

/// One uncovered interval between adjacent capture windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureOutage {
    /// `segment_seq` of the record before the hole.
    pub after_seq: i64,
    /// `segment_seq` of the record whose policy graded the hole.
    pub seq: i64,
    pub hole_ms: i64,
    /// `accounted` (signed gap record), `tolerated` (within the signed
    /// policy's max unexplained gap), or `unexplained`.
    pub class: String,
    /// The signed gap record's stated reason, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap_reason: Option<String>,
}

/// Two adjacent capture windows overlapping by more than the declared
/// jitter: both records' claimed times cannot be tight, but no time is
/// unrecorded. An observation, never an interruption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureOverlap {
    pub after_seq: i64,
    pub seq: i64,
    pub overlap_ms: i64,
}

/// The capture-completeness result for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureReport {
    #[serde(flatten)]
    pub grade: CaptureGrade,
    /// Human-readable summary (counts, uncovered seconds).
    pub detail: String,
    /// `camera_segment/*` records read from carried bodies.
    pub camera_records: usize,
    /// Distinct signed policies declared across the graded records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<CapturePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outages: Vec<CaptureOutage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub overlaps: Vec<CaptureOverlap>,
}

impl CaptureReport {
    fn ungraded(grade: CaptureGrade, camera_records: usize) -> CaptureReport {
        CaptureReport {
            grade,
            detail: String::new(),
            camera_records,
            policies: Vec::new(),
            outages: Vec::new(),
            overlaps: Vec::new(),
        }
    }
}

/// One `camera_segment/2` record's graded fields.
struct CamRecord {
    camera_id: String,
    segment_seq: i64,
    start_ns: i64,
    end_ns: i64,
    gap: Option<GapRecord>,
    policy_s: (f64, f64, f64),
    policy: CapturePolicy,
}

/// A structurally valid gap record. `after_seq` is additionally checked
/// against the previous record of the same camera during the walk — a gap
/// citing some OTHER boundary must never account for this one.
struct GapRecord {
    after_seq: i64,
    reason: String,
}

/// Longest accepted gap `reason`. The producer writes short machine reasons
/// ("driver-restart"); a reason field is not a place to smuggle unbounded
/// content into reports.
const GAP_REASON_MAX_BYTES: usize = 256;

/// Strict read of a record's `gap` field.
///
/// `null` is no gap. Anything else must be an object whose `after_seq` is an
/// integer and whose `reason` is a nonempty string of at most
/// [`GAP_REASON_MAX_BYTES`]; everything else is `Err` with the defect named.
/// This is DELIBERATELY stricter than the producer's current `if gap:`
/// (Python truthiness), under which a nonempty string, a nonempty array or
/// any nonempty object would launder an unexplained outage into an accounted
/// one. A malformed gap grades FAILED, never accounted.
fn read_gap(v: &Value) -> Result<Option<GapRecord>, String> {
    let Value::Object(o) = v else {
        return match v {
            Value::Null => Ok(None),
            _ => Err(format!(
                "gap is {}, not an object",
                match v {
                    Value::Bool(_) => "a boolean",
                    Value::Number(_) => "a number",
                    Value::String(_) => "a string",
                    Value::Array(_) => "an array",
                    _ => "unreadable",
                }
            )),
        };
    };
    let Some(after_seq) = o.get("after_seq").and_then(Value::as_i64) else {
        return Err("gap carries no integer after_seq".to_owned());
    };
    let Some(reason) = o.get("reason").and_then(Value::as_str) else {
        return Err("gap carries no reason string".to_owned());
    };
    if reason.is_empty() {
        return Err("gap reason is empty".to_owned());
    }
    if reason.len() > GAP_REASON_MAX_BYTES {
        return Err(format!("gap reason exceeds {GAP_REASON_MAX_BYTES} bytes"));
    }
    Ok(Some(GapRecord {
        after_seq,
        reason: reason.to_owned(),
    }))
}

fn ms(seconds: f64) -> i64 {
    (seconds * 1000.0).round() as i64
}

/// Longest accepted single capture window, and the ceiling on
/// `nominal_segment_s`: one day. A record claiming a longer window would
/// make every later boundary appear covered on the record's own say-so —
/// the enormous-window laundering this bound refuses.
const MAX_WINDOW_S: f64 = 86_400.0;
/// Ceiling on `max_unexplained_gap_s`: one year. A declared tolerance above
/// it is not a policy, it is a blanket pardon.
const MAX_UNEXPLAINED_GAP_CEILING_S: f64 = 31_536_000.0;

/// The usable policy of a `camera_segment/2` body, or `None`. Mirrors the
/// producer's own validation — nominal > 0, jitter and max gap >= 0, jitter
/// < nominal (a jitter as wide as a segment would tolerate a whole missing
/// segment as continuous) — plus Docket's own sanity ceilings: every value
/// finite, nominal at most [`MAX_WINDOW_S`], max gap at most
/// [`MAX_UNEXPLAINED_GAP_CEILING_S`]. Values must be JSON numbers — this
/// reader does not coerce strings the producer never emits.
fn body_policy(body: &Value) -> Option<(f64, f64, f64)> {
    let p = body.get("capture_policy")?.as_object()?;
    let nominal = p.get("nominal_segment_s")?.as_f64()?;
    let jitter = p.get("jitter_s")?.as_f64()?;
    let max_gap = p.get("max_unexplained_gap_s")?.as_f64()?;
    if !nominal.is_finite() || !jitter.is_finite() || !max_gap.is_finite() {
        return None;
    }
    if nominal <= 0.0 || jitter < 0.0 || max_gap < 0.0 || jitter >= nominal {
        return None;
    }
    if nominal > MAX_WINDOW_S || max_gap > MAX_UNEXPLAINED_GAP_CEILING_S {
        return None;
    }
    Some((nominal, jitter, max_gap))
}

/// Grade capture completeness for one session against the bodies the bundle
/// carries. `store` is `None` for a hash-only bundle (no `--artifacts`).
///
/// The walk mirrors the producer's grader: records sorted by `segment_seq`
/// per camera, each hole graded against the LATER record's own signed
/// policy — that is the record making the continuity claim.
pub fn grade_capture_completeness(chain: &SessionChain, store: Option<&ArtifactStore>) -> CaptureReport {
    let Some(store) = store else {
        return CaptureReport::ungraded(
            CaptureGrade::Unverifiable {
                reason: "the bundle carries no artifact bodies (exported without --artifacts), so no \
                         capture record or declared cadence can be read"
                    .to_owned(),
            },
            0,
        );
    };

    // Every carried body that parses as a camera_segment record, plus the
    // count of entries whose bodies are NOT carried — an uncarried body may
    // be a camera record this grader cannot see, so its presence makes the
    // timeline unreadable rather than silently shorter.
    let mut hash_only = 0usize;
    let mut cam_bodies: Vec<(i64, Value)> = Vec::new(); // (entry sequence, body)
    for e in &chain.entries {
        match store.get(&e.fields.artifact_hash) {
            None => hash_only += 1,
            Some(bytes) => {
                let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
                    continue; // not JSON; not a camera record
                };
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

    if cam_bodies.is_empty() {
        return CaptureReport::ungraded(
            CaptureGrade::Unverifiable {
                reason: "no camera_segment records among the carried bodies; there is no declared \
                         capture cadence to grade this session against"
                    .to_owned(),
            },
            0,
        );
    }
    let n = cam_bodies.len();
    if hash_only > 0 {
        return CaptureReport::ungraded(
            CaptureGrade::Unverifiable {
                reason: format!(
                    "{hash_only} of {} entries have no carried body, so the capture timeline cannot \
                     be read in full; a hole spanning an unread record cannot be graded",
                    chain.entries.len()
                ),
            },
            n,
        );
    }

    // Schema gate. /1 declares no cadence (UNVERIFIABLE, never CONTINUOUS
    // and never a guess); an unrecognised /N is refused by name.
    let mut v1 = 0usize;
    for (_, body) in &cam_bodies {
        match body.get("schema").and_then(Value::as_str) {
            Some(SCHEMA_V1) => v1 += 1,
            Some(SCHEMA_V2) => {}
            Some(other) => {
                return CaptureReport::ungraded(
                    CaptureGrade::Unverifiable {
                        reason: format!(
                            "unrecognised schema {other:?} — this verifier cannot read its capture \
                             policy and will not guess one"
                        ),
                    },
                    n,
                );
            }
            // cam_bodies holds only bodies whose schema parsed as a string;
            // grade defensively rather than panic if that ever changes.
            None => {
                return CaptureReport::ungraded(
                    CaptureGrade::Unverifiable {
                        reason: "camera record carries no readable schema".to_owned(),
                    },
                    n,
                );
            }
        }
    }
    if v1 > 0 {
        return CaptureReport::ungraded(
            CaptureGrade::Unverifiable {
                reason: format!(
                    "{v1} of {n} camera_segment records declare no capture policy (camera_segment/1); \
                     without the producer's signed cadence, continuity in time cannot be graded"
                ),
            },
            n,
        );
    }

    // Extract the graded fields of every /2 record. A record that claims /2
    // and does not carry them is checked and wrong.
    let mut records: Vec<CamRecord> = Vec::with_capacity(n);
    for (entry_seq, body) in &cam_bodies {
        let Some(policy_s) = body_policy(body) else {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera_segment/2 record at chain sequence {entry_seq} carries no usable \
                         capture_policy"
                    ),
                },
                n,
            );
        };
        let field_i64 = |name: &str| body.get(name).and_then(Value::as_i64);
        let (Some(segment_seq), Some(start_ns), Some(end_ns), Some(camera_id)) = (
            field_i64("segment_seq"),
            field_i64("capture_start_utc_ns"),
            field_i64("capture_end_utc_ns"),
            body.get("camera_id").and_then(Value::as_str),
        ) else {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera_segment/2 record at chain sequence {entry_seq} lacks a usable \
                         camera_id, segment_seq or capture window"
                    ),
                },
                n,
            );
        };
        // Structural validation of the record's own claims. A window is a
        // DECLARATION; before grading continuity from it, it must at least
        // be shaped like time: end after start, bounded, a nonnegative
        // sequence, a named camera. Checked and wrong is FAILED — never a
        // window silently accepted because it exists.
        if camera_id.is_empty() {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!("camera_segment/2 record at chain sequence {entry_seq} has an empty camera_id"),
                },
                n,
            );
        }
        if segment_seq < 0 {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera_segment/2 record at chain sequence {entry_seq} claims negative \
                         segment_seq {segment_seq}"
                    ),
                },
                n,
            );
        }
        if end_ns <= start_ns {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera_segment/2 record at chain sequence {entry_seq} claims a capture \
                         window that ends at or before its start"
                    ),
                },
                n,
            );
        }
        if (end_ns as i128 - start_ns as i128) as f64 / 1e9 > MAX_WINDOW_S {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera_segment/2 record at chain sequence {entry_seq} claims a capture \
                         window longer than a day; a window that size would cover later \
                         boundaries on its own say-so"
                    ),
                },
                n,
            );
        }
        let gap = match read_gap(body.get("gap").unwrap_or(&Value::Null)) {
            Ok(g) => g,
            Err(defect) => {
                return CaptureReport::ungraded(
                    CaptureGrade::Failed {
                        detail: format!(
                            "camera_segment/2 record at chain sequence {entry_seq} carries a \
                             malformed gap record ({defect}); a gap that cannot be read must \
                             never account for an outage"
                        ),
                    },
                    n,
                );
            }
        };
        records.push(CamRecord {
            camera_id: camera_id.to_owned(),
            segment_seq,
            start_ns,
            end_ns,
            gap,
            policy_s,
            policy: CapturePolicy {
                nominal_segment_ms: ms(policy_s.0),
                jitter_ms: ms(policy_s.1),
                max_unexplained_gap_ms: ms(policy_s.2),
            },
        });
    }

    // The walk: per camera, in segment_seq order.
    records.sort_by(|a, b| (a.camera_id.as_str(), a.segment_seq).cmp(&(b.camera_id.as_str(), b.segment_seq)));
    let mut policies: Vec<CapturePolicy> = Vec::new();
    for r in &records {
        if !policies.contains(&r.policy) {
            policies.push(r.policy.clone());
        }
    }
    // segment_seq must be unique per camera: two records claiming the same
    // slot cannot both be the segment, and sorted-with-duplicates would
    // grade a fabricated timeline. Uniqueness plus the sort gives strictly
    // increasing sequences.
    for pair in records.windows(2) {
        if pair[0].camera_id == pair[1].camera_id && pair[0].segment_seq == pair[1].segment_seq {
            return CaptureReport::ungraded(
                CaptureGrade::Failed {
                    detail: format!(
                        "camera {:?} claims segment_seq {} more than once; duplicate sequences \
                         cannot be graded as a timeline",
                        pair[0].camera_id, pair[0].segment_seq
                    ),
                },
                n,
            );
        }
    }
    // A gap record must cite the boundary it stands on: after_seq equal to
    // the previous record's segment_seq for the SAME camera. A gap citing a
    // different boundary — another camera's, another segment's, or one this
    // session does not carry — is malformed: FAILED, never accounted.
    for (i, r) in records.iter().enumerate() {
        if let Some(g) = &r.gap {
            let prev = if i > 0 { Some(&records[i - 1]) } else { None };
            let prev_same = prev.filter(|p| p.camera_id == r.camera_id);
            let defect = match prev_same {
                None => Some(format!(
                    "cites after_seq {}, but this session carries no previous record for that camera",
                    g.after_seq
                )),
                Some(p) if p.segment_seq != g.after_seq => Some(format!(
                    "cites after_seq {}; the previous record of that camera is segment_seq {}",
                    g.after_seq, p.segment_seq
                )),
                Some(_) => None,
            };
            if let Some(defect) = defect {
                return CaptureReport::ungraded(
                    CaptureGrade::Failed {
                        detail: format!(
                            "camera {:?} segment_seq {} carries a gap record that {defect}; a gap \
                             citing a different boundary must never account for this one",
                            r.camera_id, r.segment_seq
                        ),
                    },
                    n,
                );
            }
        }
    }
    let mut grade = CaptureGrade::Continuous;
    let mut outages: Vec<CaptureOutage> = Vec::new();
    let mut overlaps: Vec<CaptureOverlap> = Vec::new();
    let mut uncovered_ms: i64 = 0;
    for pair in records.windows(2) {
        let (prev, cur) = (&pair[0], &pair[1]);
        if prev.camera_id != cur.camera_id {
            continue;
        }
        let (_, jitter_s, max_gap_s) = cur.policy_s;
        let hole_s = (cur.start_ns - prev.end_ns) as f64 / 1e9;
        if hole_s <= jitter_s {
            if hole_s < -jitter_s {
                overlaps.push(CaptureOverlap {
                    after_seq: prev.segment_seq,
                    seq: cur.segment_seq,
                    overlap_ms: ms(-hole_s),
                });
            }
            continue;
        }
        let (class, pair_grade) = if cur.gap.is_some() {
            ("accounted", CaptureGrade::InterruptedAccounted)
        } else if hole_s <= max_gap_s {
            ("tolerated", CaptureGrade::InterruptedAccounted)
        } else {
            ("unexplained", CaptureGrade::InterruptedUnexplained)
        };
        outages.push(CaptureOutage {
            after_seq: prev.segment_seq,
            seq: cur.segment_seq,
            hole_ms: ms(hole_s),
            class: class.to_owned(),
            gap_reason: cur.gap.as_ref().map(|g| g.reason.clone()),
        });
        uncovered_ms += ms(hole_s);
        if pair_grade.rank() > grade.rank() {
            grade = pair_grade;
        }
    }

    let detail = if outages.is_empty() {
        if overlaps.is_empty() {
            format!("{n} records; every segment boundary within the declared jitter")
        } else {
            format!(
                "{n} records; no uncovered time; {} boundary/ies beyond the declared jitter, all overlaps",
                overlaps.len()
            )
        }
    } else {
        format!(
            "{n} records; {} outage(s), {:.1} s not covered",
            outages.len(),
            uncovered_ms as f64 / 1000.0
        )
    };
    CaptureReport {
        grade,
        detail,
        camera_records: n,
        policies,
        outages,
        overlaps,
    }
}

/// Distinct `camera_id` values the carried camera records claim, across one
/// session. What the SIGNED PRODUCER says the source was — a claim the
/// boundary result names and does not endorse.
pub fn claimed_camera_ids(chain: &SessionChain, store: Option<&ArtifactStore>) -> Vec<String> {
    let Some(store) = store else { return Vec::new() };
    let mut ids: Vec<String> = Vec::new();
    for e in &chain.entries {
        if let Some(bytes) = store.get(&e.fields.artifact_hash) {
            if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
                let is_cam = v
                    .get("schema")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.starts_with("camera_segment/"));
                if is_cam {
                    if let Some(id) = v.get("camera_id").and_then(Value::as_str) {
                        if !ids.iter().any(|k| k == id) {
                            ids.push(id.to_owned());
                        }
                    }
                }
            }
        }
    }
    ids
}
