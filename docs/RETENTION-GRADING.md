# Retention grading: a declared deletion, and what it is not

Evidence gets deleted on a schedule. A capture host ages out its outbox, an
O-node spool ages out `done/`. Deletion is the one thing an evidence system
does that looks exactly like the attack it exists to catch, so the producer
declares every batch first, in a producer-signed, chain-appended
`camera_retention/*` record naming the policy, the camera, the tier and the
exact digests removed. The full record shape is VIRP's, in
`camera/RETENTION.md` §2.

This document is what the **verifier** does with one, and — more
importantly — what it refuses to do.

## The one sentence

**A declared deletion is an ABSENT this bundle can account for. It is never
a pass.**

A retention record proves the operator *declared* the deletion, under a
producer key, at a chained time. It does not prove the bytes ever matched
their digests: nothing re-verified them on the way out. No verdict moves
because a deletion was explained.

## producer_signature covers camera_retention/*

`camera_segment/*` and `camera_retention/*` both carry `producer_key_id`
and `producer_sig` over the same canonical body-minus-`producer_sig`,
signed by the same capture-host key. They are graded by one code path and
one vocabulary — VERIFIED / FAILED / UNVERIFIABLE, keyed by
`producer_key_id`, with trust reported on its own axis. A retention record
is not a weaker record; it is a different statement signed by the same
hand.

### A schema this verifier does not examine grades ABSENT, and says so

    producer_signature  ABSENT  schema not examined by this verifier: the
                                carried bodies declare <schema> and no
                                producer-signed record (camera_segment/*,
                                camera_retention/*) is among them

Never a pass. Silence about an unexamined body reads as "checked and fine"
to anyone scanning a grade, which is the collapse this vocabulary exists to
prevent. "I did not look at this" and "there was nothing to look at" are
different facts and get different words.

## absent_by_declared_policy

When the exporter finds no bytes for a cited digest, and a carried
`camera_retention/*` record in the same export names that digest in
`removed[]`, the manifest row reads:

    { "sha256": "…", "present": false,
      "reason": "absent_by_declared_policy",
      "retention_session": "camera-retention:<camera>:<date>",
      "retention_sequence": N }

**The exporter verifies nothing.** It holds no producer key and judges
nothing. That row is a POINTER — where the claim is, not whether it holds.

`virp-verify` then re-reads the named record and re-checks it, all four:

1. the bundle carries it;
2. its bytes hash to the `artifact_hash` the chain committed to;
3. its `producer_sig` verifies under a key supplied out of band
   (`--producer-key`);
4. its `removed[]` actually lists this digest.

All four, and the citation reads:

    referenced_artifact_binding  ABSENT  … 1 not carried — ABSENT, not a
      pass (1 declared by a verified retention record, 0 undeclared)

Any of them failing, and the citation is plain ABSENT with the claim named:

    declaration NOT honoured  seq 7 cites <digest>, claimed declared by
      <session> seq N — <why it did not hold>

The failure is printed rather than dropped. A broken declaration is worse
than none, because someone wrote it down.

Declared and undeclared absences are counted apart, in the session line and
in the boundary summary. `absent - absent_declared` is the remainder an
examiner still has to chase.

## The pointer is a required pair

`retention_session` and `retention_sequence` are **both required**.

Chain sequences are per session and every session starts at 0. The
retention record always lives in a `camera-retention:` session, while the
citation lives in a `camera:` one. A bare `retention_sequence: 0` therefore
names a record in both sessions and identifies neither.

A citation carrying one without the other is **malformed, not merely
unresolved**:

    declaration NOT honoured  seq 7 cites <digest>, claims a declaration it
      does not identify — the citation claims absent_by_declared_policy but
      names no retention_session; the pair is required, so nothing
      identifies the record that would substantiate it

It grades **ABSENT** — a definite absence — and names the missing field.
Not UNVERIFIABLE: that word says the evidence could not be looked at, and
this is a defect in the manifest, not a question about the evidence. Not
plain `not_found` either, which would hide that a claim was written here at
all.

An unrecognised reason string is a different case again and stays
UNVERIFIABLE: an unknown reason may name a look that never happened, and
guessing which known absence it is would be the same collapse.

## Retention records are not capture

They are listed under their session:

    retention declaration  seq 0 capture-host  camera <id> — policy_days 30,
                                               removed_count 6

and they never reach the coverage grader. `capture_completeness` counts
`camera_segment/*` records only. Letting a deletion count as capture would
let an operator paper over an outage by deleting into it.
