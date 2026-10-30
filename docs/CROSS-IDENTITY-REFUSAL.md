# Cross-identity refusal detection (`cross_identity_refusal`, EVADED_REFUSAL)

> A refusal from VIRP is a stop, not an obstacle. If an operation is refused
> under one identity, you do not retry it under another.

On 2026-10-29 an O-Node refused a `chain_append` for one uid with a bare
framed error — no chain entry — and ninety seconds later accepted the same
append from a different uid. Every entry the chain held was individually
valid. From 2026-10-30 the O-Node chains every refusal as a
`gate_rejection/2` body keyed on the canonical operation, refuses a different
uid's retry of the same operation while that refusal is live (and chains the
attempt as `refusal_evaded/1`), admits a retry after the window while
chaining `refusal_expired/1`, and clears a refusal early only through an
owner-signed `refusal_lifted/1`. This verifier reads those bytes
independently.

## What is graded

A bundle-level **boundary result** `cross_identity_refusal`, beside the
verdict, never inside it: the chain is intact either way. It is omitted
entirely when the bundle carries no refusal-class entry, so bundles exported
before the feature serialize unchanged.

| status | meaning |
|---|---|
| VERIFIED | refusal bodies read, operation keys recomputed, no accepted entry finished another identity's refused operation inside its window |
| FAILED | at least one `EVADED_REFUSAL` finding (below) |
| UNVERIFIABLE | refusals exist but the bundle carries no bodies for them (hash-only export); nothing could be keyed |

`EVADED_REFUSAL` names the refusal entry hash, the accepted entry hash, the
operation kind and key, both uids (the retry uid is `unknown` for externally
submitted entries, which carry no uid in chain bytes), both sessions, the gap
in seconds and the refusal's own TTL. `--fail-on-evasion` turns a FAILED
result into exit 7 when the chain is otherwise intact.

## Operation keys

Recomputed here, not read from the refusal body alone:

```text
execute       SHA256("VIRP-REFUSAL-OP/execute\0" || device || "\0" || canonical(command))
chain_append  SHA256("VIRP-REFUSAL-OP/chain_append\0" || artifact_type || "\0" || session_id || "\0" || artifact_hash)
```

`canonical()` trims leading whitespace, drops CR, collapses runs of space
and tab to one space, and strips trailing spaces — the O-Node's v2 command
canonicalization. Vectors are pinned in `refusal.rs` and must agree with the
daemon's `tests/test_onode.c`.

Accepted entries are `gate_intent` (the gate's admission), `gate_execution`
whose intent was not already reported, and every externally submitted type.

## Lifts

`refusal_lifted/1` is honoured only when the examiner supplies the approver
PUBLIC key that signed it (`--approver-key FILE`, 32 raw bytes or 64 hex
chars; `key_id = sha256(pub)[..16]`, the O-Node's `approvers.json`
convention) and the signature verifies over

```text
"VRL1" || refusal_entry_hash(32) || op_key(32) || be64 refused_uid || be64 lifted_at_ns
```

and the lift names an existing keyed refusal's hash, operation key and uid
exactly, and sits between the refusal and the retry. Anything else — no key
supplied, wrong key, bad signature, a lift naming a refusal that is not
there — does **not** clear the refusal. The finding then carries a note
saying which.

## What this cannot see

`gate_rejection/1` entries (every refusal before 2026-10-30) carry no uid
and no operation key; they are counted as `legacy_unkeyed` and nothing can
match them. A refusal the daemon never chained at all — the 2026-10-29 one
— is invisible to any reader of chain bytes, which is why the daemon now
chains them.
