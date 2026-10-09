# Evidence bundle contract: docket-bundle/0.1

This document describes the reader and exporter at **virp-verify-v0.1.3**,
commit `c38c4f8828bee1509fc0df1a88db27b4e7ea2cad`. It does not introduce a
new format, change the verifier, or specify future verifier behavior.
The release reports `docket-report/0.9`; that is an output report version,
not the bundle version. `virp-evidence-bundle/0.3` is not an accepted value
for this reader's `docket_bundle_version` field.

Source references below refer to this exact commit. The implementation
controls where a detail is not restated here:

- [Bundle reader and manifest](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/crates/docket-bundle/src/bundle.rs)
- [Chain types and grading](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/crates/docket-bundle/src/verify.rs)
- [Canonical bytes](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/crates/docket-bundle/src/canonical.rs)
- [Detached signatures](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/crates/docket-bundle/src/sig.rs)
- [Exporter](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/tools/export/export_bundle.py)
- [Witness material](https://github.com/nhowardtli/virp-verify/blob/c38c4f8828bee1509fc0df1a88db27b4e7ea2cad/crates/docket-bundle/src/witness.rs)

## 1. Container and manifest

The CLI reads a **directory**, with `manifest.json` at its root. An archive
is transport packaging and must be safely extracted before verification.
Referenced paths are relative to this directory. Absolute paths, parent
components and symlinks below the root are rejected. The reader enforces
resource limits and rejects duplicate session identities and paths.
Do not permit concurrent modification of a bundle during verification;
the source documents a residual path-check/open race.

Minimal manifest shape:

```json
{
  "docket_bundle_version": "docket-bundle/0.1",
  "chain_format": "v1",
  "sessions": [{"session_id": "example", "path": "sessions/example.json"}]
}
```

| Field | Shape and meaning |
| --- | --- |
| `docket_bundle_version` | Required string, exactly `docket-bundle/0.1`. |
| `chain_format` | Required string, exactly `v1`. |
| `sessions` | Required list of `{session_id, path}`; file identity must match. |
| `producer`, `created_at` | Optional strings describing the exporter and export time; not chain-signed timestamps. |
| `keys` | Optional relative path to the public key file. |
| `seal` | Optional relative path to a `virp-seal/1` document. |
| `seal_signature` | Optional relative path to its detached minisign signature; requires a seal. |
| `artifacts` | Optional list of `{artifact_hash, path}` carrying exact artifact-body bytes. |
| `referenced_artifacts` | Optional citation carriage list described below. |
| `redaction` | Optional exporter withholding metadata described below. |
| `witness` | Optional witness carriage block described below. |

The reader hashes the raw manifest bytes for report identification. That
hash is not, by itself, a signature or an authentication of manifest claims.

## 2. Session, entries and heads

A session file contains `session_id`, `entries` and optional `head`.
Entries carry the following twelve fields, flattened at the entry's top
level. Their exact order in the **canonical bytes** is:

```text
artifact_hash, artifact_hash_alg, artifact_id, artifact_schema_version,
artifact_type, monotonic_ns, previous_entry_hash, sequence, session_id,
signer_node_id, signer_org_id, timestamp_ns
```

All are strings except `monotonic_ns` and `timestamp_ns` (unsigned 64-bit),
`sequence` (signed 64-bit), and `signer_node_id` (unsigned 32-bit).
The canonicalizer writes compact fixed-order text, integers in decimal,
and string contents **raw without JSON escaping**. It is not a generic
JSON canonicalization algorithm. `serde_json` serialization of arbitrary
objects is not a replacement. Reader validation also rejects unencodable
identifier content; see `validate_session_input` and the golden vectors.

Each entry additionally carries required `chain_entry_hash` and optional
`canonical_utf8`, `chain_hmac`, and `signature`. `chain_entry_hash` is
SHA-256 of the twelve-field canonical bytes. A carried `canonical_utf8`
must reproduce those bytes exactly. These additional fields are excluded
from the canonical input.

The first previous hash is:

```text
hex(SHA256("VIRP_CHAIN_GENESIS:" || session_id))
```

Entries are checked for their hashes, links, sequence contiguity and
session binding. The optional head contains `session_id`, `last_sequence`,
`last_entry_hash`, and optional `canonical_utf8`, `head_hmac`, `signature`.
Its canonical bytes are exactly:

```text
{"last_entry_hash":"…","last_sequence":N,"session_id":"…","v":"VIRP-CHAIN-HEAD-v1"}
```

A head must commit to the carried session's sequence and final entry hash.
A new producer must emit these existing fields; names such as `prev_hash`,
`seq`, `entry_hash` and `sig` in an application design are not replacements
for the bundle's wire names.

## 3. Signatures and public keys

A detached signature object is:

```json
{
  "signature_scheme": "ed25519-detached-v1",
  "signing_key_id": "32 lowercase hexadecimal characters",
  "signature_hex": "128 hexadecimal characters"
}
```

The signed messages are:

```text
entry: "VIRP-CHAIN-ENTRY-SIG-v1" || 0x00 || entry_canonical_bytes
head:  "VIRP-CHAIN-HEAD-SIG-v1"  || 0x00 || head_canonical_bytes
```

**Signing `entry_hash` alone is not D-1 compatible.** The domain tags and
terminating NUL are required. Neither domain tag enters the entry hash.
Key IDs are the first 16 bytes of SHA-256 of the raw 32-byte public key,
encoded as 32 lowercase hexadecimal characters. The verifier enforces
session-level signing-key binding; rotation must not be assumed to permit
mixing signing keys within one signed session.

A manifest-carried key file is `{"keys": [...]}`; each row contains
`key_id`, `algorithm: "ed25519"`, `public_key_hex`, and optional `comment`.
Claimed IDs are checked against the key bytes. Carried public keys establish
internal consistency, not examiner trust. `--pin` accepts an out-of-band
key file or raw public key encoded as 64 hex characters. Public test keys
are fixtures, never production trust anchors. Private keys are not bundle
content.

## 4. Artifact bodies, citations and redaction

`artifact_hash` commits to exact body bytes. When `artifacts` carries those
bytes, the verifier recomputes their SHA-256. Application fields such as
command, output, rationale, redactions and peer identity can be content of
an artifact body; the twelve-field chain envelope does not define their
schema or interpret their truth.

The existing exporter recovers bodies from its snapshot database as UTF-8
TEXT or decoded `base64:` envelopes. It preserves evidence even when the
stored body and recorded hash disagree; verification then detects the
mismatch. It never repairs chain rows, hashes, signatures or numbering.

`referenced_artifacts` rows have required `sha256` and `present`; optional
`path`, `reason`, `retention_sequence`, `retention_session`; and default-empty
`cited_by` rows with `session_id`, optional `segment_seq`, and `field`.
These are exporter claims. The grader re-derives supported camera citations
from carried bodies and checks actual referenced bytes. Retention pointers
are honored only after checking the carried retention declaration and its
producer signature. Declared deletion remains absence, never proof of the
deleted bytes or a passing content check.

`redaction` contains `policy`, `entries_withheld`, and default-empty
`withheld` rows containing `artifact_hash`, `bytes`, default-zero
`spans_masked` and default-false `unclassifiable`. This manifest block is
unsigned explanatory metadata. Existing `--redacted` export **withholds**
affected bodies and preserves their original hashes; it does not replace
body bytes and pretend the old hashes still match. Scrubbing before a new
producer hashes its own body is a separate producer operation.

## 5. Seal and witness material

Seal bytes and optional detached minisign signature are carried unchanged.
The examiner provides the seal verification key out of band through
`--seal-key`; a claimed in-band seal public key is not a trust anchor.

The `witness` manifest object contains `witness_url`, optional
`witness_key_id`, `sth` (relative path), `tree_size`, and `sessions`.
Each session row has `session_id`, `present`, and optional `path` and
`reason` (`not_submitted`, `unreachable`, or `lookup_failed`).

The STH file uses `v: "docket-witness-sth/1"`, `witness_url`,
`witness_key_id`, `fetched_at`, and `sth_served` (the exact served response
as a string). A proof file uses `v: "docket-witness-proof/1"`, `session_id`,
`leaf`, `leaf_index`, `tree_size`, `audit_path`, and `proof_served`.
The pinned `witness.rs` defines leaf and signed-tree-head fields and their
canonical messages; a producer must reuse those constructions unchanged.

`--witness-key` supplies examiner trust. Offline inclusion verification
checks the signed tree head, RFC 9162 audit path, and correspondence with
the session's own head. It does not prove the truth of an action, a physical
device's identity, or that a daemon's receive timestamp is accurate.
Live consistency checking is separately requested using `--witness-url`.

The exporter fetches witness material only with `--witness`. It reads
local submission receipts to identify leaf indices, matches receipts by
head identity, and fetches proofs. Exporting does not submit heads. A new
daemon must separately implement submission and receipt custody.

## 6. Extensions: compatibility, not authentication

The v0.1.3 `Manifest` deserializer ignores unknown top-level fields.
The witnessd work order names two such fields:

```json
{
  "content_tier": "self-reported",
  "mode": "witness"
}
```

The alternative labels are `observed` and `tap`. These are witnessd's
proposed descriptive vocabulary, not values validated by v0.1.3. The fields
are placed at the manifest top level, not inside a new `extensions` object.
An unchanged v0.1.3 accepts them but neither reports nor grades them.

**These manifest labels are unsigned and mutable.** Changing a label does
not break a chain signature. The report's manifest digest changes, but
without an authenticated reference that does not establish the label's
truth. A consumer must not elevate manifest labels into verified provenance.
Where per-entry labels are to be cryptographically bound, an application
must put them in the carried body whose bytes `artifact_hash` commits to
and verify that binding. This document does not invent a witnessd body
schema, a mixed-tier summary representation, or a new verifier grade.

Compatibility was checked with the published x86_64 v0.1.3 binary and the
repository's synthetic `inv-lock-bundle` fixture, pinning its public TEST
key solely for the test. Baseline, added `self-reported`/`witness`, and added
`observed`/`tap` each exited 0 with identical session grading. Corrupting the
first entry's **actual** `chain_entry_hash` while retaining the extensions
exited 1 with verdict `failed`. This proves extension tolerance and continued
hash checking; it does not prove observed capture or authenticated labels.

## 7. Grading and exporter limits

The CLI reports independent properties; a successful chain verdict is not
an assertion that all optional evidence exists or all application content
was examined. Exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | Cryptographically verified under examiner-pinned chain keys. |
| 1 | A checked property failed. |
| 2 | Unreadable bundle or usage error; no verification verdict. |
| 3 | Operator-attested, unverifiable authenticity. |
| 4 | Consistent, unauthenticated. |
| 5 | Cryptographically consistent without examiner-pinned signer trust. |
| 6 | Coverage failure requested by `--fail-on-coverage`, when the cryptographic verdict did not fail. |

HMACs cannot be verified by this public-key-only verifier. Their presence
is not a cryptographic pass; malformed or incomplete HMAC material can fail.
Producer-signature grading examines `camera_segment/*` and
`camera_retention/*`. A fully carried session containing only a new witnessd
schema grades producer `ABSENT`, trust `UNESTABLISHED`, explaining that the
schema was not examined. Uncarried bodies can instead yield `UNVERIFIABLE`.
No generic producer grading or content-tier reporting is supplied by this
release.

The exporter is a read-only snapshot exporter, not a signer. It requires a
new output directory, discovers optional database columns, and copies their
values without canonical repair. `SOURCE_DATE_EPOCH` fixes `created_at`
for reproducible exports. Optional keys, bodies, redaction, citations, seal
and witness features are enabled by its corresponding flags. The exporter
does not currently generate the two witnessd manifest extension fields.
