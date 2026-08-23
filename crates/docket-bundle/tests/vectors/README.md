# Golden vectors (copied verbatim from the VIRP tree)

These are shared test FIXTURES, not source. They are the interoperability
contract between the VIRP C tree and Docket: both must agree byte-for-byte
on canonical bytes, hashes, key_ids and Ed25519 signatures.

| file | origin (VIRP tree, branch `feat/detached-chain-signing`, 545273a) |
| --- | --- |
| `chain-signing-v1.json` | `tests/vectors/chain-signing-v1.json` — D-1 Ed25519 detached-signing vectors (public test key; the seed is PUBLIC and is never loaded by Docket code — only `public_key_hex` is read) |
| `fixtures-appendix-a.json` | `tools/seal/fixtures-appendix-a.json` — D-0 Appendix A entries A–E, head, genesis, milestone (contains HMAC OUTPUTS only; no secret material) |

Do not edit. If a value here won't reproduce, that is a finding, not a
fixture to soften.
| `seal-2026-08.json` | `tools/seal/seal-2026-08.json` — the D-0 seal (virp-seal/1): 350 session heads, Merkle root, residual disclosure. Public document; its minisign signature lives beside it in the VIRP tree and is NOT checked by Docket yet |
