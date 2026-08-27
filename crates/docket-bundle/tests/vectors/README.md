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
| `seal-2026-08.json` | `tools/seal/seal-2026-08.json` — the D-0 seal (virp-seal/1): 350 session heads, Merkle root, residual disclosure. Public document; the operator's real minisign signature lives beside it in the VIRP tree. Docket checks a seal signature only under an out-of-band `--seal-key` |

# Minisign TEST vectors (generated in the Docket tree, NOT from VIRP)

| file | what it is |
| --- | --- |
| `minisign-test.pub` | throwaway TEST minisign public key (minisign 0.11) |
| `seal-2026-08.json.test.minisig` | TEST signature over the `seal-2026-08.json` bytes above, made with that throwaway key. **Not the operator's signature.** The prehashed (`ED`, BLAKE2b-512) kind, with trusted comment and global signature — what current minisign emits |

The signing key is a THROWAWAY generated only so Docket's minisign
*verification* has a real vector; its unencrypted secret key is published
below on purpose (never a production key, attests nothing). The real D-0
seal key is different, its secret never enters this repository, and — as
with every key here — no key-role overlap may be inferred from test usage.

Regenerate with:

```sh
minisign -S -s minisign-test.key -m seal-2026-08.json \
  -t "Docket TEST signature over the vector seal (throwaway key; not the operator's signature)" \
  -x seal-2026-08.json.test.minisig
```

where `minisign-test.key` contains:

```text
untrusted comment: Docket TEST minisign key (throwaway; secret is published in the repo README)
RWQAAEIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWSkC0OxKdVq9C4qOk2clqHuqS+NXRtJz16k4WFHRGwxgTkgBI1j661rfqkA3EVKewmsA0nkuYc21cFGz1LGomVCdvkR+V8KKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

(Note: minisign randomizes a signature's bytes per run, so a regenerated
`.minisig` verifies but is not byte-identical to the committed one.)
