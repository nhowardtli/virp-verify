# virp-verify 0.1.2

`virp-verify` reads a VIRP evidence bundle, recomputes its hashes, chain links,
Ed25519 signatures and RFC 9162 witness proofs, and prints which properties
hold — it never signs, never holds a private key, and never executes anything
from the bundle.

**Requirements:** Linux on **x86_64** — native, WSL2, or an x86_64 container
(`docker run --rm -it debian:stable-slim`) — with `curl`, `jq`, `minisign`,
`tar` and `sha256sum` installed. The released binary is x86_64 Linux only; on
Apple Silicon or arm Linux it will not run, and *Build it yourself* below is
your path.

## Everything, in one block

```sh
keys=https://raw.githubusercontent.com/nhowardtli/virp-verify/411d008a04eb9a52b3ade9a4afe58ae4b358099b/keys
mkdir -p virp-verify-0.1.2 && cd virp-verify-0.1.2
# Every release asset except the keys — those come from the commit above, which
# is dated and cannot be replaced, unlike a file attached to a release page.
curl -fsSL https://api.github.com/repos/nhowardtli/virp-verify/releases/tags/virp-verify-v0.1.2 \
  | jq -r '.assets[].browser_download_url' | grep -vE '\.(hex|keys\.json)$' \
  | xargs -n1 curl -fsSLO
for k in $(grep -oE '[^ ]+\.(hex|keys\.json)$' SHA256SUMS) seal-virp-ad48b20f-2026-09-05.pub; do
  curl -fsSL "$keys/$k" -o "$k"
done
sha256sum -c SHA256SUMS
minisign -Vm SHA256SUMS -p seal-virp-ad48b20f-2026-09-05.pub
tar -xzf axis-20260904-v6.tar.gz
chmod +x virp-verify
show='^virp-verify |^  (witness {16}|referenced_artifact_binding )[A-Z]|^OVERALL VERDICT'
./virp-verify axis-20260904-v6 | grep -E "$show"
./virp-verify \
    --pin          chain-313-c1104805-2026-08-28.hex \
    --producer-key producer-axis-m3085v-fae0d249-2026-09-03.hex \
    --witness-key  witness-virp-systems-2a771e12-2026-09-03.hex \
    axis-20260904-v6 | grep -E "$show"
```

`sha256sum -c` prints `OK` seven times and `minisign` prints `Signature and
comment signature verified`. The two runs print four lines each; the full
report is what you get without the `grep`.

---

## What you just saw

The same bundle, twice, with one difference: the second run was given three
public keys from outside the bundle.

    OVERALL VERDICT: CRYPTOGRAPHICALLY-CONSISTENT (signer trust not established)
    OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED

Nothing about the evidence changed between those two lines. Every hash, link
and signature verified in both runs. What changed is **where the verifying key
came from**. In the first run the only key available was the one carried inside
the bundle being examined, and a bundle that vouches for itself proves internal
consistency and nothing else — anyone can generate a keypair, sign fabricated
evidence, and ship the public half alongside it. In the second run the keys came
from a commit in this repository, chosen by you, which is what `--pin` means.

The witness line flips the same way and for the same reason: from
`UNVERIFIABLE` ("no `--witness-key` was supplied, so the signed tree head was
not checked under any key the examiner selected") to `VERIFIED` (leaf 476 of
tree 571, under a key you supplied). **UNVERIFIABLE is not a failure and not a
pass** — it is the verifier declining to grade something it was not given what
it needs to check. That distinction is the whole point of the tool.

`referenced_artifact_binding` does not flip, because it needs no key: the
verifier recomputes SHA-256 over the 51 artifacts the signed records cite — the
segment video, the validator's output about it, the device leaf certificate —
and compares each against the citing field. Which digests are cited is
re-derived from the signed bodies, never read from the unsigned manifest.

Everything above ran offline. After the downloads, neither run touched the
network: the witness result comes from an inclusion proof and a signed tree
head carried inside the bundle and recomputed here, and `--witness-url` — which
re-checks the carried tree against the log serving it now — is the only flag
that would go out and ask anyone anything.

## What CRYPTOGRAPHICALLY-VERIFIED does and does not mean

It means: every keyless property held, every signature verified, and the key
that verified them was one **you** supplied out of band.

It does **not** mean the entries are true, that the video shows what anyone says
it shows, or that any particular physical device produced it. No frame is
decoded and no scene is judged. `source_device_established` grades `NO` in this
very bundle, and says why. The verifier prints its own limits at the bottom of
every report — read them; they are the honest part.

## The trust boundary

Three keys, three separate boundaries, and none of them ever stands in for
another:

| key | what it says |
|---|---|
| `chain-313-c1104805-2026-08-28.hex` | the O-Node committed to this sequence (`--pin`) |
| `producer-axis-m3085v-fae0d249-2026-09-03.hex` | the capture host committed to these record bodies (`--producer-key`) |
| `witness-virp-systems-2a771e12-2026-09-03.hex` | an append-only log held this head at a stated time (`--witness-key`) |

A bundle carries key *ids*, never keys. The three above are published so this
sample is runnable, and **that convenience is also the weakness**: keys fetched
from a repository controlled by the same party that produced the evidence prove
rather less than keys that reach you by a route that party does not control. In
real work they arrive from someone whose word about them means something. The
witness key is also published independently at
<https://github.com/nhowardtli/virp-witness-heads>; prefer that copy.

## Exit codes

Deliberately not collapsed into pass/fail. `./virp-verify --help` lists them.
The two runs above exit `5` and `0` — the pipe into `grep` reports `grep`'s
status rather than the verifier's, so run them without it to see the codes.

## Build it yourself

If you will not run a stranger's binary — correct, for evidence work — build
your own. That is what the source is public for.

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/nhowardtli/virp-verify && cd virp-verify
rustup target add x86_64-unknown-linux-musl    # or aarch64-unknown-linux-musl
tools/release/build-verifier.sh
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.98.0) and `rustup`
selects it inside the repository, so you pass no version anywhere. The script
builds both musl targets, skips any you have not added, and writes
`dist/SHA256SUMS` with one line per target it built.

**The binary in this release was built at this release's tag.** That is a rule
now, not a coincidence:

```sh
git checkout virp-verify-v0.1.2
tools/release/build-verifier.sh
```

Compare what that writes against the `virp-verify` line of the `SHA256SUMS` you
downloaded and checked the signature on. The published hash is the one in that
manifest — this README does not repeat the number, and cannot: the commit is
compiled into the binary, so a README carrying its own build's hash would
change the commit that produced the hash it carries. The signed manifest is the
place that number can live honestly, and `docs/VERIFIER-RELEASE.md` sets out the
rule and why.

Check out the tag, not `main`. `virp-verify --version` reports the commit it was
built from and that string is compiled in, so a build from any other commit is a
different binary with a different hash by design — the binary cannot misreport
where it came from.

The aarch64 build has **no published hash to compare against**. It is a
different target: different machine code, linked with the `rust-lld` that ships
with the toolchain rather than the host `cc`, and stripped by `rustc` at link
time rather than by GNU `strip`. Its hash is not the x86_64 hash and never
could be. Reproducibility here is per-target, and only x86_64-musl has been
reproduced from separate clean clones at separate paths.

A different hash at the right tag and target means your build differed some
other way — a different `rustc`, different dependency versions, a different
`strip` — not "this one is bad".

## The seal key rotated

`SHA256SUMS.minisig` is signed with **`AD48B20F5D11CED6`**, generated
2026-09-05. The previous seal key, **`4F0B72D4DA341448`** (2026-08-23), is
**retained, not revoked**: it still verifies what it signed, notably
`seal-2026-08.json`, and it verifies nothing in this release. Trying the old
key against this signature fails with a key-id mismatch, which is the correct
outcome.

Both public halves are committed under [`keys/`](keys/), in commit
`411d008a04eb9a52b3ade9a4afe58ae4b358099b` — whose message says which key is
which, when each was generated and which host holds each private half, and
which carries an OpenTimestamps proof of its own date. A release asset can be
replaced silently; a commit cannot. The block above therefore takes every key
from that commit, and never from the release page.

The four bundle keys are *also* attached to the release, under the same bare
filenames `SHA256SUMS` uses, so a reader who downloads every asset by hand
passes `sha256sum -c` with nothing to arrange. **Those copies are byte-identical
to the ones in that commit, and you do not have to take that on faith:**
`SHA256SUMS` covers the keys, so writing the commit's copies over the downloaded
ones and re-running the check — exactly what the block above does — is the
check. The commit stays the canonical, dated source; the assets are a
convenience that the hashes keep honest.

## The repository

    crates/docket-bundle    the library: canonical bytes, hashing, signature
                            verification, bundle reading, witness proofs
    crates/virp-verify      the binary: CLI, report rendering, exit codes
    tools/release           the reproducible build recipe
    docs/VERIFIER-RELEASE.md   the long form on what a hash does and does not tell you

`cargo test --workspace` runs the suite, including the golden vectors under
`crates/docket-bundle/tests/vectors/`: chain signing, the seal, and the RFC 9162
witness vector set. The exporter that writes bundles is not here — the verifier
is a pure reader, which is what makes it publishable.

Apache License 2.0. See `LICENSE` and `NOTICE`.
