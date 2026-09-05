# virp-verify

The standalone verifier for VIRP evidence bundles, and the library it reads
them with.

`virp-verify` reads a bundle, recomputes the hashes, links and Ed25519
signatures, and prints which properties hold. **It never signs, never holds a
private key, and never executes anything from the bundle.** Built for the musl
target it is one static x86_64 Linux file: no runtime, no libc, no installer.

This repository exists so that a reader handed a binary can build their own and
compare hashes. If you would not run a stranger's executable over evidence —
and you should not — this is the answer to that.

## Build it

    rustup target add x86_64-unknown-linux-musl
    tools/release/build-verifier.sh

The toolchain is pinned in `rust-toolchain.toml`; `rustup` selects it
automatically inside this repository, so you pass no version anywhere. Output
lands in `dist/virp-verify-0.1.0-x86_64-unknown-linux-musl/`, with a
`SHA256SUMS` beside it.

The build is **path-independent and reproducible**: the script sets
`CARGO_INCREMENTAL=0` and remaps absolute paths out of the binary, so the same
source on the same toolchain produces the same bytes wherever the tree sits on
disk. `--locked` holds the dependency versions to `Cargo.lock`.

`docs/VERIFIER-RELEASE.md` is the long form: what a hash does and does not tell
you, what is pinned, and what would change the bytes.

### The binary names the commit it was built from

    $ virp-verify --version
    virp-verify 0.1.0 (commit <short>, clean, release)

That string is compiled in, so **two builds from different commits are
different binaries by design**, even when every other input matches. A release
hash therefore belongs to one tagged commit in this repository, and checking
out that tag is what reproduces it.

## Run it

    virp-verify --help
    virp-verify <bundle-dir>
    virp-verify --pin <examiner-key> <bundle-dir>

`--pin` is the one that matters. Without it a bundle can only be checked
against the key it carries, which proves internal consistency and nothing about
who produced it — anyone can generate a keypair, sign fabricated evidence and
ship the public half alongside.

Exit codes are deliberately not collapsed into pass/fail; `--help` lists them.

## Tests

    cargo test --workspace

Includes the golden vectors under `crates/docket-bundle/tests/vectors/`: chain
signing, the seal, and the RFC 9162 witness vector set (8 leaves, 8 signed tree
heads, 36 inclusion proofs, 36 consistency proofs). The witness proof algorithms
are transcribed from the RFC here rather than shared with the witness's own
implementation, precisely so that the two can disagree and the vectors can catch
it.

## Layout

    crates/docket-bundle    the library: canonical bytes, hashing, signature
                            verification, bundle reading, witness proofs
    crates/virp-verify      the binary: CLI, report rendering, exit codes
    tools/release           the reproducible build recipe
    docs/VERIFIER-RELEASE.md

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
