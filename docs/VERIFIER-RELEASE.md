# Building and checking `virp-verify`

`virp-verify` is the standalone verifier. It reads a Docket evidence bundle,
recomputes the hashes, links and Ed25519 signatures, and prints which
properties hold. It never signs, never holds a private key, and never
executes anything from the bundle.

This document is for someone who has been handed a bundle and a binary and
wants to know what they are running.

## What you can and cannot conclude from the hash

You can conclude: **the bytes you have are the bytes whoever wrote
`SHA256SUMS` had.**

You cannot conclude: that those bytes came from this source, or from anyone
in particular. A hash published beside the file it describes, on a page
controlled by whoever produced both, is a download-integrity check and
nothing more. Nothing in this release is signed, and this document will not
imply otherwise.

If that is not good enough for what you are doing — and for evidence work it
should not be — **build it yourself** from the source. It takes one command
and produces the same bytes; see *Reproducibility* below.

## Checking a binary you were given

```
sha256sum -c SHA256SUMS
```

Run it in the directory holding both files. It prints `virp-verify: OK` or
it fails. If you were given the hash by some other route than the file next
to the binary — a different channel, a different person, a printout — that
comparison is worth more, and it is the only version of this check that adds
anything.

## Building it yourself

### The toolchain

The repository pins the toolchain in `rust-toolchain.toml`:

```
channel = "1.98.0"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

`rustup` reads that file and selects 1.98.0 automatically inside the
repository — you do not pass a version anywhere. If you do not have rustup:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-musl
```

`rustup target add` is the only step that needs the network beyond the
initial install and the crate download. The musl target is what makes the
result a single file that runs on a machine with no Rust, no `libc` and no
shell.

### The command

```
tools/release/build-verifier.sh
```

That is the whole recipe. It:

1. prints the exact `rustc` and `cargo` versions it is about to use;
2. builds `virp-verify` for `x86_64-unknown-linux-musl` with `--locked`, so
   the dependency versions are the ones in `Cargo.lock` and not whatever is
   newest today;
3. strips the binary;
4. writes `SHA256SUMS` beside it;
5. prints the hash and the command to check it.

Output lands in `dist/virp-verify-<version>-x86_64-unknown-linux-musl/`.
Pass a directory as the first argument to put it elsewhere.

The script does not sign, tag, publish or upload anything, and it never
will: those are decisions for a person.

## Reproducibility

The build is **path-independent and reproducible**: the same source, on the
same toolchain, produces the same bytes regardless of where the source tree
sits on disk.

This is not automatic. Absolute paths from the build machine otherwise end
up inside panic messages and debug strings, so two builds of identical
source in different directories differ. The script sets:

```
CARGO_INCREMENTAL=0
RUSTFLAGS="--remap-path-prefix=<repo>=/docket --remap-path-prefix=<cargo home>=/cargo"
```

which is what makes the output a function of the source rather than of the
machine.

Verified on 2026-09-02, toolchain 1.98.0, three builds:

| build | source tree | sha256 |
|-------|-------------|--------|
| 1 | the repository | `34b0f845054d66ac7a05f236e76614b8e0ef74d5e3f812ba0395adf6f4b5d89d` |
| 2 | the repository, `target/x86_64-unknown-linux-musl` deleted first | same |
| 3 | a copy of the tree at an unrelated absolute path | same |

Build 3 is the one that matters: a rebuild in place proves little, and two
different paths producing one hash is the claim.

What is **not** pinned, and would change the bytes: a different `rustc`
(hence the `rust-toolchain.toml` pin), a different target, different
dependency versions (hence `--locked`), and a different `strip`. Reproduce
on the pinned toolchain or expect a different hash — a mismatch means "these
were built differently", not "this one is bad".

## Confirming the binary behaves like the one you would build

The musl binary was checked against the ordinary glibc release build on the
Sep 1 reference bundle: byte-identical stdout and the same exit code. If you
build both, you can repeat that:

```
diff <(./dist/*/virp-verify BUNDLE) <(cargo run --release -q -p virp-verify -- BUNDLE)
```

## Running it

```
./virp-verify <bundle-dir>
./virp-verify --pin <examiner-key.json> <bundle-dir>
./virp-verify --json <bundle-dir>
./virp-verify --help
```

`--pin` is the one that matters. Without it a bundle can only be checked
against the key it carries, which proves internal consistency and nothing
about who produced it — anyone can generate a keypair, sign fabricated
evidence and ship the public half alongside. `--pin` takes either accepted
key form: 64 hex characters, or a docket `keys.json`.

The exit codes are deliberately not collapsed into pass/fail; run
`--help` for the list.
