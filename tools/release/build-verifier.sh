#!/bin/sh
# Build the static virp-verify a stranger can run without a Rust toolchain.
#
# Three reviewers in a row had no Rust installed. This script produces one
# self-contained x86_64 Linux binary plus a SHA256SUMS file beside it, using
# the toolchain the repository pins.
#
# It does NOT sign anything, publish anything, tag anything or upload
# anything. A hash beside a binary on the same web page proves nothing about
# who built it; see docs/VERIFIER-RELEASE.md, which says so plainly.
#
# Usage:  tools/release/build-verifier.sh [output-dir]
#         (default output-dir: dist/)
set -eu

TARGET=x86_64-unknown-linux-musl
CRATE=virp-verify

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo"
[ -f Cargo.toml ] && [ -f rust-toolchain.toml ] || {
    echo "build-verifier: not at the repository root ($repo)" >&2
    exit 2
}

out_root=${1:-dist}

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "build-verifier: cannot read version from Cargo.toml" >&2; exit 2; }
out="$out_root/$CRATE-$version-$TARGET"

# The toolchain is whatever rust-toolchain.toml pins; print it so the build
# log names the compiler that produced the bytes.
echo "build-verifier: toolchain $(rustc --version) / $(cargo --version)"
echo "build-verifier: target   $TARGET"

rustup target list --installed 2>/dev/null | grep -qx "$TARGET" || {
    echo "build-verifier: target $TARGET is not installed." >&2
    echo "                rustup target add $TARGET   (needs network)" >&2
    exit 2
}

# Refuse to delete anything this script did not write. An output directory
# holding files we do not produce is somebody else's; overwriting it blind
# once cost a set of release notes from a previous build.
if [ -e "$out" ]; then
    stray=$(find "$out" -mindepth 1 -maxdepth 1 ! -name "$CRATE" ! -name SHA256SUMS -print -quit)
    if [ -n "$stray" ]; then
        echo "build-verifier: $out holds files this script did not write (e.g. $stray)." >&2
        echo "                Move it aside, or pass a different output directory." >&2
        exit 2
    fi
    rm -rf "$out"
fi

# Absolute paths from THIS machine otherwise land in panic messages and debug
# strings, so two builds of the same source in different directories differ.
# Remapping them is what makes the output a function of the source.
CARGO_INCREMENTAL=0
RUSTFLAGS="--remap-path-prefix=$repo=/docket --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
export CARGO_INCREMENTAL RUSTFLAGS

cargo build --release --locked --target "$TARGET" -p "$CRATE"

mkdir -p "$out"
cp "target/$TARGET/release/$CRATE" "$out/$CRATE"
chmod 0755 "$out/$CRATE"
strip "$out/$CRATE"

( cd "$out" && sha256sum "$CRATE" > SHA256SUMS )

echo
echo "build-verifier: wrote $out/$CRATE"
sed 's/^/build-verifier: /' "$out/SHA256SUMS"
echo "build-verifier: check it with:  cd $out && sha256sum -c SHA256SUMS"
echo "build-verifier: nothing was signed, tagged or uploaded."
