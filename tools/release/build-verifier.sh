#!/bin/sh
# Build the static virp-verify a stranger can run without a Rust toolchain.
#
# Three reviewers in a row had no Rust installed. This script produces one
# self-contained Linux binary per target plus a SHA256SUMS naming all of
# them, using the toolchain the repository pins.
#
# It does NOT sign anything, publish anything, tag anything or upload
# anything. A hash beside a binary on the same web page proves nothing about
# who built it; see docs/VERIFIER-RELEASE.md, which says so plainly.
#
# Usage:  tools/release/build-verifier.sh [output-dir]
#         TARGETS="..." tools/release/build-verifier.sh   (override the list)
#         (default output-dir: dist/)
set -eu

TARGETS=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}
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

# The toolchain is whatever rust-toolchain.toml pins; print it so the build
# log names the compiler that produced the bytes.
echo "build-verifier: toolchain $(rustc --version) / $(cargo --version)"
echo "build-verifier: targets   $TARGETS"

installed=$(rustup target list --installed 2>/dev/null || true)

mkdir -p "$out_root"
: > "$out_root/SHA256SUMS.tmp"
built=0

for target in $TARGETS; do
    # A reader on one architecture should still get their own binary rather
    # than an error about somebody else's. Skip what is not installed, name
    # the command that would install it, and fail only if nothing is left.
    echo "$installed" | grep -qx "$target" || {
        echo "build-verifier: skipping $target (not installed: rustup target add $target)" >&2
        continue
    }

    out="$out_root/$CRATE-$version-$target"

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

    # Absolute paths from THIS machine otherwise land in panic messages and
    # debug strings, so two builds of the same source in different directories
    # differ. Remapping them is what makes the output a function of the source.
    flags="--remap-path-prefix=$repo=/docket --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

    # x86_64 links with the host `cc` and is stripped afterwards by the host
    # `strip`: that pipeline produced the published 0.1.0 hash and is left
    # exactly as it was. aarch64 cannot use either on an x86_64 host — GNU
    # strip does not recognise the format — so it links with the rust-lld
    # that ships with the toolchain and has rustc strip at link time. Same
    # source, different machinery: see docs/VERIFIER-RELEASE.md on why the
    # two hashes are not comparable and never will be.
    case "$target" in
    aarch64-*) flags="$flags -C linker=rust-lld -C strip=symbols" ;;
    esac

    CARGO_INCREMENTAL=0 RUSTFLAGS="$flags" \
        cargo build --release --locked --target "$target" -p "$CRATE"

    mkdir -p "$out"
    cp "target/$target/release/$CRATE" "$out/$CRATE"
    chmod 0755 "$out/$CRATE"
    case "$target" in
    aarch64-*) : ;;  # already stripped at link time
    *) strip "$out/$CRATE" ;;
    esac

    ( cd "$out_root" && sha256sum "$CRATE-$version-$target/$CRATE" ) >> "$out_root/SHA256SUMS.tmp"
    built=$((built + 1))
done

[ "$built" -gt 0 ] || {
    rm -f "$out_root/SHA256SUMS.tmp"
    echo "build-verifier: no target in \"$TARGETS\" is installed; nothing was built." >&2
    exit 2
}

mv "$out_root/SHA256SUMS.tmp" "$out_root/SHA256SUMS"

echo
sed 's/^/build-verifier: /' "$out_root/SHA256SUMS"
echo "build-verifier: check them with:  cd $out_root && sha256sum -c SHA256SUMS"
if [ "$built" -gt 1 ]; then
    echo "build-verifier: one hash per target; different machine code, never the same hash."
fi
echo "build-verifier: nothing was signed, tagged or uploaded."
