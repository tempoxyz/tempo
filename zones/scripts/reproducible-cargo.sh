#!/bin/sh
# Run a cargo command, optionally through sccache.
#
# Dockerfile.reproducible calls this for every reproducible cargo build. With
# ZONES_SCCACHE unset or 0 (releases, clean rebuilds, independent verifiers) it
# runs the command unchanged. Pull request candidate builds set ZONES_SCCACHE=1
# to reuse compiled crates from a BuildKit cache mount at /sccache. sccache only
# returns outputs rustc produced for the same inputs, so the binary is unchanged.
set -eu

if [ "${ZONES_SCCACHE:-0}" != 1 ]; then
  exec "$@"
fi

version=0.14.0
sha256=8424b38cda4ecce616a1557d81328f3d7c96503a171eab79942fad618b42af44
name="sccache-v${version}-x86_64-unknown-linux-musl"
tmp=$(mktemp -d)
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/sccache.tar.gz" \
  "https://github.com/mozilla/sccache/releases/download/v${version}/${name}.tar.gz"
echo "${sha256}  $tmp/sccache.tar.gz" | sha256sum -c - >/dev/null
tar -xzf "$tmp/sccache.tar.gz" -C "$tmp" "${name}/sccache"
install -m 0755 "$tmp/${name}/sccache" /usr/local/bin/sccache
rm -rf "$tmp"

export RUSTC_WRAPPER=/usr/local/bin/sccache SCCACHE_DIR=/sccache CARGO_INCREMENTAL=0
"$@"
sccache --show-stats
