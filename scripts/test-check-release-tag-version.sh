#!/usr/bin/env bash
# Regression matrix for scripts/check-release-tag-version.sh (#7541).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
check="$root/scripts/check-release-tag-version.sh"
cargo_ver=1.13.2

pass() {
  local tag="$1"
  if ! "$check" "$tag" "$cargo_ver" >/dev/null; then
    echo "EXPECTED ACCEPT: tag=$tag cargo=$cargo_ver" >&2
    exit 1
  fi
  echo "ACCEPTED tag=$tag cargo=$cargo_ver"
}

fail() {
  local tag="$1"
  if "$check" "$tag" "$cargo_ver" >/dev/null 2>&1; then
    echo "EXPECTED REJECT: tag=$tag cargo=$cargo_ver" >&2
    exit 1
  fi
  echo "REJECTED tag=$tag cargo=$cargo_ver"
}

pass v1.13.2
pass v1.13.2-rc.1
fail v1.13.20
fail v1.13.2junk
fail v1.13.3

echo "check-release-tag-version matrix ok"
