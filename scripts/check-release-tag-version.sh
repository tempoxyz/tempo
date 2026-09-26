#!/usr/bin/env bash
# Return 0 when TAG identifies CARGO_VER exactly or with a hyphen prerelease.
# Usage: check-release-tag-version.sh <tag> <cargo_ver>
set -euo pipefail

tag="${1:?tag required}"
cargo_ver="${2:?cargo version required}"
tag="${tag#v}"

if [[ "$tag" == "$cargo_ver" || "$tag" == "$cargo_ver"-* ]]; then
  exit 0
fi

echo "Tag $tag doesn't match the Cargo version $cargo_ver" >&2
exit 1
