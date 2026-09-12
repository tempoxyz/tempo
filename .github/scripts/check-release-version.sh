#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || -z ${1-} || -z ${2-} ]]; then
  echo "Usage: check-release-version.sh <tag> <cargo-version> (both nonempty)" >&2
  exit 1
fi

tag=${1#v}
cargo_ver=$2

if [[ "$tag" == "$cargo_ver" ]]; then
  exit 0
fi

# Cargo can use the base version while release tags add a SemVer prerelease.
# Numeric prerelease identifiers cannot have leading zeroes; build metadata can.
# A Cargo version that already has a suffix must match exactly.
identifier='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
prerelease="^${identifier}(\.${identifier})*(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$"
if [[ "$cargo_ver" != *[-+]* && "$tag" == "$cargo_ver"-* && "${tag#"$cargo_ver"-}" =~ $prerelease ]]; then
  exit 0
fi

echo "Tag $tag doesn't match the Cargo version $cargo_ver" >&2
exit 1
