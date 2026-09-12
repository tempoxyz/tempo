#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
checks=0

check() {
  local expected=$1 tag=$2 cargo_ver=$3 status=0
  bash "$script_dir/check-release-version.sh" "$tag" "$cargo_ver" >/dev/null 2>&1 || status=$?
  if [[ "$status" != "$expected" ]]; then
    echo "Tag '$tag' with Cargo '$cargo_ver': expected exit $expected, got $status" >&2
    exit 1
  fi
  checks=$((checks + 1))
}

for tag in v1.14.0 1.14.0 v1.14.0-rc.1 v1.14.0-alpha v1.14.0-beta.2 \
  v1.14.0-0 v1.14.0-0a v1.14.0-rc.1+build.001; do
  check 0 "$tag" 1.14.0
done

for tag in v1.14.00 v1.14.01 v1.14.0junk v1.14.1 v1.140.0 v11.14.0 \
  v1.14.0- v1.14.0-rc. v1.14.0-.rc v1.14.0-rc..1 v1.14.0-01 \
  v1.14.0-rc.01 v1.14.0-rc_1 v1.14.0-rc.1+ v1.14.0-rc.1+build..1 \
  v1.14.0+build.1 vv1.14.0 '' 'v1.14.0-rc.1 extra'; do
  check 1 "$tag" 1.14.0
done

# Exact Cargo prereleases and build metadata remain valid.
check 0 v1.14.0-rc.1 1.14.0-rc.1
check 1 v1.14.0-rc.10 1.14.0-rc.1
check 0 v1.14.0+build.1 1.14.0+build.1
check 1 v1.14.0-rc.1-rc.2 1.14.0-rc.1
check 1 v1.14.0+build.1-rc.1 1.14.0+build.1

# Missing metadata must never turn into a successful comparison.
check 1 '' ''
check 1 v ''
check 1 v1.14.0 ''
check 1 '' 1.14.0

printf 'Passed %s release version checks\n' "$checks"
