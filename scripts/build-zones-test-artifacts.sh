#!/usr/bin/env bash
# Earn vendors a partial IZone ABI. Build Earn first so Zones owns the final ABI.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
earn_root="${EARN_ROOT:-$repo_root/earn}"
contracts_root="$repo_root/crates/zones/contracts"

forge build --root "$earn_root" --skip test --skip script --no-lint \
  --out "$contracts_root/out"
forge build --root "$contracts_root" --no-lint
