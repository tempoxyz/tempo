#!/usr/bin/env bash
# Earn vendors a partial IZone ABI. Build Earn first so Zones owns the final ABI.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
earn_root="${EARN_ROOT:-$repo_root/earn}"
# A checkout of tempoxyz/earn may hold Earn as its earn/ project rather than at its root.
if [[ -f "$earn_root/earn/foundry.toml" ]]; then earn_root="$earn_root/earn"; fi
contracts_root="$repo_root/crates/zones/contracts"
# Earn may name its own compiler wrapper (solar-solc). Forge resolves it from its working directory,
# so pass it absolutely, and only to Earn's build: the Zones contracts keep their pinned solc.
earn_env=()
if [[ -x "$earn_root/solar-solc" ]]; then earn_env=(FOUNDRY_SOLC="$earn_root/solar-solc"); fi

env ${earn_env[@]+"${earn_env[@]}"} forge build --root "$earn_root" --skip test --skip script --no-lint \
  --out "$contracts_root/out"
forge build --root "$contracts_root" --no-lint
