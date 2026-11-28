#!/usr/bin/env bash
# Earn vendors a partial IZone ABI. Build Earn first so Zones owns the final ABI.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
earn_root="${EARN_ROOT:-$repo_root/earn}"
# A checkout of tempoxyz/contracts may hold Earn as its earn/ project rather than at its root.
if [[ -f "$earn_root/earn/foundry.toml" ]]; then earn_root="$earn_root/earn"; fi
contracts_root="$repo_root/crates/zones/contracts"
# Earn may name its own compiler wrapper (solar-solc). Forge resolves it from its working directory,
# so pass it absolutely, and only to Earn's build: the Zones contracts keep their pinned solc.
earn_env=()
if [[ -x "$earn_root/solar-solc" ]]; then earn_env=(FOUNDRY_SOLC="$earn_root/solar-solc"); fi
# A single-project checkout of tempoxyz/contracts also holds the Zone router, card spend, and vendored
# copies of Zones contracts. Build only Earn and its demo fixtures so none of those reach Zones' out/.
earn_paths=()
if [[ -d "$earn_root/src/earn" ]]; then earn_paths=("$earn_root/src/earn" "$earn_root/src/demo"); fi

env ${earn_env[@]+"${earn_env[@]}"} forge build --root "$earn_root" --skip test --skip script --no-lint \
  --out "$contracts_root/out" ${earn_paths[@]+"${earn_paths[@]}"}
forge build --root "$contracts_root" --no-lint
