#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
zones_revision="$(tr -d '[:space:]' < "$repo_root/crates/contracts/ZONES_REVISION")"
workdir="$(mktemp -d)"
anvil_log="$workdir/anvil.log"

cleanup() {
  if [[ -n "${anvil_pid:-}" ]]; then
    kill "$anvil_pid" 2>/dev/null || true
    wait "$anvil_pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

git clone --quiet https://github.com/tempoxyz/zones.git "$workdir/zones"
git -C "$workdir/zones" checkout --quiet "$zones_revision"
git -C "$workdir/zones" submodule update --init --recursive --quiet

anvil --silent >"$anvil_log" 2>&1 &
anvil_pid=$!
rpc_url="http://127.0.0.1:8545"
for _ in {1..50}; do
  if cast block-number --rpc-url "$rpc_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
cast block-number --rpc-url "$rpc_url" >/dev/null

deployment="$({
  cd "$workdir/zones/specs/ref-impls"
  forge create src/tempo/ZonePortal.sol:ZonePortal \
    --broadcast \
    --json \
    --rpc-url "$rpc_url" \
    --private-key ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
})"
portal_address="$(jq -r '.deployedTo' <<<"$deployment")"
local_runtime="$(cast code "$portal_address" --rpc-url "$rpc_url" | tr '[:upper:]' '[:lower:]')"
tempo_runtime="$({
  sed -n '/pub const ZONE_PORTAL_RUNTIME/,/^);/p' \
    "$repo_root/crates/contracts/src/zones.rs" \
    | grep -oE '"[0-9a-fx]+"' \
    | tr -d '"\n'
} | tr '[:upper:]' '[:lower:]')"

without_metadata() {
  local bytecode="${1#0x}"
  local metadata_length=$((16#${bytecode: -4} + 2))
  echo "0x${bytecode:0:${#bytecode} - metadata_length * 2}"
}

local_executable="$(without_metadata "$local_runtime")"
tempo_executable="$(without_metadata "$tempo_runtime")"

if [[ "$local_executable" != "$tempo_executable" ]]; then
  echo "ZonePortal executable mismatch for zones@$zones_revision" >&2
  echo "local: $(cast keccak "$local_executable")" >&2
  echo "tempo: $(cast keccak "$tempo_executable")" >&2
  exit 1
fi

echo "ZonePortal executable matches zones@$zones_revision ($(cast keccak "$tempo_executable"))"
