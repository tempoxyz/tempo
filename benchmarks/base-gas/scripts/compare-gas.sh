#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$PROJECT_DIR/../.." && pwd)
OUT_DIR="$PROJECT_DIR/out"
mkdir -p "$OUT_DIR"

BASE_JSON="$OUT_DIR/base-gas.json"
CURRENT_SNAPSHOT_DIR="$REPO_ROOT/crates/node/tests/it/gas/snapshots"
TIP1060_SNAPSHOT_DIR=${TIP1060_SNAPSHOT_DIR:-/tmp/tempo-rus-tip1060-gas/crates/node/tests/it/gas/snapshots}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-json)
      BASE_JSON=$2
      shift 2
      ;;
    --current-snapshots)
      CURRENT_SNAPSHOT_DIR=$2
      shift 2
      ;;
    --tip1060-snapshots)
      TIP1060_SNAPSHOT_DIR=$2
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

need_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing file: $1" >&2
    exit 1
  fi
}

need_dir() {
  if [[ ! -d "$1" ]]; then
    echo "missing directory: $1" >&2
    exit 1
  fi
}

need_file "$BASE_JSON"
need_dir "$CURRENT_SNAPSHOT_DIR"
need_dir "$TIP1060_SNAPSHOT_DIR"
command -v jq >/dev/null 2>&1 || {
  echo "missing required command: jq" >&2
  exit 1
}

snap_value() {
  local dir=$1
  local file=$2
  local key=$3
  local path="$dir/$file"
  need_file "$path"
  awk -F': ' -v key="$key" '$1 == key { print $2; found = 1 } END { if (!found) exit 1 }' "$path"
}

signed_diff() {
  local diff=$1
  if ((diff >= 0)); then
    echo "+$diff"
  else
    echo "$diff"
  fi
}

base_gas() {
  jq -r --arg scenario "$1" '.scenarios[$scenario].gas' "$BASE_JSON"
}

bridge_file=it__gas__tip1060_bridge_direct_swap__tip1060_bridge_direct_swap_t7_gas.snap
minimal_file=it__gas__tip1060_minimal_direct_swap__tip1060_minimal_direct_swap_t7_gas.snap
morpho_file=it__gas__tip1060_morpho_deposit__tip1060_morpho_deposit_t7_gas.snap
layerzero_file=it__gas__tip1060_layerzero_bridge__tip1060_layerzero_bridge_t7_gas.snap

current_bridge=$(snap_value "$CURRENT_SNAPSHOT_DIR" "$bridge_file" bridge_direct_swap)
tip1060_bridge=$(snap_value "$TIP1060_SNAPSHOT_DIR" "$bridge_file" bridge_direct_swap)
base_bridge=$(base_gas bridge_direct_swap)

current_minimal=$(snap_value "$CURRENT_SNAPSHOT_DIR" "$minimal_file" minimal_direct_swap)
tip1060_minimal=$(snap_value "$TIP1060_SNAPSHOT_DIR" "$minimal_file" minimal_direct_swap)
base_minimal=$(base_gas minimal_direct_swap)

current_morpho=$(snap_value "$CURRENT_SNAPSHOT_DIR" "$morpho_file" morpho_deposit)
tip1060_morpho=$(snap_value "$TIP1060_SNAPSHOT_DIR" "$morpho_file" morpho_deposit)
base_morpho=$(base_gas morpho_deposit)

current_layerzero=$(snap_value "$CURRENT_SNAPSHOT_DIR" "$layerzero_file" layerzero_bridge)
tip1060_layerzero=$(snap_value "$TIP1060_SNAPSHOT_DIR" "$layerzero_file" layerzero_bridge)
base_layerzero=$(base_gas layerzero_bridge)

OUTPUT="$OUT_DIR/comparison.md"
{
  echo "| use case | call(s) | Tempo current | Tempo TIP-1060 | Base-style surrogate | TIP-1060 vs Base | Base workflow |"
  echo "|---|---|---:|---:|---:|---:|---|"
  echo "| bridge_direct_swap | swapExactOut(address,address,uint256) | $current_bridge | $tip1060_bridge | $base_bridge | $(signed_diff "$((tip1060_bridge - base_bridge))") | auth plus wrapped-handler unwrap/wrap path |"
  echo "| minimal_direct_swap | swapExactOut(address,address,uint256) | $current_minimal | $tip1060_minimal | $base_minimal | $(signed_diff "$((tip1060_minimal - base_minimal))") | auth plus direct unwrap/wrap path |"
  echo "| morpho_deposit | approve(address,uint256); deposit(uint256,address) | $current_morpho | $tip1060_morpho | $base_morpho | $(signed_diff "$((tip1060_morpho - base_morpho))") | ERC20 approve plus ERC4626-style nested deposit |"
  echo "| layerzero_bridge | approve(address,uint256); approve(address,uint256); wrap(address,address,uint256); approve(address,uint256); sendBridge(address,uint256,address,uint256,address) | $current_layerzero | $tip1060_layerzero | $base_layerzero | $(signed_diff "$((tip1060_layerzero - base_layerzero))") | ERC20 approve/wrap/bridge/send path |"
} >"$OUTPUT"

cat "$OUTPUT"
echo
echo "Wrote $OUTPUT"
