#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
OUT_DIR="$PROJECT_DIR/out"
mkdir -p "$OUT_DIR"

export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

BASE_RPC_URL=${BASE_RPC_URL:-https://mainnet.base.org}
BASE_FORK_BLOCK=${BASE_FORK_BLOCK:-}
PORT=${PORT:-8550}
ANVIL_RPC_URL=${ANVIL_RPC_URL:-}
DEPLOYER_PK=${DEPLOYER_PK:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}
USER_PK=${USER_PK:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}
GAS_LIMIT=${GAS_LIMIT:-10000000}

DIRECT_SWAP_AMOUNT=4000000000
MINIMAL_SWAP_AMOUNT=4000000000
MORPHO_DEPOSIT_AMOUNT=1200000000
LAYERZERO_BRIDGE_AMOUNT=922346250
LAYERZERO_WRAP_AMOUNT=108287

ANVIL_PID=""
cleanup() {
  if [[ -n "$ANVIL_PID" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
    wait "$ANVIL_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need anvil
need cast
need forge
need jq

if [[ -z "$ANVIL_RPC_URL" ]]; then
  ANVIL_RPC_URL="http://127.0.0.1:$PORT"
  anvil_args=(--host 127.0.0.1 --port "$PORT" --chain-id 8453 --hardfork cancun)
  if [[ -n "$BASE_RPC_URL" && "$BASE_RPC_URL" != "none" ]]; then
    anvil_args+=(--fork-url "$BASE_RPC_URL")
    if [[ -n "$BASE_FORK_BLOCK" ]]; then
      anvil_args+=(--fork-block-number "$BASE_FORK_BLOCK")
    fi
  fi

  anvil "${anvil_args[@]}" >"$OUT_DIR/anvil.log" 2>&1 &
  ANVIL_PID=$!
fi

for _ in $(seq 1 80); do
  if cast block-number --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! cast block-number --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1; then
  echo "anvil did not become ready; see $OUT_DIR/anvil.log" >&2
  exit 1
fi

cd "$PROJECT_DIR"
forge build >/dev/null

DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
USER=$(cast wallet address --private-key "$USER_PK")

create_json=$(
  forge create src/BaseGasBenchmarks.sol:BaseGasFixture \
    --broadcast \
    --json \
    --rpc-url "$ANVIL_RPC_URL" \
    --private-key "$DEPLOYER_PK" \
    --constructor-args "$USER"
)
FIXTURE=$(jq -r '.deployedTo // .contractAddress // .address' <<<"$create_json")
if [[ -z "$FIXTURE" || "$FIXTURE" == "null" ]]; then
  echo "failed to deploy BaseGasFixture" >&2
  echo "$create_json" >&2
  exit 1
fi

addr() {
  cast call "$FIXTURE" "$1()(address)" --rpc-url "$ANVIL_RPC_URL"
}

PATHUSD=$(addr pathusd)
DLUSD=$(addr dlusd)
BRIDGE_TOKEN=$(addr bridgeToken)
WRAPPED_TOKEN=$(addr wrappedToken)
DIRECT_ROUTER=$(addr directSwapRouter)
MINIMAL_SWAP=$(addr minimalDirectSwap)
PRIMARY_VAULT=$(addr primaryVault)
WRAPPER=$(addr layerZeroWrapper)
STARGATE=$(addr stargate)

send_setup() {
  local to=$1
  local data=$2
  cast send "$to" \
    --data "$data" \
    --rpc-url "$ANVIL_RPC_URL" \
    --private-key "$USER_PK" \
    --gas-limit "$GAS_LIMIT" \
    --json >/dev/null
}

# Setup-only approvals for scenarios whose business benchmark starts from an already-approved user.
send_setup "$PATHUSD" "$(cast calldata 'approve(address,uint256)' "$DIRECT_ROUTER" "$DIRECT_SWAP_AMOUNT")"
send_setup "$PATHUSD" "$(cast calldata 'approve(address,uint256)' "$MINIMAL_SWAP" "$MINIMAL_SWAP_AMOUNT")"

RESULTS_TSV="$OUT_DIR/base-gas.tsv"
: >"$RESULTS_TSV"

hex_to_dec() {
  local hex=${1#0x}
  printf "%d" "$((16#$hex))"
}

measure_and_send() {
  local scenario=$1
  local call_name=$2
  local to=$3
  local data=$4

  local trace gas_hex gas_dec receipt status
  trace=$(
    cast rpc --rpc-url "$ANVIL_RPC_URL" debug_traceCall \
      "{\"from\":\"$USER\",\"to\":\"$to\",\"gas\":\"$(cast to-hex "$GAS_LIMIT")\",\"data\":\"$data\"}" \
      latest \
      '{"tracer":"callTracer"}'
  )
  gas_hex=$(jq -r '.gasUsed' <<<"$trace")
  gas_dec=$(hex_to_dec "$gas_hex")

  receipt=$(
    cast send "$to" \
      --data "$data" \
      --rpc-url "$ANVIL_RPC_URL" \
      --private-key "$USER_PK" \
      --gas-limit "$GAS_LIMIT" \
      --json
  )
  status=$(jq -r '.status // empty' <<<"$receipt")
  if [[ "$status" != "0x1" && "$status" != "1" ]]; then
    echo "transaction failed for $scenario / $call_name" >&2
    echo "$receipt" >&2
    exit 1
  fi

  printf '%s\t%s\t%s\n' "$scenario" "$call_name" "$gas_dec" >>"$RESULTS_TSV"
}

BASE_SNAPSHOT=$(cast rpc --rpc-url "$ANVIL_RPC_URL" evm_snapshot | tr -d '"')
reset_snapshot() {
  cast rpc --rpc-url "$ANVIL_RPC_URL" evm_revert "$BASE_SNAPSHOT" >/dev/null
  BASE_SNAPSHOT=$(cast rpc --rpc-url "$ANVIL_RPC_URL" evm_snapshot | tr -d '"')
}

reset_snapshot
measure_and_send \
  bridge_direct_swap \
  'swapExactOut(address,address,uint256)' \
  "$DIRECT_ROUTER" \
  "$(cast calldata 'swapExactOut(address,address,uint256)' "$PATHUSD" "$DLUSD" "$DIRECT_SWAP_AMOUNT")"

reset_snapshot
measure_and_send \
  minimal_direct_swap \
  'swapExactOut(address,address,uint256)' \
  "$MINIMAL_SWAP" \
  "$(cast calldata 'swapExactOut(address,address,uint256)' "$PATHUSD" "$DLUSD" "$MINIMAL_SWAP_AMOUNT")"

reset_snapshot
measure_and_send \
  morpho_deposit \
  'approve(address,uint256)' \
  "$PATHUSD" \
  "$(cast calldata 'approve(address,uint256)' "$PRIMARY_VAULT" "$MORPHO_DEPOSIT_AMOUNT")"
measure_and_send \
  morpho_deposit \
  'deposit(uint256,address)' \
  "$PRIMARY_VAULT" \
  "$(cast calldata 'deposit(uint256,address)' "$MORPHO_DEPOSIT_AMOUNT" "$USER")"

reset_snapshot
measure_and_send \
  layerzero_bridge \
  'bridgeToken.approve(address,uint256)' \
  "$BRIDGE_TOKEN" \
  "$(cast calldata 'approve(address,uint256)' "$STARGATE" "$LAYERZERO_BRIDGE_AMOUNT")"
measure_and_send \
  layerzero_bridge \
  'pathUSD.approve(address,uint256)' \
  "$PATHUSD" \
  "$(cast calldata 'approve(address,uint256)' "$WRAPPER" "$LAYERZERO_WRAP_AMOUNT")"
measure_and_send \
  layerzero_bridge \
  'wrap(address,address,uint256)' \
  "$WRAPPER" \
  "$(cast calldata 'wrap(address,address,uint256)' "$PATHUSD" "$USER" "$LAYERZERO_WRAP_AMOUNT")"
measure_and_send \
  layerzero_bridge \
  'wrappedToken.approve(address,uint256)' \
  "$WRAPPED_TOKEN" \
  "$(cast calldata 'approve(address,uint256)' "$STARGATE" "$LAYERZERO_WRAP_AMOUNT")"
measure_and_send \
  layerzero_bridge \
  'sendBridge(address,uint256,address,uint256,address)' \
  "$STARGATE" \
  "$(cast calldata 'sendBridge(address,uint256,address,uint256,address)' "$BRIDGE_TOKEN" "$LAYERZERO_BRIDGE_AMOUNT" "$WRAPPED_TOKEN" "$LAYERZERO_WRAP_AMOUNT" "$USER")"

JSON_OUT="$OUT_DIR/base-gas.json"
MD_OUT="$OUT_DIR/base-gas.md"

jq -Rn --arg rpc "$ANVIL_RPC_URL" --arg fixture "$FIXTURE" --arg user "$USER" '
  [inputs | select(length > 0) | split("\t") | {
    scenario: .[0],
    call: .[1],
    gas: (.[2] | tonumber)
  }] as $rows
  | {
      generated_at: (now | todate),
      chain_id: 8453,
      rpc_url: $rpc,
      fixture: $fixture,
      user: $user,
      measurement: "Base-style surrogate business-call execution gas; excludes deployment, setup, AA wrapper overhead, and Base L1 data fee",
      scenarios: (
        $rows
        | group_by(.scenario)
        | map({
            key: .[0].scenario,
            value: {
              gas: (map(.gas) | add),
              calls: (map({name: .call, gas: .gas}))
            }
          })
        | from_entries
      )
    }
' "$RESULTS_TSV" >"$JSON_OUT"

{
  echo "| use case | call(s) | Base-style surrogate |"
  echo "|---|---|---:|"
  jq -r '
    .scenarios
    | to_entries
    | sort_by(.key)
    | .[]
    | "| \(.key) | \(.value.calls | map(.name) | join("; ")) | \(.value.gas) |"
  ' "$JSON_OUT"
} >"$MD_OUT"

cat "$MD_OUT"
echo
echo "Wrote $JSON_OUT"
echo "Wrote $MD_OUT"
