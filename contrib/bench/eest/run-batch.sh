#!/usr/bin/env bash
# Regenerate multiple EEST benchmark cases on Tempo and export their blocks.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TEMPO_REPO=$(cd -- "$SCRIPT_DIR/../../.." && pwd)

: "${EEST_REPO:?set EEST_REPO to an ethereum/execution-specs checkout}"
: "${SUITE_OUT:?set SUITE_OUT to the output suite directory}"

TEMPO_IMAGE=${TEMPO_IMAGE:-docker.io/tempoxyz/tempo:latest}
UV_IMAGE=${UV_IMAGE:-ghcr.io/astral-sh/uv:python3.11-bookworm}
EEST_FORK=${EEST_FORK:-Prague}
GAS_MILLIONS=${GAS_MILLIONS:-10}
CHAIN_ID=${CHAIN_ID:-1337}
SUITE_NAME=${SUITE_NAME:-eest-prague-batch-10m}
SUITE_DESCRIPTION=${SUITE_DESCRIPTION:-EEST ${EEST_FORK} workloads regenerated on Tempo at ${GAS_MILLIONS}M gas}
RPC_PORT=${RPC_PORT:-18545}
ENGINE_PORT=${ENGINE_PORT:-18551}
BLOCK_TIME=${BLOCK_TIME:-250ms}
DEV_SEED_KEY=${DEV_SEED_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}
EOA_START=${EOA_START:-103835740027347086785932208981225044632444623980288738833340492242305523519088}
EOA_START_HEX=${EOA_START_HEX:-0xe590f237b4c6d4872b2003046ea885cad5bbb2b107f558ae5d387a9aad960e70}
CONTAINER_NAME=tempo-eest-batch-$$

if (($# == 0)); then
  set -- tests/benchmark/compute/instruction/test_arithmetic.py
fi
SOURCE_TESTS=("$@")
for source_test in "${SOURCE_TESTS[@]}"; do
  if [[ ! -f "$EEST_REPO/$source_test" ]]; then
    echo "EEST source test does not exist: $EEST_REPO/$source_test" >&2
    exit 1
  fi
done

capture_dir=$(mktemp -d)
cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  if [[ -n ${capture_dir:-} && -d $capture_dir ]]; then
    find "$capture_dir" -type f -delete
    rmdir "$capture_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

rpc() {
  local method=$1
  local params=$2
  curl -fsS "http://127.0.0.1:${RPC_PORT}" \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}"
}

docker run -d --name "$CONTAINER_NAME" \
  -p "${RPC_PORT}:8545" -p "${ENGINE_PORT}:8551" \
  "$TEMPO_IMAGE" \
  node --dev --dev.block-time="$BLOCK_TIME" \
  --datadir=/tmp/tempo-eest \
  --http --http.addr=0.0.0.0 --http.api=all --http.port=8545 \
  --authrpc.addr=0.0.0.0 --authrpc.port=8551 \
  --disable-discovery --no-persist-peers --builder.max-tasks=1 >/dev/null

for _ in $(seq 1 40); do
  if rpc eth_chainId '[]' >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
rpc eth_chainId '[]' >/dev/null

set +e
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e PYTHONPATH=/tempo/contrib/bench/eest \
  -e PYTEST_PLUGINS=tempo_eest_adapter \
  -e TEMPO_CAPTURE_FILE=/capture/capture.jsonl \
  -e TEMPO_CAPTURE_RPC_URL="http://host.docker.internal:${RPC_PORT}" \
  -v "$EEST_REPO:/work" \
  -v "$TEMPO_REPO:/tempo:ro" \
  -v "$capture_dir:/capture" \
  -v tempo-eest-uv-cache:/root/.cache/uv \
  -w /work "$UV_IMAGE" \
  uv run execute remote -q \
  --fork="$EEST_FORK" --chain-id="$CHAIN_ID" \
  --rpc-endpoint="http://host.docker.internal:${RPC_PORT}" \
  --rpc-seed-key="$DEV_SEED_KEY" \
  --eoa-start="$EOA_START" \
  --gas-benchmark-values="$GAS_MILLIONS" \
  --tx-wait-timeout=30 --skip-cleanup \
  "${SOURCE_TESTS[@]}"
pytest_status=$?
set -e

capture_file=$capture_dir/capture.jsonl
if [[ ! -s "$capture_file" ]]; then
  echo "EEST produced no capture records (pytest status $pytest_status)" >&2
  exit "$pytest_status"
fi
echo "EEST pytest status: $pytest_status"
jq -s 'group_by(.outcome) | map({outcome: .[0].outcome, count: length})' "$capture_file"

revision=$(git -C "$EEST_REPO" rev-parse HEAD)
source_test_list=$(IFS=,; echo "${SOURCE_TESTS[*]}")
export_args=(
  generate-benchmark-suite
  --rpc-url "http://127.0.0.1:${RPC_PORT}"
  --genesis "$TEMPO_REPO/crates/chainspec/src/genesis/dev.json"
  --out "$SUITE_OUT"
  --name "$SUITE_NAME"
  --capture-file "$capture_file"
  --description "$SUITE_DESCRIPTION"
  --tag eest --tag ethereum-derived --tag tempo-normalized
  --seed "$EOA_START_HEX"
  --revision "$revision"
  --origin-kind eest
  --origin-repository https://github.com/ethereum/execution-specs
  --generator "EEST execute remote + Tempo TIP-20 adapter + tempo-xtask capture export"
  --metadata "source_tests=$source_test_list"
  --metadata "source_fork=$EEST_FORK"
  --metadata "gas_target_millions=$GAS_MILLIONS"
  --hardfork dev-all --chain-id "$CHAIN_ID"
)
if [[ ${FORCE:-false} == true ]]; then
  export_args+=(--force)
fi

if [[ -x "$TEMPO_REPO/target/debug/tempo-xtask" ]]; then
  "$TEMPO_REPO/target/debug/tempo-xtask" "${export_args[@]}"
else
  (cd "$TEMPO_REPO" && cargo xtask "${export_args[@]}")
fi

jq '{name, metadata, tests: (.tests | length)}' "$SUITE_OUT/manifest.json"
