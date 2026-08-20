#!/usr/bin/env bash
# Generate one EEST benchmark as a canonical Tempo/Benchmarkoor replay suite.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TEMPO_REPO=$(cd -- "$SCRIPT_DIR/../../.." && pwd)

: "${EEST_REPO:?set EEST_REPO to an ethereum/execution-specs checkout}"
: "${SUITE_OUT:?set SUITE_OUT to the output suite directory}"

TEMPO_IMAGE=${TEMPO_IMAGE:-docker.io/tempoxyz/tempo:latest}
UV_IMAGE=${UV_IMAGE:-ghcr.io/astral-sh/uv:python3.11-bookworm}
EEST_TEST=${EEST_TEST:-tests/benchmark/compute/instruction/test_arithmetic.py}
EEST_FILTER=${EEST_FILTER:-opcode_ADD and not ADDMOD}
EEST_FORK=${EEST_FORK:-Prague}
GAS_MILLIONS=${GAS_MILLIONS:-10}
CHAIN_ID=${CHAIN_ID:-1337}
SUITE_NAME=${SUITE_NAME:-eest-prague-add-10m}
RPC_PORT=${RPC_PORT:-18545}
ENGINE_PORT=${ENGINE_PORT:-18551}
CONTAINER_NAME=tempo-eest-generator-$$
DEV_SEED_KEY=${DEV_SEED_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}
EOA_START=${EOA_START:-103835740027347086785932208981225044632444623980288738833340492242305523519088}
EOA_START_HEX=${EOA_START_HEX:-0xe590f237b4c6d4872b2003046ea885cad5bbb2b107f558ae5d387a9aad960e70}

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
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
  node --dev --dev.block-time=1s \
  --datadir=/tmp/tempo-eest \
  --http --http.addr=0.0.0.0 --http.api=all --http.port=8545 \
  --authrpc.addr=0.0.0.0 --authrpc.port=8551 \
  --disable-discovery --no-persist-peers --builder.max-tasks=1 >/dev/null

for _ in $(seq 1 30); do
  if rpc eth_chainId '[]' >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
rpc eth_chainId '[]' >/dev/null

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e PYTHONPATH=/tempo/contrib/bench/eest \
  -e PYTEST_PLUGINS=tempo_eest_adapter \
  -v "$EEST_REPO:/work" \
  -v "$TEMPO_REPO:/tempo:ro" \
  -v tempo-eest-uv-cache:/root/.cache/uv \
  -w /work "$UV_IMAGE" \
  uv run execute remote -v \
  --fork="$EEST_FORK" --chain-id="$CHAIN_ID" \
  --rpc-endpoint="http://host.docker.internal:${RPC_PORT}" \
  --rpc-seed-key="$DEV_SEED_KEY" \
  --eoa-start="$EOA_START" \
  --gas-benchmark-values="$GAS_MILLIONS" \
  --tx-wait-timeout=30 --skip-cleanup \
  "$EEST_TEST" -k "$EEST_FILTER"

head_hex=$(rpc eth_blockNumber '[]' | jq -er .result)
head=$((16#${head_hex#0x}))
last_nonempty=0
for ((number = 1; number <= head; number++)); do
  count=$(rpc eth_getBlockByNumber "[\"0x$(printf '%x' "$number")\",false]" \
    | jq -er '.result.transactions | length')
  if ((count > 0)); then
    last_nonempty=$number
  fi
done

if ((last_nonempty == 0)); then
  echo "EEST passed but no transaction block was found" >&2
  exit 1
fi

eest_revision=$(git -C "$EEST_REPO" rev-parse HEAD)
export_args=(
  generate-benchmark-suite
  --rpc-url "http://127.0.0.1:${RPC_PORT}"
  --genesis "$TEMPO_REPO/crates/chainspec/src/genesis/dev.json"
  --out "$SUITE_OUT"
  --name "$SUITE_NAME"
  --from-block "$last_nonempty"
  --to-block "$last_nonempty"
  --description "EEST ${EEST_FORK} ${EEST_FILTER} workload regenerated on Tempo at ${GAS_MILLIONS}M gas"
  --tag eest --tag ethereum-derived --tag tempo-normalized
  --seed "$EOA_START_HEX"
  --revision "$eest_revision"
  --origin-kind eest
  --origin-repository https://github.com/ethereum/execution-specs
  --generator "EEST execute remote + Tempo TIP-20 adapter + tempo-xtask export"
  --metadata "source_test=${EEST_TEST}"
  --metadata "source_filter=${EEST_FILTER}"
  --metadata "source_fork=${EEST_FORK}"
  --metadata "gas_target_millions=${GAS_MILLIONS}"
  --hardfork dev-all --chain-id "$CHAIN_ID"
)

if [[ -f "$SUITE_OUT/manifest.json" ]]; then
  if [[ ${FORCE:-false} != true ]]; then
    echo "$SUITE_OUT/manifest.json already exists; set FORCE=true to replace it" >&2
    exit 1
  fi
  export_args+=(--force)
fi

if [[ -x "$TEMPO_REPO/target/debug/tempo-xtask" ]]; then
  "$TEMPO_REPO/target/debug/tempo-xtask" "${export_args[@]}"
else
  (cd "$TEMPO_REPO" && cargo xtask "${export_args[@]}")
fi

echo "Generated $SUITE_OUT/manifest.json"
