#!/usr/bin/env bash
#
# Replay benchmark: runs real Tempo moderato blocks through the Engine API
# (reth-bench new-payload-fcu) against baseline and feature Tempo binaries,
# using a schelk-managed snapshot for instant rollback between runs.
#
# Runs in B-F-F-B interleaved order to reduce systematic bias.
#
# Required env:
#   BASELINE_REF, FEATURE_REF     – git SHAs to build
#   BENCH_BLOCKS                  – number of blocks to benchmark
#   BENCH_WARMUP_BLOCKS           – number of warmup blocks
#   BENCH_BASELINE_ARGS           – extra node args for baseline (optional)
#   BENCH_FEATURE_ARGS            – extra node args for feature (optional)
#   BENCH_SAMPLY                  – "true" to enable samply profiling (optional)
set -euxo pipefail

SCHELK_MOUNT="/reth-bench"
BENCH_WORK_DIR="${BENCH_WORK_DIR:-bench-results/replay}"
SNAPSHOT_BUCKET="r2-tempo-snapshots/tempo-node-snapshots"
TEMPO_SCOPE="tempo-replay.scope"

# Chain-specific configuration
CHAIN="${BENCH_CHAIN:-mainnet}"
case "$CHAIN" in
  mainnet)
    CHAIN_ID=4217
    CHAIN_NAME="mainnet"
    REPLAY_RPC_URL="https://rpc.tempo.xyz"
    ;;
  testnet)
    CHAIN_ID=42431
    CHAIN_NAME="moderato"
    REPLAY_RPC_URL="https://rpc.moderato.tempo.xyz"
    ;;
  *)
    echo "::error::Unknown chain: $CHAIN (must be 'mainnet' or 'testnet')"
    exit 1
    ;;
esac

DATADIR="$SCHELK_MOUNT/tempo-replay-${CHAIN_NAME}"
SNAPSHOT_PREFIX="tempo-${CHAIN_ID}-"
SNAPSHOT_HASH_FILE="$HOME/.tempo-replay-snapshot-hash-${CHAIN_NAME}"
echo "Chain: $CHAIN_NAME (id=$CHAIN_ID, rpc=$REPLAY_RPC_URL)"

MC="mc"
BLOCKS="${BENCH_BLOCKS:-5000}"
WARMUP="${BENCH_WARMUP_BLOCKS:-1000}"

mkdir -p "$BENCH_WORK_DIR"

# ============================================================================
# Install txgen-tempo and bench-cli
# ============================================================================

echo "Installing txgen-tempo and bench-cli..."
cargo install --git "https://x-access-token:${DEREK_PAT}@github.com/tempoxyz/txgen" --locked txgen-tempo bench-cli

# ============================================================================
# Build baseline + feature binaries
# ============================================================================

build_tempo() {
  local label="$1" ref="$2" src_dir="$3"

  if [ -d "$src_dir" ]; then
    git -C "$src_dir" fetch origin "$ref" --quiet 2>/dev/null || true
  else
    git clone . "$src_dir"
  fi
  git -C "$src_dir" checkout "$ref"

  echo "Building $label tempo ($ref)..."
  cd "$src_dir"
  RUSTFLAGS="-C target-cpu=native" \
    cargo build --profile profiling --bin tempo
  cd -
}

build_tempo baseline "$BASELINE_REF" ../tempo-baseline &
PID_BASELINE=$!
build_tempo feature "$FEATURE_REF" ../tempo-feature &
PID_FEATURE=$!

FAIL=0
wait $PID_BASELINE || FAIL=1
wait $PID_FEATURE || FAIL=1
if [ $FAIL -ne 0 ]; then
  echo "::error::One or more build tasks failed"
  exit 1
fi

BASELINE_BIN="$(cd ../tempo-baseline && pwd)/target/profiling/tempo"
FEATURE_BIN="$(cd ../tempo-feature && pwd)/target/profiling/tempo"

# ============================================================================
# Snapshot management
# ============================================================================

# Pick second-to-latest snapshot directory (filter out .json/.tar.lz4 files)
SNAPSHOTS=$($MC ls "$SNAPSHOT_BUCKET/" | awk '{print $NF}' | sed 's:/$::' | grep "^${SNAPSHOT_PREFIX}" | grep -v '\.' | sort)
SNAPSHOT_COUNT=$(echo "$SNAPSHOTS" | wc -l)
if [ "$SNAPSHOT_COUNT" -lt 2 ]; then
  echo "::error::Need at least 2 snapshots matching ${SNAPSHOT_PREFIX}*, found $SNAPSHOT_COUNT"
  exit 1
fi
SNAPSHOT_NAME=$(echo "$SNAPSHOTS" | tail -2 | head -1)
echo "Selected snapshot: $SNAPSHOT_NAME"

# Extract snapshot block number from name: tempo-{chain_id}-{block_number}-{timestamp}
SNAPSHOT_BLOCK=$(echo "$SNAPSHOT_NAME" | awk -F- '{print $3}')
echo "Snapshot block: $SNAPSHOT_BLOCK"

MANIFEST_REMOTE="${SNAPSHOT_BUCKET}/${SNAPSHOT_NAME}/manifest.json"
REMOTE_HASH=$($MC cat "$MANIFEST_REMOTE" 2>/dev/null | sha256sum | awk '{print $1}')
LOCAL_HASH=""
[ -f "$SNAPSHOT_HASH_FILE" ] && LOCAL_HASH=$(cat "$SNAPSHOT_HASH_FILE")

# Mount schelk before checking $DATADIR/db existence
sudo schelk recover -y --kill 2>/dev/null || true
sudo schelk mount -y

if [ "$REMOTE_HASH" != "$LOCAL_HASH" ] || [ ! -d "$DATADIR/db" ]; then
  if [ -n "$LOCAL_HASH" ]; then
    echo "Snapshot needs update (local: ${LOCAL_HASH:0:16}…, remote: ${REMOTE_HASH:0:16}…)"
  else
    echo "Snapshot needs update (local: <none>, remote: ${REMOTE_HASH:0:16}…)"
  fi

  MANIFEST_URL="https://tempo-node-snapshots.tempoxyz.dev/${SNAPSHOT_NAME}/manifest.json"

  # Prepare schelk volume for fresh download
  sudo rm -rf "$DATADIR"
  sudo mkdir -p "$DATADIR"
  sudo chown -R "$(id -u):$(id -g)" "$DATADIR"

  # Download snapshot using the feature binary
  "$FEATURE_BIN" download \
    --manifest-url "$MANIFEST_URL" \
    -y \
    --minimal \
    --datadir "$DATADIR"

  if [ ! -d "$DATADIR/db" ] || [ ! -d "$DATADIR/static_files" ]; then
    echo "::error::Snapshot download did not produce expected directory layout"
    ls -la "$DATADIR" || true
    exit 1
  fi

  sync
  sudo schelk promote -y
  echo "$REMOTE_HASH" > "$SNAPSHOT_HASH_FILE"
  echo "Snapshot promoted to schelk baseline"
else
  echo "Snapshot is up-to-date (hash: ${REMOTE_HASH:0:16}…)"
fi

# ============================================================================
# Single run function
# ============================================================================

run_single() {
  local label="$1" binary="$2" output_dir="$3"

  echo "=== Starting run: $label ==="
  mkdir -p "$output_dir"
  local log="$output_dir/node.log"

  # Recover snapshot
  sudo systemctl stop "$TEMPO_SCOPE" 2>/dev/null || true
  sudo systemctl reset-failed "$TEMPO_SCOPE" 2>/dev/null || true
  sudo schelk recover -y --kill || sudo schelk full-recover -y || true
  sudo schelk mount -y
  sudo chown -R "$(id -u):$(id -g)" "$SCHELK_MOUNT"

  sync
  sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'

  # Build node args
  local NODE_ARGS=(
    node
    --dev
    --chain "$CHAIN_NAME"
    --datadir "$DATADIR"
    --log.file.directory "$output_dir/tempo-logs"
    --http
    --http.port 8545
    --http.api all
    --authrpc.port 8551
    --metrics 9001
    --disable-discovery
    --no-persist-peers
  )

  # Per-label extra node args
  local extra_args=""
  case "$label" in
    baseline*) extra_args="${BENCH_BASELINE_ARGS:-}" ;;
    feature*)  extra_args="${BENCH_FEATURE_ARGS:-}" ;;
  esac
  if [ -n "$extra_args" ]; then
    # shellcheck disable=SC2206
    NODE_ARGS+=($extra_args)
  fi

  # Memory limit: 95% of available RAM
  local total_mem_kb
  total_mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  local mem_limit=$(( total_mem_kb * 95 / 100 * 1024 ))

  # Start tempo node
  if [ "${BENCH_SAMPLY:-false}" = "true" ]; then
    local samply_bin
    samply_bin="$(which samply)"
    sudo systemd-run --quiet --scope --collect --unit="$TEMPO_SCOPE" \
      -p MemoryMax="$mem_limit" \
      nice -n -20 \
      "$samply_bin" record --save-only --presymbolicate --rate 10000 \
      --output "$output_dir/samply-profile.json.gz" \
      -- "$binary" "${NODE_ARGS[@]}" \
      > "$log" 2>&1 &
  else
    sudo systemd-run --quiet --scope --collect --unit="$TEMPO_SCOPE" \
      -p MemoryMax="$mem_limit" \
      nice -n -20 "$binary" "${NODE_ARGS[@]}" \
      > "$log" 2>&1 &
  fi
  stdbuf -oL tail -f "$log" | sed -u "s/^/[$label] /" &
  local tail_pid=$!

  # Wait for RPC
  for i in $(seq 1 120); do
    if curl -sf http://127.0.0.1:8545 -X POST \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
      > /dev/null 2>&1; then
      echo "tempo ($label) RPC is up after ${i}s"
      break
    fi
    if [ "$i" -eq 120 ]; then
      echo "::error::tempo ($label) failed to start within 120s"
      cat "$log"
      kill "$tail_pid" 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done

  local from_block=$(( SNAPSHOT_BLOCK + 1 ))

  # Warmup
  if [ "$WARMUP" -gt 0 ]; then
    local warmup_to=$(( from_block + WARMUP - 1 ))
    echo "Running warmup ($WARMUP blocks: $from_block..$warmup_to)..."
    txgen-tempo extract --rpc "$REPLAY_RPC_URL" --from "$from_block" --to "$warmup_to" \
      | bench send-blocks \
        --engine http://127.0.0.1:8551 \
        --jwt-secret "$DATADIR/jwt.hex" 2>&1 | sed -u "s/^/[bench] /"
    from_block=$(( warmup_to + 1 ))
  fi

  # Benchmark
  local bench_to=$(( from_block + BLOCKS - 1 ))
  echo "Running benchmark ($BLOCKS blocks: $from_block..$bench_to)..."
  txgen-tempo extract --rpc "$REPLAY_RPC_URL" --from "$from_block" --to "$bench_to" \
    | bench send-blocks \
      --engine http://127.0.0.1:8551 \
      --jwt-secret "$DATADIR/jwt.hex" \
      --metrics-url http://localhost:9001 \
      --report "json:$output_dir/report.json" 2>&1 | sed -u "s/^/[bench] /"

  # Cleanup
  kill "$tail_pid" 2>/dev/null || true
  if [ "${BENCH_SAMPLY:-false}" = "true" ]; then
    sudo pkill -INT -x tempo 2>/dev/null || true
    for i in $(seq 1 60); do
      sudo pgrep -x samply > /dev/null 2>&1 || break
      sleep 1
    done
  fi
  sudo systemctl stop "$TEMPO_SCOPE" 2>/dev/null || true
  sudo systemctl reset-failed "$TEMPO_SCOPE" 2>/dev/null || true
  sudo chown -R "$(id -un):$(id -gn)" "$output_dir" 2>/dev/null || true
  sudo schelk recover -y --kill || true
  echo "=== Finished run: $label ==="
}

# ============================================================================
# B-F-F-B interleaved runs
# ============================================================================

run_single baseline-1 "$BASELINE_BIN" "$BENCH_WORK_DIR/baseline-1"
run_single feature-1  "$FEATURE_BIN"  "$BENCH_WORK_DIR/feature-1"
run_single feature-2  "$FEATURE_BIN"  "$BENCH_WORK_DIR/feature-2"
run_single baseline-2 "$BASELINE_BIN" "$BENCH_WORK_DIR/baseline-2"

echo "All replay benchmark runs complete."
