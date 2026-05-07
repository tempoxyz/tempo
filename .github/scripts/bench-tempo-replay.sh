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
#   BENCH_BASELINE_ENV            – extra env vars for baseline node (optional)
#   BENCH_FEATURE_ENV             – extra env vars for feature node (optional)
#   BENCH_BENCH_ARGS              – extra args for bench send-blocks (optional)
#   BENCH_BENCH_ENV               – extra env vars for bench send-blocks (optional)
#   BENCH_SAMPLY                  – "true" to enable samply profiling (optional)
#   BENCH_TRACY                   – "off", "on", or "full" for Tracy profiling (optional)
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
BENCH_BENCHMARK_ID="${BENCH_BENCHMARK_ID:-bench-replay-$(date -u +%Y%m%d-%H%M%S)}"
BENCH_REFERENCE_EPOCH="${BENCH_REFERENCE_EPOCH:-$(date +%s)}"
BENCH_TRACY="${BENCH_TRACY:-off}"
BENCH_TRACY_SECONDS="${BENCH_TRACY_SECONDS:-30}"
BENCH_TRACY_OFFSET="${BENCH_TRACY_OFFSET:-120}"
BENCH_TRACY_FILTER="${BENCH_TRACY_FILTER:-debug}"

case "$BENCH_TRACY" in
  off|on|full) ;;
  *)
    echo "::error::BENCH_TRACY must be one of: off, on, full (got '$BENCH_TRACY')"
    exit 1
    ;;
esac
if [ "${BENCH_SAMPLY:-false}" = "true" ] && [ "$BENCH_TRACY" != "off" ]; then
  echo "::error::BENCH_SAMPLY and BENCH_TRACY are mutually exclusive"
  exit 1
fi

mkdir -p "$BENCH_WORK_DIR"

# `cargo install` writes binaries to CARGO_HOME/bin, but self-hosted runner
# services do not necessarily inherit a login-shell PATH for the runner user.
CARGO_BIN_DIR="${CARGO_HOME:-$HOME/.cargo}/bin"
export PATH="$CARGO_BIN_DIR:$PATH"
TXGEN_TEMPO_BIN="${TXGEN_TEMPO_BIN:-txgen-tempo}"
TXGEN_BENCH_BIN="${TXGEN_BENCH_BIN:-bench}"

TRACING_OTLP="${BENCH_TRACING_OTLP:-}"
if [ -z "$TRACING_OTLP" ] && [ -n "${GRAFANA_TEMPO:-}" ]; then
  TRACING_OTLP="${GRAFANA_TEMPO%/}/v1/traces"
elif [ -z "$TRACING_OTLP" ] && [ -n "${TEMPO_TELEMETRY_URL:-}" ]; then
  TRACING_OTLP="${TEMPO_TELEMETRY_URL%/}/opentelemetry/v1/traces"
fi

if [ "${BENCH_SAMPLY:-false}" = "true" ] && ! command -v samply >/dev/null; then
  echo "::error::samply not found in PATH"
  exit 1
fi

if [ "$BENCH_TRACY" != "off" ] && ! command -v tracy-capture >/dev/null; then
  echo "::error::tracy-capture not found in PATH"
  exit 1
fi

if [ "$BENCH_TRACY" = "full" ] && [ "$(uname)" = "Linux" ]; then
  echo "Configuring system for Tracy CPU sampling..."
  sudo sysctl -w kernel.perf_event_paranoid=-1 || true
  sudo mount -t tracefs tracefs /sys/kernel/tracing -o remount,mode=755 || true
  sudo chmod -R a+r /sys/kernel/tracing || true
fi

# ============================================================================
# Install txgen-tempo and bench-cli
# ============================================================================

echo "Installing txgen-tempo and bench-cli..."
if [ -n "${DEREK_BENCH_TOKEN:-}" ]; then
  TXGEN_GIT_URL="https://x-access-token:${DEREK_BENCH_TOKEN}@github.com/tempoxyz/txgen"
else
  TXGEN_GIT_URL="https://github.com/tempoxyz/txgen"
fi
TXGEN_INSTALL_ARGS=(--git "$TXGEN_GIT_URL")
if [ -n "${BENCH_TXGEN_REF:-}" ]; then
  if git ls-remote --exit-code --heads "$TXGEN_GIT_URL" "$BENCH_TXGEN_REF" >/dev/null 2>&1; then
    TXGEN_INSTALL_ARGS+=(--branch "$BENCH_TXGEN_REF")
  elif git ls-remote --exit-code --tags "$TXGEN_GIT_URL" "$BENCH_TXGEN_REF" >/dev/null 2>&1; then
    TXGEN_INSTALL_ARGS+=(--tag "$BENCH_TXGEN_REF")
  else
    TXGEN_INSTALL_ARGS+=(--rev "$BENCH_TXGEN_REF")
  fi
fi
cargo install "${TXGEN_INSTALL_ARGS[@]}" --locked txgen-tempo bench-cli
command -v "$TXGEN_TEMPO_BIN"
command -v "$TXGEN_BENCH_BIN"

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
  local rustflags="-C target-cpu=native"
  local cargo_args=(build --profile profiling --bin tempo)
  if [ "$BENCH_TRACY" != "off" ]; then
    rustflags="$rustflags -C force-frame-pointers=yes"
    cargo_args+=(--features tracy)
  fi
  RUSTFLAGS="$rustflags" cargo "${cargo_args[@]}"
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
  local extra_env=""
  local git_ref=""
  local run_type=""
  case "$label" in
    baseline*)
      extra_args="${BENCH_BASELINE_ARGS:-}"
      extra_env="${BENCH_BASELINE_ENV:-}"
      git_ref="$BASELINE_REF"
      run_type="baseline"
      ;;
    feature*)
      extra_args="${BENCH_FEATURE_ARGS:-}"
      extra_env="${BENCH_FEATURE_ENV:-}"
      git_ref="$FEATURE_REF"
      run_type="feature"
      ;;
  esac
  if [ -n "$extra_args" ]; then
    # shellcheck disable=SC2206
    NODE_ARGS+=($extra_args)
  fi
  if [ -n "$TRACING_OTLP" ]; then
    NODE_ARGS+=(--tracing-otlp="$TRACING_OTLP")
  fi
  if [ "$BENCH_TRACY" != "off" ]; then
    NODE_ARGS+=(--log.tracy --log.tracy.filter "$BENCH_TRACY_FILTER")
  fi

  local NODE_ENV=(
    "OTEL_RESOURCE_ATTRIBUTES=benchmark_id=${BENCH_BENCHMARK_ID},benchmark_run=${label},run_type=${run_type},git_ref=${git_ref}"
  )
  if [ "$BENCH_TRACY" = "on" ]; then
    NODE_ENV+=(TRACY_NO_SYS_TRACE=1)
  elif [ "$BENCH_TRACY" = "full" ]; then
    NODE_ENV+=(TRACY_SAMPLING_HZ=1)
  fi
  if [ -n "$extra_env" ]; then
    # shellcheck disable=SC2206
    local extra_env_parts=($extra_env)
    NODE_ENV+=("${extra_env_parts[@]}")
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
      nice -n -20 env "${NODE_ENV[@]}" \
      "$samply_bin" record --save-only --presymbolicate --rate 10000 \
      --output "$output_dir/samply-profile.json.gz" \
      -- "$binary" "${NODE_ARGS[@]}" \
      > "$log" 2>&1 &
  else
    sudo systemd-run --quiet --scope --collect --unit="$TEMPO_SCOPE" \
      -p MemoryMax="$mem_limit" \
      nice -n -20 env "${NODE_ENV[@]}" "$binary" "${NODE_ARGS[@]}" \
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

  local tracy_pid=""
  local tracy_profile="$output_dir/tracy-profile.tracy"
  if [ "$BENCH_TRACY" != "off" ]; then
    local seconds_flag=()
    if [ "$BENCH_TRACY_SECONDS" -gt 0 ]; then
      seconds_flag=(-s "$BENCH_TRACY_SECONDS")
    fi
    if [ "$BENCH_TRACY_OFFSET" -gt 0 ]; then
      echo "Tracy capture for $label will start in ${BENCH_TRACY_OFFSET}s..."
      ( sleep "$BENCH_TRACY_OFFSET"; tracy-capture -f -o "$tracy_profile" "${seconds_flag[@]}" ) &
    else
      echo "Starting Tracy capture for $label..."
      ( tracy-capture -f -o "$tracy_profile" "${seconds_flag[@]}" ) &
    fi
    tracy_pid=$!
  fi

  local from_block=$(( SNAPSHOT_BLOCK + 1 ))
  local BENCH_SEND_ARGS=()
  local BENCH_ENV_ARGS=()
  if [ -n "${BENCH_BENCH_ARGS:-}" ]; then
    # shellcheck disable=SC2206
    BENCH_SEND_ARGS=(${BENCH_BENCH_ARGS})
  fi
  if [ -n "${BENCH_BENCH_ENV:-}" ]; then
    # shellcheck disable=SC2206
    BENCH_ENV_ARGS=(${BENCH_BENCH_ENV})
  fi

  # Warmup
  if [ "$WARMUP" -gt 0 ]; then
    local warmup_to=$(( from_block + WARMUP - 1 ))
    echo "Running warmup ($WARMUP blocks: $from_block..$warmup_to)..."
    "$TXGEN_TEMPO_BIN" extract --rpc "$REPLAY_RPC_URL" --from "$from_block" --to "$warmup_to" \
      | env "${BENCH_ENV_ARGS[@]}" "$TXGEN_BENCH_BIN" send-blocks \
        --engine http://127.0.0.1:8551 \
        --jwt-secret "$DATADIR/jwt.hex" \
        "${BENCH_SEND_ARGS[@]}" 2>&1 | sed -u "s/^/[bench] /"
    from_block=$(( warmup_to + 1 ))
  fi

  # Benchmark
  local bench_to=$(( from_block + BLOCKS - 1 ))
  echo "Running benchmark ($BLOCKS blocks: $from_block..$bench_to)..."
  "$TXGEN_TEMPO_BIN" extract --rpc "$REPLAY_RPC_URL" --from "$from_block" --to "$bench_to" \
    | env "${BENCH_ENV_ARGS[@]}" "$TXGEN_BENCH_BIN" send-blocks \
      --engine http://127.0.0.1:8551 \
      --jwt-secret "$DATADIR/jwt.hex" \
      --metrics-url http://localhost:9001 \
      --report "json:$output_dir/report.json" \
      "${BENCH_SEND_ARGS[@]}" 2>&1 | sed -u "s/^/[bench] /"

  # Cleanup
  if [ -n "$tracy_pid" ]; then
    sudo pkill -INT -x tracy-capture 2>/dev/null || true
    kill "$tracy_pid" 2>/dev/null || true
    wait "$tracy_pid" 2>/dev/null || true
    for i in $(seq 1 30); do
      pgrep -x tracy-capture > /dev/null 2>&1 || break
      sleep 1
    done
  fi
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

upload_samply_profiles() {
  local upload_script="contrib/bench/upload-samply-profile.sh"
  if [ ! -x "$upload_script" ]; then
    echo "Warning: $upload_script not found or not executable, skipping samply uploads"
    return
  fi

  for label in baseline-1 feature-1 feature-2 baseline-2; do
    local profile="$BENCH_WORK_DIR/$label/samply-profile.json.gz"
    if [ ! -f "$profile" ]; then
      echo "Warning: samply profile not found: $profile"
      continue
    fi
    local url
    if url=$(bash "$upload_script" "$profile"); then
      url="$(echo "$url" | tail -1 | tr -d '\r')"
      if [ -n "$url" ]; then
        echo "$url" > "$BENCH_WORK_DIR/profile-$label-url.txt"
      fi
    else
      echo "Warning: failed to upload samply profile: $profile"
    fi
  done
}

upload_tracy_profiles() {
  for label in baseline-1 feature-1 feature-2 baseline-2; do
    local profile="$BENCH_WORK_DIR/$label/tracy-profile.tracy"
    if [ ! -f "$profile" ]; then
      echo "Warning: Tracy profile not found: $profile"
      continue
    fi

    local commit_ref="$FEATURE_REF"
    if [[ "$label" == baseline* ]]; then
      commit_ref="$BASELINE_REF"
    fi
    local short_sha="${commit_ref:0:8}"
    local timestamp
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    local remote_name="${label}-${short_sha}-${timestamp}.tracy"

    if "$MC" cp "$profile" "r2/tracy/profiles/$remote_name" >/dev/null; then
      rm -f "$profile"
      echo "https://tracy.tempoxyz.dev?profile_url=/profiles/$remote_name" > "$BENCH_WORK_DIR/tracy-$label-url.txt"
    else
      echo "Warning: failed to upload Tracy profile: $profile"
    fi
  done
}

# ============================================================================
# B-F-F-B interleaved runs
# ============================================================================

run_single baseline-1 "$BASELINE_BIN" "$BENCH_WORK_DIR/baseline-1"
run_single feature-1  "$FEATURE_BIN"  "$BENCH_WORK_DIR/feature-1"
run_single feature-2  "$FEATURE_BIN"  "$BENCH_WORK_DIR/feature-2"
run_single baseline-2 "$BASELINE_BIN" "$BENCH_WORK_DIR/baseline-2"

echo "All replay benchmark runs complete."

if [ "${BENCH_SAMPLY:-false}" = "true" ]; then
  upload_samply_profiles
fi
if [ "$BENCH_TRACY" != "off" ]; then
  upload_tracy_profiles
fi
