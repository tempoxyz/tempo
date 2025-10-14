#!/bin/bash

set -euo pipefail

LOG_FILE="${TEMPO_LOG_FILE:-debug.log}"
JSON_OUTPUT=""
ANALYZE_LABEL=""
QUIET_ANALYZE=0
SKIP_ANALYSIS=0

usage() {
  cat <<EOF
Usage: ./bench_and_kill.sh [options]

Options:
  --log <path>           Path to debug log produced by tempo node (default: debug.log)
  --json-output <path>   Write summary metrics JSON to the given path
  --label <name>         Label to include in the metrics JSON
  --quiet                Suppress verbose analysis output
  --skip-analysis        Skip the log analysis step (use when orchestrator handles it)
  -h, --help             Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log)
      LOG_FILE="$2"
      shift 2
      ;;
    --json-output)
      JSON_OUTPUT="$2"
      shift 2
      ;;
    --label)
      ANALYZE_LABEL="$2"
      shift 2
      ;;
    --quiet)
      QUIET_ANALYZE=1
      shift
      ;;
    --skip-analysis)
      SKIP_ANALYSIS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

echo "Step 1: Running tempo-bench with max-tps..."
cargo run --bin tempo-bench run-max-tps \
  --tps 20000 \
  --target-urls http://localhost:8545 \
  --disable-thread-pinning true \
  --chain-id 1337

echo ""
echo "Step 2: Finding tempo node process..."
TEMPO_PID=$(pgrep -x tempo)

if [ -z "$TEMPO_PID" ]; then
  echo "No tempo process found"
  exit 1
fi

echo "Found tempo process with PID: $TEMPO_PID"

echo ""
echo "Step 3: Killing tempo node..."
kill "$TEMPO_PID"

echo "Tempo process killed successfully"

if [[ ${SKIP_ANALYSIS} -eq 1 ]]; then
  echo ""
  echo "Skipping log analysis step (requested via --skip-analysis)."
  exit 0
fi

echo ""
echo "Step 4: Analyzing logs (${LOG_FILE})..."
ANALYZE_ARGS=(--log "${LOG_FILE}")

if [[ -n "${JSON_OUTPUT}" ]]; then
  mkdir -p "$(dirname "${JSON_OUTPUT}")"
  ANALYZE_ARGS+=(--json "${JSON_OUTPUT}")
fi

if [[ -n "${ANALYZE_LABEL}" ]]; then
  ANALYZE_ARGS+=(--label "${ANALYZE_LABEL}")
fi

if [[ ${QUIET_ANALYZE} -eq 1 ]]; then
  ANALYZE_ARGS+=(--quiet)
fi

python3 analyze_log.py "${ANALYZE_ARGS[@]}"