#!/usr/bin/env bash
# Build one boundary-aware manifest from every production benchmark suite.
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TEMPO_REPO=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
SUITES_DIR="$TEMPO_REPO/contrib/bench/suites"

"$SCRIPT_DIR/merge-suites.py" \
  --out "$SUITES_DIR/all/manifest.json" \
  --name tempo-complete-benchmark-suite \
  "$SUITES_DIR/eest/batch-arithmetic-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-bitwise-context-flow-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-stack-memory-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-instruction-core-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-comparison-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-keccak-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-call-context-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-log-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-storage-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-system-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-precompile-basic-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-precompile-modexp-10m/manifest.json" \
  "$SUITES_DIR/eest/batch-scenarios-small-10m/manifest.json" \
  "$SUITES_DIR/tip20/existing-recipients/manifest.json" \
  "$SUITES_DIR/tip20/new-recipients/manifest.json" \
  "$SUITES_DIR/tip20/shared-existing-recipient/manifest.json"
