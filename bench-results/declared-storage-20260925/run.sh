#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/repos/tempo-payments-bloat-pr
export STATE_PATH_CHECKPOINT_TOOL="$PWD/bench-results/declared-storage-20260925/tools/read_finish_checkpoint"
export STATE_PATH_CACHE_EVICT_TOOL="$PWD/bench-results/declared-storage-20260925/tools/evict-benchmark-file-cache"
export TXGEN_TEMPO_BIN="$PWD/bench-results/declared-storage-20260925/tools/txgen-tempo"
export TXGEN_BENCH_BIN="$PWD/bench-results/declared-storage-20260925/tools/bench"
exec nu --no-config-file bench-e2e.nu state-access-bloat-worst-case --declared-storage \
  --feature-binary "$PWD/bench-results/declared-storage-20260925/tools/tempo" \
  --feature-env TEMPO_BENCH_TX_TIMING=1
