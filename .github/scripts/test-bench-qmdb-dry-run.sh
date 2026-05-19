#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

output="$(
  BENCH_CHAIN=mainnet-qmdb \
  BENCH_BLOCKS=2 \
  BENCH_WARMUP_BLOCKS=0 \
  BENCH_DRY_RUN=1 \
    bash .github/scripts/bench-tempo-replay.sh
)"

grep -F "source RPC: https://rpc.tempo.xyz" <<< "$output"
grep -F -- "--chain mainnet-qmdb" <<< "$output"
grep -F -- "--state-root.backend qmdb" <<< "$output"
grep -F "tempo translate-blocks" <<< "$output"
grep -F "benchmark range: 1..2" <<< "$output"
