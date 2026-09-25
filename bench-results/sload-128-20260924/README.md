# 128-SLOAD rerun

Started native suite at 2026-09-24 18:14:07 UTC. The only workload change is
transaction granularity: 128 reads from uniformly selected aligned chunks over
the full original populated state, instead of 4096 reads. Both the storage and
unique bytecode corpora are retained. The old router artifact is archived here.
Router-only fixture update: `../history-router-update-20260924-181353`.

```sh
env TXGEN_TEMPO_BIN=/home/ubuntu/repos/txgen/target/release/txgen-tempo \
  TXGEN_BENCH_BIN=/home/ubuntu/.cargo/bin/bench \
  STATE_PATH_CHECKPOINT_TOOL=/home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/build-payload-cancel-20260923-v3/read_finish_checkpoint \
  nu --no-config-file bench-e2e.nu state-access-bloat-worst-case \
  --baseline HEAD --feature HEAD --case sload \
  --feature-binary /home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/bytecode-prefetch-e2e-20260924-v2/tempo \
  --feature-env RETH_BYTECODE_PREFETCH=1

node bench-results/sload-128-20260924/analyze.cjs \
  bench-results/state-access-bloat-20260924-181407-282
```

The benchmark retains the standard 1200-second load, 600-second warmup, 1000 TPS,
1000 signers, CPU/device allocation, memory limits, and prewarming. Acceptance
requires at least 90% measured-window history coverage, sampled zero-overlap
parent-state replays, 128 unique populated cold SLOADs, successful receipts,
cursor reconciliation, and durable catch-up. Raw source inputs are in `source/`.
