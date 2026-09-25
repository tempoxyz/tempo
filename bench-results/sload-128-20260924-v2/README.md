# Corrected 128-SLOAD rerun

Native suite started 2026-09-24 18:25:24 UTC:
`state-access-bloat-20260924-182524-130`.
The original nonbinding 10000000 transaction gas limit is retained. The first
attempt with a 500000 cap was rejected during warmup; see
`../sload-128-20260924/INVALID-INITIAL-ATTEMPT.md`. No measurements from it are used.

```sh
env TXGEN_TEMPO_BIN=/home/ubuntu/repos/txgen/target/release/txgen-tempo \
  TXGEN_BENCH_BIN=/home/ubuntu/.cargo/bin/bench \
  STATE_PATH_CHECKPOINT_TOOL=/home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/build-payload-cancel-20260923-v3/read_finish_checkpoint \
  nu --no-config-file bench-e2e.nu state-access-bloat-worst-case \
  --baseline HEAD --feature HEAD --case sload \
  --feature-binary /home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/bytecode-prefetch-e2e-20260924-v2/tempo \
  --feature-env RETH_BYTECODE_PREFETCH=1

node bench-results/sload-128-20260924-v2/analyze.cjs \
  bench-results/state-access-bloat-20260924-182524-130
```

The full original populated storage and code corpora remain present. The router
now chooses any of the 32 aligned 128-slot chunks in every original 4096-slot
logical page, so the active storage domain is not reduced. Standard 1200-second
load, 600-second warmup, 1000 TPS, 1000 signers, role isolation, memory limits and
prewarming are unchanged. The same archived binary as the successful bytecode
prefetch run is used, but the router hash and fixture state root have changed.

Acceptance requires at least 90% measured-window history coverage, 128 unique
populated cold SLOADs and zero parent-replay overlap in sampled non-first calls,
successful receipts, cursor reconciliation, and durable catch-up. Exact run
inputs are under `source/`; the analysis script writes `throughput.json` and
`throughput.md` only after a completed run passes its assertions.
