# Near-cap state access

Separate saved variants target the tested Tempo 30M transaction gas cap:
13800 cold SLOADs and 10800 EXTCODECOPY operations. The latter still copies only
32 bytes at offset 1 from each selected 24 KiB code blob; it does not inflate
copy or memory-expansion gas. Random code draws can repeat, so audits require
at least 99% cold and unique targets. Read ranges remain wholly inside the
original populated storage domain. Both selectors include the history cursor.

Existing 128-read/code and 4096-read entry points remain available. Build the
router with `bash contrib/bench/txgen/compile-history-state-paths.sh`, run its
`--test` mode, then install it with `bash contrib/bench/update-history-router.sh`.
The guarded update changes only the router and corresponding root in prepared
history fixtures, not the state/code corpus. It archives before/after metadata.

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  contrib/bench/evict-benchmark-file-cache.c -o /tmp/tempo-evict-file-cache
export STATE_PATH_CACHE_EVICT_TOOL=/tmp/tempo-evict-file-cache
export STATE_PATH_CHECKPOINT_TOOL=/absolute/path/to/read_finish_checkpoint
export TXGEN_TEMPO_BIN=/absolute/path/to/txgen-tempo
export TXGEN_BENCH_BIN=/absolute/path/to/bench

nu bench-e2e.nu state-access-bloat-worst-case \
  --max-transaction-size --baseline HEAD --feature HEAD
```

Use `--case sload` or `--case bytecode` to select one. `--dry-run` and `--list`
work without touching the fixture. This profile enables targeted bytecode
prefetch, leaves prewarming enabled, and applies 20 GiB per node, zero swap,
and verified per-file cold-start eviction. Ordinary suite defaults are unchanged.

For an archived, fixed-binary paired experiment with live CPU/flag/limit evidence:

```sh
node contrib/bench/run-sload-size-isolation.cjs \
  /absolute/path/to/tempo bench-results/max-state-access-UNIQUE_ID \
  --max-transaction-size
```

The paired runner hashes tools, fixture and sources, restores before each case,
and reports builder/follower execution, canonical production, durable progress,
backlog, page faults and physical I/O. Each load lasts 1200 seconds and excludes
the first 600 seconds. Populated-state calls calibrate gas before timed load;
post-load audits verify actual successful receipt gas of 29.7-30M, access sets,
cold opcodes, corpus contents, cursor reconciliation and durable catch-up.
One small, excluded transaction first initializes the cursor: Tempo charges
250k for creating its storage slot, which would otherwise push the first
near-cap transaction over budget even though subsequent transactions fit.
The preflight archives this initialization receipt; workload cursor checks
reconcile against the actual pre-load value rather than assuming zero.
For near-cap opcode replays, the simulated legacy sender nonce is set to 1.
Otherwise `debug_traceCall` charges legacy new-account gas absent from the
actual AA transaction and can spuriously run out of gas. The router ignores
sender nonce. Actual receipts, actual prestate, and access-set/output equality
remain authoritative; replay gas is not substituted for transaction gas.

Near-cap transactions may be the only transaction in a block. Unlike the small
history-bypass workload, these cases explicitly allow first-transaction trace
samples and report their actual history eligibility. Do not claim proven
within-block bypass when eligibility is low. Whole-node I/O includes speculative
work and persistence; it is not an opcode-attributed cache-miss counter. Growing
follower backlog disqualifies production rate as sustainable end-to-end throughput.

## Sparse Or Stalled Outcomes

The 2026-09-25 paired run produced only four bytecode transactions in the full
20-minute load, two after warmup. Such a run intentionally fails the ordinary
minimum-eight-receipt audit; that is not evidence that the load never ran.
Preserve the failed manifest and audit every available inclusion separately.
Do not relax the ordinary suite's sampling gate or claim a steady-state
execution rate from a handful of surviving proposals.

The current bench binary trims its scrape archive before the final reported
block. For sparse runs, this can omit a substantial idle tail and even the
last inclusion's counter increment. Use the original metric clock to define
the full [600s,1200s] window. Canonical block timestamps, the untrimmed node
logs and the independent cgroup observer retain the necessary evidence.
Cross-check reconstructed execution durations against retained counter deltas.
Do not shorten the denominator to the surviving scrape window.

The archived result and reconstruction scripts are in
`bench-results/max-state-access-20260925-final/`; see its `README.md` and
`throughput.md`. The sparse-result audit is post-load only and retains the
standard suite's failed outcome. The timing reconstruction corrects analysis,
not the measured workload or node binary.
