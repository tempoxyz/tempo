# Tempo resident-state controls: capped throughput baseline

2026-09-23. Draft for Google Docs; not yet published to Google Docs.

## Summary

Two cache-resident application workloads sustained 86.83 and 78.32 Mgas/s in
the completed runs. These are worth tracking against the stated 1 Ggas/s target,
but **they do not establish an execution ceiling below that target**: every
measured builder block hit an explicit 900-transaction cap. Follower execution
alone processed gas at 2.69 and 2.48 Ggas/s, excluding the rest of the chain's
wall-clock time. Neither metric by itself establishes uncapped sustainable
throughput.

## Cases and results

Both cases deployed the same unmodified 7514-byte StrategyVault runtime and used
1000 funded accounts, expiring-nonce Tempo transactions, and PathUSD fees.

| Case | Application work | Canonical Mgas/s | Canonical tx/s | Follower execution Ggas/s |
| --- | --- | ---: | ---: | ---: |
| Getter reads | Three calls: name, symbol, decimals | 86.83 | 1875.63 | 2.689 |
| Allowance writes | Approve a bounded varying amount to one fixed spender | 78.32 | 1872.61 | 2.482 |

At approximately 2.08 blocks/s, 900 transactions/block permits about 1875 tx/s.
Multiplying by approximately 46293 gas/read transaction or 41826 gas/write
transaction explains the observed gas rates. The lower write rate is therefore
not evidence that writes exhausted disk or execution capacity.

The active code/storage working sets were small and reused. Although the
original database contained 100 GB of imported storage bloat, that did not make
these accesses cold. Measured follower database-device reads were 0.00586
I/Os/Mgas for reads and zero for writes. Corresponding whole-node write traffic
was about 268 and 305 kB/Mgas. Those I/O counters include trie/persistence and
other node work; they are not EVM-only cache misses.

## Method and confidence

Each original load lasted 20 minutes; the first 10 were excluded. Offered load
was 50000 TPS with a 900-transaction block cap and permissive gas limits. One
node proposed; the follower had no transaction ingress. CPU sets and database
devices were separate, but host RAM was shared. Builder prewarming was enabled.

Each case passed 7200 sampled successful receipts, three real call/storage-diff
checks, and durable state/trie catch-up on both nodes. No stall recurred. The
binary included cancellation/resource-lifecycle fixes and a RocksDB cache-shard
fix; total RocksDB cache capacity remained 128 MiB. These are single-run control
measurements, not confidence intervals or worst-case state-access results.

Tempo base: f62969a95e8a787d2956f3509d25c533bdaac746.
Exact binary SHA256:
57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6.
Source results: bench-results/state-path-controls-patched-20260923-v4/throughput.json.

## Reproduction and next measurement

`contrib/bench/run-clean-state-path-controls.sh` now runs these exact application
presets on freshly generated zero-bloat databases, with no dump import or
dependency on historical results. It records binary/source hashes and performs
the same receipt, trace, and persistence checks. Instructions are in
`contrib/bench/resident-state-paths.md`.

Keep the default cap to reproduce the baseline. A separate run with
`STATE_PATH_MAX_TRANSACTIONS=none` removes that artificial ceiling while keeping
the ordinary workloads unchanged. Compare canonical throughput and durable
follower progress with the 1 Ggas/s target; use execution-only rates and stop
reasons to explain the result rather than substituting them for chain capacity.

## Clean-database verification

The new runner passed both cases on fresh zero-bloat databases on 2026-09-23:
86.01 Mgas/s reads and 77.58 Mgas/s writes. These were six-minute verification
loads with one minute excluded, 5000 offered TPS, and the same 900-transaction
cap. Each passed 7200 sampled receipts, three trace checks, and persistence on
both nodes. This reproduces the capped behavior without a bloat database; it
is not an uncapped capacity test or a replacement for the original 20-minute
measurements. Results: bench-results/resident-state-paths-clean-smoke-20260923.
