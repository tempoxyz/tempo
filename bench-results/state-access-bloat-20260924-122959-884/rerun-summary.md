# SLOAD rerun: 2026-09-24

The native suite completed with exit code 0. The correctness and persistence
audit passed without changing the original 4,096-SLOAD workload or relaxing
the minimum three non-first-transaction trace samples.

## Reproduction

Run from the repository root, with the prepared block-zero `history_paths`
fixtures. This deliberately selects the same locally patched binary used for
the earlier bytecode and write runs; it is not a benchmark of unpatched HEAD.

```sh
env TXGEN_TEMPO_BIN=/home/ubuntu/repos/txgen/target/release/txgen-tempo \
  TXGEN_BENCH_BIN=/home/ubuntu/.cargo/bin/bench \
  STATE_PATH_CHECKPOINT_TOOL=/home/ubuntu/repos/tempo-payments-bloat-pr/target/profiling/examples/read_finish_checkpoint \
  nu --no-config-file bench-e2e.nu state-access-bloat-worst-case \
    --baseline HEAD --feature HEAD --case sload \
    --feature-binary /home/ubuntu/repos/tempo-payments-bloat-pr/target/profiling/tempo
```

- Harness revision: `84dd0be10d38a0d3e2670c7371a16f028a8bcaf0`.
- Node SHA256: `57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6`.
- Generator SHA256: `cfd237552aa6fa8210cdfdc3b6089a80e620f097fb857abfbef2b9f573307d6a`.
- Sender SHA256: `ae47ab9631c6aa59c5435b087d19a40e083fa78b61b4f5fdda98b18391c39d5c`.
- Load: 1,000 offered TPS, 1,000 signers, 1,200 seconds, first 600 seconds excluded.
- Fixture: original 100,000 MiB populated storage plus 100,000 MiB unique bytecode.
- Prewarming enabled, no artificial transaction cap, unchanged CPU/role/device allocation.

## Throughput

Rates use the same aligned-counter analysis functions as the earlier two-case
report. Execution rates divide gas by instrumented execution time, not wall time.
Chain rates count canonical gas over elapsed time. Durable rates follow state/trie
persistence frontiers and can temporarily exceed chain rates during catch-up.

| Case | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s | Follower durable Mgas/s |
| --- | ---: | ---: | ---: | ---: |
| SLOAD rerun | 19.524 | 42.479 | 19.257 | 19.432 |
| Earlier bytecode | 6.110 | 7.743 | 5.982 | 5.356 |
| Earlier writes | 66.822 | 68.444 | 22.240 | 8.404 |

The binary hash, offered load, duration, warmup, and large data corpora match.
However, the router was updated to inherit the original SLOAD entry points after
the earlier bytecode/write runs. Router hash and fixture state root therefore
differ. These are not an exact-fixture three-way comparison; bytecode and writes
would need fresh runs on the shared router to establish one.

## Validation and Limits

The measured block window contained 1,292 blocks and 1,297 transactions. Only
five transactions (0.386%) had a preceding workload transaction in their block.
Across the full load, the corresponding fraction was 26/2,946 (0.883%). The five
measured multi-transaction blocks were 1707, 2385, 2503, 2653, and 2983.

All three sampled non-first transactions accessed 4,096 populated slots with
2,100-gas cold SLOADs and zero overlap with parent-state replay. Fourteen sampled
receipts succeeded. The cursor advance reconciled all 2,946 included workload
transactions, and both nodes durably persisted through drained block 3039.

This passes the sampled mechanism audit, but the small history-advanced fraction
does not establish widespread avoidance of parent-state prewarming. It must not
be treated as a robustly cache-evasive worst case merely because the audit passed.
First transactions can match parent-state prewarming; actual cache misses can
still arise from capacity, timing, and other speculative work.

All 1,281 observed builder stop events in the counter window were build-budget
stops. Follower producer-to-durable backlog fell from 0.446 to 0.366 Ggas rather
than growing. This is one sustained run, not a statistical confidence interval
or proof of asymptotic capacity.

## State Access

| Role | Storage-cache misses/Mgas | Whole-node major faults/executed Mgas | Whole-node read I/Os/executed Mgas |
| --- | ---: | ---: | ---: |
| Builder | 457.485 | 8,129.601 | 7,874.037 |
| Follower | 459.819 | 333.824 | 333.826 |

Whole-node faults and I/O include prewarming, persistence, and speculative work
for transactions that are never included. They are not direct SLOAD attribution
or unique-page counts. Builder speculative amplification must not be presented
as physical reads caused only by the finally included SLOADs.

## Evidence

- `manifest.json` and `configuration.json`: native suite settings and provenance.
- `rerun-analysis.json`: aligned rates, raw endpoints, observer metrics, history coverage, and comparison checks.
- `../20260924-123000-011/`: standard summary, raw samples, observer archive, priming evidence, and correctness/traces.
- `../sload-rerun-20260924-1230.log`: complete runner output.
- `../history-state-paths-sustained-20260924-v2/throughput.json`: earlier bytecode/write reference rates.

No runtime source changes, fixture updates, audit relaxations, or additional
bytecode/write runs were made for this rerun.
