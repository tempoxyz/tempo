# Why the follower is faster

Reanalysis of the two completed sized-transaction runs. No new benchmark or
runtime change was needed for these findings.

## Main finding: serialized prewarming delays the next payload

The builder's reported transaction-execution timer covers the whole transaction
fill loop, including waiting for its transaction iterator. The follower's
`Executed block` timer covers block execution and execution finalization, not
builder transaction selection or the builder-prewarm coordinator queue.

| Metric | SLOAD (7200/tx) | Bytecode (2250/tx) |
| --- | ---: | ---: |
| Previously reported builder throughput, Mgas/s | 17.775 | 6.879 |
| Builder transaction-call-only throughput, Mgas/s | 35.124 | 12.901 |
| Follower block execution throughput, Mgas/s | 37.524 | 16.630 |
| Mean builder transaction fill, ms | 880.084 | 909.483 |
| Mean builder transaction call, ms | 445.389 | 484.928 |
| Mean fill time outside transaction call, ms | 434.695 | 424.555 |
| Mean builder-prewarm queue wait, ms | 434.536 | 424.393 |
| Mean follower block execution, ms (approximately) | 416.904 | 376.203 |

The call-only rate joins valid timed attempts to completed nonempty payloads by
payload ID and divides their gas by summed transaction-call durations. It is not
an end-to-end throughput measurement. It excludes selection/wait/finalization;
the follower timer also includes execution finalization, so the timer boundaries
are close but not identical. Follower means above use average canonical gas/tx
and aggregate execution throughput; endpoint block cohorts can differ by one.

Raw metric endpoints within the same 600-second measurement window span 595
seconds. `reth_executor_named_worker_queue_wait_duration_seconds_{sum,count}`
with `node=a,worker=builder-prewarm` increases by:

- SLOAD: 292.008427505 seconds / 672 starts = 434.536 ms/start.
- Bytecode: 275.431201098 seconds / 649 starts = 424.393 ms/start.

This accounts for approximately 94% and 80% of the mean builder-fill versus
follower-execution timing gap respectively. These are aggregate decompositions,
not per-job queue/attempt joins or confidence intervals.

The source explains the queue:

1. Tempo launches every prewarm coordinator through the same named
   `builder-prewarm` worker. Reth executes jobs for a given name sequentially.
2. Prewarming seeds speculative transactions and replenishes them while building.
   Only one actual transaction lands per measured block in these runs.
3. Dropping the builder iterator requests stop, but an already-running
   `evm.transact_raw` is not interrupted by this stop flag. The scoped workers
   and cleanup must finish before the named coordinator job returns.
4. The next payload's coordinator queues behind that previous job. Its builder
   blocks in `transactions_rx.recv()` before receiving its first transaction.

This is waiting for the previous payload's speculative work to drain, not a
requirement to finish prewarming the next selected transaction. In the measured
nonparallel mode, the coordinator sends candidates before prewarming them.

All measured payloads record zero explicit transaction-fill idle sleep and no
invalid transaction attempts. Builder finalization p50 is 0.310 ms for SLOAD and
0.586 ms for bytecode. The delay is not empty-pool sleep, state-root finalization,
or proposal cancellation; both selected measured windows had zero cancellations.

## Why actual execution is also slower

Builder transaction execution remains approximately 7% slower in rate than
follower block execution for SLOAD (follower/builder = 1.068), and 29% for bytecode
(1.289). The nodes do not do equal physical work:

| Whole-node physical DB reads | SLOAD | Bytecode |
| --- | ---: | ---: |
| Builder, MB/s | 640.858 | 1947.141 |
| Follower, MB/s | 27.714 | 63.891 |
| Builder/follower ratio | 23.124 | 30.476 |

The follower receives only included blocks, has transaction ingress/gossip
disabled, and skips transaction prewarming below five transactions. Its prewarm
execution counter has zero increment during both measured windows. The builder
speculates over additional mempool transactions with different salts, generating
additional state accesses without additional canonical gas.

The builder also fails to advance its execution cache after every measured
payload: half report the cache still in use, and half cannot find a cache for
the parent. It creates a new cache on half the following lookups (339/678 SLOAD,
327/654 bytecode), consistent with speculative work retaining cache references.
The follower's normal path updates the cache after execution.

Lower follower I/O does not mean all follower state is cached. Its source=engine
getter counters still show approximately 99.86% storage misses for SLOAD and
100% code misses for bytecode over the observer endpoints. Application-cache
misses and physical page reads are different measures. The databases are on
separate NVMe devices; the follower does not share the builder's DB page cache.

The earlier four-cell SLOAD size/prewarming control independently found that
turning prewarming off increased 4096-read chain throughput from 18.013 to 38.798
Mgas/s and sharply reduced physical I/O per included read. That supports the
speculation/contention mechanism, but is not a matched off-control for these
7200/2250 sizes. The residual execution-time difference has not been separately
apportioned among I/O contention, CPU competition, and cache churn.

Whole-node read ratios are not unique page misses per opcode and do not measure
the number of speculative transactions directly. Removing queue delay alone
does not establish a 2x safe sustained speedup; speculative work would still
need bounding or cancellation. Follower execution throughput also excludes its
wall-clock wait for new blocks and is not measured saturated follower capacity.

## Evidence

- SLOAD raw run: `bench-results/20260925-161847-632`.
- Bytecode raw run: `bench-results/20260925-153713-270`.
- Both: `latency-analysis.json`, full A/B logs, raw metric NDJSON gzip,
  `state-path-observer-feature-1.jsonl`, and saved live command lines.
- Tempo: `crates/payload/builder/src/prewarming.rs`: coordinator at line 80,
  scoped work at 110, whole-transaction execution at 255, stop/drop and iterator
  at 308 and 320. This file matches the binary's archived build source exactly.
- Tempo: `crates/payload/builder/src/lib.rs`: fill timer starts at 511,
  transaction-call instrumentation at 672, reported timer at 807.
- Reth: `crates/tasks/src/runtime.rs:535` and `worker_map.rs:41`: serialized named
  worker and its queue-wait instrumentation.
- Reth: `crates/engine/tree/src/tree/payload_processor/mod.rs:51,221,495`:
  small-block prewarm threshold, gating, and cache update conditions.
- Reth: `crates/engine/tree/src/tree/payload_validator.rs:1073`: execution timer.
