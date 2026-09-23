# Persistence timing comparison

Run serial, parallel-table, and sharded-table builds from the same OTEL-fixed
baseline family. Keep the load generator, state size, duration, node arguments,
cache reset, and instrumentation identical. This is a diagnostic comparison;
per-operation timing adds overhead and must not be presented as an uninstrumented
throughput result.

Enable transaction-local operation timing on both nodes with the benchmark
options `--baseline-env=RETH_PERSISTENCE_TIMINGS=1` and
`--feature-env=RETH_PERSISTENCE_TIMINGS=1`. Keep debug logs for
`engine::persistence`, `engine::tree::payload_validator`, and the payload builder.
The normal OTLP benchmark configuration exports these structured logs.

Export these messages for the exact benchmark ID and phase time range:

- `Persistence table operations`: logical table name, operation count, summed
  operation nanoseconds. Covers timed cursor and transaction calls in
  `save_blocks`; includes reads/seeks required by writes. Does not measure time
  spent outside those calls. Sharded tables aggregate their physical cursors.
- `Persistence table task`: full wall time and start offset for the account,
  storage, account-trie, and storage-trie writing tasks; includes a shard index
  and thread ID. Parallel task offsets share one origin, allowing overlap to be
  measured. Serial task groups do not share one origin.
- `Persistence worker preparation`: setup time and actual persistence pool size.
- `Persistence child transaction commits`: time to publish child metadata into
  the parent transaction after the parallel workers finish.
- `Persistence batch writes`: `save_blocks` wall time and overlapping backend
  times, block/transaction counts, and separate state-trie block count.
- `Persistence batch complete`: complete persistence wall time including commit
  and BAL flush, plus the duration of the provider commit separately.
- `Executed block`, `Executed block via BAL path`: validator execution seconds.
- `Built payload`: builder wall time and transaction-execution time in seconds.

Keep `benchmark_id`, `benchmark_run`, `runner_role`, `last_block_number`,
`state_block_number`, and the numeric fields in the export. The block-data and
state-trie frontiers identify a batch within one node/phase. The analysis rejects
unmatched write/completion events from persistence totals. Check exported log
coverage and dropped-log warnings before interpreting missing table events.

```sh
uv run python scripts/bench-persistence-timings.py logs.json --output timings.json
uv run python scripts/test_bench_persistence_timings.py
```

For each node and phase, compare:

1. Mean builder time and mean validator execution time (separate populations;
   execution attempts may include speculative or repeated work).
2. Mean produced-block interval from the benchmark's `summary.json`.
3. Sum of complete persistence durations divided by persisted block count, and
   its reciprocal (blocks per second while persistence is busy).
4. Sum of complete persistence durations divided by persisted transactions.
5. Per-table task means and operation totals; include child/parent commit time.

Do not add overlapping worker/backend durations to obtain wall time. Do not
average per-batch ratios when batch sizes differ. Preserve node/phase samples
when comparing runs, rather than counting every block as an independent trial.
Partial state-trie persistence can advance separately from block data; report
both counts and avoid treating the block-normalized figure as single-block
latency. Backpressure also depends on allowed backlog and batch scheduling, so
an average alone cannot prove the absence of future stalls.
