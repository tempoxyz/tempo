# Persistence timing comparison

Use normal Prometheus metrics on serial, parallel-only and sharded builds.
No environment switch or per-cursor-operation instrumentation is required.
Enable ordinary benchmark metrics collection on both sides.

New Prometheus metrics:

- `reth_storage_providers_database_table_write_seconds{table,shard}`: wall time
  per table-writing loop/task, including preparation and seeks. Shared helpers
  also run during init/sync: query only the measured benchmark phase.
  State/trie workers run per batch; other tables can run per block.
- `reth_storage_providers_database_persistence_worker_preparation_seconds` and
  `reth_storage_providers_database_persistence_child_commit_seconds`: parallel
  worker setup and child-transaction commit time.
- `reth_consensus_engine_persistence_persisted_blocks_total`,
  `persisted_transactions_total`, and `persisted_state_trie_blocks_total`
  (same prefix): counts recorded after successful provider commit.
- `reth_consensus_engine_persistence_commit_duration_seconds`: provider commit.

Reuse existing persistence `save_blocks_duration_seconds`, provider
`save_blocks_total` and backend timers, validator
`reth_sync_execution_execution_histogram`, builder
`reth_tempo_payload_builder_payload_build_duration_seconds` and
`reth_tempo_payload_builder_block_time_millis`.

For one node and measured phase:

1. Per-table mean = duration sum increase / observation count increase.
2. Complete persistence time/block = save_blocks_duration_seconds sum increase /
   persisted_blocks_total increase. Includes commit and BAL flush.
3. Service throughput = persisted blocks or transactions / complete persistence
   duration. This is capacity while busy, not network TPS.
4. Execution/build mean = duration sum / count. These are execution attempts,
   potentially speculative/repeated, not necessarily distinct canonical blocks.
5. Produced-block interval = block_time_millis sum / count; check summary.json too.

Do not add overlapping table/backend durations to obtain wall time. Keep each
shard separate. Use sums/counts rather than averaging batch ratios. State/trie
and block-data frontiers can advance separately; report both counts. Missing
table observations are not a measured zero. Static-file/RocksDB work uses backend
timers, not MDBX table labels. Failed task observations are attempts; exclude
failed benchmark phases before comparing successful persistence counts.

Export a Prometheus query_range matrix for the exact measured phase and these
metric families, including _sum/_count and persisted counters, with node and
benchmark labels preserved. Then run:

```sh
uv run python scripts/bench-persistence-timings.py metrics.json --output timings.json
uv run python scripts/test_bench_persistence_timings.py
```

The report uses first-to-last scrape deltas and rejects resets or fewer than two
samples. Check scrape bounds: first-use registration or missing scrapes can omit
early observations. Native increase/rate queries interpolate boundaries; do not
silently mix those estimates with exact deltas. Compare matched workloads/state
sizes and preserve per-node/per-phase samples. TPS verdicts come from summary.json
and paired-run noise, not from persistence timings alone.
