# Persistence-path profile and optimization direction

Date: 2026-09-02

## Conclusion

The block-time wobble is not caused by CPU saturation, and “backpressure” is
not the underlying work. The high-confidence culprit is variable service time
in the storage-backed sparse-trie persistence path:

```text
sparse-trie reads/leaf updates
  -> random mmap/page-cache activity and trie allocation
  -> serial MDBX cursor/page writes in write_trie_updates_sorted
  -> slow save_blocks / commit
  -> persistence backlog and engine backpressure
  -> block-time spikes
```

Backpressure is the visible stop and an amplifier. It becomes active because
the one MDBX writer cannot drain the durable trie work quickly enough. Raising
the persistence or backpressure thresholds changes when the stop is reached;
it does not reduce the work or make the writer faster.

This profile localizes the expensive path well enough to choose the next
optimization category. It does not yet distinguish the last storage-level
microcause—cache policy versus trie layout/cursor traffic versus device
scheduler—so those should be measured with the next controlled A/B rather than
guessed at.

## Profile run

- Workflow: [33639450561](https://github.com/tempoxyz/tempo/actions/runs/33639450561)
- ClickHouse run: `c83c4a52-57bb-4523-a9dc-4a501f38114c`
- Revision: `4d9e35885f799b94a0285e4e81c51057ece86a0d`
- Workload: `tip20:recipient=existing,fee-token=any_tip20`, about 409.6M
  accounts, 100 GiB bloat, four TIP-20 tokens, 50,000 TPS target, 180-second
  timed phase
- Profiling: Samply feature build on both validators; CPU/page-fault/NVMe
  metrics scraped into ClickHouse
- Profile A: [Firefox profiler](https://share.firefox.dev/4xyV4pt)
- Profile B: [Firefox profiler](https://share.firefox.dev/4yjGu5h)

The timed phase produced 266 ClickHouse block rows: p50 `495 ms`, p90
`1,352 ms`, p99 `3,684 ms`, maximum `3,747 ms`. No block exceeded four
seconds in this particular 180-second sample, but the multi-second tail is
still present.

## Evidence

| Signal | Observation | What it rules in or out |
|---|---:|---|
| Host CPU | 56.2% busy across 32 CPUs; 4.37% iowait | Not whole-host CPU exhaustion |
| Tempo process CPU | Validator A `6.98`, B `7.57` CPU-seconds per wall-second | Both processes have CPU headroom; adding persistence threads is not the obvious win |
| Page faults | About `446k/s` minor and `74k/s` major | Heavy mmap/page-cache churn is present |
| I/O pressure | PSI “some I/O” about `0.199 s/s`; memory pressure about `0.003 s/s` | Storage stalls are material; global memory pressure is not |
| State NVMe queues | Average sampled `io_now`: nvme0 `96.7`, nvme1 `90.1`; weighted in-flight I/O: `133.0` and `127.5` | Both state devices are busy and tail-sensitive |
| State NVMe writes | About 66,091 MiB on nvme0 and 68,075 MiB on nvme1 in 178.4 s | The persistence workload is writing substantial state while serving reads |

The current runner has one NUMA node. `/reth-bench-a` used `nvme0n1` and
`/reth-bench-b` used `nvme1n1`; the `dm-0`/`dm-1` queue values were not counted
as extra devices because they aggregate those underlying NVMe devices.

### Persistence thread

Both validator profiles have the same inclusive hot-stack shape. The dominant
symbols are:

- `write_storage_trie_updates_sorted` / `write_trie_updates_sorted`;
- MDBX `txn_execute`, `cursor_del`, `cursor_put`, `cursor_seek`,
  `mdbx_cursor_del`, `page_touch`, `page_alloc_finalize`, and
  `gc_alloc_single`;
- kernel page-fault handlers and `mincore` probes.

The run-so-far `q=1` histogram snapshots reached the following values (these
are cumulative histogram snapshots, not exact per-block samples):

| Metric | Validator A | Validator B |
|---|---:|---:|
| `write_trie_updates` | `4.40 s` | `3.69 s` |
| `write_hashed_state` | `1.47 s` | `1.38 s` |
| `commit_mdbx` | `2.66 s` | `3.31 s` |
| `save_blocks` total | `8.23 s` | `7.17 s` |
| beacon backpressure stall | `4.10 s` | `2.67 s` |

The profile therefore catches the persistence thread doing the expensive
MDBX/page work itself; this is not merely an idle consumer waiting for some
other persistence task.

### Sparse-trie thread

The sparse-trie profiles independently show the algorithmic side of the same
path. The hottest functions are `ArenaParallelSparseTrie::make_progress`,
`process_leaf_updates`, `update_leaves`, `process_new_updates`, `seek`,
leaf-update sorting/quicksort, and arena/slot-map allocation. Keccak hashing
is present, but it is not the dominant sampled shape. The first code-level
targets are therefore leaf-update traversal, lookup locality, sorting/allocation,
and the handoff into the durable trie writer—not a blind increase in hashing
threads.

### State-root timing

In this profiling run, the state-root validation histogram snapshot reached
`300 ms` on A and `197 ms` on B, while the persistence stages reached several
seconds. Historical worst runs did show state-root validation tails up to
multiple seconds. These are two manifestations of the same large, sparse
state working set: reads/reconstruction can initiate a backlog, while durable
trie writes keep it alive. The current profile identifies the persistence
write path as the more direct optimization target.

## What to optimize

### 1. Reduce durable trie work first

The highest-value Reth/Tempo direction is to reduce the number and cost of
trie pages touched per persisted block or batch.

- Keep state masking enabled as the first operational mitigation. The tested
  configuration `threshold=7`, `memory_block_buffer_target=5`,
  `num_state_masking_blocks=1` reduced the aggregate block-time p99 by 83.9%
  in [33630670721](https://github.com/tempoxyz/tempo/actions/runs/33630670721)
  and removed the >4-second tail in its uploaded phase. It reduces the
  durable state/trie frontier; it does not make MDBX intrinsically faster, and
  its lower TPS/invalid-skip behavior still needs to be separated before it
  becomes a general default.
- Inspect whether the wide TIP-20 workload creates redundant updates that are
  merged too late or rewritten unnecessarily. Reth already merges pending
  trie updates across a save batch, so the useful question is how many unique
  nodes/pages survive that merge and how many cursor seeks/touches are needed
  to apply them.
- Optimize `write_storage_trie_updates_sorted`: preserve storage-prefix order,
  group operations that share pages, and avoid avoidable seek/delete/touch
  cycles. This is a concrete hot path from the profile, but must be benchmarked
  against MDBX correctness and write amplification.
- In the sparse trie, measure and reduce `process_leaf_updates`/`seek` and
  arena allocation churn. Disabling sparse-trie sharing is not a fix: it failed
  to meet the proposal deadline in the controlled experiment.

### 2. Tune cache and persistence boundaries

The page-fault and sparse-trie profile support testing cache retention and
pruning policy. The right experiment is a matched matrix of masking/window and
cache settings, recording major faults, trie-write duration, dirty-page/write
volume, and block-time tail. More RAM may postpone cold misses, but this run
had roughly 85 GiB available and negligible PSI memory pressure, so RAM alone
is not the primary diagnosis.

Do not add persistence workers as the first fix. The observed work is inside
one MDBX write transaction, and MDBX still has a single-writer serialization
point. Reth's storage pool parallelizes static-file/RocksDB work, not this
MDBX trie transaction.

### 3. Validate storage layout and scheduling

The next run should keep the topology dump and add per-device read/write
latency or queue-depth counters if available. It should verify that the state
mounts are on the intended NVMe devices, that benchmark copy/DM layers are not
being mistaken for independent devices, and that device interrupt locality is
understood. This runner exposes one NUMA node, so `numactl --interleave` is not
expected to fix it; a multi-NUMA machine would need a separate memory/IRQ
placement experiment.

## Next experiment and acceptance criteria

The next serious code experiment should compare default persistence with one
change at a time: state masking/cache retention, trie-update application, and
sparse-trie traversal/allocation. The instrumentation now staged in
`contrib/bench/clickhouse-metrics.txt` adds exact `_last` save-stage gauges and
per-device read/write counters for the following run.

For each phase, record:

- `write_trie_updates_last`, `write_hashed_state_last`, `commit_mdbx_last`,
  and total `save_blocks` duration;
- block-time p50/p99/p99.9, blocks over four seconds, and backpressure stall;
- minor/major faults, I/O PSI, per-device queue depth, read/write bytes, and
  process CPU;
- unique trie updates/pages and transaction/block, so a latency win is not
  confused with simply doing less useful work;
- valid transactions and application TPS separately from block-production
  smoothness.

The acceptance bar for a production fix is a repeatable reduction in
`write_trie_updates`/`save_blocks` tail and backpressure at the same workload,
without moving the cost into invalid transactions, unbounded memory growth, or
an artificially larger persistence backlog.

## Caveats

- The current ClickHouse run has the feature phase used for this profile; the
  baseline phase was not inserted as a comparable ClickHouse row, so these
  profile numbers are localization evidence, not a fresh A/B improvement
  claim.
- Prometheus histogram `q=1` samples are run-so-far snapshots. They identify
  the tail but cannot be joined exactly to a block with the current
  `txgen_blocks` schema.
- Host page-fault and disk counters are runner-wide. The topology and the
  matching persistence stacks make the attribution strong, but a future run
  should expose per-node/device operation IDs for exact event correlation.
- Older investigation text contains a runner-specific `nvme2`/`nvme3`
  mapping. The profiling runner used `nvme0`/`nvme1`; device names must always
  be taken from that run's topology dump.

## Sources

- [Profiling workflow](https://github.com/tempoxyz/tempo/actions/runs/33639450561)
- [Reth `save_blocks` implementation](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/storage/provider/src/providers/database/provider.rs#L573-L795)
- [Reth persistence service](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/persistence.rs#L36-L225)
- [Reth state-masking frontier](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/tree/mod.rs#L2252-L2343)
- [State-masking A/B](https://github.com/tempoxyz/tempo/actions/runs/33630670721)
