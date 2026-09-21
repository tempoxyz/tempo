# Execution and proof-read readiness

Deep dive into run [35578876523](https://github.com/tempoxyz/tempo/actions/runs/35578876523),
following [the causal reanalysis](CAUSAL-REANALYSIS-2026-09-21.md).
Pinned Tempo `0bd62dd2f0e509016439b2189cd0f4998d007a26`, Reth
`000fc3cdf3d5f09a816ad30554a555881f2e28bf`. All evidence is from the
previously audited pre-backpressure capture. No new node experiment was run
for this analysis. These are mechanisms and experiment candidates, not
benchmark-proven savings.

## Execution: many synchronous read waits, with concurrent proof faults

The worst executor fault total, 101.487 ms on block32, is not one continuous
pause. Audited focused scheduler exports decompose it as follows:

| Receiver block | Execution wall | Fault-path blocked total | Sleep intervals | Median / p90 sleep | Longest sleep |
|---|---:|---:|---:|---:|---:|
| 32 | 261.546 ms | 101.487 ms | 465 | 0.077 / 0.374 ms | 18.718 ms |
| 11 | 151.898 ms | 21.972 ms | 314 | 0.067 / 0.093 ms | 0.476 ms |
| 71 | 85.728 ms | 3.406 ms | 15 | 0.066 / 0.075 ms | 2.479 ms |

These are scheduling sleep intervals inside the filemap-fault I/O path, not
counts of unique page faults or physical device reads. For block32, 11 exceed
1 ms and only one exceeds 5 ms. Therefore a logger that emits only individual
reads above 5 ms would miss a potentially important accumulation of short
waits. Block11 demonstrates that even 22 ms of accumulated blocking need not
contain a single sleep above 0.5 ms.

During block32's executor fault waits, **27.645 of its 32 storage-proof workers
are also fault-blocked on average**, plus 13.206 other registered threads.
The storage-worker association uses that block's worker spans, source thread
ordinals and overlapping worker lifetimes, not virtual Perfetto lanes. For
block11 the corresponding storage-worker average is 20.645; for block71,
3.252. Other registered threads are not identified as prewarm workers because
this capture does not establish that classification.

This establishes concurrent demand for file-backed data. It does not establish
common pages, shared device contention, device saturation, reclaim or eviction.
The 2,805.603 ms of overlapping storage-worker faults during block32's
101.487 ms of executor faults is concurrent worker time, never additional
block wall time. We must not claim all 101 ms is removable by changing proof
scheduling.

## Where the execution reads come from

The serial receiver executes transactions immediately as conversion supplies
them. Each converted transaction is offered to both prewarm and execution;
there is **no prewarm-completion dependency** before authoritative execution.
The prewarm channel is sized to the complete block, and the coordinator may
submit the entire converted stream. The builder's bounded initial lookahead
is not this receiver path.

Source chain on an execution-cache miss:

1. `engine/execution-cache/src/cached_state.rs:848,890,927`: txpool snapshot,
   then shared account/storage/code cache. Canonical execution is lookup-only;
   prewarm fills on a miss.
2. `storage/storage-overlay/src/provider.rs:408,825`: execution overlay, then
   optional historical fallback or current DB state. The actual engine uses
   this overlay provider; instrumenting only `LatestStateProvider` would miss
   this path.
3. The overlay's `basic_account_from_db` and `storage_from_db` use the configured
   hashed or plain account/storage tables. Storage uses a duplicate cursor
   `seek_by_key_subkey`; historical fallback can also read history/changesets.
4. MDBX reads are synchronous; its environment explicitly sets `no_rdahead:
   true` for random-access workloads (`storage/db/src/implementation/mdbx/mod.rs:469`).
   This is an existing deliberate policy, not evidence that enabling global
   readahead would help.

The benchmark's random existing recipients span the large bloat pool. TIP20
balances are mapping slots: transfer credits the recipient through
`increment_balance`, then storage increment reads the existing value. Thus
1,000 sending accounts does not imply a 1,000-entry storage working set.
The trace still does not identify recipient balance reads as the measured
fault source; that requires per-operation attribution.

Fixed-cache 0.1.10 is best effort: `get_inner` uses `try_lock`; its
`get_or_try_insert_with_ref` performs the miss initializer before insertion,
without an in-flight-read reservation. An executor and prewarmer may both
reach the underlying read before the result is published. This is not proof
of duplicate physical I/O: kernel page-cache machinery may share the same
in-progress page read. Cache contention can cause misses but does not itself
park the executor behind a lock held across the prewarm database read.

Prewarm workers skip obsolete transactions before `evm.transact`; they do not
check the execution frontier before each provider read. A transaction already
running can continue issuing reads after execution passes it. Access hints
for proofs are emitted after speculative transaction completion. These are
candidate sources of insufficient or wasteful read preparation; occurrence
and cost are not measured in this capture.

Cross-block cache availability also needs its own counter. A matching-parent
cache with outstanding handles can be unavailable for checkout, causing
`cache_for` to allocate a fresh cache. A parent mismatch clears cached state;
insertion can be skipped while another user holds the cache. These are safety
conditions, not instructions to reuse stale data. Record the checkout reason
(`disabled`, `fresh_absent`, `fresh_matching_parent_in_use`,
`fresh_other_parent_in_use`, `reuse_matching_parent`,
`reuse_after_parent_reset`) before concluding
that warm entries were evicted or that increasing cache capacity would help.

## Proof tail: the queue grows while execution is running

Block11's proof work begins about 0.486 ms after execution starts. It is not
waiting until the end of execution to begin:

| Time since execution start | Dispatched account-proof jobs | Service-completed jobs |
|---|---:|---:|
| 25 ms | 247 | 65 |
| 75 ms | 518 | 227 |
| 150 ms | 1,075 | 499 |
| Execution end, about 151.9 ms | 1,078 | 500 |

At the first drain observation, the 579 outstanding batches reconcile as
**538 still queued + 32 executing + a 9-result completion/consumption gap**.
All 1,080 jobs have then been dispatched and 501 consumed. The nine is
service-completed minus consumed, not a direct result-channel occupancy
measurement: result publication precedes service completion. This rules out
slow result consumption as the main explanation for this particular backlog.

Account queue wait p50/p90/max is 75.052/116.469/128.260 ms, versus storage
queue wait 1.516/9.030/21.343 ms. Account workers dispatch storage proofs and
wait for their results while occupying the account-worker slots. The short
storage queue therefore does not show the full upstream backlog.

Only two account targets does not mean a two-entry working set: TIP20
recipient balances are storage slots under token accounts. This block has
10,180 storage targets across 1,479 storage jobs; 1,200 jobs contain 2–8
targets. Existing target dedup means these counts do not prove duplicate reads.

The original dependency join remains decisive: the final storage child spends
33.483 ms fault-blocked; four final storage roots take about 10 ms concurrently;
final account-root hashing takes 0.067 ms. Account-root hashing is a poor
first optimization target for this outlier.

## Next experiments and the evidence each needs

First measure **readiness and work amplification**, with low-volume accounting:

- Thread-local aggregate counts and duration buckets for every provider read,
  classified as account/storage/code and snapshot/cache/overlay/current DB/
  history fallback. Include sub-millisecond reads. Flush per block or worker;
  do not emit a tracing span or take `getrusage` on every storage access.
- A bounded sample of exact slow-read intervals with parent block/job ID and
  a closed operation/table class. Mark sampling, overflow and unattributed
  time explicitly. Preserve strict cutoff and pruning.
- Record prewarm start/completion distance from the authoritative transaction
  frontier. For selected misses, an in-memory diagnostic map can distinguish
  never scheduled, queued, read in flight and completed-but-missed. Export only
  aggregate outcomes; never keys, addresses, page offsets, file names or
  native process/thread identities. A transaction-level completion flag alone
  cannot establish whether its relevant read was ready.
- For each proof batch, record an anonymous dispatch-to-service ID, hint versus
  authoritative origin, target counts, split trigger, queue depth and
  completion. Count cursor seek/next operations and read duration by table
  class. Execution values and trie proofs use different access paths; warming
  the value cache does not establish proof readiness.

The strongest proof experiment is **backlog-aware batching**: retain small
batches while workers are free, but combine compatible pending targets once
workers are saturated, with bounded maximum work and age. The current
`dispatch_with_chunking` forces splitting above 300 targets even without idle
workers; the default small chunk size is 5. This is a concrete source of queued
small jobs, but the existing capture does not record which branch caused each
split. Same-key/same-context dedup already exists; do not describe this as
blindly removing duplicate targets.

The idle-worker flags are advisory: workers mark themselves busy only after
receiving a job, and a dispatcher snapshots availability once before enqueueing
all chunks. Idle storage workers can also trigger splitting into an already
busy account pool. These permit admission bursts; the trace does not prove
which condition produced the observed backlog. A narrow alternative experiment
is to decline idle-based fragmentation when that input queue already has work,
while preserving the limit on oversized jobs. Measure trigger counts first.

Any prototype must preserve widened parent-prefix requests, authoritative
state-update order, deletions/wipes, error propagation, completion accounting,
root equality **and retained database updates**. Keep pending work bounded and
flush on completion even if no further update arrives. Combining compatible
queued requests can share trie traversal; blindly combining proof outputs or
suppressing later broader requests is unsafe.

Do not repeat a global chunk-size or worker-count change as an established
fix. Previous chunk32 gains under full tracing reversed under milestone
capture. Inline singleton proofs and storage-only forwarding shifted work
between pools without a consistent replay-plus-root improvement. Any new
candidate needs matched minimal-observation and diagnostic arms, common-window
completed work, execution fault totals and combined replay/root latency.
If cursor reads do not decrease, fewer job/span records alone are insufficient.

For execution, choose between prioritizing imminent prewarm reads, suppressing
obsolete speculative reads, or limiting proof read concurrency **after** the
readiness classification. More threads previously reduced executor wall/tx
while reducing completed work. Reduced proof concurrency may help execution
but worsen root completion; judge their combined critical path.

## Scope and reproducibility

Body availability is explicitly deferred in
[the optimization notes](OPTIMIZATION-NOTES.md#deferred-body-availability-2026-09-21).
Background state-persistence backpressure remains outside optimization scope.
The protected ownership fix remains untouched.

Local evidence lives under the capture's findings directory:
`reanalysis/fault-episodes.py` and `.json`, the proof-readiness deep-dive and
its queue reconstruction. The three fault totals independently match the
original integer-nanosecond raw-source joins within 10 ns; worker-role
integrals reconcile with total concurrent-fault integrals. Focused exports use
microsecond floats and are not a replacement for the original audited joins.
All retained outputs use anonymous validator/block/thread aliases and closed
operation classes. No new runner artifacts were generated by this analysis.
