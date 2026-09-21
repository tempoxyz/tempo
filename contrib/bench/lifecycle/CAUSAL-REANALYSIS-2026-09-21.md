# Causal reanalysis of the execution-fault capture

This supersedes the unresolved root-tail explanation in
[the first pass](EXECUTION-FINDINGS-2026-09-21.md). It reuses run
[35578876523](https://github.com/tempoxyz/tempo/actions/runs/35578876523),
including all 77 eligible blocks and selected exact dependency chains. No new
benchmark was launched. All observations remain strictly before backpressure.
These are causes observed under instrumentation, not measured optimization wins.

Pinned sources: Tempo `0bd62dd2f0e509016439b2189cd0f4998d007a26`, Reth
`000fc3cdf3d5f09a816ad30554a555881f2e28bf`, Commonware
`e755c2f335acb4fccab4cbfd3d4184206742360e`, workflow
`8da0d5f862bff01dabb56a8492d70fbdaf42c7aa`.

## 1. Execution stalls are mainly inside transaction execution

Across the 77 receiver loops, wall time is 10.623 s, thread CPU 7.628 s,
transaction execution wall 9.935 s, iterator acquisition 0.328 s and receipt
delivery 0.224 s. Even assigning **all** loop CPU to `execute_transaction`
leaves at least 2.307 s of non-CPU time inside that call: 77% of the total
2.994 s loop wall/CPU gap. Transaction delivery and receipt channels cannot
explain most of the gap.

Exact scheduler joins attribute 1.849 s to file-backed page-fault I/O blocking,
0.923 s to runnable delay and 0.219 s to futex blocking over the enclosing
execution scopes. These scopes have slightly different boundaries from the
loop counters; do not force exact equality. Block 32 contains 101.487 ms of
filemap-fault blocking and 29.419 ms runnable delay. This establishes demand
thread fault-path blocking, not its database table, device or eviction cause.

The workload helps explain why a short warmup may not remove these waits.
The workflow's `default` preset chooses **random existing recipients across
the large state-bloat pool**, with four tokens. The configured 1,000 accounts
does not restrict recipients to 1,000 addresses. The 100 setting resolves to
100,000 MiB and approximately 409.6 million candidate recipient indices per
token. That recipe continually exposes broad state/proof paths; actual cache
miss causes and physical reads still require measurement. Sources:
workflow `contrib/bench/txgen/helpers.nu:54,500,516`,
`presets/tip20/recipient-existing.yml`, `bench-e2e.nu:302`.

Canonical execution uses lookup-only caches and calls the underlying
account/storage/code provider on a miss (`cached_state.rs:848–962`). The
fixed-cache dependency uses `try_lock`: contention can turn a lookup into a
miss and another read, but does not park this thread behind a prewarmer's
database read. Current data cannot separate cold misses, evictions, contention
misses and data that prewarming has not reached. Prewarm execution checks the
authoritative transaction frontier before the whole speculative transaction;
an already-running transaction can issue later reads after it becomes obsolete.
That is a testable mechanism, not a measured frequency in this capture.

## 2. The 170 ms root tail is a backlog of storage proofs

Block 11's receiver waits 170.459 ms in `execution.state_root.finish`, of
which 170.444 ms is futex blocking. The producer dependency is now resolved:

| Time after finish begins | Dependency |
|---|---|
| +2.668 ms | First drain observation still has 579 proof batches in flight |
| Through +119 ms | Account jobs are still leaving a large input queue |
| +119.375 to +159.803 ms | Last account job waits for its storage results |
| +120.176 to +159.791 ms | Its last storage child: 33.483 ms filemap-fault blocking, 4.730 ms scheduled, 1.401 ms runnable |
| +160.313 to +170.346 ms | Four final storage roots computed concurrently |
| +170.374 to +170.441 ms | Final account-root/update operation: **0.067 ms** |

During the tail, the 32 storage workers accumulate 3.396 s of overlapping
filemap-fault waits and 0.468 s scheduled residency. The 32 account workers
accumulate 5.426 s futex wait and only 0.016 s scheduled. These concurrent
totals are neither wall time nor measured CPU. The tail is not explained by
account-root hashing or account-worker CPU saturation.

The block has 1,080 account jobs but only two account targets; 901 jobs are
storage-only/single-group. Account workers mostly dispatch and wait for storage
proofs in this workload. Source confirms storage result collection before trie
drain/final roots: Reth `proof_task.rs:1102–1135`, `value_encoder.rs:267–291`,
`state_root_strategy/sparse_trie.rs:329–365,756–811`.

One observed account queue wait is 128.260 ms, but its queue record lacks an
explicit job ID linking it to the final service call. We do not assign that
particular queue duration to the last job. The final storage-child association
uses exact raw parent edges and service-completion markers.

This favors investigating proof-read readiness, locality and fault sources.
It does not establish that bypassing account workers will help: earlier inline
singleton experiments reduced root-tail medians but worsened combined replay
plus validation-tail p90 by 5–9%. Moving work between pools is not enough.

## 3. Finalization outliers contain required durability barriers

Block 55's 95.044 ms vote-to-finalization interval contains **two sequential
voter journal syncs: 73.644 ms and 15.440 ms**. Their durable-write service
times are 73.519 ms and 15.346 ms; the finalization vote is emitted 0.027 ms
after the second barrier. Block 80 repeats this pattern with 23.561 ms and
40.209 ms syncs inside a 70.690 ms interval.

Same-view journal fields and notarization/finalize handler ancestry establish
the association. These journal spans currently have null report-block aliases:
the reporter should carry the unambiguous view-to-block linkage rather than
leave these waits disconnected. Commonware's voter stages journal mutations,
syncs them, then publishes (`simplex/actors/voter/actor.rs:277–299,905–971`).
Dropping a barrier is not a justified performance fix.

The archive outliers are also mostly **backend sync service**, not waiting
for a blocking worker:

| Block/path | Backend sync wall | Blocking-pool queue | Scheduler evidence |
|---|---:|---:|---|
| 18 proposer | 103.995 ms | 0.015 ms | 103.671 ms blocked; 46.421 ms generic I/O, 57.250 ms unknown sleep |
| 81 proposer | 80.408 ms | 0.009 ms | 79.874 ms classified generic I/O |
| 67 receiver | 37.265 ms | 0.008 ms | 36.855 ms blocked |

Pinned Linux backend calls `File::sync_data`
(`runtime/src/storage/tokio/blob.rs:107–118,420–457`). The capture does not
identify the underlying device/filesystem transaction or competing writer.
There are separate receiver-81 blocking queues of 7.8–10.0 ms; avoid applying
the negligible-queue conclusion to every call.

Block 67's 53.492 ms verification-to-vote interval comprises archive sync
37.265 ms, metadata open 9.442 ms, then journal sync 4.868 ms. Journal
preparation targets the metadata portion; it cannot remove the archive or
paired journal barriers. Archive overlap may unblock other actor work, but
does not remove this block's durability dependency. Neither prepared variant
is benchmark-proven.

## 4. Builder time contains substantial intentional sleep

All 77 proposer `block_fill` scopes have exact scheduler coverage. Timer
sleep is p50 **91.308 ms**, p90 **220.410 ms**, total 8.120 s; 51 calls exceed
5 ms. Excluding the three nearly empty blocks leaves p50 87.155 ms and p90
196.235 ms. Block 71 spends 269.732 ms sleeping in a 355.862 ms fill span,
with 69.889 ms scheduled residency.

Pinned builder code sleeps for 1 ms when the transaction iterator returns
`None` and a build budget remains (`builder/src/lib.rs:511–565`). It also
reserves predicted validator and marshal work. Thus much of the large builder
phase is waiting under the proposal budget, not EVM computation. The trace
does not establish whether each empty result means actual supply exhaustion,
eligibility filtering or an iterator artifact. It cannot establish a txgen
bottleneck from these sleeps alone.

There is a **reproduced false-empty iterator behavior** worth fixing in
isolation. `BestTransactionsPrewarming::next` consumes an initial `None`,
requests advance, then consumes another `None` without checking the rest of
the ready queue. With `[None, None, Some(tx)]`, it returns `None` despite an
already-buffered transaction. Initial seeding and completed prewarm jobs can
queue these empty replies; a reachable seed-empty-then-arrival schedule leaves
15 further false-empty returns with a transaction ready. Each return reaches
the builder's 1 ms sleep branch. A standalone fixture using the exact pinned
iterator body and standard channels passes three reproductions. It is not a
full builder benchmark, and the capture has no counters proving how often
stale replies caused the observed sleeps. **Do not claim the 91 ms is all
removable or that a node-level gain is established.**

## 5. Most body-availability time is decode/validation

For every eligible block there is exactly one complete proposer and receiver
`block.read_cfg` between digest release and body ready. Their disjoint
lifetimes account for **80.5%** of summed body-availability time. Proposer
decode/validation p50 is 10.085 ms; receiver p50 is 9.633 ms. These independent
medians must not be added to form a percentile of the total.

Block 32's 21.663 ms interval contains proposer decode 8.592 ms, receiver
decode 8.811 ms, 3.014 ms between them, and 1.245 ms outside them. The 148
decode scopes lasting at least 1 ms have 1.525 s scheduled residency, only
8.775 ms runnable delay and no observed blocking. This is primarily executing
decode/body validation, not waiting for disk or network inside those scopes.
The gaps also include dispatch and encryption; raw frames lack complete block
linkage, so no gap is labeled pure wire latency. Seeded proposer reuse remains
deferred to other work as requested.

## 6. CPU scheduling and observer effects need better controls

Runnable delay is real, but 154 registered threads per validator does not prove
CPU saturation. During block 32's 29.419 ms executor runnable interval, observed
registered-thread CPU concurrency averages 9.21 against 16 allowed logical
CPUs. Unregistered work, the recorder writer, collector, IRQ/host work and
per-CPU scheduling are not fully represented. This neither proves spare host
capacity nor identifies the interfering task. Blindly lowering pool sizes is
not a supported fix.

The current loaded window produces about **408,000 timestamped lifecycle
records/s and 35.8 MB/s** of raw lifecycle output, plus scheduler collection.
Zero drops does not imply low overhead. Ordinary pre-cutoff recorder calls
use `try_send`, so queue-capacity backpressure is not an established cause.

Historical same-binary full/milestones controls show an observer interaction:
chunk-32 validation-tail p90 changes of −9.21%/−34.49% under full capture
reverse to +36.53%/+7.29% under milestones. Current kernel tracing has no
matched disabled control. Therefore this capture locates mechanisms, but its
absolute wait sizes are not established uninstrumented production costs.

Adaptive block budgeting also requires comparing completed work. Recomputed
common-window transaction rates show fixed-lookahead 32 versus 16 prewarming
threads falling 2.4–2.7%, despite 12–14% better execution wall/transaction.
The eight-thread trial's faster block percentiles came with 4.7–12.8% less
completed work. Deferred overlay cloning has a small favorable work-rate
signal (+0.26%/+1.59%) despite latency regressions; retain that qualification
without promoting it as a material proven win. These complete-block work-rate
proxies are edge-censored and do not establish equal transaction gas/state mix.

## Next steps and exclusions

1. Fix and test stale empty replies as an isolated builder candidate; measure
   false-empty count, queued-ready work and actual idle time before claiming
   a latency or throughput gain.
2. Attribute only slow provider/proof reads with closed operation/table classes,
   cache outcome and prewarm frontier state. Keep parent/job linkage; export
   no keys, addresses, native filenames or arbitrary stacks. Then test targeted
   read preparation rather than repeat unproductive blanket thread changes.
3. Link journal views to block aliases and split metadata preparation from
   durable-write service. Test prepared archive/journal variants against those
   specific dependencies, preserving durability guarantees.
4. Repair the all-five runner reservation barrier before resuming one workload
   at a time. Compare identical binaries/capture modes and include a matched
   minimal-observation control, common-window completed work and replay plus
   validation latency. The failed root follow-up produced no performance data.

Background state-persistence backpressure optimization remains excluded;
consensus/archive/journal durability remains in scope. Protected correctness
PR #7679 and deferred seeded decode work remain untouched. Prior rejected
approaches stay recorded in [OPTIMIZATION-NOTES.md](OPTIMIZATION-NOTES.md).

## Validation and retained evidence

The new broad joins cover 768 complete operation scopes against original
audited scheduler sources. Focused root/durability joins cover 521/45 scopes
using audited exports and raw entered intervals. All have zero uncovered
entered time. Nested worker totals are never added as exclusive wall/CPU.
The three standalone iterator tests exercise the exact source body; no full
Rust suite or new node benchmark was run for this analysis.

Compact numeric joins, scripts, source bindings and the iterator reproducer
remain in the run's local findings directory. Original raw capture and focused
traces remain available for verification. The already-downloaded remote bulk
artifact was deleted previously, and runner cleanup receipts remain verified.
Large temporary analysis derivatives can be pruned; final raw-data cleanup
must retain these compact proofs and focused traces under the cleanup plan.
