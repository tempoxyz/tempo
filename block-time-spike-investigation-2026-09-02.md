# Root cause of the existing-recipient block-time spikes

Date: 2026-09-02

## Bottom line

The culprit is the storage-backed sparse-trie/state-root and persistence path.
The wide-state TIP-20 benchmark drives that path into multi-second work on the
bad physical datadir/CPU pairing. Synchronous `newPayload` processing and
persistence/backpressure then turn that work into the observed block-time
spikes.

The completed isolation matrix rules out validator identity and RPC ingress as
the cause. Its result follows the physical pairing of the state datadir and
the CPU set: the slow state-root series follows the A-datadir + B-CPU pairing,
regardless of which logical validator owns it. This implicates CPU/storage
NUMA or interrupt locality. The benchmark harness pins CPU sets, but does not
bind memory or storage interrupts to the corresponding NUMA/device locality.

This is separate from the already-isolated public TPS regression. The T10
capacity change does not explain these block-time spikes; the spikes predate
that change and occur with an approximately unchanged median block interval.

## Workload and measurement

The affected scenario is
`tip20:recipient=existing,fee-token=any_tip20`: approximately 409.6M existing
accounts, 100 GiB of state bloat, four TIP-20 tokens, a 50,000 TPS target, and
10-minute runs. Block intervals come from `default.txgen_blocks` in
ClickHouse. Node timings come from `default.txgen_metric_samples`.

The metric quantiles below are averages of frequent Prometheus quantile
snapshots. Their maxima identify the tail but are not exact per-event
distributions. Historical block rows do not contain usable per-block component
timings, so the telemetry cannot always be joined to the exact outlier block.

## Historical shape

The median stays near the intended 500ms while the tail reaches seconds or
tens of seconds. The issue is therefore intermittent processing starvation,
not a uniformly larger configured block interval.

| Date | ClickHouse run | Blocks | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|---:|
| Jul 13 | `6e35a152-eb67-4c95-a786-6bfbe745380e` | 928 | 473 | 3,034 | 4,215 | 2 |
| Jul 22 | `25fffbdd-902c-4a43-9480-d1c292e6cdab` | 723 | 476 | 5,066 | 27,504 | 16 |
| Jul 28 | `9e273576-5384-4ef9-950d-9fed9f4c4cf3` | 605 | 486 | 9,757 | 30,408 | 24 |
| Jul 31 | `827215da-7cbb-4e22-b282-8feb7b20d70f` | 640 | 490 | 11,002 | 27,548 | 22 |
| Aug 20 | `0dba3fda-fbc1-4997-9541-cbb0dfe54c52` | 473 | 476 | 15,665 | 45,494 | 29 |
| Aug 31 | `6f2593fb-04fc-46c3-8c86-e34551f98c91` | 554 | 495 | 14,860 | 39,386 | 31 |
| Sep 2 | `1e9cadbe-8a5e-4579-880f-267188e4a948` | 550 | 490 | 10,093 | 33,428 | 28 |

The tail is present before the T10 capacity change and varies substantially
between runs. This is consistent with a sensitive placement/cache/I/O path,
not a deterministic capacity step.

## Evidence for the software path

The diagnostic branch tested state-root controls with the same workload:

| Diagnostic | GitHub run / ClickHouse run | Blocks | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|---:|
| `--debug.skip-state-root` | [33403428060](https://github.com/tempoxyz/tempo/actions/runs/33403428060) / `cf987c37-67ea-46ef-a2e9-d131aa937a19` | 1,163 | 512 | 647 | 1,503 | 0 |
| `--engine.state-root-task-timeout=0s` | [33403428827](https://github.com/tempoxyz/tempo/actions/runs/33403428827) / `1d12e17c-310c-4e3f-b6e9-3d0bea0ff628` | 727 | 471 | 6,140 | 11,196 | 27 |
| `--engine.disable-sparse-trie-cache-pruning` | [33403428608](https://github.com/tempoxyz/tempo/actions/runs/33403428608) / `b699b64a-98d0-4cf3-b95e-7db51201f513` | 714 | 476 | 6,450 | 10,822 | 27 |

Skipping state-root computation nearly removes the tail, proving that the
root/trie path is necessary for the observed block gaps. It is not a viable
production fix because it bypasses state-root correctness, and it does not
separate validation from trie-update generation. Removing cache pruning or the
sequential fallback alone does not remove the tail, so those settings are
amplifiers/mitigations rather than a complete explanation.

## Controlled mechanism experiments

The following experiments used the same existing-recipient workload and, where
the comparison was useful, the same code revision on both sides.

| Theory or intervention | Feature result | Matched/control result | Verdict |
|---|---|---|---|
| Disable execution-cache sharing | 451 blocks; p99 4,172 ms; max 8,888 ms; 6 blocks >4 s | 379; p99 8,675 ms; max 14,107 ms; 9 >4 s | Not the cause. Execution-cache wait stayed at microseconds on both sides; the tail remained in root/persistence/backpressure. |
| Allow persistence during payload building | 248; p99 7,356 ms; max 10,580 ms; 4 >4 s | 210; p99 6,073 ms; max 13,428 ms; 5 >4 s | Not a standalone fix. It changes the scheduling gate, but does not remove the tail or reduce the >4 s rate. |
| NUMA interleave | 263; p99 3,576 ms; max 9,686 ms; 2 >4 s | 283; p99 3,532 ms; max 4,860 ms; 1 >4 s | Neutral on this host, which exposes only one NUMA node. It neither proves nor disproves multi-node memory/IRQ locality. |
| Disable sparse-trie sharing | The run advanced only one measurable block; logs repeatedly reported the proposal channel closing before the payload was proposed | — | Not viable for this workload. Removing sharing makes the builder miss the consensus deadline, so it is not a production fix. |
| Persistence threshold 0, buffer 0 | [33623583937](https://github.com/tempoxyz/tempo/actions/runs/33623583937) / `99b49e5d`: 263 blocks; p99 4,094 ms; max 10,577 ms; 3 >4 s. Replication [33624497701](https://github.com/tempoxyz/tempo/actions/runs/33624497701) / `c8a79727`: 255; p99 4,511 ms; max 9,595 ms; 4 >4 s | Fresh default control [33625253549](https://github.com/tempoxyz/tempo/actions/runs/33625253549) / `7e610cf4`: 257; p99 4,438 ms; max 10,271 ms; 3 >4 s | Not a supported fix: one run improved p99, the replication did not, and persistence writes remained expensive (up to 14.0 s). It changes scheduling but does not remove the storage bottleneck. |
| Persistence threshold 4, buffer 2 | [33624510498](https://github.com/tempoxyz/tempo/actions/runs/33624510498) / `7e3c9839`: 262 blocks; p99 3,722 ms; max 10,659 ms; 2 >4 s. Replication [33626396491](https://github.com/tempoxyz/tempo/actions/runs/33626396491) / `a1d21337`: 249; p99 5,765 ms; max 10,086 ms; 5 >4 s | Fresh default control [33625253549](https://github.com/tempoxyz/tempo/actions/runs/33625253549) / `7e610cf4`: 257; p99 4,438 ms; max 10,271 ms; 3 >4 s | Not a supported fix: the initial improvement did not reproduce. The replication produced 3.1% fewer blocks, a 30% higher p99, and more >4-s blocks. It changes backlog timing but does not remove the storage bottleneck. |
| Backpressure threshold 32 | [33623594278](https://github.com/tempoxyz/tempo/actions/runs/33623594278) / `61c16c11`: 296 blocks; p99 6,062 ms; max 6,870 ms; 6 >4 s | Fresh default control above | Does not fix the tail. Allowing a larger in-memory gap changes when the engine blocks, but not the underlying slow persistence/root work. |

The execution-cache and persistence-gate tests eliminate two attractive
software explanations. The no-sharing test is a useful boundary condition: the
shared sparse trie is needed to meet the proposal deadline at this state size,
but contention inside that shared/storage-backed path still needs to be fixed.
The threshold-4 replication also eliminates persistence-threshold tuning as a
reliable fix for the underlying tail.

## Placement isolation

The follow-up matrix used corrected harness switches from draft PR
[#7370](https://github.com/tempoxyz/tempo/pull/7370):

- `--bench-e2e-swap-signing-keys`: exchange the complete validator identity and
  network binding;
- `--bench-e2e-swap-mounts`: exchange the two state datadirs;
- `--bench-e2e-swap-cpus`: exchange the CPU sets;
- `--bench-e2e-reverse-rpc`: exchange generation and submission RPC order.

The raw `feature-1` ClickHouse rows below all remain noisy, but none of the
swaps eliminates the tail. The three-pair aggregate analysis in PR #7370 found
identity and RPC neutral, while datadir exchange increased validation
p50/p90/p99 by 11.6%/10.7%/27.0%; builder latency remained neutral.

| Mode | GitHub run / ClickHouse run | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|
| Control | [33421299290](https://github.com/tempoxyz/tempo/actions/runs/33421299290) / `1d34baf2-25d2-4832-a3b8-336c12d23dbd` | 481 | 4,995 | 10,655 | 16 |
| Identity swap | [33421299205](https://github.com/tempoxyz/tempo/actions/runs/33421299205) / `b3b178e1-d775-4602-919b-f206ba48437c` | 470 | 6,076 | 10,950 | 19 |
| Datadir swap | [33421299561](https://github.com/tempoxyz/tempo/actions/runs/33421299561) / `b60c9644-1e39-414d-b54b-8a6f5b01626b` | 507 | 5,147 | 12,985 | 17 |
| CPU swap | [33421299267](https://github.com/tempoxyz/tempo/actions/runs/33421299267) / `21ae8a6c-1756-4696-b9f6-e265adb201e8` | 496 | 7,060 | 12,504 | 34 |
| RPC reversal | [33421299272](https://github.com/tempoxyz/tempo/actions/runs/33421299272) / `eaf1a51f-c946-46bc-9c03-9085c6335ff1` | 475 | 4,097 | 10,588 | 10 |

The runner maps `/reth-bench-a` to `/dev/nvme2n1` and
`/reth-bench-b` to `/dev/nvme3n1`. The harness assigns CPU set A as
`0-7,16-23` and CPU set B as `8-15,24-31`. The diagnostic result says the
slow series follows the physical A-datadir + B-CPU combination, not a logical
validator role. That is the concrete explanation for why one node often looks
like “the bad follower” and why the bad side can move between runs.

## Telemetry during a bad run

For Aug 31 run `6f2593fb-04fc-46c3-8c86-e34551f98c91`, node B showed:

| Metric | Scraped p50 average | Max sampled |
|---|---:|---:|
| State-root validation | 54 ms | 9.390 s |
| `newPayload` latency | 221 ms | 9.612 s |
| Builder `state_root_with_updates` | 1.323 s | 7.486 s |
| `save_blocks` persistence | 7.030 s | 43.009 s |
| Trie-update write portion | 3.970 s | 31.798 s |
| Beacon backpressure stall | 3.700 s | 39.121 s |

Node A also showed multi-second persistence and trie-write tails, while its
state-root validation was much healthier. This separates the trigger from the
downstream delay: a slow validation/root reconstruction starts the problem;
trie writes, persistence, and backpressure keep the engine behind for much
longer than one root calculation.

The nearest telemetry snapshots in the persistence-gate feature run make the
relationship concrete even though the current schema lacks a block ID join:

| Block | Block time | Nearest sampled timings |
|---|---:|---|
| 152 | 10,580 ms | Node A: root 3.793 s, `newPayload` 4.002 s, backpressure 2.028 s, persistence 6.632 s; node B persistence 6.829 s |
| 210 | 9,172 ms | Node B: root 7.266 s, `newPayload` 7.444 s, backpressure 3.367 s, persistence 7.112 s |
| 249 (fresh default control) | 10,271 ms | Node A: root 6.208 s, `newPayload` 6.333 s, backpressure 4.187 s, persistence 7.349 s |

These are quantile snapshots sampled within 500 ms of the block timestamp, not
claims that every displayed duration belongs to that exact block. They do show
the outliers occurring while the engine is simultaneously reporting the same
multi-second root, persistence, and backpressure path.

## What is actually stalling?

Persistence backpressure is the visible stop, not the initiating fault. Reth
only enters `wait_for_persistence_event()` when a persistence task is already
running and the canonical-to-persisted gap has exceeded its limit. With the
current defaults, threshold persistence starts after more than 7 blocks are
ahead, 5 blocks are retained in memory, and engine backpressure starts at a
gap of 16 blocks beyond that buffer (about 21 blocks behind the canonical tip).
Only one persistence task is in flight at a time.

The Aug 31 timeline shows the order: persistence was already above 1 s at an
offset of 6.0 s, while backpressure did not exceed 0.5 s until 23.4 s. The
eventual maxima were 43.009 s for `save_blocks`, 39.121 s for backpressure,
31.798 s for trie-update writes, and 9.390 s for state-root validation. The
engine is therefore waiting for slow storage/trie work; backpressure prevents
it from making progress while that work is unfinished.

This is not a persistence-trigger-frequency problem: the node does not launch
multiple concurrent save tasks, and the threshold experiments did not show a
reliable benefit from changing when saves start. However, it is still possible
to persist too much *state/trie* for this workload. With Reth's default
`num_state_masking_blocks=0`, every block that leaves the in-memory buffer
contributes its hashed-state/trie updates to the durable write. Reth now has an
experimental state-masking option that can keep a recent suffix's state/trie
updates in memory while still persisting the block/execution data; this is a
direct persistence-volume reduction and is tested below.

Setting the persistence threshold to zero increased write frequency without
fixing the tail; allowing writes during payload builds also did not fix it.
Raising the backpressure threshold only allowed a larger backlog and made the
tail worse. The problem is slow storage-backed trie work, amplified by the
single MDBX writer and the resulting backpressure—not too many persistence
tasks being scheduled.

## Causal chain

```text
409.6M-account existing-recipient state
  -> random storage access and sparse-trie cache misses
  -> cache pruning/reconstruction makes incoming state-root validation slow
  -> synchronous newPayload handling continues until validation returns
  -> trie updates compete with reads during persistence
  -> persistence backlog and engine backpressure extend the block gap
```

The relevant implementation behavior is visible in the pinned Reth engine
path: the engine calls `on_new_payload(payload)` synchronously before sending
the response. If the request is canceled while that call is running, the
receiver is only observed as dropped after the work returns. The logs contain
these long validation completions and canceled response deliveries.

The sparse-trie task also deliberately prunes its preserved trie after
persistence. That bounds memory, but makes frequently reused storage paths
eligible for later reveal/reconstruction. The payload builder has a separate
state-root path; its latency stays neutral in the datadir comparison, which is
why the evidence points specifically to incoming-payload validation rather
than ordinary block building.

Relevant code:

- [`bench-e2e.nu`](bench-e2e.nu) pins CPU sets with `taskset` and applies a
  memory cap, but does not bind NUMA memory or device IRQs.
- [`crates/payload/builder/src/lib.rs`](crates/payload/builder/src/lib.rs)
  shows the builder state-root wait and synchronous fallback.
- [`crates/payload/builder/src/metrics.rs`](crates/payload/builder/src/metrics.rs)
  defines the builder timing surfaces.
- [Pinned Reth engine message loop](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/tree/mod.rs#L1852-L1940)
  shows synchronous `on_new_payload` handling.

## What this does and does not establish

Established with high confidence:

- the timestamp gaps are real, not a dashboard artifact;
- the wide-state existing-recipient workload is the trigger;
- state-root/trie work is necessary for the tail;
- the immediate long-gap mechanism is validation/persistence/backpressure;
- validator identity and RPC placement are not the explanation;
- the observed asymmetry follows a physical datadir/CPU placement; the bad
  pairing, not validator identity, determines which logical node exhibits the
  tail.

Remaining deployment validation:

- the swap matrix identifies the bad physical datadir/CPU pairing, but this
  runner has one NUMA node and does not let us separate CPU placement, NVMe
  PCIe locality, and NVMe IRQ affinity;
- exact one-block causality is not available because the benchmark does not
  attach a common block ID to node telemetry and `txgen_blocks` component
  fields are null for these runs.

That limitation does not leave the cause unknown: the measured cause is the
storage-backed sparse-trie/state-root and persistence path, with the bad
physical datadir/CPU pairing determining which logical node exhibits the tail.
The unresolved part is only the lowest-level hardware locality factor—CPU
placement versus NVMe PCIe or IRQ affinity—not whether the block-time spike is
caused by the TPS/capacity setting or by execution-cache sharing.

## Recommended next action

The directly supported operational fix is to keep each node's CPU set, memory,
NVMe device, and NVMe IRQs on the same physical locality as its state datadir.
Without a multi-NUMA host, the practical alternatives are to remove the
measured A-datadir + B-CPU pairing, move the state datadir to the better NVMe
device, or pin that device's interrupts to the node's existing CPU set. The
swap matrix is the experiment that supports changing the datadir/CPU pairing;
the interleave run was neutral only because this particular host has one NUMA
node. On a multi-NUMA host, validate the same arrangement with explicit
`cpunodebind`/`membind` and device IRQ affinity.

The software experiments did not produce a supported scheduling fix. Keep
sparse-trie sharing enabled because disabling it misses the proposal deadline;
execution-cache sharing, `suppress_persistence_during_build`, threshold 0, and
backpressure threshold 32 all left the storage tail in place. Threshold 4 /
buffer 2 showed one favorable sample but failed replication, so it must not be
made a production default. Reth's experimental
`--engine.num-state-masking-blocks` is the direct software candidate because it
reduces durable state/trie work rather than moving the persistence gate; its
matched A/B result is recorded below. If placement and storage cannot change,
the remaining code-level path is to reduce sparse-trie/state-root I/O or make
persistence share less contention with validation. Do not use
`--debug.skip-state-root` outside diagnosis.

Add a block number or trace ID to state-root, `newPayload`, persistence,
trie-write, and backpressure telemetry. That will identify whether each
outlier begins in validation or is solely an already-created persistence
backlog.

## Persistence note

The precise answer to “are we persisting too much?” is: not too many save
*tasks*, but potentially too many state/trie updates. Reth runs one persistence
task at a time. With the current defaults, threshold persistence starts after
more than 7 canonical blocks are ahead, retains 5 blocks in memory, and stops
draining engine messages once the persisted tip is about 21 blocks behind the
canonical tip (16 blocks beyond that buffer).

The initiating work is storage-backed sparse-trie/state-root processing. In
the bad run, sampled maxima were 9.390 s for state-root validation, 31.798 s
for trie-update writes, and 43.009 s for `save_blocks`. Backpressure reached
39.121 s only after persistence was already slow. It is the protective gate
that exposes the backlog as a block-time spike, not the source of the slow
operation.

The non-NUMA alternatives are therefore to remove the measured A-datadir +
B-CPU pairing, move the state database to the better/dedicated NVMe device,
and pin that device’s interrupts to the node’s existing CPU set. The tested
configuration alternatives—more frequent persistence, persistence during
payload builds, a larger backpressure gap, and threshold 4/buffer 2—did not
survive matched replication. The Reth state-masking A/B below tests the one
direct software lever found in the pinned source. If it is not sufficient, the
remaining software work is a code change to reduce sparse-trie I/O or
contention between state-root validation and trie-update persistence; threshold
tuning only moves the stall.

## Reth persistence audit

Source revision audited: Tempo's pinned Reth commit
`23305f9d98e2424da527fdd8a46f762a18d9de3f` (2026-08-27).

### What Reth already does

- `PersistenceService::run` consumes persistence actions on one blocking OS
  thread. There is no parallel queue of MDBX writers.
- `save_blocks` opens one MDBX write transaction. The state and trie writes run
  on that persistence thread; MDBX's single-writer model prevents simply
  making those writes concurrent.
- Reth already runs static-file and RocksDB block writes in parallel with the
  MDBX work. Its 16-thread storage pool applies to those backends, not to the
  observed `write_state`/`write_trie_updates` path.
- Hashed-state and trie updates are already merged across the save batch before
  opening the write cursors. Increasing `storage_threads` therefore is not an
  obvious fix for this tail. The engine proof/account worker counts affect
  state-root proof computation, not the persistence writer.
- Pruning is run after the save is acknowledged, and its sampled durations in
  the control run are sub-millisecond. It is not the multi-second bottleneck
  here.

These checks rule out the tempting “add persistence threads” and “increase the
storage pool” fixes. The expensive operation is the serial MDBX state/trie
transaction, especially `write_trie_updates`, not a starved static-file worker
pool.

### Direct Reth candidate: state masking

Reth exposes the experimental
`--engine.num-state-masking-blocks <N>` option. On a threshold save it still
persists ordinary block/execution/history data through
`head - memory_block_buffer_target`, but advances the durable hashed-state/trie
frontier only through
`head - memory_block_buffer_target - N`. The newest `N` blocks form an
in-memory mask, so redundant older state/trie updates can be omitted from the
current MDBX write and applied when the mask leaves memory.

The invariant is `N + memory_block_buffer_target < persistence_threshold`.
With the benchmark defaults (threshold 7, buffer 5), `N=1` is the largest
valid value without changing those defaults. The option is disabled by default
and marked experimental, so it needs recovery, memory-growth, and sustained
tail validation before becoming an operational default. It is available in the
pinned Reth revision without a Cargo feature; a local profiling build of Tempo
also shows the flag in `tempo node --help` with default `0`. Reth's own
`test_threshold_persistence_with_state_masking_blocks` passes at this pinned
revision.

There is also upstream operational precedent for a larger window: Reth's
2026-08-31 nightly Docker configuration sets
`RETH_ENGINE_PERSISTENCE_THRESHOLD=50` and
`RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=30`. That is evidence that the
configuration is intended to be exercised, not proof that it is safe or
optimal for this 100-GiB workload. The matched run below rejects it as a fix
for this benchmark.

The first controlled comparison is complete in GitHub Actions
[33630670721](https://github.com/tempoxyz/tempo/actions/runs/33630670721):
baseline used threshold 7 / buffer 5 / masking 0, and the feature side used
the same settings with `--engine.num-state-masking-blocks 1`. Across two
baseline and two feature phases, the benchmark summary reported:

| Aggregate result | Masking 0 | Masking 1 | Change |
|---|---:|---:|---:|
| Blocks | 266 | 367 | +37.8% |
| Block-time mean | 621.6 ms | 469.0 ms | -24.5% |
| Block-time p50 | 497 ms | 462 ms | -7.0% |
| Block-time p99 | 3,671 ms | 592 ms | -83.9% |

The conservative configuration to carry into the next node test is
`--engine.persistence-threshold 7 --engine.memory-block-buffer-target 5 --engine.num-state-masking-blocks 1`.
It keeps the existing persistence and memory policy and only masks one newest
state/trie block.

The uploaded masking-1 phase `feature-1` is ClickHouse run
`3e3b8cbb-f771-48c9-a2e8-3886ee1c64b0`: 187 timed blocks, p50 464 ms, p99
566.6 ms, max 602 ms, and zero blocks over 4 s. Its sampled persistence
maxima were 3.67 s (`save_blocks`) and 1.55 s (`write_trie_updates`) across
the two nodes; backpressure was at most 30 ms. This is a positive A/B result
for the block-time tail and is the first verified software mitigation in this
investigation.

The comparison also reported lower aggregate benchmark TPS on the masking
side (11,187 vs 13,407, -16.6%), plus more invalid-transaction skips. That
means the result is a block-tail win, not yet a claim of higher application
throughput; the transaction-generation/invalid-skip behavior must be
separated before adopting it as a general performance default. A second
comparison in GitHub Actions [33632541164](https://github.com/tempoxyz/tempo/actions/runs/33632541164)
replicated the block-time direction: 287 baseline blocks versus 357 masked
blocks, block-time mean 598.2 ms versus 482.5 ms, and p99 1,935 ms versus
1,039 ms. Its directly uploaded baseline ClickHouse run
`9ef042e8-8e8d-4fbe-ba4d-1721279900b2` had persistence max 5.87 s, trie-update
write max 2.53 s, and backpressure max 2.72 s; the feature phase was not the
ClickHouse-selected phase in that workflow, so those component metrics are
not being presented as a direct same-run pair.

The upstream-sized configuration was tested in GitHub Actions
[33634046606](https://github.com/tempoxyz/tempo/actions/runs/33634046606),
with threshold 50 / buffer 5 on both sides and masking 30 on the feature side:

| Aggregate result | Masking 0 | Masking 30 | Change |
|---|---:|---:|---:|
| Blocks | 325 | 316 | -2.8% |
| TPS mean | 16,866 | 14,506 | -14.0% |
| Block-time mean | 526.4 ms | 470.1 ms | -10.7% |
| Block-time p50 | 527 ms | 461 ms | -12.5% |
| Block-time p99 | 662 ms | 655 ms | -1.1% |

The feature phase also produced repeated proposal-channel-closed warnings.
Because threshold 50 raises the default backpressure limit to 100 blocks, its
clean feature tail is not evidence that persistence became fast; the setting
mostly permits a much larger backlog. Masking 30 therefore is not a production
fix here. Its ClickHouse feature phase was
`acd69fa3-7413-481c-b0cd-dee62f92088c`: p99 block time 617.6 ms, max 681 ms,
zero blocks over 4 s, zero backpressure, persistence max 6.43 s, and trie
update-write max 1.77 s.

### Code-level follow-up, not yet a confirmed fix

The current provider loop calls `write_state(WriteStateInput::Single)` once per
block, even though Reth has a `WriteStateInput::Multiple` API. That may remove
repeated state conversion/cursor setup if the save path constructs one aggregate
`ExecutionOutcome`, but the observed control metrics show `write_state` is
tiny while `write_trie_updates` dominates. It is therefore a secondary
engineering experiment, not a claimed explanation or production fix.

## Sources

- [Original benchmark investigation thread](https://tempoxyz.slack.com/archives/C0A87C21805/p1788182749824189)
- [Follower-isolation harness PR #7370](https://github.com/tempoxyz/tempo/pull/7370)
- [Diagnostic-mode harness commit](https://github.com/tempoxyz/tempo/commit/cd0650f57da011154ac60410e497e9fcdf6e76d0)
- [Separate public TPS/capacity report](public-tps-capacity-regression-report-2026-09-02.md)
- [Pinned Reth `save_blocks` implementation](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/storage/provider/src/providers/database/provider.rs#L573-L795)
- [Pinned Reth persistence service](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/persistence.rs#L36-L225)
- [Pinned Reth state-masking frontier calculation](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/tree/mod.rs#L2252-L2343)
- [Reth nightly persistence configuration](https://github.com/paradigmxyz/reth/commit/0efb81fb4a2d9936dc0468d4db72bffe8fdd5788)
