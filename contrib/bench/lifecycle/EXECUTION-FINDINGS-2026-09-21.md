# Validated execution-stall capture and runner-election failure

Capture: [35578876523](https://github.com/tempoxyz/tempo/actions/runs/35578876523).
One fully instrumented portable x86-64-v3 capture, 77 eligible blocks,
490,532 transactions over 39.106 seconds of eligible load. Strict
pre-backpressure cutoff applied. This is diagnosis, not a measured optimization
win or a comparison with historical native builds. With 77 observations, p99
is the maximum observed block, not a stable population-tail estimate.

## What dominates block time

Block lifecycle p50/p90/p99: 518.106 / 598.398 / 670.256 ms.
Shares below divide summed non-overlapping lifecycle phases by summed block
lifecycles; they are not sums of overlapping nested operation durations.

| Phase | p50 ms | p90 ms | Share of summed lifecycle |
|---|---:|---:|---:|
| Proposal to release | 288.549 | 369.044 | 56.7% |
| Body availability | 24.429 | 34.355 | 4.8% |
| Replay setup | 0.519 | 1.129 | 0.1% |
| Replay | 144.514 | 202.545 | 27.8% |
| Post-replay validation | 31.658 | 53.684 | 7.0% |
| Validation complete to vote | 4.155 | 14.991 | 1.4% |
| Vote to finalization | 6.394 | 17.986 | 2.1% |

Proposal time is not all removable work: the pinned builder has a build-time
budget and waits when its transaction iterator empties. This capture does not
separate all builder CPU/idle time; do not call the entire 57% an optimization
opportunity. Body availability includes decode and dispatch, not just transport.
Individual recorded network transfers have median 0.067 ms and p99 2.383 ms;
that is a different population and is not subtractable from body latency.

## Execution stalls: now directly attributed

All 77 complete own-block receiver execution scopes have measured loop CPU and
an exact parent-linked execution child. All 77 entered scheduler joins have zero
uncovered time. No nearest-time block matching or inferred thread assignment.

Across these calls, execution-loop wall time totals 10.623 s and thread CPU
7.628 s. The wall-minus-CPU gap is p50 34.670 ms, p90 80.158 ms, max 130.785 ms.
74/77 calls have a gap of at least 5 ms; 76/77 report major page faults.

Independent scheduler attribution over the enclosing execution children:

- File-backed fault I/O-path blocking: 1.849 s total, p50 16.772 ms,
  p90 61.451 ms, max 101.487 ms; 63/77 calls exceed 5 ms.
- Runnable but not scheduled: 0.923 s total, p50 12.160 ms,
  p90 18.564 ms, max 29.419 ms.
- Futex blocking: 0.219 s total. Unknown blocked ancestry: 1.813 ms total.

The execution-child span and loop CPU timer have slightly different boundaries.
Scheduled residency also includes kernel/interrupt time. Do not force exact
arithmetic equality or equate residency with task CPU.

Concrete example: block 32 (the p90 lifecycle representative) has 261.531 ms loop
wall / 130.746 ms thread CPU, 159 major faults and 1,160 block-input-operation
units. Its execution-child scheduler span contains 101.487 ms blocked in
`filemap_fault_io_schedule`, 29.419 ms runnable delay, and 0.869 ms futex wait.
This directly identifies a file-backed fault I/O wait path. It does NOT identify
the file, DB table, instruction, device, physical read, or background persistence
as the cause. Do not convert block-input-operation counters to bytes or IOPS.

This is not exclusively startup: the last 20 calls still have filemap-wait median
6.870 ms and max 62.658 ms, versus first-20 median 26.739 ms and max 96.468 ms.
These are temporal subsets with changing workload, not a controlled warmup test.

## Separate root-completion and durability tails

Block 11 is the largest lifecycle (670.256 ms): 314.489 ms proposal-to-release,
155.236 ms replay, and 170.692 ms validation tail. An exact receiver span
`execution.state_root.finish` lasts 170.459 ms in that tail. The final root wait
is located, but this runtime lacks the finer root-completion instrumentation
needed to assign it to proof readiness, trie completion, or publication.
Long proof-worker lifetime spans overlap and must not be added as CPU/work time.

Block 18's proposer has a 103.995 ms blob sync under this exact parent chain:
`handle_propose -> proposal.persist -> marshal.mailbox.verified ->
marshal.actor.process -> marshal.handle_mailbox_message ->
marshal.persist_verified -> storage.archive.start_sync -> ... -> storage.blob.fsync`.
The label wraps the instrumented durability operation; do not infer a specific
physical device. Block 81 has overlapping 80.408 ms and 60.549 ms proposal syncs;
these are not additive. Block 67 has a 37.265 ms verified-archive sync on the
receiver verify path. These consensus/archive waits remain in scope; background
state-persistence backpressure optimization remains excluded.

## Next experiments justified by this data

1. Identify the provider/read operation behind file-backed faults using anonymous
   operation categories and exact execution ancestry; preserve the privacy
   boundary (no file paths, keys, addresses or transaction identities). Then test
   targeted prefetch/prewarming/cache changes with matched instrumentation.
   Current evidence does not choose a specific cache or prove a speedup.
2. Test worker-count/CPU-affinity changes separately for the 12 ms median runnable
   delay. A smaller pool may reduce contention but hurt proof throughput; measure
   both complete-block latency and root tails.
3. Run the prepared root-completion diagnostic to resolve the 170 ms wait.
4. Test archive overlap and journal preparation separately. The archive-sync
   parent chains justify the experiments but do not yet establish their benefit.

The seeded proposer decode-cache path remains deferred to other work, per user
instruction. No new benchmark has been launched during this analysis.

## Root benchmark failure pinned

[35592243235](https://github.com/tempoxyz/tempo/actions/runs/35592243235) failed
before workload execution. The five reservation jobs ran on three distinct
runners. Two elections started at 11:07:11/12 UTC and timed out exactly 180 s
later. Two queued jobs did not publish receipts until 11:11:06/08 UTC, after
those failures. Subsequent elections reject prior failures outside job setup.

All five receipts pass the original election function when replayed together;
it selects a runner with 770,070 MiB free, versus about 50.3 GiB required.
Root-directory write denial is an explicitly supported probe result when the
workspace is writable; it was not the cause. All five cleanup steps succeeded.

Cause: the all-five receipt barrier assumes simultaneous runner availability.
Increasing the timeout alone does not remove that assumption. Before restarting,
replace the reservation barrier with one queued benchmark job plus its capacity,
artifact and snapshot preflight, or a coordinator that releases unused probes
and admits an explicit available subset while guaranteeing one workload. Do not
silently ignore failed jobs or change immutable historical receipts.

## Retained evidence

`findings.json`, `execution-stalls.json`, `receiver-loop-totals.json`,
`scheduler-findings-summary.json`, `selected-operation-spans.json`, and
`durability-examples.json` retain compact numeric/source evidence. `focused/`
contains checksum-verified ordinary and scheduler Perfetto exports for actual
blocks 71 (p50), 32 (p90), and 11 (p99). The remote ~3 GB lifecycle artifact was
deleted after local checksum verification. Raw local data remains available;
local bulk cleanup must follow completed required analysis and retained-output
validation under the cleanup plan.
