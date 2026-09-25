# Validation findings: 2026-09-22

## Verdict

The current benchmark executes the intended populated, high-density cold reads
and creates substantial real storage I/O. The resident control strongly validates
that cold-state access drives its execution cost. It is **not yet a demonstrated
general-gas worst case**, nor a clean demonstration that cursor dependence is the
dominant reason prewarming is ineffective.

## Controlled comparison

All three validation loads used the same f62969a node binary, original snapshots,
host configuration, offered load, and 20-minute duration. The first ten minutes
were excluded. The resident case retained the full database, method, cursor
read/write, and 4096 data reads, but selected only page zero.

| Measured follower metric | Dependent repeat | Resident control |
| --- | ---: | ---: |
| Storage-cache misses per million gas | 459.818 | 0.06827 |
| Payload-thread major faults per million gas | 403.908 | 0 |
| Execution milliseconds per million gas | 29.8855 | 0.12250 |
| Payload-thread major faults, raw window total | 5,092,461 | 0 |
| Database-device reads, raw window total | 5,232,952 | 11 |

The follower was approximately **244 times faster per gas** with resident state.
Builder execution fell from 45.8878 to 0.12104 ms/Mgas, approximately **379 times
faster**. Both comparison windows had zero pipeline starts, zero pipeline execution
timer increments, and zero payloads returning SYNCING. Device reads are device-wide
corroboration, not individually attributed SLOAD reads. Zero observed major faults
is not a claim that every possible cache miss was measured.

The original dependent run measured 459.819 storage misses and 413.721 major
faults/Mgas, closely reproducing the repeat's miss density. Its timing was less
stable: builder execution averaged 60.97 rather than 45.89 ms/Mgas, and follower
fault/time rates drifted across two-minute slices. The repeat was substantially
steadier. Do not treat a transient peak or either average as a universal bound.

## Correctness and load checks

- Whole-report cursor increments matched all 3,012 dependent, 3,817 predictable,
  and 994,613 resident included transactions across contiguous reported blocks.
- All 2,213 sampled canonical receipts passed status and gas-total checks.
- Nine sampled transactions passed method, calldata, fixture bytecode, actual
  transaction access-set, populated-value, and successful-output checks.
- Matched parent-state opcode replays verified 4096 unique populated data reads,
  2100 gas per data SLOAD, the expected page selection, and one cursor increment.
  The AA default transaction opcode logger is unsupported in this build; actual
  transaction prestate/call traces were cross-checked with the replay. Replay
  wrapper gas was not used for normalization. Detailed trace/receipt checks are
  sampled, not exhaustive.
- All measured builder windows had zero reverted transactions, zero invalid
  execution attempts, zero fill-idle time, a populated AA2D pool, and build-budget
  stops rather than transaction-limit stops. This supports builder saturation,
  not a claim that the follower is always saturated.
- Host-wide swap-in deltas were 928 pages for the dependent repeat and 831 for
  resident. Swapping does not plausibly explain millions of dependent faults.

## Claims not established

The predictable control reduced builder misses from 438.80 to 405.16/Mgas, but
its average builder execution was slower: 49.62 versus 45.89 ms/Mgas. Its
two-minute rates drifted from 31.24 to 68.60 ms/Mgas. This is not a stable causal
comparison proving that state dependence dominates cost or defeats prewarming.

The predictable follower entered catch-up syncing: four pipeline starts and
549.54 seconds recorded by the pipeline execution-stage timer in the measured
counter window. Pipeline execution shares gas/time metrics but bypasses the
payload-thread fault scope and engine cache. Its aggregate fault/cache-miss
ratios are therefore suppressed, not presented as evidence of improvement.

Engine prewarming was inactive in the dependent follower's measured window but
active in the resident case. Both used the same configuration; effective work
and scheduling differ with the workload. The resident comparison validates the
working-set effect, not an isolated estimate of disk latency with all cache and
prewarming behavior held constant.

Major faults are not an exact page-cache miss percentage. They cover one handler
thread, include non-SLOAD work, and exclude other workers. The builder has no
equivalent execution-thread fault counter in these runs. The two nodes also
share roughly 62 GiB of host RAM despite separate CPU allocations and database
devices. The configured 100000 MiB fixture produced an initial database size of
205,679,992,427 bytes per node. These results should not be extrapolated to a
different single-node cache budget without another measurement.

Before claiming a worst case or changing the workload, the remaining validation
priorities are a stable predictable comparison and execution-scoped fault
accounting covering both normal and catch-up execution. No workload intensification
was performed in this validation task.

## Artifacts and verification

- [Counter tables, trends, and caveats](validation.md)
- [Suite manifest](manifest.json)
- [Reproduction and interpretation guide](../../contrib/bench/state-access-validation.md)
- Each run directory contains correctness JSON, compressed trace evidence, raw
  metric samples, and aligned counter endpoints in `state-access-analysis.json`.
- All 17 focused validator/analyzer tests pass, including counter-reset,
  incomplete-coverage, incorrect-state, duplicate-read, and warm-read failures.
