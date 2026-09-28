# Bytecode follower OOM fix validation

## Failure

Reference: `../builder-prewarm-control-20260925/bytecode-off`, raw run
`../builder-prewarm-control-20260925/harness/bench-results/20260925-215721-114`.
The follower entered pipeline sync and was killed by its 20 GiB memory cgroup at
2026-09-25 22:24:32 UTC, about 18m48s into the 1200-second load. Kernel evidence
records 20,319,468 KiB anonymous RSS and only 85,624 KiB file RSS. This was not
a host-wide OOM or simply a large reclaimable page cache.

REVM `State::code_by_hash` keeps read-only bytecodes in `cache.contracts` for
the lifetime of the batch. Reth `BasicBlockExecutor::size_hint` returns only
`bundle_state.size_hint()`, which counts changed state rather than the read
cache or bytecode buffer bytes. The pipeline's other defaults allow 500,000
blocks, 1.5 trillion gas, or ten minutes per batch. A read-only bytecode
workload can therefore retain gigabytes while staying below all limits.

## Fix

The standalone patch is `oom-fix.patch`, against the local Reth base recorded
in `build-manifest.json`. Existing prefetch/payload changes are preserved in
`reth-candidate.patch` but are not part of the OOM fix.

- Add executor accounting for cached bytecode buffers and jump tables,
  independently of changed-state accounting.
- Default `[stages.execution].max_cached_bytecode_bytes` to 536870912 (512 MiB).
- End and commit execution/backfill batches at the bytecode limit, using the
  existing state-output and database-commit paths. Releasing the executor
  then releases its read cache without discarding pending writes.
- Check between blocks. This is a soft limit with up to one block's overshoot,
  not a total RSS cap or a solution to arbitrary single-block OOMs. Account,
  storage, allocator and other caches are not included in the bytecode hint.

The bytecode size scan is linear in the number of cached code hashes and runs
once per block during batching, not per EVM access. Custom executors that
retain their own code caches must implement the new hint.

## Validation

38 focused tests passed: 4 EVM, 18 stage types, 16 configuration tests. These
include read-only code growth with zero bundle changes, shared repeated code
reads, exact limit boundaries, and old-config/default/override behavior.
See `executor-threshold-tests.log` and `config-tests.log`.

The full node builds with the original profiling/native-CPU/prefetch settings.
All archived runtime source hashes from the previous measured node matched
before the OOM patch. The new Tempo HEAD contains previously uncommitted
instrumentation, not a separate runtime change in this comparison.

The archived host-specific runner used `node run.cjs --wait` after `--prepare` (preparation refuses to overwrite
an existing experiment). The shared benchmark lock is held through restore,
execution, audit and cleanup. The frozen plan reuses the prior run's workload:
2250 EXTCODECOPY accesses/transaction, full unique 24 KiB code corpus,
builder prewarming off, bytecode prefetch on, 1200 seconds with 600 warmup,
20 GiB per node, no swap, same CPU assignments, fresh restored databases and
targeted verified file-cache eviction. It does not change the memory cap,
transaction size, fixture size, offered rate or audit timeouts.

`memory-controls.jsonl` adds anonymous/file/peak cgroup memory, OOM counters,
CPU and command-line verification. Standard observer, canonical report,
execution logs, receipt/router checks and persistence audit remain enabled.
The experiment completed successfully; see `results.json`, `experiment.json`
and `run.log`. Both benchmark node scopes were stopped by normal suite cleanup.

### Forced Catch-Up During Warmup

At the last pre-intervention check the candidate was keeping up without
pipeline sync. To avoid a fix validation that only exercised normal execution,
`force-catchup.cjs` pauses the owned follower process for 120 seconds during
warmup and automatically resumes it. `sync-injection.json` records the PID,
binary and start/resume timestamps. The proposer and sender continue normally.
No intervention occurs during the final measured 600 seconds.

Subsequent log inspection showed that natural pipeline sync actually began at
10:47:26.830 UTC, immediately before the pause at 10:47:37.397. The new limit
first fired at 10:47:27.207, before intervention. Thus the recorded intervention
reason reflects the earlier observation, not the later-discovered exact
transition. The follower resumed at 10:49:37.418. The pause additionally creates
a larger backlog for the already-exercised sync path.

This makes the run a forced-catch-up OOM regression, not a strict natural-history
A/B throughput comparison with the original failed run. The analyzer requires
actual bytecode-limit commits and verifies resume preceded measurement.

## Results

The full 1200-second load completed with the original 20 GiB/no-swap limits.
Both nodes kept the same PIDs throughout the run, with zero cgroup OOM and
OOM-kill events. The follower caught up after submissions ended, and receipt,
router/history, state and persistence checks passed. The audit's quiet workload
target was block 3418; both nodes had persisted state beyond it.

| Observation | Result |
| --- | --- |
| Follower sampled peak anonymous memory (5-second sampling) | 2.003 GiB |
| Original follower process anonymous RSS at OOM | 19.378 GiB |
| Follower total cgroup peak, including file cache | 20.000 GiB |
| Bytecode-limit commits | 327 |
| Largest bytecode-buffer size at a limit commit | 533.339 MiB |
| Default soft bytecode limit | 512 MiB, checked between blocks |
| Correctness / durable persistence audit | Passed |
| Suite exit code | 0 |

The anonymous-memory measurements are not identical metrics: the new figure
is the maximum sampled whole-cgroup anonymous memory, while the old figure is
kernel-reported process anonymous RSS at death. Total node memory still reaches
the 20 GiB cap through useful, reclaimable file cache. This is not a claim that
total RAM use fell to 2 GiB.

Measured window: **2026-09-26 10:54:42.704 through 11:04:42.704 UTC**.

| Throughput | Mgas/s |
| --- | ---: |
| Builder, completed-build execution/fill timer | 17.376 |
| Chain production, canonical gas / 600 seconds | 17.111 |
| Follower, execution gas counter / sampled wall time, including pipeline work | 16.569 |

There were no normal engine `Executed block` events in the measured window,
so a normal follower execution-only rate is **not available**, not zero. The
generic native summary prints zero for that absent series; use `results.json`
instead. The follower was slower than the proposer during pipeline sync and
required about 3.5 minutes after load completion to catch up and pass the audit.
Thus the OOM is fixed for this reproduced workload, but the follower throughput
gap is not fixed. The warmup pause also precludes claiming a strict A/B speedup.

Physical database reads averaged 157.03 MB/s on the builder and 154.57 MB/s on
the follower. All 1641 measured blocks contained one workload transaction, so
this sized case still does not demonstrate within-block history-based
prewarming bypass. The load's original prewarming controls were unchanged.

Recompute this result with `node analyze.cjs`; it requires a successful suite,
full-window observations, unchanged memory/swap limits, no restart/OOM, actual
bytecode-limit activations, warmup-only intervention and a passing durable-state
audit. Full reanalysis requires the raw local observer/log archive, which is not
in Git. The code change is now included in the pinned `contrib/bench/patches/reth.patch`
bundle. For a fresh run without archived binaries, use the
[current runbook](../../contrib/bench/state-access-reproduction.md). The standard
prewarming-control suite does not inject the historical follower pause.
