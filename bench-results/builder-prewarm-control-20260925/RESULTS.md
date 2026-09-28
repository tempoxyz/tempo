# Builder prewarming control results

Checked 2026-09-26. Three runs passed the full correctness and persistence audit.
The bytecode-off load completed, but its follower was OOM-killed during load;
the final suite and experiment remain failed. No benchmark is currently running.

All rates below are Mgas/s. Each window is the final 600 seconds of a 1200-second
load, anchored to submission. Builder means completed transaction-fill time;
follower means ordinary block execution time, not saturated wall-clock capacity.
Chain means gas produced by the proposer per full 600-second wall window.

| Workload | Builder prewarming | Builder | Follower | Chain production | Audit |
| --- | --- | ---: | ---: | ---: | --- |
| SLOAD, 7200/tx | on | 17.713 | 38.731 | 17.599 | passed |
| SLOAD, 7200/tx | off | 36.777 | 39.835 | 36.450 | passed |
| Bytecode, 2250/tx | on | 6.869 | 17.032 | 6.798 | passed |
| Bytecode, 2250/tx | off | 17.225 | not comparable: pipeline sync, then OOM | 16.965 | failed; diagnostic only |

SLOAD chain throughput improves 2.071x. Builder pre-execution median falls from
446.594 ms to 0.630 ms, and transaction execution from 447.181 ms to 424.743 ms.
Whole-builder DB physical reads fall from 640.389 to 58.669 MB/s despite twice
the useful throughput. This confirms that speculative prewarming was imposing
large scheduling and I/O overhead in this workload. Both SLOAD measured windows
have zero proposal cancellations; the enabled run had three warmup cancellations.

For bytecode, builder pre-execution median falls from 427.882 ms to 1.729 ms,
transaction execution from 485.352 ms to 362.461 ms, and whole-builder DB reads
from 1944.590 to 153.227 MB/s. These are useful builder diagnostics, not proof
of sustainable network throughput because the follower failed.

## Bytecode follower failure

- Submission began at 22:05:43.767 UTC on September 25; measurement was
  22:15:43.767 through 22:25:43.767 UTC.
- The kernel OOM-killed follower PID 1382112 at 22:24:32 UTC, about 18m48s into
  the load and 72 seconds before its scheduled end.
- Kernel evidence says `CONSTRAINT_MEMCG` on `tempo-e2e-b-feature-1.scope`,
  not a host-wide OOM. Anonymous RSS was 20,319,468 KiB (about 19.38 GiB).
- At the first measured observer sample, builder/follower heads were 1693/1434.
  At the last healthy sample (22:24:29), they were 3116/2330, a 786-block gap.
- Follower total cgroup memory was 20.000 GiB with only 0.261 GiB file cache at
  that last sample. This is not simply page-cache occupancy being reclaimed.
- The follower had switched to pipeline sync. There are no ordinary
  `Executed block` events in the measured window, so no ordinary follower
  execution rate is reported. Pipeline replay counters are not substituted.
- The post-load audit failed with `ECONNREFUSED` on follower RPC port 8645.
  Receipt/trace/persistence validation did not complete. The retaining data
  structures behind the anonymous-memory growth have not yet been identified.

The single-proposer benchmark keeps producing after its certified follower dies;
16.965 Mgas/s therefore describes production, not successful follower processing.

## Controls and provenance

The fresh references and controls use the same archived diagnostic node binary,
router, generator, fixture, 20 GiB/node/no-swap limits, CPU allocations, cold
restores, offered load, and transaction sizes. Only builder prewarming changes;
engine prewarming, bytecode prefetch, and cache sharing retain their settings.
Each run has live flag/limit evidence. File-cache allocation itself is not fixed.

The initial SLOAD-off attempt is excluded: a boolean-argument merge swallowed a
follower flag. Its artifacts remain preserved. The fixed merge was regression
tested and SLOAD-off was rerun from a fresh restore. The enabled reference's
effective arguments are unchanged; the repair and source hashes are recorded
in `experiment.json` and `experiment-before-flag-fix.json`.

Raw directories, relative to `harness/bench-results/`:

- SLOAD on: `20260925-201656-298`.
- SLOAD off (valid retry): `20260925-205834-005`.
- Bytecode on: `20260925-212757-085`.
- Bytecode off (failed): `20260925-215721-114`.

Passing runs have `latency-analysis.json` and `correctness-feature-1.json`
(`ok=true`, `persisted_through_workload=true`). The failed run's preserved logs,
raw metric archive, observer, sender report, and kernel journal remain diagnostic
evidence; its original failure manifests are not rewritten as successful.
