# Lane prewarming diagnostic branch

This instrumentation changes no lane selection, gas checks, or prewarming policy.
Compare the uninstrumented parent with this branch using the same public-mix
preset, txgen revision, 100 GiB snapshot, and GCP topology. The control quantifies
instrumentation overhead; it is not a proposed optimization.

The node emits four `prewarm_diagnostics` events at INFO level:

- `prewarm_cutoff`: builder fill duration, included/yielded transactions and gas.
- `prewarm_payload`: maps the process-local build ID to the finished payload hash
  and timestamp, allowing measurement-window and canonical-block filtering.
- `prewarm_build`: iterator `next()` time, coordinator invalidation/drain time,
  number of invalidations and scanned buffered items, worker count, cutoff and
  first general-cap rejection timestamps.
- `prewarm_lane`: grouped transaction observations, emitted after the builder
  and every worker release that build. Every scheduling attempt is counted,
  including transactions never consumed by the builder.

Join by validator/process and `build_id`. A node restart resets the ID. Do not
combine warmup, cooldown, different phases, or multiple attempted payloads into
canonical measurement statistics. Match `prewarm_payload.hash` to the benchmark's
recorded blocks. Missing final summaries are incomplete observations.

`prewarm_lane` dimensions:

| Field | Meaning |
| --- | --- |
| `payment` | The builder's hardfork-specific payment classification |
| `outcome` | 0 unconsumed/filtered elsewhere; 1 included success; 2 included revert; 3 rejected for general cap; 4 other builder rejection; 5 execution error |
| `readiness` | At execution entry: 0 not attempted; 1 worker not started; 2 worker running; 3 completed successfully; 4 completed with revert; 5 completed with EVM error; 6 task finished without execution |
| `after_cap` | Worker started after the first general-cap rejection |
| `nonfitting_at_start` | General transaction's capped declared limit exceeded observed remaining general capacity when its worker started |

`worker_ns` is total task elapsed time summed across workers. It includes provider
setup and execution, and is **not** builder wall time or CPU time. Queue time is
reported separately. `worker_before_cutoff_ns` clips each task to the active build;
`worker_after_cap_ns` further clips to the interval between the first general-cap
rejection and builder cutoff. `invalidation_ns` includes coordinator work after
cutoff, if any; it can overlap builder `next_ns` and must not be added to it.
`execution_ns` sums payload execution/replay calls, including execution errors,
and is grouped by the readiness snapshot taken before each attempt.

The first general-cap rejection does not imply all smaller general transactions
are inadmissible. `nonfitting_at_start` checks each candidate individually, using
the same declared-limit cap as the builder and the most recently observed actual
general gas consumption. Concurrent starts near an accounting update may race.
Prewarming completion is not a guarantee of cache hits: caches can be evicted or
state can change. Successful prewarming is distinguished from reverts/EVM errors.

Evidence for the proposed mechanism requires both substantial active-build worker
time on nonfitting/rejected general transactions and payments reaching execution
without completed prewarming. Neither aggregate worker share nor a throughput
change alone proves causality. Report those measurements and iterator/invalidation
costs separately, together with control throughput and observation coverage.
