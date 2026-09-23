# E2E CPU allocation

`bench-e2e.nu e2e --txgen-cores 4` reserves four physical cores, including
all their SMT siblings, for the local transaction generator, sender and metrics
scraper. Both validators give up the same number of cores from their existing
CPU groups, preserving the existing placement instead of moving either validator
across groups. The runner's actual socket/core topology is checked before any
snapshot changes; overlapping groups, offline CPUs and split SMT cores are errors.

On the current 16-core/32-thread runner layout, the default is:

| Process | Physical cores | Logical CPU IDs |
| --- | ---: | --- |
| Validator a | 6 | `0-5,16-21` |
| Validator b | 6 | `8-13,24-29` |
| txgen + sender + scraper | 4 | `6-7,14-15,22-23,30-31` |

The setting accepts even numbers that leave at least one core per validator.
`--txgen-cores 0` reproduces the original two full validator groups and unpinned
load generator. This is process affinity, not kernel CPU isolation: system
services and interrupts can still run on these CPUs.

The same options are available to Derek and the reusable `bench-e2e` workflow:

```text
derek bench preset=public-mix txgen-cores=4 run-pairs=4
derek bench preset=public-mix baseline=<SHA> feature=<SAME_SHA> baseline-txgen-cores=0 txgen-cores=4 run-pairs=4
```

`baseline-txgen-cores` changes only the baseline allocation; when omitted both
sides use `txgen-cores`. The direct workflow-dispatch form is already at GitHub's
25-input limit, so custom allocations use Derek, the reusable workflow or the CLI.
The default still applies to workflow dispatch. Exact allocations, kernel and
topology are saved in `cpu-layout.json` and `summary.json`, and the allocations
are displayed in the benchmark summary. Each raw sender report records its
`txgen_cpus` metadata.

For sizing, hold node SHA, txgen SHA, resolved preset, offered TPS, tracing and
profiling settings fixed. Compare 2/4/6 dedicated cores against the shared layout
on the same host with an even number of run pairs. Check achieved included TPS,
sender throughput/failures, pool-empty/build-budget stops and CPU utilization;
lower variance alone is not sufficient if the generator stops saturating the
validators. Keep profiled runs separate from unprofiled confirmation runs.

Tests: `nu contrib/bench/cpu-layout.test.nu`.
