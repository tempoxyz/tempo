# E2E CPU allocation

`bench-e2e.nu e2e --txgen-cores 4` reserves four physical cores, including
all their SMT siblings, for the local transaction generator, sender and metrics
scraper. Both validators give up the same number of cores from their existing
CPU groups, preserving the existing placement instead of moving either validator
across groups. The runner's actual socket/core topology is checked before any
snapshot changes; overlapping groups, unavailable CPUs and split SMT cores are errors.

The default remains shared CPUs (`--txgen-cores 0`): reserving cores removes
capacity from the validators and must be evaluated for each workload.
On the current 16-core/32-thread runner layout, `--txgen-cores 4` gives:

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
sender throughput/failures, builder fill-idle time and CPU utilization;
lower variance alone is not sufficient if the generator stops saturating the
validators. Keep profiled runs separate from unprofiled confirmation runs.
Pool-empty/build-budget stop counts alone cannot establish saturation: with a
proposal budget the builder waits when the pool is empty, then may stop on its
budget instead.

Targeted validation:

```sh
nu contrib/bench/cpu-layout.test.nu
nu contrib/bench/txgen/cpu-affinity.test.nu
node --test .github/scripts/bench-e2e-cpu-summary.test.js
nu bench-e2e.nu e2e --help
git diff --check
```

## Initial sizing results

Four paired repeats of `public-mix`, 90 seconds, 100 GiB bloat, 4 tokens,
50k target TPS, 1000 accounts and 500 concurrent requests, with samply enabled
and OTLP disabled. Every comparison uses node SHA
`a31081eaf7000745cd747f620e974e9f2383ff6b` on both sides and txgen SHA
`1a3e05e4caf7ecc0d83210ef84f6531d49b6b715`; each isolated allocation is compared
against the original shared allocation on the same host.

| Dedicated txgen cores | Runner | Shared TPS | Isolated TPS | TPS change | Shared / isolated TPS CV |
| --- | --- | ---: | ---: | ---: | ---: |
| [2](https://github.com/tempoxyz/tempo/actions/runs/35838124243) | ghr-euw-07 | 14,979 | 14,422 | -3.72% | 0.98% / 0.63% |
| [4](https://github.com/tempoxyz/tempo/actions/runs/35838143865) | ghr-euw-05 | 15,126 | 13,664 | -9.67% | 0.77% / 0.63% |
| [6](https://github.com/tempoxyz/tempo/actions/runs/35838148612) | ghr-euw-03 | 14,734 | 12,082 | -18.00% | 0.44% / 0.78% |

All three summaries classify the overall result as mixed and TPS as a regression.
None had sender failures or pool-empty builder stops; all had
more than 700 build-budget stops across their four feature repeats. These stop
counts do not prove saturation. Builder fill-idle p50/p90/p99 changed from
7/30/96 ms to 11/33/79 ms with two cores, and from 9/29/92 ms to 12/32/66 ms
with four cores. The reserved logical CPUs averaged about 63% busy across the
four 2-core repeats and 35% across the four 4-core repeats, using host CPU idle
counter deltas over seconds 15-75. This includes system activity and is not a
measure of txgen process utilization or a claim of 50k included TPS capacity.
The shared-CPU [same-commit control](https://github.com/tempoxyz/tempo/actions/runs/35837783670)
was already stable (0.45% / 1.36% TPS CV, no significant difference).
Four repeats are not sufficient to establish a general variance reduction.

The first shared/2-core validator-a profiles show similar hot work: Keccak,
secp256k1, trie/cache operations, RocksDB compression and persistence. These
node profiles include startup/shutdown and do not profile txgen, so they cannot
identify generator CPU contention as the original variance cause.

The [sampler-off confirmation](https://github.com/tempoxyz/tempo/actions/runs/35841742901)
uses the same profiling build, node/txgen SHAs and workload with samply disabled,
two balanced pairs and the final CPU availability validation on ghr-euw-06.
Shared/2-core TPS was 15,400/14,965 (-2.82%, a TPS regression; overall mixed),
with zero sender failures. Builder fill-idle p50/p90/p99 was 0/16/92 ms versus
2/20/43 ms. Two pairs support the observed throughput direction but cannot
establish a general variance reduction.

Keep shared CPUs as the default. For this preset, two physical cores are the
lowest tested dedicated allocation and show average CPU headroom, but other
presets and higher achieved load need separate sizing. A separate load host
would avoid taking physical cores from validators; that configuration was not
tested here.
