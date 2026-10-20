# Prover latency comparison

The `Zones Nitro prover benchmark` workflow supports two comparisons:

- `revision` (default): Tempo main versus an exact feature SHA, with Nitro in both phases. The existing `derek bench <SHA>` PR command retains this behavior.
- `prover`: the same exact feature SHA and L1 binary with proving disabled, then enabled. This requires `full-journey` and measures deposit, withdrawal, and complete-journey p50/p95.

Deposit latency runs from observing the L1 enqueue event to observing Zone processing.
Withdrawal latency runs from observing the Zone withdrawal request to observing L1
processing. These include observation delay and exclude submission before the first
event. Complete journeys include client orchestration. Percentiles are calculated
from paired observations, never by adding step percentiles.

## Activation

Keep both repository flags disabled until the monorepo journey/settlement changes
and the pinned benchmark controller are available on main. The workflow deliberately
retains main-only authorization and checks org membership, including on reruns.
Branch dispatches do not bypass that gate.

After the dependencies land, enable `ZONES_PROVER_BENCHMARK_ENABLED=true` and run:

```sh
gh workflow run zones-prover-benchmark.yml --repo tempoxyz/tempo --ref main \
  -f feature-sha=<exact-main-commit> -f comparison-mode=prover \
  -f preset=full-journey -f tempo-hardfork=t14 \
  -f accounts=20 -f count=20 -f tps=5 -f max-concurrent=4 \
  -f state-bloat-mib=0
```

Require both phases to pass, inspect each `batch-evidence.json`, raw reports, and
`comparison.json`, and confirm the feature's Nitro journal. Every baseline batch must
settle with NoProof; every feature batch must match Nitro validation and verification.
A fallback in the feature phase fails the run. The same virgin L1 snapshot, seed,
accounts, workload, Zone revision, and L1 binary are used in both phases.

The workflow imports validated metrics into `BENCH_VICTORIAMETRICS_URL`. Import the
controller's `scripts/zones_prover/dashboard.json` into the persistent benchmark
Grafana folder and verify the **manual** series against the artifact. An import
HTTP success does not verify that the Grafana read datasource is connected to the
same storage. No-data panels are not zero latency.

Only after that smoke succeeds, set `ZONES_PROVER_NIGHTLY_ENABLED=true`. The nightly
runs at 03:45 UTC, snapshots the event's exact main SHA, and reports pass/fail to
`C0B96B0RRMJ` using `SLACK_BENCH_BOT_TOKEN`. Manual series use a separate label
and do not overwrite nightly data. Verify the first nightly Slack post and Grafana
series before declaring reporting operational; unit tests do not replace that check.
