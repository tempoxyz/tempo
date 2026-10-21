# Zone Nitro benchmark

`zones-prover-benchmark.yml` compares a baseline and a feature Tempo revision on AWS
with the prover setting applied to both phases:

- `prover=true` (default): every measured batch must be proven with NitroV1; a NoProof
  fallback fails the run.
- `prover=false`: no enclave or prover runs, and every measured batch must settle with
  NoProof.

The two settings are never compared with each other. Runs start from:

- **PR comments**: `derek bench zones [prover=true|false] [preset=NAME] [baseline=REF] [feature=REF] [no-slack]`,
  parsed by `bench.yml` like the e2e and replay commands. The feature is the pinned PR
  head, which must be a `tempoxyz/tempo` branch; the baseline defaults to its merge base
  with main.
- **Nightly** (`bench-zones-scheduled.yml`, 03:45 UTC): the latest main commit against
  the last commit that completed the nightly successfully, with the prover on.
- **Manual dispatch** of `zones-prover-benchmark.yml` on main, with every workload input.

For `preset=full-journey`, the controller reports deposit, withdrawal, and
complete-journey p50/p95. Deposit latency runs from observing the L1 enqueue event to
observing Zone processing. Withdrawal latency runs from observing the Zone withdrawal
request to observing L1 processing. These include observation delay and exclude
submission before the first event. Complete journeys include client orchestration.
Percentiles are calculated from paired observations, never by adding step percentiles.

Results update the PR comment. Slack uses `bench-slack-notify.js` like the other
benchmarks: results post to `SLACK_BENCH_CHANNEL` when a latency improves
significantly, and otherwise DM the mapped actor; failures DM the actor. Full-journey
latency is imported into `BENCH_VICTORIAMETRICS_URL` with `run_kind=manual|nightly`
and `prover=on|off` labels, so manual runs never overwrite the nightly series.

## Activation

Keep both repository flags disabled until a manual run succeeds:

1. Set `ZONES_PROVER_BENCHMARK_ENABLED=true` and dispatch a smoke run:

   ```sh
   gh workflow run zones-prover-benchmark.yml --repo tempoxyz/tempo --ref main \
     -f baseline=<main-commit> -f feature=<main-commit> -f preset=full-journey
   ```

   It uses the same workload defaults as PR and nightly runs. Inspect each
   `batch-evidence.json`, the raw reports, and `comparison.json`, and confirm the
   feature's Nitro journal. Repeat with `-f prover=false`.
2. Import the controller's `scripts/zones_prover/dashboard.json` into the persistent
   benchmark Grafana folder and verify the **manual** series against the artifact. An
   import HTTP success does not verify that the Grafana read datasource is connected to
   the same storage. No-data panels are not zero latency.
3. Set `ZONES_PROVER_NIGHTLY_ENABLED=true`, then verify the first nightly's Grafana
   series and Slack delivery; unit tests do not replace that check.
