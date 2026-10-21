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

For `preset=full-journey`, the controller reports p50/p95 for withdrawal submit → L1
funds (split into submit → Zone inclusion and Zone → L1 processing), deposit submit →
Zone credit (split into submit → L1 enqueue and L1 enqueue → Zone credit), and the full
private journey. Each is one paired txgen edge between client observations, so it
includes observation delay; percentiles are never added together. Only the three
end-to-end rows decide whether results post to the Slack channel, and only on their
p95: journeys cluster around block-timing values, so a raw percentile can jump between
clusters with no code change. `bench-zones-classify.js` rebuilds each journey's latency
from the traced instances in both phases' `report.json` and counts a p95 change only when
it clears its 95% bootstrap CI plus a 2% floor. Runs are reported as Unclassified when
journeys are missing traces or number under 100 (the p95 is one of the slowest few) or over
1000 (the trace cap). A run whose baseline and feature are the same commit never posts to
the channel.

Results update the PR comment. Slack uses `bench-slack-notify.js` like the other
benchmarks: results post to `SLACK_BENCH_CHANNEL` when a latency improves
significantly, and otherwise DM the mapped actor; failures DM the actor. Full-journey
latency is imported into `BENCH_VICTORIAMETRICS_URL` with `run_kind=manual|nightly`
and `prover=on|off` labels, so manual runs never overwrite the nightly series. That
address is only reachable over Tailscale, so the controller imports from the AWS
benchmark host, which joins with its workload identity.

## Activation

No repository variables gate these workflows, so the nightly starts as soon as this
lands. After it lands:

1. Dispatch a smoke run:

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
3. Verify the first nightly's Grafana series and Slack delivery; unit tests do not
   replace that check.
