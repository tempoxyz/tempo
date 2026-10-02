# ⚠️ Bench Comparison: Mixed Results

**Refs:** 4caada90d070419af2e72900914849867f4bb5e8 vs 844f7bb21
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=50000 accounts=1000 max-concurrent-requests=100 baseline=4caada90d070419af2e72900914849867f4bb5e8 feature=844f7bb21 baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 50000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 508
- Feature blocks: 665

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 15737 | 2977 | -81.08% ❌ (+/-9.36/floor 0.55) |
| Gas Throughput [Mgas/s] | 1455.8 | 275.4 | -81.08% ❌ (+/-9.41/floor 0.50) |
| Block Time Mean [ms] | 573.8 | 455.2 | -20.67% ✅ (+/-8.54/floor 0.40) |
| Block Time P50 [ms] | 425.0 | 453.0 | +6.59% ⚪ (+/-6.27/floor 0.70) |
| Block Time P90 [ms] | 654.0 | 504.0 | -22.94% ✅ (+/-2.29/floor 0.70) |
| Block Time P99 [ms] | 4548.0 | 558.0 | -87.73% ✅ (+/-29.83/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3587.6 | 302.6 | -91.57% ❌ (+/-3.05/floor 0.95) |
| P50 [ms] | 232.9 | 411.3 | +76.60% ❌ (+/-2.91/floor 0.45) |
| P90 [ms] | 259.0 | 435.0 | +67.95% ❌ (+/-2.48/floor 0.90) |
| P99 [ms] | 378.0 | 473.9 | +25.37% ❌ (+/-13.99/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 21.2 | 0.8 | -96.23% |
| Finish P90 [ms] | 51.6 | 1.7 | -96.71% |
| Finish P99 [ms] | 156.4 | 3.9 | -97.51% |
| Pool Fetch P50 [ms] | 8.9 | 5.1 | -42.70% |
| Pool Fetch P90 [ms] | 18.6 | 8.4 | -54.84% |
| Pool Fetch P99 [ms] | 40.0 | 12.3 | -69.25% |
| Stop Reason — Build Budget | 514 | 660 | +28.40% |
| Serialized Block Size P50 [KiB] | 2486.5 | 385.7 | -84.49% |
| Serialized Block Size P90 [KiB] | 3106.2 | 522.4 | -83.18% |
| Serialized Block Size P99 [KiB] | 3543.0 | 559.0 | -84.22% |
| Serialized Block Size / Tx P50 [B/tx] | 279.7 | 281.0 | +0.46% |
| Serialized Block Size / Tx P90 [B/tx] | 280.3 | 283.1 | +1.00% |
| Serialized Block Size / Tx P99 [B/tx] | 281.0 | 286.3 | +1.89% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3995.8 | 2398.1 | -39.98% ❌ (+/-4.71/floor 0.65) |
| P50 [ms] | 212.3 | 58.3 | -72.54% ✅ (+/-1.35/floor 1.55) |
| P90 [ms] | 299.8 | 86.1 | -71.28% ✅ (+/-3.16/floor 1.55) |
| P99 [ms] | 705.5 | 125.0 | -82.28% ✅ (+/-28.49/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 37 |
| Feature | 30 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| [failed delivering finalized block &#96;0x675772b0a4e402ee5a9a3cd492323ce33a7f0b92ade40c1232c9289424eaa9e5&#96; at height &#96;217&#96;, failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 2 | 0 |
| executor could not verify the block; abstaining | 2 | 0 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 2 | 0 |
| [failed delivering block &#96;0x14369abb3405500a7562138fce28b5c6328d248cd1b33e8127e5c62103a9611d&#96; for verification (0, 210), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |

</details>
