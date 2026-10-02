# ⚠️ Bench Comparison: Mixed Results

**Refs:** 61c979a524f9af5de9c540a0088c429a44741e4c vs c83b280859983fd3cc02f025d2e9817c662f236a
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=75000 accounts=1000 max-concurrent-requests=100 baseline=61c979a524f9af5de9c540a0088c429a44741e4c feature=c83b280859983fd3cc02f025d2e9817c662f236a baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 75000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 626
- Feature blocks: 661

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 16869 | 12202 | -27.67% ❌ (+/-3.43/floor 0.55) |
| Gas Throughput [Mgas/s] | 1559.4 | 1128.0 | -27.66% ❌ (+/-3.48/floor 0.50) |
| Block Time Mean [ms] | 434.2 | 422.1 | -2.79% ✅ (+/-2.24/floor 0.40) |
| Block Time P50 [ms] | 417.0 | 419.0 | +0.48% ⚪ (+/-1.72/floor 0.70) |
| Block Time P90 [ms] | 589.0 | 576.0 | -2.21% ⚪ (+/-3.59/floor 0.70) |
| Block Time P99 [ms] | 1226.0 | 727.0 | -40.70% ✅ (+/-14.68/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3039.4 | 1861.3 | -38.76% ❌ (+/-1.58/floor 0.95) |
| P50 [ms] | 221.8 | 249.3 | +12.40% ❌ (+/-2.13/floor 0.45) |
| P90 [ms] | 261.2 | 289.0 | +10.64% ❌ (+/-1.33/floor 0.90) |
| P99 [ms] | 372.2 | 325.1 | -12.65% ⚪ (+/-61.91/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 22.8 | 5.6 | -75.44% |
| Finish P90 [ms] | 52.8 | 12.2 | -76.89% |
| Finish P99 [ms] | 155.7 | 39.9 | -74.37% |
| Pool Fetch P50 [ms] | 6.5 | 10.2 | +56.92% |
| Pool Fetch P90 [ms] | 16.0 | 19.1 | +19.38% |
| Pool Fetch P99 [ms] | 43.3 | 40.1 | -7.39% |
| Invalid Tx Skips | 1862 | 0 | -100.00% |
| Stop Reason — Build Budget | 623 | 653 | +4.82% |
| Serialized Block Size P50 [KiB] | 2060.3 | 1424.4 | -30.87% |
| Serialized Block Size P90 [KiB] | 2514.3 | 1723.2 | -31.47% |
| Serialized Block Size P99 [KiB] | 2838.1 | 2269.7 | -20.03% |
| Serialized Block Size / Tx P50 [B/tx] | 279.7 | 279.8 | +0.04% |
| Serialized Block Size / Tx P90 [B/tx] | 280.5 | 280.7 | +0.07% |
| Serialized Block Size / Tx P99 [B/tx] | 281.3 | 281.5 | +0.07% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3486.0 | 2474.6 | -29.01% ❌ (+/-2.21/floor 0.65) |
| P50 [ms] | 196.1 | 199.4 | +1.68% ⚪ (+/-4.28/floor 1.55) |
| P90 [ms] | 275.7 | 285.4 | +3.52% ⚪ (+/-4.17/floor 1.55) |
| P99 [ms] | 568.9 | 419.8 | -26.21% ✅ (+/-15.80/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 33 |
| Feature | 33 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| executor could not verify the block; abstaining | 1 | 1 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 1 | 1 |
| [failed delivering block &#96;0x16554305209f791df377d94dbb2ab9fa1c3e58ef515660648c8d80194fcd2934&#96; for verification (0, 274), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |
| [failed delivering block &#96;0x1de09cd19670b0c8d73d518ef0747e3fdccb9f195c3bb9236fa7cc0cde7b065a&#96; for verification (0, 254), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |

</details>
