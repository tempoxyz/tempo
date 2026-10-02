# ⚠️ Bench Comparison: Mixed Results

**Refs:** 9de35499af7dd84c889fae8edbf8d0db0331b8eb vs 17f6165d9
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=50000 accounts=1000 max-concurrent-requests=100 baseline=9de35499af7dd84c889fae8edbf8d0db0331b8eb feature=17f6165d9 baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 samply feature-args="--execution.threads 8 --execution.batch-size 128 --builder.disable-prewarming"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 50000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 357
- Feature blocks: 597

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 11935 | 5192 | -56.50% ❌ (+/-14.47/floor 0.55) |
| Gas Throughput [Mgas/s] | 1104.6 | 480.4 | -56.51% ❌ (+/-14.69/floor 0.50) |
| Block Time Mean [ms] | 729.0 | 482.6 | -33.80% ✅ (+/-14.24/floor 0.40) |
| Block Time P50 [ms] | 444.0 | 486.0 | +9.46% ❌ (+/-2.40/floor 0.70) |
| Block Time P90 [ms] | 660.0 | 521.0 | -21.06% ✅ (+/-7.53/floor 0.70) |
| Block Time P99 [ms] | 16772.0 | 601.0 | -96.42% ✅ (+/-36.06/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3408.3 | 540.7 | -84.14% ❌ (+/-1.73/floor 0.95) |
| P50 [ms] | 229.7 | 424.9 | +84.98% ❌ (+/-0.77/floor 0.45) |
| P90 [ms] | 277.9 | 453.9 | +63.33% ❌ (+/-1.27/floor 0.90) |
| P99 [ms] | 381.0 | 514.6 | +35.07% ❌ (+/-16.25/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 23.3 | 1.1 | -95.28% |
| Finish P90 [ms] | 61.1 | 1.5 | -97.55% |
| Finish P99 [ms] | 147.4 | 15.6 | -89.42% |
| Pool Fetch P50 [ms] | 7.6 | 6.5 | -14.47% |
| Pool Fetch P90 [ms] | 17.2 | 11.0 | -36.05% |
| Pool Fetch P99 [ms] | 36.2 | 16.9 | -53.31% |
| Invalid Tx Skips | 36960 | 0 | -100.00% |
| Stop Reason — Build Budget | 358 | 592 | +65.36% |
| Serialized Block Size P50 [KiB] | 2413.5 | 704.7 | -70.80% |
| Serialized Block Size P90 [KiB] | 2905.2 | 921.9 | -68.27% |
| Serialized Block Size P99 [KiB] | 3439.8 | 967.2 | -71.88% |
| Serialized Block Size / Tx P50 [B/tx] | 279.7 | 280.2 | +0.18% |
| Serialized Block Size / Tx P90 [B/tx] | 280.4 | 281.8 | +0.50% |
| Serialized Block Size / Tx P99 [B/tx] | 281.4 | 283.5 | +0.75% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3821.9 | 3951.4 | +3.39% ⚪ (+/-4.22/floor 0.65) |
| P50 [ms] | 208.9 | 59.3 | -71.61% ✅ (+/-1.05/floor 1.55) |
| P90 [ms] | 303.7 | 75.1 | -75.27% ✅ (+/-5.88/floor 1.55) |
| P99 [ms] | 522.5 | 105.8 | -79.75% ✅ (+/-22.11/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 34 |
| Feature | 30 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| [failed delivering finalized block &#96;0xe78495023dabeaab2258eaef0bcaaedd5fa8acc91c778d9dddbcabce098a71f7&#96; at height &#96;143&#96;, failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 2 | 0 |
| executor could not verify the block; abstaining | 1 | 0 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 1 | 0 |

</details>
