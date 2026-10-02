# ⚠️ Bench Comparison: Mixed Results

**Refs:** 96c28fa63fd4c25c76b18c7a2bc04d690a402e72 vs c60f368fed2efe80fa9ecf9a3f07ba0285572dd3
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=50000 accounts=1000 max-concurrent-requests=100 baseline=96c28fa63fd4c25c76b18c7a2bc04d690a402e72 feature=c60f368fed2efe80fa9ecf9a3f07ba0285572dd3 baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 50000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 519
- Feature blocks: 633

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 17176 | 11489 | -33.11% ❌ (+/-1.39/floor 0.55) |
| Gas Throughput [Mgas/s] | 1588.6 | 1063.2 | -33.07% ❌ (+/-1.39/floor 0.50) |
| Block Time Mean [ms] | 540.8 | 433.1 | -19.91% ✅ (+/-1.43/floor 0.40) |
| Block Time P50 [ms] | 431.0 | 436.0 | +1.16% ⚪ (+/-3.48/floor 0.70) |
| Block Time P90 [ms] | 617.0 | 528.0 | -14.42% ✅ (+/-2.54/floor 0.70) |
| Block Time P99 [ms] | 4008.0 | 672.0 | -83.23% ✅ (+/-25.44/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3638.5 | 1387.1 | -61.88% ❌ (+/-0.91/floor 0.95) |
| P50 [ms] | 234.6 | 329.9 | +40.62% ❌ (+/-1.69/floor 0.45) |
| P90 [ms] | 272.5 | 376.0 | +37.98% ❌ (+/-1.80/floor 0.90) |
| P99 [ms] | 338.9 | 476.3 | +40.54% ❌ (+/-9.45/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 20.4 | 2.6 | -87.25% |
| Finish P90 [ms] | 47.1 | 5.6 | -88.11% |
| Finish P99 [ms] | 115.6 | 12.1 | -89.53% |
| Pool Fetch P50 [ms] | 7.1 | 8.8 | +23.94% |
| Pool Fetch P90 [ms] | 19.9 | 15.8 | -20.60% |
| Pool Fetch P99 [ms] | 49.4 | 27.1 | -45.14% |
| Stop Reason — Build Budget | 517 | 627 | +21.28% |
| Serialized Block Size P50 [KiB] | 2649.8 | 1353.0 | -48.94% |
| Serialized Block Size P90 [KiB] | 3211.2 | 1887.9 | -41.21% |
| Serialized Block Size P99 [KiB] | 3547.0 | 2053.2 | -42.12% |
| Serialized Block Size / Tx P50 [B/tx] | 279.6 | 279.9 | +0.11% |
| Serialized Block Size / Tx P90 [B/tx] | 280.2 | 280.8 | +0.21% |
| Serialized Block Size / Tx P99 [B/tx] | 281.1 | 282.2 | +0.39% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 4171.8 | 4097.7 | -1.78% ❌ (+/-0.88/floor 0.65) |
| P50 [ms] | 206.5 | 113.9 | -44.84% ✅ (+/-2.65/floor 1.55) |
| P90 [ms] | 303.5 | 166.2 | -45.24% ✅ (+/-2.65/floor 1.55) |
| P99 [ms] | 574.4 | 278.3 | -51.55% ✅ (+/-3.53/floor 2.05) |


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
| [failed delivering build parent, failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 2 | 0 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 2 | 0 |
| [executor dropped the payload channel: the build failed (the executor logs the cause) or the executor shut down, oneshot canceled] | 1 | 0 |
| [failed delivering block &#96;0x959fc0fabbbcc4305ad4c63148f354cc220bed65ededd702f5d741a9af950776&#96; for verification (0, 221), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |
| executor could not verify the block; abstaining | 1 | 0 |

</details>
