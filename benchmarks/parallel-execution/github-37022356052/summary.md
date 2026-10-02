# ⚠️ Bench Comparison: Mixed Results

**Refs:** 4caada90d070419af2e72900914849867f4bb5e8 vs 7c1f1b86ffcdf1e08e05628b4feac8d0c70dc6d2
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=50000 accounts=1000 max-concurrent-requests=100 baseline=4caada90d070419af2e72900914849867f4bb5e8 feature=7c1f1b86ffcdf1e08e05628b4feac8d0c70dc6d2 baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 samply feature-args="--execution.threads 8 --execution.batch-size 128 --engine.disable-precompile-cache"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 50000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 249
- Feature blocks: 434

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 10717 | 8142 | -24.03% ❌ (+/-11.37/floor 0.55) |
| Gas Throughput [Mgas/s] | 991.9 | 753.1 | -24.07% ❌ (+/-11.39/floor 0.50) |
| Block Time Mean [ms] | 838.9 | 677.6 | -19.23% ✅ (+/-12.75/floor 0.40) |
| Block Time P50 [ms] | 421.0 | 520.0 | +23.52% ❌ (+/-3.88/floor 0.70) |
| Block Time P90 [ms] | 565.0 | 762.0 | +34.87% ❌ (+/-3.39/floor 0.70) |
| Block Time P99 [ms] | 27744.0 | 6462.0 | -76.71% ✅ (+/-21.97/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3424.7 | 2102.6 | -38.60% ❌ (+/-0.87/floor 0.95) |
| P50 [ms] | 234.2 | 244.2 | +4.27% ❌ (+/-1.70/floor 0.45) |
| P90 [ms] | 269.5 | 250.2 | -7.16% ✅ (+/-1.89/floor 0.90) |
| P99 [ms] | 309.0 | 275.4 | -10.87% ⚪ (+/-35.93/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 23.7 | 4.7 | -80.17% |
| Finish P90 [ms] | 57.7 | 9.1 | -84.23% |
| Finish P99 [ms] | 87.5 | 46.0 | -47.43% |
| Pool Fetch P50 [ms] | 6.6 | 9.1 | +37.88% |
| Pool Fetch P90 [ms] | 17.3 | 17.3 | +0.00% |
| Pool Fetch P99 [ms] | 39.2 | 41.7 | +6.38% |
| Invalid Tx Attempts P99 | 39793.0 | 0.0 | -100.00% |
| Invalid Tx Skips | 244434 | 7033 | -97.12% |
| Stop Reason — Build Budget | 246 | 434 | +76.42% |
| Serialized Block Size P50 [KiB] | 2517.1 | 1503.2 | -40.28% |
| Serialized Block Size P90 [KiB] | 3028.3 | 1833.3 | -39.46% |
| Serialized Block Size P99 [KiB] | 3476.5 | 2449.2 | -29.55% |
| Serialized Block Size / Tx P50 [B/tx] | 279.7 | 279.8 | +0.04% |
| Serialized Block Size / Tx P90 [B/tx] | 280.4 | 280.7 | +0.11% |
| Serialized Block Size / Tx P99 [B/tx] | 281.7 | 281.6 | -0.04% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 110.0 | 0.0 | -100.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3990.1 | 1624.1 | -59.30% ❌ (+/-0.99/floor 0.65) |
| P50 [ms] | 204.6 | 306.6 | +49.85% ❌ (+/-3.03/floor 1.55) |
| P90 [ms] | 280.6 | 424.3 | +51.21% ❌ (+/-2.32/floor 1.55) |
| P99 [ms] | 375.0 | 523.2 | +39.52% ❌ (+/-14.12/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 30 |
| Feature | 37 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| [failed delivering build parent, failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 4 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 0 | 2 |
| [executor dropped the payload channel: the build failed (the executor logs the cause) or the executor shut down, oneshot canceled] | 0 | 1 |

</details>
