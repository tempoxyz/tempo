# ⚠️ Bench Comparison: Mixed Results

**Refs:** 61c979a524f9af5de9c540a0088c429a44741e4c vs c83b280859983fd3cc02f025d2e9817c662f236a
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=10000 accounts=1000 max-concurrent-requests=100 baseline=61c979a524f9af5de9c540a0088c429a44741e4c feature=c83b280859983fd3cc02f025d2e9817c662f236a baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 10000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 595
- Feature blocks: 613

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 9915 | 9924 | +0.09% ⚪ (+/-0.38/floor 0.55) |
| Gas Throughput [Mgas/s] | 917.6 | 918.4 | +0.09% ⚪ (+/-0.39/floor 0.50) |
| Block Time Mean [ms] | 446.6 | 432.6 | -3.13% ✅ (+/-0.84/floor 0.40) |
| Block Time P50 [ms] | 453.0 | 444.0 | -1.99% ⚪ (+/-2.24/floor 0.70) |
| Block Time P90 [ms] | 504.0 | 513.0 | +1.79% ⚪ (+/-1.39/floor 0.70) |
| Block Time P99 [ms] | 567.0 | 560.0 | -1.23% ⚪ (+/-18.25/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 1133.1 | 1201.6 | +6.05% ✅ (+/-0.91/floor 0.95) |
| P50 [ms] | 367.3 | 335.2 | -8.74% ✅ (+/-1.05/floor 0.45) |
| P90 [ms] | 383.4 | 351.4 | -8.35% ✅ (+/-0.48/floor 0.90) |
| P99 [ms] | 389.1 | 359.0 | -7.74% ✅ (+/-0.55/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 2.0 | 2.3 | +15.00% |
| Finish P90 [ms] | 4.2 | 4.4 | +4.76% |
| Finish P99 [ms] | 8.9 | 7.8 | -12.36% |
| Pool Fetch P50 [ms] | 2.6 | 2.5 | -3.85% |
| Pool Fetch P90 [ms] | 4.7 | 4.8 | +2.13% |
| Pool Fetch P99 [ms] | 8.9 | 7.6 | -14.61% |
| Invalid Tx Skips | 7801 | 0 | -100.00% |
| Stop Reason — Build Budget | 591 | 606 | +2.54% |
| Serialized Block Size P50 [KiB] | 1241.4 | 1183.7 | -4.65% |
| Serialized Block Size P90 [KiB] | 1374.5 | 1394.3 | +1.44% |
| Serialized Block Size P99 [KiB] | 1558.5 | 1533.7 | -1.59% |
| Serialized Block Size / Tx P50 [B/tx] | 279.9 | 279.9 | +0.00% |
| Serialized Block Size / Tx P90 [B/tx] | 280.9 | 280.9 | +0.00% |
| Serialized Block Size / Tx P99 [B/tx] | 281.7 | 281.6 | -0.04% |
| Fill Idle P50 [ms] | 96.0 | 72.0 | -25.00% |
| Fill Idle P90 [ms] | 149.0 | 121.0 | -18.79% |
| Fill Idle P99 [ms] | 173.0 | 149.0 | -13.87% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 4379.9 | 3164.9 | -27.74% ❌ (+/-0.63/floor 0.65) |
| P50 [ms] | 92.6 | 125.1 | +35.10% ❌ (+/-2.23/floor 1.55) |
| P90 [ms] | 125.4 | 162.3 | +29.43% ❌ (+/-2.94/floor 1.55) |
| P99 [ms] | 199.8 | 207.5 | +3.85% ⚪ (+/-14.86/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 30 |
| Feature | 33 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| [failed delivering block &#96;0x9cdea9f435e32ae39338c5860a5bd711c0faa0ff2567461457720208ceb17255&#96; for verification (0, 396), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |
| executor could not verify the block; abstaining | 0 | 1 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 0 | 1 |

</details>
