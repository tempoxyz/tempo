# ⚠️ Bench Comparison: Mixed Results

**Refs:** 61c979a524f9af5de9c540a0088c429a44741e4c vs c83b280859983fd3cc02f025d2e9817c662f236a
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=50000 accounts=1000 max-concurrent-requests=100 baseline=61c979a524f9af5de9c540a0088c429a44741e4c feature=c83b280859983fd3cc02f025d2e9817c662f236a baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 samply feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 50000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 553
- Feature blocks: 647

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 16745 | 13330 | -20.39% ❌ (+/-1.26/floor 0.55) |
| Gas Throughput [Mgas/s] | 1548.9 | 1233.4 | -20.37% ❌ (+/-1.25/floor 0.50) |
| Block Time Mean [ms] | 510.0 | 421.7 | -17.31% ✅ (+/-3.35/floor 0.40) |
| Block Time P50 [ms] | 433.0 | 402.0 | -7.16% ✅ (+/-0.85/floor 0.70) |
| Block Time P90 [ms] | 610.0 | 600.0 | -1.64% ⚪ (+/-3.93/floor 0.70) |
| Block Time P99 [ms] | 2941.0 | 769.0 | -73.85% ✅ (+/-45.51/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3349.0 | 1972.9 | -41.09% ❌ (+/-1.32/floor 0.95) |
| P50 [ms] | 234.5 | 256.3 | +9.30% ❌ (+/-1.77/floor 0.45) |
| P90 [ms] | 269.9 | 301.5 | +11.71% ❌ (+/-3.35/floor 0.90) |
| P99 [ms] | 319.7 | 323.8 | +1.28% ⚪ (+/-2.88/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 21.0 | 5.6 | -73.33% |
| Finish P90 [ms] | 50.2 | 11.3 | -77.49% |
| Finish P99 [ms] | 102.9 | 39.0 | -62.10% |
| Pool Fetch P50 [ms] | 7.0 | 10.6 | +51.43% |
| Pool Fetch P90 [ms] | 16.5 | 18.5 | +12.12% |
| Pool Fetch P99 [ms] | 32.6 | 47.0 | +44.17% |
| Invalid Tx Skips | 9390 | 0 | -100.00% |
| Stop Reason — Build Budget | 550 | 642 | +16.73% |
| Serialized Block Size P50 [KiB] | 2414.3 | 1569.9 | -34.98% |
| Serialized Block Size P90 [KiB] | 2905.1 | 1942.4 | -33.14% |
| Serialized Block Size P99 [KiB] | 3212.8 | 2191.5 | -31.79% |
| Serialized Block Size / Tx P50 [B/tx] | 279.6 | 279.8 | +0.07% |
| Serialized Block Size / Tx P90 [B/tx] | 280.4 | 280.7 | +0.11% |
| Serialized Block Size / Tx P99 [B/tx] | 281.4 | 281.4 | +0.00% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3894.7 | 2693.3 | -30.85% ❌ (+/-1.34/floor 0.65) |
| P50 [ms] | 204.0 | 191.5 | -6.13% ✅ (+/-3.95/floor 1.55) |
| P90 [ms] | 288.2 | 336.1 | +16.62% ❌ (+/-4.42/floor 1.55) |
| P99 [ms] | 428.3 | 452.1 | +5.56% ⚪ (+/-7.27/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 30 |
| Feature | 36 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| executor could not verify the block; abstaining | 0 | 2 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 0 | 2 |
| [failed delivering block &#96;0x01efbc5e0e3b115f9626b77a2920ea3f8c09638f467a58b0192013bc713e9d8d&#96; for verification (0, 272), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |
| [failed delivering block &#96;0xa6e1c857679af442273be9338f500b5284f2922ef94fcb71f9eb254a48ebbf53&#96; for verification (0, 414), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |

</details>
