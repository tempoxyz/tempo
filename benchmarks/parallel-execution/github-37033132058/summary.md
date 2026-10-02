# ⚠️ Bench Comparison: Mixed Results

**Refs:** 61c979a524f9af5de9c540a0088c429a44741e4c vs c83b280859983fd3cc02f025d2e9817c662f236a
**Criteria:** 95% run-bootstrap CI must clear floor; cells show delta (+/-CI/floor).

## Configuration
- Derek command: `derek bench mode=e2e preset=default duration=90 bloat=100 token-count=4 tps=25000 accounts=1000 max-concurrent-requests=100 baseline=61c979a524f9af5de9c540a0088c429a44741e4c feature=c83b280859983fd3cc02f025d2e9817c662f236a baseline-hardfork=T14 feature-hardfork=T14 gas-limit=1000000000000 run-pairs=3 run-side=comparison otlp=true metrics=false no-cache=false force-bloat=false general-gas-limit=1500000000 txgen-ref=3f389beb990872bd3b9937d92a923e534f1d3515 feature-args="--execution.threads 8 --execution.batch-size 128"`
- Bloat: 100000 MiB
- Token count: 4
- Preset: default
- Target TPS: 25000
- Duration: 90s
- Run pairs: 3
- Baseline blocks: 601
- Feature blocks: 627

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 17502 | 14634 | -16.39% ❌ (+/-1.10/floor 0.55) |
| Gas Throughput [Mgas/s] | 1618.9 | 1353.7 | -16.38% ❌ (+/-1.15/floor 0.50) |
| Block Time Mean [ms] | 442.2 | 427.2 | -3.39% ✅ (+/-1.36/floor 0.40) |
| Block Time P50 [ms] | 418.0 | 430.0 | +2.87% ❌ (+/-1.99/floor 0.70) |
| Block Time P90 [ms] | 555.0 | 588.0 | +5.95% ❌ (+/-2.22/floor 0.70) |
| Block Time P99 [ms] | 1672.0 | 711.0 | -57.48% ✅ (+/-19.84/floor 1.60) |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3088.8 | 2272.4 | -26.43% ❌ (+/-1.14/floor 0.95) |
| P50 [ms] | 233.1 | 249.3 | +6.95% ❌ (+/-1.94/floor 0.45) |
| P90 [ms] | 267.2 | 280.1 | +4.83% ❌ (+/-2.74/floor 0.90) |
| P99 [ms] | 364.4 | 299.4 | -17.84% ✅ (+/-15.18/floor 1.25) |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 11.4 | 5.2 | -54.39% |
| Finish P90 [ms] | 40.7 | 10.1 | -75.18% |
| Finish P99 [ms] | 138.3 | 34.8 | -74.84% |
| Pool Fetch P50 [ms] | 3.1 | 7.0 | +125.81% |
| Pool Fetch P90 [ms] | 12.4 | 12.7 | +2.42% |
| Pool Fetch P99 [ms] | 47.0 | 43.7 | -7.02% |
| Stop Reason — Build Budget | 598 | 621 | +3.85% |
| Serialized Block Size P50 [KiB] | 2160.8 | 1782.9 | -17.49% |
| Serialized Block Size P90 [KiB] | 2788.5 | 2123.7 | -23.84% |
| Serialized Block Size P99 [KiB] | 3282.1 | 2306.2 | -29.73% |
| Serialized Block Size / Tx P50 [B/tx] | 279.7 | 279.7 | +0.00% |
| Serialized Block Size / Tx P90 [B/tx] | 280.5 | 280.6 | +0.04% |
| Serialized Block Size / Tx P99 [B/tx] | 281.6 | 281.5 | -0.04% |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 16.0 | 0.0 | -100.00% |
| Fill Idle P99 [ms] | 108.0 | 0.0 | -100.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 3776.9 | 2768.2 | -26.71% ❌ (+/-1.32/floor 0.65) |
| P50 [ms] | 186.5 | 208.0 | +11.53% ❌ (+/-1.09/floor 1.55) |
| P90 [ms] | 265.1 | 319.2 | +20.41% ❌ (+/-3.46/floor 1.55) |
| P99 [ms] | 467.3 | 477.9 | +2.27% ⚪ (+/-44.70/floor 2.05) |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 42 |
| Feature | 36 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| context request for block &#96;0x589f5a3c363fedfadd7151f08c62fca9b67f920fee89209193786777befa017c&#96; with no consensus context | 12 | 12 |
| failed to read dealer log from block extraData header field | 12 | 12 |
| requested buffer capacity is too low, increasing it to floor | 6 | 6 |
| executor encountered fatal execution-layer update error; shutting down to prevent consensus-execution divergence | 4 | 2 |
| executor could not verify the block; abstaining | 2 | 2 |
| [failed delivering build parent, failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 2 | 0 |
| [executor dropped the payload channel: the build failed (the executor logs the cause) or the executor shut down, oneshot canceled] | 1 | 0 |
| [failed delivering block &#96;0x3a496e6bf66d8d77c6a1fd312c390b82d5917ce5c25c6f530f1a530a7324f039&#96; for verification (0, 244), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |
| [failed delivering block &#96;0x3d4763d4b9b55b4c328d9fb31dfb4f012fed965b6d5c91912c36b0beb50f7729&#96; for verification (0, 249), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |
| [failed delivering block &#96;0x5d6701542b3a9a8ce37babc3ce1f9d3b9e1d11cd5c8ed22dbf817692f582efe3&#96; for verification (0, 264), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |
| [failed delivering block &#96;0xda8c87103ed43fb733312e801925bcdd40e17a2dc729340dadfbdfeabd6646ad&#96; for verification (0, 265), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 0 | 1 |
| [failed delivering block &#96;0xf04b50792bd79f4152873133a3b687d4f874ee94007ba1b803d09dafd23cd7a1&#96; for verification (0, 245), failed sending new-payload request to execution layer, beacon consensus engine task stopped] | 1 | 0 |

</details>
