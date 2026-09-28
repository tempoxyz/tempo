# ⚪ Feature Bench: No Difference

**Refs:** 84dd0be10d38a0d3e2670c7371a16f028a8bcaf0 vs bytecode-off-bounded-cache
**Criteria:** Feature-only run; baseline columns are intentionally empty.

## Configuration
- Bloat: 100000 MiB
- Token count: 1
- Preset: history_code_sized
- Target TPS: 1000
- Duration: 1200s
- Run pairs: 1
- Run side: feature
- Baseline blocks: 0
- Feature blocks: 1670

## Tempo Metrics

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| TPS Mean | 0 | 3 | +0.00% ⚪ |
| Gas Throughput [Mgas/s] | 0.0 | 17.4 | +0.00% ⚪ |
| Block Time Mean [ms] | 0.0 | 365.1 | +0.00% ⚪ |
| Block Time P50 [ms] | 0.0 | 365.0 | +0.00% ⚪ |
| Block Time P90 [ms] | 0.0 | 372.0 | +0.00% ⚪ |
| Block Time P99 [ms] | 0.0 | 382.0 | +0.00% ⚪ |

## Builder

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 0.0 | 17.3 | +0.00% ⚪ |
| P50 [ms] | 0.0 | 361.3 | +0.00% ⚪ |
| P90 [ms] | 0.0 | 367.2 | +0.00% ⚪ |
| P99 [ms] | 0.0 | 372.2 | +0.00% ⚪ |

<details><summary>Builder details</summary>

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Finish P50 [ms] | 0.0 | 0.1 | n/a |
| Finish P90 [ms] | 0.0 | 0.1 | n/a |
| Finish P99 [ms] | 0.0 | 0.1 | n/a |
| Pool Fetch P50 [ms] | 0.0 | 1.6 | n/a |
| Pool Fetch P90 [ms] | 0.0 | 1.7 | n/a |
| Pool Fetch P99 [ms] | 0.0 | 1.8 | n/a |
| Stop Reason — Build Budget | 0 | 1629 | n/a |
| Serialized Block Size P50 [KiB] | 0.0 | 2.3 | n/a |
| Serialized Block Size P90 [KiB] | 0.0 | 2.3 | n/a |
| Serialized Block Size P99 [KiB] | 0.0 | 2.3 | n/a |
| Serialized Block Size / Tx P50 [B/tx] | 0.0 | 2365.0 | n/a |
| Serialized Block Size / Tx P90 [B/tx] | 0.0 | 2365.0 | n/a |
| Serialized Block Size / Tx P99 [B/tx] | 0.0 | 2365.0 | n/a |
| Fill Idle P50 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P90 [ms] | 0.0 | 0.0 | 0.00% |
| Fill Idle P99 [ms] | 0.0 | 0.0 | 0.00% |

</details>

## Validator

| Metric | Baseline | Feature | Delta |
|--------|----------|---------|-------|
| Gas Throughput [Mgas/s] | 0.0 | 0.0 | +0.00% ⚪ |
| P50 [ms] | 0.0 | 0.0 | +0.00% ⚪ |
| P90 [ms] | 0.0 | 0.0 | +0.00% ⚪ |
| P99 [ms] | 0.0 | 0.0 | +0.00% ⚪ |


## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | — |
| Feature | 41 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| A database read transaction has been open for too long | — | 33 |
| connecting to upstream node failed, attempting again | — | 2 |
| event stream terminated | — | 2 |
| failed to read dealer log from block extraData header field | — | 2 |
| Beacon client online, but no consensus updates received for a while. This may be because of a reth error, or an error in the beacon client! Please investigate reth and beacon client logs! | — | 1 |
| requested buffer capacity is too low, increasing it to floor | — | 1 |

</details>
