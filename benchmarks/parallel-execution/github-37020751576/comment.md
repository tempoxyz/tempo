## Benchmark Results

| Metric | [`4caada90d070419af2e72900914849867f4bb5e8`](https://github.com/tempoxyz/tempo/commit/4caada90d070419af2e72900914849867f4bb5e8) | [`844f7bb21ba07005747fefb15d6d023fd8d7135f`](https://github.com/tempoxyz/tempo/commit/844f7bb21ba07005747fefb15d6d023fd8d7135f) | Change |
|--------|------|--------|--------|
| newPayload P50 | 0.46ms | 0.46ms | +0.88% ❌ (±0.66%) |
| newPayload P90 | 1.04ms | 1.04ms | -0.10% ⚪ (±2.12%) |
| newPayload P99 | 2.17ms | 2.22ms | +2.02% ⚪ (±3.79%) |
| newPayload Mgas/s | 24.62 | 24.52 | -0.44% ⚪ (±2.14%) |
| Wall Clock | 6.03s | 6.07s | +0.64% ❌ (±0.48%) |
| Persist Wait | 0.02ms | 0.02ms | -0.59% ⚪ (±1.88%) |


<details>
<summary>Wait Time Breakdown</summary>

### Persistence Wait

| Metric | [`4caada90d070419af2e72900914849867f4bb5e8`](https://github.com/tempoxyz/tempo/commit/4caada90d070419af2e72900914849867f4bb5e8) | [`844f7bb21ba07005747fefb15d6d023fd8d7135f`](https://github.com/tempoxyz/tempo/commit/844f7bb21ba07005747fefb15d6d023fd8d7135f) |
|--------|------|--------|
| Mean | 0.02ms | 0.02ms |
| P50 | 0.02ms | 0.02ms |
| P95 | 0.04ms | 0.04ms |

### Trie Cache Update Wait

| Metric | [`4caada90d070419af2e72900914849867f4bb5e8`](https://github.com/tempoxyz/tempo/commit/4caada90d070419af2e72900914849867f4bb5e8) | [`844f7bb21ba07005747fefb15d6d023fd8d7135f`](https://github.com/tempoxyz/tempo/commit/844f7bb21ba07005747fefb15d6d023fd8d7135f) |
|--------|------|--------|
| Mean | 0.00ms | 0.00ms |
| P50 | 0.00ms | 0.00ms |
| P95 | 0.00ms | 0.00ms |

### Execution Cache Update Wait

| Metric | [`4caada90d070419af2e72900914849867f4bb5e8`](https://github.com/tempoxyz/tempo/commit/4caada90d070419af2e72900914849867f4bb5e8) | [`844f7bb21ba07005747fefb15d6d023fd8d7135f`](https://github.com/tempoxyz/tempo/commit/844f7bb21ba07005747fefb15d6d023fd8d7135f) |
|--------|------|--------|
| Mean | 0.00ms | 0.00ms |
| P50 | 0.00ms | 0.00ms |
| P95 | 0.00ms | 0.00ms |

</details>
## Observability

### Warn/Error Logs

| Run type | Total lines |
|----------|------------:|
| Baseline | 2 |
| Feature | 2 |

<details><summary>Counts by message</summary>

| Message | Baseline | Feature |
|---------|---------:|--------:|
| Error updating fork choice: Invalid fork choice update ForkchoiceState { head_block_hash: 0x36aee690f4e045c3ff3c3989daaab202ae13b8265847760c3b3b4a68bba0f0bd, safe_block_hash: 0x36aee690f4e045c3ff3c3989daaab202ae13b8265847760c3b3b4a68bba0f0bd, finalized_block_hash: 0x36aee690f4e045c3ff3c3989daaab202ae13b8265847760c3b3b4a68bba0f0bd }: ForkchoiceUpdated { payload_status: PayloadStatus { status: Syncing, latest_valid_hash: None }, payload_id: None } | 2 | 2 |

</details>
