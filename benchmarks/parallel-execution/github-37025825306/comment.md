## Benchmark Results

| Metric | [`61c979a524f9af5de9c540a0088c429a44741e4c`](https://github.com/tempoxyz/tempo/commit/61c979a524f9af5de9c540a0088c429a44741e4c) | [`2855d574f564ef6776ae6c95cd1dab0d71e58877`](https://github.com/tempoxyz/tempo/commit/2855d574f564ef6776ae6c95cd1dab0d71e58877) | Change |
|--------|------|--------|--------|
| newPayload P50 | 0.46ms | 0.45ms | -0.66% ⚪ (±0.66%) |
| newPayload P90 | 1.04ms | 1.19ms | +14.84% ❌ (±1.97%) |
| newPayload P99 | 2.14ms | 2.30ms | +7.72% ❌ (±4.17%) |
| newPayload Mgas/s | 24.77 | 21.07 | -14.93% ❌ (±4.39%) |
| Wall Clock | 6.00s | 6.30s | +5.05% ❌ (±0.52%) |
| Persist Wait | 0.02ms | 0.02ms | +1.65% ⚪ (±1.91%) |


<details>
<summary>Wait Time Breakdown</summary>

### Persistence Wait

| Metric | [`61c979a524f9af5de9c540a0088c429a44741e4c`](https://github.com/tempoxyz/tempo/commit/61c979a524f9af5de9c540a0088c429a44741e4c) | [`2855d574f564ef6776ae6c95cd1dab0d71e58877`](https://github.com/tempoxyz/tempo/commit/2855d574f564ef6776ae6c95cd1dab0d71e58877) |
|--------|------|--------|
| Mean | 0.02ms | 0.02ms |
| P50 | 0.02ms | 0.02ms |
| P95 | 0.04ms | 0.04ms |

### Trie Cache Update Wait

| Metric | [`61c979a524f9af5de9c540a0088c429a44741e4c`](https://github.com/tempoxyz/tempo/commit/61c979a524f9af5de9c540a0088c429a44741e4c) | [`2855d574f564ef6776ae6c95cd1dab0d71e58877`](https://github.com/tempoxyz/tempo/commit/2855d574f564ef6776ae6c95cd1dab0d71e58877) |
|--------|------|--------|
| Mean | 0.00ms | 0.00ms |
| P50 | 0.00ms | 0.00ms |
| P95 | 0.00ms | 0.00ms |

### Execution Cache Update Wait

| Metric | [`61c979a524f9af5de9c540a0088c429a44741e4c`](https://github.com/tempoxyz/tempo/commit/61c979a524f9af5de9c540a0088c429a44741e4c) | [`2855d574f564ef6776ae6c95cd1dab0d71e58877`](https://github.com/tempoxyz/tempo/commit/2855d574f564ef6776ae6c95cd1dab0d71e58877) |
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
