---
tempo: patch
---

Bind the fee AMM liquidity cache generation to the state provider used for transaction validation, so a canonical block applied mid-batch can no longer leave stale-by-one-block pool reserves cached for a newly seen pool.
