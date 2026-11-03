---
tempo-transaction-pool: minor
tempo-payload-builder: patch
---

`StateAwareBestTransactions` now skips transactions that an earlier transaction in the block made unexecutable: configuration commitment changes, key revocations and authorizations, spending limits, fee token pauses and policy changes, fee-token preference changes, fee AMM liquidity drains and raised protocol nonces. The payload builder runs the checks that read state through `next_with_state`. Added `BlockState` and `TempoPoolTransactionError::InvalidatedInBlock`.
