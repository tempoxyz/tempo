---
tempo-transaction-pool: patch
---

`StateAwareBestTransactions` skips, for the rest of the block, pending transactions that name as an authority an account whose configuration commitment an earlier transaction in the block changed, unless their signatures for that account match the new commitment, instead of handing them to the builder to execute. Pool maintenance revalidates skipped transactions once the block commits.
