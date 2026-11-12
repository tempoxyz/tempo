---
tempo-transaction-pool: patch
---

`StateAwareBestTransactions` skips, for the rest of the block, pending transactions that name as an authority an account whose configuration commitment an earlier transaction in the block changed, instead of handing them to the builder to execute. Pool maintenance revalidates them once the block commits.
