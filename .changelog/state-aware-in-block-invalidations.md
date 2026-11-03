---
tempo-transaction-pool: minor
tempo-payload-builder: patch
---

Added `Invalidations`, which pool maintenance and `StateAwareBestTransactions` share to decide which pending transactions a block, or the transactions executed so far, made invalid or need revalidation. The payload builder now skips such transactions within the block. `TempoTransactionPool::evict_invalidated_transactions` takes `Invalidations` and returns `InvalidatedTransactions`. `TempoPoolUpdates` replaces `blacklist_additions` and `whitelist_removals` with `policy_restrictions`, which a later lifting event cancels, and drops `fee_balance_changes`: balances now come from the state diff.
