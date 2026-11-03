---
tempo-transaction-pool: minor
tempo-payload-builder: patch
---

Added `Invalidations`, which pool maintenance and `StateAwareBestTransactions` share to decide which pending transactions a block, or the transactions executed so far, made invalid or need revalidation. Its checks read no state: they combine what the changes wrote with fee token state validation caches on each transaction (`FeeTokenState`: sender policy IDs and quote token). The payload builder now skips such transactions within the block; `StateAwareBestTransactions::new` takes the block's validator token. `TempoTransactionPool::evict_invalidated_transactions` takes `Invalidations` and returns `InvalidatedTransactions`. `TempoPoolUpdates` replaces `blacklist_additions` and `whitelist_removals` with `policy_restrictions`, which a later lifting event cancels, and drops `fee_balance_changes`: balances come from the state diff. Removed the pre-T8 fee-manager recipient policy check.
