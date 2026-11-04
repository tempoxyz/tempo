---
tempo-transaction-pool: minor
tempo-payload-builder: patch
tempo-evm: patch
tempo-precompiles: patch
---

Pending transactions now carry `Preconditions`: the storage conditions their stateful checks depended on, recorded from `StorageActions` during admission validation. `Invalidations`, shared by pool maintenance and `StateAwareBestTransactions`, checks them against the slots a block (or the transactions executed so far) wrote, without reading state, and revalidates or evicts transactions whose conditions broke. The payload builder also skips transactions not executable at the block timestamp, checks the fee AMM route against the block's writes, and seeds parent-block changes that maintenance has not applied yet from `RecentBlocks`. Fee context resolution records a `FeeTokenBalanceCheck` against the max fee. `TempoPoolUpdates` keeps only validator token changes; `FeeTokenState` and the event-based keychain and policy subjects are removed.
