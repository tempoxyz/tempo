---
tempo-precompiles: patch
---

From T15 `TipFeeManager::burn` disables TIP-1060 storage credit minting before paying out pool tokens from the FeeManager, matching `rebalance_swap` and `distribute_fees`.
