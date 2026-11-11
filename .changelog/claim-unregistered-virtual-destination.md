---
tempo-precompiles: patch
---

From T14 `ReceivePolicyGuard.claim` reverts with `InvalidClaimAddress` when `to` is a virtual address whose master is not registered, as TIP-1028 specifies, instead of `VirtualAddressUnregistered`.
