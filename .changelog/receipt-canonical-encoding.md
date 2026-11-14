---
tempo-precompiles: patch
zone-precompiles: patch
---

From T15, `ReceivePolicyGuard` `balanceOf`, `claim` and `burnBlockedReceipt` accept only the canonical ABI encoding of a receipt and revert with `InvalidReceipt` on trailing bytes or nonzero padding. Pre-T15 behavior is unchanged. Zone `balanceOf` admission applies the same decoding, so non-canonical receipts get upstream's `InvalidReceipt`.
