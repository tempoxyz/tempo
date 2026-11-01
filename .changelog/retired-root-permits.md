---
tempo-contracts: minor
tempo-precompiles: minor
---

Added the `RootKeyRetired(address account)` error to `ITIP20` and `ITIP20ChannelReserve`. From T14, TIP-20 `permit` reverts with it when the owner has a config commitment, because a committed account no longer acts through its own root key. Channel `open` and nonzero `topUp` revert with it when the voucher signer has one; vouchers on already-funded channels stay redeemable after the signer migrates.
