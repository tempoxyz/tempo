---
tempo-contracts: minor
tempo-precompiles: minor
---

Added the `RootKeyRetired(address account)` error to `ITIP20` and `ITIP20ChannelReserve`. From T14, TIP-20 `permit` and channel voucher validation revert with it when the signing account has a config commitment, because a committed account no longer acts through its own root key.
