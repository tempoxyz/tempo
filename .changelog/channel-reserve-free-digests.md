---
tempo-contracts: minor
tempo-precompiles: minor
---

Added `ChannelDescriptor::id` and `id_preimage` in tempo-contracts and `tip20_channel_reserve::voucher_digest` and `voucher_digest_with` in tempo-precompiles, which compute a channel's id and a voucher's EIP-712 digest outside a storage context, matching the precompile.
