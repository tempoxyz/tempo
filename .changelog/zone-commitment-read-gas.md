---
tempo-hardfork: minor
tempo-primitives: minor
---

Added `L1_COMMITMENT_READ_GAS` (10,000, in `constants::gas`), the gas a zone charges for the first read of an account's Tempo configuration commitment in a transaction (TIP-1154). `TempoEvmKind::Zone` now holds the accounts whose commitment the transaction already read, so `TempoEvmKind` is no longer `Copy`. Added `TempoEvmKind::zone` and `TempoEvmKind::is_l1`.
