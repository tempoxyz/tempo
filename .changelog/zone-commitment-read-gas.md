---
tempo-hardfork: minor
tempo-primitives: minor
---

Added `L1_COMMITMENT_READ_GAS` (10,000, in `constants::gas`) and `gas_params::apply_zone`, which adds it to a zone's cold account access and access-list address costs from T14 and stops warming the beneficiary, so every load that reads an account's Tempo commitment pays for it (TIP-1154). `TempoEvmKind` moved to its own module and gained `TempoEvmKind::is_l1`.
