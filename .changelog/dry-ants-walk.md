---
tempo-contracts: patch
tempo-primitives: patch
---

Moved `SYSTEM_PRECOMPILES` from `tempo-precompiles` to `tempo-contracts` and replaced the `is_precompile_address` function with an `is_precompile` method on the `TempoAddressExt` trait in `tempo-primitives`.
