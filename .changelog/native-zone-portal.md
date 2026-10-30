---
tempo-precompiles: minor
tempo-contracts: patch
---

From T15, calls to a `ZONE_PORTAL_PREFIX` address run a native ZonePortal precompile on the portal's existing storage instead of the ERC-1167 proxy and Solidity runtime, as TIP-1091 allows once precompiles can make external calls. `PrecompileStorageProvider` and `StorageCtx` gain `call` for nested EVM calls from a precompile, `TempoPrecompileError` gains `ZonePortalError` and `RawRevert`, and `ZonePortalStorage::initialize` is renamed `initialize_from_factory`. The `ZonePortal` bindings add `MAX_SEQUENCERS`, `PAUSE_DURATION` and `ABDICATION_DELAY`.
