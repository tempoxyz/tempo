---
tempo-precompiles: minor
tempo-contracts: patch
tempo-evm: patch
---

From T15, calls to a `ZONE_PORTAL_PREFIX` address run a native ZonePortal precompile on the portal's existing storage instead of the ERC-1167 proxy and Solidity runtime, as revised TIP-1091 specifies. `PrecompileStorageProvider` and `StorageCtx` gain `call` for nested EVM calls from a precompile, which run in the transaction's environment; main already pins evm2 at #866. `TempoPrecompileError` gains `ZonePortalError` and `RawRevert`, `ZonePortalStorage::initialize` is renamed `initialize_from_factory`, and the `ZonePortal` `initialize` and `deliverWithdrawal` bindings now name their parameters as `ZonePortal.sol` does.
