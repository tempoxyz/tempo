---
tempo-contracts: minor
---

TIP-1094 `IZoneAddressRegistry.registerMaster` takes an optional `creator` that may also derive the master ID's addresses, and `MasterRegistered` now indexes `creator` and carries the `requestHash`.
