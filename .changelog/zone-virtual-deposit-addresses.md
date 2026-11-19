---
tempo-contracts: minor
---

Added TIP-1094 zone deposit addresses to the T15 `ZonePortal` runtime and bindings: `depositVirtual`, `retireAddressVersionsBelow` and `minimumAddressVersion`, the `VirtualDepositMade` and `AddressVersionsRetired` events, and the `InvalidVirtualDeposit`, `AddressVersionRetired` and `InvalidVersionRetirement` errors. Added the zone address registry (`IZoneAddressRegistry`, `MasterRegistered`), the inbox `initializeVirtualAddressKey` call with the `VirtualDepositProcessed`, `VirtualDepositFailed` and `VirtualAddressKeyInitialized` events, and the outbox `InvalidWithdrawalRecipient` error.
