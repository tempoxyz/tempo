---
tempo-contracts: minor
---

Added `senderOrg` to the zone `Withdrawal`, the `WithdrawalSenderOrg` outbox event and `callbackSenderOrg()` on `IZonePortal`, which withdrawal receivers call during `onWithdrawalReceived` to read the sender's ZoneIdentity org. Withdrawals in org 0 keep their pre-T15 queue hash; `LegacyWithdrawal` and `LegacyZonePortal` bind that encoding. The T15 `ZonePortal` runtime is regenerated.
