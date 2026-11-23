---
tempo-contracts: minor
---

Added `requestWithdrawalRevealingOrg` and the `OrgRevealRequiresCallback` error to the zone `IZoneOutbox`. A withdrawal commits its sender's org only through this call, which requires a callback; `requestWithdrawal` now always carries `senderOrg = 0`.
