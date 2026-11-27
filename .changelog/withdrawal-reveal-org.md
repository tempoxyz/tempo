---
tempo-contracts: minor
---

Added a `requestWithdrawal(..., bytes revealTo, bool revealOrg)` overload and the `OrgRevealRequiresCallback` error to the zone `IZoneOutbox`. A withdrawal commits its sender's org only through this overload with `revealOrg` set, which requires a callback; the existing `requestWithdrawal` always carries `senderOrg = 0`. Because the function is now overloaded, the generated Rust types are `requestWithdrawal_0Call` (the existing signature) and `requestWithdrawal_1Call`.
