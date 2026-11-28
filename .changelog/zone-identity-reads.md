---
tempo-contracts: minor
---

Added `setReader`, `canRead` and `ReaderUpdated` to the `IZoneIdentity` bindings, which let a ZoneIdentity org's admin and the readers it names read its members' account-scoped state, and replaced `MemberUpdated` with `MemberAdded` and `MemberRemoved`.
