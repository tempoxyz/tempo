---
tempo-contracts: minor
tempo-chainspec: patch
---

Added `IZoneIdentity` bindings and `ZONE_IDENTITY_ADDRESS` for the T15 ZoneIdentity predeploy, and `setIdentityConfig` and `IdentityConfigUpdated` to `IZonePortal`. The T15 `ZonePortal` runtime, and the dev genesis that embeds it, store the ZoneIdentity registrar and enforcement flag.
