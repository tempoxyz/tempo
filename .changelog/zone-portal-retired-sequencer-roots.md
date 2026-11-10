---
tempo-contracts: patch
---

`T15_ZONE_PORTAL_RUNTIME` no longer counts a settlement signature from a sequencer whose root key was retired by `upgradeAccount` (its configuration commitment is nonzero), as TIP-1112 requires of protocol consumers of stateless `recover`.
