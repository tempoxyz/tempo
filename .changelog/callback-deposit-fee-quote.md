---
tempo-contracts: patch
tempo-chainspec: patch
---

The T15 `ZonePortal` runtime's `calculateDepositFee()` returns the operational fee alone inside a withdrawal callback whose premium-exempt deposit is still unused, matching what that deposit is charged. The T15 runtime and the dev genesis that embeds it are regenerated.
