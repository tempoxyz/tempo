---
tempo-contracts: minor
tempo-precompiles: minor
---

Emit `ProofVerified(zoneId, pcr0, pcr1, pcr2)` from the TIP-1098 zone verifier with the PCR0/1/2 measurements of each accepted Nitro proof. `verify` is no longer `view`, and the T13 `ZonePortal` runtime now calls it with `CALL` so the event is recorded.
