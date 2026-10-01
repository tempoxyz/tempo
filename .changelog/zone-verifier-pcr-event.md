---
tempo-contracts: minor
tempo-chainspec: patch
---

The native Zone verifier now emits `BatchVerified` with the approved PCR0, PCR1 and PCR2 measurements when it accepts a Nitro attestation. `IZoneVerifier.verify` is no longer `view`, and the T13 `ZonePortal` runtime now uses `CALL` to invoke it.
