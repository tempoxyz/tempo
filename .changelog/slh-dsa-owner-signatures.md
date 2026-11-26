---
tempo-primitives: minor
tempo-chainspec: minor
tempo-alloy: minor
---

Added SLH-DSA-SHA2-128s (FIPS 205) owner approvals for configurable accounts: primitive signature type `0x06` (`PrimitiveSignature::SlhDsa`), accepted only inside configurable account signatures, and the devnet-only genesis field `slhDsaTime` that activates it. `configurableAccountSimulation` approvals take `keyType: "slhDsa"` for gas estimation.
