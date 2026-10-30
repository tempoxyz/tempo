---
tempo-alloy: patch
---

Fixed `eth_estimateGas` and `eth_fillTransaction` under-estimating gas for WebAuthn senders: the mock signature now prices its authenticator data as nonzero bytes.
