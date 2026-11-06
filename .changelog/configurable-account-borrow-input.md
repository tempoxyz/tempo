---
tempo-evm: patch
tempo-precompiles: patch
---

The configurable account instruction and the signature verifier borrow their inputs instead of copying them. Keychain verification recovers the inner signature without re-encoding and reparsing it.
