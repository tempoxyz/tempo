---
tempo-precompiles: minor
tempo-evm: patch
---

From T14 a key authorization granted by an account with a configuration commitment is rejected with `InvalidKeyId` unless the account's code is the protocol marker. `PrecompileStorageProvider` gains the required `with_warm_caller_info`, which reads the already-warm caller's account info without charging gas and fails for a cold account.
