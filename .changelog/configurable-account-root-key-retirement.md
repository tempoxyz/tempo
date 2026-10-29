---
tempo-evm: minor
tempo-node: patch
tempo-alloy: patch
---

From T14 a primitive key of an account with a configuration commitment can no longer act as the transaction sender, key authorization signer, fee payer or access key: the transaction is rejected with `TempoInvalidTransaction::RootKeyRetired` (role in `RootKeyRole`). Each distinct non-sender role account costs one account access, so a sponsored transaction pays one more cold access; `eth_estimateGas` and `eth_fillTransaction` add it for a request carrying the fee payer marker, `TempoGasFiller` adds it when it fills such a request, and `account_access_gas` is exported.
