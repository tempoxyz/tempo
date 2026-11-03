---
tempo-evm: minor
tempo-precompiles: minor
---

A configurable account's first registration now emits `ConfigurableAccountConfigUpdated` with version zero. Like `KeyAuthorized`, it is emitted before the batch checkpoint, so it stays in the receipt when the transaction's calls revert, and its log gas is charged in intrinsic gas.
