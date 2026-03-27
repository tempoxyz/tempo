---
tempo-alloy: minor
---

Added `AccessKeyAccount`, `TempoWallet`, `AccessKeyFiller`, and `TempoProviderBuilderExt::with_access_key` for ergonomic access key transaction support via the standard `send_transaction` flow.

Sealed `TempoProviderBuilderExt` to allow adding new methods without breaking semver.
