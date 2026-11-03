---
tempo-precompiles: minor
tempo-evm: patch
---

The configurable account and account keychain precompiles read the transaction origin from the EVM transaction environment through the new `PrecompileStorageProvider::tx_origin`, instead of transient slots seeded by the handler. Removed `AccountKeychain::set_tx_origin`. The read still charges a warm storage read, so gas is unchanged.
