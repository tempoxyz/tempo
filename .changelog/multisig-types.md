---
tempo-primitives: minor
---

Added native multisig primitives for configurable accounts: `MultisigOwner`, `MultisigConfig` and `MultisigSignature`, with their encoding, account derivation, configuration commitments and owner-quorum weight accounting. Transaction signatures do not accept them yet. Derived account addresses use a placeholder account-proxy init-code hash, `ACCOUNT_PROXY_INIT_CODE_HASH`, and will change when TIP-1110 fixes the canonical account proxy.
