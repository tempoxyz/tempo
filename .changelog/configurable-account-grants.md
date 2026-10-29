---
tempo-primitives: minor
tempo-evm: minor
tempo-alloy: patch
---

From T14 a configurable account can sign key authorizations. `SignedKeyAuthorization.signature` is now an `AccountSignature`: a primitive root signature or the account's owner quorum, with the same wire encoding. `SignedKeyAuthorization::recover_account` returns the named configurable account, and `recover_signer` fails for one. Sender recovery verifies the grant's owner quorum, and the handler checks the grant account's code and configuration commitment, registers it on first use and accepts an admin delegate's quorum for the grants it signs. The Tempo Accounts store persists configurable-signed key authorizations, and zones reject them.
