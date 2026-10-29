---
tempo-primitives: minor
tempo-evm: minor
tempo-precompiles: minor
tempo-alloy: patch
---

From T14 a configurable account can act as an access key. A V2 `KeychainSignature` now carries an `AccountSignature`: a primitive approval or the delegate's owner quorum. `SignatureType::ConfigurableAccount` (3) names such a delegate in a key authorization, which is rejected before T14. The handler checks the delegate's account, code and configuration commitment, registers it on first use and charges its account access; a primitive key whose ID has since migrated accepts its owner quorum. Gas estimation rejects a configurable key type without a configuration witness, the signature verifier rejects configurable keychain signatures, and zones reject configurable delegates.
