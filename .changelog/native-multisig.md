---
tempo-alloy: minor
tempo-contracts: minor
tempo-precompiles: minor
tempo-primitives: minor
tempo-evm: minor
tempo-revm: minor
tempo-node: minor
---

Activates native multisig accounts at T11, including a new multisig precompile, signature-carried `InitMultisig` bootstrap configs, and `MultisigSignature` validation across the EVM, transaction pool, and RPC layers. Native 1-of-1 secp256k1 multisigs pay an 8,400 gas authorization surcharge over equivalent primitive secp256k1 transactions.
