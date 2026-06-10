---
tempo-alloy: minor
tempo-contracts: minor
tempo-precompiles: minor
tempo-primitives: minor
tempo-evm: minor
tempo-revm: minor
tempo-transaction-pool: minor
tempo-payload-builder: minor
tempo-payload-types: minor
tempo-consensus: minor
tempo-node: minor
tempo-e2e: minor
---

Added native multisig account support, including a new multisig precompile, signature-carried `InitMultisig` bootstrap configs, and `MultisigSignature` validation across the EVM, transaction pool, and RPC layers. Native 1-of-1 secp256k1 multisigs now pay a 2,100 gas authorization surcharge over equivalent primitive secp256k1 transactions.
