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

Added native multisig account support, including a new multisig precompile, an `InitMultisig` transaction field for bootstrapping derived multisig accounts, and `MultisigSignature` validation across the EVM, transaction pool, and RPC layers.
