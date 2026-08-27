---
tempo-alloy: minor
tempo-contracts: minor
tempo-precompiles: minor
tempo-primitives: minor
tempo-evm: minor
tempo-revm: minor
tempo-node: minor
---

Activates counterfactual native multisig accounts at T12, including a new multisig precompile, signature-carried configuration witnesses, and `MultisigSignature` validation across the EVM, transaction pool, and RPC layers. Initial account identity uses a canonical CREATE2 recovery address, while owner updates persist one configuration commitment slot.
