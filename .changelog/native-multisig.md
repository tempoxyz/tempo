---
tempo-alloy: minor
tempo-primitives: minor
tempo-evm: minor
tempo-revm: minor
tempo-node: minor
---

Activates counterfactual native multisig accounts at T12, including signature-carried configuration witnesses and updates, and `MultisigSignature` validation across the EVM, transaction pool, and RPC layers. Initial account identity uses a dedicated cross-chain CREATE2 recovery factory that is reserved on Tempo, while owner updates persist one configuration hash in the account leaf.
