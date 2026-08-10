---
tempo-hardfork: minor
tempo-chainspec: minor
tempo-evm: minor
tempo-node: minor
tempo-precompiles: minor
tempo-revm: minor
---

Added the T11 hardfork activating TIP-1016 (EIP-8037 state gas): state creation gas is charged from the block-level storage reservoir instead of execution gas, and the transaction gas limit cap returns from the TIP-1000 30M cap to the EIP-7825 Osaka cap.
