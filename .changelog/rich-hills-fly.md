---
tempo-chainspec: minor
tempo-contracts: minor
tempo-evm: minor
tempo-node: minor
tempo-revm: minor
---

Added TIP-1059 discounted gas pricing for pure payment transfers that fit within the SSTORE_SET gas cap. Introduced `is_discounted_payment_call` helper, `TEMPO_T6_DISCOUNTED_PAYMENT_GAS_PRICE` constant, and applied the discounted effective gas price in both EVM execution and RPC receipt conversion when T6 is active.
