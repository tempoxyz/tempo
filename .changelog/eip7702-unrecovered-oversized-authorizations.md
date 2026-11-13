---
tempo-evm: patch
tempo-hardfork: minor
---

A standard EIP-7702 transaction whose gas limit cannot pay for its authorization list keeps the authorizations unrecovered, so execution rejects it without recovering any signature. `gas_params::EIP7702_PER_EMPTY_ACCOUNT_COST_T1` is now public.
