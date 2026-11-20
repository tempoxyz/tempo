---
tempo-contracts: minor
---

Updated the T15 `ZonePortal` runtime and bindings for the TIP-1171 unbounded deposit queue. Replaced `MAX_UNPROCESSED_DEPOSITS` with `DEPOSITS_PER_BUCKET` and `MAX_DEPOSIT_WEIGHT_PER_BLOCK`, added the checkpoint, weight and congestion-price getters and the `FeeTooHigh` error, bound the `maxFee` overloads of `deposit` and `depositEncrypted` (calls are now suffixed: `deposit_0`/`deposit_1`, `depositEncrypted_0`/`depositEncrypted_1`), and added `max_fee` to `SwapAndDepositRouterCallback`.
