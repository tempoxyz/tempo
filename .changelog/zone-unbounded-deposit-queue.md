---
tempo-contracts: minor
---

Updated the T15 `ZonePortal` runtime and bindings for the TIP-1171 unbounded deposit queue. Replaced `MAX_UNPROCESSED_DEPOSITS` with `DEPOSITS_PER_BUCKET`, added the checkpoint and congestion-price getters and the `FeeTooHigh` error, bound the `maxFee` overloads of `deposit` and `depositEncrypted` (calls are now suffixed: `deposit_0`/`deposit_1`, `depositEncrypted_0`/`depositEncrypted_1`), and added an optional `max_fee` to `SwapAndDepositRouterCallback` that makes the router call the `maxFee` overload.
