---
tempo-evm: minor
tempo-hardfork: minor
tempo-transaction-pool: patch
---

Added separate payment-lane gas pricing for state loading: from T15, payment-lane transactions pay discounted cold storage slot and cold account surcharges (`tempo_hardfork::gas_params::payment_lane_version`). `TempoEvm` selects the schedule per transaction, so block building, block execution, transaction pool validation, RPC calls, gas estimation, simulation and tracing price payment transactions the same way.
