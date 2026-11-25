---
tempo-hardfork: minor
---

Added separate payment-lane gas pricing for state loading: from T15, payment-lane transactions pay discounted cold storage slot and cold account surcharges (`tempo_hardfork::gas_params::payment_lane_gas_params`). Tempo transaction handlers select and restore the gas parameters, so block building, block execution, transaction pool validation, RPC calls, gas estimation, simulation and tracing price payment transactions the same way.
