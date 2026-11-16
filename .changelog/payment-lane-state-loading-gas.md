---
tempo-evm: minor
tempo-hardfork: minor
---

Added separate payment-lane gas pricing for state loading: from T15, payment-lane transactions pay discounted cold storage slot and cold account surcharges (`tempo_hardfork::gas_params::payment_lane_version`).
