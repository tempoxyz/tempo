---
tempo-primitives: minor
tempo-hardfork: minor
---

Added `TempoTxEnvelope::is_payment_v3_without_access_list` so mutable execution environments can cache payment eligibility while checking their current access list separately.

Added draft T15 lane-dependent cold storage and account prices on `TempoHardfork`.
