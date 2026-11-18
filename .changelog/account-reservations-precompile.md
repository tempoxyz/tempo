---
tempo-contracts: minor
---

Added the TIP-1153 reservation core interface (IReservationCore) at RESERVATIONS_ADDRESS, a system precompile from T16: two-slot holds keyed by owner, placer and id and deleted on settlement, holder spend budgets, per-creditor debt with a term, pledges and role liens, all paid through one policy-checked TIP-20 path.
