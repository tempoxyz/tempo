---
tempo-contracts: minor
---

Added the TIP-1153 reservation core interface (`IReservationCore`) at `RESERVATIONS_ADDRESS`, a system precompile from T15: holds on TIP-20 balances placed by the owner or by a holder contract within an allowance the owner approves, hard expiry, captures with a per-payee tolerance, stand-in holds, charges, refunds by the payee, capped debt repaid from incoming credits, role liens, owner pledges, and pledges a holder places within its allowance (up to 400 days), which only their authority releases, reduces or seizes.
