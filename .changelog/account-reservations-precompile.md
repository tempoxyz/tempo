---
tempo-contracts: minor
---

Added the TIP-1153 account reservations precompile interface (`IReservations`) and its `RESERVATIONS_ADDRESS`, a system precompile from T15: holds on TIP-20 balances, capture (including capture of a live hold by its payee, up to the held amount, and several non-final captures of one hold through `capturePart` and `captureForPart`), charge, capped debt and linked refunds.
