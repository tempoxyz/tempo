---
tempo-contracts: major
---

Added the `WithdrawalAlreadyAttempted` error. From T13, Zone transactions allow one non-static withdrawal attempt, including native batches, even when the request or an enclosing frame reverts. Earlier forks retain their historical withdrawal behavior.
