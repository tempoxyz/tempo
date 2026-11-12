---
tempo-transaction-pool: patch
---

A sender at the 2D pool's per-authority limit can add the transaction at the on-chain nonce of a lane that holds transactions. The lane's highest nonce is evicted for it, so a lane waiting behind a nonce gap can be made executable.
