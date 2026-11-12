---
tempo-transaction-pool: patch
---

A sender at the 2D pool's per-authority limit can add the transaction at the on-chain nonce of a lane whose transactions wait behind a nonce gap. The lane's highest nonce is evicted for it, which makes the rest executable.
