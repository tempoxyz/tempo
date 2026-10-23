---
tempo-evm: patch
---

Fixed parallel payload building committing a transaction whose fee payer can no longer afford its max fee. Fee resolution now records the max-fee balance check, so replay rejects the transaction and the builder executes it normally.
