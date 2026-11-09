---
tempo-transaction-pool: minor
---

From T14 the pool admits a sender whose code is the configurable account marker, since the Tempo pipeline already checks its commitment and signature authority, and revalidates pending transactions when a block changes the configuration commitment of their sender, key authorization signer, fee payer or access key, so the transactions of a migrated root key leave the pool, including on reorg.
