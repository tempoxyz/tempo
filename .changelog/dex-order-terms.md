---
tempo-precompiles: minor
---

Added `stablecoin_dex::validate_order_terms`, the storage-free amount, tick and flip tick checks `place` and `placeFlip` run, so callers can predict which orders the DEX accepts at a hardfork. `place` and `placeFlip` now call it, with the same errors in the same order.
