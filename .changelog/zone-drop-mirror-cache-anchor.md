---
zone-evm: patch
zone-precompiles: patch
---

Removed `L1State::select_mirror_cache_anchor` and `L1State::note_mirrored_read`. The Zone EVM no longer drops mirrored TIP-403 and TIP-20 pause entries from its accepted cache between transactions, since every Zone EVM executes a single block.
