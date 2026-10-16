---
tempo-primitives: major
tempo-alloy: patch
---

Remove the obsolete `0x5b` subblock nonce-key reservation. Ordinary 2D nonce keys can use this prefix, and `Random2DNonceFiller` no longer excludes it. Remove `TEMPO_SUBBLOCK_NONCE_KEY_PREFIX`, `has_sub_block_nonce_key_prefix`, and the corresponding transaction/envelope methods from `tempo-primitives`; legacy subblock metadata decoding remains available for historical replay.
