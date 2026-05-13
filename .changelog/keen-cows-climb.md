---
tempo-evm: minor
tempo-primitives: minor
tempo-contracts: patch
---

Enshrined the stricter TIP-1045 payment classifier (`is_payment_v2`) at the T5 hardfork for consensus-level payment lane validation. Relaxed the v2 classifier to allow bounded `key_authorization` (RLP length ≤ 1024 bytes).
