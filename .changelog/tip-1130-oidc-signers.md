---
tempo-primitives: minor
tempo-contracts: minor
tempo-alloy: patch
---

Implemented TIP-1131 ZK signatures (type `0x06`) and the TIP-1132 Key Publisher precompile behind T14. Scheme `0x01` (TIP-1133) has no verifying key until its trusted setup completes, so ZK signatures are still rejected on every network.
