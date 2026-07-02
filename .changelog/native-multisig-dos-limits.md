---
tempo-alloy: patch
tempo-precompiles: patch
tempo-primitives: patch
tempo-revm: patch
---

Caps native multisig thresholds and submitted owner approvals at 8 while keeping configs at up to 255 owners. Registered authorization now reads the account threshold plus submitted owner weights instead of scanning the full owner list, charges owner-weight lookup gas, rejects trailing approvals after quorum, and limits nesting to one nested multisig level.
