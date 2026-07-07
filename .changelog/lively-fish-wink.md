---
tempo-alloy: patch
---

Added typed `RecoveryAuthority` selector and `set_receive_policy_for_receiver` helper for building validated TIP-1028 receive-policy calls, rejecting recovery authorities that can never pass `ReceivePolicyGuard.claim()`.
