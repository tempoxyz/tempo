---
tempo-primitives: patch
---

Built signed transactions with `SignableTransaction::into_signed` instead of `Signed::new_unhashed` (same lazy hashing).
