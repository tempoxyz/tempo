---
tempo-alloy: minor
---

`KeyRestrictions` with spending limits and no explicit call scopes now scopes the key to TIP-20 `transfer`, `transferWithMemo` and `approve` on each limited token, so a limited key cannot call precompiles its limits do not meter, such as `setReceivePolicy`. Use `with_unrestricted_calls()` to allow any call. `allowed_calls()` now returns the effective scopes as an owned `Vec`.
