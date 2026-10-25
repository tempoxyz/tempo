---
tempo-alloy: patch
tempo-primitives: patch
tempo-chainspec: patch
---

The `tempo-contracts` bindings no longer implement `Serialize` and `Deserialize` unless `tempo-contracts/serde` is enabled. `tempo-alloy`, `tempo-primitives` and `tempo-chainspec` no longer enable it, including through their `serde` features.
