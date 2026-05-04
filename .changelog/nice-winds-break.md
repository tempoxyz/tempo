---
tempo-primitives: minor
tempo-alloy: minor
---

Moved TIP-20 and TIP-1022 virtual-address helpers (`is_tip20_prefix`, `is_virtual_address`, `decode_virtual_address`, `make_virtual_address`, `MasterId`, `UserTag`) from `tempo-precompiles` into a new `TempoAddressExt` trait on `Address` in `tempo-primitives`. Updated all consumers to use the new trait methods (`address.is_tip20()`, `address.is_virtual()`, `Address::new_virtual(...)`, etc.).
