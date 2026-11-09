---
tempo-alloy: patch
---

`TempoNetwork::build_unsigned` refuses to build an AA transaction whose `max_priority_fee_per_gas` exceeds its `max_fee_per_gas`, or that fails `TempoTransaction::validate`, so it is never signed.
