---
tempo-alloy: patch
---

Fixed `eth_simulateV1` rejecting every AA batch with "only one CREATE call is allowed per transaction" by no longer appending the filled-in `Create` destination to the batch's calls.
