---
tempo: minor
---

Add an experimental `tempo-multiplex` supervisor for a legacy v1 node and a fixed-T11 `tempo-v2` node. Historical HTTP RPC execution is routed to v1 using a verified checkpoint, while v2 compiles out runtime Tempo hardfork selection and refuses pre-T11 execution.
