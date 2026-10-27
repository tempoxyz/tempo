---
tempo-primitives: major
tempo-chainspec: patch
---

`TempoHeader::consensus_context` is now a required `TempoConsensusContext` instead of an `Option`. Headers always encode it (all zero for genesis, dev-mode and zone blocks), and RLP, JSON and database records without it are rejected.
