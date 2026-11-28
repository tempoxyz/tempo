# Tempo Fuzz Engine

The stateless block executor behind [`tempo-fuzz-harness`](../fuzz-harness)
and [`zone-fuzz-harness`](../zones/fuzz-harness): it executes a
[`tempo-fuzz-types`](../fuzz-types) input on an in-memory state and checks
[`tempo-invariants`](../invariants) after every step.

A chain is an `Engine`: its chain spec, EVM config and consensus, its genesis,
the hardforks and input modes it supports, which protocol contracts it runs,
how it calls views, and the transactions its block builder adds around the
input's. `Tempo` is Tempo L1's. Each harness exports the shared C ABI with the
`ffi` helpers; the engine exports no symbols, so both harnesses build in one
workspace.
