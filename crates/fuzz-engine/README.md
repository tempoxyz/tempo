# Tempo Fuzz Engine

The stateless block executor behind [`tempo-fuzz-harness`](../fuzz-harness)
and [`zone-fuzz-harness`](../zones/fuzz-harness): it executes a
[`tempo-fuzz-types`](../fuzz-types) input on an in-memory state and checks
[`tempo-invariants`](../invariants) after every step.

A chain is an `Engine`: its chain spec, EVM config and consensus, its genesis,
the system transactions that open and close each block, and which protocol
contracts it runs. `Tempo` is Tempo L1's. Each harness exports the shared C ABI
with the `ffi` helpers; the engine exports no symbols, so both harnesses build
in one workspace.
