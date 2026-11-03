# Tempo Fuzz Harness

A stateless Tempo block executor, built as a cdylib for differential fuzzing
and for replaying blocks taken from a node. The input and outcome types and
their contracts are in [`tempo-fuzz-types`](../fuzz-types).

```bash
cargo build -p tempo-fuzz-harness --release
cargo bench -p tempo-fuzz-harness --bench execute
```

The library exports two bincode-encoded C ABI functions:

- `tempo_fuzz_execute_with_result_v1`: a `TempoHarnessInput` in, a
  `TempoHarnessOutcome` out.
- `tempo_fuzz_capabilities_v1`: the harness's `TempoHarnessCapabilities`, so a
  runner that loads several revisions can generate inputs all of them support.
