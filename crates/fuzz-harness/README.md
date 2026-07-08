# Tempo Fuzz Harness

This crate builds the cdylib loaded by the external Tempo fuzz runner for
hardfork differential fuzzing and typed replay.

```bash
cargo build -p tempo-fuzz-harness --release
```

The harness exports exactly two C ABI functions:

- `tempo_fuzz_execute_with_result_v1`
- `tempo_fuzz_capabilities_v1`

`tempo_fuzz_execute_with_result_v1` accepts a bincode-encoded
`tempo_fuzz_types::TempoHarnessInput` and returns a bincode-encoded
`tempo_fuzz_types::TempoHarnessOutcome`.

`tempo_fuzz_capabilities_v1` returns
`tempo_fuzz_types::TempoHarnessCapabilities`, including explicit hardfork and
input-kind support. The external runner intersects capabilities across loaded
harnesses before generating fuzz inputs, so older release branches can avoid
newer hardfork-only behavior.

The checked-in conformance fixtures live under `fixtures/block`. The `Conformance Fixtures` GitHub Action runs the full fixture directory with:

```bash
cargo test -p tempo-fuzz-harness --release conformance_fixtures -- --nocapture
```

Fixture files are binary bincode payloads. `.gitattributes` marks `fixtures/**/*.fixture` as binary so Git does not apply text normalization or textual diffs.
