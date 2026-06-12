# Tempo Fuzz Harness

This crate builds the cdylib loaded by the external Tempo fuzz runner for hardfork differential fuzzing and conformance replay.

```bash
cargo build -p tempo-fuzz-harness --release
```

The harness exports exactly three C ABI functions:

- `tempo_fuzz_execute_tx_with_result_v1`
- `tempo_fuzz_execute_block_with_result_v1`
- `tempo_fuzz_capabilities_v1`

`tempo_fuzz_execute_tx_with_result_v1` accepts a bincode-encoded `tempo_fuzz_types::TxInput` and returns a bincode-encoded `tempo_fuzz_types::TxResult`.

`tempo_fuzz_execute_block_with_result_v1` accepts a bincode-encoded `tempo_fuzz_types::BlockInput` and returns a bincode-encoded `tempo_fuzz_types::BlockResult`. Block input is the conformance fixture format: a chain spec, pre-state, and ordered block payloads whose transaction bytes are RLP/EIP-2718 encoded `TempoTxEnvelope` values.

`tempo_fuzz_capabilities_v1` returns `tempo_fuzz_types::HarnessCapabilities`, including the hardfork ids supported by this build. The external runner intersects capabilities across loaded harnesses before generating fuzz inputs, so older release branches can avoid newer hardfork-only behavior.

The conformance fixtures live in the `conformance-fixtures` R2 bucket. CI reads the archive filename from `CONFORMANCE_FIXTURES_ARCHIVE` in `.github/workflows/conformance-fixtures.yml`. That value points at an immutable `<sha>.tar.zst` archive object. CI downloads that archive, verifies its hash from the filename, and runs the fixture directory through a direct Rust binary:

```bash
cargo build -p tempo-fuzz-harness --release --lib
archive_key="f1dcf20753e610770ff1068df520af1a3019a9ed39f490b36fab1d625b689f90.tar.zst"
wrangler r2 object get "conformance-fixtures/${archive_key}" --file /tmp/conformance-fixtures.tar.zst
cargo run -p tempo-fuzz-harness --release --bin conformance-fixture-archive -- verify-unpack "$archive_key" /tmp/conformance-fixtures.tar.zst
cargo run -p tempo-fuzz-harness --release --bin conformance-fixtures -- fixtures/block
```

Fixture files are binary bincode payloads. New fixture releases publish the archive at `<archive-sha256>.tar.zst`, optionally publish metadata at `<archive-sha256>.json`, then PR the workflow archive value update to contain `<archive-sha256>.tar.zst`.

The GitHub workflow needs `CLOUDFLARE_ACCOUNT_ID` and `R2_CONFORMANCE_FIXTURES_READ_TOKEN` configured as repository secrets.
