# tempo-monitor

`tempo-monitor` runs a Tempo node with the monitor ExEx installed under the id `tempo-monitor`.

The current PoC processes finalized blocks through `monitor`, commits normalized finalized-block facts plus the `TEMPO-BLOCK-TOTAL-GAS` stateless check to the monitor store, logs check outcomes and block commits, and emits `FinishedHeight` only after the store commit and `monitor_head` acknowledgement succeed.

## Current scope

Implemented:

- Tempo node startup with the monitor ExEx installed.
- Finalized watermark polling from the Reth provider.
- Finalized block normalization into monitor-owned facts.
- In-memory `MonitorStore` commits.
- `TEMPO-BLOCK-TOTAL-GAS` check results and coverage records.
- Logs for:
  - monitor ExEx startup;
  - finalized watermark observations;
  - check outcomes;
  - block commits;
  - `FinishedHeight` emission;
  - retry/halt adapter errors.

Not implemented yet:

- Durable monitor-owned storage.
- Monitor CLI/config.
- Full invariant suite.
- Finding/outbox emission policy for check violations.
- Production proof durability.

## Durability caveat

`tempo-monitor` currently uses `InMemoryMonitorStore`.

This is useful for local PoC validation, but monitor state is not restart-durable. Do not use this binary for production proof claims until the in-memory backend is replaced with durable monitor-owned storage.

## Run locally

```bash
cargo run -p tempo-monitor -- node --dev
```

Expected monitor logs include messages like:

- `tempo monitor ExEx started`
- `monitor finalized watermark observed`
- `monitor check result`
- `monitor block committed`
- `monitor FinishedHeight emitted`

For the current dev-node smoke test, finalized genesis should be processed and `TEMPO-BLOCK-TOTAL-GAS` should pass.

## Verification

```bash
cargo +nightly fmt -p monitor -p tempo-monitor -p tempo
cargo check -p monitor --no-default-features
cargo check -p monitor --features store
cargo check -p monitor --features reth
cargo test -p monitor --all-features
cargo check -p tempo-monitor
cargo check -p tempo --lib --no-default-features
cargo check -p tempo --lib --features exex-overrides
CARGO_TERM_COLOR=never cargo clippy -p monitor --all-features -- -D warnings
```
