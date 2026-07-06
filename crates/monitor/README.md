# monitor

`monitor` is the Tempo monitor core crate.

It owns monitor-domain types, normalized finalized-block facts, invariant metadata, check/coverage/finding models, the monitor store contract, and the optional Reth adapter used by `tempo-monitor`.

Core modules avoid Reth provider, notification, and database types. Reth integration is isolated behind the `reth` feature in `monitor::reth`.

## Features

- default: no optional features enabled.
- `store`: enables the `MonitorStore` trait, atomic `BlockCommit` model, and `InMemoryMonitorStore` backend.
- `reth`: enables the Reth finalized-block adapter and monitor ExEx loop. This feature depends on `store`.
- `activity`: reserved for activity-related monitor components.

## Current PoC behavior

With `store` enabled, `FinalizedBlockProcessor` builds a single atomic `BlockCommit` for each finalized block.

The commit includes:

- finalized block identity and metadata;
- normalized block facts;
- normalized transaction facts;
- normalized receipt facts;
- ordered logs;
- check results;
- coverage records;
- the new `monitor_head`.

`BlockCommit` is the only path that advances `monitor_head`.

The current processor emits the initial stateless check:

- `TEMPO-BLOCK-TOTAL-GAS`

The check passes when receipt-derived total gas equals header `gas_used` and header `gas_used` does not exceed `gas_limit`. Missing receipt gas yields an inconclusive check outcome and inconclusive coverage.

Finding/outbox rows for violations are intentionally deferred until the reporting policy is wired.

## Reth adapter

With `reth` enabled, `monitor::reth` provides finalized-block processing for a Tempo node ExEx:

- `FinalizedWatermark`
- `FinalizedBlockSource`
- `FinishedHeightSink`
- `FinalizedLoop`
- `RethFinalizedBlockSource`
- `RethFinishedHeightSink`
- `MonitorExExConfig`
- `run_monitor_exex`

The monitor ExEx id is:

```rust
monitor::reth::EXEX_ID == "tempo-monitor"
```

Finalized blocks are processed in order. `MonitorStore::commit_block` runs before any `FinishedHeight` emission. `FinishedHeight(N)` is emitted only after the commit succeeds and `monitor_head >= N` is observed, or during startup acknowledgement of an already durable head.

ExEx notifications are used as wakeups. The finalized provider watermark is the processing source of truth.

## Store caveat

The only backend currently implemented is `InMemoryMonitorStore`.

It enforces the same store contract used by tests, including continuity, idempotent recommit mismatch detection, outbox/finding/health constraints, and `monitor_head` advancement through `BlockCommit`. However, it is not restart-durable and must not be used for production proof claims.

Durable monitor-owned storage remains future work.

## Verification

```bash
cargo +nightly fmt -p monitor -p tempo-monitor -p tempo
cargo check -p monitor --no-default-features
cargo check -p monitor --features store
cargo check -p monitor --features reth
cargo test -p monitor --all-features
CARGO_TERM_COLOR=never cargo clippy -p monitor --all-features -- -D warnings
```
