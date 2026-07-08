# monitor

`monitor` is the Tempo monitor core crate.

It owns monitor-domain types, normalized finalized-block facts, invariant metadata, check/coverage/finding models, typed report payloads, the monitor store contract, durable monitor-owned storage, outbox primitives, and the optional Reth adapter used by `tempo-monitor`.

Core modules avoid Reth provider and notification types. Reth integration is isolated behind the `reth` feature in `monitor::reth`.

## Module layout

- `input`: monitor-owned finalized chain input facts, normalization, and read views.
- `diagnostics`: coverage/check outcomes, evidence, finding lifecycle types, and typed report payloads.
- `invariants`: invariant identifiers and metadata.
- `entity`: monitored protocol entity keys.
- `processor`: store-backed finalized-block processing and commit construction. Enabled by `store`.
- `store`: durable commit contract, MDBX/in-memory backends, and outbox worker/sink primitives. Enabled by `store`.
- `reth`: Reth provider/ExEx adapter. Enabled by `reth`.

## Features

- default: no optional features enabled.
- `store`: enables the finalized-block processor, reporting policy, `MonitorStore` trait, atomic `BlockCommit` model, `InMemoryMonitorStore`, durable `MdbxMonitorStore`, and outbox worker/sink primitives.
- `reth`: enables the Reth finalized-block adapter and monitor ExEx loop. This feature depends on `store`.
- `activity`: reserved for activity-related monitor components.

## Current behavior

With `store` enabled, `FinalizedBlockProcessor` builds one atomic `BlockCommit` for each finalized block.

The commit includes:

- finalized block identity and metadata;
- normalized block facts;
- normalized transaction facts;
- normalized receipt facts;
- ordered logs;
- check results;
- coverage records;
- finding transitions;
- monitor health updates;
- report outbox events;
- the new `monitor_head`.

`BlockCommit` is the only path that advances `monitor_head`.

The current processor emits the initial stateless check:

- `TEMPO-BLOCK-TOTAL-GAS`

The check passes when receipt-derived total gas equals header `gas_used` and header `gas_used` does not exceed `gas_limit`. Missing receipt gas yields an inconclusive check outcome and inconclusive coverage.

## Reporting and outbox

The store-backed reporting policy converts check outcomes into durable commit rows:

- violations open findings and enqueue typed `tempo.monitor.finding.v1` outbox payloads;
- inconclusive checks enqueue typed `tempo.monitor.coverage_gap.v1` payloads and record `CoverageDegraded` health updates;
- check errors record `CheckError` health updates;
- passing checks emit no reports in the MVP.

Outbox rows are committed atomically with finalized block data. Delivery is intentionally post-commit and does not participate in `monitor_head` advancement.

The JSONL sink is the initial test/debug sink for validating durable outbox semantics and inspecting emitted reports locally. MDBX remains the durable source of truth; JSONL is an at-least-once delivery artifact and is expected to be complemented or replaced by production sinks such as webhook or proof-submission sinks.

The JSONL sink appends one newline-terminated JSON object per delivered outbox row, flushes after each row, and returns a `DeliveryRecord` only after the write succeeds. Emitted rows include stable idempotency keys of the form:

```text
tempo-monitor:<outbox-sequence>:<event-digest>
```

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

## Store backends

`InMemoryMonitorStore` is a correctness/test backend. It enforces the same store contract as durable storage, including continuity, idempotent recommit mismatch detection, outbox/finding/health constraints, and `monitor_head` advancement through `BlockCommit`, but it is not restart-durable.

`MdbxMonitorStore` is the durable monitor-owned backend. It commits one finalized block per atomic MDBX write transaction and writes `monitor_head` last. Identical replay is idempotent and does not duplicate outbox rows; differing replay returns `IdempotencyMismatch`.

## Verification

```bash
cargo +nightly fmt --check
cargo check -p monitor --no-default-features
cargo check -p monitor --features store
cargo check -p monitor --features reth
cargo clippy -p monitor --features reth --all-targets -- -D warnings
cargo test -p monitor --features store
cargo test -p monitor --features reth
cargo check -p tempo-monitor
```
