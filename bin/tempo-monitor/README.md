# tempo-monitor

`tempo-monitor` runs a Tempo node with the monitor ExEx installed under the id `tempo-monitor`.

It processes finalized blocks through `monitor`, commits normalized finalized-block facts, check results, typed finding reports, and durable outbox rows to monitor-owned MDBX storage, logs check outcomes and block commits, and emits `FinishedHeight` only after the store commit and `monitor_head` acknowledgement succeed. The binary currently enables a JSONL sink for local outbox validation and operator inspection.

## Current scope

Implemented:

- Tempo node startup with the monitor ExEx installed.
- Finalized watermark polling from the Reth provider.
- Finalized block normalization into monitor-owned facts.
- Durable `MdbxMonitorStore` commits at `<tempo datadir>/monitor.mdbx`.
- `TEMPO-BLOCK-TOTAL-GAS` check results and coverage records.
- Typed report payloads:
  - `tempo.monitor.finding.v1` for violations;
  - `tempo.monitor.coverage_gap.v1` for inconclusive checks.
- Durable report outbox rows committed atomically with finalized block data.
- Initial JSONL outbox sink for local testing/inspection at `<tempo datadir>/monitor-outbox.jsonl`.
- Logs for:
  - monitor ExEx startup;
  - durable MDBX store path;
  - JSONL outbox worker config;
  - finalized watermark observations;
  - check outcomes;
  - block commits;
  - outbox delivery failures;
  - `FinishedHeight` emission;
  - retry/halt adapter errors.

Not implemented yet:

- Monitor CLI/config for MDBX/outbox paths and worker settings.
- Full invariant suite.
- Store-aware cross-block finding update/resolve policy.
- Webhook/Slack/Loki/proof-submission sinks.
- Exact-once external delivery.

## Durability and delivery semantics

`tempo-monitor` uses durable monitor-owned MDBX storage by default:

```text
<tempo datadir>/monitor.mdbx
```

The initial JSONL sink writes delivered rows to:

```text
<tempo datadir>/monitor-outbox.jsonl
```

MDBX is the durable source of truth. JSONL is an at-least-once delivery artifact for local validation/inspection and is expected to be complemented or replaced by production sinks such as webhook or proof-submission sinks.

Outbox delivery is at-least-once:

- rows are delivered only after they are durable in MDBX;
- successful delivery is recorded with `mark_outbox_delivered`;
- failed delivery leaves the row pending;
- delivery never advances or mutates `monitor_head`;
- restart resumes from pending rows;
- duplicate external emission is possible after a crash between JSONL write and delivery marking.

Each JSONL object includes a stable idempotency key so consumers can dedupe:

```text
tempo-monitor:<outbox-sequence>:<event-digest>
```

## Run locally

```bash
cargo run -p tempo-monitor -- node --dev
```

Expected monitor logs include messages like:

- `opening durable monitor MDBX store`
- `configuring monitor JSONL outbox worker`
- `tempo monitor ExEx started`
- `monitor finalized watermark observed`
- `monitor check result`
- `monitor block committed`
- `monitor FinishedHeight emitted`

For the current dev-node smoke test, finalized genesis should be processed and `TEMPO-BLOCK-TOTAL-GAS` should pass.

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
