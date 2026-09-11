# Tempo Replay

`tempo-replay` provides three independent tools for finalized Tempo traffic:

- `run` mirrors original signed user transactions to a shadow fork.
- `audit` compares finalized source and shadow inclusion and execution.
- `profile` measures source workload characteristics over an exact range.

The tools share typed Tempo providers and certificate-authenticated finalized history, but do not share runtime state. Auditing and profiling cannot block or influence dispatch.

## Build

```sh
cargo build --locked --release -p tempo-replay
cargo test --locked -p tempo-replay
cargo clippy --locked -p tempo-replay --all-targets -- -D warnings
cargo +nightly fmt --all --check
```

Copy [tempo-replay.example.toml](tempo-replay.example.toml) and set the source, target, checkpoint, state, authentication, and metrics values for the deployment. Invocation-specific ranges and output paths remain CLI arguments.

## Mirror

The checkpoint is the final source block represented by the shadow snapshot. The source and patched shadow hashes at that height differ.

```sh
tempo-replay run --config tempo-replay.toml
```

`run` authenticates contiguous source finality using Tempo's existing `FinalizedHeaderStream`, fetches typed `TempoNetwork` blocks, filters system and reserved subblock transactions, and submits each native `TempoTxEnvelope` with its exact EIP-2718 bytes.

The mirror RocksDB stores compact per-source-occurrence dispatch intents, bounded attempt evidence, outcomes, indexes, aggregate counters, and the completed source frontier. Intents are synchronously committed before a block is submitted; outcomes and the frontier advance atomically after it drains. Restarting resumes from that frontier, unresolved intents remain explicitly ambiguous, and duplicate exact-byte submissions are idempotent through `already known` handling.

Use `--to-block N` for a bounded run. The `[run]` section configures bounded submission concurrency, transport retries, successful-evidence retention, and disk watermarks. Successful detail is pruned after the retention horizon; rejected and ambiguous evidence, including exact raw bytes, is retained. Target pool admission, nonce lanes, memory accounting, and eviction are deliberately left to the Tempo node.

## Audit

The auditor follows source and shadow finality independently and never communicates state back to `run`.

```sh
tempo-replay audit --config tempo-replay.toml
```

For every replayable source occurrence, it records the source location and receipt summary. Finalized target transactions are matched by hash. Included transactions are compared for status, gas used, and a hash of their serialized receipt logs.

Absence is reported only after the configured `missing_after_blocks` or `missing_after_seconds` horizon; it is not presented as proof that a transaction was rejected or never submitted. Missing and execution-drift findings are diagnostic and never pause mirroring.

The auditor records finality stalls and checks naturally generated system/subblock traffic without replaying it from the source. Successful system traffic is counted; invalid ordering/envelopes and reverted receipts retain detailed failure evidence.

Use `--to-block N` for a bounded source audit. Included records older than the configured `retain_included_blocks` are summarized and atomically pruned with their indexes; missing, drift, liveness, and system findings remain available. On exit, stdout contains a bounded summary while detailed findings remain in the audit RocksDB.

## Inspect

Correlate submission and audit evidence by transaction hash or exact source occurrence, including while the primary processes are running:

```sh
tempo-replay inspect \
  --mirror-state /var/lib/tempo-replay/mirror \
  --audit-state /var/lib/tempo-replay/audit \
  --tx 0xTRANSACTION_HASH
```

Use `--source-block N --index I` instead of `--tx` for an exact repeated occurrence. Inspection opens live RocksDB secondaries and reports the mirror and auditor cursor boundaries with the matched evidence.

## Profile

Profiling reads finalized source history directly and does not require mirror or auditor state.

```sh
tempo-replay profile \
  --config tempo-replay.toml \
  --from-block 120000 \
  --to-block 123456 \
  --output workload-profile.json
```

The report is bound to exact first/last block hashes and preserves the original profile's source-observable workload facts: duration and mean TPS, non-system/system/subblock counts, encoded bytes and gas, transaction families, nonce/expiry usage, validity bounds, and peak block/sender load. Capture latency is omitted because historical RPC cannot reconstruct it.

## Authentication and metrics

Each endpoint can name a private CA file and an environment variable containing its bearer token. Redirects are disabled, and standard TLS validation remains enabled when no private CA is configured.

Set separate `metrics` addresses in `[run]` and `[audit]` so both processes can run concurrently. Each exposes only metrics for its own responsibility, including RocksDB SST, memtable, WAL, pending-compaction, and write-latency observations.

## Deployment responsibilities

The daemon performs only intrinsic safety checks: chain IDs, source and target checkpoint hashes, authenticated source ancestry, RPC connectivity, TLS, and credentials.

Private P2P isolation, validator configuration, binary/chainspec deployment, host sizing, and capacity planning remain deployment responsibilities. Protocol compatibility belongs in real-node integration tests. There is no `verify`/`qualify` command or self-authored deployment evidence schema.
