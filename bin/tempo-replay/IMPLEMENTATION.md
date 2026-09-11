# Implementation notes

See [README.md](README.md) for CLI behavior and operational usage.

| Code | Responsibility |
| --- | --- |
| `src/config.rs` | Minimal shared endpoint/checkpoint configuration and command-specific bounds. |
| `src/source.rs` | Typed `TempoNetwork` providers, authenticated finalized streams, full-block matching, and native transaction filtering. |
| `src/state.rs` | Shared replay identity, ordered occurrence keys, failure evidence, and immutable JSON report output. |
| `src/store.rs` | Bounded bincode RocksDB values, logical column families, synchronous batches, secondaries, disk bounds, and metrics. |
| `src/mirror/` | Bounded exact-byte submission and durable per-occurrence intent/outcome evidence. |
| `src/audit/` | Independent inclusion/receipt audit, finality liveness, system checks, retention, and incidents. |
| `src/profile.rs` | Bounded source workload aggregation over an exact hash-bound range. |
| `src/main.rs` | Independent command wiring, endpoint checks, inspection, metrics, and shutdown. |

## Trust and durability boundaries

- Finality comes from `tempo_consensus::FinalizedHeaderStream`, including certificate and DKG-transition verification.
- A typed RPC block is accepted only when both its hash and full header match the authenticated finalized header.
- Transactions remain native `TempoTxEnvelope` values through exact EIP-2718 encoding and submission.
- The mirror synchronously commits one intent batch before dispatch and atomically commits outcomes plus the source cursor after the block drains. An intent is not proof that bytes reached the network.
- The auditor atomically commits block evidence and its corresponding source or target cursor. Audit state never controls mirror dispatch.
- Operational state uses ordered binary keys and bounded, varint bincode values in separate mirror/audit RocksDBs. JSON is only an export format.
- Active RocksDB levels use LZ4 and the bottommost level uses Zstd. WAL sync is the crash-durability boundary; graceful flush is additional cleanup.
- Successful audit detail is pruned with its hash index after the retention horizon. Failure, ambiguity, drift, liveness, and system-failure evidence is retained by default; successful system traffic is aggregated.
- The target Tempo pool, not the mirror, owns nonce queues, admission, memory accounting, and eviction.
- Profile percentiles use fixed log2 buckets, so reported quantiles are bounded approximations rather than exact values.

## Failure evidence

Mirror records distinguish accepted, already-known, explicit rejection, and ambiguous delivery. RPC codes and bounded sanitized messages are retained where available. The independent auditor distinguishes missing-after-window, receipt drift, finality incidents, and system behavior, so absence is never treated as proof that submission failed.

The inspector joins both databases by exact source `(height, index)` and transaction hash. Separate secondary snapshots have independent cursor boundaries, which are included in output.

## System checks

Source system and reserved subblock transactions are never submitted to the target pool. The auditor aggregates successful target-generated traffic and retains detailed evidence for native-envelope, hardfork-dependent count/order/destination, and receipt failures.

## Deliberately absent

There is no deployment `verify`/`qualify` subsystem, deployment evidence manifest, external pool-credit model, receipt comparison in dispatch, state-diff comparison, or custom JSON-RPC/WebSocket/Prometheus implementation.
