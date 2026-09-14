# Implementation notes

See [README.md](README.md) for operation, compatibility, and diagnostic limits.

| Module | Responsibility |
| --- | --- |
| `config.rs`, `main.rs` | One service configuration and read-only inspection; historical profiling stays independent. |
| `source.rs` | Native envelopes, typed providers, authenticated headers/body roots, source and shadow epoch schedules, shadow network identity from the checkpoint DKG outcome. |
| `state.rs` | Source occurrence identity, bounded RPC attempt evidence, receipt observations, derived findings. |
| `evidence.rs` | Shared records, atomic dispatch/receipt cursors, one-to-one target matching, recovery/retention indexes. |
| `store.rs` | RocksDB binary codec, synchronous batches, secondary snapshots, and disk bounds. |
| `relay.rs` | Retried source stream with bounded prefetch, sequential nonce lanes, exact-byte submission, draining shutdown, conservative recovery. |
| `observe.rs` | Separate source-receipt and target-finality workers, receipt identity checks, system checks. |
| `service.rs` | Worker lifetime, observation drain, liveness metrics, retention, and shutdown. |

## Durability and scheduling

A source block's exact bytes are synchronously recorded before submission. Each round increments its durable budget before any request; outcomes and source completion advance in one batch. On shutdown, requests already issued are awaited and committed without advancing the cursor unless every queued occurrence completed; a block round after restart re-dispatches only occurrences without a committed outcome. On a hard crash, an intent remains ambiguous and retries consume the same bounded budget after restart. Interrupted intents are always handed back to `begin_round`, even with an exhausted budget, so `in_flight` is cleared. The in-memory progress value changes only after the database commit succeeds.

Relay and observers hold the shared writer only for database operations, never for RPC or retry sleeps. Source receipts may arrive before submission completes; completion enriches the current record instead of overwriting concurrent receipt observations. A source block's temporary receipt manifest is deleted only after both dispatch and receipt observation finish.

Hash indexes preserve `(source height, index)` and unmatched `(target height, index)` independently; a second unmatched index keyed by target location lets retention walk unmatched observations by age. Reconciliation consumes each target occurrence once, including multiple equal hashes within one batch and target observations that precede source ingestion.

No finding state or per-finding counter is persisted. Inspection derives the current finding from source/target receipts and attempt evidence. The clean-inclusion and recovery indexes support bounded work without repeatedly scanning historical failures or all accepted-but-pending transactions. Recovery-index membership is computed with the current process's `max_rounds` and the sampled target timestamp, so exhausted or expired records are not re-added by later enrichment. Attempted round counts are durable, but the configured limit is not part of the stored identity and may change across process opens. Pruning keeps aggregate counts for removed clean inclusions and aged-out unmatched target occurrences; anomalies retain evidence until disk bounds stop the service.

Each target finality-stream initialization reads the shadow network identity from the hash-pinned checkpoint header. Without that explicit identity, initialization would derive it by fetching the entire checkpoint..cursor header range, which grows with shadow-fork age. `last_target_progress_ms` is reset on open so downtime before the process started is not reported as a stall.

## Limits

Recovery is a bounded retry policy, not a second transaction pool or dependency scheduler. Sequential lanes preserve submission order within each block but do not enforce target inclusion order. Expiring nonces are independent. Source blocks drain serially; source prefetch is bounded to two queued blocks. There is no 1× catch-up pacing controller.

Node telemetry uses existing tracing and metrics at admission, eviction, and payload decisions. It is diagnostic, configurable, and potentially lossy. This service does not collect every node event, extract historical state, infer contract dependencies, or classify arbitrary reverts as harmless. A re-execution workflow must reconstruct the relevant parent state and execution prefix.

The schema is intentionally incompatible with the former separate mirror/audit stores. Keep old evidence with its matching binary; initialize a new directory for the unified service. One process/store is a shared failure domain, even though receipt RPC outages do not gate the relay.
