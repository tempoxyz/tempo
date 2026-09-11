# Implementation notes

Tempo Replay is a workspace package with a library and the `tempo-replay` CLI. Live operation starts with configured source/target identities and pool bounds using `run --from-block N`; exhaustive workload qualification is a separate `verify` command.

| Code | Responsibility |
| --- | --- |
| `src/config.rs` | Strict schema, bounds and policy validation; deployment evidence schema. |
| `src/model.rs` | Local native Tempo envelopes, signer recovery, canonical encoding, root/hash checks and occurrence states. |
| `src/rpc.rs` | Bounded authenticated HTTP transport and native source WebSocket notifications. |
| `src/capture.rs` | Finalized capture, certified-history repair, staged execution fallback and compatibility incidents. |
| `src/journal.rs` | Single RocksDB writer, synchronous atomic batches, indexes, independent cursors and secondary readers. |
| `src/profile.rs` | Captured workload, types, nonce distribution, deadlines and sender/block peaks. |
| `src/verify.rs` | Live identity/adapter/pool checks and separate exhaustive workload/history qualification. |
| `src/timing.rs` | Monotonic catch-up/live anchors, retained slip and separate release-rate constraint. |
| `src/engine.rs` | Pipelined dispatch, sender/network credits, gap isolation, finality/receipt reconciliation and bounded recovery. |
| `src/metrics.rs` | Prometheus counters/gauges and health endpoint. |
| `src/main.rs` | CLI, task supervision, signals and shutdown. |

## Concrete choices

- `run --from-block N` mirrors N inclusively and follows finalized traffic continuously. N must equal the native snapshot height plus one. The live path accepts no prior workload profile, probes execution retrieval at the trusted current tip, and waits if N has not finalized yet. Actual backlog ancestry is verified by concurrent capture. `verify` still requires a profile, measured throughput/latency and the complete retention-horizon probe. Live startup logs missing throughput/latency qualification without claiming an SLO.
- A supplied replay height is validated independently of an earlier capture journal's start. Repeating it on restart does not reset capture, attempt or inclusion cursors.
- RocksDB namespaces use ordered key prefixes within one column family. This retains atomic batches across metadata/occurrences/cursors with a smaller operational footprint. Source height/index entries also store the source block hash; hash indexes preserve repeated system occurrences. A canonical cursor gates staged history.
- Attempt intents for each dispatch batch share an fsync. Remaining updates commit immediately, with no deliberate group delay; this is within `group_commit_max_ms`. Retention is fail-closed disk backpressure, with no automatic pruning.
- Source WS events coalesce into a bounded latest-event slot. Every polling pass repairs from the durable cursor, and HTTP polling continues without WS traffic. The full event block supplies the trusted upper anchor. Target finality uses 250 ms polling and verified gap repair; configured target WS URLs are validated deployment metadata and are not used as a second target transport in this version.
- The crate inherits workspace dependencies and uses local Tempo primitives with minimal features. HTTP JSON is decoded directly into native Tempo headers/envelopes; no generic Ethereum-only transaction reconstruction or full node dependency is used.
- The owned consensus RPC is the finality trust boundary. Certificate/digest evidence is retained; independent BLS certificate validation with changing DKG contexts is not claimed.
- `bootstrap_artifact_digest` binds the exact native generated manifest bytes. The deployment manifest separately records node binary/chainspec digests. Its validator public-key set must equal the native manifest's set. Standard RPC verifies chain ID, patched checkpoint and finalized ancestry; effective node configuration remains operator evidence.
- Accepted/unknown pool entries retain credits until positive finalized inclusion or a rejection that has no preceding uncertain/accepted attempt. Null lookups never imply removal. An unresolved reservation pauses recovery rather than leaking credits. Automatic eviction detection and provisional-head credit release are not used, so finalized-history conflicts pause instead of rolling back provisional inclusions.
- An ambiguous attempt stays on its previous verified ingress. New work can route to another available verified ingress after reconciliation. This conservative failover avoids an unobserved cross-validator resend.
- Permanent sequential gaps block later occurrences, including those not submitted. Already accepted/in-flight successors retain credits and are reconciled. Authority nonce changes are preserved in original EIP-7702/Tempo envelopes; nonce jumps do not generate fillers. A conflicting finalized transaction or authoritative consumed nonce without the required hash pauses replay.
- Coverage counts all user occurrences after the fork boundary. `offered` means a durable initial attempt intent, which remains uncertain across a crash-before-write window. Receipt-proven finalized coverage is separate. Source receipts compare status and gas; raw logs are retained without semantic log normalization.

## Deployment qualification checklist

Run these against isolated real Tempo nodes at the pinned revision before claiming production traffic fidelity:

1. Native bootstrap, patched boundary, TLS/credentials and correct validator/chainspec deployment.
2. Full source and target retained-history recovery across the intended outage horizon; socket disconnect and node restart.
3. Future-nonce admission for legacy/key-zero/2D families, expiry and keychain rules, policy/fee-token/AMM parity, access-key and authorization dependencies.
4. Peak-block/hot-sender throughput, journal fsync cost, actual pool-accounted memory, catch-up surplus and live lag over sustained traffic. A mean source profile and operator capacity attestations are necessary, not proof of peak-rate fidelity.
5. Conservative reservation progress under eviction, restart and long inclusion delay. If this policy cannot sustain the deployment, add and qualify a positive pool-removal adapter before increasing claims of coverage or throughput.
6. Full user-denominator offered/finalized coverage and status/gas drift, including expected expiry and descendants affected by missing state transitions.

The deterministic and mock-RPC suite validates the daemon's bookkeeping, cryptographic encodings and transport/recovery decisions. It does not emulate Tempo consensus, EVM execution or mempool admission, and does not establish mainnet-rate throughput.

## Local validation

The suite covers the following checks from the Tempo workspace root:

- `cargo test --locked -p tempo-replay -j 4`: 28 tests, including continuous following, waiting for the first block, and restart recovery in `tests/live.rs`.
- `cargo clippy --locked -p tempo-replay --all-targets -- -D warnings`.
- `cargo +nightly fmt --all --check`.
- CLI help/version, example parsing, documentation links and Markdown fences.

The signature corpus includes legacy, EIP-2930/1559/7702, AA 2D and expiring nonces, sponsored batches, P256, WebAuthn, keychain V2, expiring key authorization and Tempo authorization lists. Loopback RPC tests cover capture fallback, conflicting ancestry, missing end certificates, response-loss reconciliation, restart, crash-before-write, expiry/dependency gaps, capacity deferral and cancellation. All test servers terminate with their tests.
