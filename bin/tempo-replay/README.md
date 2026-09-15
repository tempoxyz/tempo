# Tempo Replay

A Rust daemon that captures finalized Tempo transactions and submits their original signed bytes to an isolated shadow fork with independent validators. It preserves source block bursts, uses bounded catch-up, and switches to 1× pacing when the dispatch frontier reaches the configured lag.

Independent ordering, stock validator clocks and state divergence can cause rejection. Tempo Replay records those gaps against **every captured user occurrence**. It does not promise identical execution, replay system transactions, rewrite nonces, re-sign transactions, or change node validation.

## Live mirroring from a height

Configure the source RPC, shadow validators and snapshot identity once in [tempo-replay.example.toml](tempo-replay.example.toml), then start:

```sh
tempo-replay run --config tempo-replay.toml --from-block 123456
```

`123456` is the **first block to mirror, inclusive**. The configured shadow snapshot must contain source state through block `123455`. The command captures and mirrors the backlog, catches up, and keeps following newly finalized blocks at 1× pacing until you stop it. There is no end height by default. It also works when the first requested block does not exist yet: it waits for that block to finalize.

No separate capture or workload-profile command is required. Live startup verifies the configured chain/checkpoint/validator identities, pool budgets and execution RPC adapter. It validates actual history as it captures it, without scanning the entire configured retention horizon before starting. Workload and throughput qualification remain available separately through `verify`.

Restart with the same command, or omit `--from-block`:

```sh
tempo-replay run --config tempo-replay.toml
```

The durable journal resumes unfinished work and follows new traffic. Repeating the original start height does not reset progress. Starting at a different fork boundary requires the matching snapshot and a new journal. Live traffic here means transactions from newly **finalized blocks**, with the configured lag; it does not capture pending mainnet mempool arrivals.

## Build and test

Run these commands from the Tempo workspace root. The executable is `target/release/tempo-replay`.

Requires Rust 1.96+, a C/C++ compiler, CMake and libclang for RocksDB and cryptographic dependencies. On macOS, install the Xcode command-line tools; on Debian/Ubuntu, the usual build prerequisites are `build-essential clang libclang-dev cmake pkg-config`.

```sh
cargo build --locked --release -p tempo-replay
cargo test --locked -p tempo-replay
cargo clippy --locked -p tempo-replay --all-targets -- -D warnings
cargo +nightly fmt --all --check
```

Tests start local loopback RPC servers. They never contact a live chain or submit to mainnet. The crate uses local `tempo-primitives` and the shared workspace lockfile. The protocol compatibility checks currently target Tempo revision `731535b9808eda12e81ab6459703602554eaee5a`. Run the same Tempo revision on the source and shadow nodes.

## Optional capture before bootstrap

For a pre-bootstrap recording or workload profile, copy [examples/capture.toml](examples/capture.toml), configure an owned reader, and choose a start height below the intended fork boundary. Keep this reader running while taking a separate donor's snapshot.

```sh
tempo-replay capture --config capture.toml --from-block "$START_HEIGHT"
tempo-replay profile --journal ./data --output workload-profile.json
tempo-replay status --journal ./data
```

`--from-block` fixes the initial capture boundary. Omit it when resuming. Optional `--to-block` ends capture after that finalized height. Empty blocks are retained. Capture requires only run/source/journal settings and does not open a shadow connection.

Capture subscribes to native consensus events and polls finality for gap repair. Missing certificates trigger full execution-block recovery. Complete ranges are staged, checked for parent continuity, transaction roots and hashes, and connected to a trusted finalized hash before publication. `debug_getRawBlock` is cross-checked when available. Unknown encodings or conflicting history stop canonical advancement.

## Prepare and verify a shadow fork

Use Tempo's native `generate-shadowfork` and `bootstrap-shadowfork` on an immutable copy of the stopped donor's actual tip. Preserve chain ID 4217, configure independent validators and private P2P, and record the **patched shadow boundary hash**, which differs from the source hash. Tempo Replay does not bootstrap or modify nodes.

Fill in [tempo-replay.example.toml](tempo-replay.example.toml) and [examples/shadow-deployment.json](examples/shadow-deployment.json). Keep the same run ID, source endpoint and journal used for capture. The deployment manifest lists **every participating validator**, its measured pool limits, future-nonce support and validation/fee configuration evidence. The provided manifest deliberately fails qualification until its placeholders, measurements and attestations are filled in.

`checkpoint.bootstrap_artifact_digest` is `sha256:` followed by the SHA-256 of the **exact native generated manifest file bytes**. Use the same value in the deployment manifest. For example:

```sh
shasum -a 256 /etc/tempo-replay/shadowfork-manifest.json
```

Record the actual node binary and chainspec SHA-256 digests separately. Expected validator public keys must match the native generated manifest. HTTPS certificate validation, the configured private CA, bearer credentials from the named environment variables, and the patched checkpoint identify each ingress. URLs cannot embed credentials; redirects are disabled.

`run` does its own live startup checks. For exhaustive workload and retained-history qualification, first generate a profile, set the optional `run.workload_profile` path, and run:

```sh
tempo-replay verify --config tempo-replay.toml
```

`verify` sends only read RPCs. It checks the checkpoint/state root, profile history, validator-set evidence, target identities and capacity bounds, and **forces execution-layer recovery** across the configured history horizon and cache boundary. This comprehensive history scan may take substantial time; it is separate from live startup. Capture continues while `run` performs its startup checks. Standard RPC does not expose all effective node configuration, so binary/configuration/fee/capacity values remain explicit operator attestations; the program does not pretend to independently discover them.

A source workload profile is generated from actual captured blocks. For qualification, measure target sustained throughput, RPC p99 and source capture p99 on the intended deployment. Live startup reports unqualified throughput/latency as warnings and exposes runtime progress through status and metrics. Effective pool limits, memory accounting, validator identity and validation parity remain required deployment configuration. The example numbers are not measured capacity guarantees. If you explicitly configure a profile path, a missing or invalid file is an error.

## Replay and recovery

One ingress per sender is selected by rendezvous hashing. Budgets apply across all validators because gossip replicates transactions. Sequential nonce lanes pipeline only up to the configured window and verified per-family support. Unqualified families use one outstanding transaction per lane. AA key-zero and legacy transactions share a lane; 2D lanes and expiring nonces share sender credits.

Attempt intents are written in a synchronous RocksDB batch **before** requests start. Accepted and ambiguous hashes retain reservations. A lost response triggers exact-hash reconciliation and at most one identical-byte resend while still admissible. A crash between the durable intent and socket write leaves an uncertain attempt, so `attempts` and `offered` count durable attempt intents, not independently proven packet delivery. Inclusion coverage requires verified finalized-block and receipt evidence.

Expiry gets an initial attempt even when rejection is expected. Confirmed expiry or exhausted state-dependency budgets become explicit gaps; descendants in that sequential lane become `BlockedDependency`. Other lanes continue. Status-0 receipts count as included and are compared with source status/gas just like successful receipts.

This version uses **conservative retained pool reservations**. A null transaction lookup is not treated as proof of eviction. Unresolved accepted/ambiguous transactions eventually pause dispatch until authoritative finality resolves them. There is no automatic eviction-based credit reuse or blind rerouting of an ambiguous attempt. Capacity qualification must demonstrate progress with this policy. Source capture continues during recoverable target stalls.

`run --to-block N` exits when all occurrences through N have finalized or explicit terminal dispositions. It may finish with degraded coverage; inspect `gaps` and `included_through`. A compatibility/history/identity incident exits with an error. Investigate its durable evidence, then either restore a clean checkpoint into a new run/journal or explicitly use `--acknowledge-incident` after fixing the cause. That flag does not bypass verification. A checkpoint change requires a new journal.

SIGINT/SIGTERM stop new dispatch, drain bounded submissions, stop subscriptions and metrics, and flush the journal. One writer owns a journal; distributed fencing across multiple machines is an operator deployment responsibility.

## Inspect and monitor

```sh
tempo-replay status --journal ./data
tempo-replay inspect --journal ./data --tx 0xTRANSACTION_HASH
curl http://127.0.0.1:9090/metrics
curl http://127.0.0.1:9090/healthz
```

Status and inspect use a RocksDB secondary reader and work while the daemon runs. The journal contains raw source evidence, exact envelopes, attempt history, endpoint IDs, gaps and source/target receipts. Protect the directory as operational data.

The five cursors have different meanings:

| Cursor | Meaning |
| --- | --- |
| `captured_through` | Contiguous validated source history is durable. |
| `dispatch_accounted_through` | Every occurrence has an attempt intent or explicit disposition. |
| `accounted_through` | Every occurrence is finalized or terminally accounted for. |
| `included_through` | Every user occurrence is finalized; a gap stops this cursor. |
| `shadow_observed_through` | Contiguous verified target finality has been observed. |

Prometheus exposes coverage, attempts, gaps, reservations, phase, lag, slip and cursors without transaction/sender labels. `/healthz` reports recovery incidents and source unavailability. Inspect full-workload coverage separately from health. `reserved_raw_bytes` is encoded payload size; the scheduler uses the larger deployment-qualified memory estimate for its budget.

Decoded dispatch lookahead, RPC concurrency and database buffers are bounded. `max_buffered_bytes` bounds serialized work/individual responses, not total process RSS. Disk limits stop progress without deleting unresolved history. **No automatic journal pruning is implemented**; provision retention space and rotate runs explicitly. Evidence and JSON/hex storage can be several times larger than raw transaction bytes.

## Implementation and qualification

See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the code map, implementation choices and remaining deployment tests.

Local tests cover signed envelope families, P256/WebAuthn and sponsored AA batches, root/ancestry rejection, durable attempts, lost responses, restart, lane gaps, pacing and capacity invariants. Real Tempo admission/eviction, TLS deployment configuration, bootstrap behavior and sustained mainnet-rate throughput still require a private-node qualification run. No live chain was used during implementation.
