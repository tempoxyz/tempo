# Tempo Replay

`tempo-replay run` relays exact signed transactions from finalized Tempo blocks and independently observes source/target receipts. One RocksDB holds source occurrences, submission attempts, and finalized observations. Findings are derived when inspecting that evidence, not maintained as another state machine.

## Build and test

```sh
cargo build --locked --release -p tempo-replay
cargo test --locked -p tempo-replay
cargo clippy --locked -p tempo-replay --all-targets -- -D warnings
cargo +nightly fmt --all --check
```

Copy [tempo-replay.example.toml](tempo-replay.example.toml), set the endpoints, checkpoint, and state directory, then run:

```sh
tempo-replay run --config tempo-replay.toml
```

**This replaces the separate `run`/`audit` deployment.** Move observation settings into `[run]`; remove `[audit]`. Use a new state directory: the old mirror/audit databases are deliberately incompatible, and are not migrated or deleted. Retain them with the previous binary if their evidence is needed.

The checkpoint is the final source block represented by the shadow snapshot. Its source and patched shadow hashes differ. The target must use the `bootstrap-shadowfork` chainspec: `epochLength = checkpoint.height + 1`, with private DKG state. Source and target finality are authenticated using their respective epoch schedules; the shadow network identity is read from the verified checkpoint header's DKG outcome. Full blocks are fetched by authenticated hash and transaction bodies are checked against header roots; receipt bodies are taken from RPC and are not checked against `receiptsRoot`.

## Relay and recovery

The relay filters system/reserved subblock traffic and submits native `TempoTxEnvelope` EIP-2718 bytes without re-signing, changing expiry, or bypassing pool validation. One target ingress is used. An ingress load balancer must preserve sender affinity.

Within a source block, sequential `(sender, nonce_key)` lanes are submitted in source order; different lanes and expiring-nonce occurrences run concurrently. This does not enforce inclusion order or cross-account dependencies. Two source blocks can be prefetched while the current block drains. Catch-up runs at configured concurrency, not at 1× source pacing; treat backlog periods as a different workload from live mirroring.

Exact bytes and source identity are committed before dispatch. Each submission round has a synchronously committed intent. Attempts record queue, actual request, and completion times, plus bounded RPC code/message/data. Outcomes and the completed source cursor advance atomically. A crash leaves an ambiguous intent, not proof of delivery.

On SIGINT/SIGTERM, lanes issue no new requests but requests already sent are awaited (bounded by the RPC timeout) and their outcomes committed. The source cursor advances only when every queued occurrence has an outcome; otherwise unsubmitted occurrences remain durable intents and are the only ones re-dispatched after restart. Occurrences with a committed outcome are never re-dispatched by a block round; only recovery retries them.

`retries` bounds transport/ambiguous retries within a round; `max_rounds` bounds all rounds, including restart recovery. The round count is durable, but the configured limit is reapplied on each process open: lowering it can make existing records exhausted, while raising it can make them eligible again. Recent ambiguous deliveries are retried from the preceding 64 source blocks. A nonce-too-low response after uncertain delivery is `possibly_included`, not a fresh rejection.

Only structured `InsufficientFeeTokenBalanceError`, `InsufficientAmmLiquidityError`, and `FeeTokenPausedError` rejections are eligible for state-dependent recovery, after observed target finality advances. Unknown errors are not inferred as retryable. Recovery stops at its round/window/expiry bounds and never extends signed validity. The original rejection is retained even if a later attempt succeeds. A sampled finalized target head is not an exact snapshot of the ingress validator's admission state.

## Observation and inspection

Source receipts and authenticated target history have separate asynchronous workers. Slow receipt RPCs do not gate submission. Source-stream, receipt, and target-history RPC outages are recorded once per outage episode and retried from the last committed cursor; authenticated-history inconsistencies are fatal. RPC requests have a 30-second timeout. Run the service under a supervisor with restart/backoff for process-level failures.

```sh
tempo-replay inspect --config tempo-replay.toml --tx 0xTRANSACTION_HASH
# An exact source occurrence, including repeated signed hashes:
tempo-replay inspect --config tempo-replay.toml --source-block N --index I
```

Inspection makes no RPC requests. It opens one consistent RocksDB secondary snapshot and reports all cursor boundaries, attempts, source/target timestamps and positions, receipt summaries, and nearby incidents. Target occurrences are matched once each, in occurrence order, rather than using one target receipt for every repeated source hash.

Receipt comparison covers status, gas used, and canonical consensus log address/topic/data fields. RPC location metadata is excluded. A mismatch is **execution drift, not proof of an EVM bug**. Use the captured block hashes/positions with the existing re-execution workflow; reproducing an omitted transaction requires its admission/build context, not just the finalized block that omitted it.

Missing-after-window is measured from the last completed accepted/already-known submission and its sampled target frontier. Not-dispatched, in-flight, rejected, ambiguous-delivery, and awaiting-source-receipt observations remain distinct. A structured `InvalidValidBeforeError` response is reported as `expired_before_dispatch`: the request reached target admission after its signed validity window was already too short or closed. This is a replay-lag artifact (typical during catch-up), not evidence that the source transaction was invalid. Missing is not proof of rejection; always check observer progress and incidents. Naturally generated system/subblock traffic is checked but never copied into the target pool.

`--to-block N` stops source dispatch at N and lets observation/recovery drain until source receipts catch up and transactions are included or the configured missing horizon elapses. An unavailable source receipt can delay bounded-run completion; SIGINT/SIGTERM leaves resumable state. Finality stalls and RPC failures remain diagnostics, not transaction-invalidity findings.

Clean, matching inclusions older than `retain_included_blocks` **source blocks** are pruned with their indexes and counted in `archived_included`. Target occurrences that never matched a source occurrence are pruned after the same number of **target blocks** and counted in `archived_unmatched`; their presence means something other than the relay fed the shadow pool. Rejections, interrupted/ambiguous attempts, recovered failures, and drift retain detail. Disk high/low watermarks stop the service rather than silently discarding evidence. The single process/store is a shared failure domain, unlike the former two-daemon deployment.

## Node diagnostics

Use the existing node tracing/telemetry pipeline; no new collector or event database is required:

- `txpool=debug`: admission rejection and state-update eviction reasons, sampled tip context, and expiry bounds.
- `txpool=trace`: validation/insertion outcomes, including pending/queued insertion state.
- `payload_builder=trace`: per-build deferral/invalidity/execution decisions keyed by transaction hash and the enclosing payload ID, parent, and timestamp.

Attach node/validator identity using the deployment's log labels. Capacity deferral is not pool eviction; candidate-payload execution is not finalized inclusion. Enable detailed tracing selectively: it has cost and is not a lossless audit trail. Absence of a log is not evidence of absence. Metrics use bounded reason labels, never transaction hashes.

## Profile

Historical profiling needs only `[source]` and `chain_id`; it does not require service state.

```sh
tempo-replay profile --config tempo-replay.toml \
  --from-block 120000 --to-block 123456 --output workload-profile.json
```

The immutable report binds its range to exact block hashes and includes transaction families, nonce/expiry usage, encoded bytes/gas, validity bounds, and peak block/sender load. Historical RPC cannot reconstruct capture latency.

## Deployment boundaries

Endpoints require HTTPS; optional private CAs and bearer-token environment variables are supported. Redirects are disabled. Chain IDs, checkpoint hashes, and finalized ancestry are checked. P2P isolation, validator/chainspec/binary compatibility, and capacity planning remain deployment responsibilities. This is still a finalized-transaction mirror, not a production-ingress proxy or deterministic mainnet block executor.
