# Native TIP-20 light client

`tempo node --light` runs a read-only, checkpoint-backed native TIP-20 client. It authenticates
finalized Tempo headers and account/storage MPT proofs from untrusted HTTP upstreams, then decodes
balances, allowances and total supply locally. There is no unverified fallback, EVM execution,
transaction pool, signing, validator participation, state sync, or execution database.

**Status:** the native library, independent daemon startup, HTTP transport, durable checkpoints,
and minimal local API are implemented. Production acceptance is still incomplete: subscription
transport, expanded fault/crash/pruning/load tests, and representative client/RPC-server performance
measurements remain outstanding.

## Start the daemon

```sh
tempo node --light --chain moderato \
  --light.upstream https://YOUR_RPC_ENDPOINT \
  --light.datadir ./moderato-light
```

Repeat `--light.upstream` for up to eight providers. `TEMPO_LIGHT_UPSTREAM` supplies one endpoint.
The selected chain supplies the chain ID, genesis hash, known signing identity and epoch length;
none are learned from RPC. The signing identity must uniquely anchor the intended consensus
network; do not reuse validator/key material across independent trust domains. Existing certificate
domain separation is unchanged, and sparse tracking is not a genesis-to-head ancestry proof.
Explicitly anchored devnet genesis files work with `--chain genesis.json`.
A certificate-free `--dev` execution node cannot serve as a finalized-consensus devnet.

The daemon dispatches **before** full-node overrides, credentials, consensus runtime, telemetry,
node builders, snapshot downloads or database startup. `--light` conflicts with `--follow`.
Explicit execution, networking, validator and full-node database flags are rejected, including
those supplied through environment variables. Only chain selection, light options and top-level
logging/tracing settings are accepted. Light-specific options require `--light`; ordinary node
and follow defaults remain unchanged.

| Option | Default |
| --- | --- |
| `--light.listen` | `127.0.0.1:8645` |
| `--light.datadir` | `$HOME/.tempo/light/<chain-id>-<genesis-prefix>` |
| `--light.request-timeout-ms` | 3000 |
| `--light.read-timeout-ms` | 15000 |
| `--light.poll-interval-ms` | 500 |
| `--light.read-concurrency` | 8 |
| `--light.account-cache` | 4096 entries |
| `--light.slot-cache` | 16384 entries |
| `--light.transition-search` | 32 boundary queries per provider |

Non-loopback binding requires `--light.allow-remote`. The HTTP API has no signing/broadcasting
methods, Ethereum forwarding or WebSocket service. Remote access has **no authentication**; place
it behind your own authenticated proxy/network controls if necessary. A hosted daemon's word
“verified” does not remove trust in that daemon unless the consumer independently verifies evidence.
Endpoint URLs are excluded from debug formatting and transport errors; redirects and environment
HTTP proxies are disabled. Use HTTPS to protect endpoint credentials in transit.

## Local API

`light_readVerified` accepts one array of latest-only requests. No caller-selected block is allowed:

```sh
curl -s http://127.0.0.1:8645 -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0", "id":1, "method":"light_readVerified", "params":[[
    {"kind":"balance","token":"0x20c0000000000000000000000000000000000000",
     "holder":"0x0000000000000000000000000000000000000001"},
    {"kind":"allowance","token":"0x20c0000000000000000000000000000000000000",
     "owner":"0x0000000000000000000000000000000000000001",
     "spender":"0x0000000000000000000000000000000000000002"},
    {"kind":"totalSupply","token":"0x20c0000000000000000000000000000000000000"}
  ]]
}'
```

The result is `{block: {hash, height, timestampMillis}, values: ["0x…", …]}`. Values are raw
unsigned token units in request order, all at the same authenticated finalized block. Height and
timestamp are JSON numbers (native clients use `u64`); values and hashes use hex encoding.

`light_status`, with no parameters, returns `head`, `headAgeMillis`, `headInFuture`, `lastFailure`,
`durable`, `integrityFailures`, `accountCacheEntries` and `slotCacheEntries`. `lastFailure` is the
most recent head-refresh outcome; the integrity counter also records rejected proof batches.
Before initial authentication there is no head and reads fail explicitly.

Errors distinguish invalid requests (`-32602`), unsupported methods (`-32601`), integrity (`-32010`),
capability (`-32011`), availability (`-32012`), persistence (`-32013`) and concurrency admission
(`-32015`). A missing/unsupported token is an invalid request, **not** a zero balance. A capability
failure never triggers a weaker root selector or raw-value fallback. JSON-RPC protocol batches
are disabled; use the snapshot-consistent read array instead.

A valid old certificate does not prove global freshness. Check `headAgeMillis`/`headInFuture`
and apply an explicit clock/freshness policy. Accepted progress is latest **known**, not a promise
that an upstream revealed the globally newest block. A valid value does not establish spendability,
payment success, issuer solvency or transfer permission.

## Library and verification boundaries

`tempo-light` has no normal dependency on `tempo-node`, `tempo-consensus`, execution, pools or an
execution database. Rust applications can use `client::Client::open`, periodically call `refresh`,
then call `read(Vec<token::ReadRequest>)` and `status`. They own the async runtime and lifecycle.
The optional `rpc-server` feature provides the same minimal daemon API; `client` is enabled by
default. Disable default features for provider-independent verification only.

- `tempo-finality` shares the existing Commonware digest, Tempo namespace, configured network
  identities, scheme provider and body-independent finalization verifier with full nodes.
  The full-node adapter retains body validation and remote-seal consistency checks.
- `HeadTracker` authenticates sparse finalized heads, rejects regression/conflicts, and installs
  key changes only from finalized boundary evidence signed by the existing key. Historical scheme
  caches are pruned. Its clone owns an independent scheme cache for staged publication.
- `Snapshot` retains one immutable complete header/certificate. New heads never restart an
  in-flight read. Proofs are requested with `{blockHash, requireCanonical: true}`, never `latest`.
- `tempo-state-proof` shares exact-target MPT verification and the synchronous authenticated cache
  with Zones. Callers use `tempo_state_proof::verify_multi_proof` directly. Every requested account and slot must
  occur exactly once; omitted, duplicate, unexpected, substituted, truncated and forged evidence fails.
  Present empty accounts are distinguished from absence, and empty-trie markers cannot hide suffix
  nodes. Verified evidence cannot be publicly forged or deserialized.
- `token::ReadRequest` derives native V1 slots locally: supply 8, balances 9, allowances 10, with
  padded address keys and nested allowance mappings. Generated precompile layout constants are
  compile-time checked against the shared helpers in `tempo-primitives::tip20`. Prefix plus
  authenticated nonempty code matches native token initialization semantics. Unsupported future
  configured layout activations fail reads rather than silently inheriting V1 interpretation.
- `VerifiedCache` holds `(state_root, account)` mappings and raw slots keyed by
  `(account, slot, authenticated storage_root)`. Batch snapshot binding and conflicts are checked
  before mutation. Token validity/decoding succeeds before client cache publication.

### Library API migration

The shared extraction is a **source-breaking migration** of the low-level cache/error APIs, not a
compatibility facade. `Client::read`, `status`, `Snapshot::verify`, and the verified-evidence accessors
keep their interfaces; canonical keys, limits and evidence are re-exported from `tempo-state-proof`.

Low-level callers must construct `VerifiedCache` with `CacheLimits` (`CacheLimits::new` for single-batch, non-retaining use), handle its
fallible, eagerly reserving constructor, and replace `commit(snapshot, batch)` with
`publish(&[(snapshot.header().state_root(), &batch)], &RetentionDelta::default())`.
`get(state_root, key)` now returns authenticated account metadata together with the raw word;
`peek_account(AccountKey)` is non-touching metadata access, and `stats()` replaces `entry_counts()`.
Proof/cache errors use the shared typed variants rather than the former light-specific variants.
Keep root selection bound to an authenticated snapshot and complete application acceptance before
publication; passing an upstream's claimed root to these root-based APIs does not authenticate it.

Certificates authenticate the canonical complete `TempoHeader`, not an RPC-supplied root summary.
Verification checks canonical hash, signed payload, response epoch/view/digest, height-to-epoch
binding and real Commonware finalization signature/VRF. Notarization is not finality. Execution
validity relies on Tempo consensus assumptions; this client does not re-execute like a certified
full `--follow` node. Same-key sparse jumps rely on consensus safety, not an independently checked
parent link for every skipped height.

Complete non-membership authenticates a zero slot only for an initialized supported token.
Absent accounts and empty tries are supported by the raw proof API, but absent token accounts
are rejected by typed reads. Never-written and cleared slots cannot be distinguished by normal
EVM storage commitments. Missing proof evidence is never interpreted as zero.

The low-level finality boundary-registration API retains the caller-trusted ancestry contract
needed by existing full-node consumers. Untrusted light-client discovery uses `HeadTracker`'s
stricter authenticated transition API, not arbitrary registration of RPC extra data or the existing
contiguous stream's caller-trusted initial block.

## Transport, scheduling and resource limits

Compact HTTP polling is bounded and has no per-head backlog. One authoritative tracker is shared
by all upstreams. Signature mismatches may cause a bounded backwards boundary search; suggested
identities are never adopted without an authenticated transition. Large downtime with many key
changes can exceed search/deadline bounds and fail explicitly; adjust limits or use a locally
trusted updated anchor, not RPC-discovered trust.

Proof transport prefers `eth_getMultiProof`, falling back to hash-pinned `eth_getProof` **only**
on method-not-found. Standard proofs have concurrency two and a shared response-byte budget.
Provider lag, unavailable execution state or pruned proofs fail over within the operation deadline.
All reads retain their original block; no “helpful” older/latest root substitution is permitted.
Upstreams must retain a recent proof window covering in-flight requests (Reth's
`--rpc.eth-proof-window`), and required historical boundary certificates for catch-up. The devnet
harness configures 128 blocks; choose a production window from cadence/deadline/pruning budgets. Ordinary reads do not require an archive.

Identical in-flight reads share one owned job. Distinct reads have bounded, non-queuing admission;
blocking proof workers retain admission permits after asynchronous deadline expiry until they
finish. Typed batches derive ordered storage keys once before admission and deduplicate missing proof
targets after cache lookup. The daemon also caps inbound API handlers/connections at 64, request bodies
at 64 KiB and responses at 256 KiB.

Defaults cap upstream response bytes at 8 MiB per provider proof attempt, read batches at 128,
proof accounts at 64, slots at 1024, aggregate nodes at 65536, nodes at 4096 bytes and aggregate
proof bytes at 8 MiB per verification stage. A read has one proof stage for all missing slots,
sharing one operation deadline and admission permit across failover; each configured provider
can be attempted once. Head certificates are at most 16 KiB and extra data at most 1 MiB.
These are provisional safety ceilings, **not measured production budgets**.

Reads capture authenticated cache hits at the selected root and request full account/storage proofs
for all missing slots directly. Active payment tokens commonly change their whole storage root,
even when the requested holder's balance is untouched; speculative account-only proofs would then
add a sequential RPC round. There is no strategy option or account-only probe.
Cached words remain reusable whenever their account/storage root is already authenticated at the
selected global root, including authentication established by an earlier read.

New evidence lives in one operation-owned verified batch; successful native decoding and all cache
conflict checks precede atomic publication. All-warm reads copy authenticated raw values under the
lock and decode outside it without building or republishing batch maps. A proof or decoding failure
publishes neither a partial result nor new account mappings. Independent account-mapping eviction
does not invalidate retained raw slots, but reads need authenticated account evidence at their root
before those slots can be used again.

Provider failover never weakens selectors, accepts unverified values or substitutes another snapshot.
Integrity failures remain counted, and a later availability failure does not hide earlier integrity
evidence. Cache loss/eviction never invalidates retained snapshots or operation-owned batches. Caches are
disposable, independently bounded by entries, and are not persisted as an archive. Subscription
discovery, adaptive provider health and broader batching are follow-up work.

## Durable checkpoints and recovery

The separate light directory contains `lock` and `checkpoint.json`. One writer holds an exclusive
lifetime lock. Checkpoints bind version, configured network/trust/layout parameters, current
identity, finalized head and the most recent authenticated transition. Loading is bounded and
checks the checksum, format, network binding and retained cryptographic evidence. Corruption,
unknown versions and cross-network storage fail closed; there is no silent reset or anchor change.

Publication writes a private temporary file, syncs it, atomically renames it and syncs the directory.
Accepted public progress changes **after** durable publication. A critical write failure pauses
reads and sets persistence status; subsequent successful refresh/publication can recover. Refresh
runs as an owned serialized task so cancelling its caller cannot cancel critical filesystem
publication or release the writer guard mid-write. Daemon shutdown waits for head publication.

The filesystem is a **trusted local boundary**. Earlier identity history is retained as trusted
checkpoint context, not a complete self-contained genesis-to-head proof chain after arbitrary
rotations. The checksum detects corruption, not malicious editing. Crash-safe writes do not
provide resistance to malicious filesystem rollback. Back up or replace trust/storage only via an
explicit local operator decision; do not trust a checkpoint offered by an untrusted RPC.

## Compact full-node consensus RPC

Additive endpoints preserve existing full-block RPC/subscriptions:

```text
consensus_getFinalizedHeader("latest")
consensus_getFinalizedHeader({"height": N})
consensus_subscribeFinalizedHeaders()
consensus_unsubscribeFinalizedHeaders(subscriptionId)
```

Responses/notifications contain `{epoch, view, digest, certificate, header}`. The header is complete,
including fork-activated consensus context, and the certificate is the existing hex-encoded
Commonware finalization. All fields remain untrusted until verified. Compact subscriptions exclude
notarizations/nullifications and share lazy serialization. Lagging subscribers rediscover heads;
this is not a contiguous history feed. Bodies are omitted on the wire, but the backing feed still
uses its existing block archive; no new archive or mandatory consensus execution work is introduced.

## Tests, fixtures and real-devnet demonstration

```sh
cargo test -p tempo-finality -p tempo-light --features tempo-light/rpc-server
cargo test -p tempo --lib
cargo test -p tempo-consensus --lib
cargo test -p tempo-node rpc::consensus --lib
cargo +nightly fmt
```

Generated real certificates/MPTs cover inclusion, complete absence, wrong targets/scalars/roots,
truncation/limits, key rotation, conflicts, retained snapshots, staged account-only reuse, changed-root
misses, partial cached/proved batch composition, account-mapping eviction, and atomic cross-root
merge rejection. Checkpoint tests cover exclusive locking, verified restart, interrupted temporary writes,
corruption, unknown format, changed network/layout and explicit publication failure. CLI/API tests
cover credential-free light selection, incompatible flags, endpoint redaction, loopback and method
restrictions. These unit tests alone do not satisfy real-devnet acceptance.

`fixtures/mpt-finality-v1.json` contains deterministic threshold-certificate/header-RLP/proof and
negative cases for independent consumers. It is not a production anchor. Regenerate explicitly:

```sh
TEMPO_LIGHT_EXPORT_FIXTURE="$PWD/crates/light/fixtures/mpt-finality-v1.json" \
  cargo test -p tempo-light --test proof export_conformance_fixture -- --ignored
```

The real-devnet smoke harness requires Python 3, Cargo and Foundry `cast`:

```sh
cargo build -p tempo --bin tempo
python3 scripts/light-client-devnet.py --tempo-bin target/debug/tempo \
  --workdir "$(mktemp -d)/demo"
```

It creates four actual validators from a locally configured genesis, executes mint/transfer/approve/
burn transactions, compares reads with full-node calls at the exact reported block, schedules a
full-DKG signing-key rotation while the daemon is offline, restarts from disk, and runs a malicious
scalar-changing proof proxy. It also changes another token to require fresh full proofs despite an
unchanged token storage root, asserts that neither proxy receives account-only probes, and holds
a genuine proof while a real mint advances the head. The held read must return its original
block/zero value; the next read must see the minted balance at the new root. A mixed cached/new-slot
batch with a corrupted full proof must publish neither partial values nor a new account
mapping. It checks verified failover, explicit failure without the honest provider, missing-token/
method rejection and absence of execution files in the light directory.
It emits logs, a public evidence capture and a small loopback latency report. A successful run's
header/key-transition/native storage evidence is shipped as `fixtures/devnet-tip20-v1.json` and
consumed independently by the conformance test; limited smoke measurements are recorded in
[light-client-benchmarks.md](light-client-benchmarks.md). Development keys
are public and must never hold real funds. Use a fresh workdir; existing devnets are not overwritten.
Default ports start at 13000 and can be changed with `--base-port`.

This smoke demo is not the complete acceptance suite: crash injection around rename/fsync,
proof-window/pruning races, broader malicious proxies, sustained bounded load, high-volume
tracking costs, multi-token scaling, RPC proof generation CPU/IO, and comparisons against
unverified reads still need measured coverage. Do not infer production budgets from a short
loopback debug-build run. Browser/Ox/Viem integration is a separate follow-up.
