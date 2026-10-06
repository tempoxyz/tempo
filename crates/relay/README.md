# Tempo relay

`tempo-relay` is an embeddable Rust JSON-RPC relay with ordered middleware,
immutable post-fill capability enrichment, and an optional fee-payer signer.
The `tempo-relay` binary runs the same engine as a loopback sidecar.

## Development node

```sh
cargo run -p tempo -- node --dev
```

The development chain (1337) starts a relay at `http://127.0.0.1:8547` and
enables the node's HTTP RPC. Change its port with `--dev.relay-port` (zero
chooses an available port), or disable it with `--dev.relay-disable`.
Non-dev nodes and other chain IDs do not start a relay.

The automatic relay uses the first account from the public Hardhat test
mnemonic, already funded in the dev genesis. It is independent of
`--dev.mnemonic`, which controls node development accounts. Its key must
never hold real funds. The fixed sponsored fee token is pathUSD; sponsored transactions
are limited to 30 million gas and a maximum fee per gas of 100 billion.
These per-transaction limits are not a production spending budget.

Use the relay as the sponsorship endpoint for Alloy's
`TempoProviderBuilderExt::sponsor`. A viem client can use one plain
`http(relay)` transport with `feePayer: true`; `withRelay` is only needed to
split node and relay endpoints. Set `feePayer: false` to opt out of the
development relay's default sponsorship, including when the sender is the
development sponsor itself.
`TempoRelayProviderExt` adds typed fill, sign-only, configuration, operation,
and approval calls to Alloy providers.

## Standalone sidecar

```sh
cargo run -p tempo-relay-bin -- --upstream http://127.0.0.1:8545
cargo run -p tempo-relay-bin -- --dev --upstream http://127.0.0.1:8545
```

Without `--dev`, no signer is loaded. Fills select a funded, liquid fee token
and attach simulation capabilities; native multisig RPCs coordinate approvals.
`--dev` enables the
public development signer only after checking upstream chain ID 1337. A custom
`--mnemonic` needs an already-funded first account. The executable binds only
loopback; embed the crate to add authentication, quotas, production signers,
or other access policies. `--preflight` adds an optional final gas-estimation check
in addition to the default balance-diff simulation capability.
Sponsored preflight uses zero fees because the unsigned transaction cannot yet
identify its fee payer; it does not check sponsor solvency or fee-dependent behavior.

The default store is `sqlite://tempo-relay.sqlite`. Override `--store`, or set
`TEMPO_RELAY_STORE` to a SQLite/Postgres URL (use the environment for database
credentials). The automatic node relay stores `relay.sqlite` inside its node
data directory. SQLite uses WAL plus `BEGIN IMMEDIATE`; Postgres uses transaction-
scoped per-key advisory locks, including keys whose rows do not exist yet.
Neither adapter substitutes process-local locks for database atomicity.
Use `--fee-token-candidate` for additional liquidity candidates and
`--allow-fee-payer https://...` for explicitly permitted external sponsors.

## Embedding

```rust,no_run
use std::sync::Arc;
use tempo_relay::{Relay, http::HttpBackend};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let relay = Relay::new(Arc::new(HttpBackend::new("http://127.0.0.1:8545")?));
# Ok(())
# }
```

Implement `Backend` for an in-process downstream, `Plugin` for middleware and
post-fill capabilities, and `FeePayer` for a remote signer such as Horcrux.
Disable default features to omit the HTTP server/client adapter dependencies.
The engine permits one signer, rejects conflicting capabilities before signing,
validates sponsor chain/token/fee limits, preserves sender signatures, and
does not automatically retry uncertain broadcasts. Request middleware runs
before raw-transaction signing; post-fill hooks cannot mutate the transaction.

Use `with_multisig(store, chain_id)` to enable coordination, `FeeTokens` and
`Simulate` for preview plugins, and `ChainRouter` for embedded multi-chain
deployments. Chain IDs in request bodies and explicit overrides must agree;
unconfigured chains fail closed. `Sponsor::with_policy` supports async approval
and named rejection reasons; `with_observer` awaits recording before any
broadcast. A recording failure refuses sponsorship. Prepared fills skip the
downstream fill, but still run middleware and immutable enrichment. A multisig
fill defers fee-payer signing until the complete owner quorum exists.

Each multisig operation is scoped to its chain, config commitment, account,
version and payload hash. Approvals are recovered, deduplicated by owner and
reduced to a deterministic weighted quorum. Pending operations expire after
30 days. Config-update call candidates are cached without bypassing subsequent
on-chain commitment validation. A fenced 30-second submission lease is renewed
during slow signing/broadcasts; exact final bytes and candidate transaction hash
are committed before broadcast. After cancellation, restart or a transport error,
the relay reconciles that hash before allowing resubmission. A timeout never
proves that the node did not accept a transaction.

The HTTP adapter handles positional JSON-RPC requests, IDs, batches (up to 100),
notifications, and downstream error data. Request bodies are limited to 2 MiB;
HTTP downstream requests time out after 30 seconds and relay requests after
60 seconds. Fill work, including callbacks, has a configurable 10-second deadline.
Batch requests execute sequentially. WebSockets and named parameters are not
supported by this HTTP adapter. External fee payers require an operator allowlist;
the safe default rejects HTTP, loopback/private literal hosts, and redirects.

## Compatibility reference and draft acceptance gates

The relay implementation is compared against viem commit
[10b921e509f3fb63c13a7188e83c9c21ba0b8bbd](https://github.com/wevm/viem/commit/10b921e509f3fb63c13a7188e83c9c21ba0b8bbd), with viem 2.56.8 / ox 0.14.45
client and byte fixtures. The released viem package does not export the new
`Relay` API, so the reference test imports that API directly from its pinned
source checkout. `reference.mjs` executes the actual implementation, rather
than a handwritten JavaScript port. `fixtures.mjs` regenerates deterministic
public test-key fixtures with ox; it contains no production credentials.

| Surface | Rust implementation / validation |
| --- | --- |
| Middleware and fill enrichment | Ordered forwarding, concurrent immutable hooks, conflict guards, bounded deadline |
| Sponsorship | Fill/sign/send/sync, marker and service codecs, policy/recording hooks, one custody boundary |
| Native multisig | Config, operation, raw approval/sync and key-authorization approval; weighted owner recovery |
| Durable coordination | SQLite/Postgres CAS adapters, config invalidation, candidate configs, leases and reconciliation |
| Previews | Deployless liquidity/preference snapshot, fee rounding, transfer/allowance diffs, virtual targets and opt-in reverts |
| Routing and clients | Explicit chain routing, external-sponsor allowlist, typed Alloy capabilities and viem/ox HTTP flow |

This PR's consensus types do **not** implement native multisig type `0x05`, its
factory, or the native multisig precompile. The relay codec deliberately does
not add unsupported variants to consensus types. Native execution acceptance
must run against a protocol-capable downstream; the default unit tests simulate
that node and verify the relay/client wire contract.
Live acceptance passes against `joshie/configurable-t14-devnet-checkpoint`
at `baf38b399d6fe59eb69864f34ad9e266b3eb2aff`, using its dev genesis with
`multisigRecoveryFactory` set to `0x7171717171717171717171717171717171717171`
and T14 active from genesis. It covers a sponsored two-owner transfer, pending
and completed restarts, eight concurrent approvals, a two-owner access-key
grant and subsequent sponsored access-key transfer, configuration rotation,
and execution under the new threshold. These are real node executions, not
the simulated downstream used by the default unit tests.
The real Postgres multi-instance CAS and accepted-submission recovery test
also passes against a disposable loopback database. The PR remains draft
for review; these checks do not establish production readiness.
This is development software, not a
production sponsorship service: authentication, shared spend budgets, network
policy and production custody must be supplied by an embedding. `FeePayer`
allows remote custody but does not itself implement a Horcrux transport.
Automatic `tempo node --dev` startup is live-tested with a locally rebuilt node:
the relay enables HTTP RPC, creates its SQLite store in the data directory,
and sponsors plain-HTTP viem transactions. The native-account check uses the
standalone relay against the separate configurable-accounts node branch;
that branch's protocol changes are not included in this relay PR.

The embedded preflight bytecode and error catalog derive from viem; its MIT
license is retained in `VIEM-LICENSE`. The bytecode is the constant in
`src/tempo/internal/relay/preflight.ts`, built from `RelayPreflight.sol` in the
pinned source checkout. Revalidate these assets when updating the reference.

## Validation

```sh
cargo test -p tempo-relay --features storage
cargo check -p tempo-relay --no-default-features
cargo test -p tempo-alloy provider::relay
cargo test -p tempo dev_relay_flags
cargo +nightly clippy -p tempo-relay -p tempo-relay-bin --all-features --all-targets -- -D warnings
```

The Rust suite includes byte fixtures generated with ox 0.14.45 for viem's zero
fee-payer marker and `0x78` fee-payer format, alongside Alloy's canonical and
service encodings. It verifies sender/hash preservation and rejects spoofed
sender addresses, wrong chains, excess fees, trailing bytes and capability conflicts.

To exercise unchanged viem and Alloy clients against the running dev node:

```sh
npm --prefix crates/relay/tests/interop ci
cargo test -p tempo-relay --features storage unchanged_viem_client_coordinates_over_http -- --ignored
npm --prefix crates/relay/tests/interop test
cargo run -p tempo-alloy --example development_relay
```

Set `TEMPO_RPC_URL` and `TEMPO_RELAY_URL` to override the local endpoints.
These checks submit transactions only to a loopback node with chain ID 1337.
The viem check uses a non-expiring nonce key for its first transaction so a
fresh dev chain at genesis timestamp zero can bootstrap before testing fills.

To verify the automatically started relay, build and start the relay-enabled
node with `cargo run -p tempo -- node --dev`, then run
`npm --prefix crates/relay/tests/interop run node-live`. The test uses a
non-expiring nonce for the first block and checks sponsor identity, receipt
hashes, and sender balances without `withRelay`.

For native acceptance, build the configurable-accounts checkpoint node, copy
its `crates/chainspec/src/genesis/dev.json`, set the recovery factory above,
and start it with `node --dev --chain /path/to/genesis.json --http`. Build the
standalone relay from this PR and run:

```sh
TEMPO_RELAY_BINARY=/absolute/path/to/tempo-relay \
  npm --prefix crates/relay/tests/interop run native-live
```

The test starts and restarts its own sidecar and temporary SQLite store; do
not start another relay on that port. Both live tests require Node 24 and the
pinned interop dependencies. Use the endpoint environment variables above
to select different loopback ports. Fresh timestamp-zero genesis cannot
estimate viem's default expiring nonce until the first block exists.

To run the pinned reference test, check out the specified commit of
`wevm/viem`, make the interop `node_modules` available from that checkout, then
run `VIEM_REFERENCE_DIR=/path/to/viem npm --prefix crates/relay/tests/interop run reference`.

The dedicated `Relay acceptance` CI job also starts disposable Postgres 16 and
runs the multi-instance CAS and accepted-submission restart test. To run it
locally, set `TEMPO_RELAY_TEST_POSTGRES` to a loopback database named
`tempo_relay_test` and run
`cargo test -p tempo-relay --features storage postgres_multi_instance_cas_and_submission_recovery -- --ignored`.
That test refuses non-loopback hosts and other database names.
