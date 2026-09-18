# tempo-multiplex

Run the latest v1 node (`v1.14.0`) and a fixed-T11 v2 node as supervised child
processes behind one HTTP JSON-RPC endpoint. Block numbers below the configured
cutover go to v1; the cutover block itself and newer blocks go to v2. Hashes,
transaction hashes, EIP-1898 selectors, and finalized/safe tags are resolved
before selecting a backend. Logs and fee histories spanning the boundary are
split and combined. Writes always go to v2 and are never retried.

The design combines [Celestia's process supervision](https://github.com/celestiaorg/celestia-app/blob/main/multiplexer/README.md)
with [Optimism's historical RPC backend](https://docs.optimism.io/node-operators/guides/configuration/legacy-geth).
Unlike Celestia's ABCI arrangement, these are two complete Tempo processes with
separate databases. Never point them at the same data directory.

## Build

```sh
cargo build --release -p tempo-multiplex
cargo build --release -p tempo --bin tempo-v2 --features fixed-t11
```

Obtain v1.14.0 from the [release](https://github.com/tempoxyz/tempo/releases/tag/v1.14.0)
and verify the published archive checksum. Do not build the legacy binary with
`fixed-t11`: Cargo features are additive within a build. The multiplexer checks
v2's `tempo_executionRules` response before accepting traffic.

`fixed-t11` removes runtime Tempo hardfork selection from v2. All `is_t*` execution
predicates are compile-time constants, including disabled T12/T13 predicates.
The source retains historical identifiers, activation metadata, and the ordinary
v1 library build for SDK/chain-identity compatibility; this is **not** deletion of
all historical source code. Optimized builds eliminate the unused execution paths.
The v2 EVM refuses execution environments before the chain's T11 activation.
T11 activated at `1789048800` on mainnet and `1788962400` on Moderato.

## Prepare state

Use v1 to sync through T11 with archive state retained. Stop it cleanly, then take
two consistent checkpoint copies with the same genesis and the same block at
`cutover_block - 1`. Both copies must contain the first T11 block; v2 continues
from that checkpoint. Keep v1 isolated from block production and network sync.
v2 cannot replay a pre-T11 chain from genesis. A post-T11 pruned snapshot alone
does not supply the historical state needed by v1's calls/traces.

Choose the first block whose timestamp is at least T11's activation timestamp,
not a wall-clock estimate. Configure its parent's full hash. Startup compares the
chain IDs, genesis hashes, and that checkpoint hash before binding the frontend.

## Run

Create a JSON configuration (the paths below are examples):

```json
{
  "listen": "127.0.0.1:8545",
  "cutover_block": 123,
  "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "v1": {
    "rpc": "http://127.0.0.1:8546",
    "binary": "/opt/tempo/v1.14.0/tempo",
    "args": ["node", "--chain", "/data/genesis.json", "--datadir", "/data/v1", "--http", "--http.addr", "127.0.0.1", "--http.port", "8546", "--http.api", "eth,net,web3,debug,trace,tempo"]
  },
  "v2": {
    "rpc": "http://127.0.0.1:8547",
    "binary": "/opt/tempo/tempo-v2",
    "args": ["node", "--chain", "/data/genesis.json", "--datadir", "/data/v2", "--http", "--http.addr", "127.0.0.1", "--http.port", "8547", "--http.api", "eth,net,web3,debug,trace,tempo"]
  }
}
```

Configure distinct network, auth-RPC, IPC, metrics, and consensus ports too when
enabled by your node command. Supply v1's archive-only and v2's normal sync flags
appropriate to your network; the multiplexer passes argument arrays directly,
without a shell. Data directories must already exist and must not overlap.

```sh
tempo-multiplex --config /data/multiplex.json
```

The parent exits and stops both children if either child exits. It handles
SIGINT/SIGTERM and startup failure, and only opens its listener after validation.
Expose only the frontend, with the access controls appropriate to your deployment.

## RPC scope

HTTP individual/batch requests and notifications are supported. Responses retain
caller IDs and upstream error data. Batch size is bounded to 100, request bodies
to 2 MiB, each backend response to 32 MiB, and upstream calls to 30 seconds.
Unknown methods fail explicitly rather than guessing their historical semantics.
WebSocket subscriptions, stateful filters, custom pagination methods, raw encoded
block tracing and multi-block simulation across the cutover are not supported yet.
Do not use this prototype as a transparent replacement for every Tempo RPC API.

`tempo_multiplexStatus` reports the cutover block and checkpoint hash.

## Tests

```sh
cargo test -p tempo-multiplex
cargo test -p tempo-hardfork --features fixed-t11
cargo +nightly clippy -p tempo-multiplex --all-targets -- -D warnings
```

Routing tests use distinct HTTP backends and cover the exact boundary, tags,
hash/transaction lookups, cross-boundary logs and fees, revert data, write routing,
notifications, mixed batches, parse errors, and checkpoint disagreement.

The real-node smoke test creates a local dev chain with a future T11 timestamp,
mines through the upgrade with v1, stops it cleanly, copies the database for v2,
and launches the supervisor. It checks historical/current calls and traces,
T11's strict ABI decoding change, refusal of historical execution by v2,
cross-boundary logs/fees, clean shutdown, restart, and continued block production.
It leaves the tested endpoint running on port `18545` and prints a JSON report.

```sh
git show v1.14.0:crates/chainspec/src/genesis/dev.json > /tmp/multiplex-v1-genesis.json
MULTIPLEX_GENESIS=/tmp/multiplex-v1-genesis.json node contrib/multiplex/smoke.mjs \
  /opt/tempo/v1.14.0/tempo target/release/tempo-v2 target/release/tempo-multiplex
```
