# tempo-metabinary

Lets a release drop the execution rules of every hardfork older than
`TempoHardfork::MINIMUM_SUPPORTED` and still serve full history. Blocks of a frozen era are executed
by a separately built era binary that shares the node's storage. Operators keep running `tempo node`
with the same arguments, and the live binary never executes a frozen block.

![Request routing between the live node and frozen era workers](assets/routing.svg)

The crate is execution-independent. The `tempo` binary supplies the chain adapter (`eras.rs`), the
`rpc-only` worker, the startup handoff (`history.rs`), and `re-execute` delegation.

## Catalog

The built-in catalog is `bin/tempo/eras.json`. A `tempo-eras.json` beside the executable supersedes
it, and relative binaries resolve against its directory.

```json
{"chains":[{"chain_id":"0x1079","eras":[
  {"until":"T12","binary":"eras/tempo-genesis-t11",
   "checkpoint":{"number":43957544,"hash":"0x6c85…e452"}}]}]}
```

`until` is the first hardfork an era does not execute, and its activation timestamp ends the era:
block `b` is in era `i` when `boundaries[i-1] <= b.timestamp < boundaries[i]`, and era
`boundaries.len()` is live. `checkpoint` is the era's last canonical block.

Only unmodified built-in mainnet and Moderato specs use the catalog. Custom genesis files (even with
the built-in genesis hash), dev chains, and zone chains run natively, so they must activate the
floor at genesis.

## Workers

A worker is a frozen binary running `tempo rpc-only`: read-only RPC over the shared datadir on one
loopback port (HTTP and WS), without consensus, networking, or a pool. It inherits the node's
genesis, storage paths, and `EthConfig`, and answers `tempo_executionInfo`, which the node checks
before use. That handshake detects port collisions, it is not authentication.

Workers start on first use and are shared by concurrent callers. A failed start is retried after
30 s, workers idle for 5 minutes are stopped, and every child is reaped (SIGTERM, then SIGKILL after
10 s). An unavailable worker is `-32000`, a method it lacks `-32004`, and its call errors and raw
results pass through verbatim.

## Routing

Each request runs in its rule era, whose binary owns the rules it executes under. Only execution
callbacks are replaced, so transports keep their auth, limits, batching, and subscriptions, and
live requests reach the original callback with their original params.

| Requests | Rule era |
|---|---|
| `eth_call`, `eth_estimateGas`, `debug_traceCall`, `trace_call*`, block tracing and witnesses | Selected block |
| `eth_feeHistory` | Newest block |
| Transaction tracing | Containing block, live if pooled or unknown |
| `eth_callBundle`, `eth_callMany`, `debug_traceCallMany` | Base block |
| `eth_simulateV1`, `tempo_simulateV1` | Explicit block times, else the base block |
| `mev_simBundle` | Override time, else the parent block |
| `debug_traceBlock` | The RLP header |
| `trace_filter`, `reth_getBlockExecutionOutcome`, `traceChain` | Split per era |

Reviewed non-executing methods stay native, and any other method fails with `-32004`. Selected
blocks are pinned before forwarding, keeping explicit hashes and `requireCanonical` verbatim.

Reth derives the fork from the base header and only patches block-env fields, so block overrides
never change the era. Only methods that generate a block read override times, and simulations whose
explicit times span eras fail with `-32004` because speculative state never crosses processes.
Callers near a boundary should pass explicit simulated times.

Canonical ranges run per era in block order from canonical state and merge like one native call:
`trace_filter` pages once over the concatenated traces after checking the whole range,
execution outcomes merge after a strict contiguous decode, and `traceChain` relays one upstream
subscription per segment under the client's subscription ID.

## Handoff and re-execution

Before `tempo node` opens storage, each frozen era the durable head hasn't reached is synced by its
binary as `node --history-sync` with the operator's arguments, bounded at the era's checkpoint. If
finality is still within the frozen eras, consensus then bootstraps from a verified finalization,
replays or syncs execution to it, caches the executed tail for offline restarts, and persists
finality only through the durable prefix.

`tempo re-execute` runs frozen parts of its range in their era binaries and the rest in-process.

## Frozen artifacts

A frozen binary must reproduce its era's rules exactly, support the shared storage layout, implement
`rpc-only` (with `--rpc-config`, WS `debug_subscribe`, and `tempo_executionInfo`) and
`node --history-sync`, and reject specs at or above `until`. Source builds must build it separately.
