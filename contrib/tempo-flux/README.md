# tempo-flux

A from-scratch Tempo node built on [flux](https://github.com/gattaca-com/flux):
one pinned tile per core, and all communication goes through shared-memory
spine queues. Transaction bytes and block bodies ride in the queues' dcache.

## Dataflow

```
loadgen/ingress --RawTx--> verifier x N (collaborative group) --ValidTx--> builder
consensus --BuildRequest--> builder --Block--> executor, storage, consensus
executor --StateDiff--> merkle --Executed--> consensus --Finalized--> storage --Persisted--> consensus
```

| Tile | Today | Next |
|---|---|---|
| loadgen | replays presigned EIP-1559 transfers at a fixed rate | p2p gossip and JSON-RPC ingress tiles (flux-network) |
| verifier xN | decode TempoTxEnvelope (incl. 0x76 AA: secp256k1/P256/WebAuthn), recover sender; shares RawTx collaboratively | Tempo 0x76 txs, fee-token and stateless checks, admission control |
| builder | per-sender nonce-ordered pool, assembles blocks | fee ordering, payment lanes, arena-allocated pool |
| consensus | single-validator dev mode, one block per slot | Simplex BFT (threshold sigs, DKG) as a tile set: votes, certs, p2p |
| executor | Tempo's block executor from tempo#7871 (evm2, Tempo precompiles, TIP-20 fees via the fee AMM, payment lanes, pre/post system calls) over the node's in-memory state; applies each block's bundle | Tempo precompiles (TIP-20 fees, 0x76 txs), persistent state, parallel execution |
| merkle | applies diffs to an incremental in-memory MPT that caches node hashes (`trie.rs`); `--verify-root` checks it against a full recompute | parallel subtries across cores, disk-backed nodes |
| storage | io_uring append log of finalized blocks, fsync, latency report | state DB, trie and state root, sync |

## Layout

Standalone workspace, not a member of the root one. Tempo's execution crates come
from tempo#7871 (Tempo on evm2), pinned by commit, and flux from gattaca-com/flux.
Needs Rust >= 1.96.

## Run

```
cargo build --release
./target/release/tempo-flux --tps 200000 --max-txs 400000 --accounts 50000 --presigned 4200000 \
  --duration-secs 20 --first-core 4 --verifiers 12 --exec-threads 10 --exec-first-core 22
```

## First numbers

Measured on dev-dst (Xeon Gold 6526Y, 32 cores) with 500 ms slots. Latency is
the oldest tx in each block, from ingress to fsync of the finalized block.

- 20k TPS, 4 verifiers: sustained, p50 ~505 ms, so the pipeline adds ~5 ms over the slot.
- 100k TPS, 12 verifiers: verifiers top out around 75k TPS. The broadcast
  queue then laps them, dropped txs leave nonce gaps, and throughput collapses.
  Ingress needs explicit admission control (reject instead of silently drop).

## With real execution (evm2 + MPT root)

Needs Rust >= 1.96 (evm2's MSRV); on dev-dst build with RUSTUP_HOME=~/.rustup.

Same machine, 20k TPS of 10k-transfer blocks, 500 ms slots:

| Accounts | exec per block | state root per block | ingress to fsync p50 |
|---|---|---|---|
| 2k | ~8.5 ms p50, 12 ms max (evm2; revm was 7-11 ms) | ~2 ms | ~511 ms |
| 200k | ~11 ms | ~126 ms (full recompute, linear in accounts) | ~641 ms |

The state root is the next bottleneck: it has to become incremental.

## Incremental state root

200k accounts, 20k TPS (10k transfers per block), same machine:

| Root | per block p50 | max | ingress to fsync p50 |
|---|---|---|---|
| full HashBuilder recompute | ~126 ms | ~126 ms | ~641 ms |
| incremental trie | ~26 ms | ~38 ms | ~542 ms |

The incremental root matched a full recompute on every block of a 20-block
`--verify-root` run, and `trie.rs` has a randomized test against HashBuilder.

## Tempo execution and max throughput

Load: 0x76 AA transactions, each a pathUSD `transfer` paying its fee in pathUSD,
50k senders, genesis seeded like tempo's tip20 bench (TIP-403 registry, TIP-20
factory, pathUSD, fee manager, nonce manager). Mainnet hardfork (T12), 500 ms
slots, 16 verifier tiles, dev-dst (Xeon Gold 6526Y). No reverts, no failed blocks,
no dropped transactions in any run.

| Offered TPS | Sustained TPS | Execution | State root | Ingress to fsync p50 |
|---|---|---|---|---|
| 30k | 30k | 15k txs in ~322 ms | | ~0.95 s, steady |
| 35k | ~32k | 26k txs in ~580 ms | ~160 ms | ~1.5 s, growing |
| 40k-50k | ~36k (30k-tx block cap) | 30k txs in ~650 ms | ~170 ms | grows without bound |

Max sustained throughput is about 32-36k TPS. The bottleneck is sequential
execution: ~22 us per Tempo transfer at 50k accounts (~13 us at 2k), on one
core, followed by the state root (~5.5 us per tx), and a block's next build
waits for both.

## Parallel execution

`--exec-threads N` splits each block's transactions by sender across N pinned
worker threads, each running Tempo's block executor over the same pre-block
state. Bundles merge by summing deltas on pathUSD and fee-manager slots (balances
and collected fees, which every transaction touches); any other cross-shard
write re-runs the block sequentially. `--verify-parallel` re-executes every
block sequentially and asserts identical state and gas.

Same load as above (0x76 pathUSD transfers, 50k senders), 12 verifiers, 10
execution threads, 500 ms slots. No drops, reverts, failed blocks or fallbacks:

| Offered TPS | Sustained | Execution per block | State root | Ingress to fsync p50 |
|---|---|---|---|---|
| 40k | 40k | 20k txs in 68 ms | 92 ms | 0.68 s |
| 100k | 100k | 50k txs in ~165 ms | 151 ms | 0.86 s |
| 200k | 200k | 100k txs in ~272 ms | 151 ms | 1.01 s |
| 240k | ~240k | ~131k txs in ~349 ms | 151 ms | ~1.17 s, steady |
| 280k | no | ~175k txs in ~450 ms | 151 ms | grows (2.2 s to 2.7 s) |

Ceiling is about 240k TPS on dev-dst, up from ~35k sequential. Verified runs
(parallel against sequential, incremental against full root) matched on every block.

Caveats: summing deltas is exact only for balance-like slots and while no
transaction branches on a concurrently written balance. Overwrites that make
the sum wrap, a failing shard and blocks over the gas limit fall back to
sequential execution, but non-wrapping overwrites (an allowance set by
approve in one shard and spent in another) still merge wrongly. General blocks
need read-set validation (Block-STM style) before this is safe. The builder
also tracks only the default 2D nonce key per sender.
