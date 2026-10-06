# Experimental QMDB development backend

This branch ports the previous QMDB prototype to the current Tempo/Reth engine interfaces.
MPT remains the default. QMDB changes block state commitments and must not be used on
mainnet, Moderato, or with ordinary Tempo peers.

```sh
cargo build --release -p tempo --features qmdb
./target/release/tempo node --dev --state-root.backend qmdb --datadir /tmp/tempo-qmdb-dev
```

Use a fresh, separate datadir. The CLI requires `--dev`, enables payload-builder root
sharing, and persists every canonical block. Execution and ordinary RPC state reads still
use Reth's state database; QMDB replaces the header commitment, not the entire state store.
`eth_getProof` is disabled because MPT proofs cannot authenticate a QMDB root. Genesis
retains the development chainspec's original header; subsequent headers use QMDB roots.

The QMDB actor retains speculative batches for pending child blocks and commits them only
through the engine's persistence hook. Its block journal supports reopen and rewind. Startup
checks the journal against the canonical database and rewinds an ahead-of-database journal;
it refuses a canonical database that is ahead of QMDB or has conflicting hashes/roots.

## Validation and benchmark

```sh
cargo test -p tempo-qmdb-bench --test backend qmdb_builds_validates_persists_and_restarts
CARGO_PROFILE_RELEASE_LTO=false QMDB_BENCH_BLOCKS=100 QMDB_BENCH_TXS=16 QMDB_BENCH_ROUNDS=3 \
  cargo test -p tempo-qmdb-bench --release --test backend bench_mpt_vs_qmdb -- --ignored --nocapture
```

The benchmark uses the same node harness and persistence settings for MPT and QMDB.
It signs transactions outside the measured interval, then measures pool submission,
payload construction, engine validation, canonical import and durable persistence.
Each block transfers genesis-funded AlphaUSD to fresh recipients; every included
receipt must succeed. Sender token balances are checked before each run.
Ten warmup blocks are excluded per backend per round; three rounds alternate backend order.
Output includes mean, p50, p95 and observed throughput for submission/build/import, and
separately for the interval through durable persistence. The latter includes the harness's
20 ms condition-polling interval, so small durability differences are not root-only evidence.
Pool-head synchronization and receipt-success checks occur outside the timed interval.
This small-state, single-node serial workload is not a production or saturation TPS claim.

## Remaining prototype limits

- Backfill/snapshot sync, QMDB proofs and public-network interoperability are not implemented.
- New payloads must descend from the QMDB durable head or a retained pending descendant.
  Building a newly discovered fork below the durable head is not supported.
- The flat commitment retains the previous prototype's sparse storage-update semantics;
  contract wipe/destruction equivalence and broad EVM lifecycle coverage need more work.
- Speculative batches are retained in memory for this experiment; long-running fork-cache
  eviction and production resource bounds are not implemented.
- QMDB and the canonical state database are separate stores, not one atomic transaction.
  Startup reconciliation handles a QMDB-ahead crash; comprehensive fault-injection testing
  remains necessary.
- The SDK pins the prototype's coherent Commonware revision separately from Tempo's
  consensus dependencies. Upgrading that storage API is a separate task.
