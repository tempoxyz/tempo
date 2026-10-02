# Speculative execution measurements

Experimental implementation, disabled by default. This is **not** evidence that
execution is no longer the bottleneck in a live Tempo node.

Enable node validation and payload building with:

```sh
tempo node --execution.threads 16 --execution.batch-size 128
```

Run correctness checks and the in-memory throughput benchmark:

```sh
cargo test -p tempo-evm --lib
cargo test -p tempo-node --test it 'tip20::test_tip20_transfer::parallel'
CARGO_PROFILE_RELEASE_LTO=false CARGO_BUILD_JOBS=16 \
  TEMPO_BENCH_COUNTS=10000,25000,50000,100000 \
  TEMPO_BENCH_WORKERS=0,4,16,32 \
  cargo test -p tempo-evm --release execution_throughput -- --ignored --nocapture
```

`workers=0` is the existing sequential EVM. Counts are **transactions per run**,
not offered TPS. The `tps` column is completed transactions divided by measured
execution time. This benchmark does not model an offered-load queue.

The timer includes speculative scheduling, database reads, conflict validation,
replays, receipt construction, and state commits. Signing, initial state setup,
networking, consensus, disk I/O and trie hashing are excluded. After each run,
the harness compares the complete receipt vector and calculated Ethereum state
trie root to the sequential run. These are generated workloads with a warm,
in-memory database and the T0 execution environment; they are not historical or
end-to-end node benchmarks.

Workloads:

- `storage`: one distinct SSTORE per sender, with no fees.
- `compute`: 500 KECCAK256 iterations per transaction, with no fees.
- `tip20`: independent funded pathUSD transfers, with no fees.
- `tip20_paid`: the same transfers with a nonzero gas price, sharing fee state.

## Host and results

Measured 2026-10-02 using Rust 1.96.1 on an AMD EPYC 4585PX with 16 physical cores,
32 logical CPUs, and 62 GiB RAM. Release optimizations, LTO disabled, batch size
128. Each cell below is one timed run; no confidence interval is claimed.

`initial.tsv` is the initial per-transaction-worker implementation.
`worker-reuse.tsv` includes account prefetching and reuse of each worker's EVM.

At 100,000 transactions in `worker-reuse.tsv`:

| Workload | Sequential TPS | 4 workers | 16 workers | 32 workers |
| --- | ---: | ---: | ---: | ---: |
| Storage | 505,772 | 266,723 | 289,897 | 167,655 |
| Compute | 7,591 | 26,631 | 61,373 | 74,482 |
| TIP-20, no fees | 179,939 | 102,152 | 94,532 | 86,623 |
| TIP-20, paid | 115,046 | 52,389 | 55,060 | 41,943 |

Compute improves by about 9.8x with 32 workers. All cheap workloads remain slower
than sequential execution. Paid transfers replay 99,218 of 100,000 transactions:
fee-manager balances and validator fee counters are actual shared dependencies.
Ignoring these conflicts would produce incorrect state. A payment optimization
must preserve intermediate balance observations, overflow behavior, gas and logs.

`adaptive.tsv` adds scheduling backoff: after a window with fewer than one eighth
of its speculative results reused, the next eight windows execute sequentially.
The scheduler then probes again. This changes scheduling only; every reused
result still passes all dependency checks. A regression test verifies both the
backoff and the return to parallel execution.

At 100,000 transactions, the adaptive implementation measured:

| Workload | Sequential TPS | 16 workers | 32 workers |
| --- | ---: | ---: | ---: |
| Storage | 519,261 | 276,899 | 173,371 |
| Compute | 7,832 | 74,652 | 74,461 |
| TIP-20, no fees | 182,336 | 96,797 | 69,147 |
| TIP-20, paid | 115,821 | 96,677 | 94,944 |

Backoff reduces paid-transfer replays from 99,218 to 11,049 per 100,000
transactions. It does not make shared fee writes commute or replay individual
execution phases. Independent cheap transactions still pay scheduling overhead.

`final.tsv` uses Alloy's fast hash maps for speculative read caches and caps each
window's total declared gas at the block gas limit. The benchmark block gas limit
is 500M, matching the local node trials. At 100,000 transactions:

| Workload | Sequential TPS | 16 workers | 32 workers |
| --- | ---: | ---: | ---: |
| Storage | 529,535 | 300,809 | 179,508 |
| Compute | 7,552 | 58,832 | 73,458 |
| TIP-20, no fees | 186,396 | 107,860 | 82,226 |
| TIP-20, paid | 116,694 | 103,149 | 100,478 |

The variation between single runs, especially the 16-worker compute results,
requires repeated measurements before drawing smaller performance conclusions.
The stable conclusion is substantial compute scaling and continuing overhead on
cheap transactions. The local node matrix predates this last read-cache change.

## Local node trials

Build the actual node and load generator, then run isolated trials:

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_BUILD_JOBS=16 \
  cargo build --release -p tempo -p tempo-bench
python3 benchmarks/parallel-execution/run_node.py \
  --output /tmp/tempo-node-trials --duration 5 \
  --targets 10000,25000,50000,75000 --workers 0,16
```

The driver starts a fresh dev node for each trial, with the repository test
genesis, 100 funded accounts, 100 ms target block time, 500M block gas limit,
prewarming disabled, loopback RPC, and no peers. Node and load generator share
this host. The enlarged pool and RPC connection limits are recorded in each
trial's `commands.json`. Two-dimensional nonces are the default; each transaction
therefore creates a fresh nonce storage entry. This is not distributed consensus
or a large production state database.

The load generator bounds concurrent gas-estimate initialization, distributes
signing across runtime tasks, limits the initial send burst, reports generation
failures, and drains accepted transaction hashes before ending the report range.
The existing `latency_ms` report field measures **block timestamp spacing**, not
transaction confirmation latency. Accepted RPC submissions are not confirmations.

`node/matrix-2d-*.json` retains reports, busy-block payload timings, and speculative
counter deltas from the fresh-node matrix. Actual accepted submissions per second:

| Target TPS | Sequential | Adaptive, 16 workers |
| --- | ---: | ---: |
| 10,000 | 9,999 | 10,012 |
| 25,000 | 17,286 | 16,559 |
| 50,000 | 17,256 | 16,539 |
| 75,000 | 17,409 | 16,582 |

All accepted transactions in these eight trials were included; no generation,
submission or confirmation failures were reported. The higher targets were not
achieved. At the 50k target, the adaptive run spent 2.713 s in the transaction
execution section and 1.022 s finishing busy payloads (4.257 s total building).
The execution section includes pool iteration and speculative scheduling, and
does not isolate interpreter time. These measurements do not establish that
execution has ceased to be a bottleneck.

Earlier `node/sequential-*.json` and `node/speculative-*.json` trials used expiring
nonces, default queue sizes, and the load generator before parallel signing.
Both modes accepted and confirmed the 10k and 25k target workloads. The 50k
target runs fell short and left accepted transactions unconfirmed. The dev
engine also rejected some empty catch-up blocks with equal parent/child
timestamps. `node/adaptive-*.json` records intermediate diagnostic runs, including
a run whose client concurrency exceeded the default RPC connection limit. These
are retained as failed/limited trials, not successful throughput results.

The expiring-nonce ring has 300,000 entries and cannot evict an unexpired entry.
Sustained 50k TPS with 25-second expiry would exceed that protocol capacity.
Use two-dimensional nonces or shorter expiry windows for longer high-rate
experiments; changing the ring rules is outside this execution optimization.

## Canonical replay

The new read-only command compares complete execution results and state deltas,
then checks canonical stored receipts, gas/receipt-root validation, and state root:

```sh
tempo parallel-replay --chain /path/to/genesis.json --datadir /path/to/node-data \
  --from 1000 --to 1100 --threads 16 --batch-size 128 --output replay.tsv
```

Bounds are inclusive. The database must retain parent state and canonical
receipts. Backoff is disabled in this command so all windows exercise speculative
validation. The execution timers exclude trie hashing; sequential runs first,
so the timing columns are diagnostic and may have unequal cache warmth.
Historical trie reconstruction can be expensive far behind the database head.

`local-replay-10k.tsv` and `local-replay-25k.tsv` verified all 74 local canonical
blocks from the corresponding load trials: 174,885 user transactions plus 74
system transactions. Both executors matched complete state deltas, canonical
receipts and canonical state roots. The 10k replay overlapped a test compilation;
its timing columns should not be used as throughput measurements. These are
stored generated-chain blocks, not mainnet or testnet history.

## Correctness model and integration

Workers execute against a frozen batch view. Database cache misses are served on
the database's owning thread, supporting Reth providers that cannot be shared
between threads without unsafe code. Accounts named by a transaction are prefetched;
other reads are cached on demand. Every read is recorded, including reads in
transaction validation, native precompiles and reverted calls. Before reusing a
result, its transaction and environment must match and every read must still
match the committed prefix. Conflicting transactions and speculative errors run
again through the ordinary EVM.

Windows are bounded by both transaction count and total declared gas. Candidates
that do not fit the speculative gas budget retain the ordinary execution path.
Runtime configuration changes, custom fee charging, inspectors and custom
instruction/precompile configuration also retain that path.

The existing block executor owns gas-limit checks, section transitions, receipts,
state hooks and ordered commits. Known block bodies supply bounded lookahead for
validation; subblocks supply bounded batches while building. The proposer uses a
separate pool iterator for speculative candidates so speculation cannot change
invalidation or payment-lane switching on the authoritative iterator. Inspectors
and custom precompiles retain the ordinary execution path.

The generated suite covers storage dependencies, original-value gas changes,
nonce chains, reverted reads, contract creation, transient storage isolation,
TIP-20 fees, AA multicalls and two-dimensional nonces across T0/T1B/T3/T4,
shared sponsored expiring nonces across T1 through T4, keychain spending limits
and revocation, SELFDESTRUCT balance dependencies, environment changes,
configuration changes, and thread-bound database/panic behavior. A block-executor
differential check also compares actual receipts and ordered state hooks.

## Outstanding goal work

- Reduce cheap-transaction scheduling and read-validation overhead.
- Avoid full payment replays without changing fee behavior or contract observations.
- Expand AMM liquidity, authorization/delegation, hardfork-boundary and adversarial
  differential coverage, including independent implementations or state-test corpora.
- Replay historical blocks against verified parent state and canonical receipts and
  roots. The public Moderato endpoint returned HTTP 403 from this host; no historical
  mainnet/testnet replay is claimed. The local replay harness is available.
- Sustain 50k+ actual node TPS, measure transaction confirmation latency, and profile
  execution separately from pool iteration and block finishing on a larger host.
  The local offered-load matrix does not meet this acceptance criterion.
