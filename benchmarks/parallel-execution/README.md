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

`TEMPO_BENCH_WORKLOADS` selects a comma-separated subset of the workloads below.
`TEMPO_BENCH_BATCH_SIZE` changes the window (default 128; the declared-gas bound
still applies). `TEMPO_BENCH_PHASES=1` prints preparation, ordered execution and
commit times to help distinguish worker scheduling from serial replay costs.
Phase timing adds per-transaction clock reads, so compare equally instrumented runs.
`TEMPO_BENCH_STREAMING=0` waits for all workers before ordered execution, for a
comparison with streaming (the default). With streaming, ordered time includes
waiting for individual results and serving outstanding worker database reads.

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
- `compute_paid`: the same compute loop with shared fee collection and settlement.
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

## Partial call-body replay

`body-replay.tsv` adds a second reuse boundary. When a complete transaction
conflicts, validation, pre-execution and settlement run again in order, but an
unchanged call body can be reused. At 100,000 transactions:

| Workload | Sequential TPS | 16 workers | 32 workers |
| --- | ---: | ---: | ---: |
| Compute, no fees | 7,642 | 72,908 | 74,101 |
| Compute, paid | 7,439 | 34,648 | 35,727 |
| TIP-20, paid | 114,067 | 96,782 | 94,745 |

The paid compute run reuses 98,075 call bodies, compared with 774 complete
transactions. Fee processing remains sequential, so this workload improves by
4.8x but does not reach 50k TPS. Full receipt vectors and state roots still match.

`body-replay-initial.tsv` records the first version: caching cheap TIP-20 bodies
reduced throughput to 45–57k TPS. The scheduler now keeps bodies only when their
measured execution time, excluding worker database round trips, reaches 20 μs.
This is a scheduling heuristic, not a consensus decision. Differential tests and
canonical replay set the threshold to zero to exercise all supported reuse paths.
Adaptive backoff counts both complete results and reused bodies as useful work.

Workers record journal storage accesses as well as database reads, including
attempts inside reverted calls. Reuse requires equal account metadata, original
and present values for accessed slots, warm/cold status, transient state, gas
inputs and execution context. Only unobserved pre-execution storage is replaced
with its freshly executed values; the fresh journal/log prefix is preserved.
Creation and destruction use full replay. Plain fee-free transactions skip body
capture. Inspectors and custom EVM components remain on the ordinary path.

Targeted tests cover native fee-balance observations, reverted reads, successful/
reverted/halted bodies, storage gas, precompile failures, expiring AA nonce rings,
atomic multicall reverts, and post-execution fee-accumulator overflow. Tests compare
complete per-transaction outcomes and final trie roots, not just scheduling counts.
AMM tests cover liquidity exhaustion and pre-/post-T1C transient reservations while
the call bodies remain independent. Reward tests change the global accumulator
and shared reward recipient, checking both independent bodies and bodies that
observe those values. The current EVM/revm suites pass 208 tests
(one throughput benchmark is ignored by default); Clippy with warnings denied
and the EVM build without default features also pass.

The wider suite also exposed a pre-existing process-wide key-authorization gas
table initialized from the first EVM's configuration. The failure was reproduced
on the previous commit; deriving the table from the active configuration passed
40 repeated concurrent runs of all 128 revm tests. This is recorded separately
in commit `8ea53ad8`.

## Prefetching and replay allocation

`prefetch.tsv` records the next optimization: prefetch common fee balances,
preferences and reward slots, plus sender/recipient slots from the first native
TIP-20 `transfer` call. Hints are bounded, do not warm the EVM journal, and do not
replace execution reads or conflict checks. Dynamic reward delegates, token
preferences and virtual-recipient resolution retain the ordinary database path.
Call-body reuse now applies its storage changes onto the fresh journal, avoiding
copies of the fee/nonce journal, logs and unobserved slots.

The file retains two alternating 100k runs of the baseline (`021c07df`) and an
intermediate version with fee hints only. That intermediate version regressed
fee-free TIP-20 transfers with 32 workers. Adding transfer hints raised that case
to 143–145k TPS in two repeated runs, versus 77–91k for the baseline. Paid transfers
measured 102–103k TPS. Two samples are not a confidence interval.

The `final` rows are a complete 10k/25k/50k/100k transaction matrix with phase
timing enabled. At 100,000 transactions:

| Workload | Sequential TPS | 16 workers | 32 workers |
| --- | ---: | ---: | ---: |
| Storage | 489,851 | 354,829 | 233,862 |
| Compute, no fees | 7,933 | 75,915 | 79,337 |
| Compute, paid | 7,671 | 37,026 | 38,732 |
| TIP-20, no fees | 174,796 | 160,365 | 144,337 |
| TIP-20, paid | 112,574 | 103,162 | 101,971 |

All measured receipt vectors and state roots match. Paid compute still spends
1.469 s preparing workers, 1.049 s in ordered execution and 0.057 s committing
100k transactions with 32 workers. Increasing the window to 256 did not produce
a consistent improvement, so the default remains 128. Cheap transactions still
benefit from sequential execution, and paid compute remains below 50k TPS.

## Streaming speculative batches

Workers now keep running while the owner validates and executes earlier candidates.
Preparation prefetches a bounded batch and starts its workers; ordered execution
waits for the required candidate while serving database requests. Dropping or
replacing a batch cancels outstanding reads and waits for its workers to finish,
so work and memory cannot accumulate behind cancelled payloads. Provider access
stays on the owner thread. Worker panics are caught and passed back to the owner.

The generated differentials run both streaming and a frozen batch, preserving
coverage of maximum conflicts as well as concurrent scheduling. Additional tests
cover returning before later reads, cancellation, provider unwind and errors,
worker panic cleanup, and replay when prefetched accounts and later storage reads describe
different prefixes. Configuration, full-result read validation and call-body
validation retain their existing checks.

`streaming-profile-baseline.json` records the preceding node's builder CPU profile.
On the 16-worker trial, preparation accounted for 34.8% of sampled builder CPU,
including preview iteration and transaction cloning during backoff. The payload
builder now defers conversion to an EVM input until the scheduler actually starts
workers. Backoff still advances the same number of preview candidates. The
profiled twenty-second trials exceeded the confirmation drain and are diagnostic
profiles, not successful throughput measurements.

`streaming.tsv` retains both barrier/streaming comparisons and the final
10k/25k/50k/100k transaction matrix. At 100k paid-compute transactions, two barrier
runs measured 36,720 and 37,087 TPS with 16 workers. Three streaming runs measured
51,761, 49,862 and 51,236 TPS. With 32 workers, streaming measured 45,724–46,786 TPS.
These are individual runs, not confidence intervals or evidence of sustained node
throughput. The first pair predates removal of an unused transaction clone from
worker results; the repeated comparison and final matrix use the final code.

At 100,000 transactions in the final streaming matrix:

| Workload | Sequential TPS | 16 workers | 32 workers |
| --- | ---: | ---: | ---: |
| Storage | 488,643 | 297,572 | 224,913 |
| Compute, no fees | 7,390 | 69,968 | 88,313 |
| Compute, paid | 7,234 | 49,862 | 45,724 |
| TIP-20, no fees | 176,812 | 162,071 | 139,549 |
| TIP-20, paid | 112,479 | 103,433 | 103,249 |

Every run checks complete receipt vectors and final trie roots against sequential
execution. Streaming improves paid compute by overlapping its call bodies with
ordered fee work, but still adds overhead to cheap independent transactions.
The final paid-compute run spends 0.392 s in preparation, 1.525 s in ordered
execution (including worker waits), and 0.081 s committing with 16 workers.
The `speculated` counter now counts scheduled candidates, including work cancelled
when a prepared batch is abandoned; it must not be read as committed throughput.

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

`node/body-replay-workers-*.json` repeats the same eight trials with partial replay
and its 20 μs body cutoff. Actual accepted submissions per second:

| Target TPS | Sequential | Partial replay, 16 workers |
| --- | ---: | ---: |
| 10,000 | 10,008 | 9,995 |
| 25,000 | 17,350 | 16,183 |
| 50,000 | 17,522 | 16,163 |
| 75,000 | 17,416 | 16,280 |

Every accepted transaction confirmed, with no generation, submission or
confirmation failures. At the 50k target, the speculative run reused 203 call
bodies and spent 2.630 s in the transaction execution section, 0.982 s finishing
busy payloads, and 4.149 s building them overall. Shared senders/balances and cheap
TIP-20 calls leave little reusable work in this workload. These results still do
not meet the requested sustained 50k+ node throughput.

This matrix also has a protocol gas ceiling: 450M of the 500M block budget is
available to the proposer. Creating a fresh 2D nonce slot costs about 285k gas per
transfer in this workload. Busy blocks contain about 1,575 user transactions,
which permits roughly 15.75k confirmed TPS at the 100 ms target interval. The
slightly higher accepted rate includes queueing followed by the confirmation drain.
A higher benchmark genesis gas limit or a workload that reuses nonce lanes is
needed to measure node execution capacity above that ceiling. This matrix cannot
separate that limit from execution or load-generator limits.

The follow-up `node/body-replay-5b-*.json` trials remove that ceiling using a fresh
5B-gas genesis copy. The driver checks the node's reported gas limit before loading:

```sh
python3 benchmarks/parallel-execution/run_node.py \
  --output /tmp/tempo-node-body-replay-5b --duration 5 \
  --targets 50000,75000 --workers 0,16 --block-gas-limit 5000000000
```

| Target TPS | Sequential accepted TPS | Partial replay, 16 workers |
| --- | ---: | ---: |
| 50,000 | 23,188 | 21,068 |
| 75,000 | 22,989 | 21,471 |

All accepted transactions confirmed without failures. At the 50k target, partial
replay spent 2.381 s in the transaction execution section and 1.128 s finishing
busy payloads (3.738 s total). Removing the gas cap improves observed throughput,
but this workload still benefits from sequential execution. Both node and client
share the machine; these trials do not isolate the remaining submission, execution
and finalization limits or demonstrate sustained 50k TPS.

`node/prefetch-5b-*.json` repeats the full offered-load matrix after prefetching:

| Target TPS | Sequential accepted TPS | Prefetch, 16 workers |
| --- | ---: | ---: |
| 10,000 | 10,000 | 10,018 |
| 25,000 | 23,275 | 22,446 |
| 50,000 | 22,093 | 21,502 |
| 75,000 | 22,195 | 21,419 |

All 767,635 accepted transactions confirmed, with no generation, submission or
execution failures. Each trial lasts five seconds of offered load plus its drain;
the rates divide accepted transactions by measured send duration. These results
remain in the earlier node range despite the in-memory gains.

At the 50k target, the 16-worker run spent 2.304 s in busy payload execution
sections and 1.159 s finishing them (3.712 s total). The reports additionally retain
payload histogram counter deltas: transaction execution, pool fetch, finalization,
state-root computation and post-state hashing. Their scope includes setup and
all payload attempts, unlike the busy-payload rows. They are diagnostic component
timings, not independently measured throughput or confirmation latency. This
workload still does not sustain 50k node TPS.

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

## Admission concurrency and pool counting

The locked Reth validation service holds its shared receive-queue mutex while
awaiting each validation job, serializing the configured workers. A two-worker
barrier regression reproduced this on the original executor. Tempo now releases
the queue before running a job and uses a bounded sender without a sender mutex.
The configured worker count is unchanged; each batch remains one validator call,
preserving its shared provider snapshot and outcome order. Shutdown, queue capacity,
batch metadata and head callbacks are covered by tests.

Local stack profiles then identified a second admission bottleneck: every AA
insertion scanned the entire pool to count pending and queued transactions before
eviction. Pending counts are now maintained through replacement, promotion,
demotion and removal, with expiring counts derived from their existing map.
Eviction decisions and ordering are unchanged. The 225 pool tests pass, including
8,000 generated mixed operations checked against actual transaction status after
each mutation. The parallel TIP-20 node integration test and Clippy also pass.

`admission-stacks.json` records two diagnostic profiles with the built-in Pyroscope
feature at 199 Hz, captured to a local loopback server from an unstripped release
binary. Only complete ten-second profiles inside the send window are included.
Before the count change, discard consumed about 18% of sampled CPU in both modes.
These sampled user-space stacks do not account for all kernel time.

`admission-cpu.json` retains ten independent trials at 75k offered TPS for ten
seconds, using a 5B-gas genesis. Each table entry is one trial, not a confidence
interval. All accepted transactions confirmed with zero execution failures.

| Variant | Accepted TPS, sequential | Accepted TPS, 16 workers | Confirmed TPS, sequential | Confirmed TPS, 16 workers |
| --- | ---: | ---: | ---: | ---: |
| Baseline `f5db13d1` | 20,964 | 20,311 | 20,589 | 19,907 |
| Baseline, 1,024 client requests | 20,711 | 19,462 | 20,271 | 19,067 |
| Concurrent validation | 23,176 | 20,246 | 22,849 | 19,927 |
| Concurrent validation, four Tokio threads | 20,115 | 18,335 | 19,873 | 17,826 |
| Concurrent validation and cached counts | 46,169 | 45,211 | 22,408 | 15,774 |

Accepted TPS divides accepted submissions by send duration. Confirmed TPS divides
those same transactions by wall time from send start to the last busy block being
added to the canonical chain, including backlog. It is neither confirmation latency
nor a steady-state throughput estimate. The analyzer checks the receipt count and
excludes the one system transaction per block in these isolated dev trials.

The count change doubles admission capacity but exposes a large backlog: the final
trials take 20.62 s and 28.68 s, respectively, to canonicalize all transactions.
Node CPU during sending rises from about eight to sixteen logical cores, roughly
half spent in the kernel. The 16-worker run spends 19.53 s in busy payload execution
sections and 4.21 s finishing payloads. `node/admission-*.json` retains those payload
measurements and receipts summaries. Execution remains a bottleneck, and the more
heavily queued speculative workload regresses confirmed throughput.

`admission-matrix.json` and `node/admission-matrix-*.json` repeat the complete
10k–75k offered-load matrix with five-second send windows after both fixes:

| Target TPS | Accepted, sequential | Accepted, 16 workers | Confirmed, sequential | Confirmed, 16 workers |
| --- | ---: | ---: | ---: | ---: |
| 10,000 | 10,014 | 9,986 | 9,904 | 9,898 |
| 25,000 | 24,984 | 24,985 | 24,066 | 23,368 |
| 50,000 | 46,579 | 46,739 | 26,604 | 21,507 |
| 75,000 | 46,775 | 46,443 | 26,318 | 21,386 |

All 1,284,190 user transactions confirmed with zero execution failures. These
shorter trials show the duration sensitivity of backlog measurements; they do not
establish sustained 50k TPS.

Reproduce CPU and canonical-completion measurements with:

```sh
python3 benchmarks/parallel-execution/run_node.py \
  --output /tmp/tempo-node-admission --duration 10 --targets 75000 \
  --workers 0,16 --block-gas-limit 5000000000 --profile-cpu
python3 benchmarks/parallel-execution/summarize_cpu.py /tmp/tempo-node-admission
```

`--profile-cpu` requires `pidstat`. `--node-binary` supports comparisons with a
saved executable; `--client-concurrency` controls RPC pressure. The driver's host
record includes `TOKIO_WORKER_THREADS` when explicitly set. CPU summaries use only
whole one-second intervals inside sending; 100% means one logical core.

`streaming-node-matrix.json` and `node/streaming-matrix-*.json` repeat the five-second
matrix with streaming and deferred preview conversion:

| Target TPS | Accepted, sequential | Accepted, 16 workers | Confirmed, sequential | Confirmed, 16 workers |
| --- | ---: | ---: | ---: | ---: |
| 10,000 | 10,004 | 10,001 | 9,935 | 9,880 |
| 25,000 | 24,980 | 24,982 | 24,035 | 23,612 |
| 50,000 | 46,268 | 45,735 | 26,626 | 23,625 |
| 75,000 | 46,232 | 45,980 | 26,571 | 23,509 |

All 1,272,588 user transactions confirmed with no execution failures. At the
50k offered target, the speculative confirmation rate increases from 21,507 to
23,625 TPS, while sequential remains about 26.6k TPS. Busy payload execution time
falls from 6.820 s for 234,048 transactions to 5.717 s for 229,056 transactions;
finishing takes 1.959 s. These are separate trials with different transaction
counts. The node still falls far short of sustained 50k TPS, and speculative
execution still loses to sequential execution on this cheap shared-state workload.

## AA selection index

The builder profile also identified transaction selection as a serial cost. The
AA iterator now uses a preallocated hash index for transaction-ID lookups and
removals. Its separate priority-ordered set still determines selection, including
submission-order ties; the underlying pool retains its ordered range index.
All 225 pool tests pass, covering nonce dependencies, invalidation and live updates.

`pool-index.tsv` measures snapshot construction and complete selection at
10k/25k/50k/100k queued transactions, excluding admission and transaction creation.
Every repetition checks the complete selected hash sequence. At 100k transactions,
the median of five repetitions with 100 senders and scattered nonce keys falls
from 61.4 ms to 48.5 ms. Sorted IDs regress from 35.5 ms to 43.9 ms, so this is a
workload-dependent improvement. Reproduce with:

```sh
TEMPO_POOL_BENCH_SCATTERED=1 CARGO_PROFILE_RELEASE_LTO=false \
  cargo test -p tempo-transaction-pool --release --locked \
  best_transactions_throughput -- --ignored --nocapture
```

Omit `TEMPO_POOL_BENCH_SCATTERED` for sorted IDs; `TEMPO_POOL_BENCH_COUNTS`
overrides the queue sizes. These are selection timings, not EVM TPS.

`pool-index-node.json` and `node/index-*.json` retain two real-node comparisons
against `1ab7292d`, using five-second sends at 50k offered TPS and a 5B-gas genesis.
The second comparison reverses variant order. Confirmed rates include backlog:

| Index | Sequential TPS, first / repeat | 16 workers TPS, first / repeat |
| --- | ---: | ---: |
| Tree | 26,528 / 26,460 | 23,383 / 23,240 |
| Hash | 27,057 / 27,353 | 24,364 / 24,863 |

All 1,851,870 accepted user transactions confirmed with zero execution failures.
The gain persists in the repeat, but these short trials are not steady-state
throughput evidence and remain well below sustained 50k node TPS.

## Canonical replay

The new read-only command compares complete execution results and state deltas,
then checks canonical stored receipts, gas/receipt-root validation, and state root:

```sh
tempo parallel-replay --chain /path/to/genesis.json --datadir /path/to/node-data \
  --from 1000 --to 1100 --threads 16 --batch-size 128 --output replay.tsv
```

Bounds are inclusive. The database must retain parent state and canonical
receipts. Backoff and the minimum call-body duration are disabled in this command
so all windows exercise speculative validation and partial reuse. The execution timers exclude trie hashing; sequential runs first,
so the timing columns are diagnostic and may have unequal cache warmth.
Historical trie reconstruction can be expensive far behind the database head.

`local-replay-10k.tsv` and `local-replay-25k.tsv` verified all 74 local canonical
blocks from the corresponding load trials: 174,885 user transactions plus 74
system transactions. Both executors matched complete state deltas, canonical
receipts and canonical state roots. The 10k replay overlapped a test compilation;
its timing columns should not be used as throughput measurements. These are
stored generated-chain blocks, not mainnet or testnet history.

`body-replay-canonical-2d.tsv` and `body-replay-canonical-expiring.tsv` repeat
verification with partial replay forced on for 120 stored local blocks containing
100,000 user transactions and 120 system transactions. They cover both 2D and
expiring AA nonces. Complete state deltas, stored receipts, receipt roots, gas and
state roots match. These replays ran concurrently with correctness checks; their
timing columns are not benchmark results.

`prefetch-canonical-2d.tsv` and `prefetch-canonical-expiring.tsv` revalidate those
same 120 blocks after prefetching and the journal-allocation changes. All 100,000
user transactions and 120 system transactions match complete state deltas,
canonical receipts, gas, receipt roots and state roots. The two replays ran
concurrently; their timings are diagnostic only.

`admission-canonical-10k.tsv` and `admission-canonical-busy.tsv` verify 54 blocks
built after the admission changes, including three large blocks from the 50k
trial. All 94,231 user transactions and 54 system transactions match sequential
results, complete state deltas, canonical receipts, gas, receipt roots and state
roots with speculation and call-body reuse forced on. These remain local generated
chains, not public historical-chain evidence.

`streaming-canonical-2d.tsv`, `streaming-canonical-expiring.tsv` and
`streaming-canonical-busy.tsv` verify 123 stored local blocks with streaming and
call-body reuse enabled: 143,247 user transactions plus 123 system transactions.
This includes both AA nonce modes and three large blocks built by the updated
node. Complete state deltas, execution results, canonical receipts, gas, receipt
roots and state roots match. The replay jobs overlap correctness checks and each
other, so their timings are diagnostic only. Public historical replay remains
outstanding.

## Correctness model and integration

Workers execute against a cached view while the owner advances the committed
prefix. Prefetched values come from the batch start; other reads are cached when
served and may observe later commits. This can produce an inconsistent speculative
view, which is safe only because every recorded value must match the actual
transaction's committed prefix before reuse. Otherwise the result is replayed.
Database cache misses remain on the database's owning thread, supporting Reth
providers that cannot be shared between threads without unsafe code. Every
execution read is recorded, including reads in
transaction validation, native precompiles and reverted calls. Before reusing a
result, its transaction and environment must match and every read must still
match the committed prefix. Conflicting transactions run again through the ordinary
EVM, with the call-body reuse check described above. Speculative errors use full replay.

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
- Reduce the remaining serial fee-processing and partial-replay overhead.
- Expand AMM liquidity, authorization/delegation, hardfork-boundary and adversarial
  differential coverage, including independent implementations or state-test corpora.
- Replay historical blocks against verified parent state and canonical receipts and
  roots. The public Moderato endpoint returned HTTP 403 from this host; no historical
  mainnet/testnet replay is claimed. The local replay harness is available.
- Sustain 50k+ actual node TPS, measure transaction confirmation latency, and profile
  execution separately from pool iteration and block finishing on a larger host.
  The 5B-gas follow-up removes the original benchmark's block-gas ceiling, but
  the local offered-load matrix still does not meet this acceptance criterion.
