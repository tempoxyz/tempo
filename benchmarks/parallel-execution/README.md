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
`TEMPO_BENCH_FEE_REBASING=0` disables fee arithmetic rebasing for comparisons;
the `fees_rebased` column counts the subset of full results reused this way.

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

## Candidate gas budgets

Proposer lookahead now filters candidates against the remaining non-shared and
general-purpose gas budgets before converting them to worker inputs. The preview
still advances the same raw window, and the authoritative iterator performs its
usual selection and invalidation. This avoids executing candidates already known
to exceed the current budget. The parallel TIP-20 node integration test and Clippy
pass.

`candidate-budget-node.json` and `node/candidate-budget-*.json` repeat the
five-second offered-load matrix with 16 workers after this filter and the hash
index change:

| Offered TPS | Accepted TPS | Confirmed TPS including backlog |
| --- | ---: | ---: |
| 10,000 | 10,013 | 9,906 |
| 25,000 | 24,983 | 24,062 |
| 50,000 | 45,696 | 24,501 |
| 75,000 | 45,924 | 24,585 |

All 633,862 accepted user transactions confirmed with zero execution failures.
The 50k trial falls within the preceding hash-index trials; this matrix does not
demonstrate an additional throughput gain from the filter alone. The remaining
pool scan still visits candidates that cannot fit, and cheap shared-state
transactions still favor sequential execution.

## Deferred proposer preview

The proposer now advances speculative lookahead only after a candidate passes
gas-budget and block-size checks. Rejected candidates advance the authoritative
iterator; preview catch-up is deferred until another candidate can execute.
Catch-up checks cancellation and interruption between bounded chunks. Empty
live-feed polls consume neither cursor. If the rejected tail fills the remainder
of the pool, only the authoritative iterator scans it. Transaction identity and
read validation still guard every speculative result.

`lazy-preview-node.json` and `node/lazy-*.json` compare the change with `fa529f33`
at 50k offered TPS, five-second sends, 16 execution workers and 5B block gas.
The second comparison reverses variant order:

| Preview | Confirmed TPS, first / repeat |
| --- | ---: |
| Eager | 24,630 / 24,578 |
| Deferred | 25,446 / 25,554 |

All 917,857 accepted transactions confirmed with zero execution failures. Rates
include backlog and iterator cleanup; they remain short-trial measurements. The
mixed payment/non-payment node integration test now runs in both sequential and
speculative modes; both cases and Clippy pass.

## Runtime contention trials

`run_node.py --node-tokio-threads N` sets `TOKIO_WORKER_THREADS` only for the node;
the client retains its inherited runtime configuration. The override is recorded
in `commands.json` and `host.json`. Execution worker count is independent.

`runtime-node.json` and `node/runtime-*.json` retain five-second trials on
`fa529f33`, all using 16 execution workers and the 5B-gas genesis:

| Node Tokio workers | Client concurrency | Offered TPS | Accepted TPS | Confirmed TPS | Node CPU / kernel CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| 4 | 256 | 50,000 | 25,850 | 21,300 | 871% / 250% |
| 8 | 256 | 50,000 | 39,547 | 24,706 | 1,054% / 451% |
| 16 | 256 | 75,000 | 47,981 | 24,537 | 1,567% / 771% |
| 16 | 1,024 | 75,000 | 39,480 | 25,339 | 1,242% / 570% |
| Default (32) | 1,024 | 75,000 | 37,775 | 25,365 | 1,199% / 557% |

All 961,657 accepted transactions confirmed with zero execution failures. CPU is
averaged over complete one-second intervals during sending; 100% is one logical
core. Confirmed rates include backlog. These trials vary admitted transaction
counts and do not isolate a steady-state service rate. Fewer Tokio workers reduce
kernel CPU but also admission capacity; higher client concurrency reduces admission
in these trials. No production runtime default changes are justified by this data.

## Checked fee arithmetic

Speculative workers annotate three internal fee operations: crediting the fee
manager with the maximum fee, debiting its refund, and adding the actual fee to
the validator's accumulator. A candidate can rebase these slots only if no
ordinary access observes or writes the slot anywhere in the transaction. Native
precompiles, opcode storage accesses, direct database reads and cached journal
reads all participate, including reverted accesses. Transfers to the fee manager,
fee-balance views and fee distribution therefore retain ordinary conflict checks.

For each changed slot, validation checks that the recorded operation sequence
reproduces the speculative final value from its original value, then applies each
checked addition/subtraction to the committed value. Checking the net delta is
insufficient: collecting the maximum fee can overflow even when the final charge
would fit. Any failed arithmetic check or ordinary dependency triggers replay.
All checks precede mutation; only the result's original and present storage values
are adjusted. Logs, outputs, gas and other state are retained from execution.

This applies only to standard Tempo gas schedules. The annotated operations run
inside maximum-gas native fee contexts whose gas/refund accounting is discarded;
their storage-value-dependent gas does not enter transaction gas. Custom gas
schedules disable rebasing. Creation, destruction and native code installation
also disable fee metadata; created or destroyed result accounts cannot be patched.
Failed annotated writes and nested recording scopes disqualify reuse. AMM state,
reward accounting, payer balances and authorization retain ordinary validation.

Generated differentials run with rebasing both enabled and disabled, and with
streaming and frozen worker views. Dedicated cases cover direct/reverted fee
reads, contract writes to both shared fee slots, intermediate maximum-fee and
accumulator overflow, and custom gas schedules at every fork from T0 through T4.

`fee-rebasing.tsv` and `fee-rebasing-phases.json` compare enabled/disabled modes
in both orders on 100,000-transaction in-memory workloads. All full receipts and
state roots match sequential execution. Two runs per mode, same 16-core host,
streaming and phase timers enabled:

These A/B measurements retain the earlier one-eighth reuse threshold for backoff,
isolating arithmetic rebasing from the scheduling adjustment described below.

| Workload | Workers | Rebasing disabled TPS | Rebasing enabled TPS |
| --- | ---: | ---: | ---: |
| Paid TIP-20 | 16 | 105,186 / 106,515 | 133,142 / 121,273 |
| Paid TIP-20 | 32 | 102,949 / 105,786 | 118,966 / 116,955 |
| Paid compute | 16 | 50,757 / 46,245 | 60,091 / 61,465 |
| Paid compute | 32 | 47,659 / 48,300 | 61,486 / 62,423 |

Sequential controls span 112,834–114,672 TPS for paid TIP-20 and 7,413–7,459
for paid compute. Each enabled parallel run rebases 98,075 results. The initial
fee-manager account creation still causes 127 conflicts and one backoff period;
account metadata remains an ordinary dependency. These are isolated execution
measurements, not sustained node throughput.

`fee-rebasing-node.json` and `node/fee-{before,matrix,after-repeat,before-repeat}-*.json`
record the corresponding five-second node trials with the 5B-gas genesis and
16 execution workers. At offered rates of 10k/25k/50k/75k, confirmed rates including
backlog were 9,882 / 23,805 / 24,481 / 25,004 TPS. All 1,312,157 accepted transactions
across the matrix and comparisons confirmed with zero failures. At 50k offered,
the previous node completed 25,463 / 25,410 TPS versus 24,481 / 24,956 with fee
rebasing: a regression despite the independent-workload gains. Shared sender and
recipient balances still conflict, and the small increase in reuse keeps too many
unproductive windows active under the one-eighth threshold.

The scheduler now backs off when fewer than half of a window's results or call
bodies are reused. It still probes periodically, and correctness checks can
disable backoff entirely. This is a performance heuristic; low-reuse expensive
workloads may need a cost-sensitive policy beyond this threshold.

`fee-backoff.tsv` covers 10k/25k/50k/100k transaction counts with that threshold.
At 100k, 16/32 workers complete paid TIP-20 at 129,911 / 116,165 TPS and paid
compute at 60,246 / 60,087 TPS, with matching full receipts and roots.
`fee-backoff-node.json` and `node/fee-backoff-*.json` record 9,927 / 23,507 /
25,113 / 25,135 confirmed TPS for the 10k/25k/50k/75k offered-load sweep;
the repeated 50k trial completes 25,209 TPS. All 861,064 accepted transactions
confirm with zero failures. This recovers most of the earlier node loss, without
demonstrating an end-to-end gain over the previous node.

The final implementation also computes annotation keys only during speculative
recording, avoiding the extra lookup in ordinary sequential execution.
`fee-final.tsv` repeats the 10k–100k transaction-count matrix. At 100k, 16/32
workers measure 120,690 / 115,775 TPS for paid TIP-20 and 60,349 / 62,187 TPS for
paid compute, versus sequential controls of 113,190 and 7,515 TPS respectively.
Every run matches the sequential receipt vector and state root.

`fee-final-node.json` and `node/fee-final-*.json` retain the final five-second
node trials. With 16 execution workers and the 5B-gas benchmark genesis:

| Offered TPS | Accepted TPS | Confirmed TPS including backlog |
| --- | ---: | ---: |
| 10,000 | 10,007 | 9,935 |
| 25,000 | 24,995 | 23,967 |
| 50,000 | 44,303 | 25,133 |
| 75,000 | 46,199 | 25,206 |
| 50,000, repeated | 44,685 | 25,252 |

All 855,748 accepted transactions confirmed with zero failures. The result remains
slightly below the earlier 25,410–25,463 TPS node controls; no node-level gain is
claimed. The independent-workload gains do not remove actual payment-balance
dependencies, ordered validation, pool selection or block-finishing costs.

`fee-unpaid-controls.tsv` compares recording enabled/disabled on fee-free storage,
TIP-20 and compute workloads at 100k transactions. Every full receipt vector and
state root matches. Cheap storage and TIP-20 workloads still favor sequential
execution; the single comparisons vary in both directions and do not establish
an improvement from fee recording where no fees are charged.

`fee-sequential-node.json` checks the ordinary node path at 50k offered TPS:
the previous/current binaries confirm 27,185 / 27,075 TPS, with all 460,342
accepted transactions confirmed and no failures. This single pair does not
establish a significant change. Sequential execution still outperforms the
speculative node on this shared-account payment workload.

## Static AA candidate snapshots

AA selection now sorts the initial independent candidates into a vector and
drains it from the end. A separate ordered set holds live arrivals and unlocked
descendants. Selection merges the two maxima and suppresses duplicates that are
still pending, preserving the previous priority/submission-ID ordering and
reinsertion behavior. Newer submission IDs skip the snapshot duplicate search.
A generated insertion/removal oracle compares every selected transaction hash
against the previous ordered set, including empty snapshots, duplicate entries,
equal priorities and live updates. All 226 pool tests and both sequential and
parallel mixed-payment-lane node tests pass.

`candidate-vector.tsv` records five snapshot-and-drain repetitions at 10k, 25k,
50k and 100k transactions. At 100k, median combined time changes from 51.826 ms
to 45.519 ms with scattered keys, and from 38.009 ms to 37.512 ms with sorted
keys. The latter difference is small. These are pool-selection measurements,
not EVM throughput.

`candidate-vector-node.json` and `node/candidates-*.json` compare the previous
`df1725b0` binary with the vector implementation. Each trial sends for five
seconds at 50k offered TPS with the 5B-gas benchmark genesis, 100 accounts and
256 concurrent client requests. Comparisons run in both orders:

| Execution workers | Previous confirmed TPS | Vector confirmed TPS | Previous, reverse order | Vector, reverse order |
| --- | ---: | ---: | ---: | ---: |
| 0 | 26,919 | 27,417 | 27,030 | 27,195 |
| 16 | 24,875 | 25,661 | 25,432 | 25,604 |

All 1,834,499 accepted transactions in those eight completed trials confirmed
with zero failures. This is a small increase in these comparisons; sequential
execution still wins on this shared-account payment workload. With 16 workers,
pool snapshot time falls from 1.034 / 0.976 seconds to 0.846 / 0.877 seconds.
The updated runs spend about 3.0 seconds in successful transaction execution,
4.6 seconds in the full execution loop, and 2.2 seconds in finalization,
including 1.2 seconds calculating state roots. These metrics span the whole
trial, including setup and empty blocks, and are nested rather than additive.
They do not measure confirmation latency or sustained throughput.

The same file and `node/candidates-matrix-*.json` retain a fresh offered-load
sweep with 16 workers. At 10k / 25k / 75k offered TPS, accepted rates are
10,015 / 24,979 / 46,600 TPS and confirmed rates including backlog are
9,912 / 23,733 / 25,301 TPS. All 408,383 accepted transactions confirm with
zero failures. Together with the 50k trials above, this still shows a node
ceiling near 25k confirmed TPS on this host and workload.

An additional expiring-nonce trial at 50k offered TPS accepts 49,044 TPS and
confirms 24,296 TPS including backlog, with all 245,625 accepted transactions
confirmed and no failures (`node/candidates-expiring-*.json`). Its pool snapshot
cost is only 0.130 seconds, while state-root calculation takes 2.424 seconds.
This is an integration check of the other AA nonce mode, without a paired
baseline or an improvement claim.

The first reverse-order attempt failed with SIGBUS after block 9; it is retained
in `candidate-vector-failed-trial.json` and excluded from throughput results.
Disk space was very low, but no core dump was available and the cause remains
unconfirmed. After deleting obsolete task artifacts, the repeated comparisons
completed cleanly. The runner now saves process return codes before and after
cleanup plus starting/ending free disk space; `candidate-vector-exit-status.json`
retains those diagnostics for the completed reverse-order comparisons.

## Parallel block assembly

The assembler now computes each receipt bloom once and combines those blooms
for the block header. With an execution worker pool and at least 128
transactions, it computes the transaction root alongside receipt processing,
and calculates receipt blooms in parallel while retaining receipt order. It
shares the configured bounded pool; smaller blocks and the default configuration
use sequential root calculation with the same bloom reuse.

Tempo now constructs the Ethereum header fields directly, preserving the pinned
Reth assembler's fork logic. A differential test compares complete headers and
bodies against that upstream assembler across Shanghai, Cancun, Prague and
Osaka boundaries, including the first post-Cancun block. It covers empty blocks,
counts around the parallel threshold, mixed legacy/EIP-1559/AA transactions,
varied logs, withdrawals, execution requests and 0/1/4 workers. All 86 EVM tests
pass; two throughput benchmarks are ignored in the regular suite. Both
sequential and parallel mixed-payment-lane node integration tests and the
parallel TIP-20 transfer test also pass. Release Clippy checks all EVM targets,
and the EVM crate builds with default features disabled.

`assembly-roots.tsv` measures transaction roots, receipt roots and block blooms
at 10k, 25k and 50k generated transactions, with three repetitions per worker
count. Every result equals the upstream root/bloom tuple. At 50k transactions,
median times are:

| Worker count | Upstream calculation | Updated calculation |
| --- | ---: | ---: |
| 0 | 181.619 ms | 129.025 ms |
| 16 | 181.377 ms | 58.742 ms |
| 32 | 181.021 ms | 56.875 ms |

This excludes execution, state-trie roots and node overhead. Each upstream
measurement precedes its updated measurement on already initialized data;
these component timings are not node TPS or sustained-load results.

`assembly-node.json` and `node/assembly-*.json` compare the `2b0d2eea` node
against parallel assembly, using the same five-second, 50k offered-load setup
in both orders. All 1,837,758 accepted transactions in the eight trials confirm
with zero failures. Return codes and disk headroom are retained in
`assembly-exit-status.json`.

| Execution workers | Previous confirmed TPS | Updated confirmed TPS | Previous, reverse order | Updated, reverse order |
| --- | ---: | ---: | ---: | ---: |
| 0 | 27,155 | 27,307 | 26,925 | 27,195 |
| 16 | 25,156 | 26,197 | 25,548 | 26,397 |

The 16-worker comparisons improve by 4.1% and 3.3%, while the default sequential
path changes little. Whole-trial finalization falls from 2.250 / 2.165 seconds
to 1.908 / 1.903 seconds with 16 workers, even though state-root calculation
increases slightly. Those timings are nested and include setup and empty
blocks. Sequential execution still leads on this shared-account payment load;
parallel assembly does not establish sustained 50k+ node throughput.

The updated 16-worker sweep at 10k / 25k / 75k offered TPS accepts
10,008 / 25,008 / 45,185 TPS and confirms 9,906 / 23,890 / 26,239 TPS including
backlog. All 401,260 accepted transactions confirm without failures
(`node/assembly-matrix-*.json`). Together with the 50k comparisons, the updated
node still levels off near 26k confirmed TPS on this workload.

An expiring-AA trial at 50k offered TPS accepts 48,646 TPS and confirms 24,563
TPS including backlog. All 243,603 accepted transactions confirm without
failures (`node/assembly-expiring-*.json`). This single run exercises the second
nonce mode; it does not establish a throughput improvement for that workload.

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_BUILD_JOBS=16 \
  cargo test -p tempo-evm --release assembly_roots_throughput -- --ignored --nocapture
```

## Background state-root finalization

The existing `--engine.share-sparse-trie-with-payload-builder` path computes
trie updates alongside execution. It requires `--builder.max-tasks 1` because
the engine and payload builder share the trie. The trial driver exposes these
as `--share-sparse-trie --builder-max-tasks 1`; comparisons must set the same
payload-task limit for the synchronous control.

Testing this path exposed an ordering bug: the builder removed its state hook
and awaited the root before executor finalization. Post-block system calls and
balance increments therefore could change storage after the root was computed.
`trie-post-block-reproduction.json` records an independent node reproduction:
a genesis contract at the EIP-7002 address increments slot zero on each system
call. The synchronous node passes canonical replay; the shared-trie node stores
the increment but fails canonical state-root validation at block 1.

The finish provider now awaits the background result only when the block
builder requests the root, after executor finalization has emitted all state
changes and dropped the hook. A background failure retains the synchronous
calculation from the complete hashed post-state. New metrics distinguish
background waiting, successful roots and fallback failures from synchronous
root calculation.

The regression deploys state-changing EIP-7002 and EIP-7251 fixtures and verifies
account and storage proofs against the actual block header. Before the fix,
both shared-trie cases fail while both synchronous cases pass. After the fix,
all four cases pass with sequential and speculative execution. Release Clippy
passes for all payload-builder and node targets.

The rebuilt node also passes the original standalone fixture: all three shared
roots exactly equal the original synchronous roots (`trie-post-block-canonical.tsv`).
The ordinary sequential/parallel mixed-payment-lane tests and parallel TIP-20
transfer test pass as well.

`trie-initial-node.json` and `node/trie-initial-*.json` retain the preliminary
measurements on the previous binary. With one payload task, the synchronous
and shared-trie trials confirm 26,334 and 27,266 TPS respectively. These are
diagnostic only: the shared-trie implementation fails the post-block state
regression above and is not a valid optimization result.

`trie-fixed-node.json` and `node/trie-fixed-*.json` compare synchronous and
background roots using the corrected binary, five-second sends at 50k offered
TPS and one payload task for both variants. Comparisons run in both orders:

| Execution workers | Synchronous root TPS | Background root TPS | Synchronous, reverse order | Background, reverse order |
| --- | ---: | ---: | ---: | ---: |
| 0 | 27,740 | 28,300 | 27,634 | 28,230 |
| 16 | 26,338 | 27,295 | 26,853 | 27,450 |

All 1,793,023 accepted transactions confirm with zero failures. The 16-worker
comparisons improve by 3.6% and 2.2%. Their whole-trial finalization time falls
from about 1.9 seconds to 0.68 seconds, but streaming state changes increases
execution-loop time. Each background-root run records successful background
roots and no fallback failures. These remain short local trials; the sequential
EVM still leads on this shared-account workload, and sustained 50k+ node TPS
has not been demonstrated.

The corrected background-root sweep at 10k / 25k / 75k offered TPS accepts
10,017 / 24,981 / 44,953 TPS and confirms 9,967 / 24,752 / 27,465 TPS including
backlog. All 400,087 accepted transactions confirm without failures. The
expiring-AA trial at 50k offered TPS accepts 45,935 TPS and confirms 26,836 TPS,
with all 230,076 accepted transactions confirmed. All background roots complete
without fallback in these runs (`node/trie-fixed-{matrix,expiring}-*.json`).

```sh
python3 benchmarks/parallel-execution/run_node.py \
  --output /tmp/tempo-node-shared-trie --workers 16 --duration 5 \
  --block-gas-limit 5000000000 --profile-cpu \
  --share-sparse-trie --builder-max-tasks 1
```

## State-update copying experiment

Copying only touched accounts did not improve node throughput and is not enabled.
`prototypes/compact-trie-updates.patch` preserves the tested implementation against
`c0039f32`, including projection and message-order checks and the copy microbenchmark.
It omits untouched accounts that Reth's trie conversion already ignores, retains
bulk copies within each touched account, and uses the original whole-map clone
when every account is touched. The original journal and message ordering stay intact.

`trie-copy-micro-final.tsv` measures 50,000 copies per sample, with seven samples
and alternating order. Median times on the same host are:

| Journal fixture | Original copy | Touched accounts only |
| --- | ---: | ---: |
| 16 accounts × 32 slots, 3 touched accounts | 115.346 ms | 20.863 ms |
| 8 accounts × 32 slots, all written | 56.828 ms | 58.734 ms |
| 8 accounts, no storage, 3 touched accounts | 16.780 ms | 6.747 ms |

These measure copying and destruction only. The all-writes fixture adds about
3.4% overhead to this component. Filtering storage entries individually was also
rejected: it made the all-writes copy about six times slower. Retained exploration
records are `trie-copy-micro-initial.tsv` (false = original, true = filter accounts
and slots) and `trie-copy-micro-variants.tsv` (0 = original, 1 = entry filtering,
2 = clone touched accounts then retain changed slots, 3 = clone touched accounts).
The final prototype adds the whole-map fast path for entirely touched journals.

`trie-copy-node.json` and `node/trie-copy-*.json` compare the original and final
prototype in both orders, with background roots, one payload task, and five-second
sends at 50k offered TPS. Confirmed throughput includes backlog:

| Execution workers | Original TPS | Prototype TPS | Original, reverse order | Prototype, reverse order |
| --- | ---: | ---: | ---: | ---: |
| 0 | 28,930 | 28,383 | 28,483 | 28,683 |
| 16 | 27,726 | 27,335 | 27,327 | 27,303 |

All 1,773,893 accepted transactions confirm without submission or execution
failures or background-root fallbacks. The 16-worker comparisons are 1.4% and 0.1% slower with the prototype;
sequential comparisons are mixed. The component benchmark does not translate to
a useful end-to-end improvement on this workload, so the production hook retains
the original full-state copy.

The log audit also found rejected dev payloads with duplicate millisecond
timestamps. They occur strictly after each trial's last user transaction block,
so the confirmed-TPS window excludes them. `rejected_dev_payloads` records their
counts in both `trie-copy-node.json` and the preceding `trie-fixed-node.json`.
No other invalid-payload reasons occur in those trials. Whole-trial metrics still
include the dev miner's empty-block catch-up activity.

The prototype's projection test checks all 256 account status combinations and
three balances against the pinned upstream trie conversion. Its message-order and
original-journal checks pass, as do all four post-block header-root regressions,
the shared-trie TIP-20 and mixed payment-lane cases, and release Clippy. The two
new shared-trie integration cases remain enabled with the production hook.

To reproduce the final prototype in a disposable checkout:

```sh
git apply benchmarks/parallel-execution/prototypes/compact-trie-updates.patch
CARGO_PROFILE_RELEASE_LTO=false CARGO_BUILD_JOBS=16 \
  cargo test -p tempo-payload-builder --release trie_journal_copy_throughput -- --ignored --nocapture
```

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

`candidate-budget-canonical.tsv` verifies three large blocks from the updated
50k offered-load trial: 38,889 user transactions and three system transactions.
Sequential and forced speculative execution match full results, state deltas,
canonical receipts, gas, receipt roots and state roots. These remain generated
local-chain blocks, and replay timings are diagnostic only.

`lazy-preview-canonical.tsv` verifies three large blocks built with deferred
preview: 44,935 user transactions and three system transactions. Full results,
state deltas, canonical receipts, gas, receipt roots and state roots match between
sequential and forced speculative execution. This is local generated-chain evidence.

`fee-rebasing-canonical-2d.tsv` and `fee-rebasing-canonical-expiring.tsv` repeat
the 120-block AA replay with fee rebasing enabled: 100,000 user transactions and
120 system transactions match full results, state deltas, stored receipts, gas,
receipt roots and state roots. Replays overlap correctness builds; their timings
are diagnostic only. These remain local generated chains.

`fee-rebasing-canonical-busy.tsv` additionally verifies three large blocks built
with fee rebasing: 36,521 user transactions plus three system transactions, with
the same complete-result, state-delta and canonical-root checks.

`fee-final-canonical-busy.tsv` verifies three more large blocks after the backoff
and annotation changes: 35,613 user transactions and three system transactions.
Together the fee-change replays cover 126 local blocks with 172,134 user and
126 system transactions; all complete results, state deltas and canonical checks
match. Public historical blocks are still outstanding.

`candidate-vector-canonical.tsv` verifies three large blocks built with the new
AA snapshot: 38,576 user transactions and three system transactions. Full
results, state deltas, stored receipts, gas, receipt roots and canonical state
roots match sequential execution. These are generated local-chain blocks.

`candidate-vector-canonical-expiring.tsv` verifies three newly built blocks with
expiring AA nonces: 84,238 user transactions and three system transactions,
with the same full-result and canonical-root checks. Across the two candidate
snapshot replays, all 122,814 user transactions and six system transactions
match. Replay timings remain diagnostic only.

`assembly-canonical.tsv` verifies three large blocks built with parallel
assembly: 39,886 user transactions and three system transactions match full
execution results, state deltas, stored receipts, gas, receipt roots and
canonical state roots. This is generated local-chain evidence; replay timings
overlap correctness checks and are diagnostic only.

`assembly-canonical-expiring.tsv` adds three freshly built expiring-AA blocks
with 86,319 user transactions and three system transactions. All full results,
state deltas, canonical receipts, gas and roots match. Across both assembly
replays, 126,205 user transactions and six system transactions match; this is
still local generated-chain evidence rather than public historical replay.

`trie-fixed-canonical.tsv` and `trie-fixed-canonical-expiring.tsv` verify six
blocks built with the corrected background-root path, including both AA nonce
modes: 106,869 user transactions and six system transactions. Complete
execution results, state deltas, stored receipts, gas, receipt roots and
canonical state roots match sequential execution. The separate post-block
fixture above adds three system-only blocks whose roots also match the
original synchronous control. These remain generated local chains, and replay
timings are diagnostic only.

## Correctness model and integration

Workers execute against a cached view while the owner advances the committed
prefix. Prefetched values come from the batch start; other reads are cached when
served and may observe later commits. This can produce an inconsistent speculative
view. Before reuse, every recorded value must match the actual transaction's
committed prefix, except eligible fee slots that pass the arithmetic checks above.
Otherwise the result is replayed.
Database cache misses remain on the database's owning thread, supporting Reth
providers that cannot be shared between threads without unsafe code. Every
execution read is recorded, including reads in
transaction validation, native precompiles and reverted calls. Before reusing a
result, its transaction and environment must match and every ordinary read must
still match the committed prefix. Conflicting transactions run again through the ordinary
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
