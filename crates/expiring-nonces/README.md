# Expiring nonce state

Expiring replay IDs live in a persistent in-memory map, outside the nonce
precompile's EVM storage. Blocks commit to the live set through
`TempoHeader.expiring_nonce_root`. The existing block database provides durability:
on a cache miss or restart, the node reconstructs the requested branch from up to
300 seconds of block bodies and verifies the resulting commitment.

Before executing a block, remove entries whose expiry is less than or equal to the
block timestamp. Check each transaction against the remaining set and insert its
replay ID only when committing the transaction. EVM reverts consume the ID;
invalid transactions and discarded execution results do not. A full set rejects
new IDs instead of evicting live entries. Snapshots isolate speculative blocks and
forks, so reorgs restore the state of their actual parent.
Pool admission reuses the verified post-block snapshot instead of recovering
transaction signatures and inserting the same IDs again at every new head.
Its separate pool configuration also supplies post-tip state to Reth's gas-limit
lookup, avoiding parent expiry there. Execution configurations continue to start
from parent state.

If all entries expire, detach the collections; if over three quarters expire,
rebuild the membership index from the surviving buckets. Other expiry batches
remove only expired IDs. Neither optimization changes bucket digests or roots.
Evicted snapshots and replaced pool environments are destroyed outside their
shared locks.

The commitment hashes ascending expiry buckets. Each bucket contains its expiry,
entry count, and an incremental Keccak hash chain over replay IDs in inclusion
order. Finalizing a block hashes at most 300 bucket summaries. See the crate's
rustdoc for the exact encoding and domain separators.

The node enables this backend with `TempoEvmConfig::with_expiring_nonce_source`.
The low-level `TempoEvmConfig::new` constructor retains the storage backend for
legacy execution and comparative benchmarks. Standalone CLI execution commands
and shadow replay that use that constructor require equivalent block-source
wiring before they can execute the new headers.

This is an STF and header-format change. Start from a fresh chain; activation on
existing history requires an explicit migration of live replay IDs. Pruning must
retain block bodies covering the validity window. Missing history or an incorrect
commitment fails closed.

## Validation

The unit tests cover expiry boundaries, duplicate rejection, full-set rejection,
fork isolation, commitment integrity, and comparison with a reference map.
Executor tests cover successful and reverted inclusion, discarded execution,
storage-action replay, and absence of nonce-precompile writes. Cache tests cover
restart reconstruction, fork selection, missing history, and invalid commitments.
The end-to-end restart test runs with both inline and deferred verification and
checks `eth_simulateV1` and `eth_call` timestamp overrides as well.

```sh
cargo test -p tempo-evm -p tempo-primitives -p tempo-expiring-nonces -p tempo-transaction-pool --lib
cargo test -p tempo-e2e --test inline expiring_nonce_replay
cargo test -p tempo-e2e --test deferred expiring_nonce_replay
```

## Benchmarks

The repository's `bench-e2e.yml` workflow compares the complete node with the
storage backend at `3113606c89332225f6b0d6f09368cdf35a7fd544`. Use the TIP20 scenario
`tip20:recipient=existing,auth=direct,nonce=expiring,fee_token=any_tip20` to exercise
expiring replay protection without continually creating new recipient accounts.
The comparison preserves the existing expiring-nonce gas charge.

The workflow invocation pins both implementations and txgen:

```sh
gh workflow run bench-e2e.yml --repo tempoxyz/tempo \
  --ref onbjerg/expiring-nonce-benchmark \
  -f baseline=3113606c89332225f6b0d6f09368cdf35a7fd544 \
  -f feature=93b3d8a06cda56379a093b5abb748c57b7c47454 \
  -f 'preset=tip20:recipient=existing,auth=direct,nonce=expiring,fee_token=any_tip20' \
  -f duration=180 -f bloat=100 -f tps=50000 -f accounts=1000 \
  -f max-concurrent-requests=500 -f run-pairs=3 \
  -f profiling=off -f otlp=false -f no-slack=true \
  -f txgen-ref=8ca73369c4b42ffffaf40066bbde8673141049c1
```

The benchmark-only script commit `c0cf13326e3ae8d0be9b0772d35478eb5992e535`
selects unused local HTTP, metrics, and auth RPC ports once per comparison and
records them in `listener-ports.json`. Consensus/P2P endpoints, validator
identities, node implementations, and workload settings are unchanged.
It measures two validators on one runner, alternating three 180-second runs of
each implementation against the same 100,000 MiB state snapshot.

### AWS multiregion rerun with verified funding

The [AWS rerun](https://github.com/tempoxyz/tempo/actions/runs/37548185616)
completed all six phases and infrastructure teardown. It compares the same
`3113606c8933` baseline and `93b3d8a06cda` feature with 8 validators, two each in
`us-east-1`, `eu-central-1`, `ap-southeast-1`, and `ap-northeast-1`. Workload inputs
remain 100 GiB state, `tip20_existing_recipients`, 3 pairs of 180 seconds, 50,000
target TPS, 1,000 accounts, 5,000 concurrent requests, and txgen
`8ca73369c4b42ffffaf40066bbde8673141049c1`.

The Tempo workflow runs from benchmark-only commit
`90bb1ccc35b673abff57fe1f07999cd0251a7c70`, which pins the harness to
`b4924f164531651a884228b36ec16e00b811ab78`. That revision adds a sender fee-balance
preflight and rejects a phase if insufficient-funds errors exceed 0.1% of sends.
The preflight checks pathUSD; a necessary faucet top-up funds all four fee tokens.
All six phase preflights found zero underfunded senders and required no top-ups.
The minimum observed pathUSD balance was 18,446,744,063,709,551,615 base units,
versus a required 2,570,000,000. An independent scan of all six sender logs found
**zero insufficient-funds errors**; logged submission failures were exclusively
`txpool is full`. Neither arm recorded EVM reverts.

| Metric | Baseline | Feature | Observed change |
| --- | ---: | ---: | ---: |
| Included TPS, mean across runs | 9,859.7 | 10,820.7 | +9.7% |
| Builder throughput, Mgas/s | 1,267.5 | 1,407.5 | +11.1% |
| Validator throughput, Mgas/s | 1,446.1 | 1,582.3 | +9.4% |
| Mean block time, ms | 625.0 | 627.9 | +0.5% |
| Reported block time p50, ms | 628 | 633 | +0.8% |
| Reported block time p99, ms | 792 | 765 | −3.4% |
| RPC submission acceptance | 98.95% | 99.26% | +0.31 percentage points |

Per-pair included TPS was 9,835→10,836 (+10.18%), 9,889→10,786 (+9.07%), and
9,855→10,840 (+9.99%). All three favor the feature. This workflow supplies no
confidence interval, and each pair runs baseline before feature; these are
observed gains rather than a formal significance claim. Reported block latency
percentiles aggregate per-run percentiles, not a pooled block distribution.
The feature's mean and median block times are slightly higher despite greater
throughput. The 50,000 TPS target was not achieved; this comparison does not
establish which component limits throughput.

Feature-1's wrapper phase lasted 711 seconds while its measurement window was
approximately 180 seconds, like the other five phases. Wrapper elapsed includes
preparation and reporting, so it is not a transaction-throughput denominator.
The [artifact](https://github.com/tempoxyz/tempo/actions/runs/37548185616/artifacts/11454069835)
contains all six `fee-balance-preflight.json` files, sender logs, per-phase
reports, raw metrics, and the comparison summary. The invalid GCP comparison
below remains withdrawn and is not used to infer this AWS result.

### GCP multiregion comparison: withdrawn

A [multiregion comparison](https://github.com/tempoxyz/tempo/actions/runs/37537005393)
was also dispatched with the same baseline and optimized `93b3d8a06` feature,
100 GiB of state,
three 180-second pairs, and the matching `tip20_existing_recipients` preset.
It uses 8 GCP validators across `us-east4`, `europe-west4`,
`asia-southeast1`, and `asia-east1`, targeting 50,000 TPS with 5,000 concurrent
requests. Txgen is pinned to `8ca73369c4b42ffffaf40066bbde8673141049c1`.
The multiregion harness uses a 20-second expiry window, compared with 10 seconds
in the single-runner scenario. All six benchmark phases and the workflow completed
successfully. Earlier dispatches failed
before sending transactions: ValScope required OTLP, GCP exhausted capacity in
every `us-central1` zone, and the requested `c4d-standard-48-lssd` machine type
was unavailable in `us-west1-a`. This retry disables both ValScope and OTLP and
uses the four regions that provisioned successfully, with two validators each.
Both benchmark arms use the same topology.

**This multiregion comparison is invalid for performance conclusions.** The job
completed, but fee-starved benchmark accounts dominated RPC rejections. The
reported +3.9% TPS difference below is withdrawn as performance evidence; these
numbers are retained only to identify the contaminated run:

| Metric | Baseline | Feature | Observed change |
| --- | ---: | ---: | ---: |
| Included TPS, mean across runs | 5,461.7 | 5,672.7 | +3.9% |
| Mean block time, ms | 624.1 | 618.1 | −1.0% |
| Reported block time p50, ms | 621 | 623 | +0.3% |
| Reported block time p99, ms | 808 | 799 | −1.1% |
| Builder throughput, Mgas/s | 564.7 | 574.2 | +1.7% |
| Validator throughput, Mgas/s | 2,383.8 | 2,437.0 | +2.2% |
| Sender success rate | 19.24% | 19.92% | +0.68 percentage points |

Per-pair TPS was 5,279→5,804, 5,513→5,871, and 5,593→5,343. The third pair
reverses direction. This workflow provides no confidence interval or significance
test, so +3.9% is not a conclusive speedup. Block latency percentiles aggregate
per-run percentiles rather than pooling all blocks; builder/validator latency
percentiles derive from scrape-interval averages. An audit of all six `txgen.out` files found:

| Logged RPC rejection | Baseline, all three phases | Feature, all three phases |
| --- | ---: | ---: |
| Insufficient funds for gas | 12,521,514 | 12,458,688 |
| Txpool full | 16,839 | 14,902 |

These count complete phase logs, including warmup and drain, rather than exactly
the reported measurement counters. Insufficient funds account for over 99.8% of
logged submission errors in each arm. Within the wall-clock measurement windows,
the corresponding insufficient-funds counts are 12,426,185 and 12,372,061.
Example errors are `have 27380 want 30000` on baseline and
`have 28459 want 30000` on feature. Pooled RPC acceptance starts around 98% for
the first 20 seconds and falls to 11% for seconds 40–169 on both arms.

At the pinned txgen commit, `success / sent` measures RPC submission acceptance,
not inclusion or execution success. `failed` also counts later expiry/revert or
observation failures for already accepted transactions, so it is not the
complement of `success`. Neither arm recorded EVM reverts.

The workflow reused the shared 100,000 MiB snapshot and skipped rebuilding it.
It explicitly accepted a cached genesis-hash mismatch for regenesis. The cache
identity contains the bloat size and image format, but not the sender account
count or funding; requesting 1,000 senders therefore does not verify that all
1,000 have sufficient fee balances. The logs do not establish the cached object's
original creation date. A valid comparison requires correcting sender funding,
checking it before measurement, and rejecting runs contaminated by
insufficient-funds errors.

Feature block intervals in the measured windows never exceeded 1.112 seconds.
The long gaps from the single-runner scenario did not recur in these feature
windows, but the different topology and workload prevent attributing that change
to the nonce fixes. Feature-1's wrapper phase lasted 576 seconds, while its
measured block window was approximately 178 seconds like the other phases;
wrapper elapsed time includes work outside transaction measurement.

The [published artifact](https://github.com/tempoxyz/tempo/actions/runs/37537005393/artifacts/11449672591)
contains the comparison, six phase reports, actual validator distribution, and
raw metrics. `comparison.json` records exit code zero and the requested commits.

### Node measurements before the overhead fixes

[Three-pair workflow, feature `d01a65cc3`](https://github.com/tempoxyz/tempo/actions/runs/37519099848):

| Metric | Baseline | Feature | Change |
| --- | ---: | ---: | ---: |
| TPS | 10,594 | 11,892 | +12.25% |
| Builder throughput, Mgas/s | 1,735.8 | 2,010.8 | +15.85% |
| Validator throughput, Mgas/s | 2,079.1 | 2,445.0 | +17.60% |
| Mean block time, ms | 742.0 | 773.6 | +4.26% |
| Block time p99, ms | 14,376 | 13,202 | inconclusive |

The workflow classifies this as mixed: throughput improves significantly but mean
block time regresses. The 95% run-bootstrap interval for TPS improvement is
±5.18 percentage points. Process write bytes per included transaction per node
fell from 24,479 to 21,787 (11.0%); sorted trie-update entries fell from 8.22 to
5.52 (32.9%). These counters cover all node work, not only nonce storage.

### Overhead diagnosis

[Instrumented workflow, feature `f14314e6e`](https://github.com/tempoxyz/tempo/actions/runs/37526836312)
uses one pair of the same workload. Its throughput comparison is exploratory,
not a statistically significant replacement for three pairs.

Temporary counters and timers covered cache lookup, lock wait/hold, snapshot destruction,
history reads/reconstruction/signature recovery, pool head stages, expiry,
membership checks, insertion stages, per-transaction commitment hashing, and
final root aggregation. Hot paths sampled one call per 1,024 per thread; block
operations recorded every call. Slow operations (at least 10 ms) retained tracing
block context. Sampling left an unfinished tail on each thread. This diagnostic
instrumentation and its analysis script were removed after measurement; the
results below describe the instrumented revisions linked here.

The measured window excludes the first five included blocks, matching the
repository summary. Counter deltas use scrapes inside that window. Latency
quantiles below are the range across the two nodes of the **median rolling
quantile over scrapes**, not quantiles pooled over the whole run. Nested timers
must not be added together. `pool_head` also includes inner validator bookkeeping,
so its duration is not exclusively nonce CPU work.

| Operation | Mean | Rolling p50 | Rolling p99 | Observed maximum |
| --- | ---: | ---: | ---: | ---: |
| Expiry advance | 5.47 ms | 0.176–0.202 ms | 63.5–90.5 ms | 224.8 ms |
| Pool environment construction | 6.51 ms | 0.177–0.193 ms | 34.2–48.1 ms | 138.4 ms |
| Cache remember mutex held | 1.48 ms | 0.941–1.063 ms | 5.35–5.71 ms | 10.94 ms |
| Nonce check | 0.498 µs | 0.277–0.361 µs | 0.942–1.051 µs | 194.3 µs sampled |
| Insertion updates, excluding check | 1.568 µs | 1.092–1.182 µs | 5.38–6.23 µs | 373.1 µs sampled |
| Per-transaction commitment hash | 0.334 µs | 0.301–0.320 µs | 0.722–0.781 µs | 3.22 µs sampled |
| Final root aggregation | 2.333 µs | 1.583–1.603 µs | 6.31–6.71 µs | 100.9 µs |

There were 2,432 cache hash hits and zero misses, 483 pool snapshot hits, and no
history reconstruction/signature recovery in the measurement window. Thus this
run does not support increasing the 16-entry cache. Sampled check-site counts
were 5.22 million executor, 16.58 million handler (including pool admission), and
4.84 million insertion checks across both nodes. Repeated checks have a measurable
cost, but the measured serial hash and bounded root aggregation are much smaller
than expiry bursts. Their validation and commitment algorithms remain unchanged.

Eight gaps above two seconds totaled 67.733 seconds (individual gaps 2.753–14.911
seconds). The union of observed slow nonce intervals across both nodes overlapped
0.332 seconds of those gaps, with at most 96 ms in any one gap. The ten largest
expiry batches finished 0.59–1.34 seconds after the nearest gap's ending block
timestamp. This is evidence of expensive catch-up expiry, not evidence that it
caused the preceding multi-second gaps. Sampled sub-10-ms work and indirect
scheduling effects are not excluded; the remaining gap cause is unestablished.

Confirmed fixes remove both pool parent-expiry passes, use bulk expiry for large
bursts, and move snapshot destruction/expiry out of the cache mutex. A retained
300,000-ID parent snapshot gives these local median expiry times:

| Expired IDs | Individual deletion | Optimized |
| --- | ---: | ---: |
| 30,000 (10%) | 8.41 ms | 8.06 ms |
| 270,000 (90%) | 40.58 ms | 2.13 ms |
| 300,000 (100%) | approximately 42 ms | 0.001 ms |

The 10% and 90% cases use eight repeats; the original full-expiry comparison
used sixteen. These are lifecycle microbenchmarks, not node throughput gains.
Use `cargo bench -p tempo-expiring-nonces --bench lifecycle` to reproduce.

### Node measurements after the overhead fixes

[The three-pair optimized rerun](https://github.com/tempoxyz/tempo/actions/runs/37532812201)
uses `93b3d8a06` against the original baseline and workload:

| Metric | Baseline | Optimized | Change |
| --- | ---: | ---: | ---: |
| TPS | 11,751 | 13,074 | +11.26% ±2.93 pp |
| Builder throughput, Mgas/s | 1,876.3 | 2,179.6 | +16.16% ±3.18 pp |
| Validator throughput, Mgas/s | 2,212.8 | 2,598.0 | +17.41% ±4.50 pp |
| Mean block time, ms | 707.8 | 751.1 | inconclusive |
| Block time p50, ms | 416 | 436 | +4.81% ±2.00 pp, regression |
| Block time p99, ms | 12,067 | 13,759 | inconclusive |
| Builder latency p50, ms | 228.7 | 235.2 | +2.84% ±1.38 pp, regression |

Intervals are the repository's 95% run-bootstrap intervals in percentage points.
The overall result remains mixed: throughput improves, while median block and
builder latency regress. This comparison establishes the gain against the
original storage backend. It does not establish additional node throughput from
the overhead fixes: the earlier feature and this feature ran on different
runners. All included transactions succeeded; neither arm recorded EVM reverts.

Normalized process write bytes per included transaction per node fell from
23,954 to 21,251 (11.3%), read bytes from 26,120 to 25,266 (3.3%), and sorted
trie-update entries from 8.15 to 5.37 (34.1%). These are counters for the whole
node. The feature included 6,667,301 transactions after warmup, versus 5,947,303
for the baseline.

The nonce diagnostics show the following changes. Means pool observations;
after-fix rolling p99 ranges span the six node/run series. The before and after
runs used different runners, so these are observed component timings rather than
a paired estimate of the optimizations' additional TPS effect.

| Operation | Before mean | After mean | After rolling p99 | After observed maximum |
| --- | ---: | ---: | ---: | ---: |
| Pool head, including inner bookkeeping | 14.610 ms | 0.189 ms | 0.317–0.483 ms | 2.077 ms |
| Pool environment construction | 6.507 ms | 15.434 µs | 19.94–87.92 µs | 0.603 ms |
| Cache remember mutex held | 1.481 ms | 1.463 µs | 2.78–3.19 µs | 0.252 ms |
| Snapshot destruction, now outside mutex | 1.476 ms | 1.421 ms | 4.15–6.19 ms | 10.601 ms |
| Expiry advance | 5.472 ms | 3.525 ms | 19.14–32.00 ms | 117.606 ms |
| Full-set expiry | — | 1.778 µs | 1.65–2.86 µs | 3.27 µs |
| Nonce check | 0.498 µs | 0.541 µs | 1.04–1.66 µs | 899.7 µs sampled |
| Insertion updates, excluding check | 1.568 µs | 1.717 µs | 5.49–6.60 µs | 1.666 ms sampled |
| Per-transaction commitment hash | 0.334 µs | 0.362 µs | 0.77–1.01 µs | 106.3 µs sampled |
| Final root aggregation | 2.333 µs | 2.853 µs | 6.75–8.67 µs | 340.1 µs |

All 5,416 cache hash lookups hit (100%); all 1,343 pool head lookups reused a
snapshot and constructed their environment directly. There were zero measured
history reconstructions or signer recoveries. Cache hash-lock wait averaged
0.492 µs. All 55 full-expiry events used the reset path. The greater-than-75%
partial-rebuild path was not exercised in this workload; its evidence is the
lifecycle benchmark above. Individual deletion for smaller partial batches
remains measurable: the slowest advance expired 67,636 of 165,454 IDs in 117.6 ms.
Snapshot destruction still costs about 1.4 ms, but no longer holds the shared
cache mutex while doing that work.

Sampled check-site estimates were 14.44 million executor, 45.22 million handler,
and 13.36 million insertion calls across both nodes and all three runs. Checks
remain repeated; the measured costs above do not justify changing their replay
validation semantics in this patch. Per-transaction commitment maintenance and
final aggregation were measured separately.

There were 25 feature block gaps above two seconds, totaling 228.448 seconds.
Observed slow nonce intervals overlapped 0.411 seconds of those gaps, at most
76.2 ms in one gap. The gaps and the median latency regression remain unresolved.
These observations do not exclude smaller unlogged work or indirect scheduling
effects, and do not establish an unrelated component as the cause. The fixes
remove demonstrated nonce overhead; the full-node result is still mixed.

Two earlier dispatches failed before sending transactions because other
processes occupied auth RPC port 8103 and then alternate metrics port 19001.
Free-port selection applies equally to feature and baseline.

### Supporting storage microbenchmark

The local `expiring_nonces` benchmark isolates nonce overhead:

```sh
cargo bench -p tempo-evm --bench expiring_nonces
TEMPO_NONCE_BENCH_WARMUP=3000 cargo bench -p tempo-evm --bench expiring_nonces
```

It executes the legacy nonce manager and persists plain storage, hashed storage,
and incremental storage-trie updates to MDBX. The memory variant includes expiry,
fork snapshots, validation, and commitment calculation. Both durably commit one
header-root record per measured block. Full transaction execution, signatures,
account-trie updates, and common block persistence are outside this timer, so its
speedup measures nonce overhead rather than node throughput.

Local measurements with 100 blocks of 1,000 transactions each:

| Initial state | Storage backend | Memory backend | Nonce-overhead speedup |
| --- | ---: | ---: | ---: |
| Empty | 3,062.65 ms | 81.11 ms | 37.8x |
| After 3,000 warmup blocks | 17,830.71 ms | 198.95 ms | 89.6x |

The warmed run fills the old 3-million-entry ring; the memory backend retains only
the 300,000 unexpired IDs. The storage backend writes 195,622 trie nodes in the
empty run and 732,619 in the warmed run. The memory backend writes no nonce trie
nodes. These isolated timings are supporting measurements, not end-to-end TPS.
