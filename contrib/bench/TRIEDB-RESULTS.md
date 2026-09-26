# Native TrieDB public-mix experiment — 2026-09-26

## Scope

This experiment routes Reth's plain/hashed account and storage records into the
actual Category Labs native TrieDB library. It does not replace Reth's
authenticated-trie computation, history, chain metadata, or execution engine.
The adapter is opt-in and not production-ready.

## Revisions and binaries

- Baseline Tempo: [0edc0c7fe4953c6024e5bd37f05cd5149f6c8014](https://github.com/tempoxyz/tempo/commit/0edc0c7fe4953c6024e5bd37f05cd5149f6c8014).
- Candidate Tempo: [781c1036b10193c852d66b2783fe63b08826b13a](https://github.com/tempoxyz/tempo/commit/781c1036b10193c852d66b2783fe63b08826b13a).
- Candidate Reth: [c6bbfb47bbb91f837e74e293de751ebded0be5bd](https://github.com/paradigmxyz/reth/commit/c6bbfb47bbb91f837e74e293de751ebded0be5bd).
- Native Monad: [fd0faba2537e18a57266c0dad84c31acb08e37fa](https://github.com/category-labs/monad/commit/fd0faba2537e18a57266c0dad84c31acb08e37fa).
- Txgen/bench: [9d425938](https://github.com/tempoxyz/txgen/commit/9d425938).
- Samply fork: [24fd6ce78f206513751f996b6aae7a2cba54e5e7](https://github.com/danipopes/samply/commit/24fd6ce78f206513751f996b6aae7a2cba54e5e7).
- Baseline binary SHA-256: `3f75959c872a51d34e9893ad3309ba69d993662d2cd3572e623404390d3911eb`.
- Candidate binary SHA-256: `1427f8578555922d7851ca2634dc4980708ac3d60b5315dc406f26dee3ce20a9`.
- Native library SHA-256: `ec37d5ca9a6aa28c46b8258034efe6a5e00154b1e77c0357ad88e12b0949c726`.

Both Tempo binaries use stable Rust, the `profiling` profile,
`RUSTFLAGS='-C target-cpu=native'`, default features, and `jemalloc,asm-keccak`.
The candidate additionally enables `monad-triedb`. Harness portability changes
through [614dd7414c364131c17eaebe1baf28faf909d16e](https://github.com/tempoxyz/tempo/commit/614dd7414c364131c17eaebe1baf28faf909d16e) apply equally to both sides;
they do not change either node binary.

## Machine and method

- Latitude `m4-metal-medium`, Frankfurt: AMD EPYC 9124, 16 cores/32 threads,
  approximately 125 GiB RAM, Ubuntu 24.04.
- Dedicated NVMe 1: ext4 MDBX datadirs and pristine snapshots for both validators.
- Dedicated NVMe 2: two unmounted raw partitions, one native TrieDB per validator.
  OS RAID devices are separate and were not modified.
- The supported single-runner `bench-e2e.nu e2e` topology: two validators, disjoint
  16-thread CPU sets, 60 GiB memory limits, and 1 GiB reserved huge pages for both
  baseline and candidate. This is not the ten-validator multi-region topology.
- Existing `public-mix`: 80% TIP20 transfers, 5% mints, 15% MPP channel opens.
- `--bloat 1` means a 1,000 MiB generated dump in this harness, containing
  16,383,996 imported storage entries; it is not a 100 GiB state benchmark.
- 90-second generation window, 50,000 target TPS, 1,000 sender accounts,
  5,000 concurrent requests, three paired runs, five summary warmup blocks,
  Samply profiling enabled. Original database contents are restored each phase.
- A baseline-versus-baseline noise check precedes the same-parameter
  baseline-versus-candidate comparison. Native migration is before timed load.

## Baseline noise control

The completed main-versus-main control is classified **No Difference** by the
existing run-cluster bootstrap classifier (10,000 resamples, 95% confidence).
All classified axes are neutral. Mean throughput is 11,525 versus 11,532 TPS
(+0.0607%, confidence half-width 1.8322 percentage points); mean block time is
474 versus 477 ms. All six phases completed. The summary's `success_rate` is
the measured on-chain execution success rate, not RPC submission success;
submission failures are recorded separately in each sender report.

## Native TrieDB comparison

The classifier reports **Mixed Results**, not an improvement. Executed
throughput falls from **11,595 to 552 TPS (-95.2393%)**, well outside the
main-versus-main noise floor (comparison confidence half-width: 0.8639
percentage points). This adapter is not a useful performance replacement in
the measured configuration.

| Metric | MDBX | Native TrieDB | Change |
| --- | ---: | ---: | ---: |
| Executed throughput | 11,595 TPS | 552 TPS | -95.24% |
| Gas throughput | 1,069.5 Mgas/s | 51.0 Mgas/s | -95.23% |
| Mean block time | 475.8 ms | 507.8 ms | +6.73% |
| Builder P50 | 205.0 ms | 249.3 ms | +21.61% |
| Validation P50 | 161.5 ms | 238.9 ms | +47.93% |
| Validation P99 | 246.4 ms | 371.8 ms | +50.89% |

Per-pair baseline/candidate throughput is 11,549/553, 11,719/554, and
11,518/549 TPS. The classifier labels builder P99 and block P90/P99 as
improvements, but the candidate's median serialized block size is only
79,429 bytes versus 1,539,819 bytes. Those latency improvements do not establish
faster execution of equivalent work.

All measured included transactions execute successfully. Separately, sender
reports and logs contain submission failures, including `valid_before` expiry
rejections. Sender `failed` counts and included-transaction counts have different
semantics; neither the summary's 100% execution success nor the sender's
submission rate should be interpreted as the fraction of generated transactions
that landed on chain.

## Profile and disk evidence

The first pair's validator-A Samply profiles were inspected over the 90-second
sender window, excluding migration and post-load drain. CPU shares are weighted
by `threadCPUDelta`; the fork's absolute monotonic sample times are approximately
aligned to the first recorded sample and wall-clock capture start.

- Baseline leading self frames include secp256k1 multiplication (7.04%),
  Keccak permutation (4.53%), and memcpy (3.07%).
- Candidate native service-thread queue polling (`ConcurrentQueue::try_dequeue`)
  consumes 31.13% self CPU. Inclusive stack shares include AsyncIO (10.50%),
  futex paths (11.05%), and `reth_triedb_seek` (6.92%). These shares overlap and
  are not percentages of blocked wall time.
- During the middle 70 seconds of each generation window, raw-NVMe reads average
  only 0.29–0.33 requests/s, writes 3.38–3.71 MiB/s, and utilization 0.08–0.10%.
  Baseline filesystem-NVMe reads average about 4.6 requests/s. `iostat` had
  one-second intervals without timestamps, so alignment uses the job start and
  ten-second margins rather than claiming exact subsecond correlation.

The storage read bandwidth targeted by the raw-device design is not the current
bottleneck in this RAM-resident workload. The profile and the adapter's
writer-mutex-protected, blocking ordered seeks suggest integration overhead;
they do not isolate the causal share of each synchronization cost. A useful
next design would need efficient concurrent storage lookups/cursors and
asynchronous batching, followed by another paired measurement. Merely using a
raw block device is insufficient. No unrelated execution optimization was made.

## Retained evidence

- [Main-versus-main summary](triedb-results/2026-09-26/noise-summary.json).
- [MDBX-versus-TrieDB summary](triedb-results/2026-09-26/comparison-summary.json).
- [Profile analysis](triedb-results/2026-09-26/profile-analysis.json) and
  [disk analysis](triedb-results/2026-09-26/iostat-analysis.json).
- Source result directories: `20260926-155220-096` (noise) and
  `20260926-161102-900` (comparison). Autogenerated observability links in the
  summaries do not imply results were published to those services.
- Unmodified representative profile SHA-256 hashes:
  - `profile-baseline-1-a.json.gz`:
    `f275d05afee524779549301305224935b01e5b017df7d648f96bc40d4048ecae`.
  - `profile-feature-1-a.json.gz`:
    `23f367ff6a228bacea1297dfa5960783767049efa407b5d4a19acbfbf7ef5304`.

## Correctness validation

Two native tests pass on the benchmark machine: MDBX-equivalence testing and an
explicitly destructive raw-device commit/reopen round trip. Equivalence coverage
includes all four tables, migration, concurrent readers, ordered/duplicate
cursors, staged writes, aborts, clears, old snapshots, and unreferenced native
commits. All 38 standard `reth-db` unit tests pass with and without the feature.

Package-level nightly Clippy with `--all-targets --no-deps -- -D warnings`,
nightly formatting, the no-default-features check, locked Tempo dependency
resolution, and the candidate profiling build pass. Dependency-wide Clippy
encounters existing warnings in `reth-trie-common`; these were not changed.

## Interpretation limits

The seeded dataset fits in system RAM, the generator may not reach its target,
and both validators and the generator share one physical host. This does not
establish a large-state NVMe advantage. The stock datadir-size metric excludes
the raw TrieDB device and is not a total storage-footprint comparison.

The bridge uses fixed-width physical keys and serialized ordered seeks, not
Monad's production Ethereum layout and complete asynchronous execution path.
Native initialization is destructive, backups must include matched MDBX/native
data, and the native bridge/library is GPL-3.0-or-later. See [setup and remaining
limitations](TRIEDB.md) before running it.
