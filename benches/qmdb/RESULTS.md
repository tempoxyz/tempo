# QMDB development-backend benchmark — October 6, 2026

The port builds, imports, validates and persists development blocks. In this
small-state workload, the QMDB prototype is **slower** than the MPT backend:
13.14× higher mean submission/build/import latency and 2.42× higher mean latency
through the harness's durable-persistence check. These results are not a production
TPS estimate or a root-only microbenchmark.

## Configuration

- Tempo: `30a67ebf44c25d50f6bd21d9a27610d27cbf21eb`, based on main `3bfcf42140`.
- Reth: `adcaaa8291154a15ccb0e2986f40b08ebcd547f7`, based on main
  `8cd725d582628cfbe5c1903aa3f88eac6c3a7243`.
- Commonware storage: published `2026.9.0`, shared with Tempo's consensus packages.
- Bare metal: AMD EPYC 4484PX, 12 physical cores / 24 logical CPUs, FRA2.
- Rust: `1.101.0-nightly (ea137335b 2026-10-05)`; release optimization,
  debug assertions off, LTO disabled.
- Three rounds per backend, 100 measured blocks per round, 16 successful AlphaUSD
  TIP20 transfers per block to fresh recipients; 10 additional warmup blocks
  excluded per run. Order: MPT/QMDB, QMDB/MPT, MPT/QMDB.
- Fresh development-node state for every run. Both backends use the same branch,
  node harness, immediate-persistence settings and token fixture. This compares
  backend modes, not the branch against an unmodified-main binary.
- 300 measured blocks and 4,800 successful measured transfers per backend;
  660 blocks / 10,560 transfers including warmup. All included receipts succeeded.
- Token: `0x20c0000000000000000000000000000000000001`. Transfer gas limit:
  5,000,000; this is a limit, not measured gas usage.

## Aggregate results

Means are weighted equally across the three 100-block rounds. Throughput is
transactions divided by the sum of timed intervals, not the arithmetic mean of
the per-round throughput values.

| Backend | Build/import mean (ms/block) | Build/import observed tx/s | Through durability mean (ms/block) | Through durability observed tx/s |
| --- | ---: | ---: | ---: | ---: |
| MPT | 2.785 | 5,744.7 | 23.864 | 670.5 |
| QMDB | 36.602 | 437.1 | 57.702 | 277.3 |

## Per-round results

These percentiles are per round, not pooled percentiles across all rounds.

| Round | Backend | Build/import mean | Build/import p50 | Build/import p95 | Through durability mean | Through durability p50 | Through durability p95 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | MPT | 2.821 | 3.047 | 3.587 | 23.896 | 24.110 | 24.655 |
| 1 | QMDB | 35.492 | 31.671 | 71.323 | 56.626 | 52.689 | 92.449 |
| 2 | MPT | 2.737 | 2.929 | 3.443 | 23.775 | 23.982 | 24.509 |
| 2 | QMDB | 37.313 | 33.128 | 74.428 | 58.377 | 54.199 | 95.505 |
| 3 | MPT | 2.797 | 2.891 | 3.340 | 23.922 | 23.981 | 24.565 |
| 3 | QMDB | 37.000 | 33.149 | 71.995 | 58.104 | 54.274 | 92.522 |

All latency columns are milliseconds per block.

## Reproduction

```sh
CARGO_PROFILE_RELEASE_LTO=false QMDB_BENCH_BLOCKS=100 QMDB_BENCH_TXS=16 QMDB_BENCH_ROUNDS=3 \
  cargo test -p tempo-qmdb-bench --release --test backend bench_mpt_vs_qmdb \
  -- --ignored --nocapture
```

The completed benchmark test took 27.37 seconds after compilation and returned
success. The development-node independent-validation/persistence/restart test
also passed in the same release build (0.45 seconds).
Each `QMDB_BENCH` line contains the full-precision JSON summary.

These rerun results supersede the initial April-Commonware-snapshot report shared
in the Slack thread. The final branch pins Reth
`5d76959dbcee7b1db53c42e9ba31dc347cbc8623`; its only change after the measured SDK
revision is a narrowly scoped Clippy annotation for account-feature compatibility.
The subsequent Tempo changes only update that dependency reference and this report.
The runtime implementation measured here is otherwise unchanged.

Signing, token-balance probes, receipt checks and pool-head synchronization happen
outside the timed interval. The processing interval covers pool submission,
payload construction, engine validation and canonical import. The longer interval
also waits for canonical persistence, using a 20 ms condition-polling interval;
that polling dominates much of the MPT durability measurement. Neither interval
isolates QMDB hashing, storage I/O or root calculation, and the benchmark is serial
rather than a saturation test. No large-state preload or optimization is claimed.

See `../../crates/node/QMDB.md` for the isolated-dev-only restrictions, fork,
proof, contract-wipe and crash-consistency limitations of this prototype.
