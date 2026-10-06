# QMDB development-backend benchmark — October 6, 2026

The port builds, imports, validates and persists development blocks. In this
small-state workload, the QMDB prototype is **slower** than the MPT backend:
12.08× higher mean submission/build/import latency and 2.34× higher mean latency
through the harness's durable-persistence check. These results are not a production
TPS estimate or a root-only microbenchmark.

## Configuration

- Tempo: `ba37e4b4f982a9a399c8d5c8fb898bed4c95590c`, based on main `3bfcf42140`.
- Reth: `362dea1d85d77fd3f960ab6ef13e9dee6d503f83`, based on main
  `8cd725d582628cfbe5c1903aa3f88eac6c3a7243`.
- Commonware storage: `2a7dd423f0a241276a5a38db8cc3d05f11de0c03`.
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
| MPT | 2.773 | 5,769.6 | 23.842 | 671.1 |
| QMDB | 33.493 | 477.7 | 55.755 | 287.0 |

## Per-round results

These percentiles are per round, not pooled percentiles across all rounds.

| Round | Backend | Build/import mean | Build/import p50 | Build/import p95 | Through durability mean | Through durability p50 | Through durability p95 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | MPT | 2.819 | 3.036 | 3.517 | 23.922 | 24.142 | 24.671 |
| 1 | QMDB | 36.633 | 33.651 | 72.718 | 58.323 | 54.731 | 93.808 |
| 2 | MPT | 2.799 | 2.978 | 3.654 | 23.874 | 24.065 | 24.845 |
| 2 | QMDB | 35.891 | 33.476 | 78.159 | 58.663 | 54.548 | 105.534 |
| 3 | MPT | 2.702 | 2.886 | 3.547 | 23.730 | 23.936 | 24.662 |
| 3 | QMDB | 27.956 | 24.417 | 66.347 | 50.279 | 45.485 | 87.427 |

All latency columns are milliseconds per block.

## Reproduction

```sh
CARGO_PROFILE_RELEASE_LTO=false QMDB_BENCH_BLOCKS=100 QMDB_BENCH_TXS=16 QMDB_BENCH_ROUNDS=3 \
  cargo test -p tempo-qmdb-bench --release --test backend bench_mpt_vs_qmdb \
  -- --ignored --nocapture
```

The completed benchmark test took 26.80 seconds after compilation and returned
success. Each `QMDB_BENCH` line contains the full-precision JSON summary.

Signing, token-balance probes, receipt checks and pool-head synchronization happen
outside the timed interval. The processing interval covers pool submission,
payload construction, engine validation and canonical import. The longer interval
also waits for canonical persistence, using a 20 ms condition-polling interval;
that polling dominates much of the MPT durability measurement. Neither interval
isolates QMDB hashing, storage I/O or root calculation, and the benchmark is serial
rather than a saturation test. No large-state preload or optimization is claimed.

See `../../crates/node/QMDB.md` for the isolated-dev-only restrictions, fork,
proof, contract-wipe and crash-consistency limitations of this prototype.
