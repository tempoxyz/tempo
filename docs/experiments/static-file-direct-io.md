# Static-file direct I/O under Tempo load

## Revisions

- Tempo baseline: `3912cff1ff52de0c90b3512b56e746e2e87b248e` (upstream main fetched September 16, 2026).
- Tempo candidate: `b10b448a4b2d1b2fba7027fbc02548f09329bd78`.
- Original Reth pin: `95823365b9f0787a676de38c044b54830e3fb29d`.
- Patched Reth pin: `68cd59586c3dbc565230c2fdba64a4ef4f8bfd1e`, based on that exact original pin.
- Transaction generator: `5ab341ae38a875e9755cb93628af96ee020ebf38`.

The candidate uses direct I/O for static-file data and sidecars on Linux, with a
shared 64 MiB application cache of 4 KiB blocks. It preserves Tempo's other
dependencies and does not change MDBX or RocksDB.

## Protocol

[GitHub benchmark run](https://github.com/tempoxyz/tempo/actions/runs/35087336997)
uses the existing `bench-e2e.yml` workflow with:

| Setting | Value |
| --- | --- |
| Target transaction rate | 50,000 TPS |
| Duration | 300 seconds per phase |
| Baseline/candidate pairs | 3 |
| State-bloat fixture | 100 GiB parameter |
| Validators | 2 on the dedicated dual-schelk runner |
| Memory limit | 60 GiB per validator |
| Workload | `default`: TIP20 transfers to existing recipients, four fee tokens |
| Sender accounts | 1,000 |
| Concurrent requests | 500 |
| Profiling / OTLP | Disabled |

Both binaries use the same harness, snapshot restoration, and workload settings.
The state-bloat parameter is not a measurement of the final database file size.
Achieved TPS must be taken from the resulting reports, not from the target rate.

Before and after each timed workload, the harness records file-cache residency
for MDBX, static files, and RocksDB, plus cgroup memory/I/O counters and pressure.
`fincore` runs as root and inspects page residency without reading file contents.
Snapshots are taken while the nodes are alive, outside the timed workload.
They are observations at two times, not continuous peak-residency measurements.
Errors and missing files remain explicit in the JSON artifacts.

## Validation

- Tempo binary `cargo check --locked` and nightly format check passed locally.
- Patched Reth targeted storage tests and local clippy passed.
- [Linux Reth CI](https://github.com/paradigmxyz/reth/actions/runs/35086915646)
  passed: 31 direct-I/O/recovery tests, workspace clippy, and 3,331 workspace
  tests (7 skipped). The existing randomized reorg-consistency test passed on
  retry; the same failure was reproduced on unmodified upstream during the
  earlier Reth experiment.
- The Linux cache-probe test verifies that direct writes/reads leave zero pages
  resident, while buffered reads make the same file resident.
  [Probe CI](https://github.com/tempoxyz/tempo/actions/runs/35087298690) passed.

## Results

The run completed successfully. Direct I/O eliminated measured static-file page
residency, but the throughput comparison did not establish a performance gain.

### Throughput and latency

These are the existing workflow's summary values, excluding five initial blocks
per phase. Its run-cluster bootstrap classifies the TPS change as neutral
(-2.69% with a reported 5.95 percentage-point confidence bound). The workflow's
overall "Improvement" label comes with an improved median block interval; it
does not establish a throughput improvement.

| Metric | Baseline | Direct I/O + cache | Change |
| --- | ---: | ---: | ---: |
| Included transaction throughput | 8,518 TPS | 8,289 TPS | -2.7% (neutral) |
| Block interval p50 | 477 ms | 453 ms | -5.0% (good) |
| Block interval p99 | 6,409 ms | 5,245 ms | -18.2% (neutral) |
| Builder latency p50 | 197.8 ms | 190.1 ms | -3.9% (neutral) |
| Builder latency p99 | 460.4 ms | 457.4 ms | -0.7% (neutral) |
| Validation latency p50 | 183.2 ms | 170.8 ms | -6.8% (neutral) |
| Validation latency p99 | 567.5 ms | 551.7 ms | -2.8% (neutral) |

| Pair | Baseline TPS | Candidate TPS | Change |
| --- | ---: | ---: | ---: |
| 1 | 8,342 | 8,589 | +3.0% |
| 2 | 8,644 | 8,611 | -0.4% |
| 3 | 8,569 | 7,666 | -10.5% |

The third candidate run produced smaller blocks (4,284 transactions per block,
versus 6,996 in its baseline). Lower block latency alone does not mean higher
execution capacity. Candidate builder invalid-transaction skips totalled 849,
versus 6 for baseline; the cause was not established by this experiment.

The 50,000 TPS setting was a target. The sender achieved approximately 26.8k
accepted submissions/sec for baseline and 26.6k for candidate, with zero RPC
submission failures. Only approximately 8.5k/8.3k TPS were included during the
measured block range. The optional txpool-drain wait was disabled, so accepted
submissions must not be interpreted as completed transactions.

### Cache residency and pressure

The initial per-validator files were 100 GiB MDBX, 91.55 GiB static files, and
49.47 GiB RocksDB. The benchmark's initial-size metadata counts only MDBX and
static files (191.55 GiB), excluding RocksDB.

All 12 before/after snapshots returned complete file-residency measurements.
Static-file residency was **281.55–345.94 MiB per baseline validator** after the
run and **zero bytes in every candidate after snapshot**. Before each workload,
static-file residency was 256 KiB for baseline and 4 KiB for candidate; MDBX
had approximately 1.6 MiB resident.

Across the six after snapshots per side, mean MDBX residency was 12.42 GiB for
baseline and 12.85 GiB for candidate. These are observations, not a causal speedup
estimate: the first candidate snapshot was delayed by ClickHouse post-processing
(546 seconds between phase markers, versus approximately 358 seconds otherwise).
Nodes continued running during post-processing.

Each validator recorded millions of major faults and scanned pages during its
snapshot interval. The 60 GiB per-validator memory limit was not reached: observed
cgroup peaks were approximately 35–45 GiB and there were no memory-limit or OOM
events. The raw totals cover different amounts of completed work and include
post-processing; they cannot establish a normalized MDBX improvement.

The runner did not expose cgroup `io.stat`; that measurement is unavailable.
File residency and memory counters succeeded. Workload-window storage metrics
are reduced separately by `.github/scripts/bench-direct-io-metrics.py` from the
original artifact, with its archive digest verified.

The workload-window host metrics show at least **82.4 GiB of available memory**
throughout the sampled periods, on a 125.4 GiB host. Memory-pressure waiting
accounted for approximately 0.6–0.7% of each measured interval, while I/O-pressure
waiting accounted for approximately 17–19%. This was an I/O-heavy workload, but
these measurements do not demonstrate sustained page-cache capacity pressure.
The large database fixture alone does not establish that pressure.

### MDBX timings

[Metric analysis run](https://github.com/tempoxyz/tempo/actions/runs/35093286967)
reduced the original workload samples after the five-block warmup. Within each
phase, duration and count deltas are combined across the two validators; the
table compares arithmetic means of the three phase means. These are descriptive
measurements without confidence intervals, unlike the workflow's TPS comparison.

| Metric | Baseline | Direct I/O + cache | Change |
| --- | ---: | ---: | ---: |
| MDBX save work per batch | 3,816.5 ms | 2,946.9 ms | -22.8% |
| MDBX commit per call | 942.2 ms | 982.9 ms | +4.3% |
| Static-file save work per batch | 549.4 ms | 570.1 ms | +3.8% |
| Static-file finalize per call | 3.22 ms | 4.13 ms | +28.4% |
| Blocks per save batch | 6.83 | 6.69 | -2.0% |

`save_blocks_mdbx` times block/state writes, hashed-state and trie work, history
updates, and checkpoints on the MDBX path. It excludes the later transaction
commit. The static-file and RocksDB writes run concurrently; the MDBX path
dominates total save time in this workload. The commit metric directly times
`self.tx.commit()` and includes provider commits beyond block-save batches, so
its call counts differ from the save counts.

The lower MDBX batch time is encouraging, but it is not a measurement of equal
work: candidate phase three averaged 4,284 transactions per block, versus 6,996
in baseline. Its MDBX batch time fell to 2,055 ms, versus 3,813 ms, while included
TPS fell 10.5%. Even in the first two pairs, where included TPS was similar, MDBX
batch time fell 13.3% and 9.0%, but commit time rose 16.2% and 10.3%.

### Interpretation

Direct I/O works as intended: it removes the approximately 315 MiB average
static-file page-cache footprint measured after baseline phases. This experiment
does **not** establish an end-to-end throughput gain or a consistent MDBX gain.
The 50k target was not sustained, the candidate had variable block sizes, and
the runner retained considerable memory headroom. A stronger test of the original
cache-contention hypothesis would require a controlled memory-constrained run
with comparable completed work and sustained memory pressure.

The summary, per-run results, cache snapshots, and compact storage/pressure
evidence are committed in [static-file-direct-io-results.json](static-file-direct-io-results.json).
