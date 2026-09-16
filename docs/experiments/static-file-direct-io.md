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

Benchmark in progress. No performance or MDBX cache-benefit conclusion yet.
