# Benchmarks

- [Saved state-access configurations](configs/README.md): matched SLOAD,
  bytecode, and write workloads on a shared bloated database. List them with
  `nu bench-e2e.nu state-access-bloat-worst-case --list`. Run all three with
  `nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD`.
- [History-dependent state-path protocol](history-state-paths.md): fixture
  preparation, cache-evasion validation, I/O, and persistence measurements.
- [Cache-resident controls](resident-state-paths.md): reproducible ordinary
  bytecode/read and write controls without an imported bloated database.
- [Declared storage](declared-state-paths.md): separate read/write presets using
  existing native access lists, signed-list audits, and durable slot throughput.
- [Transaction-size controls](sload-size-isolation.md) and
  [latency calibration](state-access-latency.md): bounded transaction sizes,
  cancellation-aware wall time, and controlled prewarming comparisons.
- [Completed results](../../bench-results/README.md): reports, structured data,
  write-persistence diagnosis, and artifact provenance.
- [Benchmark dependency patches](patches/README.md): pinned txgen access-list
  support and the experimental Reth changes used by the recorded binaries.
