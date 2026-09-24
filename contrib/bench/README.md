# Benchmarks

- [Saved state-access configurations](configs/README.md): matched SLOAD,
  bytecode, and write workloads on a shared bloated database. List them with
  `nu bench-e2e.nu state-access-bloat-worst-case --list`. Run all three with
  `nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD`.
- [History-dependent state-path protocol](history-state-paths.md): fixture
  preparation, cache-evasion validation, I/O, and persistence measurements.
- [Cache-resident controls](resident-state-paths.md): reproducible ordinary
  bytecode/read and write controls without an imported bloated database.
