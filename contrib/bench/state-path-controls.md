# Ordinary state-path controls

These end-to-end controls measure ordinary contract calls and writes with a small
active working set on the existing storage-bloated database. They do not test
cache evasion, disk-bound bytecode working sets, or a worst case per gas.

## Workloads

- `state_paths_read.yml` deploys the existing, unmodified StrategyVault artifact
  and calls its `name`, `symbol`, and `decimals` getters in an ordinary multicall.
- `state_paths_write.yml` deploys the same artifact and performs ordinary ERC20
  approvals to one fixed spender. Amounts vary between 1 and 1000000, with no
  state-dependent address selection. There are 1000 users.
- Both use the same existing expiring-nonce transaction format, fee token,
  base node revision, offered 50000 TPS, 900-transaction block cap, role isolation,
  builder prewarming, CPU/device allocation, and database snapshots as the
  archived SLOAD reference. They do not have the same gas per transaction.
- Each load lasts 1200 seconds, excluding 600 seconds of warmup. Setup and
  deployment are outside the reported steady-state interval.

## Observation and validation

`bench-e2e.nu e2e --observe-state-paths` enables the observer only for these two
isolated presets. It samples node metrics and database-device cgroup I/O every
five seconds, and reads the committed Finish checkpoint approximately every
30 seconds. Checkpoint reads are read-only; per-scope `IOAccounting` is enabled
without changing I/O resource limits.

Fallback restoration validates a direct scratch child of the configured mount,
removes privileged scratch descendants, and checks removal/copy exit status.
Copies cannot nest inside an existing destination. Ordinary controls verify
both restored Finish checkpoints are zero before startup. Restoration never
modifies the preserved `.virgin` snapshots.

After load, the audit checks receipts from eight distributed steady-state
blocks. Three real transaction call traces verify the intended selectors, and
storage-diff traces verify the presence or absence of application storage
changes. Receipt gas, rather than call replay gas, is the basis for comparison.

The audit then observes an advancing run of empty blocks and waits for both
nodes' persisted state/trie frontiers to reach the quiet-tail target. This checks
that included work reached persistence; it does not assert every RPC submission
was included. Tracing is after load and is excluded from load I/O measurements.

## Analysis

The runner is host-specific and uses an explicitly supplied patched node binary and preserved virgin
snapshots. It restores only the benchmark's scratch copies, and serializes with
the previous benchmark's lock. Its service log is under `/mnt2`.
When using a systemd file log, make it writable by the service user: Nushell's
sender helper reopens stdout/stderr. The runner checks this before restoring data.

```sh
export STATE_PATH_FEATURE_BINARY="$PWD/bench-results/build-payload-cancel-20260923-v3/tempo"
bash contrib/bench/run-state-path-controls.sh
node contrib/bench/analyze-state-path-controls.cjs bench-results/state-path-controls-patched-20260923-v4
node --test contrib/bench/state-path-observer.test.cjs contrib/bench/analyze-state-path-controls.test.cjs
```

The binary's directory must contain `build-manifest.json`, including its
`binary_sha256`. Each case records the binary path, SHA256, and version; analysis
rejects mismatches. The historical SLOAD reference is unpatched, so this is not
a same-binary comparison. The local cancellation fix includes both Tempo and
an isolated copy of its pinned Reth dependency. Apply the
[archived dependency patches](patches/README.md) and generate the local Cargo
config before building:

```sh
RUSTFLAGS='-C target-cpu=native' SOURCE_DATE_EPOCH="$(date -u +%s)" \
  VERGEN_GIT_SHA="$(git rev-parse HEAD)" \
  VERGEN_GIT_DIRTY=true VERGEN_BUILD_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  cargo build --offline --config contrib/bench/payload-cancel-patches.toml \
  -p tempo --bin tempo --profile profiling --features jemalloc,asm-keccak -j8
```

The patch configuration contains host-local paths. Preserve both source patches
and the configuration with the build manifest; the base commit alone does not
identify this binary. Do not replace the historical binary cache with it.

The patched Reth build also sizes RocksDB cache shards to at least 16 MiB when
the total budget permits, while preserving the configured total capacity. This
lets legacy multi-megabyte index blocks remain resident instead of repeatedly
decompressing because they exceed a default shard's capacity. The new default
is eight shards within the same 128 MiB budget, not a larger cache.

For live persistence probes, the verified build directory contains
`read_finish_checkpoint`. It opens only the existing MDBX directory read-only
and reads the typed Finish checkpoint; it does not initialize static files or
RocksDB. The observer discovers this helper beside the node binary, or accepts
`--checkpoint-tool`. Its separate `observer-manifest.json` records provenance.
The full `tempo db get` fallback can fail static-file consistency checks during
active writes; those failures remain errors, never zero-valued checkpoints.

The ordinary-control analyzer writes `throughput.json` and `throughput.md` with
canonical included-block gas per wall-clock second, execution-only rates,
source-specific cache misses, payload-thread fault coverage, whole-node I/O,
and persistence lag. It rejects counter resets and insufficient observer or
frontier coverage rather than interpreting missing data as zero.

A transaction-cap-limited result is not maximum execution capacity. A cache-hot
ordinary control cannot establish how a cold-code or large-write working set
would perform. Device-wide counters in the older reference are not equivalent
to the new per-node cgroup counters; both scopes remain explicit in the output.
