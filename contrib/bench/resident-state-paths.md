# Reproduce the ordinary resident-state controls

This runner deploys one ordinary StrategyVault contract per case on a freshly
generated local chain. Reads call `name`, `symbol`, and `decimals`; writes call
`approve` for 1000 users and one fixed spender. It imports no state dump, installs
no state-access benchmark predeploy, and reads no historical result directory.
It is a throughput control, not a worst-case state-access workload.

## Prerequisites

Use the existing two-node Linux e2e benchmark host layout: 32 logical CPUs,
systemd/cgroup v2, passwordless benchmark sudo, and writable `/reth-bench-a` and
`/reth-bench-b` on the two database devices. The existing observer identifies
these as `nvme1n1` and `nvme2n1`; adapt the shared harness/observer together for
different hardware. This is not a laptop-portable replacement for the e2e host.
Both nodes share host RAM. The runner uses the existing CPU assignments and
60 GiB per-scope memory limit, not a memory reservation.

Install Nushell, Node.js 18+, GNU coreutils/util-linux, and the existing pinned
txgen generator and sender. Supply compatible executables explicitly. No binary
download or node build is performed by the runner. Binary SHA256s, node version,
source hashes, dirty-worktree patch, CPU/memory information, and configuration
are archived with every suite. The node's embedded base commit must match HEAD.

The read-only checkpoint probe is now an example in this repository:

```sh
cargo build -p tempo --example read_finish_checkpoint --profile profiling
```

The historical measurements used a locally patched node and Reth checkout;
those experimental runtime patches and machine-local dependency overrides are
not part of these benchmark configurations. To compare implementations, supply
the desired compatible node binary explicitly and preserve its recorded hash.
`tempo-xtask generate-localnet` must support `--followers`. Keep builds outside
measured intervals.

## Run

From the repository root, point these variables at your binaries:

```sh
export TEMPO_BIN="$PWD/target/profiling/tempo"
export XTASK_BIN="$PWD/target/profiling/tempo-xtask"
export STATE_PATH_CHECKPOINT_TOOL="$PWD/target/profiling/examples/read_finish_checkpoint"
export TXGEN_TEMPO_BIN="/path/to/txgen-tempo"
export TXGEN_BENCH_BIN="/path/to/bench"

bash contrib/bench/run-clean-state-path-controls.sh --dry-run
bash contrib/bench/run-clean-state-path-controls.sh
```

Defaults match the capped controls: 50000 offered TPS, 1000 users, 1200 seconds
per case, 600 seconds excluded, 900 transactions per block, one proposer and
one no-ingress follower. Builder prewarming stays enabled; follower isolation
matches the earlier controls. Gas limits remain permissive at 10^12.

The runner forces copy-based snapshots even if Schelk is installed. It rebuilds
only `tempo_e2e_0mb_isolated_roles_resident_controls` and its `.virgin` sibling
under each benchmark mount. Existing bloated snapshots are not used or modified.
`--force-bloat` in the underlying harness command means rebuild the snapshot;
with `--bloat 0`, it generates genesis only and never generates/imports bloat.
The shared state-path host lock prevents overlapping suites. Do not run other
e2e node jobs concurrently on the same host or ports.

Short integration verification (not a long-run capacity result):

```sh
STATE_PATH_DURATION=360 STATE_PATH_WARMUP=60 STATE_PATH_TPS=5000 \
  bash contrib/bench/run-clean-state-path-controls.sh
```

For a separate uncapped measurement, omit the transaction-count limit:

```sh
STATE_PATH_MAX_TRANSACTIONS=none \
  bash contrib/bench/run-clean-state-path-controls.sh
```

`none` omits the CLI flag; it does not set a zero-transaction limit. The runner
does not automatically increase load or tune limits. Removing this cap alone
does not establish saturation: inspect stop reasons, pending pool, follower
progress, and persistence before interpreting the resulting throughput.
`STATE_PATH_SUITE_DIR` can specify a new output directory; existing directories
are rejected. At least 270 measured seconds are required for persistence-probe
coverage, and both workloads fail closed on invalid audits or missing data.

## Outputs and validation

The printed suite directory contains `manifest.json`, per-case logs, source and
binary provenance, `throughput.md`, `throughput.json`, `validation.md`, and
`exit-code`. Each case's raw result directory is recorded in the manifest.
Warmup is read from that case's metadata, including in short runs.

Reported chain throughput sums canonical included gas over wall time. Execution
throughput divides executed gas by measured execution time; it is not a sustained
chain-throughput claim. Source-labeled cache counters, follower payload-thread
faults, and whole-node database-device I/O retain their separate scopes. Tiny
nonzero I/O/fault ratios are not rounded to zero in the throughput report.

Each audit checks receipts from eight distributed steady-state blocks, three
real call/storage-diff traces, and both persisted state/trie frontiers after an
advancing quiet tail. It verifies the intended application writes rather than
only fee-account changes. Missing coverage, resets, reverts, and persistence
timeouts fail the suite. RPC acceptance is never treated as execution success.

Regression tests:

```sh
node --test contrib/bench/clean-state-path-controls.test.cjs \
  contrib/bench/state-path-observer.test.cjs \
  contrib/bench/analyze-state-path-controls.test.cjs \
  contrib/bench/analyze-state-access.test.cjs \
  contrib/bench/state-access-validation.test.cjs
```
