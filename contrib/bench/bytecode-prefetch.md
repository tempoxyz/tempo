# Targeted Bytecode Prefetch Experiment

This is an experimental end-to-end follow-up to `bytecode-page-diagnostic.md`.
It keeps the history-dependent bytecode workload and bloated fixture unchanged.
General MDBX read-ahead remains disabled. The only treatment is an opt-in
`MADV_WILLNEED` for the OS pages occupied by a large Bytecodes value, after MDBX
locates the record and before Reth copies/decodes it.

The Reth patch and portable setup instructions are in
[patches/README.md](patches/README.md); it changes
`crates/storage/db/src/implementation/mdbx/`.
It applies at the raw MDBX value-decoder boundary in `get_by_encoded_key` calls
for the Bytecodes table. Read-only values are mapped; writable transactions
must pass `mdbx_is_dirty == MDBX_SUCCESS` before advice, so dirty/heap-backed
values are excluded. This also covers pipeline catch-up execution, which uses
writable transactions. It skips values no larger than one OS page and is enabled only
when `RETH_BYTECODE_PREFETCH=1`. It does not predict future addresses, modify
database contents, enable general read-ahead, or change EVM gas accounting.
Failed advice is counted but does not fail the underlying state read.

## Reproduce

Build one node with the local Reth override, then use that exact executable for
both modes. The override also retains the earlier payload cancellation and
RocksDB cache fixes used by this host's prior state-access runs.

```sh
RUSTFLAGS='-C target-cpu=native' cargo build --offline \
  --config contrib/bench/payload-cancel-patches.toml \
  -p tempo --bin tempo --profile profiling --features jemalloc,asm-keccak -j8

export TXGEN_TEMPO_BIN=/home/ubuntu/repos/txgen/target/release/txgen-tempo
export TXGEN_BENCH_BIN=/home/ubuntu/.cargo/bin/bench
export STATE_PATH_CHECKPOINT_TOOL=/absolute/path/to/read_finish_checkpoint

node contrib/bench/run-bytecode-prefetch.cjs \
  /absolute/path/to/archived/tempo bench-results/bytecode-prefetch-NEW

node contrib/bench/analyze-bytecode-prefetch.cjs \
  bench-results/bytecode-prefetch-NEW
```

The driver uses the native suite's dry-run plan and locked suite executor.
Each treatment is equivalent to:

```sh
nu bench-e2e.nu state-access-bloat-worst-case \
  --baseline HEAD --feature HEAD --case bytecode \
  --feature-binary /absolute/path/to/archived/tempo --profile profiling \
  --feature-env RETH_BYTECODE_PREFETCH=0
```

Repeat with `RETH_BYTECODE_PREFETCH=1`. Both are feature-only native runs to
allow the same explicit local binary, rather than building different git refs.
The driver archives the resolved configurations and refuses binary or fixture
drift. Existing output directories containing an experiment are not reused.

Each phase restores the established scratch databases from the same virgin
fixtures, runs 1,200 seconds at 1,000 offered TPS, excludes 600 seconds of warmup,
and performs the standard receipt, history/prewarming-evasion, and durable
catch-up audits. It does not drop the host's page cache. The nodes share host
RAM but use separate CPU sets and database NVMe devices.

## Interpretation

- Builder/follower execution throughput divides measured gas by accumulated
  execution time. Chain throughput sums canonical gas over wall-clock time.
- Read requests and bytes per gas come from the node cgroup on its database
  device. They include prewarming, persistence, and other node work, not just
  included transaction execution.
- `reth_db_bytecode_prefetch_*` metrics prove activation and syscall success.
  The byte counter counts hinted ranges, not disk bytes or newly resident pages.
  The preliminary read-only binary exported these as `reth_reth_db_*`; the
  corrected binary exports `reth_db_*`. The analyzer handles either prefix.
  `requests_rw` separately counts hints issued inside writable transactions.
- Fewer major faults do not necessarily mean fewer bytes read. Successful
  asynchronous prefetch can replace a fault without reducing disk traffic.
- A single baseline-then-prefetch pair is not a confidence interval. Inspect
  time slices and history coverage, and repeat in reverse order if a marginal
  result needs stronger attribution.

The corrected run archives its binary, build flags, source files and patches in
`bench-results/bytecode-prefetch-e2e-20260924-v2`. Its baseline and feature both
use the corrected binary, with the switch off and on respectively.

The preliminary run in `bench-results/bytecode-prefetch-e2e-20260924` was
intentionally stopped during treatment warmup: the read-only-only hook missed
pipeline catch-up, and a faster builder left the follower on that unoptimized
path. It is not a completed A/B result. That preliminary binary also inherited
cached embedded version metadata; its SHA256/source archive is its identity.
