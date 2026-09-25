# Declared storage benchmarks

These read/write workloads extend the existing native state-access suite and
reuse its populated storage, isolated builder/follower, persistence priming,
whole-node observer, and post-load durability checks. They use native Tempo
transactions carrying today's EIP-2930 access list. They do not require a new
transaction version, read/write markers, a completeness flag, or a new gas lane.

| Case | Preset / entry point | Work per declared slot |
| --- | --- | --- |
| `sload` | `declared_read` / `touchDeclaredReads` | One SLOAD, no persistent router writes |
| `writes` | `declared_write` / `touchDeclaredWrites` | One SLOAD and one changed nonzero-to-nonzero SSTORE |

Each transaction binds a uniformly random `start` once and reuses it in calldata
and the signed access list. A range of `N` consecutive logical keys is chosen
from **all** `(100000 * 4 - 1) * 4096` populated slots. The last possible range
ends at the final populated slot. Logical adjacency does not imply physical
adjacency in the hashed storage table. The write case toggles bit 255, preserving
a nonzero value and doing real work on repeated visits. There is no shared
history cursor and no bytecode-access workload. Fee/nonce system accesses are
normal native-transaction overhead; the declarations cover the router's storage.

Default `N` is 128. `--accesses` accepts 1 through 256 for one selected case,
matching the current native transaction-pool limit of 256 keys per account.
Both cases use the same number of slots so transaction-size sweeps can expose
fixed overhead. Writes are read-modify-write operations; their time is not an
isolated incremental SSTORE cost. This initial suite covers existing slots,
not state creation, deletion/refunds, multiple storage owners, or mixed workloads.

## Prewarming semantics

The access list makes first SLOADs cost 100 gas in Revm. It does **not** itself
fetch the slots from disk: the current Revm implementation registers warm keys.
Tempo's existing speculative transaction prewarming is left enabled by default.
Unlike history-dependent targets, these calldata-selected ranges are knowable
before execution. Physical cache and I/O effects must be measured, not inferred
from the 100-gas opcode charge. This suite can baseline the current path before
implementing a dedicated declared-key prefetch scheduler.

## Build and run

First apply the pinned [txgen and Reth benchmark patches](patches/README.md).
From the patched txgen checkout, build the generator with `access_list` support:

```sh
cargo build --release -p txgen-tempo --bin txgen-tempo
export TXGEN_TEMPO_BIN=/absolute/path/to/txgen/target/release/txgen-tempo
```

From the Tempo checkout, rebuild the shared router and upgrade the existing
**dedicated history fixture** using its guarded updater:

```sh
bash contrib/bench/txgen/compile-history-state-paths.sh
bash contrib/bench/txgen/compile-history-state-paths.sh --test
bash contrib/bench/update-history-router.sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  contrib/bench/evict-benchmark-file-cache.c -o /tmp/tempo-evict-file-cache
export STATE_PATH_CACHE_EVICT_TOOL=/tmp/tempo-evict-file-cache
export STATE_PATH_CHECKPOINT_TOOL=/absolute/path/to/read_finish_checkpoint
export TXGEN_BENCH_BIN=/absolute/path/to/bench

nu bench-e2e.nu state-access-bloat-worst-case --declared-storage --list
nu bench-e2e.nu state-access-bloat-worst-case --declared-storage --dry-run
nu bench-e2e.nu state-access-bloat-worst-case --declared-storage --feature HEAD
# A single cell in a size/load sweep:
nu bench-e2e.nu state-access-bloat-worst-case \
  --declared-storage --case writes --accesses 256 --tps 1000 --feature HEAD
```

The suite restores the fixture before each case, uses 20 GiB total memory and
no swap per node, evicts and verifies the restored MDBX file cache before
startup, then runs 1,200 seconds with 600 seconds excluded as warmup. The
existing 100 GB bytecode fixture is retained for comparability but not exercised.
Block/general gas limits are nonbinding for capacity measurement; transaction
gas is capped at 10M, sufficient for the configured populated-slot operations.
The suite does not measure the proposed 200M lane limit directly.

`--run-side comparison`, `--run-pairs`, per-side arguments and environments work
as in the existing suite. To include uncommitted node changes, use an explicit
`--feature-binary /absolute/path/to/tempo`. Use fresh restores for each size/load
cell. Try 1, 32, 128 and 256 slots per transaction and increase offered load until
the pipeline is saturated; compare repeated runs and rotate workload order.
A diagnostic control can use `--feature-args "--builder.disable-prewarming --engine.disable-prewarming"`.
Prewarming disabled is a separate experiment, not a production capacity claim.

Before load, the generator preflight verifies eight emitted requests share
exactly the same range between calldata and access list; old generators that
silently ignore the field fail. After load, sampled successful receipts and
actual signed access lists are reconciled with opcode/prestate/diff traces:
exact keys, 100-gas SLOADs, no cursor access, no read-case router writes, and
nonzero high-bit-toggle writes. The current native AA structured logger emits empty opcode traces even for
successful transactions. In that case, gas warmth is checked by `debug_traceCall`
using the actual signed list and actual router prestate; its output must match
the real call trace. Receipt status, access list, prestate and write diffs always
come from the actual included transaction. The opcode source and both traces
are recorded explicitly. Audit traces are archived compressed. Both
nodes must persist through the drained workload. Timed frontiers are also
retained so a successful drain cannot hide sustained backlog growth.

## Results and pricing inputs

The runner prints `STATE_ACCESS_SUITE_DIR`. Analyze that directory with:

```sh
node contrib/bench/analyze-declared-state-paths.cjs /absolute/path/to/suite
```

`declared-storage.json` and `.md` report canonical useful slots/s, full measured
wall ns/slot, both nodes' durable slots/s and backlog, plus the existing execution,
prewarming, memory and I/O observations and five time slices. All phases and
pairs in the manifest are processed. The canonical denominator is the entire
configured measurement window, not a trimmed metrics archive.

At 1 Ggas/s, ns and gas have the same numerical value. These observed ns/slot
values include fixed transaction costs and pipeline waiting. They are inputs
to calibration, not recommended opcode prices. Estimate marginal costs across
transaction sizes, verify saturation, account for existing base charges, and
validate candidate prices with additional workloads and sustained backlog.
Creation, multi-account access and missing declarations still need their own
experiments before choosing general-lane limits. No result here establishes a
universal worst case or a safe 200M block.

## Local correctness checks

The small native-node smoke initializes 4,096 slots in a temporary dev genesis
and sends two signed native transactions per case at 1, 128 and 256 slots. It
runs the same trace auditor and leaves logs/evidence under its printed
`SMOKE_DIR`, then stops the node and removes its scratch database. It does not
touch the prepared benchmark snapshots or measure large-state performance.

```sh
node --test contrib/bench/declared-state-paths.test.cjs
node contrib/bench/smoke-declared-state-paths.cjs \
  /absolute/path/to/tempo /absolute/path/to/txgen-tempo
```
