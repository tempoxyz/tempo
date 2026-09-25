# Isolating SLOAD transaction size from prewarming

The historical 4096-read and 128-read results were not a controlled size-only
comparison: executables differed, and two 60 GiB node limits shared a 62 GiB
host. The smaller-read run's builder file cache grew while the follower's shrank.
Gas per workload SLOAD also increased with smaller transactions.

This diagnostic uses four sequential cells: 4096/on, 128/on, 128/off, 4096/off.
Both read entry points are in the same history router, on the same unchanged
populated fixture. The smaller entry point can select all 32 chunks of every
original 4096-slot page, preserving the full storage domain. The archived node
binary, targeted bytecode-prefetch setting, CPU/device allocation, offered load,
signers, gas limits, 600-second warmup and 600-second measured window are fixed.
The off control disables both builder and engine prewarming, not execution caches.

Each node receives a 20 GiB total-memory limit and zero swap. Before startup,
the two restored scratch MDBX files are individually flushed and evicted, with
`mincore` verification. This prevents pages cached by the copy process from
remaining charged outside the node cgroups. There is no global cache drop and
the source snapshots are not modified. Memory limits, swap, OOM events, actual
process arguments, file-cache residency, binary hashes and fixture identity
are checked and archived. Total-memory caps do not guarantee identical file-cache
bytes; the report includes the actual cache sizes and throughput time slices.

Build the helper, then run from the repository root with explicit tools:

```sh
cc -std=c11 -O2 -Wall -Wextra -Werror \
  contrib/bench/evict-benchmark-file-cache.c -o /tmp/tempo-evict-file-cache

STATE_PATH_CACHE_EVICT_TOOL=/tmp/tempo-evict-file-cache \
STATE_PATH_CHECKPOINT_TOOL=/absolute/path/to/read_finish_checkpoint \
TXGEN_TEMPO_BIN=/absolute/path/to/txgen-tempo \
TXGEN_BENCH_BIN=/absolute/path/to/bench \
node contrib/bench/run-sload-size-isolation.cjs \
  /absolute/path/to/tempo bench-results/sload-size-isolation-UNIQUE_ID
```

The runner uses the native suite executor and its lock, restores the fixture
before every cell, refuses input drift, and runs the existing receipt, cold-read,
cursor, history-divergence and durable-catch-up audits. The small case retains
the 90% history-eligibility gate. The large case reports its actual coverage
without pretending that one-transaction blocks bypass parent-state prewarming.

Reports are generated incrementally as `throughput.md` and `throughput.json`.
Canonical workload SLOADs/s separates useful read throughput from overhead gas.
Execution-only rates, chain production, follower durable progress and backlog
are reported separately. Whole-node I/O includes speculative and persistence
work; it is not an attribution of physical reads to individual EVM opcodes.

Compare small/large read throughput with prewarming on and off. A size advantage
that disappears with prewarming off implicates the prewarming interaction, not
an intrinsically faster SLOAD. A persistent advantage requires further analysis.
These four cells are one pass, not confidence intervals; repeat in reverse order
if the result is small or time slices/cache sizes remain unstable.

## Verified 2026-09-24 result

The completed four-case experiment is archived in
`bench-results/sload-size-isolation-20260924-v4/`. Its `README.md` explains the
result and attribution limits; `throughput.md` contains the standard window
and `late-window.md` checks the last five minutes.

With prewarming on, 128-read transactions delivered 15151 canonical SLOADs/s
versus 8275 for 4096-read transactions. With prewarming off, the corresponding
rates were 17479 and 17823: the useful-read advantage disappeared. Gas per
useful read is 14.3% higher in the smaller transaction. This identifies a
transaction-size/prewarming interaction, not intrinsically faster small-tx
SLOADs. Whole-node I/O supports speculative amplification, but does not isolate
cancellation tails from other prewarming contention. All four audits passed;
the large/on control explicitly reports only 0.08% history-bypass eligibility.
