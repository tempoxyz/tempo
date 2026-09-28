# Reproducing the state-access experiments

This is the fresh-checkout entry point for the latest SLOAD, bytecode, writes,
declared-access-list and builder-prewarming controls. No archived executable or
private source checkout is required. Dependencies are pinned in
[`patches/manifest.json`](patches/manifest.json), including the bytecode pipeline
OOM fix, mapped-page prefetch, payload cancellation fixes and txgen access lists.
These are benchmark dependencies, not changes to Tempo's default dependency pins.

## Build once

Use Linux with the repository Rust toolchain, C/C++ toolchain, Node.js, Nushell,
Git, Python 3.11+, and the usual Tempo build prerequisites. Actual two-node runs
also require passwordless sudo, systemd/cgroup v2, two dedicated NVMe mounts at
`/reth-bench-a` and `/reth-bench-b`, and the CPU topology used by `tempo.nu`
(builder 0-7,16-23; follower 8-15,24-31). This is a hardware benchmark, not a
laptop smoke test. Keep 20 GiB RAM available per node plus host/tool headroom.

From the repository root, in Bash:

```sh
node contrib/bench/setup-state-access.cjs --build-tools
source target/state-access-deps/env.sh
```

In Nushell, use `source target/state-access-deps/env.nu` instead. Setup downloads
the pinned public dependency revisions into isolated directories, checks patch
digests, and builds the node, sender, checkpoint/fixture helpers and file-cache
eviction helper. `--reth-source LOCAL_REPO` and `--txgen-source LOCAL_REPO` can
reuse local Git objects without modifying those checkouts. `--directory DIR`
changes the dependency/tool directory; source the `env.sh`/`env.nu` written there.

`TEMPO_BENCH_CARGO_CONFIG` makes the native suite build the requested Tempo refs
against these patched dependencies. Such builds bypass the normal binary cache,
whose key does not include dependency patches. Use the same environment for both
sides of a comparison. Cargo may rewrite your local `Cargo.lock` to path
dependencies; that host-specific resolution must not be committed.

## Prepare the large fixture once

The history tests need the dedicated block-zero fixture: 100,000 MiB populated
storage plus 4,266,667 distinct 24 KiB contracts. The resulting database is about
331 GB per node; reserve space for both immutable snapshots and restored scratch
copies, plus the original storage-only snapshots. Reflinks help only where the
filesystem supports them. This is intentionally not a checked-in database.

On a fresh benchmark host, create the original storage-only snapshots first:

```sh
flock --nonblock /tmp/tempo-general-state-access-20260922.lock \
  nu bench-e2e.nu general-state-access-worst-case \
    --baseline HEAD --feature HEAD --force-bloat --init-only
bash contrib/bench/prepare-history-state-paths.sh
node contrib/bench/state-access-config.cjs --ignore-env --check-fixtures
```

Do not use `--force-bloat` on snapshots you want to preserve. The preparation
script holds the shared lock, refuses existing history fixtures, imports into a
new copy, and leaves original `.virgin` snapshots alone. Checked-in router
bytecode is ready to use; rebuilding it requires the pinned compiler in
[the compiler script](txgen/compile-history-state-paths.sh). If upgrading an existing history fixture,
use `bash contrib/bench/update-history-router.sh` rather than reimporting it.
See [fixture protocol and correctness limits](history-state-paths.md).

## Run the suites

```sh
# Small, history-dependent SLOAD / bytecode / writes, each from the same fixture.
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD

# Sized SLOAD and bytecode (7,200 / 2,250 accesses per transaction).
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD --sized-transactions

# Native access-list read/write controls (128 declared slots per transaction).
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD --declared-storage

# Four cells: sized SLOAD/code, builder prewarming on/off, engine unchanged.
nu bench-e2e.nu state-access-prewarm-control --baseline HEAD --feature HEAD --wait
```

Use `--dry-run` to inspect without starting nodes, and `--case sload`, `--case
bytecode` or `--case writes` to select a compatible case in the first three
commands. Defaults are 1,200 seconds per case, 600 seconds warmup, 1,000 offered
TPS, 20 GiB/node and no swap for sized/declared/control runs. All live suites
hold the shared lock; the prewarming control's `--wait` queues without disturbing
another benchmark. Every control cell restores the fixture and verifies the same
node binary hash. Ordinary suites fail fast if the lock is held.
Each suite retains a checksum-verified executable under its own results directory
and reuses it across cases, avoiding recompilation and build-timestamp changes.
The cache is private to that new suite, not the shared commit-only binary cache.

`--max-transaction-size` selects the deliberately near-30M-gas stress cases.
Those can trigger proposal timeouts: they are not a sustained-throughput target.
Sized transactions are a historical latency calibration, not a guarantee of
900 ms on different hardware, and may still yield one transaction per block.
Only the per-run access/history audit establishes actual prewarming-bypass
coverage. Access-list controls exercise today's prewarming, not a hypothetical
dedicated access-list prefetcher.

## Supporting experiments and saved evidence

- [Bytecode latency decomposition](bytecode-latency-diagnostic.md): physical
  reads, warm MDBX access, codec CPU and allocator controls. Build with
  `node contrib/bench/build-bytecode-diagnostics.cjs` after setup.
- SSD controls: `node contrib/bench/run-ssd-read-bandwidth.cjs --help`. Supply
  stopped builder/follower database files and a **new** output directory. The
  read-only runner verifies the populated range, uses direct I/O, refuses active
  benchmark scopes, and holds the shared lock. Analyze with
  `node bench-results/ssd-read-bandwidth-20260927/analyze.cjs NEW_DIRECTORY`.
- [Ethereum opcode prevalence](../../bench-results/mainnet-bytecode-opcodes-20260927/README.md)
  and [code deduplication](../../bench-results/bytecode-dedup-20260927/README.md)
  preserve source provenance, analyzers and download checksums.
- [Gas calibration](../../bench-results/gas-calibration-20260928/README.md)
  separates measured rates from estimates and backlog-limited writes.

Compact evidence is indexed in [bench-results](../../bench-results/README.md).
The following reanalyses use only checked-in inputs and need no database:

```sh
node contrib/bench/analyze-bytecode-latency.cjs bench-results/bytecode-latency-breakdown-20260927
node bench-results/ssd-read-bandwidth-20260927/analyze.cjs
node bench-results/mainnet-bytecode-opcodes-20260927/analyze.cjs
node bench-results/gas-calibration-20260928/calibrate.cjs
```

Historical full-node/OOM reanalysis additionally needs the raw logs/metrics
listed in the archive manifests. Those large files, binaries, record exports and
databases are deliberately not Git blobs. Historical host-specific runners are
provenance, not fresh-checkout entry points; use the native suites above. The
OOM result included a follower pause during warmup and is not a strict throughput
A/B. Normal runs of the new prewarming control do not inject that pause.
