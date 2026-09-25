# State-access benchmark configurations

The [state-access-bloated.json](state-access-bloated.json) registry is the source
of truth for the matched bloated-state comparison. Commands below run from the
repository root:

```sh
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD
nu bench-e2e.nu state-access-bloat-worst-case --list
nu bench-e2e.nu state-access-bloat-worst-case --dry-run
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD --case sload
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD --case bytecode
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD --case writes
```

This is a native `bench-e2e.nu` suite, like `payments-bloat-worst-case`. It calls
the ordinary e2e build/cache/run/report pipeline for each selected workload.
Like that command, it defaults to `--run-side feature`; to run both revisions:

```sh
nu bench-e2e.nu state-access-bloat-worst-case \
  --baseline main --feature HEAD --run-side comparison --run-pairs 1
```

`--baseline-args`, `--feature-args`, per-side environment flags, `--bench-env`,
`--profile`, and `--no-cache` follow the existing suite conventions. Git refs
are resolved once for the suite and built through the usual worktree/cache path.
Uncommitted node changes are not part of `HEAD`; opt into a local patched build
with `--feature-binary /absolute/path/to/tempo --run-side feature` when needed.
The native command does not silently use `TEMPO_BIN` or `HISTORY_*` overrides.
Use `--tps`, `--duration`, and `--summary-warmup-seconds` instead.

| Name | Preset | Accesses per transaction |
| --- | --- | --- |
| `sload` | `history_read` | 128 cold SLOADs, covering the full populated corpus |
| `bytecode` | `history_code` | 128 EXTCODECOPYs over unique 24 KiB contracts |
| `writes` | `history_write` | 1,024 populated-slot reads and nonzero-to-nonzero writes |

For the separate near-30M-gas SLOAD and bytecode variants, add
`--max-transaction-size`. The [max-size registry](state-access-max-tx.json)
selects 13,800 SLOADs or 10,800 EXTCODECOPYs, with verified 20 GiB/no-swap
cold-start controls. This requires the targeted eviction helper; see
[preparation and reproduction](../max-state-access.md). The ordinary registry
and defaults above are unchanged. Max-size cases report actual history coverage
and explicitly permit first-transaction samples rather than claiming that
mostly single-transaction blocks establish within-block prewarming bypass.

For latency calibration, use `--sized-transactions --case bytecode --accesses 2250`
(or select `sload` and its count). The [sized registry](state-access-sized.json)
preserves the full corpus and the same memory/prefetch controls. Counts must be
calibrated on the target machine, not assumed to guarantee a duration. See
[cancellation-aware latency measurement](../state-access-latency.md).

For declared reads and writes, use `--declared-storage`. The
[declared registry](state-access-declared.json) uses native Tempo access lists,
128 slots per transaction by default, and accepts `--case sload|writes --accesses
1..256`. It retains the memory and verified cache controls without a bytecode
workload. See [preparation, semantics, and analysis](../declared-state-paths.md).

All cases use the same node binary per side, 1,000 offered TPS, 1,000
signers, 1,200 seconds of load, and a 600-second excluded warmup. The same
block-zero fixture is restored before each case: the original 100,000 MiB
storage import plus 100,000 MiB of unique bytecode, approximately 331 GB/node.
By default prewarming is unchanged and no artificial transaction cap is set. Node arguments,
CPU allocation, devices, gas limits, priming, and observer/audit paths are shared.
The host-specific harness uses separate NVMe devices and CPU sets; both nodes
share host RAM. Restores create fresh scratch databases and nodes, but do not
globally drop the host page cache. This is a warmed sustained-load comparison,
not a controlled cold-start latency test.

## Preparation

See [fixture preparation and requirements](../history-state-paths.md#reproduction).
For an existing dedicated `history_paths` fixture, upgrade its router once:

```sh
bash contrib/bench/txgen/compile-history-state-paths.sh
bash contrib/bench/txgen/compile-history-state-paths.sh --test
bash contrib/bench/update-history-router.sh
```

This updates only the router in the dedicated history fixtures, preserving both
corpora and the original source snapshots. The shared router retains the legacy
4,096-read entry point, but the saved SLOAD case uses `touchReads`: 128-slot chunks
selected across all 32 chunks of every original 4,096-slot logical page. Merely
reading the first 128 slots of each old page would incorrectly shrink the working
set by 32x.
The runner verifies the installed router hash before starting expensive copies.
It also requires the `read_finish_checkpoint` example under
`target/PROFILE/examples/` (or `STATE_PATH_CHECKPOINT_TOOL`) and verifies both
virgin fixtures are at block zero before restoring anything.

## Results and Comparability

The native command prints `STATE_ACCESS_SUITE_DIR` and saves its resolved
`configuration.json`, `manifest.json`, and `exit-code` under
`bench-results/state-access-bloat-TIMESTAMP/`. The manifest indexes the ordinary
e2e result directory for each case. Each directory retains the normal phase
reports and summary, per-phase correctness/persistence audits, whole-node
observations, the suite configuration, and baseline/feature binary SHA256s.
Binary drift within a side fails the suite instead of claiming a matched result.
A single-case selection is not a complete three-way comparison. Fixtures must
already be prepared; this command never imports over or promotes virgin data.

Phase reports retain builder/follower/chain throughput counters and the observer
evidence needed for durable throughput, backlog, I/O and major faults per gas.
History audits record within-block history coverage and deliberately sample
non-first transactions; their mismatch rate is not the fraction of all workload
transactions that defeat prewarming. The small SLOAD case requires at least 90%
of measured-window workload transactions to have a predecessor in their block;
otherwise its audit fails. The original 4,096-read run achieved only 0.39% and
must not be treated as a verified prewarming-resistant worst case.

Different offered loads, durations, fixtures, or binaries must not be combined as
a matched comparison. At least 270 measured seconds are required. One run per
workload is not a statistical confidence interval or proof of a universal worst
case. The original `general-state-access-worst-case` command is left unchanged;
use this suite when comparing against bytecode and writes on the shared fixture.

## Earlier Local Runs

`run-history-state-paths.sh` remains a legacy local-binary measurement helper for
the earlier archives. Its `HISTORY_*` overrides and `throughput.md`/`throughput.json`
analysis are specific to that feature-only protocol. Existing archives and the
legacy `state-access-bloated-latest.json` index are not rewritten by the native
command. New invocations should use the `nu bench-e2e.nu` interface above.
