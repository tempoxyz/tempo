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
| `sload` | `state_access_dependent` | Original 4,096 cold SLOADs |
| `bytecode` | `history_code` | 128 EXTCODECOPYs over unique 24 KiB contracts |
| `writes` | `history_write` | 1,024 populated-slot reads and nonzero-to-nonzero writes |

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

This preserves both corpora and the original snapshots. The shared router
inherits the original SLOAD implementation, so its access selection, 4,096-read
loop, and cursor semantics are unchanged; router dispatch overhead can differ.
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
transactions that defeat prewarming. SLOAD's large transactions may substantially
reduce the share of non-first transactions, which is reported rather than hidden.

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
