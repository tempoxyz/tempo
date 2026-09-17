# Diagnostic-only capacity usage

This branch replaces the benchmark workflow with a read-only diagnostic. Never
merge its workflow replacement into main. It starts no validators, performs no
checkout/reset or cleanup, and changes no caches, services, kernel settings, or
snapshots. The only writes are the existing exclusive one-byte capacity probes
and the task-owned numeric report.

Schema 2 preserves the four schema 1 capacity locations, adds two fixed
stat/statvfs-only scratch_locations for the benchmark A/B mounts, and adds 12 fixed usage
roles: runner work/temp/workspace, Cargo registry/git, default/environment sccache,
and `/home`, `/var`, `/tmp`, `/opt`, `/usr`. Runner work is inferred only when the
documented runner temp directory ends in `_temp`; otherwise that role is unset.
The default sccache role uses XDG_CACHE_HOME or HOME/.cache, independently of the
explicit SCCACHE_DIR role. Cargo roles use CARGO_HOME or HOME/.cargo. Native paths,
user/host/device identities, file names and command errors are never exported.
Scratch rows do not write, traverse, restore, or inspect state files; mountpoint,
read-only and distinct-parent flags do not prove idle ownership or snapshot safety.
Device equality is represented only by local numeric filesystem ordinals shared
with the existing capacity rows.

Usage is GNU du allocated bytes, not apparent file size. Each scan is restricted
to one filesystem, does not follow symlinks, and excludes names matching the
fixed EXCLUDES policy in capacity_usage.py (virgin/snapshot, state database, and
mount/scratch categories). Redirected/protected scan roots are rejected. These
exclusions intentionally make the measurements incomplete; rows also overlap
(e.g. runner work can contain workspace). Do not add rows together or treat them
as a filesystem-wide inventory. Open-unlinked files, excluded state and filesystem
metadata are not explained by these totals. A nonzero du exit reports unavailable,
never a misleading partial byte total.

Each du receives at most 15 seconds, with one 150-second shared usage budget. Its
fixed GNU timeout wrapper runs at the same privilege as du so it can kill the
scanner. When necessary sudo is noninteractive and applies only to that fixed
read-only metadata command. The supervisor allows 2 seconds to reap after the
scanner deadline; the workflow has a 210-second subprocess deadline. Remaining
categories become budget_exhausted rather than starting new scans. stderr is
discarded. No values from the environment can supply executable names or options.

The workflow fetches both Python files at its exact immutable SHA and executes
these sources in memory with Python isolated mode. Both Python and JavaScript
validate exact closed schemas before publishing the sole capacity.json artifact.
The two matrix slots use the existing runner pool and do not cancel active jobs.
The diagnostic itself can consume bounded disk/CPU metadata work; it is not a
performance benchmark and should not be treated as timing evidence.

Focused validation:

    python3 -m unittest discover -s contrib/bench/lifecycle -p 'test_capacity*.py'

Tests cover protected/redirected paths, actual sparse-file allocation, untouched
excluded trees, fixed privileged timeout invocation, shared deadline limits,
partial-output rejection, filesystem ordinals, unknown metadata and scalar types,
legacy one-byte cleanup ownership, and the actual isolated workflow import path.
