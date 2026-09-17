# Capacity preflight branch

This diagnostic branch intentionally replaces the registered `bench-e2e.yml`
workflow with a capacity-only workflow. **Do not merge that replacement into
main.** Dispatching this branch launches no benchmark, build, snapshot operation,
or cache cleanup. The original benchmark branches remain unchanged.

Two anonymous matrix slots run with the benchmark's existing runner labels and
upload distinct `bench-capacity-1` and `bench-capacity-2` artifacts. Parallel
scheduling can sample two idle runners, but GitHub does not guarantee distinct
runners; scheduling identities must be compared privately outside the reports.

Each slot fetches the probe at its exact workflow commit, without checkout or
workspace reset. It examines only root, workspace, runner temporary directory,
and the optional preprovisioned scratch directory. Reports contain closed role
and status names, local filesystem ordinals, byte counts, and capability flags.
Ordinals establish filesystem equality only within one report. Paths, device
identifiers, hostnames, and environment values are never emitted by the probe.
GitHub-managed job metadata is outside this report's privacy contract.

On eligible writable directories, the probe exclusively creates an owned
one-byte temporary file, synchronizes it, and removes that file. It neither
creates missing locations nor follows redirected locations. A unique small
workspace directory retains only the numeric JSON for artifact upload. No
capacity guards, mount configuration, caches, or benchmark data are changed.

Validation: `python3 -m unittest discover -s contrib/bench/lifecycle
-p test_capacity_preflight.py -q` exercises actual temporary directories,
failure/privacy cases, and the exact final workflow JavaScript using mocked
GitHub/process interfaces.
