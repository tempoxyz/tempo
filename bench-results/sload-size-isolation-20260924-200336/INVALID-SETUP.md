# Unmeasured setup, not a benchmark result

Stopped during the first scratch restore, before nodes or transaction load
started. Copy-created page-cache ownership could bypass the intended node
cgroup limits. The corrected experiment adds targeted, mincore-verified eviction
of restored scratch MDBX files before each node startup. No throughput from this
directory should be included in any comparison.

Replacement: `../sload-size-isolation-20260924-v2`.
