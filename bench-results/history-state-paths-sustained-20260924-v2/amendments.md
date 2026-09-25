# Post-load audit allowance

At 07:11 UTC, while the write load was running, its post-load audit deadline was
extended from 10 to 30 minutes. Incremental Merkle processing completed batches
but the follower's backlog grew. The load duration, warmup, node binary, presets,
fixture, metrics and timed observer behavior were not changed.

The original observer is retained as `state-path-observer.measurement.cjs` in
the source archive. `state-path-observer.cjs` includes the longer audit deadline.
This allowance does not make producer throughput a sustainable follower claim.

After the write load ended, offline analysis was extended to retain zero-execution
Merkle intervals with null per-executed-gas ratios and to sum canonical gas crossed
by durable state/trie frontiers. Producer-to-durable backlog is reported separately
from the follower's own head lag. No timed samples were changed. Updated analysis
sources and regression tests are archived in the suite source directory.

Both benchmark cases exited zero and passed their audits. The original wrapper
then exited 2 while reading the remaining shell script after its archive list had
been edited during execution. The final script passes `bash -n`. Report generation
was resumed separately with `analyze-history-state-paths.cjs`; the original wrapper
exit code is retained as `exit-code.initial`, and completion metadata records the
resumed analysis. No benchmark measurements were rerun, edited, or substituted.
