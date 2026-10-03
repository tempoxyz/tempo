# State-access benchmark evidence

**Logging qualification (2026-10-03):** The archived declared-read result of
about 80,530 durable slots/s used per-transaction timing diagnostics and a
line-by-line node-output relay. A later cached-workload investigation observed
the builder blocked in `pipe_write` in 88 of 100 samples under that logging
configuration. The historical run was not separately profiled, so its entire
shortfall cannot be attributed to logging, but it is not a clean storage-capacity
or cache-speedup baseline. The current harness captures node output directly in
files and defaults transaction diagnostics off. Original measurements below are
preserved; rerun the controls with the corrected harness before calibrating
capacity or gas costs from them.

Completed experiments through 2026-09-28. Source, presets, audits, and analyzers
are under [contrib/bench](../contrib/bench/README.md). The separate txgen and Reth
changes are included as pinned [dependency patches](../contrib/bench/patches/README.md).

| Experiment | Report | Scope |
| --- | --- | --- |
| Latest runbook | [Fresh-checkout setup](../contrib/bench/state-access-reproduction.md) | Pinned builds, fixtures and native suite commands; no archived binaries required |
| Builder prewarming | [Four-cell control](builder-prewarm-control-20260925/RESULTS.md) | SLOAD on/off; bytecode on and failed/OOM off run, preserving failure status |
| Bytecode OOM fix | [Bounded pipeline cache](bytecode-oom-fix-20260926/README.md) | Successful 20 GiB follower regression with warmup catch-up intervention; not a strict A/B |
| Bytecode latency | [I/O and CPU decomposition](bytecode-latency-breakdown-20260927/README.md) | Cold/warm MDBX, direct I/O, block tracing and actual codec/allocator controls |
| SSD performance | [Read bandwidth](ssd-read-bandwidth-20260927/README.md) | Read-only sequential/random controls on both devices |
| Ethereum opcodes | [Mainnet prevalence](mainnet-bytecode-opcodes-20260927/README.md) | Public trace data and selection/coverage limits |
| Code deduplication | [Size accounting](bytecode-dedup-20260927/README.md) | Historical public dataset; not a current live-state census |
| Gas calibration | [Measured and estimated costs](gas-calibration-20260928/README.md) | Explicit operation counts and metric boundaries at a 1 Ggas/s target |
| Declared storage | [Read/write results](declared-storage-20260925/README.md) | Existing access lists, 128 slots/tx, separate read and changed-slot-write cases |
| Write slowdown | [Persistence diagnosis](declared-storage-20260925/diagnosis/README.md) | Hashed-state/trie updates, page faults, I/O, and post-load drain |
| Latency calibration | [Sized transactions](state-access-latency-20260925/README.md) | 7,200 SLOADs or 2,250 code accesses; canceled work and full wall windows |
| Builder/follower gap | [Queue diagnosis](state-access-latency-20260925/builder-follower-analysis.md) | Serialized speculative prewarming and cache retention |
| Transaction size | [Matched four-cell control](sload-size-isolation-20260924-v4/README.md) | 128/4,096 SLOADs, prewarming on/off, 20 GiB/no swap |
| Near-30M transactions | [Worst-case pair](max-state-access-20260925-final/README.md) | Proposal timeouts; sparse bytecode inclusions audited separately |
| Bytecode prefetch | [Matched comparison](bytecode-prefetch-e2e-20260924-v2/throughput.md) | Read-only and clean mapped read-write bytecode prefetch |
| Bytecode I/O | [Page investigation](bytecode-io-investigation-20260924/findings.md) | Mapped pages, decoding, and physical I/O controls |
| Ordinary controls | [Read/write controls](state-path-controls-patched-20260923-v4/throughput.md) | Cache-hot ordinary contract access, not a cold worst-case bound |
| Initial access audit | [Findings](state-access-validation-20260922/findings.md) | Populated slots, cold accesses, and actual/replayed access sets |

The declared read run produced about 81,094 useful slots/s and 80,530 durable
slots/s. The write run produced 4,020 updates/s while its follower persisted
2,806 updates/s, accumulated backlog, and needed 22.4 minutes after load to drain.
That write run establishes overload, not sustainable capacity. Individual reports
retain their timing boundaries, correctness gates, failed candidates, and limits.
None establishes a universal worst case or a safe 200M gas block.

## What is preserved

Git contains compact reports, structured results, CSVs, completed-run audits,
configuration/fixture metadata, analysis scripts, regression-test logs, and the
source snapshots for the declared-storage node and generator. Earlier failed
and superseded experiments retain their original status; use the reports above
for the selected comparisons. Historical absolute paths in JSON and commands
identify the measurement host and do not refer to files available in a fresh clone.

[artifact-inventory.json](artifact-inventory.json) records which archive files
are committed and their SHA-256 digests, plus the paths and sizes of retained
local raw artifacts. Raw node logs, compressed traces, metric streams, executable
binaries, and databases are not Git blobs. They remain in the original local
archive; no hosted raw-artifact download is claimed. Raw artifact sizes are listed
in the inventory, and full reanalysis scripts require their referenced raw inputs. A fresh
clone can inspect the reports and rebuild/rerun the workloads with the documented
fixtures and dependency patches. Build manifests retain binary and source hashes.

The builder-prewarming control and follow-up OOM regression are now included.
The latency, SSD, opcode-prevalence and gas-calibration analyses have compact
checked-in inputs and can be recomputed without raw node archives; see the runbook.
Full deduplication analysis downloads checksum-verified public ZIPs rather than
checking in multiple gigabytes of data. Historical absolute paths and frozen
runners describe the original host; current entry points live in `contrib/bench`.
