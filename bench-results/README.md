# State-access benchmark evidence

Completed experiments through 2026-09-25. Source, presets, audits, and analyzers
are under [contrib/bench](../contrib/bench/README.md). The separate txgen and Reth
changes are included as pinned [dependency patches](../contrib/bench/patches/README.md).

| Experiment | Report | Scope |
| --- | --- | --- |
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
archive; no hosted raw-artifact download is claimed. The raw archives total about
28 GB, and full reanalysis scripts require their referenced raw inputs. A fresh
clone can inspect the reports and rebuild/rerun the workloads with the documented
fixtures and dependency patches. Build manifests retain binary and source hashes.

The separate builder-prewarming control experiment was still running when this
snapshot was prepared; its live files are excluded from this completed-results set.
