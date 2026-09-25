# Declared read/write storage results

Both runs and their correctness audits completed. Reads produced 81,094 slots/s. Writes produced 4,020 existing-slot updates/s, while the follower persisted 2,806 updates/s and accumulated backlog. Builder backpressure was active 93.2% of the write window. The follower first persisted through the final reported write block 22.4 minutes after load stopped. This write run demonstrates overload and does not establish sustainable capacity.

Both cases: 128 declared slots per native Tempo transaction, 1,000 offered TPS, 1,000 signers, 1,200 seconds of load with the first 600 seconds excluded. Uniform random 128-slot ranges over 1,638,395,904 populated storage slots. Fresh fixture restore per case; AMD EPYC 4585PX with eight physical cores and 20 GiB total memory/node, no swap, verified scratch-file cache eviction, separate builder/follower CPU sets and NVMe devices. Same instrumented node binary as the previous latency runs; prewarming remains enabled.

| Case | Canonical transactions/s | Useful slots/s | Whole-wall ns/slot | Builder durable slots/s | Follower durable slots/s | Follower backlog slots first → last |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| declared_read | 633.55 | 81,093.97 | 12,331.37 | 80,530.25 | 80,532.16 | 770,048 → 1,095,296 |
| declared_write | 31.41 | 4,020.48 | 248,726.52 | 4,028.89 | 2,805.76 | 1,710,208 → 2,512,896 |

| Case | Builder transaction EVM p50 / p95 ms | Completed nonempty build p50 / p95 ms | Cancelled created payload jobs / jobs | Builder / follower backpressure active | Builder / follower read MB/s | Builder / follower write MB/s |
| --- | --- | --- | --- | --- | --- | --- |
| declared_read | 0.08 / 0.16 | 252.76 / 258.94 | 0 / 2262 | 0% / 0% | 465.56 / 276.76 | 13.83 / 13.61 |
| declared_write | 0.1 / 7.24 | 308.15 / 379.77 | 7 / 147 | 93.22% / 24.58% | 118.44 / 56.16 | 62.4 / 56.25 |

| Case | Load minutes | Canonical slots/s |
| --- | --- | ---: |
| declared_read | 10–12 | 81,153.07 |
| declared_read | 12–14 | 81,134.93 |
| declared_read | 14–16 | 81,386.67 |
| declared_read | 16–18 | 80,865.07 |
| declared_read | 18–20 | 80,930.13 |
| declared_write | 10–12 | 0 |
| declared_write | 12–14 | 10,066.13 |
| declared_write | 14–16 | 0 |
| declared_write | 16–18 | 7,261.87 |
| declared_write | 18–20 | 2,774.4 |

| Case | Builder / follower first observed durable through final reported block, seconds after load end |
| --- | --- |
| declared_read | 34.49 / 34.52 |
| declared_write | 479.97 / 1,346.05 |

Completion delays include observer sampling delay. The throughput tables above retain their original measurement windows.

At the 1 Ggas/s target, one nanosecond is numerically one gas. Whole-wall ns/slot is an observed pipeline budget including transaction overhead and cadence; it is not an isolated opcode cost or a recommended price. Write slots each include a read and a changed nonzero-to-nonzero write. New-slot creation, deletion/refunds, and multi-owner workloads are outside this experiment.

A growing durable backlog prevents interpreting canonical production as sustainable capacity. Endpoints also reflect commit batching, so inspect the five time slices and frontier series in results.json. One pass per case is not a worst-case bound or a confidence interval. The existing gas charges have not been repriced; their Mgas/s must not be confused with throughput under a future schedule.

The write follower entered pipeline catch-up. Its aggregate execution totals include that path; payload-thread fault counts and engine-cache counters do not cover all catch-up work and must not be normalized as if they did. Whole-node physical I/O and durable frontiers retain that work.

Cancellation counts cover created payload jobs. Consensus proposals may time out while waiting on a backpressured engine before a job is created; the backpressure gauge and whole-wall throughput capture that delay. EVM timing is per transaction; completed-build timing omits intervals in which no build can start.

Correctness checks use included receipts, actual signed access lists and actual prestate/write diffs. The native AA opcode tracer emits empty logs; warmth is verified by replay using each transaction’s actual prestate and signed list, with matching returned output. EIP-2930 warmth is not proof of disk prefetch.

Node SHA256: 3cf755ffee2de9d5dc90fbcc327f2dd7a54b40e0fcf821b4d9943cd663bcf19b. Raw suite: /home/ubuntu/repos/tempo-payments-bloat-pr/bench-results/state-access-bloat-20260925-185631-646. Exact binaries, sources, fixture metadata, command, and tool hashes are archived alongside this report.

Validation: 1,546 sampled read receipts and 1,317 sampled write receipts succeeded; three transaction audits per case verified signed declarations and storage effects. Replays showed 128 warm SLOADs at 100 gas per transaction, plus 128 changed-slot SSTOREs at 2,900 gas in the write case. Both nodes persisted through the drained workload. All 100 benchmark analysis tests passed; `git diff --check` passed.

Data: [full results JSON](results.json), [summary CSV](summary.csv), [two-minute slices CSV](time-slices.csv).
