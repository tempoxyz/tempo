# 128-SLOAD history-dependent bloat rerun

1,200-second load, 600-second excluded warmup, 1,000 offered TPS and 1,000 signers. Same archived node binary and prefetch setting as the bytecode-prefetch feature run. The router was extended; its hash and fixture state root changed, while both populated corpora were retained. Historical rows below are not an exact-fixture matched pair.

| Workload | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |
| --- | ---: | ---: | ---: |
| Original SLOAD 4096 (historical) | 19.524 | 42.479 | 19.257 |
| Bytecode + prefetch (historical) | 15.765 | 19.030 | 15.361 |
| SLOAD 128 | 47.357 | 40.869 | 46.473 |

**The 46.473 Mgas/s production rate is not demonstrated sustainable end-to-end throughput.** The follower durably processed 31.590 Mgas/s during the measured window, while its producer-to-durable backlog grew from 0.290 to 8.755 Ggas. Both nodes fully drained afterward; that catch-up is outside the timed load. Execution-only rates exclude non-execution wall time, and this single window's durable rate is not an asymptotic capacity estimate.

## History coverage and correctness

Measured history coverage: 97.33% (85316/87652), exceeding the required 90%.
Measured transactions/block histogram: {"18":1,"19":4,"20":16,"21":33,"22":61,"23":63,"24":56,"25":31,"26":17,"27":9,"28":17,"29":32,"30":25,"31":26,"32":58,"33":68,"34":82,"35":72,"36":70,"37":96,"38":125,"39":153,"40":170,"41":199,"42":212,"43":316,"44":243,"45":76,"46":5}.
3 sampled non-first transactions each performed 128 unique, populated SLOADs charged 2,100 gas, with zero parent-state replay overlap. The cursor reconciles 170559 workload transactions and both nodes persisted through drained block 4810.
Builder stops: {"build_budget":2317}; pending pool: {"kind":"aa_2d","min":17744,"median":18365,"max":20468}.

## Whole-node I/O and durability

| Node | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas | Durable Mgas/s | Backlog first/last Ggas |
| --- | ---: | ---: | ---: | ---: | --- |
| a | 4462.889 | 18.280 | 4468.270 | 45.873 | 0.298/0.542 |
| b | 452.438 | 1.854 | 455.314 | 31.590 | 0.290/8.755 |

## Time slices

| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s |
| --- | ---: | ---: | ---: |
| 600-720 | 32.298 | 51.630 | 31.613 |
| 720-840 | 45.180 | 45.287 | 44.327 |
| 840-960 | 50.369 | 39.791 | 49.516 |
| 960-1080 | 54.287 | 34.968 | 53.353 |
| 1080-1200 | 54.192 | 37.320 | 53.159 |

## Limits

History coverage measures eligibility for the within-block bypass; replay validates sampled access-set divergence, not every actual prewarming worker. Whole-node I/O includes speculative work and persistence, not execution-only page misses. Gas throughput includes more per-transaction overhead than the old 4096-read workload. No global cache drop was performed and the nodes share RAM. A single run is not a confidence interval or proof of a universal worst case.

Follower execution coverage: {"pipeline_runs":9,"pipeline_execution_seconds":257.196180861,"syncing_payloads":1480,"mixed_paths":true,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":true,"payload_fault_ratio_suppressed":true}.

Suite: bench-results/state-access-bloat-20260924-182524-130. Binary SHA256: 5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d.
