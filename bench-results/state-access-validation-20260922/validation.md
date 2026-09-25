# State-access validation

Node revision and database size are held fixed. Each run is 20 minutes; the first 10 minutes are excluded. Rates use aligned cumulative-counter deltas, not arithmetic means of per-block throughput.

| Case | Node | Storage misses/Mgas | Major faults/Mgas | Execution ms/Mgas | Cache miss % |
| --- | --- | ---: | ---: | ---: | ---: |
| original dependent | builder | 444.64 | n/a | 60.97 | 96.28 |
| original dependent | follower | 459.82 | 413.72 | 32.25 | 99.76 |
| dependent-repeat | builder | 438.80 | n/a | 45.89 | 95.02 |
| dependent-repeat | follower | 459.82 | 403.91 | 29.89 | 99.76 |
| predictable | builder | 405.16 | n/a | 49.62 | 87.76 |
| predictable | follower | n/a | n/a | 24.96 | 99.90 |
| resident | builder | 1.31 | n/a | 0.12 | 53.82 |
| resident | follower | 0.07 | 0.00 | 0.12 | 2.80 |

## Correctness and saturation

- original dependent: correctness audit not collected; builder reverted count 0; pending pool {"kind":"aa_2d","min":55422,"median":55422,"max":55422}; stop reasons {"build_budget":1064,"transaction_limit":0}.
- original dependent host-wide swap-in counter delta: 71 pages during the measured window (not attributed to either node).
- dependent-repeat: 8 sampled receipts and 3 transaction/access-set checks with parent-state opcode replay passed; builder reverted count 0; pending pool {"kind":"aa_2d","min":55422,"median":55422,"max":55422}; stop reasons {"transaction_limit":0,"build_budget":1397}.
- dependent-repeat whole-window check: cursor advance equals all 3012 reported transactions across contiguous blocks 20-2956.
- dependent-repeat host-wide swap-in counter delta: 928 pages during the measured window (not attributed to either node).
- predictable: 8 sampled receipts and 3 transaction/access-set checks with parent-state opcode replay passed; builder reverted count 0; pending pool {"kind":"aa_2d","min":55422,"median":55422,"max":55422}; stop reasons {"transaction_limit":0,"build_budget":1199}.
- predictable whole-window check: cursor advance equals all 3817 reported transactions across contiguous blocks 22-3010.
- predictable host-wide swap-in counter delta: 2308 pages during the measured window (not attributed to either node).
- predictable follower coverage warning: 4 pipeline starts and 549.54 seconds of pipeline execution. Gas/time include mixed paths; engine-cache and payload-thread fault counters do not cover them all, so their per-gas ratios are suppressed. Cache miss percentage covers only observed engine-cache lookups.
- resident: 2197 sampled receipts and 3 transaction/access-set checks with parent-state opcode replay passed; builder reverted count 0; pending pool {"kind":"aa_2d","min":55143,"median":55422,"max":55422}; stop reasons {"build_budget":2257,"transaction_limit":0}.
- resident whole-window check: cursor advance equals all 994613 reported transactions across contiguous blocks 22-4573.
- resident host-wide swap-in counter delta: 831 pages during the measured window (not attributed to either node).

## Measured-window stability

| Case | Minutes | Follower faults/Mgas | Follower execution ms/Mgas | Builder execution ms/Mgas |
| --- | --- | ---: | ---: | ---: |
| original dependent | 10-12 | 350.21 | 26.02 | 70.94 |
| original dependent | 12-14 | 334.09 | 25.05 | 77.41 |
| original dependent | 14-16 | 383.91 | 27.89 | 79.18 |
| original dependent | 16-18 | 461.67 | 33.65 | 50.67 |
| original dependent | 18-20 | 466.55 | 41.17 | 43.99 |
| dependent-repeat | 10-12 | 399.76 | 29.72 | 43.73 |
| dependent-repeat | 12-14 | 419.00 | 30.48 | 45.13 |
| dependent-repeat | 14-16 | 398.36 | 29.45 | 46.43 |
| dependent-repeat | 16-18 | 380.34 | 28.77 | 47.41 |
| dependent-repeat | 18-20 | 420.05 | 31.01 | 46.92 |
| predictable | 10-12 | n/a | 29.84 | 31.24 |
| predictable | 12-14 | n/a | 26.87 | 46.93 |
| predictable | 14-16 | n/a | 24.17 | 55.90 |
| predictable | 16-18 | n/a | 21.60 | 64.45 |
| predictable | 18-20 | 259.42 | 20.07 | 68.60 |
| resident | 10-12 | 0.00 | 0.12 | 0.12 |
| resident | 12-14 | 0.00 | 0.12 | 0.12 |
| resident | 14-16 | 0.00 | 0.12 | 0.12 |
| resident | 16-18 | 0.00 | 0.12 | 0.12 |
| resident | 18-20 | 0.00 | 0.12 | 0.12 |

## Interpretation limits

- Major faults cover the follower payload-processing thread, not only SLOAD or every worker. The builder has no equivalent execution-thread counter in this run.
- Pipeline catch-up shares the gas/time metrics but bypasses the payload-thread fault scope and engine cache. Intervals with pipeline starts or execution are not valid for those per-gas ratios.
- The follower has no mempool ingress and disables builder prewarming/cache sharing. Engine payload prewarming remains a separate path. Judge the predictable control on the builder as well as the follower.
- The resident control keeps the full database and 4096 cold EVM data reads per transaction, but limits selection to one page. It isolates active-working-set effects, not every possible workload difference.
- A passing sampled audit does not prove every receipt succeeded. The all-build reverted counter and sampled receipts are reported independently.
- The default AA transaction opcode logger is unsupported in this build. Opcode checks use parent-state call replay matched to actual transaction prestate/call traces; replay wrapper gas is not used for normalization.
- Acceptance TPS is not executed TPS. A build-budget limit indicates builder saturation, not necessarily follower saturation.
- A cold-SLOAD density bound is not a universal bound on physical I/O or execution time per gas.

Raw aligned counter endpoints and two-minute slices are saved in each run's state-access-analysis.json.
