# State-access validation

The ordinary controls use a patched binary; the SLOAD reference is historical and unpatched. This is not a same-binary comparison. Database size is held fixed. Each run is 20 minutes; the first 10 minutes are excluded. Rates use aligned cumulative-counter deltas, not arithmetic means of per-block throughput.

| Case | Node | Storage misses/Mgas | Major faults/Mgas | Execution ms/Mgas | Cache miss % |
| --- | --- | ---: | ---: | ---: | ---: |
| historical unpatched SLOAD reference | builder | 438.80 | n/a | 45.89 | 95.02 |
| historical unpatched SLOAD reference | follower | 459.82 | 403.91 | 29.89 | 99.76 |
| state_paths_read | builder | 0.40 | n/a | 0.35 | 0.70 |
| state_paths_read | follower | 3.64 | 0.00 | 0.37 | 6.30 |
| state_paths_write | builder | 0.46 | n/a | 0.35 | 0.58 |
| state_paths_write | follower | 4.19 | 0.00 | 0.40 | 5.26 |

## Correctness and saturation

- historical unpatched SLOAD reference: 8 sampled receipts and 3 transaction/access-set checks with parent-state opcode replay passed; builder reverted count 0; pending pool {"kind":"aa_2d","min":55422,"median":55422,"max":55422}; stop reasons {"transaction_limit":0,"build_budget":1397}.
- historical unpatched SLOAD reference whole-window check: cursor advance equals all 3012 reported transactions across contiguous blocks 20-2956.
- historical unpatched SLOAD reference host-wide swap-in counter delta: 928 pages during the measured window (not attributed to either node).
- state_paths_read: 7200 sampled receipts and 3 ordinary contract call/storage-diff checks passed (no opcode replay); builder reverted count 0; pending pool {"kind":"aa_2d","min":51230,"median":52117,"max":52117}; stop reasons {"transaction_limit":1240,"build_budget":0}.
- state_paths_read host-wide swap-in counter delta: 68 pages during the measured window (not attributed to either node).
- state_paths_write: 7200 sampled receipts and 3 ordinary contract call/storage-diff checks passed (no opcode replay); builder reverted count 0; pending pool {"kind":"aa_2d","min":54694,"median":55422,"max":55422}; stop reasons {"transaction_limit":1238,"build_budget":0}.
- state_paths_write host-wide swap-in counter delta: 237 pages during the measured window (not attributed to either node).

## Measured-window stability

| Case | Minutes | Follower faults/Mgas | Follower execution ms/Mgas | Builder execution ms/Mgas |
| --- | --- | ---: | ---: | ---: |
| historical unpatched SLOAD reference | 10-12 | 399.76 | 29.72 | 43.73 |
| historical unpatched SLOAD reference | 12-14 | 419.00 | 30.48 | 45.13 |
| historical unpatched SLOAD reference | 14-16 | 398.36 | 29.45 | 46.43 |
| historical unpatched SLOAD reference | 16-18 | 380.34 | 28.77 | 47.41 |
| historical unpatched SLOAD reference | 18-20 | 420.05 | 31.01 | 46.92 |
| state_paths_read | 10-12 | 0.00 | 0.37 | 0.35 |
| state_paths_read | 12-14 | 0.00 | 0.37 | 0.35 |
| state_paths_read | 14-16 | 0.00 | 0.37 | 0.35 |
| state_paths_read | 16-18 | 0.00 | 0.37 | 0.34 |
| state_paths_read | 18-20 | 0.00 | 0.38 | 0.35 |
| state_paths_write | 10-12 | 0.00 | 0.40 | 0.35 |
| state_paths_write | 12-14 | 0.00 | 0.40 | 0.35 |
| state_paths_write | 14-16 | 0.00 | 0.40 | 0.35 |
| state_paths_write | 16-18 | 0.00 | 0.41 | 0.35 |
| state_paths_write | 18-20 | 0.00 | 0.41 | 0.34 |

## Interpretation limits

- Major faults cover the follower payload-processing thread, not only SLOAD or every worker. The builder has no equivalent execution-thread counter in this run.
- Pipeline catch-up shares the gas/time metrics but bypasses the payload-thread fault scope and engine cache. Intervals with pipeline starts or execution are not valid for those per-gas ratios.
- The follower has no mempool ingress and disables builder prewarming/cache sharing. Engine payload prewarming remains a separate path. Judge the predictable control on the builder as well as the follower.
- Ordinary contract controls have small active working sets; they do not establish cold-code or large-write-working-set behavior. Where included, the resident SLOAD control isolates active-working-set effects, not every workload difference.
- A passing sampled audit does not prove every receipt succeeded. The all-build reverted counter and sampled receipts are reported independently.
- Where opcode checks are reported, they use parent-state call replay matched to actual transaction prestate/call traces; replay wrapper gas is not used for normalization. Ordinary contract audits use real transaction call/storage-diff traces, not opcode replay.
- Acceptance TPS is not executed TPS. A build-budget limit indicates builder saturation, not necessarily follower saturation.
- A cold-SLOAD density bound is not a universal bound on physical I/O or execution time per gas.

Raw aligned counter endpoints and two-minute slices are saved in each run's state-access-analysis.json.
