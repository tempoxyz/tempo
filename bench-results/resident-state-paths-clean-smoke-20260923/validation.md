# State-access validation

Node revision and database size are held fixed. Each run uses its recorded duration and warmup exclusion. Rates use aligned cumulative-counter deltas, not arithmetic means of per-block throughput.

| Case | Node | Storage misses/Mgas | Major faults/Mgas | Execution ms/Mgas | Cache miss % |
| --- | --- | ---: | ---: | ---: | ---: |
| state_paths_read | builder | 0.45 | n/a | 0.30 | 0.78 |
| state_paths_read | follower | 1.84 | 0.00 | 0.30 | 3.18 |
| state_paths_write | builder | 0.47 | n/a | 0.30 | 0.59 |
| state_paths_write | follower | 2.32 | 0.00 | 0.31 | 2.91 |

## Correctness and saturation

- state_paths_read: 7200 sampled receipts and 3 ordinary contract call/storage-diff checks passed (no opcode replay); builder reverted count 0; pending pool {"kind":"aa_2d","min":51247,"median":52117,"max":52117}; stop reasons {"build_budget":0,"transaction_limit":609}.
- state_paths_read host-wide swap-in counter delta: 47 pages during the measured window (not attributed to either node).
- state_paths_write: 7200 sampled receipts and 3 ordinary contract call/storage-diff checks passed (no opcode replay); builder reverted count 0; pending pool {"kind":"aa_2d","min":54592,"median":55422,"max":55422}; stop reasons {"transaction_limit":608,"build_budget":0}.
- state_paths_write host-wide swap-in counter delta: 13 pages during the measured window (not attributed to either node).

## Measured-window stability

| Case | Minutes | Follower faults/Mgas | Follower execution ms/Mgas | Builder execution ms/Mgas |
| --- | --- | ---: | ---: | ---: |
| state_paths_read | 1-2 | 0.00 | 0.30 | 0.30 |
| state_paths_read | 2-3 | 0.00 | 0.29 | 0.30 |
| state_paths_read | 3-4 | 0.00 | 0.30 | 0.30 |
| state_paths_read | 4-5 | 0.00 | 0.30 | 0.30 |
| state_paths_read | 5-6 | 0.00 | 0.30 | 0.30 |
| state_paths_write | 1-2 | 0.00 | 0.31 | 0.30 |
| state_paths_write | 2-3 | 0.00 | 0.31 | 0.30 |
| state_paths_write | 3-4 | 0.00 | 0.31 | 0.29 |
| state_paths_write | 4-5 | 0.00 | 0.31 | 0.30 |
| state_paths_write | 5-6 | 0.00 | 0.31 | 0.30 |

## Interpretation limits

- Major faults cover the follower payload-processing thread, not only SLOAD or every worker. The builder has no equivalent execution-thread counter in this run.
- Pipeline catch-up shares the gas/time metrics but bypasses the payload-thread fault scope and engine cache. Intervals with pipeline starts or execution are not valid for those per-gas ratios.
- The follower has no mempool ingress and disables builder prewarming/cache sharing. Engine payload prewarming remains a separate path. Judge the predictable control on the builder as well as the follower.
- Ordinary contract controls have small active working sets; they do not establish cold-code or large-write-working-set behavior. Where included, the resident SLOAD control isolates active-working-set effects, not every workload difference.
- A passing sampled audit does not prove every receipt succeeded. The all-build reverted counter and sampled receipts are reported independently.
- Where opcode checks are reported, they use parent-state call replay matched to actual transaction prestate/call traces; replay wrapper gas is not used for normalization. Ordinary contract audits use real transaction call/storage-diff traces, not opcode replay.
- Acceptance TPS is not executed TPS. A build-budget limit indicates builder saturation, not necessarily follower saturation.
- A cold-SLOAD density bound is not a universal bound on physical I/O or execution time per gas.

Raw aligned counter endpoints and five equal-duration slices are saved in each run's state-access-analysis.json.
