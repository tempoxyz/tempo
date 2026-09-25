# History-dependent state paths

Unique code corpus: 4266667 x 24576 bytes. Original populated 100000 MiB storage import retained.
1200s load; 600s warmup excluded; no artificial transaction cap; prewarming unchanged.

| Case | Canonical Mgas/s | Follower durable Mgas/s | Follower execution Mgas/s | Follower payload-thread major faults/Mgas |
| --- | ---: | ---: | ---: | ---: |
| history_write | 22.240 | 8.404 | 68.444 | n/a |
| history_code | 5.982 | 5.356 | 7.743 | n/a |

## Durable progress

Gas in canonical blocks crossed by each durable state/trie frontier, measured between frontier observations. Batched commits are stepwise. Backlog is relative to the producer, not the follower's potentially stale head. A growing backlog invalidates a sustainable producer-rate claim.

| Case | Node | Durable Mgas/s | Producer-to-durable backlog first/last/max blocks | Backlog first/last Ggas |
| --- | --- | ---: | --- | --- |
| history_write | a | 22.996 | 105/73/105 | 1.915/1.317 |
| history_write | b | 8.404 | 560/985/985 | 9.716/17.511 |
| history_code | a | 5.934 | 41/37/50 | 0.065/0.073 |
| history_code | b | 5.356 | 40/203/248 | 0.064/0.404 |

## Whole-node I/O

| Case | Node | Read I/Os/Mgas | Read bytes/Mgas | Write bytes/Mgas | Persistence lag first/last/max |
| --- | --- | ---: | ---: | ---: | --- |
| history_write | a | 4171.308 | 17105161.572 | 4712299.330 | 105/73/105 |
| history_write | b | 927.499 | 3810980.397 | 2047427.566 | 0/0/0 |
| history_code | a | 35413.436 | 145053465.101 | 153467.307 | 41/37/50 |
| history_code | b | 2074.061 | 8496809.222 | 114237.072 | 40/0/49 |

## Whole-node faults

Cgroup counters aligned with each node's executed-gas counter. These include prewarming, persistence and catch-up execution. Major faults and file refaults are not unique-page counts or cache-miss percentages.

| Case | Node | Major faults/Mgas | File refaults/Mgas | File cache first/last GiB |
| --- | --- | ---: | ---: | --- |
| history_write | a | 4201.171 | 4008.356 | 19.626/25.390 |
| history_write | b | 927.177 | 644.743 | 17.649/16.516 |
| history_code | a | 35595.675 | 31688.762 | 14.710/33.747 |
| history_code | b | 2090.343 | 365.038 | 29.376/10.044 |

## Validation

- history_write: 70.54% of all included workload transactions have a preceding transaction in their block; first transactions are not claimed to evade matching parent-state prewarming.
- history_write: 26 successful sampled receipts; 3 actual access-set/opcode-replay checks; parent-state mismatch fractions 1.000, 1.000, 1.000; both persistence frontiers reached 1708.
- history_write: builder stop reasons {"build_budget":721}; pending pool {"kind":"aa_2d","min":21505,"median":25635,"max":46633}; code-cache misses/Mgas (builder/follower) 0.086/n/a.
- history_code: 77.64% of all included workload transactions have a preceding transaction in their block; first transactions are not claimed to evade matching parent-state prewarming.
- history_code: 34 successful sampled receipts; 3 actual access-set/opcode-replay checks; parent-state mismatch fractions 1.000, 1.000, 1.000; both persistence frontiers reached 4452.
- history_code: builder stop reasons {"build_budget":2128}; pending pool {"kind":"aa_2d","min":21502,"median":21683,"max":21749}; code-cache misses/Mgas (builder/follower) 324.710/n/a.

## Time slices

| Case | Load seconds | Canonical Mgas/s | Follower executed wall Mgas/s |
| --- | --- | ---: | ---: |
| history_write | 600-720 | 21.569 | 0.000 |
| history_write | 720-840 | 15.637 | 9.152 |
| history_write | 840-960 | 20.419 | 65.811 |
| history_write | 960-1080 | 35.228 | 0.000 |
| history_write | 1080-1200 | 19.516 | 0.000 |
| history_code | 600-720 | 5.248 | 5.262 |
| history_code | 720-840 | 4.744 | 4.758 |
| history_code | 840-960 | 4.669 | 4.638 |
| history_code | 960-1080 | 7.894 | 6.972 |
| history_code | 1080-1200 | 7.363 | 6.612 |

## Limits

- Writes vary populated slots in the original single storage tree; bytecode reads vary account addresses. This is not a multi-account storage-write experiment.
- Parent-state replay establishes the history dependency, not an instrumented record of every prewarm worker. Other transactions can warm overlapping targets; the first transaction can match.
- Payload-thread fault/gas ratios are suppressed when catch-up bypasses their instrumentation. Whole-node cgroup faults and I/O have broader coverage, including prewarming for transactions that may never be included; I/Os are not individual cache misses.
- Timed-load metrics exclude post-load traces. Durable catch-up verifies completion, not that delayed writes have no steady-state cost. Inspect lag and time slices.
- Whole-node per-gas denominators are executed gas, which can include replays, not strictly finally charged canonical gas. Growing write backlog means the window ratios do not capture all eventual persistence work for that window.
- Execution-only gas rate is not sustainable chain throughput. Both nodes share host RAM.
- The archived original SLOAD result used a different unpatched binary; these results alone do not establish a same-binary ranking or a universal worst case.
