# Declared storage benchmark

Slots are useful canonical operations, not gas counters, submissions, speculative attempts, or cache hits. A write slot includes one SLOAD plus one changed nonzero-to-nonzero SSTORE.

| Case / phase | Slots/tx | Canonical slots/s | Canonical wall ns/slot | Builder durable slots/s | Follower durable slots/s | Follower backlog slots first/last |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| sload/feature-1 | 128 | 81093.97 | 12331.37 | 80530.25 | 80532.16 | 770048/1095296 |
| writes/feature-1 | 128 | 4020.48 | 248726.52 | 4028.89 | 2805.76 | 1710208/2512896 |

The JSON retains builder/follower execution and prewarming counters, five time slices, database I/O, memory, durable frontiers, actual signed transaction traces, and tool/binary provenance.

At 1 Ggas/s, one nanosecond corresponds numerically to one gas. The reported ns/slot includes transaction overhead, prewarming, execution, block cadence and other pipeline limits. It is an observed calibration input, not a recommended opcode price. Vary slots/transaction and offered load, check steady-state backlog and resource saturation, and repeat on reference hardware. Do not subtract write and read rates to infer an incremental SSTORE price.

EIP-2930 marks slots warm for EVM gas accounting. Current speculative prewarming remains in use; this benchmark does not implement a direct access-list disk-prefetch scheduler. Warm opcodes do not prove cache residency. Growing durable backlog disqualifies canonical production as sustainable throughput; post-load drain alone does not fix that.
