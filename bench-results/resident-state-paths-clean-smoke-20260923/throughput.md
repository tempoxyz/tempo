# Ordinary state-path throughput

The controls use the same recorded node binary. Fresh genesis, no imported state bloat. 360-second loads; first 60 seconds excluded. The ordinary controls have small active working sets and do not test cache evasion or cold-code access. Stop reasons below determine whether the configured transaction cap limited each run.

| Case | Canonical wall Mgas/s | Builder wall Mgas/s | Follower wall Mgas/s | Follower execution Mgas/s | Follower major faults/Mgas |
| --- | ---: | ---: | ---: | ---: | ---: |
| state_paths_read | 86.01 | 86.01 | 85.87 | 3370.72 | 0.00 |
| state_paths_write | 77.58 | 77.58 | 77.58 | 3209.16 | 0.00 |

## Scope and validation

- state_paths_read: binary SHA256 57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6; local override true.
- state_paths_read: builder stop reasons {"build_budget":0,"transaction_limit":609}; pending AA pool {"kind":"aa_2d","min":51247,"median":52117,"max":52117}; reverted transactions 0; invalid attempts 0.
- state_paths_read: builder code misses/Mgas 0.02; follower code misses/Mgas 0.03.
- state_paths_read: deployed runtime 7514 bytes; 7200 sampled receipts succeeded; 3 real transaction call/storage-diff checks passed; both durable state/trie frontiers reached quiet block 801.
- state_paths_write: binary SHA256 57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6; local override true.
- state_paths_write: builder stop reasons {"transaction_limit":608,"build_budget":0}; pending AA pool {"kind":"aa_2d","min":54592,"median":55422,"max":55422}; reverted transactions 0; invalid attempts 0.
- state_paths_write: builder code misses/Mgas 0.03; follower code misses/Mgas 0.03.
- state_paths_write: deployed runtime 7514 bytes; 7200 sampled receipts succeeded; 3 real transaction call/storage-diff checks passed; both durable state/trie frontiers reached quiet block 792.

## Node I/O and persistence

These counters cover each whole node on its database device, including prewarming and persistence. They are not execution-thread counters.

| Case | Node | Read bytes/Mgas | Write bytes/Mgas | Read I/Os/Mgas | Write I/Os/Mgas | State lag: first/last/max blocks |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| state_paths_read | a | 0.16 | 126494.14 | 3.98e-5 | 9.14 | 36/38/51 |
| state_paths_read | b | 0.65 | 125024.36 | 1.59e-4 | 8.81 | 36/38/51 |
| state_paths_write | a | 0.00 | 141062.25 | 0.00 | 10.12 | 47/50/50 |
| state_paths_write | b | 0.00 | 139531.74 | 0.00 | 9.76 | 47/50/50 |

## Interpretation

- Wall-clock throughput includes inter-block waiting and bottlenecks; execution-only throughput is not a sustainable chain-rate claim.
- A transaction-cap-limited result is throughput under that cap, not maximum execution capacity.
- No cache misses in ordinary resident controls would not invalidate the cold SLOAD benchmark or establish a worst case.
- Durable catch-up after load establishes that included work reached persistence, not that every submitted transaction was included. Expiring-nonce submissions can expire.
- Fault/gas counters cover the follower payload thread, not all trie and persistence workers. Node I/O counters cover a broader scope.
- Post-load receipt/tracing checks can create reads. Their I/O is not counted in the measured load window or described as persistence-only I/O.
- The two nodes share host RAM despite separate CPU sets and database devices.
