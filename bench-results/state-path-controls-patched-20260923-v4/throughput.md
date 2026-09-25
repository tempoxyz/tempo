# Ordinary state-path throughput

The ordinary controls use a locally patched node; the SLOAD reference is historical and unpatched, not a same-binary comparison. Same 100 GB storage-bloated snapshot, role isolation, prewarming configuration, offered load, and 900-transaction block cap. Twenty-minute loads; first ten minutes excluded. The ordinary controls have small active working sets and do not test cache evasion or cold-code access.

| Case | Canonical wall Mgas/s | Builder wall Mgas/s | Follower wall Mgas/s | Follower execution Mgas/s | Follower major faults/Mgas |
| --- | ---: | ---: | ---: | ---: | ---: |
| SLOAD reference | 21.19 | 21.20 | 21.19 | 33.46 | 403.91 |
| state_paths_read | 86.83 | 86.83 | 86.83 | 2689.40 | 0.00 |
| state_paths_write | 78.32 | 78.32 | 78.32 | 2482.06 | 0.00 |

## Scope and validation

- SLOAD reference: builder stop reasons {"transaction_limit":0,"build_budget":1397}; pending AA pool {"kind":"aa_2d","min":55422,"median":55422,"max":55422}; reverted transactions 0; invalid attempts 0.
- SLOAD reference: builder code misses/Mgas 0.17; follower code misses/Mgas 0.22.
- state_paths_read: binary SHA256 57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6; local override true.
- state_paths_read: builder stop reasons {"transaction_limit":1240,"build_budget":0}; pending AA pool {"kind":"aa_2d","min":51230,"median":52117,"max":52117}; reverted transactions 0; invalid attempts 0.
- state_paths_read: builder code misses/Mgas 0.02; follower code misses/Mgas 0.03.
- state_paths_read: deployed runtime 7514 bytes; 7200 sampled receipts succeeded; 3 real transaction call/storage-diff checks passed; both durable state/trie frontiers reached quiet block 2562.
- state_paths_write: binary SHA256 57169b32c8d0867ce3768af7f9c0cc7d36146fe7dcadecaed45064ee1479d4f6; local override true.
- state_paths_write: builder stop reasons {"transaction_limit":1238,"build_budget":0}; pending AA pool {"kind":"aa_2d","min":54694,"median":55422,"max":55422}; reverted transactions 0; invalid attempts 0.
- state_paths_write: builder code misses/Mgas 0.03; follower code misses/Mgas 0.03.
- state_paths_write: deployed runtime 7514 bytes; 7200 sampled receipts succeeded; 3 real transaction call/storage-diff checks passed; both durable state/trie frontiers reached quiet block 2559.

## Node I/O and persistence

These counters cover each whole node on its database device, including prewarming and persistence. They are not execution-thread counters. The SLOAD reference has device-wide counters but no matching cgroup/frontier observer; do not equate these scopes.

| Case | Node | Read bytes/Mgas | Write bytes/Mgas | Read I/Os/Mgas | Write I/Os/Mgas | State lag: first/last/max blocks |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| state_paths_read | a | 924.25 | 269404.35 | 0.00 | 39.02 | 36/41/51 |
| state_paths_read | b | 933.76 | 267790.58 | 0.01 | 38.71 | 36/41/51 |
| state_paths_write | a | 1023.87 | 306112.17 | 0.00 | 43.62 | 50/38/50 |
| state_paths_write | b | 0.00 | 304582.22 | 0.00 | 43.31 | 50/38/50 |

## Interpretation

- Wall-clock throughput includes inter-block waiting and bottlenecks; execution-only throughput is not a sustainable chain-rate claim.
- A transaction-cap-limited result is throughput under that cap, not maximum execution capacity.
- No cache misses in ordinary resident controls would not invalidate the cold SLOAD benchmark or establish a worst case.
- Durable catch-up after load establishes that included work reached persistence, not that every submitted transaction was included. Expiring-nonce submissions can expire.
- Fault/gas counters cover the follower payload thread, not all trie and persistence workers. Node I/O counters cover a broader scope.
- Post-load receipt/tracing checks can create reads. Their I/O is not counted in the measured load window or described as persistence-only I/O.
- The two nodes share host RAM despite separate CPU sets and database devices.
