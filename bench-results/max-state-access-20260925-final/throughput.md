# Near-cap state-access results

1200s offered load, first 600s excluded; same binary, populated fixture, 20 GiB/node with no swap, verified cold restores, prewarming and bytecode prefetch enabled.

| Workload | Operations/tx | Gas/tx | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s | Measured txs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| sload | 13800 | 29945641.857 | 34.462 | 35.503 | 5.240 | 105 |
| bytecode | 10800 | 29858475.000 | 64.413 | 10.577 | 0.100 | 2 |

Bytecode is a near-stall/liveness result, not a clean steady-state execution throughput estimate. Its usual eight-receipt audit failed; the post-load exhaustive audit checked every included transaction. Successful-build metrics omit work canceled before metric recording. Both workloads have 0% within-block history eligibility at this size.

| Workload | Node | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas | File cache first/last GiB | Follower durable Mgas/s |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| sload | a | 29851.787 | 122.273 | 30697.054 | 16.314/16.126 | n/a |
| sload | b | 412.831 | 1.691 | 412.831 | 6.556/11.465 | 5.285 |
| bytecode | a | 1533628.275 | 19160.877 | 894177.666 | 11.462/10.808 | n/a |
| bytecode | b | 1217.895 | 12.345 | 858.667 | 0.745/1.432 | 0.000 |

Whole-node reads include speculation, aborted proposals, trie work and persistence. Per-gas ratios have a very small included-gas denominator in bytecode; they are not unique misses per opcode. The durable frontier did not advance during the sparse bytecode window, but all included work reached both databases during post-load validation.

Timing correction: bench trimmed the raw scrape archive before the last included block, removing idle time. The headline uses the exact 600-second wall window reconstructed from complete node logs and canonical block timestamps; execution durations match the retained scrape counters exactly over their overlapping interval. In throughput.json, full_window contains these authoritative rates; builder/follower retain the original trimmed-scrape analysis for comparison. Observer I/O uses its aligned snapshots inside that full window.

Original manifests and logs retain their failures. SLOAD used an RPC-only nonce override to repair its post-load replay audit; the zero-transaction malformed-preset bytecode attempt is excluded. This report does not relabel those original runs as ordinary suite passes.
