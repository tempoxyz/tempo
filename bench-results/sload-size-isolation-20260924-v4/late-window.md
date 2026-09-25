# Late-window sensitivity check

Common load offsets 900-1200 seconds (last five minutes), selected before the size/prewarming comparison completed. This supplements, not replaces, the standard 600-1200 second window.

| Reads/tx | Prewarming | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s | Canonical SLOAD/s | Builder whole-node read requests/canonical SLOAD |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 4096 | on | 18.255 | 40.907 | 18.045 | 8289.165 | 18.788 |
| 128 | on | 38.514 | 42.753 | 37.677 | 15146.522 | 13.893 |
| 128 | off | 44.002 | 61.334 | 43.398 | 17446.183 | 0.806 |
| 4096 | off | 39.128 | 39.246 | 38.749 | 17800.184 | 0.795 |

| Cell | Node | File-cache first/last GiB | File-cache min/max GiB | Durable Mgas/s | Backlog first/last Ggas |
| --- | --- | --- | --- | ---: | --- |
| 1-4096-on | a | 16.797/16.562 | 16.514/16.918 | 17.824 | 0.357/0.419 |
| 1-4096-on | b | 19.160/19.180 | 19.149/19.191 | 17.824 | 0.357/0.419 |
| 2-128-on | a | 16.551/16.621 | 16.456/16.714 | 38.084 | 0.478/0.373 |
| 2-128-on | b | 17.108/17.064 | 17.056/17.110 | 37.503 | 0.339/0.392 |
| 3-128-off | a | 18.118/17.902 | 17.844/18.165 | 43.151 | 0.472/0.534 |
| 3-128-off | b | 18.396/18.231 | 18.229/18.396 | 43.109 | 0.629/0.703 |
| 4-4096-off | a | 18.880/18.846 | 18.838/18.928 | 38.372 | 0.749/0.820 |
| 4-4096-off | b | 19.158/19.158 | 19.135/19.175 | 37.717 | 0.731/0.981 |

Read requests/canonical SLOAD includes speculative work, trie and persistence; it is not an opcode-attributed miss count. Follower execution may include pipeline replay. A growing backlog means chain production is not demonstrated sustainable throughput.
