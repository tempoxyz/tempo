# SLOAD transaction-size isolation

Status: complete; 4/4 completed cells. All rates below exclude 600 seconds of warmup from a 1,200-second load.

Same binary SHA256 5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d, same fixture root 0x35b455ab5ebd982f1516eb9cd5660e4a652e1bbbe78de642b1f0f59eb5cc9784, unchanged 100 GB populated storage corpus and code corpus, 1,000 offered TPS / 1,000 signers. Both nodes have a verified 20 GiB total-memory cap and no swap. Restored MDBX files are individually evicted and mincore-verified before startup; no global cache flush. CPU/device isolation is unchanged. Prefetch stays enabled in all cells.

| Reads/tx | Prewarming | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s | Canonical workload SLOAD/s | Follower durable Mgas/s | Follower backlog first/last Ggas |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |
| 4096 | on | 18.241 | 38.783 | 18.013 | 8274.594 | 18.072 | 0.446/0.419 |
| 128 | on | 38.516 | 42.682 | 37.689 | 15151.328 | 37.700 | 0.402/0.392 |
| 128 | off | 44.100 | 54.906 | 43.479 | 17478.992 | 42.908 | 0.413/0.703 |
| 4096 | off | 39.183 | 39.274 | 38.798 | 17822.763 | 38.285 | 0.785/0.981 |

## Cache and I/O

| Cell | Node | File cache first/last GiB | File cache min/max GiB | Read requests/Mgas | Read MB/Mgas | Major faults/Mgas |
| --- | --- | --- | --- | ---: | ---: | ---: |
| 1-4096-on | a | 16.890/16.562 | 16.514/16.942 | 8635.622 | 35.372 | 8900.373 |
| 1-4096-on | b | 17.655/19.180 | 17.655/19.206 | 365.953 | 1.499 | 365.950 |
| 2-128-on | a | 16.673/16.621 | 16.456/16.772 | 5582.820 | 22.867 | 5590.690 |
| 2-128-on | b | 17.106/17.064 | 17.056/17.138 | 648.561 | 2.657 | 656.745 |
| 3-128-off | a | 17.624/17.902 | 17.624/18.390 | 323.377 | 1.325 | 323.369 |
| 3-128-off | b | 18.607/18.231 | 18.229/18.607 | 255.777 | 1.048 | 255.771 |
| 4-4096-off | a | 18.896/18.846 | 18.838/18.931 | 365.149 | 1.496 | 365.145 |
| 4-4096-off | b | 19.190/19.158 | 19.135/19.197 | 362.696 | 1.486 | 362.692 |

## Size effect

Prewarming on: small/large canonical gas throughput = 2.092x; workload SLOAD/s = 1.831x; gas per workload SLOAD = 1.143x.
Prewarming off: small/large canonical gas throughput = 1.121x; workload SLOAD/s = 0.981x; gas per workload SLOAD = 1.143x.

## Correctness and time slices

### 1-4096-on

History eligibility 0.08%; transactions/block {"1":1210,"2":1}. Three cold-read traces passed; sampling policy {"policy":"large-sload-control-first-allowed","non_first_samples":0}. Cursor reconciled 2413 workload transactions; both nodes persisted through drain block 2527.

Pipeline coverage: {"pipeline_runs":0,"pipeline_execution_seconds":0,"syncing_payloads":0,"mixed_paths":false,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":false,"payload_fault_ratio_suppressed":false}.

| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |
| --- | ---: | ---: | ---: |
| 600-720 | 18.324 | 36.813 | 18.066 |
| 720-840 | 18.215 | 35.522 | 17.988 |
| 840-960 | 18.153 | 40.651 | 17.988 |
| 960-1080 | 18.335 | 40.805 | 18.143 |
| 1080-1200 | 18.168 | 40.964 | 17.910 |

### 2-128-on

History eligibility 96.72%; transactions/block {"26":1,"27":10,"28":73,"29":277,"30":666,"31":1080,"32":216,"33":8}. Three cold-read traces passed; sampling policy {"policy":"non-first-required","non_first_samples":3}. Cursor reconciled 141951 workload transactions; both nodes persisted through drain block 4807.

Pipeline coverage: {"pipeline_runs":0,"pipeline_execution_seconds":0,"syncing_payloads":0,"mixed_paths":false,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":false,"payload_fault_ratio_suppressed":false}.

| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |
| --- | ---: | ---: | ---: |
| 600-720 | 38.442 | 42.178 | 37.663 |
| 720-840 | 38.571 | 41.991 | 37.743 |
| 840-960 | 38.540 | 44.749 | 37.715 |
| 960-1080 | 38.482 | 41.857 | 37.660 |
| 1080-1200 | 38.540 | 42.602 | 37.724 |

### 3-128-off

History eligibility 97.15%; transactions/block {"31":1,"32":3,"33":20,"34":436,"35":1284,"36":538,"37":53,"38":2}. Three cold-read traces passed; sampling policy {"policy":"non-first-required","non_first_samples":3}. Cursor reconciled 153191 workload transactions; both nodes persisted through drain block 4814.

Pipeline coverage: {"pipeline_runs":47,"pipeline_execution_seconds":290.501439821,"syncing_payloads":1683,"mixed_paths":true,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":true,"payload_fault_ratio_suppressed":true}.

| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |
| --- | ---: | ---: | ---: |
| 600-720 | 44.308 | 46.143 | 43.696 |
| 720-840 | 43.984 | 49.377 | 43.402 |
| 840-960 | 44.609 | 58.069 | 44.062 |
| 960-1080 | 43.769 | 71.186 | 43.164 |
| 1080-1200 | 43.859 | 49.785 | 43.189 |

### 4-4096-off

History eligibility 42.17%; transactions/block {"1":411,"2":1097,"3":2}. Three cold-read traces passed; sampling policy {"policy":"non-first-required","non_first_samples":3}. Cursor reconciled 5035 workload transactions; both nodes persisted through drain block 3246.

Pipeline coverage: {"pipeline_runs":0,"pipeline_execution_seconds":0,"syncing_payloads":0,"mixed_paths":false,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":false,"payload_fault_ratio_suppressed":false}.

| Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain production Mgas/s |
| --- | ---: | ---: | ---: |
| 600-720 | 40.445 | 41.221 | 40.086 |
| 720-840 | 37.247 | 36.517 | 36.985 |
| 840-960 | 41.020 | 41.037 | 40.706 |
| 960-1080 | 40.274 | 41.140 | 39.931 |
| 1080-1200 | 37.187 | 36.382 | 36.752 |

## Interpretation limits

Production throughput is not sustainable end-to-end throughput if follower backlog grows. Execution-only rates exclude other work. A total-memory cap does not reserve identical file-cache bytes: heap usage and cache residency are recorded separately. Whole-node I/O includes prewarming, execution, trie and persistence; it is not direct opcode attribution. History eligibility plus sampled replay divergence does not instrument every actual prewarm worker. Sizes use separate entry points in the same router; full storage-domain coverage is retained. One sequential pass cannot provide confidence intervals or eliminate all time/order effects. Prewarming-off is a diagnostic control, not the production worst-case configuration.
