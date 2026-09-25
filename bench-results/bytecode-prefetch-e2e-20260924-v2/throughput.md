# Targeted bytecode prefetch: end-to-end A/B

Same binary, fixture, offered load, CPU sets, and memory limits. Each phase restores its scratch databases, runs for 1,200 seconds, and excludes the first 600 seconds. General read-ahead remains disabled. One sequential baseline/feature pair, not replicated confidence intervals.

| Metric | Baseline | Prefetch | Ratio |
| --- | ---: | ---: | ---: |
| Builder execution Mgas/s | 6.207 | 15.765 | 2.540x |
| Follower execution Mgas/s | 6.411 | 19.030 | 2.968x |
| Chain Mgas/s | 6.073 | 15.361 | 2.530x |
| Builder read requests/Mgas | 34627.394 | 10156.259 | 0.293x |
| Builder read MB/Mgas | 141.834 | 134.018 | 0.945x |
| Follower read requests/Mgas | 2551.116 | 1170.029 | 0.459x |
| Follower read MB/Mgas | 10.449 | 15.030 | 1.438x |

I/O counters cover each whole node on its database device, including prewarming and persistence. Prefetch byte counters measure hinted ranges, not actual disk reads. Execution rates are gas divided by execution time, not sustainable chain rates.

- baseline: 75.66% of reported measured transactions follow another transaction in their block; correctness and durable catch-up passed. Prefetch evidence: {"a":{"enabled":0,"requests":0,"requests_rw":0,"bytes":0,"errors":0,"hinted_bytes_per_request":null},"b":{"enabled":0,"requests":0,"requests_rw":0,"bytes":0,"errors":0,"hinted_bytes_per_request":null}}.
- prefetch: 90.35% of reported measured transactions follow another transaction in their block; correctness and durable catch-up passed. Prefetch evidence: {"a":{"enabled":1,"requests":52788339,"requests_rw":0,"bytes":1513547800576,"errors":0,"hinted_bytes_per_request":28672.010319854922},"b":{"enabled":1,"requests":5976736,"requests_rw":80625,"bytes":171365031936,"errors":0,"hinted_bytes_per_request":28672.009594534542}}.

## Time Slices and Scope

The headline uses the entire prespecified measured window, not the best slice. These two-minute slices expose cache redistribution and catch-up effects; they are not independent replications.

| Mode | Load seconds | Builder execution Mgas/s | Follower execution Mgas/s | Chain Mgas/s |
| --- | --- | ---: | ---: | ---: |
| baseline | 600-720 | 6.228 | 6.505 | 6.088 |
| baseline | 720-840 | 6.214 | 6.441 | 6.078 |
| baseline | 840-960 | 6.192 | 6.409 | 6.054 |
| baseline | 960-1080 | 6.195 | 6.351 | 6.068 |
| baseline | 1080-1200 | 6.205 | 6.357 | 6.061 |
| prefetch | 600-720 | 12.140 | 25.063 | 11.820 |
| prefetch | 720-840 | 14.967 | 19.022 | 14.615 |
| prefetch | 840-960 | 17.228 | 18.173 | 16.747 |
| prefetch | 960-1080 | 17.395 | 17.716 | 16.956 |
| prefetch | 1080-1200 | 17.222 | 17.819 | 16.753 |

Follower read-byte ratio: 1.438x. Reduced requests must not be described as reduced page-cache misses or bandwidth.
Follower pipeline coverage: baseline {"pipeline_runs":0,"pipeline_execution_seconds":0,"syncing_payloads":0,"mixed_paths":false,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":false,"payload_fault_ratio_suppressed":false}; prefetch {"pipeline_runs":1,"pipeline_execution_seconds":7.961278759000038,"syncing_payloads":45,"mixed_paths":true,"unknown_pipeline_coverage":false,"engine_cache_ratio_suppressed":true,"payload_fault_ratio_suppressed":true}. The analyzer suppresses execution-thread fault/cache ratios when pipeline coverage differs.
The nodes share host RAM, so cache allocation can change during a run. Faster blocks also change the fraction of transactions with a predecessor. These are measured end-to-end effects, not a fixed-trace isolated-I/O comparison.


Binary SHA256: 5e4752f9d04cf152486487c6d4a33c91fa31011e6df9e7fa3760d0acd39b9f2d.
