# Lane prewarming: GCP multi-region result

## Conclusion

Wasted general-lane prewarming is real, but this run does **not** support the
proposed consequence that payments are mostly left un-prewarmed. Of 417,733
included payment transactions, 417,470 (99.937%) had completed successful
prewarming before payload execution. All included payments succeeded.

The large measured builder cost is iterator/coordinator churn: `next()` consumes
69.706% of fill time, while general transaction execution consumes 5.967%.
General-cap rejection repeatedly rebuilds the prewarming delivery buffer. These
measurements identify a much stronger bottleneck than cold payment execution;
they do not establish how much throughput a scheduling or invalidation fix would
recover without an intervention benchmark.

## Run and coverage

- [GitHub Actions run](https://github.com/tempoxyz/tempo/actions/runs/36427900066)
- Instrumented node: [11b17296d2cde163ac1136cd3e5ab867e4eae6a9](https://github.com/tempoxyz/tempo/commit/11b17296d2cde163ac1136cd3e5ab867e4eae6a9)
- Uninstrumented control: [63f6e325ee29ebd09f38439677b0d7dce7d21acd](https://github.com/tempoxyz/tempo/commit/63f6e325ee29ebd09f38439677b0d7dce7d21acd)
- GCP; 10 validators across us-east4, us-central1, europe-west4,
  asia-southeast1, and asia-east1; 100 GiB bloat preset; 48 prewarming workers.
- One paired run, 90-second measurements, 50,000 target TPS, 1,000 accounts,
  5,000 concurrent requests, `public-mix`, prewarming on, parallel replay off.
- The workload subtree matches [9b96ad902001ef2e78a017ee91dc5bd22f4a1f3d](https://github.com/tempoxyz/tempo/commit/9b96ad902001ef2e78a017ee91dc5bd22f4a1f3d);
  txgen is pinned to [9d2124ad5831e848381b369dea3875c3e7999a38](https://github.com/tempoxyz/txgen/commit/9d2124ad5831e848381b369dea3875c3e7999a38).
- Instrumented measurement: 2026-09-28 14:14:38.576 to 14:16:08.585 UTC.
  All 130 reported blocks, heights 417 through 546, have complete diagnostics.
  All 10 validators contributed measured payloads.
- The txgen report omits block hashes. Matching used exact height and timestamp;
  transaction counts and gas used agree for every block, and all 130 payload
  hashes independently appear in canonical-chain logs.
- No missing final summaries; every scheduled observation has a finished worker
  record, including tasks that returned without executing. Included outcome
  counts reconcile with the builder, and execution plus iterator time never
  exceeds fill time.

## Builder wall-time accounting

These are arithmetic means over the same 130 blocks, not percentile sums.

| Component | Mean per block | Share of fill time |
| --- | ---: | ---: |
| Iterator `next()` | 243.379 ms | 69.706% |
| Payment execution | 80.251 ms | 22.985% |
| General execution, successes and reverts | 20.834 ms | 5.967% |
| Remaining builder work | 4.687 ms | 1.342% |
| Total fill | 349.151 ms | 100% |

Every measured block stopped on its build-time budget. Mean composition was
3,213.33 payments and 130.65 general transactions; mean gas was 355.431 Mgas total,
including 25.022 Mgas general and 330.409 Mgas payments.

There were 24,004 general-cap rejections / coordinator invalidations: 184.65 per
block. They scanned 484,556,184 buffered entries, or 3,727,355 per block. The
coordinator recorded 180.846 ms of invalidation/drain time per block. That timer
can include work after cutoff and overlaps builder `next()`; **do not add it to
the wall-time table**. Iterator time includes waiting and other iterator work,
not just invalidation.

## Prewarming

| Observation | Result |
| --- | ---: |
| Scheduled attempts | 4,959,058 |
| General share of active-build worker time | 74.849% |
| Worker time on general candidates already too large for remaining general gas at worker start | 38.994% |
| General share of worker time after the first general-cap rejection | 80.530% |
| Average measured worker occupancy during build windows | 43.278% of 48 workers |
| Already-nonfitting general work as a fraction of worker capacity | 16.876% |
| Included payments with successful prewarming complete at execution entry | 417,470 / 417,733 (99.937%) |
| Included payments whose worker had not started | 138 (0.033%) |
| Included payments whose worker was still running | 125 (0.030%) |
| Worst block's fraction of included payments with incomplete prewarming | 1.060% |

Worker spans are elapsed time summed across threads, including state-provider
setup, not CPU time or builder wall time. They are clipped at the builder cutoff.
Summed work after cutoff was only 557.826 worker-ms across all 130 builds,
including 409.572 general worker-ms; it is excluded from active-build shares.

Only 0.951% of active-build worker time belongs to general transactions explicitly
rejected by the builder. Most excess work is never reached by the builder at all:
2,578,581 general scheduling attempts and 1,921,756 payment attempts were
unconsumed or filtered elsewhere. Therefore counting only explicit gas-cap
rejections would badly undercount wasted prewarming.

Complete prewarming does not guarantee every later access hits a cache. These
results reject the strong explanation that payments generally miss their
prewarming because of the general lane; they do not exclude cache eviction,
memory-bandwidth contention, or other effects of unnecessary general work.

## Execution timings and receipt outcomes

| Included category | Count | Mean payload execution |
| --- | ---: | ---: |
| Payments, all successful | 417,733 | 24.974 us |
| Payments with successful prewarming already complete | 417,470 | 24.845 us |
| Payments whose prewarming had not started | 138 | 294.948 us |
| Payments whose prewarming was running | 125 | 159.479 us |
| General, successful receipts | 5,521 | 398.170 us |
| General, reverted receipts | 11,463 | 44.499 us |
| General, all included outcomes | 16,984 | 159.467 us |

The 6.39x general/payment ratio is the mixed-success average. Successful general
transactions alone average 15.94x payments, but the entire general lane still
accounts for only 20.834 ms per block. These categories are lanes, not a
zone-only transaction breakdown. The few incompletely prewarmed payments are
slower, but too rare here to explain a large throughput loss.

## Control and limitations

| Reported metric | Control | Instrumented |
| --- | ---: | ---: |
| Mean TPS | 4,989 | 4,924 (-1.3%) |
| Builder latency p50 | 359.7 ms | 357.6 ms |
| Builder gas throughput | 1,013.5 Mgas/s | 1,018.7 Mgas/s |

The paired results show no large instrumentation regression, but one pair is not
a precise overhead estimate. This uses the current benchmark runner, including
its dedicated GCP load generator; it is not an exact reproduction of the older
runner/network path. No scheduling, gas-admission, or invalidation policy was
changed. No claim is made that fixing buffer churn recovers the historical 10x
payment difference without a separate intervention run.

## Reproduction and validation

Download the `tempo-bench-e2e-multi-region-results` artifact from the linked run,
then run:

```sh
uv run python contrib/bench/analyze-prewarm.py RESULTS_ROOT --output ANALYSIS_DIR
```

The script writes `summary.json`, `lane-observations.csv`, and
`block-observations.csv`. The latter two preserve the underlying counts and
block hashes for independent checks. This analysis and report were added after
the benchmark; the tested node revision remains the commit linked above.

Rust formatting, diff checks, and payload-builder test compilation passed. All
three new diagnostic unit tests passed. The focused prewarming suite had 13
passes and one existing intermittent worker-state test failure; the identical
failure was reproduced on the uninstrumented parent (one of five repeat runs).
It was not changed as part of this diagnostic work.
