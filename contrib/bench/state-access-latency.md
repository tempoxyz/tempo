# State-access transaction latency calibration

Adjust the number of accesses, not the populated domain or the consensus timeout.
The sized router uses the same salt/history-selected corpus as the max-size tests:
100000 MiB storage plus 100000 MiB of distinct 24 KiB bytecode. Counts are bounded
at 13800 SLOADs or 10800 EXTCODECOPYs. Existing entry points are unchanged.

```sh
nu bench-e2e.nu state-access-bloat-worst-case \
  --baseline HEAD --feature HEAD --sized-transactions \
  --case bytecode --accesses 2250
```

Use `--case sload --accesses 7200` for SLOAD, or omit both flags to run the saved
pair. These counts were calibrated on the reference host, not proved to guarantee
900 ms on arbitrary hardware or in cold-start tails. Saved defaults live in
`configs/state-access-sized.json`. `--accesses` requires a single selected case.
The normal suite defaults to 1200 seconds with 600 seconds of warmup. Exploratory
calibration can use `--duration 600 --summary-warmup-seconds 300`.

As with `--max-transaction-size`, build/set `STATE_PATH_CACHE_EVICT_TOOL` and the
checkpoint helper described in `max-state-access.md`. The suite enforces 20 GiB
per node, no swap, fresh restores, and verified targeted file-cache eviction.
It leaves prewarming enabled and sets `RETH_BYTECODE_PREFETCH=1`. Update the
dedicated fixtures once with `update-history-router.sh` after rebuilding the
router artifact. This does not reimport the corpus.

For cancellation-aware calibration, build the diagnostic binary and pass
`--feature-env TEMPO_BENCH_TX_TIMING=1`. Timing logs include each builder attempt's
start, execution duration, elapsed build time, validity, and cancellation state.
Logging is opt-in and does not change proposal deadlines or cancellation behavior.
Use the same binary and logging setting for both workloads.

```sh
node contrib/bench/analyze-state-access-latency.cjs bench-results/RESULT_DIRECTORY
```

The analyzer uses the actual submission-relative clock, including the full quiet
tail if block production stalls. Attempts are selected by start time, including
later completions and cancelled builds. Missing completions remain explicitly
counted as unfinished. Invalid attempts have a separate distribution. Completed
build throughput is conditional on success; chain gas divided by the full wall
window remains the useful sustained-throughput measure.

Calibrate toward roughly 900 ms of total builder wall time while checking
p95/p99 and actual proposal cancellations. The initial 3000-access bytecode
candidate took about 650 ms in EVM execution but another roughly 570 ms before
execution, already reaching the 1200 ms deadline. A 900 ms EVM-only median is
therefore not sufficient headroom on this setup. Re-run selected counts over the full
1200/600-second comparison window. Report measured history-bypass coverage:
large transactions may still be alone in their blocks.

## Reference result (2026-09-25)

Both selected sizes passed the full 1200/600-second run, receipt/opcode/access-set
audits, and post-load persistence checks. Prewarming and bytecode prefetch stayed on.

| Workload | Accesses/tx | Gas/tx | EVM median | Total build median | Build p95 | Build max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SLOAD | 7200 | 15.644M | 445 ms | 891 ms | 912 ms | 973 ms |
| Bytecode | 2250 | 6.256M | 485 ms | 915 ms | 946 ms | 962 ms |

Neither had a cancellation in the measured window (678 SLOAD and 654 bytecode
proposal jobs). SLOAD had four cancellations in its first seven seconds of cold
startup; bytecode had none during warmup. This is a sustained-load sizing result,
not a hard deadline guarantee. Both ran one transaction per measured block, so
within-block history-bypass coverage was 0% despite the history-dependent router.

Builder/follower/chain throughput was respectively 17.775/37.524/17.651 Mgas/s
for SLOAD and 6.879/16.630/6.809 Mgas/s for bytecode. Builder throughput here uses
completed transaction-fill duration, including iterator wait; it is not EVM-only
throughput. Canonical gas uses the entire measured 600-second wall window.

The diagnostic binary SHA256 was
`3cf755ffee2de9d5dc90fbcc327f2dd7a54b40e0fcf821b4d9943cd663bcf19b`.
Local source/build provenance and raw result indexes are archived under
`bench-results/state-access-latency-20260925/`. The source at the original measurement base did not contain all runtime
changes. This PR includes them and the [dependency patches](patches/README.md);
use `--feature-binary` to select a consistently built diagnostic node.
