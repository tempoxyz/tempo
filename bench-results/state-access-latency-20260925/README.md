# State-access sizing below the proposal deadline

Validated 2026-09-25. Target: approximately 900 ms of **total builder wall time**,
not 900 ms inside the EVM. The proposer hard timeout remains 1200 ms.

## Selected sizes

Each selected case ran for 1200 seconds with the first 600 excluded. Both passed
receipt, opcode, actual-access-set, router/cursor and persistence audits.

| Workload | Accesses/tx | Average gas/tx | EVM p50 | Build p50 | Build p95 | Build max | Measured cancellations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SLOAD | 7200 | 15,643,766 | 445 ms | 891 ms | 912 ms | 973 ms | 0 / 678 jobs |
| Bytecode | 2250 | 6,256,185 | 485 ms | 915 ms | 946 ms | 962 ms | 0 / 654 jobs |

SLOAD had four cancellations during its first seven seconds of cold startup.
Bytecode had none in warmup. These are measured sustained-load operating points,
not guarantees on every transaction or on different hardware.

| Workload | Builder Mgas/s | Follower Mgas/s | Chain Mgas/s | Builder reads MB/s | Follower reads MB/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| SLOAD | 17.775 | 37.524 | 17.651 | 640.9 | 27.7 |
| Bytecode | 6.879 | 16.630 | 6.809 | 1947.1 | 63.9 |

Builder throughput uses completed transaction-fill time, including iterator wait;
follower throughput uses completed execution time. Chain throughput divides
canonical gas by the full 600-second wall window. Independent cgroup read rates
retain their explicit sample endpoints in `latency-analysis.json`. Attempt and
job cohorts have distinct start/completion boundaries, so their counts need not
equal included transaction counts. No selected measured attempts were censored.

## Controls and rejected candidates

Both cases used the same archived binary, updated router, 100000 MiB storage plus
100000 MiB unique 24 KiB bytecode fixture, fresh restores, verified targeted cache
eviction, 20 GiB/node, no swap, separate NVMe/CPU allocations, 1000 offered TPS,
1000 signers, 25-second expiring nonces, and nonbinding 1T block/general gas caps.
Prewarming and bytecode prefetch stayed enabled. Total memory caps do not force
equal file-cache allocation between workloads.

Both selected cases had one transaction per measured block: history-bypass
coverage was 0%. The router still depends on history, and substantial physical
reads persist, but these results do not establish within-block prewarming bypass
or a universal worst case.

The 3000-code-access diagnostic completed 600 seconds of load with 300 seconds
excluded: 649 ms EVM median plus 563 ms before execution produced a 1218 ms median
at transaction finish and 247 cancellations / 252 jobs. Only five measured
transactions landed, failing the standard steady-state receipt-sample gate.
Its failed manifest remains unchanged. The 9000-SLOAD candidate was deliberately
stopped during warmup at roughly 1120 ms typical build time. Its interrupted
transaction stream ended with a parse error; it is explicitly incomplete and
is not included in the matched throughput table.

## Reproduction and artifacts

The saved profile uses 7200 SLOADs and 2250 code accesses:

```sh
nu bench-e2e.nu state-access-bloat-worst-case \
  --baseline HEAD --feature HEAD --sized-transactions \
  --feature-binary "$PWD/bench-results/state-access-latency-20260925/tempo" \
  --feature-env TEMPO_BENCH_TX_TIMING=1
```

Use the helper environment documented in `contrib/bench/max-state-access.md`.
To tune a single case, add `--case sload --accesses 7200` or
`--case bytecode --accesses 2250`. Analyze each ordinary result directory with
`node contrib/bench/analyze-state-access-latency.cjs RESULT_DIRECTORY`.

Binary SHA256: `3cf755ffee2de9d5dc90fbcc327f2dd7a54b40e0fcf821b4d9943cd663bcf19b`.
`build-manifest.json` and `build-source/` preserve the exact diagnostic build.
`results.json` indexes selected results, audits, configurations and rejected
candidates. Complete raw directories:

- Bytecode: `bench-results/20260925-153713-270`, suite `state-access-bloat-20260925-153713-128`.
- SLOAD: `bench-results/20260925-161847-632`, suite `state-access-bloat-20260925-161847-487`.

Each raw directory has `latency-analysis.json`, full node logs, raw metric
archives, independent observers and the correctness audit with compressed traces.
The analysis keeps all attempted transactions, including cancelled work, and
anchors time to load submission rather than first inclusion or trimmed metrics.
