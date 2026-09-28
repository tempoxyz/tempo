# State-Access Gas Calibration, 2026-09-28

Target: **1,000,000,000 execution gas/s**. These are amortized processing budgets per useful operation, including the benchmark's transaction/router overhead. They are NOT isolated opcode prices, additive miss surcharges, or deployment-ready constants. Existing intrinsic/base costs must be reconciled rather than charged twice, and safety margin is not included.

```text
gas_budget_per_operation = 1,000,000,000 / useful_operations_per_second
                        = measured_workload_gas_per_operation * 1,000 / measured_Mgas_per_second
```

Do not substitute 100 gas for a declared read's workload gas per operation: the access-list intrinsic charge and other transaction costs are also in the measured gas counter. Transfer service time per operation when estimating another operation, not its nominal gas price.

## Critical Operations

M = measured workload; E = estimate from the identified proxy. Mgas/s on account-proxy rows is the **storage benchmark's rate**, not a measured account-op rate. The BD rate is an equivalent at the serial bytecode workload's existing gas/access; the proposed code marker has no finalized gas schedule.

| Resource operation | Path | Mgas/s used | Useful operations/s | Budget at 1 Ggas/s | Evidence / benchmark |
| --- | --- | ---: | ---: | ---: | --- |
| Persistent slot read: SLOAD, or one nonce/configuration slot | Access list + prewarming | 189.96 | 80,530 | **12,418 gas** | M SLOAD; RD. Native precompile use is a per-slot E, excluding additional native computation. |
| Same slot read | Serial | 36.45 | 16,776 | **59,609 gas** | M SLOAD; RS. |
| Existing-slot read-modify-write: SLOAD + changed nonzero-to-nonzero SSTORE | Access list + prewarming | 14.92 | 2,806 | **356,410 gas** | M; WD; overloaded durable-write window, provisional. |
| Same existing-slot update | Serial/history-dependent | 8.40 | 1,627 | **614,587 gas** | M; WS; overloaded durable-write window, provisional. |
| Account metadata read: existence, nonce, native balance, code hash | Access list + prewarming | 189.96 proxy | 80,530 E | **~12,400 gas** | E from RD; account-only cold benchmark absent. |
| Same account read | Serial | 36.45 proxy | 16,776 E | **~59,600 gas** | E from RS. |
| Existing account metadata update: nonce or native balance | Access list + prewarming | 14.92 proxy | 2,806 E | **~356,000 gas** | E from WD; account-trie work may differ substantially. |
| Same account update | Serial | 8.40 proxy | 1,627 E | **~615,000 gas** | E from WS; not a measured account mutation cost. |
| Full unique 24-KiB bytecode load: EXTCODECOPY; proxy for CALL-family/EXTCODESIZE loading | Access list + prewarming | ~79.54 equivalent E | ~28,605 E | **~35,000 gas** | E model BD = BS scaled by RD/RS operation-rate gain; no direct code-list benchmark. |
| Same full-code load | Serial | 16.57 | ~5,959 | **~167,800 gas** | M gas rate; BS. Operation rate inferred from workload gas/access; CALL-family use is E and excludes callee execution. |

The bytecode read model uses **80,530 / 16,776 = 4.8003x** as the hypothetical prewarming gain. This is an explicit low-confidence extrapolation, not a measured code speedup: larger fetches, memory limits, CPU, staging dependencies, and prefetch waste may prevent that gain. Giving it no speedup credit instead yields the serial **167,800 gas** placeholder. Do not price production code access at 35,000 until directly tested.

The account-read proxy assumes an unrelated cold account record costs about one cold storage-record read. The account-write proxy assumes comparable per-record mutation and trie service work to a populated-slot update. These assumptions need distinct, sufficiently bloated account fixtures. Account configuration and nonzero nonce domains actually stored in Tempo precompiles use their real `(precompile address, slot)` resources, not the user's account record.

Bytecode measurements do not separately force the account-record corpus out of cache. An independently cold account plus cold code is not fully characterized. Do not mechanically add all full-workload budgets to CALL: resources and transaction overhead overlap, and calls may also execute arbitrary callee work. DELEGATECALL's code source and storage owner must be covered separately.

## Measurement Scope

| ID | Rate used for calibration | Other measured rate / caveat |
| --- | --- | --- |
| RD | Builder durable 189.9569 Mgas/s, slightly below follower durable 189.9614 | Chain 191.2866. Existing EIP-2930 list plus speculative execution, not dedicated direct-key prefetch. |
| RS | Chain 36.4500 Mgas/s over the full 600-second window | Builder completed-fill 36.7766. Only builder prewarming disabled; engine prewarming remains enabled. |
| WD | Follower durable 14.9162 Mgas/s | Chain 21.3741. Backlog grows; 22.4-minute follower drain after load. |
| WS | Follower durable 8.4038 Mgas/s | Chain 22.2404. Backlog grows; older memory controls and binary, not matched to WD. |
| BS | Follower executed gas / wall time 16.5692 Mgas/s, including pipeline work | Chain 17.1106; builder completed-fill 17.3762. OOM-fixed run included a follower pause during warmup. This is NOT a durable-frontier count. |

The write rates are measured service-window observations during overload, not proven sustainable rates. Both write workloads include an old-value read and persistence, and toggling bit 255 can expand compact value encoding. Their gas budgets are not incremental SSTORE-only costs. The declared read's small durable backlog growth and all runs' batching/tails likewise require longer matched reruns before final pricing. These experiments are not a same-binary, same-window matrix and provide no statistical confidence interval.

"Access list + prewarming" includes time spent preparing the data; it never means measuring only execution after all I/O was done for free. Today's declared-storage results are a baseline for a dedicated declaration-driven scheduler, not measurements of that proposed scheduler. "Serial" means demand accesses in the measured workload; RS/BS suppress builder speculation, while WS retains it. This is not a controlled dependency-depth A/B experiment.

New-slot creation, account creation, code installation, deletion/refunds, and mixed workloads remain uncalibrated. A populated-slot update is the nearest write diagnostic, but does not determine their total gas schedule or state-growth charge. No numeric code-deployment estimate is justified by these read-only code experiments.

## Benchmarks To Run

Run from the repository root after the [fresh-checkout setup](../../contrib/bench/state-access-reproduction.md).
Each suffix below follows:

```bash
nu bench-e2e.nu state-access-bloat-worst-case --baseline HEAD --feature HEAD
```

| ID | Append these arguments | What this actually measures |
| --- | --- | --- |
| RD | `--declared-storage --case sload --accesses 128` | Existing signed storage lists with speculative prewarming. |
| RS | `--sized-transactions --case sload --accesses 7200 --feature-args "--builder.disable-prewarming"` | Serial SLOAD with builder speculation off. |
| WD | `--declared-storage --case writes --accesses 128` | Listed existing-slot read-modify-write and persistence. |
| WS | `--case writes` | History-dependent 1,024-slot update workload; legacy fixture/memory conventions. |
| BS | `--sized-transactions --case bytecode --accesses 2250 --feature-args "--builder.disable-prewarming"` | Serial code demand loads with intra-object page prefetch on. |
| BD | No dedicated runnable case yet; run RD, RS, BS to refresh the proxy | Requires known code targets/signed declarations, the unique 24-KiB corpus, and bounded full-cost code prefetch. |

Account-only benchmarks are also missing. RD/RS and WD/WS are explicitly proxies, not commands that measure account metadata. A proper account test must vary many independently cold account records and, for writes, measure account-trie persistence without sharing a small sender set.

The native suite builds the requested git ref. Use the same pinned patched dependencies
across cases, including the bytecode memory fix, by running:

```bash
node contrib/bench/setup-state-access.cjs --build-tools
source target/state-access-deps/env.sh
```

This makes new runs usable with the bytecode memory fix; it is not an exact replay of every historical binary or of BS's warmup intervention. The current dependency patch includes the OOM fix. Sized cases set `RETH_BYTECODE_PREFETCH=1`; this is database page prefetch within a code object, not an access-list code declaration.

Prerequisites: the populated history fixture, current compiled router, patched txgen with signed-list support, the cache-eviction and checkpoint helpers, and an available shared benchmark lock. See [suite configuration](../../contrib/bench/configs/README.md), [declared storage preparation](../../contrib/bench/declared-state-paths.md), and [dependency patches](../../contrib/bench/patches/README.md). Do not run concurrently with another load. All five commands above passed dry-run with the OOM-fixed binary; no new load was launched for this report.

## Sources And Recalculation

- [Declared reads/writes](../declared-storage-20260925/README.md).
- [Serial SLOAD control](../builder-prewarm-control-20260925/RESULTS.md).
- [History-dependent serial writes](../history-state-paths-sustained-20260924-v2/throughput.md).
- [OOM-fixed serial bytecode](../bytecode-oom-fix-20260926/README.md).
- [Exact calculated values and input SHA256s](calibration.json).

```bash
node bench-results/gas-calibration-20260928/calibrate.cjs > bench-results/gas-calibration-20260928/calibration.json
```

The calculator verifies the operation/gas conversion identity and reconciles every block and gas unit crossed by the serial-write durable frontier. It reads saved artifacts only. No node code or benchmark results were changed.
