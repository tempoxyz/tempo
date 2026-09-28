# Queued builder-prewarming control

This experiment is complete; see [RESULTS.md](RESULTS.md), including the failed
bytecode-off OOM case and its [follow-up fix](../bytecode-oom-fix-20260926/README.md).
The frozen runner below describes the original host. For a new run from source,
use the [setup runbook](../../contrib/bench/state-access-reproduction.md) and
`nu bench-e2e.nu state-access-prewarm-control --baseline HEAD --feature HEAD --wait`.
Large logs and the frozen harness copy are not checked in.

Waits for the complete declared-storage benchmark suite through the shared
`/tmp/tempo-general-state-access-20260922.lock`, then holds that lock across all
four control runs and their audits. It does not stop or alter the active run.

Order: SLOAD on, SLOAD off, bytecode on, bytecode off. Fresh enabled references
are included because the preceding experiment updated the shared router and
transaction generator. The comparison changes only `--builder.disable-prewarming`;
engine prewarming, execution-cache sharing, and bytecode prefetch remain unchanged.

Each run uses the saved 7200-SLOAD or 2250-bytecode-access size, 1200 seconds of
load with 600 seconds excluded, 1000 TPS, 20 GiB/node, no swap, a fresh fixture
restore, targeted cold-cache eviction, and the original diagnostic node binary.
No transaction size is retuned. Expected total time after acquiring the lock is
roughly two hours including restores and audits, not a completion guarantee.

The small benchmark harness is frozen under `harness/`; archived tools and fixture
metadata are verified before starting. A changed fixture/tool or leftover active
benchmark scope causes a safe failure rather than silently changing the experiment.
No compile, database restore, node launch, or cache eviction occurs while waiting.

`experiment.json` records queue status and indexes per-run plans, logs, live
controls, audits, and latency/I/O/gas-throughput analyses. The historical enabled
runs remain separate and are not treated as an exactly matched baseline.

Service: `tempo-builder-prewarm-control-20260925.service` (user systemd).

```sh
systemctl --user status tempo-builder-prewarm-control-20260925.service
journalctl --user -u tempo-builder-prewarm-control-20260925.service
```
