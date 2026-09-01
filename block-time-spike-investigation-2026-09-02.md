# Root cause of the existing-recipient block-time spikes

Date: 2026-09-02

## Bottom line

The block-time spikes are real. They are caused by the wide-state TIP-20
benchmark driving slow sparse-trie state-root validation, especially on one
datadir/CPU placement. The immediate stall is amplified by synchronous
`newPayload` processing and persistence/backpressure.

The completed isolation matrix rules out validator identity and RPC ingress as
the cause. Its result follows the physical pairing of the state datadir and
the CPU set: the slow state-root series follows the A-datadir + B-CPU pairing,
regardless of which logical validator owns it. This implicates CPU/storage
NUMA or interrupt locality. The benchmark harness pins CPU sets, but does not
bind memory or storage interrupts to the corresponding NUMA/device locality.

This is separate from the already-isolated public TPS regression. The T10
capacity change does not explain these block-time spikes; the spikes predate
that change and occur with an approximately unchanged median block interval.

## Workload and measurement

The affected scenario is
`tip20:recipient=existing,fee-token=any_tip20`: approximately 409.6M existing
accounts, 100 GiB of state bloat, four TIP-20 tokens, a 50,000 TPS target, and
10-minute runs. Block intervals come from `default.txgen_blocks` in
ClickHouse. Node timings come from `default.txgen_metric_samples`.

The metric quantiles below are averages of frequent Prometheus quantile
snapshots. Their maxima identify the tail but are not exact per-event
distributions. Historical block rows do not contain usable per-block component
timings, so the telemetry cannot always be joined to the exact outlier block.

## Historical shape

The median stays near the intended 500ms while the tail reaches seconds or
tens of seconds. The issue is therefore intermittent processing starvation,
not a uniformly larger configured block interval.

| Date | ClickHouse run | Blocks | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|---:|
| Jul 13 | `6e35a152-eb67-4c95-a786-6bfbe745380e` | 928 | 473 | 3,034 | 4,215 | 2 |
| Jul 22 | `25fffbdd-902c-4a43-9480-d1c292e6cdab` | 723 | 476 | 5,066 | 27,504 | 16 |
| Jul 28 | `9e273576-5384-4ef9-950d-9fed9f4c4cf3` | 605 | 486 | 9,757 | 30,408 | 24 |
| Jul 31 | `827215da-7cbb-4e22-b282-8feb7b20d70f` | 640 | 490 | 11,002 | 27,548 | 22 |
| Aug 20 | `0dba3fda-fbc1-4997-9541-cbb0dfe54c52` | 473 | 476 | 15,665 | 45,494 | 29 |
| Aug 31 | `6f2593fb-04fc-46c3-8c86-e34551f98c91` | 554 | 495 | 14,860 | 39,386 | 31 |
| Sep 2 | `1e9cadbe-8a5e-4579-880f-267188e4a948` | 550 | 490 | 10,093 | 33,428 | 28 |

The tail is present before the T10 capacity change and varies substantially
between runs. This is consistent with a sensitive placement/cache/I/O path,
not a deterministic capacity step.

## Evidence for the software path

The diagnostic branch tested state-root controls with the same workload:

| Diagnostic | GitHub run / ClickHouse run | Blocks | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|---:|
| `--debug.skip-state-root` | [33403428060](https://github.com/tempoxyz/tempo/actions/runs/33403428060) / `cf987c37-67ea-46ef-a2e9-d131aa937a19` | 1,163 | 512 | 647 | 1,503 | 0 |
| `--engine.state-root-task-timeout=0s` | [33403428827](https://github.com/tempoxyz/tempo/actions/runs/33403428827) / `1d12e17c-310c-4e3f-b6e9-3d0bea0ff628` | 727 | 471 | 6,140 | 11,196 | 27 |
| `--engine.disable-sparse-trie-cache-pruning` | [33403428608](https://github.com/tempoxyz/tempo/actions/runs/33403428608) / `b699b64a-98d0-4cf3-b95e-7db51201f513` | 714 | 476 | 6,450 | 10,822 | 27 |

Skipping state-root computation nearly removes the tail, proving that the
root/trie path is necessary for the observed block gaps. It is not a viable
production fix because it bypasses state-root correctness, and it does not
separate validation from trie-update generation. Removing cache pruning or the
sequential fallback alone does not remove the tail, so those settings are
amplifiers/mitigations rather than a complete explanation.

## Placement isolation

The follow-up matrix used corrected harness switches from draft PR
[#7370](https://github.com/tempoxyz/tempo/pull/7370):

- `--bench-e2e-swap-signing-keys`: exchange the complete validator identity and
  network binding;
- `--bench-e2e-swap-mounts`: exchange the two state datadirs;
- `--bench-e2e-swap-cpus`: exchange the CPU sets;
- `--bench-e2e-reverse-rpc`: exchange generation and submission RPC order.

The raw `feature-1` ClickHouse rows below all remain noisy, but none of the
swaps eliminates the tail. The three-pair aggregate analysis in PR #7370 found
identity and RPC neutral, while datadir exchange increased validation
p50/p90/p99 by 11.6%/10.7%/27.0%; builder latency remained neutral.

| Mode | GitHub run / ClickHouse run | p50 ms | p99 ms | Max ms | >4 s |
|---|---|---:|---:|---:|---:|
| Control | [33421299290](https://github.com/tempoxyz/tempo/actions/runs/33421299290) / `1d34baf2-25d2-4832-a3b8-336c12d23dbd` | 481 | 4,995 | 10,655 | 16 |
| Identity swap | [33421299205](https://github.com/tempoxyz/tempo/actions/runs/33421299205) / `b3b178e1-d775-4602-919b-f206ba48437c` | 470 | 6,076 | 10,950 | 19 |
| Datadir swap | [33421299561](https://github.com/tempoxyz/tempo/actions/runs/33421299561) / `b60c9644-1e39-414d-b54b-8a6f5b01626b` | 507 | 5,147 | 12,985 | 17 |
| CPU swap | [33421299267](https://github.com/tempoxyz/tempo/actions/runs/33421299267) / `21ae8a6c-1756-4696-b9f6-e265adb201e8` | 496 | 7,060 | 12,504 | 34 |
| RPC reversal | [33421299272](https://github.com/tempoxyz/tempo/actions/runs/33421299272) / `eaf1a51f-c946-46bc-9c03-9085c6335ff1` | 475 | 4,097 | 10,588 | 10 |

The runner maps `/reth-bench-a` to `/dev/nvme2n1` and
`/reth-bench-b` to `/dev/nvme3n1`. The harness assigns CPU set A as
`0-7,16-23` and CPU set B as `8-15,24-31`. The diagnostic result says the
slow series follows the physical A-datadir + B-CPU combination, not a logical
validator role. That is the concrete explanation for why one node often looks
like “the bad follower” and why the bad side can move between runs.

## Telemetry during a bad run

For Aug 31 run `6f2593fb-04fc-46c3-8c86-e34551f98c91`, node B showed:

| Metric | Scraped p50 average | Max sampled |
|---|---:|---:|
| State-root validation | 54 ms | 9.390 s |
| `newPayload` latency | 221 ms | 9.612 s |
| Builder `state_root_with_updates` | 1.323 s | 7.486 s |
| `save_blocks` persistence | 7.030 s | 43.009 s |
| Trie-update write portion | 3.970 s | 31.798 s |
| Beacon backpressure stall | 3.700 s | 39.121 s |

Node A also showed multi-second persistence and trie-write tails, while its
state-root validation was much healthier. This separates the trigger from the
downstream delay: a slow validation/root reconstruction starts the problem;
trie writes, persistence, and backpressure keep the engine behind for much
longer than one root calculation.

## Causal chain

```text
409.6M-account existing-recipient state
  -> random storage access and sparse-trie cache misses
  -> cache pruning/reconstruction makes incoming state-root validation slow
  -> synchronous newPayload handling continues until validation returns
  -> trie updates compete with reads during persistence
  -> persistence backlog and engine backpressure extend the block gap
```

The relevant implementation behavior is visible in the pinned Reth engine
path: the engine calls `on_new_payload(payload)` synchronously before sending
the response. If the request is canceled while that call is running, the
receiver is only observed as dropped after the work returns. The logs contain
these long validation completions and canceled response deliveries.

The sparse-trie task also deliberately prunes its preserved trie after
persistence. That bounds memory, but makes frequently reused storage paths
eligible for later reveal/reconstruction. The payload builder has a separate
state-root path; its latency stays neutral in the datadir comparison, which is
why the evidence points specifically to incoming-payload validation rather
than ordinary block building.

Relevant code:

- [`bench-e2e.nu`](bench-e2e.nu) pins CPU sets with `taskset` and applies a
  memory cap, but does not bind NUMA memory or device IRQs.
- [`crates/payload/builder/src/lib.rs`](crates/payload/builder/src/lib.rs)
  shows the builder state-root wait and synchronous fallback.
- [`crates/payload/builder/src/metrics.rs`](crates/payload/builder/src/metrics.rs)
  defines the builder timing surfaces.
- [Pinned Reth engine message loop](https://github.com/paradigmxyz/reth/blob/23305f9d98e2424da527fdd8a46f762a18d9de3f/crates/engine/tree/src/tree/mod.rs#L1823-L1846)
  shows synchronous `on_new_payload` handling.

## What this does and does not establish

Established with high confidence:

- the timestamp gaps are real, not a dashboard artifact;
- the wide-state existing-recipient workload is the trigger;
- state-root/trie work is necessary for the tail;
- the immediate long-gap mechanism is validation/persistence/backpressure;
- validator identity and RPC placement are not the explanation;
- the observed asymmetry follows a physical datadir/CPU placement and is
  consistent with NUMA or IRQ locality.

Not yet separated:

- whether NUMA memory placement, NVMe PCIe locality, IRQ affinity, or a
  combination is responsible for the bad A-datadir+B-CPU pairing;
- the exact sparse-trie cache policy/code change that should be modified for a
  software-only fix;
- exact one-block causality, because the benchmark does not currently attach a
  common block ID to node telemetry and `txgen_blocks` component fields are
  null for these runs.

## Recommended next action

Run the same three-pair matrix with each node launched under explicit
`cpunodebind`/`membind` for the NVMe device serving its datadir, and set the
NVMe IRQs to the same CPU node. If the validation tail follows the corrected
local pairing, that closes the hardware diagnosis. In parallel, retain hot
storage tries or reduce pruning/reveal churn and measure the tradeoff in memory
against validation p99; do not use `--debug.skip-state-root` outside diagnosis.

Add a block number or trace ID to state-root, `newPayload`, persistence,
trie-write, and backpressure telemetry. That will identify whether each
outlier begins in validation or is solely an already-created persistence
backlog.

## Sources

- [Original benchmark investigation thread](https://tempoxyz.slack.com/archives/C0A87C21805/p1788182749824189)
- [Follower-isolation harness PR #7370](https://github.com/tempoxyz/tempo/pull/7370)
- [Diagnostic-mode harness commit](https://github.com/tempoxyz/tempo/commit/cd0650f57da011154ac60410e497e9fcdf6e76d0)
- [Separate public TPS/capacity report](public-tps-capacity-regression-report-2026-09-02.md)
