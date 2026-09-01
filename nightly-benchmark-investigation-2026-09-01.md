# Tempo nightly benchmark investigation

Working notes for the 2026-09-01 investigation. Times below are UTC unless stated otherwise.

## Scope and data

- Target: nightly `public` and `tip20:recipient=existing,fee-token=any_tip20` runs over the preceding 14 days, with extra attention to 2026-08-05 through 2026-08-08.
- Sources: Tempo benchmark data in ClickHouse (`default.txgen_*`), GitHub Actions workflow/commit metadata, the linked Slack thread, and available Tempo observability data.
- The TIP-20 scenario uses roughly 409.6M existing accounts; the public scenario uses 1,000 accounts.

## Confirmed facts

### Benchmark configuration changed during Aug 5–8

- The nightly workflow runs the same two scenarios, for 600 seconds at a 50,000 TPS target.
- The Aug 5 run used `max-concurrent-requests=100`.
- Commit [`f7358002`](https://github.com/tempoxyz/tempo/commit/f73580029c2c7c8451b4aa3d2aceb89e8d0a7b9) (2026-08-05 12:47 UTC) raised the benchmark/workflow default from 100/500 to 5,000. Aug 6 and Aug 8 run metadata reports 5,000 connections.
- Therefore TPS across Aug 5 versus Aug 6–8 is not a like-for-like client-load comparison. This is a benchmark-harness confounder, not by itself evidence of a node regression.
- [`ff796a68`](https://github.com/tempoxyz/tempo/commit/ff796a6881dd5792f4def49dbb15e850c3c6ee14) (2026-08-17 11:57 UTC) partially reverted that change: single-region/local workflow defaults returned to 100 (with a 500 fallback in the job environment), while multi-region retained 5,000.
- The sender counters show the consequence under TIP-20: failed submissions were 0 on Aug 5, 10,057 on Aug 6, and 23,339 on Aug 8; public remained at 0. This is consistent with excess client concurrency amplifying an already-backpressured node, although it does not isolate the node-side cause.

### Block-time behavior

The public scenario stays close to a 500 ms block interval throughout. TIP-20 has a similar median but much heavier and highly variable tails, including before Aug 5:

| date | scenario | connections | p50 / p99 / max block ms | tx count |
|---|---|---:|---:|---:|
| Aug 4 | public | 100 | 507 / 580 / 661 | 12.57M |
| Aug 4 | TIP-20 | 100 | 490 / 8,332 / 27,741 | 4.22M |
| Aug 5 | public | 100 | 513 / 600 / 652 | 12.50M |
| Aug 5 | TIP-20 | 100 | 492 / 4,875 / 5,944 | 5.87M |
| Aug 6 | public | 5,000 | 510 / 604 / 646 | 13.57M |
| Aug 6 | TIP-20 | 5,000 | 475 / 3,537 / 4,501 | 5.10M |
| Aug 8 | public | 5,000 | 502 / 627 / 643 | 11.05M |
| Aug 8 | TIP-20 | 5,000 | 488 / 5,958 / 12,046 | 4.09M |

- The large TIP-20 tails are not new on Aug 5: Aug 1, Aug 4, Aug 8, Aug 11, Aug 13, Aug 15, and later runs all show multi-second to tens-of-seconds outliers.
- In the recent window, public p99 remains roughly 598–628 ms (apart from one Aug 31 max outlier), while TIP-20 p99 ranges roughly 3.7–14.0 seconds and max ranges roughly 9.7–39.4 seconds.
- There are no exact nightly ClickHouse rows for Aug 3, 7, 9, 10, 12, 16, 18, 23, or 24; Aug 3 does have a release run, but it is excluded here. This is a data/run-availability gap, not evidence that those runs were healthy.

For the exact Aug 4–8 nightly rows, public had 0 blocks above 1 s on every day. TIP-20 had 76/94/116/95 blocks above 1 s on Aug 4/5/6/8 respectively, with 20/22/1/22 above 4 s and 6/0/0/3 above 10 s.

### Metrics and logs point to the follower state-root path

- Public runs have no meaningful beacon backpressure and sub-second state-root/write/persistence tails.
- TIP-20 runs repeatedly show beacon backpressure, multi-second persistence and trie-write tails, and rare multi-second state-root samples. The affected side alternates between A and B across runs.
- The linked Slack investigation reports that the worst `newPayload` cases are dominated by follower state-root validation rebuilding a pruned sparse-trie cache; one Aug 31 case spent about 9.39 s of a 9.61 s `newPayload` call there.
- Controlled tests in that thread found that retaining the sparse-trie cache reduced mean/p99 block time by about 29%/60%, and skipping state-root validation reduced it by about 42%/85%. Storage/CPU/RPC swaps were not consistently causal; the logical validator identity was not proven causal.
- The current interpretation is cache pruning/reconstruction on the incoming-payload validation critical path, amplified by the wide existing-recipient state. It is not that the follower persists more frequently: both sides use the same persistence threshold/cadence.
- A current partner-log sample independently shows the same mechanism’s surface symptoms: repeated sparse-trie reuse, `SparseStateTrie::prune completed` events, and canceled/receiver-dropped `newPayload` responses. That datasource does not retain the benchmark IDs or Aug 5–8 node logs, so it supports the mechanism but cannot map those historical events to a particular nightly run.

### Code timeline check

- The Aug 5 node commit was the broad Commonware 2026.7.0 migration; its Aug 5 TIP-20 p99/max block times (4.87 s/5.94 s) improved over Aug 4 (8.33 s/27.74 s), so the ClickHouse series does not support it as the source of an abrupt Aug 5 regression.
- Aug 1–6 were pinned to Reth `fc3f7da`; the Aug 8 build switched to `10aa6a5` via [`c93d08a9`](https://github.com/tempoxyz/tempo/commit/c93d08a9b6b26baa3026a4f280e5d82aa2d65643), which also bumps Revm. The Reth range includes storage-overlay/persistence changes and an IPC codec fix. Aug 8’s TIP-20 persistence/state-root tails were worse than Aug 6, so this is a plausible secondary contributor, but it is confounded with the 5,000-request load and the same failure mode already being present on Aug 1/4.
- The Aug 6 Tempo commit fixes an upstream subscription retry storm, and the Aug 8 Tempo commit changes TIP-1093 nonce-window parameters. Neither alone aligns cleanly with a new block-time cliff in the nightly data.

### Public TPS-drop isolation (2026-09-01/02)

- The user’s isolated test rules out the benchmark client-concurrency bump. The earlier isolated capacity test did not reproduce a regression, so the capacity lead below is specifically checked against the public 600-second expiring-nonce workload.
- The exact Aug 6 → Aug 8 public comparison is 22,616 → 18,423 tx/s. Average block time is effectively unchanged (504.3 → 497.1 ms), while average transactions per block fall 11,403 → 9,151 and average gas per block falls 503.3M → 403.9M. Average gas per transaction stays about 44.1k. This is a node capacity/throughput change, not a block-gas-limit or block-interval change.
- A fixed-load A/B of the c93 boundary found no regression: [`33537393831`](https://github.com/tempoxyz/tempo/actions/runs/33537393831), baseline `86e6b83b` versus feature `c93d08a9b6`, public, 600 s, 100 concurrent requests, one token: `22,777 → 22,660 TPS` (`-0.5%`). This rules out the Revm 41 → 42.0.1 bump and the accompanying Reth pin range as the cause by themselves.
- A second fixed-load A/B found no effect from the candidate Reth persistence change: [`33538896617`](https://github.com/tempoxyz/tempo/actions/runs/33538896617), c93 versus temporary `onbjerg/tempo-bench-no959` using Reth commit `ad0540f5`: `23,009 → 22,919 TPS` (`-0.4%`). The split-frontier/empty-mask `save_blocks` merge is therefore not the cause.
- The c93 → Aug 8-tip comparison reproduces the regression under fixed concurrency: [`33540514061`](https://github.com/tempoxyz/tempo/actions/runs/33540514061), c93 versus `db8e7abd9`: `23,246 → 19,977 TPS` (`-14.1%`). Block time is unchanged (`514.4 → 509.9 ms`), while validator and builder gas throughput fall about 12% and builder pool fetch gets faster, so the loss is not a slower consensus interval or a client submission bottleneck.
- ClickHouse shows the degraded feature run’s persistence p50 at roughly `0.91–0.94 s` and trie-update p50 at `0.17–0.19 s`, versus about `0.44–0.46 s` and `0.08–0.09 s` on the no959/c93 control. Backpressure, state-root validation, and execution-cache wait remain zero. In the degraded run, average transactions/block falls from 12.1k in minute 0 to 9.5k by minutes 5–9 while block time stays around 510 ms.
- The same shape is visible in the historical Aug 8 ClickHouse row: average transactions/block falls from 13.4k in minute 0 to 9.2k in minute 2 and 7.6–7.9k afterward; persistence p50 rises from about 0.44 s to 0.97–1.10 s and trie-update p50 from about 0.085 s to 0.19–0.20 s. This aligns the throughput cliff with accumulating state rather than with the block clock.
- [`db8e7abd`](https://github.com/tempoxyz/tempo/commit/db8e7abd920f599a642a06957dc34eda0763b9cc) adds the T10 expiring-nonce parameters: replay capacity `300,000 → 3,000,000` and maximum validity `30 → 300 s`. The benchmark test genesis has `t10Time=0`, and the exact historical txgen piece uses `valid_for_secs: 5`, so the validity-window increase does not affect acceptance. Each public transaction does update the nonce precompile’s `expiring_nonce_seen` mapping and ring mapping; at roughly 20k TPS, a 3m ring takes about 150 s to fill versus 15 s for 300k. The observed two-minute persistence/trie ramp is strong evidence that the larger ring retains roughly 10× more nonce state and makes trie persistence the bottleneck. Direct live-state cardinality is not exported, so this last step is an inference from the code and time-series metrics.
- The commit midpoint controls completed without a regression: [`33603030767`](https://github.com/tempoxyz/tempo/actions/runs/33603030767), c93 → `59e8c54f7`, measured `22,959 → 22,988 TPS` (`+0.1%`); [`33603030510`](https://github.com/tempoxyz/tempo/actions/runs/33603030510), c93 → `7b3c986b0`, measured `23,049 → 22,861 TPS` (`-0.8%`, classified as no difference). This removes the commits between c93 and db8 as the source of the drop.
- The attempted pre-T10 control [`33603250915`](https://github.com/tempoxyz/tempo/actions/runs/33603250915) is not valid: its summary was `23,611 → 21,178 TPS` (`-10.3%`), but the logs show `T10 @0` on both sides. The benchmark helper builds its fork ordering from JSON field order, where T10 appears before T9, so a T9 cutoff still activates T10. I exclude this run from the causal result.
- The direct capacity-only control [`33603956655`](https://github.com/tempoxyz/tempo/actions/runs/33603956655) changes only `POST_T10_CAPACITY` back to `300,000` on top of db8, while leaving T10 active. It measured `22,533 → 22,268 TPS` (`-1.2%`, classified as no difference). ClickHouse shows the control staying flat at roughly 11.2–11.6k transactions/block, with persistence p50 around 0.28–0.52 s and trie-update p50 around 0.053–0.079 s across the run. This is the causal confirmation: the 10× capacity increase, not the rest of db8, produces the public throughput loss.
- A direct same-commit toggle closes the remaining cross-run gap: [`33606886320`](https://github.com/tempoxyz/tempo/actions/runs/33606886320) compares db8 with the 3m capacity against a branch differing only by `3,000,000 → 300,000`. With T10 active on both sides, TPS changes `20,831 → 23,047` (`+10.6%`). The 300k feature stays flat at about 11.7–12.1k transactions/block across the five minutes (ClickHouse run `8e5ae1a8-a06a-4b2e-ad1d-032faebe838d`), while the 3m baseline is the degraded side. This is the direct causal confirmation; the earlier c93-versus-rollback A/B was supporting evidence, not this direct toggle.

## Current working conclusion

There are two separate issues:

1. The public TPS regression is caused by the T10 branch of TIP-1093 in `db8e7abd9`, specifically the 10× expiring-nonce replay capacity. The fixed-load A/B reproduces a 14.1% drop, and the direct same-commit capacity toggle produces a 10.6% recovery with no other code change. The historical run shows the matching two-minute state/persistence ramp. The Revm/Reth c93 boundary, the intervening Tempo commits, and the Reth split-frontier merge have all been controlled out. The attempted T9 control was invalid because the benchmark helper still activated T10.
2. The elevated and spiky block times on the existing-recipient TIP-20 workload are a separate node-side behavior that predates Aug 5 and persists afterward. The strongest evidence there still implicates sparse-trie validation-cache pruning/reconstruction on the follower state-root path.

## Open checks

- Historical partner logs for Aug 5–8 are not available in the retained observability datasource; benchmark-specific evidence is therefore from ClickHouse, GitHub artifacts/metadata, and the Slack investigation.
- The temporary Tempo/Reth benchmark branches, worktrees, local Reth clone, and downloaded logs were removed after the investigation.
- For the separate TIP-20 existing-recipient issue, rerun the same commit/scenario with fixed client concurrency and the cache/state-root toggles used in the Slack thread.

## Links

- [Slack investigation thread](https://tempoxyz.slack.com/archives/C0A87C21805/p1788182749824189)
- [Aug 5 nightly workflow](https://github.com/tempoxyz/tempo/actions/runs/30971327555)
- [Aug 6 nightly workflow](https://github.com/tempoxyz/tempo/actions/runs/31067516615)
- [Aug 8 nightly workflow](https://github.com/tempoxyz/tempo/actions/runs/31235525026)
- [Latest Aug 31 nightly workflow](https://github.com/tempoxyz/tempo/actions/runs/33350395883)
