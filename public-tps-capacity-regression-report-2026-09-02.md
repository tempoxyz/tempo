# Public TPS regression: expiring-nonce capacity

Date: 2026-09-02  
Scope: the drop in the public benchmark from roughly 22k TPS to roughly 18–20k TPS after the Aug 8 db8 build.

## Conclusion

The regression is caused by the T10 expiring-nonce replay-capacity increase in [`db8e7abd`](https://github.com/tempoxyz/tempo/commit/db8e7abd920f599a642a06957dc34eda0763b9cc):

| T10 parameter | Before db8 | db8 |
|---|---:|---:|
| Expiring-nonce replay capacity | 300,000 | 3,000,000 |
| Maximum expiry | 30 s | 300 s |

The capacity change is the causal difference. The maximum-expiry change is not exercised by the public workload, whose txgen template uses `valid_for_secs: 5`.

## Direct isolation

The cleanest test compared db8 against a temporary branch based on the same commit, changing only `POST_T10_CAPACITY` from `3,000,000` back to `300,000`. T10 was active on both sides.

In [GitHub Actions run 33606886320](https://github.com/tempoxyz/tempo/actions/runs/33606886320), using the public preset, 50,000 TPS target, 100 concurrent requests, one token, and 300 seconds per side:

| Build | Capacity | TPS mean |
|---|---:|---:|
| db8 baseline | 3,000,000 | 20,831 |
| Same db8 code, capacity-only change | 300,000 | 23,047 |

The capacity-only change improves throughput by 10.6%. Mean block time remains in the same range (`511.9 → 515.8 ms`), so the result is explained by more transactions per block rather than a faster block clock. The 300k side stays at roughly 11.7–12.1k transactions/block across the five-minute run.

This is a same-commit, one-line toggle and is the strongest evidence that the capacity increase caused the regression.

## Supporting benchmark evidence

- The fixed-load c93 → db8 comparison in [run 33540514061](https://github.com/tempoxyz/tempo/actions/runs/33540514061) measured `23,246 → 19,977 TPS` (`-14.1%`). Block time remained effectively unchanged (`514.4 → 509.9 ms`), while transactions and gas per block fell by about 12%.
- ClickHouse showed the degraded db8 side with persistence p50 around `0.91–0.94 s` and trie-update p50 around `0.17–0.19 s`, versus approximately `0.44–0.46 s` and `0.08–0.09 s` on the control. Average transactions/block fell from about 12.1k in minute 0 to 9.5k by minutes 5–9.
- The historical Aug 8 public run shows the same shape: transactions/block fell from 13.4k in minute 0 to 9.2k by minute 2 and 7.6–7.9k afterward; persistence p50 rose from about 0.44 s to 0.97–1.10 s and trie-update p50 from about 0.085 s to 0.19–0.20 s.
- The earlier c93 → db8-with-capacity-rollback test in [run 33603956655](https://github.com/tempoxyz/tempo/actions/runs/33603956655) was only a supporting comparison: `22,533 → 22,268 TPS` (`-1.2%`, classified as no difference). “No difference” meant the rollback build matched c93; it was not a direct 3m-versus-300k comparison. The direct toggle above closes that gap.

## Why capacity affects TPS

The public workload uses expiring nonces. Each transaction updates the nonce precompile’s replay-tracking state, including the `expiring_nonce_seen` mapping and the expiring-nonce ring. The capacity determines how many replay entries remain represented in that state before old entries are evicted.

At roughly 20,000 TPS:

- a 300,000-entry ring reaches its capacity in about 15 seconds;
- a 3,000,000-entry ring reaches its capacity in about 150 seconds.

The larger ring therefore retains roughly 10 times as much nonce state. The observed two-minute ramp in persistence and trie-update latency, followed by a sustained fall in transactions/block while blocks continue arriving every roughly 500 ms, matches that larger retained state becoming the throughput bottleneck.

## Other hypotheses controlled out

- The concurrency increase was tested independently and did not explain the public regression.
- The c93 boundary A/B in [run 33537393831](https://github.com/tempoxyz/tempo/actions/runs/33537393831) showed no meaningful change, ruling out the accompanying Revm/Reth pin transition by itself.
- The candidate Reth persistence change was tested in [run 33538896617](https://github.com/tempoxyz/tempo/actions/runs/33538896617) and showed no meaningful change.
- Two midpoint controls between c93 and db8 showed no regression: [run 33603030767](https://github.com/tempoxyz/tempo/actions/runs/33603030767) and [run 33603030510](https://github.com/tempoxyz/tempo/actions/runs/33603030510).
- An attempted T9-only control is invalid because the benchmark helper’s JSON-field ordering still activated T10; it is excluded from the conclusion.

## Caveats and mitigation

The direct toggle is one 300-second pair, so repeated pairs would better quantify run-to-run variance. However, it changes one constant on the same db8 commit and produces a 10.6% throughput difference with the expected state-growth behavior.

For this workload, restoring the pre-db8 T10 capacity removes the regression. If the larger replay window is required, the retained-state and persistence cost needs to be addressed or the change should be activated only under a later hardfork with an appropriate performance budget. The separate existing-recipient TIP-20 sparse-trie/state-root issue is a different problem and is not needed to explain this public TPS drop.

## References

- [Capacity-change commit db8e7abd](https://github.com/tempoxyz/tempo/commit/db8e7abd920f599a642a06957dc34eda0763b9cc)
- [Direct same-commit capacity toggle](https://github.com/tempoxyz/tempo/actions/runs/33606886320)
- [Full investigation notes](nightly-benchmark-investigation-2026-09-01.md)
