# Shadow replay expectations

`expectations.rs` registers checks at the hardfork introducing a feature. Replay selects
checks in `(canonical fork, candidate fork]` once per block, after validating the canonical
control. Each check receives the existing execution evidence and one typed difference:

```rust,ignore
struct Expectation {
    id: &'static str,
    check: fn(&Context<'_>, &Difference) -> Option<Continuation>,
}

enum Continuation {
    Continue,
    InconclusiveSuffix,
}
```

`None` means the check cannot explain this difference. `Some` accepts only that difference;
`Continue` additionally asserts that it preserves comparability for later execution.
Multiple accepting checks are ambiguous, regardless of ordering. The engine finishes every
comparison at the current boundary before applying a cutoff. An unexplained state, gas, or
block-gas difference conservatively cuts off the suffix. Fee-slot provenance does not exempt
a state change. An accepted difference can also require a cutoff.

The next block starts independently at its canonical parent state. A candidate rejection
after a cutoff contributes to missing coverage, not a second independent finding. A rejection
without an earlier cutoff remains unexplained. Checks do not currently classify rejections.

## Adding a feature

1. Implement a feature module beside the registry, with a stable ID per check and a link to
   its TIP. Register its checks under the introducing fork; a compile-time length assertion
   and a uniqueness test require one registry entry per fork.
2. Check applicability and exact effects from typed evidence. Return `None` when evidence
   is insufficient. A changed gas amount or a fee-touched slot alone is insufficient.
3. Use `InconclusiveSuffix` for accepted persistent state/context changes unless the check
   establishes comparability. Inspect coupled effects as needed, but accept each difference
   separately. Make overlapping checks disjoint or replace them with an explicit combined check.
4. Add fixtures for accepted effects, nearby incorrect effects, unrelated differences at the
   same boundary, and continuation. The classifier's synthetic test rules are not production
   validators and must not be registered.

No production expectations are registered in this draft. In particular, TIP-1016 needs
independent gas/fee accounting checks and sufficient evidence before any gas, fee, or
gas-dependent application differences are accepted. The registry is not an allowlist.

## Reporting and cost

Replay distinguishes `Match`, fully compared `Expected`, `Inconclusive`, and unexplained
`Findings`. Findings can coexist with lost coverage; inspect coverage counters in every case.
Historical replay reports these outcomes separately and `--fail-on-findings` also fails for
inconclusive blocks. Logs call findings unexplained, not confirmed regressions.

- `tempo_shadow_replay_expected_differences_total{rule}` counts accepted differences.
- `tempo_shadow_replay_unexplained_differences_total` counts unexplained differences.
- `tempo_shadow_replay_ambiguous_differences_total` counts overlapping acceptances.
- `tempo_shadow_replay_boundaries_total{result="compared"|"inconclusive"}` exposes coverage.
- `tempo_shadow_replay_findings_total{kind="divergence"|"inconclusive"}` counts review blocks.
  `divergence` preserves the existing label and means unexplained, not confirmed regression.

Reports retain at most eight deterministic samples, prioritizing unexplained differences.
Counts are exact for compared boundaries. Rule IDs are static; addresses, slots and block
hashes are not metric labels. Logs still contain one review report per affected block;
notification deduplication/persistent review queues are outside this draft.

Classification uses both existing executions and the existing state transitions. Recording
`TempoTxResult::block_gas_used()` adds a scalar per transaction, with no tracing or extra
replay. Differences stay typed until logging. No overhead percentage is claimed without a
representative replay benchmark.

The system cannot guarantee zero false positives: incomplete checks leave legitimate changes
unexplained, and incorrect checks can accept bugs. Persistent expected divergence can make
most of a block inconclusive. Recovering that coverage needs another execution strategy or
stronger comparability checks; metadata alone does not recover it. The control validates
receipts, not full canonical state equality, as in the underlying replayer.
