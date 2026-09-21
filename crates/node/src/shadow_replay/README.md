# Shadow replay expectations

`expectations.rs` registers checks at the hardfork that introduces a feature. For each block,
replay selects checks in `(canonical fork, candidate fork]` after validating the canonical
control.

A check receives the existing execution evidence and a changed field descriptor. It returns:

- `None` when it cannot explain the difference;
- `Some(false)` when it accepts the difference and later boundaries remain comparable;
- `Some(true)` when it accepts the difference but invalidates later comparisons.

The first accepting check owns attribution and continuation. Checks run in fork order, then
registration order, and all fields at the current boundary are compared before a cutoff takes
effect. Unexplained state or gas differences conservatively invalidate the suffix. Fee-slot
provenance alone never accepts a difference.

## Adding an expectation

1. Add a stable, unique rule ID under the introducing fork, keeping registry entries ordered.
2. Match `Field` metadata and read typed values from `Context`; do not parse diagnostic strings.
3. Return `None` when evidence is insufficient. Use `Some(true)` for persistent state or context
   changes unless the rule establishes that later boundaries remain comparable.
4. Test accepted effects, nearby incorrect effects, unrelated differences at the same boundary,
   and continuation behavior.

## Reporting and observability

Replay distinguishes `Match`, fully compared `Expected`, `Inconclusive`, and unexplained
`Findings`; `--fail-on-findings` fails for the latter two.

- `tempo_shadow_replay_expected_differences_total{rule}` counts accepted differences.
- `tempo_shadow_replay_unexplained_differences_total` counts unexplained differences.
- `tempo_shadow_replay_boundaries_total{result="compared"|"inconclusive"}` exposes coverage.
- `tempo_shadow_replay_findings_total{kind="unexplained"|"inconclusive"}` counts review blocks.
- `tempo_shadow_replay_execution_duration_seconds` records live replay duration per block.
- `tempo_shadow_replay_latest_completed_block` tracks the latest completed live replay.

Metric labels are bounded: rule IDs are static, while addresses, slots, and block hashes are not
labels. Reports keep exact counts but retain at most eight deterministic samples, prioritizing
unexplained differences. Classification reuses existing execution evidence, and only retained
values are formatted for diagnostics.
