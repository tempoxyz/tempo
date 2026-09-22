# Shadow replay

Shadow replay runs on a follower node and evaluates a candidate hardfork against blocks already
accepted by the canonical chain. It is a pre-activation safety tool: operators can observe how
historical or newly canonical traffic behaves under future rules before those rules become
consensus-critical. It reports expected fork changes, unexplained differences, and places where an
early difference prevents a trustworthy comparison of the rest of the block. It does not decide
consensus validity or modify the canonical chain.

The live replayer subscribes to canonical-state notifications and processes newly committed blocks.
It reports notification gaps rather than backfilling them; the `shadow-replay` command can instead
scan an explicit historical block range. Blocks where the candidate hardfork is already canonical
are skipped.

## Execution model

For each selected canonical block, replay opens the canonical parent state and performs two
independent executions of the exact block transactions:

- the **control** uses the hardfork active for the canonical block.
- the **shadow** uses the selected candidate hardfork and its hardfork schedule.

Both executions include pre-block changes, transactions in canonical order, and post-block changes.
They use isolated in-memory overlays and may run concurrently. Their state is never persisted,
shared with block production, submitted to fork choice, or carried into the next block. Every block
therefore starts independently from its own canonical parent, even if the previous shadow block
diverged.

The control also acts as a live re-execution test for the shipped binary: it continuously checks
that the binary can execute canonical blocks successfully and reproduce their receipts under the
active rules, catching STF-breaking changes before shadow differences are interpreted. A control
failure terminates live replay because an unverified baseline cannot be attributed to the candidate
rules. This validates receipt reproduction rather than full canonical state equality. A shadow
failure is retained as a finding or as inconclusive coverage when it occurs after an earlier cutoff.

## Comparison model

After both executions finish, analysis compares their pre-block changes, completed transactions,
and post-block changes in order. Transaction comparisons cover success, output, application and
fee logs, receipt log order, receipt and block gas, and net account and storage transitions. This
compares observable effects at completed boundaries, not opcode traces, internal write history, or
transactions re-executed one-by-one from identical canonical intermediate states.

An unexplained state or gas difference creates a cutoff because later shadow transactions may have
run from a different state or execution context. Analysis still finishes every comparison at the
current boundary, but later boundaries are reported as inconclusive rather than independent
findings. The next block starts independently from its canonical parent. Fee provenance is recorded
for classification but does not by itself exempt a state difference.

## Expectations

`analysis/expectations.rs` registers checks at the hardfork introducing a feature. For each block,
replay selects checks in `(canonical fork, candidate fork]` after validating the control.

A check receives existing execution evidence and a changed field descriptor. It returns:

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
