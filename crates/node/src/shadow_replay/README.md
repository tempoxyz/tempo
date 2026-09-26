# Shadow replay

Shadow replay runs on a follower node and evaluates a candidate hardfork against blocks already
accepted by the canonical chain. It is a pre-activation safety tool: operators can observe how
historical or newly canonical traffic behaves under future rules before those rules become
consensus-critical. It reports expected fork changes, unexplained differences, and incomplete
execution coverage. It does not decide consensus validity or modify the canonical chain.

Enable live replay with `--shadow-replay` (latest compiled hardfork) or
`--shadow-replay HARDFORK` (explicit candidate). The existing `--shadow-replay.hardfork HARDFORK`
form is also accepted. The live replayer subscribes to canonical-state notifications and processes
newly committed blocks. It reports notification gaps rather than backfilling them; the
`shadow-replay` command can instead scan an explicit historical block range. Blocks where the
candidate hardfork is already canonical are skipped.

## Execution model

For each selected canonical block, replay opens the canonical parent state and creates two
executors:

- the **control** uses the hardfork active for the canonical block.
- the **shadow** uses the selected candidate hardfork and its hardfork schedule.

Transactions execute in canonical order under both rule sets. A blocking replay task runs each
block inline; within a block, a control thread and shadow worker pipeline results through a
one-entry queue. Replay records both results but commits
the control result into both executors. Every shadow transaction receives the canonical prefix
plus candidate pre-block setup, without inheriting earlier candidate transaction results; an early
candidate transaction difference cannot cause derivative mismatches later. Pre-block changes are
preserved across control commits, but canonical transaction writes to the same fields take precedence.
Candidate post-block behavior runs against this isolated prefix, not a fully committed candidate
block. The candidate schedule activates all predecessor forks so their required pre-block setup
is included.

All execution uses isolated in-memory overlays. State is never persisted, shared with block
production, submitted to fork choice, or carried into the next block. Every block starts
independently from its own canonical parent. Replay executes only canonical transactions; it does
not generate candidate-only transactions.

The control also acts as a live re-execution test for the shipped binary: it continuously checks
that the binary can execute canonical blocks successfully and reproduce their receipts under the
active rules, catching STF-breaking changes before shadow differences are interpreted. A control
failure terminates live replay because an unverified baseline cannot be attributed to the candidate
rules. This validates receipt reproduction rather than full canonical state equality. A rejected
shadow transaction is recorded as a finding; replay still commits the control result and executes
later transactions. A failed pre- or post-block boundary is retained as a finding, and boundaries
that could not execute are reported as incomplete coverage.

## Comparison model

After execution finishes, analysis compares pre-block changes, shadow transactions, and post-block
changes in order. Transaction comparisons cover the full success/revert/halt outcome, output,
ordered receipt logs, and net account and storage transitions. Gas-only differences are not findings, although gas is still
checked against canonical receipts and used to validate fee-derived effects. This compares
observable effects at completed boundaries, not opcode traces or internal write history.

Because every shadow transaction starts from the same canonical prefix, findings at later
transactions remain independent and are all compared. The post-fee TIP-20 transfer amount is masked
when hashing the full receipt only if both arms emit the verified transfer in the same position
and each amount equals its gas-derived charge. All other log contents and positions must match.
Fee-hook storage provenance alone never exempts a state difference: a fee-state expectation also
requires the same value before the post-fee writes in both arms and validates each arm's final value
against its ordered hook writes (including fee-AMM swaps). Unsupported fee changes remain findings;
other state differences still require fork expectations.

## Expectations

`expectations.rs` registers checks at the hardfork introducing a feature. For each block,
replay selects checks in `(canonical fork, candidate fork]` after validating the control. The T12
channel and DEX rules retain their precompile-scoped storage checks, including TIP-1060 credits;
they no longer need to accept gas differences because those are not compared.

A check receives existing execution evidence and a changed field descriptor. It returns `None` when
it cannot explain the difference and `Some(())` when it accepts it. The first accepting check owns
attribution. Checks run in fork order, then registration order. `Context::call()` iterates every
call in an AA batch (or the single call of a non-AA transaction), but cannot see internal EVM
calls. Fee-slot provenance alone never accepts a difference.

## Adding an expectation

1. Add a stable, unique rule ID under the introducing fork, keeping registry entries ordered.
2. Match `Field` metadata and read typed values from `Context`; do not parse diagnostic strings.
3. Return `None` when evidence is insufficient.
4. Test accepted effects, nearby incorrect effects, and unrelated differences at the same boundary.

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
