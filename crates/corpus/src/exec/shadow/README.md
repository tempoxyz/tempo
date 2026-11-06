# Shadow replay

Shadow replay evaluates a candidate hardfork against blocks already accepted by the canonical
chain. It is a pre-activation safety tool: it shows how historical traffic behaves under future
rules before those rules become consensus-critical. It reports expected fork changes, unexplained
differences, and incomplete execution coverage. It does not decide consensus validity or modify
the canonical chain.

Run it with `tempo corpus replay --shadow HARDFORK` (built with the `corpus` feature) over a
captured corpus range. Each block is first verified against its corpus record, then both arms
execute on the pre-state the corpus recorded. Blocks where the candidate hardfork is already
canonical are skipped. The corpus holds only what the canonical execution read, so a candidate
that reads anything else, such as a precompile account its pre-block setup deploys, fails at that
boundary with an `uncaptured` error and is reported as a finding.

## Execution model

For each selected canonical block, replay opens the canonical parent state and creates two
executors:

- the **control** uses the hardfork active for the canonical block.
- the **shadow** uses the selected candidate hardfork and its hardfork schedule.

Transactions execute in canonical order under both rule sets. Within a block, a control thread
and a shadow worker pipeline results through a one-entry queue. Replay records both results but
commits the control result into both executors. Every shadow transaction receives the canonical prefix
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

The control also acts as a re-execution test for the binary: it checks that the binary can
execute canonical blocks successfully and reproduce their receipts under the active rules,
catching STF-breaking changes before shadow differences are interpreted. A control failure is an
error because an unverified baseline cannot be attributed to the candidate rules. This validates
receipt reproduction rather than full canonical state equality. A rejected shadow transaction is recorded as a finding; replay still commits the control result and executes
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

`expectations.rs` always enables the fee-state check and registers feature-specific checks at
their introducing hardfork. For each block, replay selects the baseline check followed by those in
`(canonical fork, candidate fork]` after validating the control.

A check receives existing execution evidence and a changed field descriptor. It returns `None` when
it cannot explain the difference and `Some(())` when it accepts it. The first accepting check owns
attribution. The baseline check runs first, followed by fork-specific checks in fork and
registration order. Fee-slot provenance alone never accepts a difference.

## Adding an expectation

1. Add a stable, unique rule ID under the introducing fork, keeping registry entries ordered
   (unless the rule applies to every fork pair).
2. Match `Field` metadata and read typed values from `Context`; do not parse diagnostic strings.
3. Return `None` when evidence is insufficient.
4. Test accepted effects, nearby incorrect effects, and unrelated differences at the same boundary.

## Reporting

Replay distinguishes `Match`, fully compared `Expected`, `Inconclusive`, and unexplained
`Findings`; `--fail-on-findings` fails for the latter two.

Reports keep exact counts but retain at most eight deterministic samples, prioritizing
unexplained differences. Classification reuses existing execution evidence, and only retained
values are formatted for diagnostics.
