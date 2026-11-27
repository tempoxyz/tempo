# Shadow replay

Shadow replay evaluates a candidate hardfork against blocks already accepted by the canonical
chain. It is a pre-activation safety tool: it shows how historical traffic behaves under future
rules before those rules become consensus-critical. It reports expected fork changes, unexplained
differences, and incomplete execution coverage. It does not decide consensus validity or modify
the canonical chain.

Run it with `tempo corpus replay --shadow HARDFORK` (built with the `corpus` feature) over a
captured corpus range. Each block is first verified against its corpus record, then replayed on the
pre-state the corpus recorded. Blocks where the candidate hardfork is already canonical are
skipped. The corpus holds only what the canonical execution read, so a candidate that reads
anything else, such as a precompile account its pre-block setup deploys, fails at that boundary
with an `uncaptured` error. That boundary is not compared, so the block is `Inconclusive` rather
than a finding.

## Execution model

The canonical side of every comparison is the block's verified corpus record: its pre- and
post-block changes and each transaction's outcome, receipt and changes. The candidate side runs
under the selected candidate hardfork and its schedule, which activates all predecessor forks so
their required pre-block setup is included.

Replay keeps two views of the state: the canonical one and the candidate one, which starts with
the candidate's pre-block changes instead of the canonical ones. Each transaction executes alone
on the candidate view, from the canonical executor state before it. Then the transaction's
canonical changes are applied to both views. Changes apply field by field, so candidate pre-block
setup survives unless a canonical transaction writes the same field, and no candidate transaction
result carries into a later transaction. The candidate's post-block changes run on the candidate
view from the executor state the last transaction left.

Nothing is persisted, and every block starts from its own recorded pre-state. Replay executes
only canonical transactions; it does not generate candidate-only transactions.

The canonical pre- and post-block changes run again on the canonical view, and so does every
transaction whose candidate result differs, to record its fee hook actions. Each must reproduce its
verified record; otherwise the baseline cannot be trusted and replay fails. A rejected candidate
transaction is recorded as a finding, and later transactions still execute. A failed candidate
pre- or post-block boundary is retained as a finding, and boundaries that could not execute are
reported as incomplete coverage.

## Comparison model

After execution finishes, analysis compares pre-block changes, shadow transactions, and post-block
changes in order. A transaction whose candidate record equals its canonical one matches.
Otherwise the comparison covers its success and stop reason, output, ordered receipt logs, and the
net account and storage changes it makes to the view it ran on. Gas-only differences are not findings, although gas is still
used to validate fee-derived effects. This compares
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
`(canonical fork, candidate fork]`.

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
