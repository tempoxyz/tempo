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

The fee-state check is built in and always runs first. Fork-specific rules come from one JSON file
per candidate hardfork in `expectations/` (`t15.json` for `--shadow T15`), compiled into the
binary. Each rule names the fork that introduces it; replay applies the rules for forks in
`(canonical fork, candidate fork]`, in file order. A candidate without a rule file is rejected
before replay starts.

A `skip-header-checks` rule makes the candidate skip the checks of a block's header against state
that its fork introduces, such as T14's proposer fee recipient check. They read state blocks of
earlier forks never read, so the corpus lacks it, and they change no state, so skipping them
hides no compared effect. The executor can only skip all such checks at once, so the candidate
skips them all on a block whose canonical fork predates any skip rule's fork.

A rule's `kind` selects a check implemented in Rust, and its other fields configure it, naming
`tempo-contracts` constants such as `ZONE_PORTAL_IMPL_ADDRESS` or `T14_ZONE_PORTAL_RUNTIME`. Rule
files are strict: unknown fields, kinds or constant names, duplicate ids, an account listed twice
in one rule, and rules out of fork order or after the candidate are errors.

A check receives existing execution evidence and a changed field descriptor, and either accepts
the difference or leaves it unexplained. The first accepting check owns attribution. Fee-slot
provenance alone never accepts a difference.

## Adding an expectation

1. Add the rule to the file of its introducing fork and of every later candidate that still
   replays blocks from before that fork, with a stable, unique id. Copies of a rule must be
   identical.
2. If the rule names a new constant, add it to the matching `named_constants!` list.
3. If no existing `kind` expresses the rule, add one: a `Rule` variant, a `Check` variant, and its
   arm in `Expectation::accepts`, matching `Field` metadata and reading typed values from
   `Context`, never diagnostic strings.
   Leave a difference unexplained when evidence is insufficient.
4. Test accepted effects, nearby incorrect effects, and unrelated differences at the same boundary.

## Reporting

Replay distinguishes `Match`, fully compared `Expected`, `Inconclusive`, and unexplained
`Findings`; `--fail-on-findings` fails for the latter two.

Reports keep exact counts but retain at most eight deterministic samples, prioritizing
unexplained differences. Classification reuses existing execution evidence, and only retained
values are formatted for diagnostics.
