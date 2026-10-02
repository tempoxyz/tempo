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
ordered receipt logs, and net account and storage transitions. A replay-only inspector also
records each top-level call actually entered (every AA envelope call up to the first failure, or
the single call of a regular transaction): its outcome, output, and net state relative to call
entry. Outcome and output comparisons include these per-call values, so a batch that fails at a
different call is a difference even when both transactions revert. Gas-only differences are not findings, although gas is still
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

The native fee-state check (`expectations.rs`) always runs first. Fork-specific rules are data in
embedded per-hardfork files, [`expectations/<fork>.json`](expectations), evaluated by `rules.rs`.
For each block, replay selects the files whose hardfork is in `(canonical fork, candidate fork]`,
in fork then rule order, after validating the control. The first accepting rule owns attribution. Rules cannot accept
transaction invalidation (`execution`), failed boundaries, or missing coverage.

A generic rule has a `boundary` (`pre_block`, `transaction`, `call`, `post_block`), an optional `when`
condition, and `accept` entries listing explicit `fields`, an `address` (`"any"` or an address),
a `slot` (required for `storage`), and an optional `where` condition. A `call` rule is evaluated
once per envelope call: `real.call.*` and `call.*` refer to that call, and its `call` filter
(`to`, `functions` signatures) matches message calls made at any depth within it, as
recorded by the replay inspector. `call_changed_storage` requires that same envelope call to
have changed the address's storage in either arm.

Conditions use a closed vocabulary: `all`, `any`, `not`, `eq`, `lte`, `sub` (checked),
`to_u256`, `call_changed_storage`, typed literals (`u256`, `b256`, `address`, `bool`, `outcome`),
and `ref`s such as `real.outcome`, `tx.gas_limit`, or `real.call.output_hash`. Unknown keys,
references, and type mismatches fail at load; unavailable operands and failed checked arithmetic
never accept a difference.

A code upgrade needs only `id`, `description`, and `"code_upgrade": "0x<address>"`.
The file's hardfork selects the canonical old/new runtime definitions (currently T13 zone upgrades).
Hashes are resolved at load time; unknown hardfork/address pairs fail to load. The rule accepts only
pre-block code changes at that address, from empty or the expected previous runtime to the exact new
runtime, while the control code remains unchanged. Do not combine it with generic conditions or scopes.
New hardfork upgrade sets must be wired to their canonical definitions in `rules::load`, not copied
into a separate address/runtime table.

## Adding an expectation

1. Append a rule with a stable, unique `id` to `expectations/<fork>.json` for its introducing
   hardfork. A new file also needs an entry in `RULE_FILES` (`expectations.rs`), oldest fork first.
2. Keep scopes explicit: list fields, and use `"any"` addresses or slots only for intentional
   heuristics, described in `description`.
3. Test accepted effects, nearby incorrect effects, and unrelated differences at the same boundary.

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
