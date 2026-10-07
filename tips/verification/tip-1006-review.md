# TIP-1006 automated source review

Reviewed by Codex parent and independent specialist agents. This records source and assertion meaning, not human approval or a proof over all inputs. `reviews.json` binds the reviewed inventory and links to exact content digests; execution evidence is collected separately from completed test attempts.

## Inventory and source

R1–R7 preserve the seven numbered invariants. R8 covers the role identifier and default administration; R9 the indexed event ABI; R10 the function; R11–R19 the nine behavior rules; R20 access-key authorization and rollback; R21 selector activation; R22 the interface. The activation paragraph makes the existing T12 dispatch boundary explicit. Specification behavior is unchanged. G1 inventories the Threat Model warning and the following issuer role-separation recommendation; operator guidance is treated separately and has no protocol implementation claim.

R21 links the real `#[schedule(since = T12)]` attributes on both selectors in `tip20/dispatch.rs`. Unconditional helpers marked `gate=always` are reached through this dispatch boundary; that annotation does not make the external selectors available before T12. R8/R22 link the role getter and are reviewed against the keccak constant, `ITIP20` ABI, and generic role administration (default admin is configurable, as with other roles).

R1/R2/R4/R5/R9–R13/R15–R18/R20 link `burn_at`: it checks pause, caller role and protected source, authorizes the source's spending, debits its balance, reduces supply, and emits `Transfer` and `BurnAt`. It does not check transfer policy. R3/R14 link `check_burn_address`, shared with `burnBlocked`: active protected constants, this token's address and the full Zone portal prefix are rejected. R6 links `_transfer`; `rewards.rs::update_rewards` returns the zero recipient at T8+, leaving reward state unchanged on this path. R7/R20 link the helper delegating `(from, token, amount)` to `AccountKeychain::authorize_transfer`; source inspection includes its origin/key/limit checks and periodic reset logic.

R19 has no reviewed implementation: no Zone-mode rejection was found in `burn_at`, its dispatch, or the shared precompile registration paths in this checkout. No Zone runtime was exercised. This is missing enforcement/evidence here, not a demonstrated failure of an external Zone implementation. Protocol changes are outside this dashboard patch.

## Assertion meaning and gaps

Separate ignored tests copy relevant existing burnAt fixtures without changing required test bodies. A test-only `spec_evidence!` evaluates a unit-returning assertion once and prints only after it completes. Test success must independently accompany the marker; neither an annotation nor this review establishes execution.

Activation cases explicitly use T11, T12 and T13. T12 cases check role hash and default admin, role grant/revoke, pause errors, policy independence, the protected set, insufficient balance, zero amount and indexed ABI events. A deterministic sequence burns from two holders and checks cumulative supply, every seeded balance and ordered events, then checks positive-value unauthorized, protected and paused attempts leave balances, supply and logs unchanged. These are bounded examples of R1–R5, not an all-sequences proof. Supplementary single-field and `burnBlocked` checks do not independently prove cumulative burnAt properties.

Reward cases seed and compare the recipient, reward checkpoint, reward balance, global accumulator, opted-in supply and backing balance; a nonzero burn checks balance/supply changes, followed by a successful settled reward claim. The bridge cases use the existing `TempoEvm<InMemoryDB>` fixture, deployed Multicall3 bytecode, signed access-key transactions and committed EVM state. They check successful/zero burns, insufficient balance, a caught subcall failure, an enclosing revert after a successful burn, spending-limit errors and discarded logs. Direct HashMap calls are not used as evidence of EVM rollback.

Declared gaps remain visible: Zone rejection (R19), mixed transfer-and-burn spending in one transaction (R7), disabled-limit and non-origin accounting cases (R20), and issuer deployment-policy review. Source review of R7/R20 does not satisfy these missing execution obligations. Finite tests do not cover every input, future fork, key-administration transition or arbitrary call sequence. Only activation/interface boundaries execute on T11/T13; the detailed behavior witnesses use T12.

No protocol logic is changed. TIP-1088's earlier stable spec IDs remain available, but its demo code annotations/tests and source-review records were removed when the showcase moved to TIP-1006. Missing links do not establish absence of its existing implementation.
