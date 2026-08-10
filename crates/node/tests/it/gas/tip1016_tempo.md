# TIP-1016 fixtures that exercise custom Tempo flows

Subset of [tip1016.md](tip1016.md) (88 of 151 tests). A test is listed here when the scenario it
covers runs through Tempo-specific code rather than unmodified upstream revm: the custom handler
(`crates/revm/src/handler.rs`), the TIP-1060 storage-credits SSTORE path, the custom gas-params
table, 7702/auth handling, TIP20 fee billing, or the stateful-precompile storage provider.

Tests *not* listed (plain CALL/CREATE frame mechanics, reservoir passing between frames, value
transfers, SELFDESTRUCT, code-deposit sizing) exercise upstream revm logic that Tempo does not
override.

## Flow tags

| Tag | Tempo flow | Where |
|---|---|---|
| `[sstore-credits]` | T7+ SSTORE opcode override + TIP-1060 storage credits decide whether the 245k charge lands in state gas vs execution gas; 0→x→0 mints a credit instead of refilling the reservoir; credit refunds settle as *execution* refunds at end of tx | `crates/revm/src/gas_credits.rs:151`, `crates/precompiles/src/storage_credits/accounting.rs:118` |
| `[intrinsic]` | `validate_initial_tx_gas` fully replaces upstream: state-gas surcharges for CREATE / auths / nonce-0, tx gas-limit cap 16,777,216 at T11, post-validation second cap check | `crates/revm/src/handler.rs:2078`, `:1072` |
| `[refund]` | EIP-3529 refund cap **removed** on T7+; `gas_credits::apply_refund` runs before `refund` and is uncapped | `crates/revm/src/handler.rs:918`, `:885` |
| `[7702]` | Custom `apply_eip7702_auth_list` (extended to AA txs), per-auth intrinsic state gas incl. `auth.nonce == 0` extra charge, `tx_eip7702_state_gas_bytecode` deliberately **0** | `crates/revm/src/handler.rs:960`, `:2120`, `crates/revm/src/gas_params.rs:128` |
| `[billing]` | TIP20 fee settlement bills `gas.used() − gas.reservoir()`; `reward_beneficiary` is a no-op; block header `gas_used` counts regular gas only (state gas exempt from block capacity) | `crates/revm/src/handler.rs:1701`, `:1771`, `crates/evm/src/block.rs:673` |
| `[params]` | Tempo ships its own fixed `amsterdam_gas_params()` table (`sstore_set_state_gas=245k`, `create_state_gas=468k`, `new_account_state_gas=225k`) — fixtures that scale costs with block gas limit (cpsb) stress this table | `crates/revm/src/gas_params.rs:41` |
| `[create-tx]` | EIP-2780 stays disabled: `create_state_gas` is charged at intrinsic time instead, and the top frame's `set_charged_create_state_gas(true)` is set manually so the failed-deploy refund fires | `crates/revm/src/handler.rs:2120`, `:553` |
| `[precompile]` | Stateful precompiles act as contracts through `EvmPrecompileStorageProvider`; state gas / reservoir round-trips via `PrecompileOutput` and `fill_state_gas` | `crates/precompiles/src/storage/evm.rs:193`, `crates/precompiles/src/dispatch.rs:144` |

## Known divergence risks

Tests most likely to *disagree* with Tempo semantics, not just exercise them:

- `refund_cap_includes_state_gas` — asserts the EIP-3529 1/5 cap; Tempo removed the cap on T7+.
- all `*_scales_with_cpsb` — assert costs derived from block gas limit; Tempo's table is fixed.
- `sstore_restoration_*` / `*storage_clear_credit*` — assert the EIP-8037 reservoir-refill /
  clear-credit model; on T7+ the opcode path mints TIP-1060 credits instead (execution-side,
  uncapped refund), so the reservoir-refill branch is effectively dead for the opcode.
- `state_gas_set_code` fixtures assuming per-auth bytecode state gas — Tempo zeroes
  `tx_eip7702_state_gas_bytecode`.
- value-carrying scenarios can only run as imported state fixtures: native Tempo txs reject
  `value != 0` (`handler.rs:1805`).

## Proposed tests: AA batch × state gas

AA batches cannot be expressed as imported state-test fixtures, so none of the 151 fixtures cover
`execute_multi_call_with` (`crates/revm/src/handler.rs:602-761`). The flow, and what makes it easy
to get wrong under TIP-1016:

- Each call is handed the batch's **entire** remaining gas and current reservoir
  (`GasTracker::new_used_gas(batch_gas.remaining(), 0, batch_gas.reservoir())`, `handler.rs:665`),
  and `batch_gas.set_remaining(0)`. On success the call settles back into `batch_gas` via
  `handle_reservoir_remaining_gas` (`handler.rs:737`, revm `frame.rs:592`): unused regular gas
  flows back, the reservoir is adopted, state gas / spill / refunds accumulate.
- On **any** call failure the outer checkpoint reverts every call and `batch_gas` is discarded:
  the failed call's already-settled tracker is returned with its limit widened. Before the
  discard, the state gas prior successful calls settled into `batch_gas` is rolled back onto
  the returned tracker (mirroring `GasTracker::rollback_state_gas`: reservoir portion restored,
  spill returned to `remaining` on revert, consumed on halt), keeping reverted-batch billing
  and header accounting symmetric with the single-call revert exemption.
- Batch intrinsic gas (`calculate_aa_batch_intrinsic_gas`, `handler.rs:2283`) pre-shrinks the
  reservoir: per-auth `new_account_state_gas` (+ again for `auth.nonce == 0`), `create_state_gas`
  per CREATE call, key-authorization `sstore_set_state_gas × intended_writes`, 2D-nonce
  `nonce == 0` surcharge (`handler.rs:2436`).
- Keychain scope prevalidation runs metered with the reservoir but writes back only `remaining`
  (`handler.rs:508`); its failure path returns a synthetic halt with a widened limit.
- On full success the last call's `Gas` is replaced wholesale with `batch_gas`
  (`handler.rs:750-758`) — the receipt and block accounting see only this tracker.

Existing coverage in `tip1016.rs` (formerly `tip1016_storage.rs`):
`test_tip1016_batch_reverting_create_refunds_create_state_gas`,
`test_tip1016_high_gas_limit_batch_tip20_transfers`.

### Results (all proposed tests implemented in `tip1016.rs`, 2026-08-10)

All 21 tests below are implemented as `test_tip1016_batch_*` and pass. Both confirmed
divergences below have since been fixed in production code; the tests now assert the fixed
behavior. (`..._failed_create_first_call_nonce_semantics` was split into
`..._failed_create_bumps_protocol_nonce` and `..._failed_create_2d_nonce_no_protocol_bump`.)

**Confirmed divergences (both fixed 2026-08-10):**

1. **[FIXED 2026-08-10] A reverted batch billed the rolled-back state gas**
   (`..._late_revert_billing_and_block_exemption`). Call 1 creates a slot, call 2 reverts the
   batch. Versus an identical batch writing an existing slot, the receipt was **264,200** gas
   higher: 17,100 regular SSTORE delta + 2,100 credit-bookkeeping SLOAD + **245,000 state gas of
   the rolled-back creation**, with the 245k also landing in the block header as regular gas —
   asymmetric with the single-call equivalent, which refunds it
   (`test_tip1016_reverted_sstore_still_exempts_state_gas`). Cause: prior successful calls'
   state gas was recorded only on `batch_gas`, which the failure path discards. Fix
   (`execute_multi_call_with` failure branch): before the discard, mirror
   `GasTracker::rollback_state_gas` on the returned tracker using the batch-accumulated
   counters — the reservoir-drawn portion restores the reservoir, the spilled portion returns
   to `remaining` on revert (a halt consumes it, matching the single-frame `spend_all`-after-
   rollback model). The receipt delta is now the regular-gas-only **19,200**, and the header no
   longer carries the phantom 245k.
2. **[FIXED 2026-08-10] Block header gas ignored execution refunds**
   (`..._set_in_call1_clear_in_call2_nets_zero`, `..._refunds_accumulate_across_successful_calls`).
   SSTORE refunds (19,900 restore-to-original-zero; 4,800 per clear) were subtracted from receipt
   `gas_used` but not from `block_regular_gas_used` (upstream glamsterdam-devnet-8 semantics per
   EIP-7778: mainnet refunds come from storage clearing whose execution work was still performed,
   so they stay in block gas). Tempo has no clearing refunds — its refunds reflect work rolled
   back within the tx — so Tempo now subtracts the **full, uncapped** refund from block gas too:
   - `tempo_block_regular_gas_used` (`crates/evm/src/block.rs`) =
     `max(total_spent − state_gas − refunded, floor)`, used for section validation and to correct
     the inner executor's pre-refund accumulator in `commit_transaction`.
   - `gas_credits::apply_refund` (`crates/revm/src/gas_credits.rs`) now settles storage credits
     in the **state dimension** on T11 (`refill_reservoir`, the same primitive as 0→x→0
     restoration) instead of recording an execution refund — otherwise the settled 245k would sit
     in `state_gas_spent` *and* the refund counter and be double-subtracted. Receipts are
     unchanged; `state_gas_spent` now reflects only state actually created.
   Result: the header again equals the receipts total minus the state-gas exemption; both tests
   assert exemption 0 with header == receipts.

**Expectations corrected (behavior reasonable, proposal was wrong):**

3. Clearing a slot NOT created in the same tx refunds the legacy **4,800**, not a 245k
   storage-credit refund — the minted credit belongs to the contract, it is not a sender refund.
   The "uncapped 245k execution refund" path from the code-scan report needs a Refund-mode
   contract and did not trigger for plain contract storage.
4. A keychain scope violation charges only the gas actually used (**28,200** = intrinsic +
   metered scope walk), not the full gas limit
   (`..._scope_violation_halts_with_full_budget_limit`).
5. Re-authorizing an existing key is rejected at validation with `KeyAlreadyExists`, so the
   key-authorization intrinsic over-charge (245k state gas for already-nonzero slots) is
   unreachable via duplicate authorization (`..._key_authorization_state_gas_estimate`).

**Confirmed as designed:** additive state gas across calls; reservoir exact-fit boundary and
mid-batch spill to gas_left; OOG on spill reverts the batch atomically consuming the full limit;
halt consumes the full limit with full rollback; refunds are dropped when a later call fails;
failed first-call CREATE bumps the protocol nonce (and does NOT with a 2D nonce, whose 225k
new-key state gas persists on failure); CREATE intrinsic state gas 468k + 73.6k code deposit;
gas_limit one below intrinsic is rejected while the exact fit (521,000 for an empty initcode) is
accepted and fully consumed — an empty-code deploy does **not** refund `create_state_gas`; a
fresh nonce-0 authority costs exactly 450k state gas with the delegation installed
(bytecode state gas is 0); a fresh 2D nonce key costs 225k state gas; expiring nonces cost zero
state gas; the calldata floor binds over the summed tokens of all calls (exactly 621,000, no
state exemption); scope prevalidation charges regular gas only; above-cap gas limits spend state
gas from the reservoir without billing the unused remainder.

### Reservoir hand-off between calls (`handler.rs:665-671`, `:737-741`)

- [x] `test_tip1016_batch_state_gas_additive_across_calls` — Call 1 and call 2 each SSTORE 0→nonzero; block-gas exemption equals the sum of both calls' state gas; receipt bills regular gas only.
- [x] `test_tip1016_batch_reservoir_exhausted_mid_batch_spills_to_gas_left` — Call 1 drains the reservoir; call 2's creation spills into `gas_left`; spill accounting must match the equivalent single-call spill.
- [x] `test_tip1016_batch_creation_at_exact_reservoir_boundary` — Second call's creation cost lands exactly on the remaining reservoir; no spill, off-by-one check on the hand-off.
- [x] `test_tip1016_batch_oog_when_spill_exceeds_gas_left` — Reservoir empty and `gas_left < sstore_set_state_gas`; the call OOGs and the whole batch reverts atomically.

### Failure path — `batch_gas` discarded (`handler.rs:686-729`)

- [x] `test_tip1016_batch_late_revert_billing_and_block_exemption` — Call 1 creates storage, call 2 reverts; assert all state rolled back and the rolled-back state gas refunded (receipt delta vs an existing-slot control is regular gas only), consistent with the single-call reverted-SSTORE exemption (asymmetry fixed — see divergence 1 above).
- [x] `test_tip1016_batch_late_halt_consumes_gas_restores_reservoir` — Call 2 halts (invalid opcode): all regular gas consumed (`spend_all`), reservoir restored to its post-call-1 value, call 1's state gas rolled back.
- [x] `test_tip1016_batch_refund_dropped_when_later_call_fails` — Call 1 clears a slot (earns a refund), call 2 reverts; the refund must not survive (`set_refunded(0)` + discarded `batch_gas`).
- [x] `test_tip1016_batch_failed_create_first_call_nonce_semantics` — First-call CREATE reverts: protocol nonce (`nonce_key == 0`) is still bumped, 2D nonce is not (`handler.rs:699-714`); intrinsic `create_state_gas` refund lands in the unused reservoir, not billed.

### Cross-call restoration and refunds (revm `frame.rs:614-627`)

- [x] `test_tip1016_batch_set_in_call1_clear_in_call2_nets_zero` — 0→x in call 1, x→0 in call 2: the second call's negative `state_gas_spent` contribution flows back through the batch settle (`saturating_add` of a negative child value); on T7+ this routes through a TIP-1060 credit settled once at tx end.
- [x] `test_tip1016_batch_refunds_accumulate_across_successful_calls` — Slot clears spread over several calls; refund counter accumulates per successful call and settles uncapped (T7+) at end of tx.

### Batch intrinsic gas and reservoir sizing (`handler.rs:2283-2383`, `:2436`)

- [x] `test_tip1016_batch_create_intrinsic_state_gas_reserved` — CREATE as first call: `create_state_gas` (468k) charged at intrinsic time shrinks the reservoir before execution; exact-fit boundary at `gas_limit == initial_total_gas()`.
- [x] `test_tip1016_batch_gas_limit_one_below_intrinsic_rejected` — One gas below `initial_total_gas()` → `CallGasCostMoreThanGasLimit` (`handler.rs:2463`).
- [x] `test_tip1016_batch_auth_list_per_auth_state_gas` — AA tx carrying `tempo_authorization_list`: 225k state gas per auth, doubled for `auth.nonce == 0` (`handler.rs:2321-2324`), `tx_eip7702_state_gas_bytecode` contributes 0; billed amount vs header exemption.
- [x] `test_tip1016_batch_2d_nonce_new_key_state_gas` — `nonce_key != 0, nonce == 0` adds `new_account_state_gas` at intrinsic while the actual nonce write runs unmetered (`handler.rs:1190`); assert the estimate is what the user pays.
- [x] `test_tip1016_batch_expiring_nonce_no_state_gas` — Expiring-nonce tx pays the flat 13k as regular gas; zero state gas despite real ring-buffer SSTOREs.
- [x] `test_tip1016_batch_key_authorization_state_gas_estimate` — Inline `KeyAuthorization` on T11: intrinsic state gas = `sstore_set_state_gas × intended_writes` (`handler.rs:368-374`) while the writes run unmetered and persist even if the batch reverts (`handler.rs:1554-1564`); include the re-authorize-existing-key case (slots already nonzero → intrinsic over-charge, state-gas block exemption for state never created).
- [x] `test_tip1016_batch_calldata_floor_over_summed_tokens` — Floor gas computed over the summed tokens of all calls (`handler.rs:2368`, `:2380`); floor-wins case zeroes the reservoir and TIP20 billing must agree.

### Keychain scope prevalidation (`handler.rs:440-528`)

- [x] `test_tip1016_batch_scope_prevalidation_charges_regular_gas_only` — Metered prevalidation deducts from `remaining` only (`handler.rs:508`); reservoir and state-gas counters untouched.
- [x] `test_tip1016_batch_scope_violation_halts_with_full_budget_limit` — Scope check fails → synthetic halt frame with limit widened to the tx budget (`handler.rs:643-647`); billing and header accounting consistent.

### Receipt and block accounting (`handler.rs:750-758`, `crates/evm/src/block.rs:673`)

- [x] `test_tip1016_batch_receipt_gas_equals_batch_tracker` — Multi-call success: receipt `gas_used` comes from the wholesale-replaced batch tracker and equals the sum of per-call spends; header `gas_used` excludes the batch's total state gas.
- [x] `test_tip1016_batch_gas_limit_above_cap_reservoir_spend` — `gas_limit > 16,777,216` (legal at T11 — the excess is reservoir): batch spends state gas across calls; TIP20 pre-funds the full limit and unused reservoir is not billed.

## eip_mainnet (2 of 3)

- [ ] `create_tx_deploys_contract` `[create-tx]` `[intrinsic]` — Creation tx pays `create_state_gas` at intrinsic time through Tempo's replaced calculation.
- [ ] `sstore_zero_to_nonzero` `[sstore-credits]` — Baseline 0→nonzero goes through the T7+ opcode override; the `tip1016` flag routes 245k to state gas.

## state_gas_call (1 of 29)

- [ ] `call_value_precompile_halt_refunds_new_account_state_gas` `[precompile]` — Value CALL to a precompile that halts; Tempo's precompile dispatch returns reservoir/state gas like a child frame and must refund `NEW_ACCOUNT` correctly.

## state_gas_calldata_floor (7 of 7)

Floor interacts with Tempo's replaced intrinsic calc, TIP20 billing, and state-gas-exempt block accounting.

- [ ] `calldata_floor_binds_with_reservoir` `[billing]` — Floor path zeroes the reservoir upstream; TIP20 `reimburse_caller` bills `used() − reservoir` and must agree.
- [ ] `calldata_floor_counts_toward_block_gas` `[billing]` — Tempo's header `gas_used` is regular-gas-only; floor must land in the regular dimension.
- [ ] `calldata_floor_exceeding_tx_gas_limit_cap` `[intrinsic]` — Rejection against Tempo's T11 cap (16,777,216) in the replaced validation.
- [ ] `calldata_floor_higher_than_execution_with_state_ops` `[billing]` — Floor-wins settlement with nonzero state gas feeds Tempo's fee charge.
- [ ] `calldata_floor_independent_of_state_gas` `[billing]` — Dimension separation must survive Tempo's `used() − reservoir` billing.
- [ ] `calldata_floor_not_discounted_by_state_gas` `[billing]` — State-gas spend must not discount the regular-gas floor charged to the block.
- [ ] `calldata_floor_with_sstore` `[sstore-credits]` `[billing]` — Floor plus a credit-path SSTORE in one tx.

## state_gas_create (5 of 27)

Only creation-*transaction* and SSTORE-adjacent tests touch custom code; opcode CREATE/CREATE2 frame mechanics are upstream.

- [ ] `create_tx_below_total_intrinsic` `[intrinsic]` `[create-tx]` — Rejection boundary of Tempo's replaced intrinsic calc for creation txs.
- [ ] `create_tx_intrinsic_gas_boundary` `[intrinsic]` `[create-tx]` — Exact-fit intrinsic incl. the state component Tempo adds because EIP-2780 is off.
- [ ] `create_tx_state_gas` `[intrinsic]` `[create-tx]` — `create_state_gas` charged at intrinsic time (Tempo-specific placement).
- [ ] `failed_create_tx_refills_top_frame_new_account` `[create-tx]` — Exercises the manual `set_charged_create_state_gas(true)` top-frame refund workaround.
- [ ] `sstore_oog_no_reservoir_inflation` `[sstore-credits]` — SSTORE charge ordering inside the overridden opcode (static pre-charge → credits → dynamic → state gas).

## state_gas_delegation_pointer (3 of 3)

- [ ] `delegation_pointer_new_account_state_gas` `[7702]` — Delegated-account creation gas with Tempo's custom auth application and zeroed bytecode state gas.
- [ ] `sstore_direct_call_same_contract` `[sstore-credits]` — Control case for the pointer test; same overridden SSTORE path.
- [ ] `sstore_via_delegation_pointer` `[7702]` `[sstore-credits]` — SSTORE through a delegation set by Tempo's auth handling.

## state_gas_ordering (1 of 4)

- [ ] `sstore_oog_reservoir_inflation_detection` `[sstore-credits]` — Charge-ordering detection targets exactly the sequence Tempo's SSTORE override reimplements; CALL/CREATE/SELFDESTRUCT variants are upstream.

## state_gas_pricing (12 of 15)

- [ ] `auth_state_gas_scales_with_cpsb` `[7702]` `[params]` — Per-auth state gas comes from Tempo's intrinsic surcharge and fixed table.
- [ ] `call_new_account_state_gas_scales_with_cpsb` `[params]` — cpsb scaling vs Tempo's fixed `new_account_state_gas=225k`.
- [ ] `calldata_floor_enforced_with_state_gas` `[intrinsic]` `[billing]` — Floor enforcement inside the replaced validation.
- [ ] `create_state_gas_scales_with_cpsb` `[params]` — cpsb scaling vs Tempo's fixed `create_state_gas=468k`.
- [ ] `intrinsic_regular_gas_exceeds_cap` `[intrinsic]` — Cap check lives in Tempo's replaced validation (T11 cap 16,777,216).
- [ ] `intrinsic_regular_gas_exceeds_cap_with_floor_below_cap` `[intrinsic]` — Same, isolating the floor from the cap check.
- [ ] `intrinsic_within_cap_gas_limit_above_cap` `[intrinsic]` `[billing]` — `gas_limit` above the cap is legal; TIP20 must still pre-fund the *full* limit including the reservoir portion.
- [ ] `pricing_at_various_gas_limits` `[params]` — Reservoir allocation across gas limits against Tempo's table and cap.
- [ ] `refund_cap_includes_state_gas` `[refund]` — **Asserts the EIP-3529 cap Tempo removed on T7+.**
- [ ] `refund_with_reservoir_state_gas` `[refund]` `[billing]` — Refund settlement when state gas came from the reservoir; feeds `used() − reservoir` billing.
- [ ] `selfdestruct_new_beneficiary_scales_with_cpsb` `[params]` — cpsb scaling vs the fixed table.
- [ ] `sstore_refund_scales_with_cpsb` `[params]` `[sstore-credits]` — Restoration refund sizing vs fixed table and credit routing.

## state_gas_reservoir (12 of 12)

Reservoir settlement is the input to Tempo's TIP20 billing, and every clear-credit fixture collides with TIP-1060 credit routing.

- [ ] `create_tx_reservoir` `[create-tx]` `[intrinsic]` — Reservoir sizing after Tempo's intrinsic `create_state_gas` deduction.
- [ ] `insufficient_gas_for_sstore_state_cost` `[sstore-credits]` — OOG inside the overridden SSTORE when spill exceeds `gas_left`.
- [ ] `nested_state_gas_refund_consumed_at_depth` `[sstore-credits]` — Refund routing at depth: reservoir refill (fixture model) vs credit mint (Tempo T7+).
- [ ] `reservoir_allocation_boundary` `[intrinsic]` `[billing]` — Allocation at the TX_MAX_GAS_LIMIT boundary; Tempo's T11 cap and full-limit TIP20 pre-charge.
- [ ] `revert_discards_descendant_storage_clear_credit_through_depth` `[sstore-credits]` — Clear-credit rollback through depth vs Tempo's transient credit slots.
- [ ] `sstore_state_gas_entirely_from_gas_left` `[sstore-credits]` — Zero-reservoir spill path of the overridden opcode.
- [ ] `sstore_state_gas_source` `[sstore-credits]` — Reservoir-vs-gas_left sourcing inside the override.
- [ ] `subcall_revert_does_not_leak_grandchild_storage_clear_credit` `[sstore-credits]` — Credit-leak containment across reverting frames.
- [ ] `subcall_set_clear_revert_pays_no_state_gas` `[sstore-credits]` — 0→x→0 + revert: fixture expects reservoir refill; Tempo mints/discards a credit.
- [ ] `top_level_failure_refunds_execution_state_gas` `[billing]` — Failed-tx settlement flows into TIP20 `reimburse_caller` / `catch_error` accounting.
- [ ] `top_level_failure_spilled_state_gas` `[billing]` — Spilled state gas on failure must bill consistently under `used() − reservoir`.
- [ ] `top_level_opcode_oog_before_frame_end_does_not_refund_state_gas` `[billing]` — No-settlement OOG path feeding Tempo's fee charge.

## state_gas_set_code (27 of 27)

Every set-code fixture runs Tempo's custom auth application (`apply_eip7702_auth_list`, extended to AA), per-auth intrinsic state-gas surcharges (incl. the `auth.nonce == 0` extra `new_account_state_gas`), the deliberately zeroed `tx_eip7702_state_gas_bytecode`, and — for header/receipt assertions — the state-gas-exempt block accounting.

- [ ] `auth_and_execution_state_oog_boundary` `[7702]` `[intrinsic]` — Auth + execution state gas against the reservoir Tempo pre-shrinks at intrinsic time.
- [ ] `auth_block_gas_accounting` `[7702]` `[billing]` — Block/receipt gas vs Tempo's regular-gas-only header accounting.
- [ ] `auth_sender_billing_after_failure` `[7702]` `[billing]` — Sender billed via TIP20 settlement, not balance deduction.
- [ ] `auth_state_gas_in_header_after_failure` `[7702]` `[billing]` — Header `gas_used` after top-level failure; state-gas exemption must hold.
- [ ] `auth_state_gas_persists_on_top_level_revert` `[7702]` — Auth applied outside the execution checkpoint persists on revert (matches Tempo's placement).
- [ ] `auth_with_calldata_and_access_list` `[7702]` `[intrinsic]` — Combined intrinsic components in the replaced calculation.
- [ ] `auth_with_multiple_sstores` `[7702]` `[sstore-credits]` — Auth surcharge plus credit-path SSTOREs in one tx.
- [ ] `authorization_state_gas_scaling` `[7702]` `[intrinsic]` — Per-auth scaling of Tempo's intrinsic state-gas surcharge.
- [ ] `authorization_to_precompile_address` `[7702]` `[precompile]` — Delegation targeting a precompile address; Tempo has 16+ stateful precompiles at reserved addresses.
- [ ] `authorization_with_sstore` `[7702]` `[sstore-credits]` — Auth plus one credit-path SSTORE.
- [ ] `duplicate_signer_authorizations` `[7702]` — Per-authority dedup in Tempo's auth application.
- [ ] `existing_account_auth_header_gas_used` `[7702]` `[billing]` — Existing-authority pricing vs header accounting.
- [ ] `existing_account_no_refund` `[7702]` — Reduced charge for existing authority in Tempo's surcharge logic.
- [ ] `existing_account_no_refund_with_sstore` `[7702]` `[sstore-credits]` — Same, combined with a credit-path SSTORE.
- [ ] `fresh_authority_and_sstores_full_state` `[7702]` `[sstore-credits]` — Full state cost: new-authority surcharge + SSTORE creations.
- [ ] `invalid_auth_no_top_frame_charge` `[7702]` — Rejected auths must not incur Tempo's top-frame surcharge.
- [ ] `invalid_chain_id_auth_still_charges_intrinsic` `[7702]` `[intrinsic]` — Invalid auth still pays the intrinsic base in the replaced calc.
- [ ] `invalid_nonce_auth_still_charges_intrinsic` `[7702]` `[intrinsic]` — Same for nonce mismatch.
- [ ] `many_authorizations` `[7702]` `[intrinsic]` — Surcharge accumulation over ten auths.
- [ ] `mixed_auths_header_gas_used` `[7702]` `[billing]` — Mixed new/existing auths vs header accounting.
- [ ] `mixed_new_and_existing_auths` `[7702]` — New-vs-existing distinction in the surcharge.
- [ ] `mixed_valid_and_invalid_auths` `[7702]` — Valid/invalid mix under Tempo's per-auth charging.
- [ ] `same_authority_increasing_nonce_net_once` `[7702]` — Once-per-authority invariant in Tempo's application order.
- [ ] `same_tx_clear_then_reset_pre_delegated` `[7702]` — Clear-then-reset on a pre-delegated authority; bytecode state gas is zeroed in Tempo.
- [ ] `same_tx_create_then_clear` `[7702]` — Create-then-clear in one tx; refund/charge netting.
- [ ] `self_sponsored_authorization` `[7702]` `[billing]` — Sender-is-authority; Tempo separately rejects self-sponsored *fee payers*, adjacent validation.
- [ ] `set_code_tx_below_total_intrinsic` `[7702]` `[intrinsic]` — Rejection boundary of the replaced intrinsic calc for set-code txs.

## state_gas_sstore (18 of 18)

Every boundary-crossing SSTORE runs Tempo's T7+ opcode override; the `tip1016` flag inside `sstore_storage_credits` is the single switch deciding state gas vs execution gas, and all restoration refunds route through TIP-1060 credits (execution-side, uncapped) instead of the fixture's reservoir-refill model.

- [ ] `sstore_clear_refund_reversal` `[sstore-credits]` `[refund]` — Clear-then-unclear refund reversal in the credit path.
- [ ] `sstore_multiple_slots` `[sstore-credits]` — Per-slot 245k accumulation through the override.
- [ ] `sstore_nonzero_to_nonzero` `[sstore-credits]` — Non-boundary write must bypass the credit logic entirely.
- [ ] `sstore_nonzero_to_zero` `[sstore-credits]` `[refund]` — Clearing mints a credit/refund on Tempo; fixture expects plain no-charge.
- [ ] `sstore_restoration_ancestor_revert` `[sstore-credits]` — Restoration credit must not inflate the caller's reservoir on ancestor revert.
- [ ] `sstore_restoration_charge_in_ancestor` `[sstore-credits]` — 0→x→0 split across frames: credit routing vs fixture's refill model.
- [ ] `sstore_restoration_charge_in_ancestor_intermediate_revert` `[sstore-credits]` — Deferred refund across an intermediate revert.
- [ ] `sstore_restoration_create_init_revert` `[sstore-credits]` — Restoration inside reverting CREATE init.
- [ ] `sstore_restoration_create_init_success` `[sstore-credits]` — Restoration across successful CREATE init.
- [ ] `sstore_restoration_nonzero_no_state_refund` `[sstore-credits]` — y→z→y must produce no state refund and no credit.
- [ ] `sstore_restoration_refund` `[sstore-credits]` `[refund]` — Core 0→x→0 refund; Tempo settles it as an uncapped execution refund at end of tx.
- [ ] `sstore_restoration_refund_credits_local_reservoir` `[sstore-credits]` — Fixture asserts the refund credits the *local reservoir*; Tempo's credit path never refills the reservoir.
- [ ] `sstore_restoration_sub_frame_revert` `[sstore-credits]` — Sub-frame revert must not leak the credit.
- [ ] `sstore_state_gas_all_tx_types` `[sstore-credits]` `[intrinsic]` — Same SSTORE across tx types; Tempo adds AA/custom tx types with their own intrinsic paths.
- [ ] `sstore_state_gas_drawn_from_reservoir` `[sstore-credits]` — Reservoir-first sourcing inside the override.
- [ ] `sstore_stipend_check_excludes_reservoir` `[sstore-credits]` — The 2300-stipend check in the overridden opcode must use `gas_left` only.
- [ ] `sstore_zero_to_nonzero` `[sstore-credits]` — Baseline creation charge through the override.
- [ ] `sstore_zero_to_zero` `[sstore-credits]` — No boundary crossing → credit logic must not fire.
