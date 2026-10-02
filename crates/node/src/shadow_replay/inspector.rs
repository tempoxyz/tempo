//! Replay-only observation of execution, never installed on production EVMs.
//!
//! Observes through two seams: revm's `Inspector` for top-level frames, and a pass-through
//! `ProtocolFeeManager` for fee hooks, which run outside frames. Neither changes execution.
//!
//! A top-level frame is one envelope call of an AA batch or the single call of a regular
//! transaction; calls after a failed AA call are never entered and so not recorded. Fee hooks'
//! storage writes and logs are recorded; application writes may touch the same slots, and fee
//! paths outside these hooks are not tracked.

use super::{TxOutcome, transition};
use alloy_primitives::{Address, B256, Selector, U256, keccak256};
use reth_revm::{
    context::{ContextTr, JournalTr},
    db::TransitionState,
    handler::FrameResult,
    inspector::Inspector,
    interpreter::{CallInputs, CallOutcome, FrameInput},
    state::{AccountStatus, EvmState},
};
use std::{cell::RefCell, collections::HashSet, ops::Range, rc::Rc};
use tempo_precompiles::{
    storage::{StorageAction, StorageActions},
    tip_fee_manager::amm::{Pool, compute_amount_out},
};
use tempo_revm::{ProtocolFeeContext, ProtocolFeeManager, TempoFeeManager};

/// Per-transaction capture shared by the replay inspector and the fee manager.
#[derive(Debug, Default)]
pub(super) struct Recorded {
    pub(super) fee: FeeWrites,
    pub(super) calls: Vec<ObservedCall>,
    /// Current frame depth, journal state at entry of the current top-level frame, and the calls
    /// it has invoked so far.
    depth: usize,
    entry: Option<EvmState>,
    invocations: Vec<Invocation>,
}

/// Installed as both inspector and fee manager on each replay EVM; drained after every boundary.
#[derive(Debug, Clone, Default)]
pub(super) struct ReplayInspector(Rc<RefCell<Recorded>>);

impl ReplayInspector {
    /// Returns everything recorded since the last call and resets the recorder.
    pub(super) fn take(&self) -> Recorded {
        std::mem::take(&mut *self.0.borrow_mut())
    }

    /// Runs one fee hook with an isolated recorder and returns its ordered storage writes.
    fn record<DB: alloy_evm::Database, R>(
        &self,
        ctx: ProtocolFeeContext<'_, DB>,
        collect: impl FnOnce(ProtocolFeeContext<'_, DB>) -> R,
    ) -> (R, Vec<StorageAction>) {
        let ProtocolFeeContext {
            journal,
            block_env,
            cfg,
            tx_env,
            ..
        } = ctx;
        let before = journal.logs().len();
        let actions = StorageActions::enabled();
        let result = collect(ProtocolFeeContext {
            journal: &mut *journal,
            block_env,
            cfg,
            tx_env,
            actions: actions.clone(),
        });
        let writes = self.consolidate(
            actions.take().unwrap_or_default(),
            before..journal.logs().len(),
        );
        (result, writes)
    }

    /// Keeps writes in their original order and records all fee-hook slot provenance.
    fn consolidate(
        &self,
        mut actions: Vec<StorageAction>,
        range: Range<usize>,
    ) -> Vec<StorageAction> {
        let mut recorded = self.0.borrow_mut();
        let writes = &mut recorded.fee;
        actions.retain(|action| {
            let Some((slot, ..)) = storage_write(action) else {
                return false;
            };
            writes.slots.insert((action.address(), slot));
            true
        });
        if !range.is_empty() {
            writes.log_ranges.push(range);
        }
        actions
    }
}

/// Storage slots and log ranges produced by protocol fee hooks during one transaction.
#[derive(Debug, Default)]
pub(super) struct FeeWrites {
    pub(super) slots: HashSet<(Address, U256)>,
    pub(super) log_ranges: Vec<Range<usize>>,
    /// Successful pre-fee charge limit, used to validate the post-fee refund.
    pub(super) pre_tx_max: Option<U256>,
    /// Ordered post-fee actions; the first write's old value is the application's final value.
    pub(super) post_tx_actions: Vec<StorageAction>,
    /// Log index, token, payer, actual charge, and refund of the successful post-fee hook.
    pub(super) post_tx_transfer: Option<(usize, Address, Address, U256, U256)>,
}

/// Slot, entry value, and exit value of a storage-mutating action. `after` is `None` when it
/// can't be computed (overflow or a failed swap); reads and checks return `None`.
fn storage_write(action: &StorageAction) -> Option<(U256, U256, Option<U256>)> {
    Some(match *action {
        StorageAction::Sload(..) | StorageAction::FeeAmmLiquidityCheck(..) => return None,
        StorageAction::Sstore(_, slot, before, after) => (slot, before, Some(after)),
        StorageAction::Sinc(_, slot, before, delta) => (slot, before, before.checked_add(delta)),
        StorageAction::Sdec(_, slot, before, delta) => (slot, before, before.checked_sub(delta)),
        StorageAction::FeeAmmSwap(slot, before, amount_in) => {
            let mut pool = Pool::decode_from_slot(before);
            let after = compute_amount_out(amount_in).ok().and_then(|out| {
                pool.apply_swap(amount_in, out).ok()?;
                pool.encode_to_slot().ok()
            });
            (slot, before, after)
        }
    })
}

/// Derives a slot's entry and exit values from ordered writes within the post-fee hook.
/// Rejects discontinuous writes rather than attributing them to fees.
pub(super) fn post_fee_slot_change(
    actions: &[StorageAction],
    address: Address,
    slot: U256,
) -> Option<(U256, U256)> {
    let mut change: Option<(U256, U256)> = None;
    for action in actions {
        let Some((key, before, after)) = storage_write(action) else {
            continue;
        };
        if action.address() != address || key != slot {
            continue;
        }
        let after = after?;
        let initial = match change {
            Some((initial, current)) if current == before => initial,
            Some(_) => return None,
            None => before,
        };
        change = Some((initial, after));
    }
    change
}

impl<DB: alloy_evm::Database> ProtocolFeeManager<DB> for ReplayInspector {
    fn collect_fee_pre_tx(
        &self,
        ctx: ProtocolFeeContext<'_, DB>,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
        skip_liquidity_check: bool,
    ) -> tempo_precompiles::error::Result<Address> {
        let (result, _) = self.record(ctx, |ctx| {
            TempoFeeManager::new().collect_fee_pre_tx(
                ctx,
                fee_payer,
                user_token,
                max_amount,
                beneficiary,
                skip_liquidity_check,
            )
        });
        if result.is_ok() {
            self.0.borrow_mut().fee.pre_tx_max = Some(max_amount);
        }
        result
    }

    fn collect_fee_post_tx(
        &self,
        ctx: ProtocolFeeContext<'_, DB>,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> tempo_precompiles::error::Result<U256> {
        let log_index = ctx.journal.logs().len();
        let (result, actions) = self.record(ctx, |ctx| {
            TempoFeeManager::new().collect_fee_post_tx(
                ctx,
                fee_payer,
                actual_spending,
                refund_amount,
                fee_token,
                beneficiary,
            )
        });
        if result.is_ok() {
            let writes = &mut self.0.borrow_mut().fee;
            writes.post_tx_actions = actions;
            writes.post_tx_transfer = Some((
                log_index,
                fee_token,
                fee_payer,
                actual_spending,
                refund_amount,
            ));
        }
        result
    }
}

/// Evidence for one top-level call, relative to its frame entry.
#[derive(Debug, Default)]
pub(super) struct ObservedCall {
    pub(super) outcome: TxOutcome,
    pub(super) output_hash: B256,
    /// Net account and storage transitions made by this call, including its internal calls.
    pub(super) state: TransitionState,
    /// Every message call made within this call at any depth, including the call itself.
    pub(super) invocations: Vec<Invocation>,
}

impl ObservedCall {
    /// Whether this call changed any storage slot of `address`.
    pub(super) fn changed_storage(&self, address: Address) -> bool {
        self.state
            .transitions
            .get(&address)
            .is_some_and(|account| account.storage.values().any(|slot| slot.is_changed()))
    }
}

/// Target and selector of one message call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Invocation {
    pub(super) to: Address,
    pub(super) selector: Option<Selector>,
}

/// Records top-level frames and the message calls made within them.
impl<CTX: ContextTr<Journal: JournalTr<State = EvmState>>> Inspector<CTX> for ReplayInspector {
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let selector = inputs
            .input
            .as_bytes(context)
            .first_chunk::<4>()
            .map(Selector::from);
        self.0.borrow_mut().invocations.push(Invocation {
            to: inputs.target_address,
            selector,
        });
        None
    }

    fn frame_start(&mut self, context: &mut CTX, _: &mut FrameInput) -> Option<FrameResult> {
        let mut recording = self.0.borrow_mut();
        if recording.depth == 0 {
            recording.entry = Some(context.journal_ref().evm_state().clone());
        }
        recording.depth += 1;
        None
    }

    fn frame_end(&mut self, context: &mut CTX, _: &FrameInput, result: &mut FrameResult) {
        let mut recording = self.0.borrow_mut();
        recording.depth = recording.depth.saturating_sub(1);
        if recording.depth != 0 {
            return;
        }
        let Some(entry) = recording.entry.take() else {
            return;
        };
        let instruction = result.instruction_result();
        let invocations = std::mem::take(&mut recording.invocations);
        recording.calls.push(ObservedCall {
            outcome: if instruction.is_ok() {
                TxOutcome::Success
            } else if instruction.is_revert() {
                TxOutcome::Revert
            } else {
                TxOutcome::Halt
            },
            output_hash: keccak256(result.output().data()),
            state: frame_transition(&entry, context.journal_ref().evm_state()),
            invocations,
        });
    }
}

/// Net transitions from `entry` to `exit` in the existing `TransitionState` shape.
fn frame_transition(entry: &EvmState, exit: &EvmState) -> TransitionState {
    let state = exit
        .iter()
        .filter_map(|(&address, account)| {
            let mut account = account.clone();
            if let Some(before) = entry.get(&address) {
                *account.original_info_mut() = before.info.clone();
                for (slot, value) in &mut account.storage {
                    if let Some(before) = before.storage.get(slot) {
                        value.original_value = before.present_value;
                    }
                }
                if before.is_created() {
                    account.unmark_created();
                    account.status.remove(AccountStatus::LoadedAsNotExisting);
                }
                if before.is_selfdestructed() && account.is_selfdestructed() {
                    account.unmark_selfdestruct();
                }
            }
            (account.is_created()
                || account.is_selfdestructed()
                || account.info != account.original_info()
                || account.changed_storage_slots().next().is_some())
            .then_some((address, account))
        })
        .collect();
    transition(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_revm::state::{Account, AccountInfo, EvmStorageSlot, TransactionId};
    use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;

    fn account(balance: u64, slots: &[(u64, u64, u64)]) -> Account {
        let mut account = Account::from(AccountInfo {
            balance: U256::from(balance),
            ..Default::default()
        });
        for &(slot, original, present) in slots {
            account.storage.insert(
                U256::from(slot),
                EvmStorageSlot::new_changed(
                    U256::from(original),
                    U256::from(present),
                    TransactionId::ZERO,
                ),
            );
        }
        account.mark_touch();
        account
    }

    #[test]
    fn frame_transition_excludes_earlier_calls() {
        let (earlier, current, untouched) = (
            Address::repeat_byte(1),
            Address::repeat_byte(2),
            Address::repeat_byte(3),
        );
        // An earlier call changed `earlier` and slot 1 of `current`.
        let entry = EvmState::from_iter([
            (earlier, account(5, &[(1, 0, 7)])),
            (current, account(10, &[(1, 0, 3)])),
        ]);
        // This call changes slot 1 again, loads and writes slot 2, and changes a new account.
        let exit = EvmState::from_iter([
            (earlier, account(5, &[(1, 0, 7)])),
            (current, account(10, &[(1, 0, 4), (2, 8, 9)])),
            (untouched, account(1, &[])),
        ]);
        let mut new = Account::from(AccountInfo::default());
        new.info.balance = U256::from(2);
        new.mark_touch();
        let exit = exit
            .into_iter()
            .chain([(Address::repeat_byte(4), new)])
            .collect();

        let transitions = frame_transition(&entry, &exit).transitions;
        assert!(!transitions.contains_key(&earlier));
        assert!(!transitions.contains_key(&untouched));
        let storage = &transitions[&current].storage;
        assert_eq!(
            storage[&U256::from(1)].previous_or_original_value,
            U256::from(3)
        );
        assert_eq!(storage[&U256::from(1)].present_value, U256::from(4));
        assert_eq!(
            storage[&U256::from(2)].previous_or_original_value,
            U256::from(8)
        );
        assert_eq!(
            transitions[&Address::repeat_byte(4)]
                .info
                .as_ref()
                .unwrap()
                .balance,
            U256::from(2)
        );
    }

    #[test]
    fn recorder_keeps_only_top_level_frames() {
        let recorder = ReplayInspector::default();
        use reth_revm::MainContext as _;
        let mut ctx = reth_revm::Context::mainnet();
        let mut inspector = recorder.clone();
        let input = FrameInput::Empty;
        let frame = |result| {
            FrameResult::Call(reth_revm::interpreter::CallOutcome::new(
                reth_revm::interpreter::InterpreterResult::new(
                    result,
                    Default::default(),
                    reth_revm::interpreter::Gas::new(0),
                ),
                0..0,
            ))
        };
        use reth_revm::interpreter::InstructionResult::*;
        for top in [Stop, Revert] {
            inspector.frame_start(&mut ctx, &mut FrameInput::Empty);
            inspector.frame_start(&mut ctx, &mut FrameInput::Empty);
            inspector.frame_end(&mut ctx, &input, &mut frame(OutOfGas));
            inspector.frame_end(&mut ctx, &input, &mut frame(top));
        }
        let outcomes: Vec<_> = recorder
            .take()
            .calls
            .iter()
            .map(|call| call.outcome)
            .collect();
        assert_eq!(outcomes, [TxOutcome::Success, TxOutcome::Revert]);
        assert!(recorder.take().calls.is_empty());
    }

    #[test]
    fn post_fee_writes_require_continuity() {
        let address = Address::repeat_byte(1);
        let slot = U256::from(2);
        let actions = [
            StorageAction::Sinc(address, slot, U256::from(10), U256::from(5)),
            StorageAction::Sdec(address, slot, U256::from(15), U256::from(2)),
        ];
        assert_eq!(
            post_fee_slot_change(&actions, address, slot),
            Some((U256::from(10), U256::from(13)))
        );
        assert_eq!(post_fee_slot_change(&actions, address, U256::from(3)), None);
        let bad = [
            actions[0],
            StorageAction::Sdec(address, slot, U256::from(14), U256::from(2)),
        ];
        assert_eq!(post_fee_slot_change(&bad, address, slot), None);
    }

    #[test]
    fn post_fee_swap_uses_the_packed_pool_transition() {
        let pool = Pool {
            reserve_user_token: 100,
            reserve_validator_token: 200,
        };
        let old = pool.encode_to_slot().unwrap();
        let slot = U256::from(2);
        let amount = U256::from(10);
        let mut expected = pool;
        expected
            .apply_swap(amount, compute_amount_out(amount).unwrap())
            .unwrap();
        assert_eq!(
            post_fee_slot_change(
                &[StorageAction::FeeAmmSwap(slot, old, amount)],
                TIP_FEE_MANAGER_ADDRESS,
                slot,
            ),
            Some((old, expected.encode_to_slot().unwrap()))
        );
    }
}
