//! Replay-only inspector that records each top-level call of a transaction.
//!
//! A top-level frame is one envelope call of an AA batch or the single call of a regular
//! transaction. Calls after a failed AA call are never entered and therefore not recorded.
//! Fee hooks run outside frames and are tracked separately by `fees`.

use super::{TxOutcome, transition};
use alloy_primitives::{B256, keccak256};
use reth_revm::{
    context::{ContextTr, JournalTr},
    db::TransitionState,
    handler::FrameResult,
    inspector::Inspector,
    interpreter::FrameInput,
    state::{AccountStatus, EvmState},
};
use std::{cell::RefCell, rc::Rc};

/// Evidence for one top-level call, relative to its frame entry.
#[derive(Debug, Default)]
pub(super) struct ObservedCall {
    pub(super) outcome: TxOutcome,
    pub(super) output_hash: B256,
    /// Net account and storage transitions made by this call, including its internal calls.
    pub(super) state: TransitionState,
}

#[derive(Debug, Default)]
pub(super) struct Recording {
    depth: usize,
    /// Journal state at entry of the current top-level frame.
    entry: Option<EvmState>,
    calls: Vec<ObservedCall>,
}

/// Records top-level frames into a shared buffer drained after each transaction.
#[derive(Debug, Clone, Default)]
pub(super) struct CallRecorder(pub(super) Rc<RefCell<Recording>>);

impl CallRecorder {
    /// Returns the calls recorded since the last call and resets the recorder.
    pub(super) fn take(&self) -> Vec<ObservedCall> {
        std::mem::take(&mut *self.0.borrow_mut()).calls
    }
}

impl<CTX: ContextTr<Journal: JournalTr<State = EvmState>>> Inspector<CTX> for CallRecorder {
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
    use alloy_primitives::{Address, U256};
    use reth_revm::state::{Account, AccountInfo, EvmStorageSlot, TransactionId};

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
        let recorder = CallRecorder::default();
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
        let outcomes: Vec<_> = recorder.take().iter().map(|call| call.outcome).collect();
        assert_eq!(outcomes, [TxOutcome::Success, TxOutcome::Revert]);
        assert!(recorder.take().is_empty());
    }
}
