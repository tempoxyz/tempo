//! Tracks storage slots written by protocol fee hooks within each transaction.
//!
//! Normal fee-manager behavior is preserved. Application writes may touch the same slots,
//! and fee paths outside these hooks are not tracked.

use alloy_primitives::{Address, U256};
use reth_revm::context::JournalTr as _;
use std::{cell::RefCell, collections::HashSet, ops::Range, rc::Rc};
use tempo_precompiles::{
    storage::{StorageAction, StorageActions},
    tip_fee_manager::amm::{Pool, compute_amount_out},
};
use tempo_revm::{ProtocolFeeContext, ProtocolFeeManager, TempoFeeManager};

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

/// Delegates protocol fee collection while recording hook-local storage writes and emitted logs.
#[derive(Debug, Clone)]
pub(super) struct RecordingFeeManager(pub(super) Rc<RefCell<FeeWrites>>);

impl RecordingFeeManager {
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
        let mut writes = self.0.borrow_mut();
        actions.retain(|action| {
            let slot = match action {
                StorageAction::Sstore(_, key, ..)
                | StorageAction::Sinc(_, key, ..)
                | StorageAction::Sdec(_, key, ..)
                | StorageAction::FeeAmmSwap(key, ..) => key,
                StorageAction::Sload(..) | StorageAction::FeeAmmLiquidityCheck(..) => return false,
            };
            writes.slots.insert((action.address(), *slot));
            true
        });
        if !range.is_empty() {
            writes.log_ranges.push(range);
        }
        actions
    }
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
        let key = match action {
            StorageAction::Sstore(_, key, ..)
            | StorageAction::Sinc(_, key, ..)
            | StorageAction::Sdec(_, key, ..)
            | StorageAction::FeeAmmSwap(key, ..) => *key,
            StorageAction::Sload(..) | StorageAction::FeeAmmLiquidityCheck(..) => continue,
        };
        if action.address() != address || key != slot {
            continue;
        }
        let (before, after) = match *action {
            StorageAction::Sstore(_, _, before, after) => (before, after),
            StorageAction::Sinc(_, _, before, delta) => (before, before.checked_add(delta)?),
            StorageAction::Sdec(_, _, before, delta) => (before, before.checked_sub(delta)?),
            StorageAction::FeeAmmSwap(_, before, amount_in) => {
                let mut pool = Pool::decode_from_slot(before);
                pool.apply_swap(amount_in, compute_amount_out(amount_in).ok()?)
                    .ok()?;
                (before, pool.encode_to_slot().ok()?)
            }
            StorageAction::Sload(..) | StorageAction::FeeAmmLiquidityCheck(..) => continue,
        };
        let initial = match change {
            Some((initial, current)) if current == before => initial,
            Some(_) => return None,
            None => before,
        };
        change = Some((initial, after));
    }
    change
}

impl<DB: alloy_evm::Database> ProtocolFeeManager<DB> for RecordingFeeManager {
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
            self.0.borrow_mut().pre_tx_max = Some(max_amount);
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
            let mut writes = self.0.borrow_mut();
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_contracts::precompiles::TIP_FEE_MANAGER_ADDRESS;

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
