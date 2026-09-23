//! Tracks storage slots written by protocol fee hooks within each transaction.
//!
//! Normal fee-manager behavior is preserved. Application writes may touch the same slots,
//! and fee paths outside these hooks are not tracked.

use alloy_primitives::{Address, U256};
use reth_revm::context::JournalTr as _;
use std::{cell::RefCell, collections::HashSet, ops::Range, rc::Rc};
use tempo_precompiles::storage::{StorageAction, StorageActions};
use tempo_revm::{ProtocolFeeContext, ProtocolFeeManager, TempoFeeManager};

/// Storage slots and log ranges produced by protocol fee hooks during one transaction.
#[derive(Debug, Default)]
pub(super) struct FeeWrites {
    pub(super) slots: HashSet<(Address, U256)>,
    pub(super) log_ranges: Vec<Range<usize>>,
    /// Index and inputs of the post-transaction fee transfer, when the hook succeeded.
    pub(super) post_tx_transfer: Option<(usize, Address, Address, U256)>,
}

/// Delegates protocol fee collection while recording hook-local storage writes and emitted logs.
#[derive(Debug, Clone)]
pub(super) struct RecordingFeeManager(pub(super) Rc<RefCell<FeeWrites>>);

impl RecordingFeeManager {
    /// Runs one fee hook with an isolated recorder and retains its storage and log provenance.
    fn record<DB: alloy_evm::Database, R>(
        &self,
        ctx: ProtocolFeeContext<'_, DB>,
        collect: impl FnOnce(ProtocolFeeContext<'_, DB>) -> R,
    ) -> R {
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
        self.consolidate(actions, before..journal.logs().len());
        result
    }

    /// Reduces raw storage actions to the slot provenance retained by replay evidence.
    fn consolidate(&self, actions: StorageActions, range: Range<usize>) {
        let mut writes = self.0.borrow_mut();
        for action in actions.take().unwrap_or_default() {
            let slot = match action {
                StorageAction::Sstore(_, key, ..)
                | StorageAction::Sinc(_, key, ..)
                | StorageAction::Sdec(_, key, ..)
                | StorageAction::FeeAmmSwap(key, ..) => Some(key),
                StorageAction::Sload(..) | StorageAction::FeeAmmLiquidityCheck(..) => None,
            };
            if let Some(slot) = slot {
                writes.slots.insert((action.address(), slot));
            }
        }
        if !range.is_empty() {
            writes.log_ranges.push(range);
        }
    }
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
        self.record(ctx, |ctx| {
            TempoFeeManager::new().collect_fee_pre_tx(
                ctx,
                fee_payer,
                user_token,
                max_amount,
                beneficiary,
                skip_liquidity_check,
            )
        })
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
        let result = self.record(ctx, |ctx| {
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
            self.0.borrow_mut().post_tx_transfer =
                Some((log_index, fee_token, fee_payer, actual_spending));
        }
        result
    }
}
