//! Which pending transactions a set of state changes may have made unexecutable.
//!
//! Pool maintenance feeds [`Invalidations`] a committed chain segment and checks the whole pool;
//! the payload builder's [`StateAwareBestTransactions`](crate::StateAwareBestTransactions) feeds
//! it each transaction it executes, seeded with the blocks maintenance has not processed yet, and
//! checks every candidate. Both ask [`Invalidations::verdict`], which reads no state: it compares
//! what the changes wrote with the [`Preconditions`](crate::Preconditions) validation recorded on
//! each transaction. The callers differ only in how they check fee AMM liquidity, which depends
//! on the block's validator token, and in what they do with the answer.

use crate::{TempoPoolUpdates, preconditions::Condition, transaction::TempoPooledTransaction};
use alloy_consensus::Transaction;
use alloy_primitives::{
    Address, B256, U256,
    map::{AddressMap, AddressSet, HashMap, U256Map},
};
use evm2::evm::{AccountChangeRef, AccountInfo, StateChangeSink, StateChangeSource, StorageChange};
use parking_lot::Mutex;
use reth_evm::BlockTransactionResult;
use reth_provider::Chain;
use reth_transaction_pool::PoolTransaction;
use std::{collections::VecDeque, sync::Arc};
use tempo_evm::TempoEvmTypes;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::amm::Pool};
use tempo_primitives::TempoPrimitives;

/// What a block, a chain segment or the transactions executed so far changed that pending
/// transactions may depend on.
#[derive(Debug, Default)]
pub struct Invalidations {
    /// Invalidation events the changes emitted. Only committed chain segments collect them.
    pub events: TempoPoolUpdates,
    /// Current value of every storage slot the changes wrote.
    pub(crate) slots: HashMap<(Address, U256), U256>,
    /// Accounts whose code or configuration commitment (TIP-1112) changed.
    pub(crate) changed_accounts: AddressSet,
    /// Current protocol nonce of every account whose nonce changed.
    pub(crate) nonces: AddressMap<u64>,
    /// Fee manager slots whose decoded validator-token reserve decreased, with their current
    /// value. Slots that are not pools may appear.
    pub(crate) decreased_reserves: U256Map<U256>,
}

impl From<TempoPoolUpdates> for Invalidations {
    fn from(events: TempoPoolUpdates) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
}

impl Invalidations {
    /// Collects the events and state changes of a committed chain segment.
    pub fn from_chain(chain: &Chain<TempoPrimitives>) -> Self {
        let mut this = Self::from(TempoPoolUpdates::from_chain(chain));
        for (&address, account) in chain.execution_outcome().state().state() {
            this.record_account(
                address,
                account.original_info.as_ref(),
                account.info.as_ref(),
            );
            for (&slot, value) in &account.storage {
                this.record_storage(address, slot, value.original_value(), value.present_value);
            }
        }
        this
    }

    /// Collects the state changes of a transaction the payload builder executed.
    pub fn on_transaction_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        result.result().pending_state.visit(&mut *self).unwrap();
    }

    /// Adds the state changes of `later`, which come after these.
    pub fn extend(&mut self, later: &Self) {
        self.slots
            .extend(later.slots.iter().map(|(&key, &value)| (key, value)));
        self.changed_accounts
            .extend(later.changed_accounts.iter().copied());
        self.nonces
            .extend(later.nonces.iter().map(|(&key, &value)| (key, value)));
        for (&slot, &value) in &later.decreased_reserves {
            self.decreased_reserves.insert(slot, value);
        }
    }

    /// Returns whether a fee AMM reserve decreased or a validator changed its fee token.
    pub(crate) fn fee_liquidity_may_have_decreased(&self) -> bool {
        !self.decreased_reserves.is_empty() || !self.events.validator_token_changes.is_empty()
    }

    /// Returns whether `tx` may have become unexecutable through these changes.
    ///
    /// `has_fee_liquidity` answers whether the fee AMM can still swap a fee amount of a token.
    pub(crate) fn verdict(
        &self,
        tx: &TempoPooledTransaction,
        mut has_fee_liquidity: impl FnMut(&TempoPooledTransaction, Address, U256) -> bool,
    ) -> Verdict {
        // Another transaction can raise an account's protocol nonce only through an
        // authorization list (EIP-7702 or Tempo authorizations). 2D and expiring nonces live in
        // the nonce manager, whose lanes the preconditions cover.
        if !tx.is_aa_2d()
            && self
                .nonces
                .get(tx.sender_ref())
                .is_some_and(|&nonce| tx.nonce() < nonce)
        {
            return Verdict::StaleNonce;
        }

        // Account fields are not storage: validation checks the code and commitment of the
        // transaction's authorities.
        if !self.changed_accounts.is_empty() && tx.has_authority_in(&self.changed_accounts) {
            return Verdict::Revalidate(Reason::Account);
        }

        if !self.slots.is_empty()
            && let Some(preconditions) = tx.preconditions()
        {
            for precondition in preconditions.iter() {
                if let Some(&value) = self.slots.get(&(precondition.address, precondition.slot))
                    && !precondition.condition.holds(value)
                {
                    return match precondition.condition {
                        Condition::LaneAtMost(_) => Verdict::StaleNonce,
                        _ => Verdict::Revalidate(Reason::Precondition),
                    };
                }
            }
        }

        if !has_fee_liquidity(tx, tx.effective_fee_token(), tx.fee_token_cost()) {
            return Verdict::Invalid(Reason::FeeLiquidity);
        }

        Verdict::Valid
    }

    fn record_account(
        &mut self,
        address: Address,
        original: Option<&AccountInfo>,
        current: Option<&AccountInfo>,
    ) {
        // A missing account has the code and commitment of an empty one.
        let empty = AccountInfo::default();
        let original = original.unwrap_or(&empty);
        let current_or_empty = current.unwrap_or(&empty);
        if (original.extension.as_ref(), original.code_hash)
            != (
                current_or_empty.extension.as_ref(),
                current_or_empty.code_hash,
            )
        {
            self.changed_accounts.insert(address);
        }
        if let Some(current) = current
            && original.nonce != current.nonce
        {
            self.nonces.insert(address, current.nonce);
        }
    }

    pub(crate) fn record_storage(
        &mut self,
        address: Address,
        slot: U256,
        original: U256,
        current: U256,
    ) {
        if address == TIP_FEE_MANAGER_ADDRESS {
            if Pool::decode_from_slot(current).reserve_validator_token
                < Pool::decode_from_slot(original).reserve_validator_token
            {
                self.decreased_reserves.insert(slot, current);
            } else if let Some(value) = self.decreased_reserves.get_mut(&slot) {
                *value = current;
            }
        }
        self.slots.insert((address, slot), current);
    }
}

impl StateChangeSink for Invalidations {
    type Error = core::convert::Infallible;

    fn account(&mut self, change: AccountChangeRef<'_>) -> Result<(), Self::Error> {
        self.record_account(change.address, change.original, change.current);
        Ok(())
    }

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        self.record_storage(change.address, change.key, change.original, change.current);
        Ok(())
    }
}

/// Whether a pending transaction may still execute after some state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The changes did not affect it.
    Valid,
    /// It cannot execute.
    Invalid(Reason),
    /// It may not execute: validation must run again.
    Revalidate(Reason),
    /// The sender's nonce moved past it. Its descendants may still execute.
    StaleNonce,
}

/// What made a pending transaction invalid or in need of revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    /// A slot its pre-execution checks read changed so that their condition no longer holds.
    Precondition,
    /// The code or configuration commitment of one of its authorities changed.
    Account,
    /// The fee AMM cannot swap its fee into the validator token.
    FeeLiquidity,
}

impl Reason {
    /// Returns a short description, used in errors and logs.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Precondition => "state its pre-execution checks read changed",
            Self::Account => "an authority's code or configuration changed",
            Self::FeeLiquidity => "insufficient fee AMM liquidity",
        }
    }
}

/// The changes of the most recent committed blocks, published before pool maintenance processes
/// them.
///
/// The payload builder iterates a snapshot of the pool that maintenance may not have pruned yet:
/// it seeds its changes with every block between the last one maintenance processed and its
/// parent, so that transactions a parent block invalidated do not reach execution.
#[derive(Debug, Default)]
pub struct RecentBlocks(Mutex<VecDeque<RecentBlock>>);

#[derive(Debug)]
struct RecentBlock {
    tip: B256,
    parent: B256,
    changes: Arc<Invalidations>,
    maintained: bool,
}

impl RecentBlocks {
    /// How many chain segments to keep.
    const CAPACITY: usize = 16;

    /// Publishes the changes of a committed chain segment from the block after `parent` to `tip`.
    pub fn publish(&self, parent: B256, tip: B256, changes: Arc<Invalidations>) {
        let mut blocks = self.0.lock();
        if blocks.len() == Self::CAPACITY {
            blocks.pop_front();
        }
        blocks.push_back(RecentBlock {
            tip,
            parent,
            changes,
            maintained: false,
        });
    }

    /// Records that maintenance took out what the segment ending at `tip` invalidated.
    pub fn mark_maintained(&self, tip: B256) {
        if let Some(block) = self
            .0
            .lock()
            .iter_mut()
            .rev()
            .find(|block| block.tip == tip)
        {
            block.maintained = true;
        }
    }

    /// Returns the changes of the segments up to `parent` that maintenance has not processed,
    /// oldest first.
    pub fn unmaintained(&self, mut parent: B256) -> Vec<Arc<Invalidations>> {
        let blocks = self.0.lock();
        let mut changes = Vec::new();
        while let Some(block) = blocks.iter().rev().find(|block| block.tip == parent)
            && !block.maintained
        {
            changes.push(block.changes.clone());
            parent = block.parent;
        }
        changes.reverse();
        changes
    }
}
