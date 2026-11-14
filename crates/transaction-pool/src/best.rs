//! A state-aware iterator over the best transactions in the tempo pool.

use crate::transaction::TempoPooledTransaction;
use alloy_primitives::{Address, U256, map::HashMap};
use evm2::evm::{StateChangeSink, StateChangeSource, StorageChange};
use reth_evm::BlockTransactionResult;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_evm::TempoEvmTypes;
use tempo_precompiles::tip20::is_tip20_prefix;

pub type BestTransaction = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

struct DecreasedBalancesSink<'a>(&'a mut HashMap<(Address, U256), U256>);

impl StateChangeSink for DecreasedBalancesSink<'_> {
    type Error = core::convert::Infallible;

    fn storage(&mut self, change: StorageChange) -> Result<(), Self::Error> {
        if !is_tip20_prefix(change.address) {
            return Ok(());
        }

        if change.current < change.original {
            self.0.insert((change.address, change.key), change.current);
        } else if let Some(balance) = self.0.get_mut(&(change.address, change.key)) {
            *balance = change.current;
        }
        Ok(())
    }

    fn storage_read(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<(), Self::Error> {
        if is_tip20_prefix(address)
            && let Some(balance) = self.0.get_mut(&(address, key))
        {
            *balance = value;
        }
        Ok(())
    }
}

/// A [`BestTransactions`] wrapper that tracks execution state changes and skips
/// transactions that would fail due to state mutations from previously
/// included transactions.
pub struct StateAwareBestTransactions<I> {
    inner: I,
    /// Tracks decreased TIP20 balance slots: `(token_address, slot) -> new_balance`.
    /// Updated after each executed transaction. Used to check if a candidate
    /// transaction's fee payer can still cover its fee cost.
    decreased_balances: HashMap<(Address, U256), U256>,
    /// Ordered fallback fee tokens active for the block being built.
    fallback_fee_tokens: &'static [Address],
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    /// Wraps an existing [`BestTransactions`] iterator.
    ///
    /// `fallback_fee_tokens` lists the tokens execution may fall back to when no transaction
    /// field or fee-manager rule selects the fee token.
    pub fn new(inner: I, fallback_fee_tokens: &'static [Address]) -> Self {
        Self {
            inner,
            decreased_balances: HashMap::default(),
            fallback_fee_tokens,
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result<R: BlockTransactionResult<TempoEvmTypes>>(&mut self, result: &R) {
        result
            .result()
            .pending_state
            .visit(&mut DecreasedBalancesSink(&mut self.decreased_balances))
            .unwrap();
    }

    /// Returns whether execution may pay the fee with another fallback token.
    ///
    /// Untracked balances may have grown during the block, so they count as sufficient.
    fn may_use_other_fallback_token(
        &self,
        tx: &BestTransaction,
        (token, slot): (Address, U256),
        fee: U256,
    ) -> bool {
        tx.transaction.is_fallback_fee_token()
            && self.fallback_fee_tokens.iter().any(|&candidate| {
                // TIP-20 balance slots share a layout.
                candidate != token
                    && self
                        .decreased_balances
                        .get(&(candidate, slot))
                        .is_none_or(|&balance| balance >= fee)
            })
    }
}

impl<I> Iterator for StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tx = self.inner.next()?;
            let best_tx = tx.best_transaction();

            let Some(key) = best_tx.transaction.fee_balance_slot() else {
                debug_assert!(false, "pool transaction must have cached fee_balance_slot");
                continue;
            };

            let fee = best_tx.transaction.fee_token_cost();
            if let Some(&balance) = self.decreased_balances.get(&key)
                && balance < fee
                && !self.may_use_other_fallback_token(best_tx, key, fee)
            {
                self.inner.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::InsufficientFunds((balance, fee).into()),
                    ),
                );
                continue;
            }

            return Some(tx);
        }
    }
}

impl<I> BestTransactions for StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        self.inner.mark_invalid(transaction, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

/// [`StateAwareBestTransactions`] iterator item.
pub trait StateAwarePoolTransaction {
    fn best_transaction(&self) -> &BestTransaction;
}

impl StateAwarePoolTransaction for BestTransaction {
    fn best_transaction(&self) -> &BestTransaction {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{TxBuilder, wrap_valid_tx},
        tt_2d_pool::AA2dPool,
    };
    use reth_transaction_pool::TransactionOrigin;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_evm::ResolvedFeeToken;

    /// Returns whether a transaction survives when `drained` balances drop just below its fee.
    fn state_aware_yields(
        tx: BestTransaction,
        fallback_fee_tokens: &'static [Address],
        drained: &[Address],
    ) -> bool {
        let (_, slot) = tx.transaction.fee_balance_slot().unwrap();
        let fee = tx.transaction.fee_token_cost();
        assert!(!fee.is_zero());
        let mut pool = AA2dPool::default();
        pool.add_transaction(tx, 0, TempoHardfork::T1).unwrap();
        let mut best =
            StateAwareBestTransactions::new(pool.best_transactions(), fallback_fee_tokens);
        for &token in drained {
            best.decreased_balances
                .insert((token, slot), fee - U256::ONE);
        }
        best.next().is_some()
    }

    #[test]
    fn test_state_aware_skips_only_when_no_fallback_token_can_pay() {
        let t13 = TempoHardfork::T13.fallback_fee_tokens();
        let &[path_usd, ousd] = t13 else {
            panic!("T13 falls back to pathUSD, then OUSD");
        };
        let tx = |resolved| {
            let tx = Arc::new(wrap_valid_tx(
                TxBuilder::aa(Address::random()).build(),
                TransactionOrigin::External,
            ));
            tx.transaction.set_resolved_fee_token(resolved);
            tx
        };
        let fallback = || tx(ResolvedFeeToken::Fallback(path_usd));
        // An explicit token, stored preference, or TIP-20 inference never falls back.
        let selected = || tx(ResolvedFeeToken::Selected(path_usd));

        assert!(state_aware_yields(fallback(), t13, &[path_usd]));
        assert!(!state_aware_yields(fallback(), t13, &[path_usd, ousd]));
        assert!(!state_aware_yields(selected(), t13, &[path_usd]));
        assert!(!state_aware_yields(
            fallback(),
            TempoHardfork::T12.fallback_fee_tokens(),
            &[path_usd]
        ));
    }
}
