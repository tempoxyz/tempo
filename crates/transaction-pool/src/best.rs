//! An iterator over the best transactions in the tempo pool.

use crate::{
    ordering::TempoTipOrdering,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    tt_2d_pool::BestAA2dTransactions,
};
use alloy_primitives::{Address, U256, map::HashMap};
use reth_evm::block::TxResult;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, Priority, TransactionOrdering, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tempo_precompiles::tip20::is_tip20_prefix;

pub type BestTransaction = Arc<ValidPoolTransaction<TempoPooledTransaction>>;
type BestTransactionWithPriority = (BestTransaction, Priority<u64>);

/// A best-transaction iterator that merges the protocol pool and the 2D nonces pool,
/// always yielding the next best item from either iterator.
pub struct MergeBestTransactions {
    protocol_pool: Box<dyn BestTransactions<Item = BestTransaction>>,
    aa_2d_pool: BestAA2dTransactions,
    next_protocol_pool: Option<BestTransactionWithPriority>,
    next_aa_2d_pool: Option<BestTransactionWithPriority>,
    base_fee: u64,
    general_gas_limit: Option<GeneralGasLimit>,
}

impl MergeBestTransactions {
    /// Creates a new iterator over the given iterators.
    pub(crate) fn new(
        protocol_pool: Box<dyn BestTransactions<Item = BestTransaction>>,
        aa_2d_pool: BestAA2dTransactions,
        base_fee: u64,
    ) -> Self {
        Self {
            protocol_pool,
            aa_2d_pool,
            next_protocol_pool: None,
            next_aa_2d_pool: None,
            base_fee,
            general_gas_limit: None,
        }
    }
}

impl MergeBestTransactions {
    /// Returns the next transaction from either pool with the higher priority.
    fn next_best(&mut self) -> Option<BestTransactionWithPriority> {
        if self.next_protocol_pool.is_none() {
            self.next_protocol_pool = self.protocol_pool.next().map(|tx| {
                let priority = TempoTipOrdering::default().priority(&tx.transaction, self.base_fee);
                (tx, priority)
            });
        }
        if self.next_aa_2d_pool.is_none() {
            self.next_aa_2d_pool = self.aa_2d_pool.next_tx_and_priority();
        }

        match (&mut self.next_protocol_pool, &mut self.next_aa_2d_pool) {
            (None, None) => {
                // both iters are done
                None
            }
            // Only the protocol pool has an item - take it
            (Some(_), None) => {
                let (item, priority) = self.next_protocol_pool.take()?;
                Some((item, priority))
            }
            // Only the AA2D pool has an item - take it
            (None, Some(_)) => {
                let (item, priority) = self.next_aa_2d_pool.take()?;
                Some((item, priority))
            }
            // Both pools have items - compare priorities and take the higher one
            (Some((_, protocol_priority)), Some((_, aa_2d_priority))) => {
                // Higher priority value is better
                if protocol_priority >= aa_2d_priority {
                    let (item, priority) = self.next_protocol_pool.take()?;
                    Some((item, priority))
                } else {
                    let (item, priority) = self.next_aa_2d_pool.take()?;
                    Some((item, priority))
                }
            }
        }
    }
}

impl Iterator for MergeBestTransactions {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (tx, _) = self.next_best()?;
            if self
                .general_gas_limit
                .as_ref()
                .is_some_and(|limit| !limit.fits(&tx))
            {
                self.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::Other(Box::new(
                        TempoPoolTransactionError::ExceedsNonPaymentLimit,
                    )),
                );
                continue;
            }
            return Some(tx);
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let buffered = usize::from(self.next_protocol_pool.is_some())
            + usize::from(self.next_aa_2d_pool.is_some());
        let (protocol_lower, protocol_upper) = self.protocol_pool.size_hint();
        let (aa_2d_lower, aa_2d_upper) = self.aa_2d_pool.size_hint();

        (
            if self.general_gas_limit.is_some() {
                0
            } else {
                buffered
                    .saturating_add(protocol_lower)
                    .saturating_add(aa_2d_lower)
            },
            protocol_upper
                .zip(aa_2d_upper)
                .and_then(|(protocol_upper, aa_2d_upper)| protocol_upper.checked_add(aa_2d_upper))
                .and_then(|upper| upper.checked_add(buffered)),
        )
    }
}

impl BestTransactions for MergeBestTransactions {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        if transaction.transaction.is_aa_2d() {
            self.aa_2d_pool.mark_invalid(transaction, kind);
            if !transaction.transaction.is_expiring_nonce()
                && self.next_aa_2d_pool.as_ref().is_some_and(|(next, _)| {
                    next.transaction.aa_transaction_id().map(|id| id.seq_id)
                        == transaction
                            .transaction
                            .aa_transaction_id()
                            .map(|id| id.seq_id)
                })
            {
                self.next_aa_2d_pool = None;
            }
        } else {
            self.protocol_pool.mark_invalid(transaction, kind);
            if self.next_protocol_pool.as_ref().is_some_and(|(next, _)| {
                next.transaction.sender() == transaction.transaction.sender()
            }) {
                self.next_protocol_pool = None;
            }
        }
    }

    fn no_updates(&mut self) {
        self.protocol_pool.no_updates();
        self.aa_2d_pool.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.protocol_pool.set_skip_blobs(skip_blobs);
        self.aa_2d_pool.set_skip_blobs(skip_blobs);
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
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    /// Wraps an existing [`BestTransactions`] iterator.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            decreased_balances: HashMap::default(),
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result(&mut self, result: &impl TxResult) {
        for (&address, account) in &result.result().state {
            if !is_tip20_prefix(address) {
                continue;
            }

            for (&slot, storage_slot) in &account.storage {
                if storage_slot.present_value < storage_slot.original_value {
                    self.decreased_balances
                        .insert((address, slot), storage_slot.present_value);
                } else if let Some(balance) = self.decreased_balances.get_mut(&(address, slot)) {
                    *balance = storage_slot.present_value;
                }
            }
        }
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

            if let Some(&balance) = self.decreased_balances.get(&key)
                && balance < best_tx.transaction.fee_token_cost()
            {
                self.inner.mark_invalid(
                    &tx,
                    InvalidPoolTransactionError::Consensus(
                        InvalidTransactionError::InsufficientFunds(
                            (balance, best_tx.transaction.fee_token_cost()).into(),
                        ),
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
    I: BestTransactions + Send,
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

/// Tempo-specific controls for best-transaction iterators.
pub trait TempoBestTransactions: BestTransactions {
    /// Filter non-payments against a shared, decreasing general-lane gas budget.
    ///
    /// This affects this iterator only and does not remove transactions from the pool.
    /// The caller must use the T5 payment classification.
    fn set_general_gas_limit(&mut self, limit: GeneralGasLimit);
}

impl TempoBestTransactions for MergeBestTransactions {
    fn set_general_gas_limit(&mut self, limit: GeneralGasLimit) {
        self.general_gas_limit = Some(limit);
    }
}

impl<I> TempoBestTransactions for StateAwareBestTransactions<I>
where
    I: TempoBestTransactions,
    I::Item: StateAwarePoolTransaction,
{
    fn set_general_gas_limit(&mut self, limit: GeneralGasLimit) {
        self.inner.set_general_gas_limit(limit);
    }
}

impl<I: TempoBestTransactions + ?Sized> TempoBestTransactions for Box<I> {
    fn set_general_gas_limit(&mut self, limit: GeneralGasLimit) {
        (**self).set_general_gas_limit(limit);
    }
}

impl<T> TempoBestTransactions for std::iter::Empty<T> {
    fn set_general_gas_limit(&mut self, _limit: GeneralGasLimit) {}
}

/// General-lane admission budget shared by the builder, iterator, and prewarm workers.
#[derive(Clone, Debug)]
pub struct GeneralGasLimit {
    remaining: Arc<AtomicU64>,
    tx_gas_limit_cap: u64,
}

impl GeneralGasLimit {
    /// Creates a budget using the same transaction gas cap as the block executor.
    pub fn new(remaining: u64, tx_gas_limit_cap: u64) -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(remaining)),
            tx_gas_limit_cap,
        }
    }

    /// Returns the remaining general gas.
    pub fn remaining(&self) -> u64 {
        self.remaining.load(Ordering::Relaxed)
    }

    /// Decreases the budget after execution charges actual gas to the general lane.
    ///
    /// Increasing the budget cannot restore transactions already excluded from this iterator.
    pub fn set_remaining(&self, remaining: u64) {
        self.remaining.fetch_min(remaining, Ordering::Relaxed);
    }

    /// Returns the regular gas required for admission, not the gas eventually consumed.
    pub fn required_gas(&self, tx: &BestTransaction) -> u64 {
        tx.gas_limit().min(self.tx_gas_limit_cap)
    }

    /// Payments do not consume the general lane's budget.
    pub fn fits(&self, tx: &BestTransaction) -> bool {
        tx.transaction.is_payment() || self.required_gas(tx) <= self.remaining()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordering::TempoTipOrdering,
        test_utils::{TxBuilder, wrap_valid_tx},
        tt_2d_pool::AA2dPool,
    };
    use alloy_primitives::Address;
    use futures::executor::block_on;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_transaction_pool::{
        Pool, PoolConfig, TransactionOrigin, TransactionPool, blobstore::InMemoryBlobStore,
        test_utils::OkValidator,
    };
    use std::sync::Arc;
    use tempo_chainspec::{hardfork::TempoHardfork, spec::TEMPO_T1_BASE_FEE};
    use tempo_primitives::transaction::Call;

    type TestTx = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn tx_with_nonce_key(nonce_key: U256, sender: Address, nonce: u64, priority: u128) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .max_priority_fee(priority)
                .max_fee(u128::from(TEMPO_T1_BASE_FEE) + priority)
                .build(),
            TransactionOrigin::External,
        ))
    }

    fn protocol_tx(nonce: u64, priority: u128) -> TestTx {
        protocol_tx_for_sender(Address::random(), nonce, priority)
    }

    fn protocol_tx_for_sender(sender: Address, nonce: u64, priority: u128) -> TestTx {
        tx_with_nonce_key(U256::ZERO, sender, nonce, priority)
    }

    fn aa_2d_tx(nonce: u64, priority: u128) -> TestTx {
        aa_2d_tx_for_sequence(Address::random(), nonce, priority)
    }

    fn aa_2d_tx_for_sequence(sender: Address, nonce: u64, priority: u128) -> TestTx {
        tx_with_nonce_key(U256::from(1), sender, nonce, priority)
    }

    fn protocol_best_transactions(
        txs: Vec<TestTx>,
    ) -> Box<dyn BestTransactions<Item = BestTransaction>> {
        let pool = Pool::new(
            OkValidator::<TempoPooledTransaction>::default(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );

        let results = block_on(pool.add_transactions(
            TransactionOrigin::External,
            txs.into_iter().map(|tx| tx.transaction.clone()).collect(),
        ));
        assert!(
            results.iter().all(Result::is_ok),
            "all protocol transactions must be added successfully: {results:?}"
        );
        Box::new(pool.inner().best_transactions())
    }

    fn aa_2d_best_transactions(txs: Vec<TestTx>) -> BestAA2dTransactions {
        let mut pool = AA2dPool::default();
        let mut on_chain_nonces: HashMap<crate::tt_2d_pool::AASequenceId, u64> = HashMap::default();
        for tx in &txs {
            let id = tx
                .transaction
                .aa_transaction_id()
                .expect("AA2D transaction must have an AA transaction id");
            on_chain_nonces
                .entry(id.seq_id)
                .and_modify(|nonce: &mut u64| *nonce = (*nonce).min(id.nonce))
                .or_insert(id.nonce);
        }

        pool.set_base_fee(TEMPO_T1_BASE_FEE);
        for tx in txs {
            let id = tx
                .transaction
                .aa_transaction_id()
                .expect("AA2D transaction must have an AA transaction id");
            let on_chain_nonce = on_chain_nonces[&id.seq_id];
            pool.add_transaction(tx, on_chain_nonce, TempoHardfork::T1)
                .expect("AA2D transaction must be added successfully");
        }
        pool.best_transactions()
    }

    fn merged_best_transactions(
        protocol_txs: Vec<TestTx>,
        aa_2d_txs: Vec<TestTx>,
    ) -> MergeBestTransactions {
        MergeBestTransactions::new(
            protocol_best_transactions(protocol_txs),
            aa_2d_best_transactions(aa_2d_txs),
            TEMPO_T1_BASE_FEE,
        )
    }

    fn payment_tx(sender: Address, nonce_key: U256, nonce: u64, priority: u128) -> TestTx {
        let mut input = vec![0xa9, 0x05, 0x9c, 0xbb];
        input.resize(68, 0);
        let tx = TxBuilder::aa(sender)
            .nonce_key(nonce_key)
            .nonce(nonce)
            .max_priority_fee(priority)
            .max_fee(u128::from(TEMPO_T1_BASE_FEE) + priority)
            .calls(vec![Call {
                to: alloy_primitives::TxKind::Call(tempo_precompiles::PATH_USD_ADDRESS),
                value: U256::ZERO,
                input: input.into(),
            }])
            .build();
        assert!(tx.is_payment());
        Arc::new(wrap_valid_tx(tx, TransactionOrigin::External))
    }

    #[test]
    fn skip_non_payment_filters_both_pools_and_buffered_candidates() {
        for first_is_protocol in [false, true] {
            let protocol_general = protocol_tx(0, if first_is_protocol { 10 } else { 9 });
            let aa_general = aa_2d_tx(0, if first_is_protocol { 9 } else { 10 });
            let protocol_payment = payment_tx(Address::random(), U256::ZERO, 0, 2);
            let aa_payment = payment_tx(Address::random(), U256::ONE, 0, 1);
            let mut best = merged_best_transactions(
                vec![protocol_general, protocol_payment.clone()],
                vec![aa_general, aa_payment.clone()],
            );
            assert!(!best.next().unwrap().transaction.is_payment());
            best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
            best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
            assert_eq!(best.size_hint().0, 0);
            assert_eq!(
                best.map(|tx| *tx.hash()).collect::<Vec<_>>(),
                vec![*protocol_payment.hash(), *aa_payment.hash()],
            );
        }
    }

    #[test]
    fn skip_non_payment_excludes_dependent_payments_but_preserves_other_nonce_keys() {
        let sender = Address::random();
        let protocol_general = protocol_tx_for_sender(sender, 0, 10);
        let protocol_child = payment_tx(sender, U256::ZERO, 1, 9);
        let aa_general = aa_2d_tx_for_sequence(sender, 0, 8);
        let aa_child = payment_tx(sender, U256::ONE, 1, 7);
        let independent = payment_tx(sender, U256::from(2), 0, 6);
        let mut best = merged_best_transactions(
            vec![protocol_general, protocol_child],
            vec![aa_general, aa_child, independent.clone()],
        );
        best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
        assert_eq!(best.next().map(|tx| *tx.hash()), Some(*independent.hash()));
        assert!(best.next().is_none());
    }

    #[test]
    fn skip_non_payment_keeps_payments_after_an_included_general_transaction() {
        for nonce_key in [U256::ZERO, U256::ONE] {
            let sender = Address::random();
            let general = tx_with_nonce_key(nonce_key, sender, 0, 2);
            let payment = payment_tx(sender, nonce_key, 1, 1);
            let txs = vec![general.clone(), payment.clone()];
            let mut best = if nonce_key.is_zero() {
                merged_best_transactions(txs, vec![])
            } else {
                merged_best_transactions(vec![], txs)
            };
            assert_eq!(best.next().map(|tx| *tx.hash()), Some(*general.hash()));
            best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
            assert_eq!(best.next().map(|tx| *tx.hash()), Some(*payment.hash()));
            assert!(best.next().is_none());
        }
    }

    #[test]
    fn test_merge_best_transactions_basic() {
        // Create two mock iterators with different priorities
        // Left: priorities [10, 5, 3]
        // Right: priorities [8, 4, 1]
        // Expected order: [10, 8, 5, 4, 3, 1]
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let tx_c = protocol_tx(2, 3);
        let tx_d = aa_2d_tx(3, 8);
        let tx_e = aa_2d_tx(4, 4);
        let tx_f = aa_2d_tx(5, 1);
        let mut merged = merged_best_transactions(
            vec![tx_a.clone(), tx_b.clone(), tx_c.clone()],
            vec![tx_d.clone(), tx_e.clone(), tx_f.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash())); // priority 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_d.hash())); // priority 8
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash())); // priority 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_e.hash())); // priority 4
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_c.hash())); // priority 3
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_f.hash())); // priority 1
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_size_hint() {
        let protocol_sender = Address::random();
        let protocol_tx_0 = protocol_tx_for_sender(protocol_sender, 0, 10);
        let protocol_tx_1 = protocol_tx_for_sender(protocol_sender, 1, 9);
        let aa_2d_tx = aa_2d_tx(0, 8);
        let mut merged = merged_best_transactions(
            vec![protocol_tx_0.clone(), protocol_tx_1.clone()],
            vec![aa_2d_tx.clone()],
        );
        merged.no_updates();

        assert_eq!(merged.size_hint(), (0, Some(3)));

        assert_eq!(
            merged.next().map(|tx| *tx.hash()),
            Some(*protocol_tx_0.hash())
        );
        assert_eq!(merged.size_hint(), (1, Some(2)));

        assert_eq!(
            merged.next().map(|tx| *tx.hash()),
            Some(*protocol_tx_1.hash())
        );
        assert_eq!(merged.size_hint(), (1, Some(1)));

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*aa_2d_tx.hash()));
        assert_eq!(merged.size_hint(), (0, Some(0)));
    }

    #[test]
    fn test_merge_best_transactions_empty_left() {
        // Left iterator is empty
        let tx_a = aa_2d_tx(0, 10);
        let tx_b = aa_2d_tx(1, 5);
        let mut merged = merged_best_transactions(vec![], vec![tx_a.clone(), tx_b.clone()]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_empty_right() {
        // Right iterator is empty
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let mut merged = merged_best_transactions(vec![tx_a.clone(), tx_b.clone()], vec![]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_both_empty() {
        let mut merged = merged_best_transactions(vec![], vec![]);

        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_equal_priorities() {
        // When priorities are equal, left should be preferred (based on >= comparison)
        let tx_a = protocol_tx(0, 10);
        let tx_b = protocol_tx(1, 5);
        let tx_c = aa_2d_tx(2, 10);
        let tx_d = aa_2d_tx(3, 5);
        let mut merged = merged_best_transactions(
            vec![tx_a.clone(), tx_b.clone()],
            vec![tx_c.clone(), tx_d.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash())); // equal priority, left preferred
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_c.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_b.hash())); // equal priority, left preferred
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_d.hash()));
        assert!(merged.next().is_none());
    }

    // ============================================
    // Single item tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_single_left() {
        let tx_a = protocol_tx(0, 10);
        let mut merged = merged_best_transactions(vec![tx_a.clone()], vec![]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_merge_best_transactions_single_right() {
        let tx_a = aa_2d_tx(0, 10);
        let mut merged = merged_best_transactions(vec![], vec![tx_a.clone()]);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*tx_a.hash()));
        assert!(merged.next().is_none());
    }

    // ============================================
    // Interleaved priority tests
    // ============================================

    #[test]
    fn test_merge_best_transactions_interleaved() {
        // Left has higher odd positions, right has higher even positions
        let l1 = protocol_tx(0, 9);
        let l2 = protocol_tx(1, 7);
        let l3 = protocol_tx(2, 5);
        let r1 = aa_2d_tx(3, 10);
        let r2 = aa_2d_tx(4, 6);
        let r3 = aa_2d_tx(5, 4);
        let mut merged = merged_best_transactions(
            vec![l1.clone(), l2.clone(), l3.clone()],
            vec![r1.clone(), r2.clone(), r3.clone()],
        );

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r1.hash())); // 10
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash())); // 9
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash())); // 7
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r2.hash())); // 6
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l3.hash())); // 5
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*r3.hash())); // 4
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_aa_2d_to_right_pool() {
        // Invalidating an AA2D tx must NOT propagate to the
        // left-side (protocol) pool.
        let aa_2d_sender = Address::random();
        let l1 = protocol_tx(0, 9);
        let l2 = protocol_tx(1, 7);
        let r1 = aa_2d_tx_for_sequence(aa_2d_sender, 0, 10);
        let r2 = aa_2d_tx_for_sequence(aa_2d_sender, 1, 8);
        let mut merged =
            merged_best_transactions(vec![l1.clone(), l2.clone()], vec![r1.clone(), r2]);

        // Right has highest priority, so R1 is yielded first
        let first = merged.next().unwrap();
        assert_eq!(*first.hash(), *r1.hash());

        // Simulate payload builder marking R1 as invalid
        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        // The AA2D descendant must be skipped, while protocol txs still yield.
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l1.hash()));
        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_aa_2d_after_later_protocol_next() {
        let aa_2d_sender = Address::random();
        let protocol_sender = Address::random();
        let l1 = protocol_tx_for_sender(protocol_sender, 0, 9);
        let l2 = protocol_tx_for_sender(protocol_sender, 1, 7);
        let r1 = aa_2d_tx_for_sequence(aa_2d_sender, 0, 10);
        let mut merged = merged_best_transactions(vec![l1.clone(), l2.clone()], vec![r1.clone()]);
        let first = merged.next().unwrap();
        let second = merged.next().unwrap();

        assert_eq!(*first.hash(), *r1.hash());
        assert_eq!(*second.hash(), *l1.hash());

        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*l2.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn test_mark_invalid_routes_protocol_aa_to_left_pool() {
        let protocol_sender = Address::random();
        let left_tx = protocol_tx_for_sender(protocol_sender, 0, 10);
        let left_descendant = protocol_tx_for_sender(protocol_sender, 1, 9);
        let right_tx = aa_2d_tx(0, 8);
        assert!(left_tx.transaction.is_aa());
        assert!(!left_tx.transaction.is_aa_2d());
        assert!(right_tx.transaction.is_aa_2d());

        let mut merged = merged_best_transactions(
            vec![left_tx.clone(), left_descendant],
            vec![right_tx.clone()],
        );
        let first = merged.next().unwrap();
        assert_eq!(*first.hash(), *left_tx.hash());

        let kind =
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported);
        merged.mark_invalid(&first, kind);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*right_tx.hash()));
        assert!(merged.next().is_none());
    }

    #[test]
    fn skip_non_payment_invalidates_cached_descendants_after_prewarming() {
        for nonce_key in [U256::ZERO, U256::ONE] {
            let sender = Address::random();
            let general = tx_with_nonce_key(nonce_key, sender, 0, 10);
            let child = payment_tx(sender, nonce_key, 1, 1);
            let other_key = if nonce_key.is_zero() {
                U256::ONE
            } else {
                U256::ZERO
            };
            let other = payment_tx(Address::random(), other_key, 0, 5);
            let txs = vec![general.clone(), child];
            let mut best = if nonce_key.is_zero() {
                merged_best_transactions(txs, vec![other.clone()])
            } else {
                merged_best_transactions(vec![other.clone()], txs)
            };
            let skipped = best.next().unwrap();
            assert_eq!(*skipped.hash(), *general.hash());
            assert_eq!(best.next().map(|tx| *tx.hash()), Some(*other.hash()));
            // Prewarming has buffered the general transaction and the merged iterator has
            // already pulled its descendant from the underlying pool.
            best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
            best.mark_invalid(
                &skipped,
                InvalidPoolTransactionError::Other(Box::new(
                    TempoPoolTransactionError::ExceedsNonPaymentLimit,
                )),
            );
            assert!(best.next().is_none());
        }
    }

    #[test]
    fn skip_non_payment_keeps_independent_expiring_nonce_payments() {
        let sender = Address::random();
        let general = Arc::new(wrap_valid_tx(
            TxBuilder::aa(sender)
                .nonce_key(U256::MAX)
                .valid_before(u64::MAX)
                .build(),
            TransactionOrigin::External,
        ));
        let payment = payment_tx(sender, U256::MAX, 0, 1);
        let mut best = merged_best_transactions(vec![], vec![general, payment.clone()]);
        best.set_general_gas_limit(GeneralGasLimit::new(0, u64::MAX));
        assert_eq!(best.next().map(|tx| *tx.hash()), Some(*payment.hash()));
        assert!(best.next().is_none());
    }

    #[test]
    fn general_gas_budget_keeps_smaller_non_payments_and_payments() {
        for nonce_key in [U256::ZERO, U256::ONE, U256::MAX] {
            let large = general_tx_with_gas_limit(nonce_key, 300_000, 10);
            let exact = general_tx_with_gas_limit(nonce_key, 200_000, 9);
            let small = general_tx_with_gas_limit(nonce_key, 100_000, 8);
            let payment = payment_tx(Address::random(), nonce_key, 0, 7);
            let txs = vec![large, exact.clone(), small.clone(), payment.clone()];
            let mut best = if nonce_key.is_zero() {
                merged_best_transactions(txs, vec![])
            } else {
                merged_best_transactions(vec![], txs)
            };
            best.set_general_gas_limit(GeneralGasLimit::new(200_000, u64::MAX));
            assert_eq!(
                best.map(|tx| *tx.hash()).collect::<Vec<_>>(),
                vec![*exact.hash(), *small.hash(), *payment.hash()]
            );
        }
    }

    #[test]
    fn general_gas_budget_updates_filter_cached_candidates() {
        let first = general_tx_with_gas_limit(U256::ZERO, 100_000, 10);
        let cached = general_tx_with_gas_limit(U256::ONE, 200_000, 9);
        let small = general_tx_with_gas_limit(U256::ONE, 100_000, 8);
        let mut best = merged_best_transactions(vec![first.clone()], vec![cached, small.clone()]);
        let limit = GeneralGasLimit::new(250_000, u64::MAX);
        best.set_general_gas_limit(limit.clone());
        assert_eq!(best.next().map(|tx| *tx.hash()), Some(*first.hash()));
        limit.set_remaining(150_000);
        assert_eq!(best.next().map(|tx| *tx.hash()), Some(*small.hash()));
        assert!(best.next().is_none());
    }

    #[test]
    fn general_gas_budget_uses_executor_cap_and_never_increases() {
        let tx = general_tx_with_gas_limit(U256::ONE, 500_000, 1);
        let limit = GeneralGasLimit::new(200_000, 200_000);
        assert!(limit.fits(&tx));
        limit.set_remaining(199_999);
        assert!(!limit.fits(&tx));
        limit.set_remaining(300_000);
        assert_eq!(limit.remaining(), 199_999);
        assert!(!limit.fits(&tx));
    }

    fn general_tx_with_gas_limit(nonce_key: U256, gas_limit: u64, priority: u128) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(Address::random())
                .nonce_key(nonce_key)
                .gas_limit(gas_limit)
                .valid_before(u64::MAX)
                .max_priority_fee(priority)
                .max_fee(u128::from(TEMPO_T1_BASE_FEE) + priority)
                .build(),
            TransactionOrigin::External,
        ))
    }
}
