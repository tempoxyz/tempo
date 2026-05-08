//! An iterator over the best transactions in the tempo pool.

use crate::{transaction::TempoPooledTransaction, tt_2d_pool::BestAA2dTransactions};
use alloy_primitives::{Address, U256, map::HashMap};
use reth_evm::block::TxResult;
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_transaction_pool::{
    BestTransactions, CoinbaseTipOrdering, Priority, ValidPoolTransaction,
    error::InvalidPoolTransactionError, pool::BestTransactions as BestProtocolTransactions,
};
use std::{
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tempo_evm::TempoTxResult;
use tempo_precompiles::tip20::is_tip20_prefix;

type TxOrdering = CoinbaseTipOrdering<TempoPooledTransaction>;
type BestTransaction = Arc<ValidPoolTransaction<TempoPooledTransaction>>;
type BestTransactionWithPriority = (BestTransaction, Priority<u128>);

/// A best-transaction iterator that merges the protocol pool and the 2D nonces pool,
/// always yielding the next best item from either iterator.
pub struct MergeBestTransactions {
    protocol_pool: BestProtocolTransactions<TxOrdering>,
    aa_2d_pool: BestAA2dTransactions,
    next_protocol_pool: Option<BestTransactionWithPriority>,
    next_aa_2d_pool: Option<BestTransactionWithPriority>,
}

impl MergeBestTransactions {
    /// Creates a new iterator over the given iterators.
    pub(crate) fn new(
        protocol_pool: BestProtocolTransactions<TxOrdering>,
        aa_2d_pool: BestAA2dTransactions,
    ) -> Self {
        Self {
            protocol_pool,
            aa_2d_pool,
            next_protocol_pool: None,
            next_aa_2d_pool: None,
        }
    }

    /// Returns the next transaction from either pool with the higher priority.
    fn next_best(&mut self) -> Option<BestTransactionWithPriority> {
        if self.next_protocol_pool.is_none() {
            self.next_protocol_pool = self.protocol_pool.next_tx_and_priority();
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
        self.next_best().map(|(tx, _)| tx)
    }
}

impl BestTransactions for MergeBestTransactions {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
        if transaction.transaction.is_aa_2d() {
            self.aa_2d_pool.mark_invalid(transaction, kind);
            if self
                .next_aa_2d_pool
                .as_ref()
                .is_some_and(|(tx, _)| is_invalidated_buffered_transaction(transaction, tx))
            {
                self.next_aa_2d_pool = None;
            }
        } else {
            self.protocol_pool.mark_invalid(transaction, kind);
            if self
                .next_protocol_pool
                .as_ref()
                .is_some_and(|(tx, _)| is_invalidated_buffered_transaction(transaction, tx))
            {
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

/// Pool transaction type streamed into the payload builder.
pub type PoolTx = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

/// Event returned by [`BestTransactionsStream`].
#[derive(Debug)]
pub enum BestTransactionsStreamEvent {
    /// A transaction is ready for sequential payload execution.
    Transaction(PoolTx),
    /// No transaction is currently buffered.
    Empty,
    /// The coordinator drained the finite iterator or disconnected.
    End,
}

#[derive(Debug)]
enum BestTransactionsStreamMessage {
    Transaction(PoolTx),
    End,
}

enum BestTransactionsStreamCommand {
    Invalid(InvalidTransaction),
    Stop,
}

struct InvalidTransaction {
    tx: PoolTx,
    kind: InvalidPoolTransactionError,
    old_receiver: Receiver<BestTransactionsStreamMessage>,
    new_sender: Sender<BestTransactionsStreamMessage>,
}

/// Drains a [`BestTransactions`] iterator into a channel while preserving delayed invalidation.
pub struct BestTransactionsStream {
    receiver: Receiver<BestTransactionsStreamMessage>,
    commands: Sender<BestTransactionsStreamCommand>,
    handle: Option<JoinHandle<()>>,
}

impl BestTransactionsStream {
    /// Spawns a payload-scoped coordinator for `best_txs`.
    pub fn new<Txs>(mut best_txs: Txs, live: bool) -> Self
    where
        Txs: BestTransactions<Item = PoolTx> + Send + 'static,
    {
        if !live {
            best_txs.no_updates();
        }

        let (sender, receiver) = mpsc::channel();
        let (commands, command_receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            run_best_transactions_coordinator(best_txs, sender, command_receiver, live);
        });

        Self {
            receiver,
            commands,
            handle: Some(handle),
        }
    }

    /// Returns the next stream event without blocking.
    pub fn next(&mut self) -> BestTransactionsStreamEvent {
        match self.receiver.try_recv() {
            Ok(BestTransactionsStreamMessage::Transaction(tx)) => {
                BestTransactionsStreamEvent::Transaction(tx)
            }
            Ok(BestTransactionsStreamMessage::End) | Err(TryRecvError::Disconnected) => {
                BestTransactionsStreamEvent::End
            }
            Err(TryRecvError::Empty) => BestTransactionsStreamEvent::Empty,
        }
    }

    /// Marks a transaction invalid and refilters transactions already buffered for execution.
    pub fn mark_invalid(&mut self, tx: &PoolTx, kind: InvalidPoolTransactionError) {
        let (new_sender, new_receiver) = mpsc::channel();
        let old_receiver = std::mem::replace(&mut self.receiver, new_receiver);
        let invalid = InvalidTransaction {
            tx: tx.clone(),
            kind,
            old_receiver,
            new_sender,
        };
        let _ = self
            .commands
            .send(BestTransactionsStreamCommand::Invalid(invalid));
    }
}

impl Drop for BestTransactionsStream {
    fn drop(&mut self) {
        let _ = self.commands.send(BestTransactionsStreamCommand::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_best_transactions_coordinator<Txs>(
    mut best_txs: Txs,
    mut sender: Sender<BestTransactionsStreamMessage>,
    command_receiver: Receiver<BestTransactionsStreamCommand>,
    live: bool,
) where
    Txs: BestTransactions<Item = PoolTx>,
{
    const IDLE_SLEEP: Duration = Duration::from_millis(1);
    let mut ended = false;

    loop {
        if ended {
            match command_receiver.recv() {
                Ok(BestTransactionsStreamCommand::Invalid(invalid)) => {
                    process_invalid_transaction(&mut best_txs, invalid, &mut sender);
                }
                Ok(BestTransactionsStreamCommand::Stop) | Err(_) => break,
            }
            continue;
        }

        while let Ok(command) = command_receiver.try_recv() {
            match command {
                BestTransactionsStreamCommand::Invalid(invalid) => {
                    process_invalid_transaction(&mut best_txs, invalid, &mut sender);
                }
                BestTransactionsStreamCommand::Stop => return,
            }
        }

        match best_txs.next() {
            Some(tx) => {
                if sender
                    .send(BestTransactionsStreamMessage::Transaction(tx))
                    .is_err()
                {
                    break;
                }
            }
            None if live => thread::sleep(IDLE_SLEEP),
            None => {
                let _ = sender.send(BestTransactionsStreamMessage::End);
                ended = true;
            }
        }
    }
}

fn process_invalid_transaction<Txs>(
    best_txs: &mut Txs,
    invalid: InvalidTransaction,
    sender: &mut Sender<BestTransactionsStreamMessage>,
) where
    Txs: BestTransactions<Item = PoolTx>,
{
    best_txs.mark_invalid(&invalid.tx, &invalid.kind);

    let mut saw_end = false;
    while let Ok(message) = invalid.old_receiver.try_recv() {
        match message {
            BestTransactionsStreamMessage::Transaction(tx) => {
                if !is_invalidated_buffered_transaction(&invalid.tx, &tx) {
                    let _ = invalid
                        .new_sender
                        .send(BestTransactionsStreamMessage::Transaction(tx));
                }
            }
            BestTransactionsStreamMessage::End => saw_end = true,
        }
    }

    if saw_end {
        let _ = invalid.new_sender.send(BestTransactionsStreamMessage::End);
    }

    *sender = invalid.new_sender;
}

fn is_invalidated_buffered_transaction(invalid: &PoolTx, candidate: &PoolTx) -> bool {
    if invalid.transaction.is_expiring_nonce() {
        return false;
    }

    if invalid.transaction.is_aa_2d() {
        let Some(invalid_id) = invalid.transaction.aa_transaction_id() else {
            return false;
        };
        return candidate
            .transaction
            .aa_transaction_id()
            .is_some_and(|candidate_id| {
                candidate_id.seq_id == invalid_id.seq_id && candidate_id.nonce >= invalid_id.nonce
            });
    }

    !candidate.transaction.is_aa_2d()
        && candidate.sender() == invalid.sender()
        && candidate.nonce() >= invalid.nonce()
}

/// A [`BestTransactions`] wrapper that tracks execution state changes and skips
/// transactions that would fail due to state mutations from previously
/// included transactions.
pub struct StateAwareBestTransactions<I> {
    inner: I,
    tracker: StateInvalidationTracker,
}

/// Tracks state changes that can invalidate later pool transactions.
#[derive(Debug, Default)]
pub struct StateInvalidationTracker {
    /// Tracks decreased TIP20 balance slots: `(token_address, slot) -> new_balance`.
    decreased_balances: HashMap<(Address, U256), U256>,
}

/// Result of checking a transaction against [`StateInvalidationTracker`].
#[derive(Debug)]
pub enum StateTransactionCheck {
    /// The transaction can be attempted.
    Valid,
    /// The transaction did not carry the cached state metadata expected by the builder.
    MissingFeeBalanceSlot,
    /// The transaction is invalidated by state changes from already-executed transactions.
    Invalid(InvalidPoolTransactionError),
}

impl StateInvalidationTracker {
    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result(&mut self, result: &TempoTxResult) {
        for (&address, account) in &result.result().state {
            if !is_tip20_prefix(address) {
                continue;
            }

            for (&slot, storage_slot) in &account.storage {
                if storage_slot.present_value < storage_slot.original_value {
                    self.decreased_balances
                        .insert((address, slot), storage_slot.present_value);
                }
            }
        }
    }

    /// Checks whether `tx` is still valid under tracked state changes.
    pub fn check(&self, tx: &PoolTx) -> StateTransactionCheck {
        let Some(key) = tx.transaction.fee_balance_slot() else {
            debug_assert!(false, "pool transaction must have cached fee_balance_slot");
            return StateTransactionCheck::MissingFeeBalanceSlot;
        };

        if let Some(&balance) = self.decreased_balances.get(&key)
            && balance < tx.transaction.fee_token_cost()
        {
            return StateTransactionCheck::Invalid(InvalidPoolTransactionError::Consensus(
                InvalidTransactionError::InsufficientFunds(
                    (balance, tx.transaction.fee_token_cost()).into(),
                ),
            ));
        }

        StateTransactionCheck::Valid
    }
}

impl<I> StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    /// Wraps an existing [`BestTransactions`] iterator.
    pub fn new(inner: I) -> Self {
        Self {
            inner,
            tracker: StateInvalidationTracker::default(),
        }
    }

    /// Processes a new transaction execution result and collects any relevant
    /// state changes that might affect other transactions validity.
    pub fn on_new_result(&mut self, result: &TempoTxResult) {
        self.tracker.on_new_result(result);
    }
}

impl<I> Iterator for StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
{
    type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let tx = self.inner.next()?;
            match self.tracker.check(&tx) {
                StateTransactionCheck::Valid => return Some(tx),
                StateTransactionCheck::MissingFeeBalanceSlot => continue,
                StateTransactionCheck::Invalid(kind) => {
                    self.inner.mark_invalid(&tx, &kind);
                    continue;
                }
            }
        }
    }
}

impl<I> BestTransactions for StateAwareBestTransactions<I>
where
    I: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>> + Send,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: &InvalidPoolTransactionError) {
        self.inner.mark_invalid(transaction, kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{TxBuilder, wrap_valid_tx},
        tt_2d_pool::AA2dPool,
    };
    use alloy_primitives::{Address, U256};
    use futures::executor::block_on;
    use reth_primitives_traits::transaction::error::InvalidTransactionError;
    use reth_transaction_pool::{
        Pool, PoolConfig, TransactionOrigin, TransactionPool, blobstore::InMemoryBlobStore,
        test_utils::OkValidator,
    };
    use std::sync::Arc;
    use tempo_chainspec::hardfork::TempoHardfork;

    type TestTx = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

    fn tx_with_nonce_key(nonce_key: U256, sender: Address, nonce: u64, priority: u128) -> TestTx {
        Arc::new(wrap_valid_tx(
            TxBuilder::aa(sender)
                .nonce_key(nonce_key)
                .nonce(nonce)
                .max_priority_fee(priority)
                .max_fee(TempoHardfork::T1.base_fee() as u128 + priority)
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

    fn protocol_best_transactions(txs: Vec<TestTx>) -> BestProtocolTransactions<TxOrdering> {
        let pool = Pool::new(
            OkValidator::<TempoPooledTransaction>::default(),
            CoinbaseTipOrdering::default(),
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
        pool.inner().best_transactions()
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
        )
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
        merged.mark_invalid(&first, &kind);

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
        merged.mark_invalid(&first, &kind);

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
        merged.mark_invalid(&first, &kind);

        assert_eq!(merged.next().map(|tx| *tx.hash()), Some(*right_tx.hash()));
        assert!(merged.next().is_none());
    }
}
