use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::Instant,
};

use alloy_primitives::{Address, B256, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_storage_api::{
    StateProvider, StateProviderBox, StateProviderFactory, errors::provider::ProviderResult,
};
use reth_tasks::{TaskExecutor, pool::WorkerPool};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, NONCE_PRECOMPILE_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::slots as nonce_slots,
    storage::StorageKey as _,
    tip_fee_manager::slots as fee_manager_slots,
    tip20::{ITIP20, tip20_slots},
};
use tempo_primitives::TempoAddressExt;
use tempo_transaction_pool::best::BestTransaction;
use tracing::trace;

/// Total best-transaction window touched per advance: one returned immediately
/// plus buffered transactions prewarmed for the next builder iterations.
const PREWARMING_WINDOW: usize = 16;
const PREWARMING_BUFFERED_LOOKAHEAD: usize = PREWARMING_WINDOW - 1;

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    commands_tx: Sender<BestTransactionsCommand>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        executor: TaskExecutor,
        provider: Provider,
        parent_hash: B256,
        fee_recipient: Address,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let (commands_tx, commands_rx) = mpsc::channel();
        let builder_consumed_tx_count = Arc::new(AtomicUsize::new(0));
        let prewarm = PrewarmingExecutionContext {
            provider,
            parent_hash,
            fee_recipient,
            builder_consumed_tx_count,
        };
        let prewarm_executor = executor.clone();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(
                prewarm_executor,
                BestTransactionsPrewarmingContext {
                    best_txs,
                    commands_rx,
                    prewarm,
                    next_tx_index: 0,
                },
            );
        });

        Self { commands_tx }
    }

    /// Runs the coordinator side of prewarming for a payload build.
    ///
    /// See [`BestTransactionsPrewarming`] for details.
    fn start_prewarming<Txs, Provider>(
        executor: TaskExecutor,
        mut ctx: BestTransactionsPrewarmingContext<Txs, Provider>,
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let pool = executor.prewarming_pool();

        pool.in_place_scope(|scope| {
            let mut buffered_txs = VecDeque::new();
            let fill_prewarming_buffer =
                |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>,
                 buffered_txs: &mut VecDeque<IndexedTransaction>| {
                    while buffered_txs.len() < PREWARMING_BUFFERED_LOOKAHEAD {
                        let Some(tx) = ctx.next_transaction() else {
                            break;
                        };

                        let prewarm = ctx.prewarm.clone();
                        let tx_index = tx.index;
                        let prewarm_tx = tx.transaction.clone();
                        buffered_txs.push_back(tx);

                        scope.spawn(move |_| {
                            Self::prewarm_transaction(prewarm, tx_index, prewarm_tx)
                        });
                    }
                };

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance { response } => {
                        let tx = buffered_txs.pop_front().or_else(|| ctx.next_transaction());
                        let should_refill = tx.is_some();
                        let tx = tx.map(|tx| {
                            ctx.prewarm
                                .builder_consumed_tx_count
                                .store(tx.index + 1, Ordering::Relaxed);
                            tx.transaction
                        });
                        let _ = response.send(tx);

                        if should_refill {
                            fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                        }
                    }
                    BestTransactionsCommand::Invalid(invalid) => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        buffered_txs.retain(|tx| {
                            !is_invalidated_buffered_transaction(&invalid.tx, &tx.transaction)
                        });
                        fill_prewarming_buffer(&mut ctx, &mut buffered_txs);
                    }
                    BestTransactionsCommand::NoUpdates => {
                        ctx.best_txs.no_updates();
                    }
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs);
                    }
                    BestTransactionsCommand::Stop => {
                        return;
                    }
                }
            }
        });

        pool.clear();
    }

    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        tx_index: usize,
        tx: BestTransaction,
    ) where
        Provider: StateProviderFactory + Clone + 'static,
    {
        if prewarm.is_consumed_by_builder(tx_index) {
            return;
        }

        WorkerPool::with_worker_mut(|worker| {
            let worker_state =
                worker.get_or_init::<PrewarmWorkerState>(PrewarmWorkerState::default);
            if worker_state.parent_hash != prewarm.parent_hash
                || worker_state.state_provider.is_none()
            {
                worker_state.parent_hash = prewarm.parent_hash;
                worker_state.state_provider = prewarm.state_provider_for_ctx();
            }

            let Some(state_provider) = worker_state.state_provider.as_ref() else {
                return;
            };

            if prewarm.is_consumed_by_builder(tx_index) {
                return;
            }

            let start = Instant::now();
            let tx_hash = *tx.hash();
            let touches = storage_touches_for_transaction(&tx, prewarm.fee_recipient);

            for touch in &touches {
                if let Err(err) = touch.warm(state_provider.as_ref()) {
                    trace!(
                        target: "payload_builder",
                        %err,
                        ?tx_hash,
                        "Failed to prewarm transaction storage"
                    );
                    return;
                }
            }

            trace!(
                target: "payload_builder",
                elapsed = ?start.elapsed(),
                touched = touches.len(),
                ?tx_hash,
                "Prewarmed transaction"
            );
        });
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        let (response, rx) = mpsc::channel();
        self.commands_tx
            .send(BestTransactionsCommand::Advance { response })
            .ok()?;
        rx.recv().ok().flatten()
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::Invalid(InvalidTransaction {
                tx: transaction.clone(),
                kind,
            }));
    }

    fn no_updates(&mut self) {
        let _ = self.commands_tx.send(BestTransactionsCommand::NoUpdates);
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        let _ = self
            .commands_tx
            .send(BestTransactionsCommand::SkipBlobs(skip_blobs));
    }
}

/// Context for prewarming best transactions for a payload build.
struct BestTransactionsPrewarmingContext<Txs, Provider> {
    best_txs: Txs,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
    next_tx_index: usize,
}

impl<Txs, Provider> BestTransactionsPrewarmingContext<Txs, Provider>
where
    Txs: BestTransactions<Item = BestTransaction>,
{
    fn next_transaction(&mut self) -> Option<IndexedTransaction> {
        let transaction = self.best_txs.next()?;
        let index = self.next_tx_index;
        self.next_tx_index += 1;
        Some(IndexedTransaction { index, transaction })
    }
}

/// Transaction tagged with its source iterator order.
struct IndexedTransaction {
    index: usize,
    transaction: BestTransaction,
}

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
struct PrewarmingExecutionContext<Provider> {
    provider: Provider,
    parent_hash: B256,
    fee_recipient: Address,
    /// Number of source transactions already handed to the builder.
    builder_consumed_tx_count: Arc<AtomicUsize>,
}

#[derive(Default)]
struct PrewarmWorkerState {
    parent_hash: B256,
    state_provider: Option<StateProviderBox>,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn state_provider_for_ctx(&self) -> Option<StateProviderBox> {
        match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => Some(provider),
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for transaction prewarming"
                );
                None
            }
        }
    }

    fn is_consumed_by_builder(&self, tx_index: usize) -> bool {
        tx_index < self.builder_consumed_tx_count.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageTouch {
    Account(Address),
    Storage { address: Address, slot: U256 },
}

impl StorageTouch {
    fn warm(&self, state_provider: &dyn StateProvider) -> ProviderResult<()> {
        match *self {
            Self::Account(address) => {
                let _ = state_provider.basic_account(&address)?;
            }
            Self::Storage { address, slot } => {
                let _ = state_provider.storage(address, slot.into())?;
            }
        }

        Ok(())
    }
}

fn storage_touches_for_transaction(
    tx: &BestTransaction,
    fee_recipient: Address,
) -> Vec<StorageTouch> {
    let mut touches = Vec::with_capacity(24);
    let sender = tx.transaction.sender();
    let fee_payer = tx.transaction.inner().fee_payer(sender).unwrap_or(sender);
    let fee_token = tx.transaction.resolved_fee_token().unwrap_or_else(|| {
        tx.transaction
            .inner()
            .fee_token()
            .unwrap_or(DEFAULT_FEE_TOKEN)
    });

    add_tip20_fee_touches(&mut touches, fee_token, fee_payer);
    add_fee_manager_touches(&mut touches, fee_recipient, fee_token);

    if tx.transaction.is_payment() {
        for (kind, input) in tx.transaction.inner().calls() {
            add_tip20_call_touches(&mut touches, sender, kind, input);
        }
    }

    add_expiring_nonce_touches(&mut touches, tx);

    touches
}

fn add_tip20_fee_touches(touches: &mut Vec<StorageTouch>, fee_token: Address, fee_payer: Address) {
    if !fee_token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, fee_token);
    add_tip20_balance_touch(touches, fee_token, fee_payer);
    add_tip20_balance_touch(touches, fee_token, TIP_FEE_MANAGER_ADDRESS);
    add_tip20_reward_touches(touches, fee_token, fee_payer);
}

fn add_tip20_call_touches(
    touches: &mut Vec<StorageTouch>,
    sender: Address,
    kind: TxKind,
    input: &[u8],
) {
    let Some(token) = kind.to().copied() else {
        return;
    };
    if !token.is_tip20() {
        return;
    }

    add_tip20_common_touches(touches, token);
    let Ok(call) = ITIP20::ITIP20Calls::abi_decode(input) else {
        return;
    };

    match call {
        ITIP20::ITIP20Calls::transfer(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferWithMemo(call) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, sender);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFrom(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::transferFromWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.from);
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_allowance_touch(touches, token, call.from, sender);
            add_tip20_reward_touches(touches, token, call.from);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::approve(call) => {
            add_tip20_allowance_touch(touches, token, sender, call.spender);
        }
        ITIP20::ITIP20Calls::mint(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::mintWithMemo(call) => {
            add_tip20_balance_touch(touches, token, call.to);
            add_tip20_reward_touches(touches, token, call.to);
        }
        ITIP20::ITIP20Calls::burn(_) | ITIP20::ITIP20Calls::burnWithMemo(_) => {
            add_tip20_balance_touch(touches, token, sender);
            add_tip20_reward_touches(touches, token, sender);
        }
        _ => {}
    }
}

fn add_tip20_common_touches(touches: &mut Vec<StorageTouch>, token: Address) {
    add_account_touch(touches, token);
    add_storage_touch(touches, token, tip20_slots::CURRENCY);
    add_storage_touch(touches, token, tip20_slots::PAUSED);
    add_storage_touch(touches, token, tip20_slots::TRANSFER_POLICY_ID);
    add_storage_touch(touches, token, tip20_slots::GLOBAL_REWARD_PER_TOKEN);
    add_storage_touch(touches, token, tip20_slots::OPTED_IN_SUPPLY);
}

fn add_tip20_balance_touch(touches: &mut Vec<StorageTouch>, token: Address, account: Address) {
    add_storage_touch(touches, token, account.mapping_slot(tip20_slots::BALANCES));
}

fn add_tip20_allowance_touch(
    touches: &mut Vec<StorageTouch>,
    token: Address,
    owner: Address,
    spender: Address,
) {
    add_storage_touch(
        touches,
        token,
        spender.mapping_slot(owner.mapping_slot(tip20_slots::ALLOWANCES)),
    );
}

fn add_tip20_reward_touches(touches: &mut Vec<StorageTouch>, token: Address, account: Address) {
    let base_slot = account.mapping_slot(tip20_slots::USER_REWARD_INFO);
    add_storage_touch(touches, token, base_slot);
    add_storage_touch(touches, token, base_slot + U256::from(1));
    add_storage_touch(touches, token, base_slot + U256::from(2));
}

fn add_fee_manager_touches(
    touches: &mut Vec<StorageTouch>,
    fee_recipient: Address,
    fee_token: Address,
) {
    add_account_touch(touches, TIP_FEE_MANAGER_ADDRESS);
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_recipient.mapping_slot(fee_manager_slots::VALIDATOR_TOKENS),
    );
    add_storage_touch(
        touches,
        TIP_FEE_MANAGER_ADDRESS,
        fee_token.mapping_slot(fee_recipient.mapping_slot(fee_manager_slots::COLLECTED_FEES)),
    );
}

fn add_expiring_nonce_touches(touches: &mut Vec<StorageTouch>, tx: &BestTransaction) {
    let Some(expiring_nonce_slot) = tx.transaction.expiring_nonce_slot() else {
        return;
    };

    add_account_touch(touches, NONCE_PRECOMPILE_ADDRESS);
    add_storage_touch(touches, NONCE_PRECOMPILE_ADDRESS, expiring_nonce_slot);
    add_storage_touch(
        touches,
        NONCE_PRECOMPILE_ADDRESS,
        nonce_slots::EXPIRING_NONCE_RING_PTR,
    );
}

fn add_account_touch(touches: &mut Vec<StorageTouch>, address: Address) {
    add_unique_touch(touches, StorageTouch::Account(address));
}

fn add_storage_touch(touches: &mut Vec<StorageTouch>, address: Address, slot: U256) {
    add_account_touch(touches, address);
    add_unique_touch(touches, StorageTouch::Storage { address, slot });
}

fn add_unique_touch(touches: &mut Vec<StorageTouch>, touch: StorageTouch) {
    if !touches.contains(&touch) {
        touches.push(touch);
    }
}

/// Command sent by [`BestTransactionsPrewarming`] consumer.
#[derive(Debug)]
enum BestTransactionsCommand {
    Advance {
        response: Sender<Option<BestTransaction>>,
    },
    Invalid(InvalidTransaction),
    NoUpdates,
    SkipBlobs(bool),
    Stop,
}

/// Invalid transaction encountered during execution.
#[derive(Debug)]
struct InvalidTransaction {
    tx: BestTransaction,
    kind: InvalidPoolTransactionError,
}

/// Returns whether the candidate transaction is invalidated by the given invalid transaction.
fn is_invalidated_buffered_transaction(
    invalid: &BestTransaction,
    candidate: &BestTransaction,
) -> bool {
    // Skip invalidation for expiring nonce transactions - they are independent
    // and should not block other expiring nonce txs from the same sender
    if invalid.transaction.is_expiring_nonce() {
        return false;
    }

    if invalid.transaction.is_aa_2d() {
        candidate
            .transaction
            .aa_transaction_id()
            .zip(invalid.transaction.aa_transaction_id())
            .is_some_and(|(candidate_id, invalid_id)| candidate_id.seq_id() == invalid_id.seq_id())
    } else {
        candidate.transaction.sender() == invalid.transaction.sender()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::SolCall;
    use reth_primitives_traits::{
        Recovered, SealedHeader, transaction::error::InvalidTransactionError,
    };
    use reth_storage_api::noop::NoopProvider;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };
    use tempo_chainspec::TempoChainSpec;
    use tempo_evm::TempoEvmConfig;
    use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope};
    use tempo_transaction_pool::transaction::TempoPooledTransaction;

    #[derive(Debug, Default)]
    struct TestLog {
        yielded: usize,
        empty_polls: usize,
        invalid: usize,
        no_updates: usize,
        skip_blobs: Vec<bool>,
    }

    struct TestBestTransactions {
        txs: VecDeque<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    }

    impl TestBestTransactions {
        fn new(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> Self {
            Self {
                txs: txs.into(),
                log,
            }
        }
    }

    impl Iterator for TestBestTransactions {
        type Item = BestTransaction;

        fn next(&mut self) -> Option<Self::Item> {
            let tx = self.txs.pop_front();
            {
                let mut log = self.log.lock().unwrap();
                if tx.is_some() {
                    log.yielded += 1;
                } else {
                    log.empty_polls += 1;
                }
            }
            if tx.is_none() {
                thread::sleep(Duration::from_millis(1));
            }
            tx
        }
    }

    impl BestTransactions for TestBestTransactions {
        fn mark_invalid(&mut self, transaction: &Self::Item, _kind: InvalidPoolTransactionError) {
            self.log.lock().unwrap().invalid += 1;
            self.txs
                .retain(|tx| !is_invalidated_buffered_transaction(transaction, tx));
        }

        fn no_updates(&mut self) {
            self.log.lock().unwrap().no_updates += 1;
        }

        fn set_skip_blobs(&mut self, skip_blobs: bool) {
            self.log.lock().unwrap().skip_blobs.push(skip_blobs);
        }
    }

    fn test_tx(sender: Address, nonce: u64) -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: TxKind::Call(Address::random()),
            value: U256::ZERO,
            input: Bytes::new(),
        };
        let envelope =
            TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, Signature::test_signature()));
        let pooled = TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender));
        Arc::new(ValidPoolTransaction {
            transaction_id: TransactionId::new(0u64.into(), nonce),
            transaction: pooled,
            propagate: true,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    fn prewarming(
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> BestTransactionsPrewarming {
        let executor = TaskExecutor::test();
        let evm_config = TempoEvmConfig::moderato();
        let provider =
            NoopProvider::<TempoChainSpec, TempoPrimitives>::new(evm_config.chain_spec().clone());
        let parent_header = SealedHeader::seal_slow(TempoHeader {
            inner: Header {
                number: 0,
                timestamp: 1,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1),
                ..Default::default()
            },
            general_gas_limit: 30_000_000,
            timestamp_millis_part: 0,
            shared_gas_limit: 0,
            ..Default::default()
        });
        BestTransactionsPrewarming::new(
            executor,
            provider,
            parent_header.hash(),
            Address::ZERO,
            TestBestTransactions::new(txs, log),
        )
    }

    fn wait_until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(condition(), "condition did not become true before timeout");
    }

    #[test]
    fn tip20_touch_collection_dedups_overlapping_fee_and_call_slots() {
        let sender = Address::random();
        let recipient = Address::random();
        let token = DEFAULT_FEE_TOKEN;
        let mut touches = Vec::new();

        add_tip20_fee_touches(&mut touches, token, sender);
        add_tip20_call_touches(
            &mut touches,
            sender,
            TxKind::Call(token),
            &ITIP20::transferCall {
                to: recipient,
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        for (index, touch) in touches.iter().enumerate() {
            assert!(
                !touches[index + 1..].contains(touch),
                "duplicate storage prewarm touch: {touch:?}"
            );
        }

        assert!(touches.contains(&StorageTouch::Account(token)));
        assert!(touches.contains(&StorageTouch::Storage {
            address: token,
            slot: sender.mapping_slot(tip20_slots::BALANCES)
        }));
        assert!(touches.contains(&StorageTouch::Storage {
            address: token,
            slot: recipient.mapping_slot(tip20_slots::BALANCES)
        }));
    }

    #[test]
    fn source_ordering_is_unchanged_when_prewarming_is_enabled() {
        let sender = Address::random();
        let txs = vec![test_tx(sender, 0), test_tx(sender, 1), test_tx(sender, 2)];
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(txs, log);
        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").hash())
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn prewarming_window_limits_source_iterator_drain_after_first_advance() {
        let sender = Address::random();
        let txs = (0..PREWARMING_WINDOW + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(txs, log.clone());
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, 0);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == PREWARMING_WINDOW);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().yielded, PREWARMING_WINDOW);

        assert!(prewarming.next().is_some());
        wait_until(|| log.lock().unwrap().yielded == PREWARMING_WINDOW + 1);
    }

    #[test]
    fn empty_source_is_polled_once_per_advance() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 0);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 1);
        thread::sleep(Duration::from_millis(25));
        assert_eq!(log.lock().unwrap().empty_polls, 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 2);
    }

    #[test]
    fn mark_invalid_filters_already_buffered_invalidated_transactions() {
        let sender = Address::random();
        let tx1 = test_tx(sender, 0);
        let tx2 = test_tx(sender, 1);
        let tx3 = test_tx(Address::random(), 0);
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming(vec![tx1.clone(), tx2.clone(), tx3.clone()], log.clone());
        assert_eq!(
            prewarming.next().as_ref().map(|tx| tx.hash()),
            Some(tx1.hash())
        );

        wait_until(|| log.lock().unwrap().yielded == 3);
        prewarming.mark_invalid(
            &tx1,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.hash(), tx3.hash());
        assert_ne!(next.hash(), tx2.hash());
        wait_until(|| log.lock().unwrap().invalid == 1);
    }

    #[test]
    fn commands_are_forwarded_to_source_iterator() {
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming(Vec::new(), log.clone());

        prewarming.no_updates();
        prewarming.set_skip_blobs(true);

        wait_until(|| {
            let log = log.lock().unwrap();
            log.no_updates == 1 && log.skip_blobs == vec![true]
        });
    }
}
