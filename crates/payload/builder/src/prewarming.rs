use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
};

use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_sol_types::SolInterface;
use reth_engine_tree::tree::{CachedStateMetrics, CachedStateProvider, SavedCache};
use reth_evm::{Database, Evm, EvmEnvFor};
use reth_revm::database::StateProviderDatabase;
use reth_storage_api::{StateProviderBox, StateProviderFactory};
use reth_tasks::{TaskExecutor, WorkerPool};
use reth_transaction_pool::{
    BestTransactions, PoolTransaction, error::InvalidPoolTransactionError,
};
use tempo_evm::{TempoEvmConfig, evm::TempoEvm};
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

type PrewarmEvmState = Option<TempoEvm<StateProviderDatabase<StateProviderBox>>>;

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: Receiver<Option<BestTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    stop: Arc<AtomicBool>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        executor: TaskExecutor,
        provider: Provider,
        cache: Option<SavedCache>,
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let prewarm = PrewarmingExecutionContext {
            provider,
            parent_hash,
            cache,
            evm_env,
            stop: stop.clone(),
        };

        let this = Self {
            transactions_rx,
            commands_tx: commands_tx.clone(),
            stop,
        };

        let prewarm_executor = executor.clone();
        executor.spawn_blocking_named("builder-prewarm", move || {
            Self::start_prewarming(
                prewarm_executor,
                BestTransactionsPrewarmingContext {
                    best_txs,
                    transactions_tx,
                    commands_rx,
                    commands_tx,
                    prewarm,
                },
            );
        });

        this
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
            let prewarm = ctx.prewarm.clone();
            scope.spawn(move |_| {
                pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx());
            });

            let advance = |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>| {
                let Some(tx) = ctx.best_txs.next() else {
                    let _ = ctx.transactions_tx.send(None);
                    return;
                };
                let _ = ctx.transactions_tx.send(Some(tx.clone()));

                let prewarm = ctx.prewarm.clone();
                let commands_tx = ctx.commands_tx.clone();
                scope.spawn(move |_| {
                    Self::prewarm_transaction(prewarm, tx.clone());
                    let _ = commands_tx.send(BestTransactionsCommand::Advance);
                });
            };

            // Fill the initial batch of transactions to execute and prewarm.
            //
            // We schedule 2x the number of threads to make sure that workers are never idle.
            for _ in 0..pool.current_num_threads() * 2 {
                advance(&mut ctx);
            }

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance => {
                        advance(&mut ctx);
                    }
                    BestTransactionsCommand::Invalid {
                        invalid,
                        old_rx,
                        new_tx,
                    } => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        ctx.transactions_tx = new_tx;

                        for tx in old_rx {
                            if let Some(tx) = tx
                                && !is_invalidated_buffered_transaction(&invalid.tx, &tx)
                            {
                                let _ = ctx.transactions_tx.send(Some(tx));
                            }
                        }
                    }
                    BestTransactionsCommand::NoUpdates => {
                        ctx.best_txs.no_updates();
                    }
                    BestTransactionsCommand::SkipBlobs(skip_blobs) => {
                        ctx.best_txs.set_skip_blobs(skip_blobs);
                    }
                    BestTransactionsCommand::Stop => {
                        ctx.prewarm.stop();
                        return;
                    }
                }
            }
        });

        pool.clear();
    }

    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        tx: BestTransaction,
    ) where
        Provider: StateProviderFactory + Clone + 'static,
    {
        if prewarm.is_stopped() {
            return;
        }

        WorkerPool::with_worker_mut(|worker| {
            let Some(evm) = worker.get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx()) else {
                return;
            };

            let tx_hash = *tx.hash();

            let touched = if is_tip20_transfer_transaction(&tx) {
                let touches =
                    storage_touches_for_transaction(&tx, prewarm.evm_env.block_env.beneficiary);

                for touch in &touches {
                    if prewarm.is_stopped() {
                        return;
                    }
                    if let Err(err) = touch.warm(evm) {
                        trace!(
                            target: "payload_builder",
                            %err,
                            ?tx_hash,
                            "Failed to prewarm transaction storage"
                        );
                        return;
                    }
                }

                Some(touches.len())
            } else {
                if prewarm.is_stopped() {
                    return;
                }

                if let Err(err) = evm.transact_raw(tx.transaction.clone().into_with_tx_env().tx_env)
                {
                    trace!(
                        target: "payload_builder",
                        %err,
                        ?tx_hash,
                        "Failed to prewarm transaction by execution"
                    );
                    return;
                }

                None
            };

            trace!(
                target: "payload_builder",
                touched,
                ?tx_hash,
                "Prewarmed transaction"
            );
        });
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = BestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(Some(tx)) = self.transactions_rx.try_recv() {
            return Some(tx);
        }
        self.commands_tx
            .send(BestTransactionsCommand::Advance)
            .ok()?;
        self.transactions_rx.recv().ok().flatten()
    }
}

impl BestTransactions for BestTransactionsPrewarming {
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        let (new_tx, new_rx) = mpsc::channel();
        let old_rx = core::mem::replace(&mut self.transactions_rx, new_rx);
        let _ = self.commands_tx.send(BestTransactionsCommand::Invalid {
            invalid: InvalidTransaction {
                tx: transaction.clone(),
                kind,
            },
            old_rx,
            new_tx,
        });
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
    transactions_tx: Sender<Option<BestTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
}

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
struct PrewarmingExecutionContext<Provider> {
    provider: Provider,
    parent_hash: B256,
    cache: Option<SavedCache>,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    stop: Arc<AtomicBool>,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn evm_for_ctx(&self) -> PrewarmEvmState {
        let mut state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
            Ok(provider) => provider,
            Err(err) => {
                trace!(
                    target: "payload_builder",
                    %err,
                    parent_hash = ?self.parent_hash,
                    "failed to build state provider for transaction prewarming"
                );
                return None;
            }
        };

        if let Some(cache) = &self.cache {
            state_provider = Box::new(CachedStateProvider::new_prewarm(
                state_provider,
                cache.cache().clone(),
                // Use unlabeled default metrics to avoid polluting the builder metrics.
                CachedStateMetrics::default(),
            ));
        }

        let state_provider = StateProviderDatabase::new(state_provider);
        let mut evm_env = self.evm_env.clone();
        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;

        Some(TempoEvm::new(state_provider, evm_env))
    }

    fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageTouch {
    Account(Address),
    Storage { address: Address, slot: U256 },
}

impl StorageTouch {
    fn warm<DB: Database>(&self, evm: &mut TempoEvm<DB>) -> Result<(), DB::Error> {
        match *self {
            Self::Account(address) => {
                let _ = evm.db_mut().basic(address)?;
            }
            Self::Storage { address, slot } => {
                let _ = evm.db_mut().storage(address, slot)?;
            }
        }

        Ok(())
    }
}

fn is_tip20_transfer_transaction(tx: &BestTransaction) -> bool {
    tx.transaction.is_payment() && is_tip20_transfer_calls(tx.transaction.inner().calls())
}

fn is_tip20_transfer_calls<'a>(calls: impl IntoIterator<Item = (TxKind, &'a Bytes)>) -> bool {
    let mut has_call = false;
    for (kind, input) in calls {
        has_call = true;
        if !is_tip20_transfer_call(kind, input) {
            return false;
        }
    }
    has_call
}

fn is_tip20_transfer_call(kind: TxKind, input: &[u8]) -> bool {
    let Some(token) = kind.to().copied() else {
        return false;
    };
    if !token.is_tip20() {
        return false;
    }

    matches!(
        ITIP20::ITIP20Calls::abi_decode(input),
        Ok(ITIP20::ITIP20Calls::transfer(_)
            | ITIP20::ITIP20Calls::transferWithMemo(_)
            | ITIP20::ITIP20Calls::transferFrom(_)
            | ITIP20::ITIP20Calls::transferFromWithMemo(_))
    )
}

fn storage_touches_for_transaction(
    tx: &BestTransaction,
    fee_recipient: Address,
) -> Vec<StorageTouch> {
    let mut touches = Vec::new();
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
    Advance,
    Invalid {
        invalid: InvalidTransaction,
        old_rx: Receiver<Option<BestTransaction>>,
        new_tx: Sender<Option<BestTransaction>>,
    },
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
    use alloy_consensus::{BlockHeader, Header, Signed, TxLegacy};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use alloy_sol_types::SolCall;
    use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
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
    use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
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
        test_tx_with_gas_limit(sender, nonce, 21_000)
    }

    fn test_tx_with_gas_limit(sender: Address, nonce: u64, gas_limit: u64) -> BestTransaction {
        let tx = TxLegacy {
            chain_id: Some(42431),
            nonce,
            gas_price: 20_000_000_000,
            gas_limit,
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

    struct TestPrewarming {
        prewarming: Option<BestTransactionsPrewarming>,
        executor: TaskExecutor,
    }

    impl Drop for TestPrewarming {
        fn drop(&mut self) {
            drop(self.prewarming.take());
            self.executor
                .spawn_blocking_named("builder-prewarm", || {})
                .get();
        }
    }

    impl std::ops::Deref for TestPrewarming {
        type Target = BestTransactionsPrewarming;

        fn deref(&self) -> &Self::Target {
            self.prewarming.as_ref().expect("prewarming exists")
        }
    }

    impl std::ops::DerefMut for TestPrewarming {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.prewarming.as_mut().expect("prewarming exists")
        }
    }

    fn prewarming(txs: Vec<BestTransaction>, log: Arc<Mutex<TestLog>>) -> TestPrewarming {
        let executor = TaskExecutor::test();
        prewarming_with_executor(executor, txs, log)
    }

    fn prewarming_with_executor(
        executor: TaskExecutor,
        txs: Vec<BestTransaction>,
        log: Arc<Mutex<TestLog>>,
    ) -> TestPrewarming {
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
        let attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: 2,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                gas_limit: parent_header.gas_limit(),
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data: Default::default(),
                slot_number: None,
            },
            general_gas_limit: 30_000_000,
            shared_gas_limit: 0,
            timestamp_millis_part: 0,
            consensus_context: None,
            subblock_fee_recipients: Default::default(),
        };
        let evm_env = evm_config
            .next_evm_env(&parent_header, &attributes)
            .expect("test next block env");
        let prewarming = BestTransactionsPrewarming::new(
            executor.clone(),
            provider,
            None,
            parent_header.hash(),
            evm_env,
            TestBestTransactions::new(txs, log),
        );
        TestPrewarming {
            prewarming: Some(prewarming),
            executor,
        }
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
    fn tip20_fast_path_is_limited_to_transfers() {
        let token = DEFAULT_FEE_TOKEN;
        let transfer = Bytes::from(
            ITIP20::transferCall {
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );
        let transfer_from = Bytes::from(
            ITIP20::transferFromCall {
                from: Address::random(),
                to: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );
        let approve = Bytes::from(
            ITIP20::approveCall {
                spender: Address::random(),
                amount: U256::from(1),
            }
            .abi_encode(),
        );

        assert!(is_tip20_transfer_call(TxKind::Call(token), &transfer));
        assert!(is_tip20_transfer_calls(
            [&transfer, &transfer_from]
                .into_iter()
                .map(|input| (TxKind::Call(token), input)),
        ));
        assert!(!is_tip20_transfer_call(TxKind::Call(token), &approve));
        assert!(!is_tip20_transfer_calls(
            [&transfer, &approve]
                .into_iter()
                .map(|input| (TxKind::Call(token), input)),
        ));
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
    fn prewarming_eagerly_drains_source_iterator() {
        let sender = Address::random();
        let executor = TaskExecutor::test();
        let txs = (0..executor.prewarming_pool().current_num_threads() * 2 + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming_with_executor(executor, txs, log.clone());
        wait_until(|| log.lock().unwrap().yielded == expected.len());

        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").hash())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn empty_source_is_polled_for_eager_advances_and_each_consumer_advance() {
        let executor = TaskExecutor::test();
        let eager_advances = executor.prewarming_pool().current_num_threads() * 2;
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor, Vec::new(), log.clone());

        wait_until(|| log.lock().unwrap().empty_polls == eager_advances);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == eager_advances + 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == eager_advances + 2);
    }

    #[test]
    fn mark_invalid_filters_already_buffered_invalidated_transactions() {
        let sender = Address::random();
        let mut sender_nonces = 0..;
        let tx1 = test_tx(sender, sender_nonces.next().expect("first nonce"));
        let tx2 = test_tx(sender, sender_nonces.next().expect("second nonce"));
        let tx3 = test_tx(
            Address::random(),
            sender_nonces.next().expect("third nonce"),
        );
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

    #[test]
    fn prewarming_does_not_use_shared_worker_state_slot() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();
        pool.init::<usize>(|existing| existing.map(|value| *value).unwrap_or(1));

        let sender = Address::random();
        let txs = vec![test_tx(sender, 0)];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor.clone(), txs, log);

        assert!(prewarming.next().is_some());

        pool.broadcast(pool.current_num_threads(), |worker| {
            assert_eq!(*worker.get::<usize>(), 1);
        });
    }
}
