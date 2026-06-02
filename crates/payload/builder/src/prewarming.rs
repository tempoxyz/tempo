use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender, SyncSender},
};

use alloy_primitives::{Address, B256, Bytes, TxKind, U256, map::U256Map};
use alloy_sol_types::SolInterface;
use reth_engine_tree::tree::{CachedStateProvider, SavedCache};
use reth_evm::{Database, Evm, EvmEnvFor};
use reth_revm::{
    Database as RevmDatabase,
    cached::{CachedAccount, CachedReads},
    database::StateProviderDatabase,
    primitives::{StorageKey, StorageValue},
    state::{AccountId, AccountInfo, Bytecode},
};
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

#[derive(Clone)]
pub(crate) struct PrewarmingBuffers {
    buffers_tx: SyncSender<CachedReads>,
    buffers_rx: Arc<Mutex<Receiver<CachedReads>>>,
    capacity: usize,
}

impl PrewarmingBuffers {
    pub(crate) fn for_executor(executor: &TaskExecutor) -> Self {
        Self::new(executor.prewarming_pool().current_num_threads() * 2)
    }

    fn new(capacity: usize) -> Self {
        let (buffers_tx, buffers_rx) = mpsc::sync_channel(capacity);
        Self {
            buffers_tx,
            buffers_rx: Arc::new(Mutex::new(buffers_rx)),
            capacity,
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn overlay(&self) -> PrewarmedOverlay {
        PrewarmedOverlay::new(self.buffers_tx.clone())
    }

    fn cached_reads(&self) -> CachedReads {
        self.try_cached_reads().unwrap_or_default()
    }

    fn try_cached_reads(&self) -> Option<CachedReads> {
        let Ok(buffers_rx) = self.buffers_rx.lock() else {
            return None;
        };
        buffers_rx.try_recv().ok()
    }
}

impl core::fmt::Debug for PrewarmingBuffers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrewarmingBuffers")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: Receiver<Option<BestTransactionWithOverlay>>,
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
        buffers: PrewarmingBuffers,
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
                    buffers,
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
        let buffer_capacity = ctx.buffers.capacity();

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
                let overlay = ctx.buffers.overlay();
                let transaction = (tx.clone(), overlay.clone());
                let _ = ctx.transactions_tx.send(Some(transaction));
                let cached_reads = ctx.buffers.cached_reads();

                let prewarm = ctx.prewarm.clone();
                let commands_tx = ctx.commands_tx.clone();
                scope.spawn(move |_| {
                    Self::prewarm_transaction(prewarm, tx.clone(), overlay, cached_reads);
                    let _ = commands_tx.send(BestTransactionsCommand::Advance);
                });
            };

            // Fill the initial batch of transactions to execute and prewarm.
            //
            // We schedule 2x the number of threads to make sure that workers are never idle.
            for _ in 0..buffer_capacity {
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
                            if let Some(tx) = tx {
                                if !is_invalidated_buffered_transaction(&invalid.tx, &tx.0) {
                                    let _ = ctx.transactions_tx.send(Some(tx));
                                } else {
                                    tx.1.recycle();
                                }
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
        overlay: PrewarmedOverlay,
        mut cached_reads: CachedReads,
    ) where
        Provider: StateProviderFactory + Clone + 'static,
    {
        if prewarm.is_stopped() {
            overlay.recycle_cached_reads(cached_reads);
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
                        overlay.recycle_cached_reads(cached_reads);
                        return;
                    }
                    if let Err(err) = touch.warm(evm, &mut cached_reads) {
                        trace!(
                            target: "payload_builder",
                            %err,
                            ?tx_hash,
                            "Failed to prewarm transaction storage"
                        );
                        overlay.recycle_cached_reads(cached_reads);
                        return;
                    }
                }

                overlay.publish(cached_reads);
                Some(touches.len())
            } else {
                if prewarm.is_stopped() {
                    overlay.recycle_cached_reads(cached_reads);
                    return;
                }

                if let Err(err) = evm.transact_raw(tx.transaction.clone_tx_env()) {
                    trace!(
                        target: "payload_builder",
                        %err,
                        ?tx_hash,
                        "Failed to prewarm transaction by execution"
                    );
                    overlay.recycle_cached_reads(cached_reads);
                    return;
                }

                overlay.recycle_cached_reads(cached_reads);
                None
            };

            drop(overlay);
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
    type Item = BestTransactionWithOverlay;

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
                tx: transaction.0.clone(),
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

#[derive(Clone)]
pub(crate) struct PrewarmedOverlay {
    reads: Arc<OnceLock<CachedReads>>,
    buffers_tx: SyncSender<CachedReads>,
}

impl PrewarmedOverlay {
    fn new(buffers_tx: SyncSender<CachedReads>) -> Self {
        Self {
            reads: Arc::new(OnceLock::new()),
            buffers_tx,
        }
    }

    fn get(&self) -> Option<&CachedReads> {
        self.reads.get()
    }

    fn publish(&self, cached_reads: CachedReads) {
        if let Err(cached_reads) = self.reads.set(cached_reads) {
            self.recycle_cached_reads(cached_reads);
        }
    }

    pub(crate) fn recycle(mut self) {
        self.recycle_published_reads();
    }

    fn recycle_cached_reads(&self, cached_reads: CachedReads) {
        Self::recycle_to(&self.buffers_tx, cached_reads);
    }

    fn recycle_published_reads(&mut self) {
        let Some(reads) = Arc::get_mut(&mut self.reads) else {
            return;
        };
        if let Some(cached_reads) = reads.take() {
            Self::recycle_to(&self.buffers_tx, cached_reads);
        }
    }

    fn recycle_to(buffers_tx: &SyncSender<CachedReads>, mut cached_reads: CachedReads) {
        clear_cached_reads(&mut cached_reads);
        let _ = buffers_tx.try_send(cached_reads);
    }
}

impl core::fmt::Debug for PrewarmedOverlay {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrewarmedOverlay")
            .field("published", &self.reads.get().is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for PrewarmedOverlay {
    fn drop(&mut self) {
        self.recycle_published_reads();
    }
}

pub(crate) type BestTransactionWithOverlay = (BestTransaction, PrewarmedOverlay);

fn clear_cached_reads(cached_reads: &mut CachedReads) {
    cached_reads.accounts.clear();
    cached_reads.contracts.clear();
    cached_reads.block_hashes.clear();
}

/// Context for prewarming best transactions for a payload build.
struct BestTransactionsPrewarmingContext<Txs, Provider> {
    best_txs: Txs,
    transactions_tx: Sender<Option<BestTransactionWithOverlay>>,
    commands_tx: Sender<BestTransactionsCommand>,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
    buffers: PrewarmingBuffers,
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
    fn warm<DB: Database>(
        &self,
        evm: &mut TempoEvm<DB>,
        overlay: &mut CachedReads,
    ) -> Result<(), DB::Error> {
        match *self {
            Self::Account(address) => {
                let account = evm.db_mut().basic(address)?;
                overlay
                    .accounts
                    .entry(address)
                    .or_insert_with(|| CachedAccount {
                        info: account,
                        storage: U256Map::default(),
                    });
            }
            Self::Storage { address, slot } => {
                let value = evm.db_mut().storage(address, slot)?;
                overlay
                    .accounts
                    .entry(address)
                    .or_insert_with(|| CachedAccount {
                        info: None,
                        storage: U256Map::default(),
                    })
                    .storage
                    .insert(slot, value);
            }
        }

        Ok(())
    }
}

/// Database wrapper that serves reads from the current transaction's prewarmed overlay first.
#[derive(Debug)]
pub(crate) struct PrewarmedStateOverlay<DB> {
    db: DB,
    overlay: Option<PrewarmedOverlay>,
}

impl<DB> PrewarmedStateOverlay<DB> {
    pub(crate) const fn new(db: DB) -> Self {
        Self { db, overlay: None }
    }

    pub(crate) fn set_overlay(&mut self, overlay: PrewarmedOverlay) {
        self.overlay = Some(overlay);
    }

    pub(crate) fn clear_overlay(&mut self) {
        self.overlay = None;
    }

    fn overlay_basic(&self, address: Address) -> Option<AccountInfo> {
        let overlay = self.overlay.as_ref()?.get()?;
        overlay
            .accounts
            .get(&address)
            .and_then(|account| account.info.clone())
    }

    fn overlay_storage(&self, address: Address, slot: StorageKey) -> Option<StorageValue> {
        let overlay = self.overlay.as_ref()?.get()?;
        overlay
            .accounts
            .get(&address)
            .and_then(|account| account.storage.get(&slot).copied())
    }

    fn overlay_code(&self, code_hash: B256) -> Option<Bytecode> {
        let overlay = self.overlay.as_ref()?.get()?;
        overlay.contracts.get(&code_hash).cloned()
    }

    fn overlay_block_hash(&self, number: u64) -> Option<B256> {
        let overlay = self.overlay.as_ref()?.get()?;
        overlay.block_hashes.get(&number).copied()
    }
}

impl<DB> RevmDatabase for PrewarmedStateOverlay<DB>
where
    DB: Database,
{
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.overlay_basic(address) {
            return Ok(Some(account));
        }
        self.db.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.overlay_code(code_hash) {
            return Ok(code);
        }
        self.db.code_by_hash(code_hash)
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if let Some(value) = self.overlay_storage(address, index) {
            return Ok(value);
        }
        self.db.storage(address, index)
    }

    fn storage_by_account_id(
        &mut self,
        address: Address,
        account_id: AccountId,
        storage_key: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if let Some(value) = self.overlay_storage(address, storage_key) {
            return Ok(value);
        }
        self.db
            .storage_by_account_id(address, account_id, storage_key)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        if let Some(hash) = self.overlay_block_hash(number) {
            return Ok(hash);
        }
        self.db.block_hash(number)
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
        old_rx: Receiver<Option<BestTransactionWithOverlay>>,
        new_tx: Sender<Option<BestTransactionWithOverlay>>,
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
        convert::Infallible,
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

    #[derive(Debug, Clone)]
    struct TestOverlayDb {
        account: AccountInfo,
        storage: U256,
        code: Bytecode,
        block_hash: B256,
    }

    impl Default for TestOverlayDb {
        fn default() -> Self {
            Self {
                account: AccountInfo {
                    balance: U256::from(1),
                    ..Default::default()
                },
                storage: U256::from(2),
                code: Bytecode::default(),
                block_hash: B256::with_last_byte(3),
            }
        }
    }

    impl RevmDatabase for TestOverlayDb {
        type Error = Infallible;

        fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(Some(self.account.clone()))
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(self.code.clone())
        }

        fn storage(
            &mut self,
            _address: Address,
            _index: StorageKey,
        ) -> Result<StorageValue, Self::Error> {
            Ok(self.storage)
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(self.block_hash)
        }
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
            PrewarmingBuffers::for_executor(&executor),
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
            .map(|_| *prewarming.next().expect("transaction").0.hash())
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
            .map(|_| *prewarming.next().expect("transaction").0.hash())
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
        let first = prewarming.next().expect("first transaction");
        assert_eq!(first.0.hash(), tx1.hash());

        wait_until(|| log.lock().unwrap().yielded == 3);
        prewarming.mark_invalid(
            &first,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.0.hash(), tx3.hash());
        assert_ne!(next.0.hash(), tx2.hash());
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
    fn prewarmed_state_overlay_reads_published_cache_without_locking() {
        let address = Address::random();
        let slot = U256::from(7);
        let code_hash = B256::with_last_byte(8);
        let block_number = 9;
        let overlay_account = AccountInfo {
            balance: U256::from(10),
            ..Default::default()
        };
        let overlay_storage = U256::from(11);
        let overlay_code = Bytecode::default();
        let overlay_block_hash = B256::with_last_byte(12);

        let mut storage = U256Map::default();
        storage.insert(slot, overlay_storage);
        let mut cached_reads = CachedReads::default();
        cached_reads.accounts.insert(
            address,
            CachedAccount {
                info: Some(overlay_account.clone()),
                storage,
            },
        );
        cached_reads
            .contracts
            .insert(code_hash, overlay_code.clone());
        cached_reads
            .block_hashes
            .insert(block_number, overlay_block_hash);

        let (buffers_tx, _buffers_rx) = std::sync::mpsc::sync_channel(1);
        let overlay = PrewarmedOverlay::new(buffers_tx);
        overlay.publish(cached_reads);

        let mut db = PrewarmedStateOverlay::new(TestOverlayDb::default());
        db.set_overlay(overlay);

        assert_eq!(db.basic(address), Ok(Some(overlay_account)));
        assert_eq!(db.storage(address, slot), Ok(overlay_storage));
        assert_eq!(db.code_by_hash(code_hash), Ok(overlay_code));
        assert_eq!(db.block_hash(block_number), Ok(overlay_block_hash));
    }

    #[test]
    fn prewarmed_state_overlay_falls_back_when_cache_is_unset() {
        let address = Address::random();
        let slot = U256::from(7);
        let block_number = 9;
        let fallback = TestOverlayDb::default();
        let mut db = PrewarmedStateOverlay::new(fallback.clone());

        let (buffers_tx, _buffers_rx) = std::sync::mpsc::sync_channel(1);
        db.set_overlay(PrewarmedOverlay::new(buffers_tx));

        assert_eq!(db.basic(address), Ok(Some(fallback.account)));
        assert_eq!(db.storage(address, slot), Ok(fallback.storage));
        assert_eq!(db.code_by_hash(B256::ZERO), Ok(fallback.code));
        assert_eq!(db.block_hash(block_number), Ok(fallback.block_hash));
    }

    #[test]
    fn prewarmed_overlay_recycles_published_cached_reads() {
        let (buffers_tx, buffers_rx) = std::sync::mpsc::sync_channel(1);
        let overlay = PrewarmedOverlay::new(buffers_tx);
        let address = Address::random();
        let slot = U256::from(7);

        let mut storage = U256Map::default();
        storage.insert(slot, U256::from(11));
        let mut cached_reads = CachedReads::default();
        cached_reads.accounts.insert(
            address,
            CachedAccount {
                info: Some(AccountInfo::default()),
                storage,
            },
        );
        cached_reads
            .contracts
            .insert(B256::with_last_byte(8), Bytecode::default());
        cached_reads
            .block_hashes
            .insert(9, B256::with_last_byte(12));

        overlay.publish(cached_reads);
        overlay.recycle();

        let recycled = buffers_rx.try_recv().expect("recycled buffer");
        assert!(recycled.accounts.is_empty());
        assert!(recycled.contracts.is_empty());
        assert!(recycled.block_hashes.is_empty());
    }

    #[test]
    fn prewarmed_overlay_recycles_published_cached_reads_on_drop() {
        let buffers = PrewarmingBuffers::new(1);
        let overlay = buffers.overlay();
        let address = Address::random();
        let slot = U256::from(7);

        let mut storage = U256Map::default();
        storage.insert(slot, U256::from(11));
        let mut cached_reads = CachedReads::default();
        cached_reads.accounts.insert(
            address,
            CachedAccount {
                info: Some(AccountInfo::default()),
                storage,
            },
        );

        overlay.publish(cached_reads);
        drop(overlay);

        let recycled = buffers
            .try_cached_reads()
            .expect("published reads should be recycled");
        assert!(recycled.accounts.is_empty());
    }

    #[test]
    fn prewarmed_overlay_recycle_is_nonblocking_when_still_shared() {
        let (buffers_tx, buffers_rx) = std::sync::mpsc::sync_channel(1);
        let overlay = PrewarmedOverlay::new(buffers_tx);
        let shared = overlay.clone();

        overlay.publish(CachedReads::default());
        overlay.recycle();

        assert!(buffers_rx.try_recv().is_err());
        drop(shared);
    }

    #[test]
    fn prewarming_initializes_worker_evm_state() {
        let executor = TaskExecutor::test();
        let pool = executor.prewarming_pool();

        let sender = Address::random();
        let txs = vec![test_tx(sender, 0)];
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor.clone(), txs, log);

        assert!(prewarming.next().is_some());

        wait_until(|| {
            let initialized = AtomicBool::new(true);
            pool.broadcast(pool.current_num_threads(), |worker| {
                if worker.get_or_init::<PrewarmEvmState>(|| None).is_none() {
                    initialized.store(false, Ordering::Relaxed);
                }
            });
            initialized.load(Ordering::Relaxed)
        });
    }
}
