use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
    },
};

use alloy_primitives::{
    Address, B256, Bytes, TxKind, U256,
    map::{Entry, U256Map},
};
use alloy_sol_types::SolInterface;
use reth_evm::{Database, Evm, EvmEnvFor};
use reth_revm::{
    Database as RevmDatabase,
    cached::{CachedAccount, CachedReads},
    database::StateProviderDatabase,
    state::{AccountInfo, Bytecode},
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
use tempo_transaction_pool::best::{AsBestTransaction, BestTransaction};
use tracing::trace;

type PrewarmStateProviderDatabase = StateProviderDatabase<StateProviderBox>;
type PrewarmEvmState = Option<TempoEvm<PrewarmDatabase<PrewarmStateProviderDatabase>>>;

/// Worker-local database used by prewarming.
///
/// `cached` accumulates reads across transactions on the same worker, while `recording` is swapped
/// in per transaction so those reads can be handed to builder execution as an overlay.
#[derive(Debug)]
struct PrewarmDatabase<DB> {
    db: DB,
    cached: CachedReads,
    recording: Option<CachedReads>,
}

impl<DB> PrewarmDatabase<DB> {
    fn new(db: DB) -> Self {
        Self {
            db,
            cached: CachedReads::default(),
            recording: None,
        }
    }

    fn start_recording(&mut self, cached: CachedReads) {
        debug_assert!(self.recording.is_none());
        self.recording = Some(cached);
    }

    fn finish_recording(&mut self) -> CachedReads {
        self.recording.take().unwrap_or_default()
    }

    fn record_basic(&mut self, address: Address, info: &Option<AccountInfo>) {
        if let Some(recording) = &mut self.recording {
            recording
                .accounts
                .entry(address)
                .or_insert_with(|| CachedAccount {
                    info: info.clone(),
                    storage: U256Map::default(),
                });
        }
    }

    fn record_storage(
        &mut self,
        address: Address,
        index: U256,
        info: &Option<AccountInfo>,
        value: U256,
    ) {
        if let Some(recording) = &mut self.recording {
            let account = recording
                .accounts
                .entry(address)
                .or_insert_with(|| CachedAccount {
                    info: info.clone(),
                    storage: U256Map::default(),
                });
            if info.is_some() {
                account.storage.entry(index).or_insert(value);
            }
        }
    }

    fn record_code(&mut self, code_hash: B256, code: &Bytecode) {
        if let Some(recording) = &mut self.recording {
            recording
                .contracts
                .entry(code_hash)
                .or_insert_with(|| code.clone());
        }
    }

    fn record_block_hash(&mut self, number: u64, hash: B256) {
        if let Some(recording) = &mut self.recording {
            recording.block_hashes.entry(number).or_insert(hash);
        }
    }
}

impl<DB: RevmDatabase> RevmDatabase for PrewarmDatabase<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let info = match self.cached.accounts.entry(address) {
            Entry::Occupied(entry) => entry.get().info.clone(),
            Entry::Vacant(entry) => {
                let info = self.db.basic(address)?;
                entry.insert(CachedAccount {
                    info: info.clone(),
                    storage: U256Map::default(),
                });
                info
            }
        };

        self.record_basic(address, &info);
        Ok(info)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let code = match self.cached.contracts.entry(code_hash) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => entry.insert(self.db.code_by_hash(code_hash)?).clone(),
        };

        self.record_code(code_hash, &code);
        Ok(code)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let (info, value) = match self.cached.accounts.entry(address) {
            Entry::Occupied(mut acc_entry) => {
                let info = acc_entry.get().info.clone();
                if info.is_some() {
                    let value = match acc_entry.get_mut().storage.entry(index) {
                        Entry::Occupied(entry) => *entry.get(),
                        Entry::Vacant(entry) => *entry.insert(self.db.storage(address, index)?),
                    };
                    (info, value)
                } else {
                    (info, U256::ZERO)
                }
            }
            Entry::Vacant(acc_entry) => {
                let info = self.db.basic(address)?;
                if info.is_some() {
                    let value = self.db.storage(address, index)?;
                    let mut account = CachedAccount {
                        info: info.clone(),
                        storage: U256Map::default(),
                    };
                    account.storage.insert(index, value);
                    acc_entry.insert(account);
                    (info, value)
                } else {
                    acc_entry.insert(CachedAccount {
                        info: None,
                        storage: U256Map::default(),
                    });
                    (info, U256::ZERO)
                }
            }
        };

        self.record_storage(address, index, &info, value);
        Ok(value)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        let hash = match self.cached.block_hashes.entry(number) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => *entry.insert(self.db.block_hash(number)?),
        };

        self.record_block_hash(number, hash);
        Ok(hash)
    }
}

/// A reusable map containing reads collected by prewarming one transaction.
#[derive(Debug)]
pub(crate) struct PooledPrewarmedState {
    cached: Option<CachedReads>,
    pool: PrewarmedStatePool,
}

impl PooledPrewarmedState {
    fn cached(&self) -> &CachedReads {
        self.cached.as_ref().expect("pooled state is present")
    }

    #[cfg(test)]
    fn cached_mut(&mut self) -> &mut CachedReads {
        self.cached.as_mut().expect("pooled state is present")
    }

    fn take_cached(&mut self) -> CachedReads {
        self.cached.take().expect("pooled state is present")
    }

    fn replace_cached(&mut self, cached: CachedReads) {
        debug_assert!(self.cached.is_none());
        self.cached = Some(cached);
    }
}

impl Drop for PooledPrewarmedState {
    fn drop(&mut self) {
        if let Some(cached) = self.cached.take() {
            self.pool.recycle(cached);
        }
    }
}

/// Small pool for prewarmed state maps so repeated payload builds do not reallocate.
#[derive(Clone, Debug, Default)]
struct PrewarmedStatePool {
    inner: Arc<Mutex<Vec<CachedReads>>>,
    max_idle: usize,
}

impl PrewarmedStatePool {
    fn new(max_idle: usize) -> Self {
        Self {
            inner: Default::default(),
            max_idle,
        }
    }

    fn take(&self) -> PooledPrewarmedState {
        let cached = self.inner.lock().expect("prewarmed state pool").pop();
        PooledPrewarmedState {
            cached: Some(cached.unwrap_or_default()),
            pool: self.clone(),
        }
    }

    fn recycle(&self, mut cached: CachedReads) {
        cached.accounts.clear();
        cached.contracts.clear();
        cached.block_hashes.clear();

        let mut inner = self.inner.lock().expect("prewarmed state pool");
        if inner.len() < self.max_idle {
            inner.push(cached);
        }
    }
}

/// Best transaction plus the parent-state reads collected while prewarming it.
pub(crate) struct PrewarmedBestTransaction {
    tx: BestTransaction,
    prewarmed_state: Option<PooledPrewarmedState>,
}

impl PrewarmedBestTransaction {
    pub(crate) fn without_prewarmed_state(tx: BestTransaction) -> Self {
        Self {
            tx,
            prewarmed_state: None,
        }
    }

    fn new(tx: BestTransaction, prewarmed_state: PooledPrewarmedState) -> Self {
        Self {
            tx,
            prewarmed_state: Some(prewarmed_state),
        }
    }

    pub(crate) fn transaction(&self) -> &BestTransaction {
        &self.tx
    }

    pub(crate) fn take_prewarmed_state(&mut self) -> Option<PooledPrewarmedState> {
        self.prewarmed_state.take()
    }

    pub(crate) fn into_transaction(self) -> BestTransaction {
        self.tx
    }
}

impl AsBestTransaction for PrewarmedBestTransaction {
    fn as_best_transaction(&self) -> &BestTransaction {
        &self.tx
    }
}

/// Adapts a regular best-transaction iterator to the prewarmed item shape.
pub(crate) struct BestTransactionsWithoutPrewarming<Txs> {
    inner: Txs,
}

impl<Txs> BestTransactionsWithoutPrewarming<Txs> {
    pub(crate) const fn new(inner: Txs) -> Self {
        Self { inner }
    }
}

impl<Txs> Iterator for BestTransactionsWithoutPrewarming<Txs>
where
    Txs: BestTransactions<Item = BestTransaction>,
{
    type Item = PrewarmedBestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(PrewarmedBestTransaction::without_prewarmed_state)
    }
}

impl<Txs> BestTransactions for BestTransactionsWithoutPrewarming<Txs>
where
    Txs: BestTransactions<Item = BestTransaction>,
{
    fn mark_invalid(&mut self, transaction: &Self::Item, kind: InvalidPoolTransactionError) {
        self.inner.mark_invalid(transaction.transaction(), kind);
    }

    fn no_updates(&mut self) {
        self.inner.no_updates();
    }

    fn set_skip_blobs(&mut self, skip_blobs: bool) {
        self.inner.set_skip_blobs(skip_blobs);
    }
}

/// Database wrapper that serves reads from the current transaction's prewarmed overlay first.
#[derive(Debug)]
pub(crate) struct PrewarmedStateOverlay<DB> {
    db: DB,
    overlay: Option<PooledPrewarmedState>,
}

impl<DB> PrewarmedStateOverlay<DB> {
    pub(crate) const fn new(db: DB) -> Self {
        Self { db, overlay: None }
    }

    pub(crate) fn set_overlay(&mut self, overlay: Option<PooledPrewarmedState>) {
        self.overlay = overlay;
    }

    pub(crate) fn clear_overlay(&mut self) {
        self.overlay = None;
    }
}

impl<DB: RevmDatabase> RevmDatabase for PrewarmedStateOverlay<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.cached().accounts.get(&address))
        {
            return Ok(account.info.clone());
        }

        self.db.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.cached().contracts.get(&code_hash))
        {
            return Ok(code.clone());
        }

        self.db.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(account) = self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.cached().accounts.get(&address))
        {
            if let Some(value) = account.storage.get(&index) {
                return Ok(*value);
            }
            if account.info.is_none() {
                return Ok(U256::ZERO);
            }
        }

        self.db.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        if let Some(hash) = self
            .overlay
            .as_ref()
            .and_then(|overlay| overlay.cached().block_hashes.get(&number))
        {
            return Ok(*hash);
        }

        self.db.block_hash(number)
    }
}

/// Prewarming orchestrator that consumes source [`BestTransactions`] with bounded
/// lookahead, prewarms buffered transactions in parallel, and produces a new
/// [`BestTransactions`] iterator with the source order and invalidations triggered
/// by [`Self::mark_invalid`] preserved.
pub(crate) struct BestTransactionsPrewarming {
    transactions_rx: Receiver<Option<PrewarmedBestTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    stop: Arc<AtomicBool>,
}

impl BestTransactionsPrewarming {
    /// Spawns prewarming for `best_txs` and returns a new [`BestTransactions`] iterator.
    pub(crate) fn new<Txs, Provider>(
        executor: TaskExecutor,
        provider: Provider,
        parent_hash: B256,
        evm_env: EvmEnvFor<TempoEvmConfig>,
        best_txs: Txs,
    ) -> Self
    where
        Txs: BestTransactions<Item = BestTransaction> + Send + 'static,
        Provider: StateProviderFactory + Clone + 'static,
    {
        let max_lookahead = (executor.prewarming_pool().current_num_threads() * 2).max(1);
        let state_pool = PrewarmedStatePool::new(max_lookahead);
        let (transactions_tx, transactions_rx) = mpsc::channel();
        let (commands_tx, commands_rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let prewarm = PrewarmingExecutionContext {
            provider,
            parent_hash,
            evm_env,
            stop: stop.clone(),
            state_pool,
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
                    max_lookahead,
                    next_sequence: 0,
                    next_emit_sequence: 0,
                    source_exhausted: false,
                    in_flight: BTreeMap::new(),
                    ready: BTreeMap::new(),
                    skipped: HashSet::new(),
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
        let prewarm = ctx.prewarm.clone();
        pool.init::<PrewarmEvmState>(|_| prewarm.evm_for_ctx());

        pool.in_place_scope(|scope| {
            let mut advance = |ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>| {
                let Some(tx) = ctx.best_txs.next() else {
                    ctx.source_exhausted = true;
                    return;
                };

                let sequence = ctx.next_sequence;
                ctx.next_sequence += 1;
                ctx.in_flight.insert(sequence, tx.clone());
                let prewarm = ctx.prewarm.clone();
                let commands_tx = ctx.commands_tx.clone();
                scope.spawn(move |_| {
                    let result = Self::prewarm_transaction(prewarm, sequence, tx);
                    let _ = commands_tx.send(BestTransactionsCommand::Prewarmed(result));
                });
            };

            Self::fill_lookahead(&mut ctx, &mut advance);
            Self::emit_ready(&mut ctx);

            while let Ok(command) = ctx.commands_rx.recv() {
                match command {
                    BestTransactionsCommand::Advance => {
                        Self::fill_lookahead(&mut ctx, &mut advance);
                        Self::emit_ready(&mut ctx);
                    }
                    BestTransactionsCommand::Prewarmed(result) => {
                        ctx.in_flight.remove(&result.sequence);
                        if ctx.skipped.remove(&result.sequence) {
                            continue;
                        }
                        ctx.ready.insert(
                            result.sequence,
                            PrewarmedBestTransaction::new(result.tx, result.state),
                        );
                        Self::emit_ready(&mut ctx);
                    }
                    BestTransactionsCommand::Invalid {
                        invalid,
                        old_rx,
                        new_tx,
                    } => {
                        ctx.best_txs.mark_invalid(&invalid.tx, invalid.kind);
                        ctx.transactions_tx = new_tx;

                        for tx in old_rx {
                            match tx {
                                Some(tx)
                                    if !is_invalidated_buffered_transaction(
                                        &invalid.tx,
                                        tx.transaction(),
                                    ) =>
                                {
                                    let _ = ctx.transactions_tx.send(Some(tx));
                                }
                                Some(_) => {}
                                None => {
                                    let _ = ctx.transactions_tx.send(None);
                                }
                            }
                        }

                        ctx.ready.retain(|sequence, tx| {
                            let keep =
                                !is_invalidated_buffered_transaction(&invalid.tx, tx.transaction());
                            if !keep {
                                ctx.skipped.insert(*sequence);
                            }
                            keep
                        });
                        for (sequence, tx) in &ctx.in_flight {
                            if is_invalidated_buffered_transaction(&invalid.tx, tx) {
                                ctx.skipped.insert(*sequence);
                            }
                        }
                        Self::emit_ready(&mut ctx);
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
        WorkerPool::with_worker_mut(|worker| worker.clear());
    }

    fn fill_lookahead<Txs, Provider>(
        ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>,
        advance: &mut impl FnMut(&mut BestTransactionsPrewarmingContext<Txs, Provider>),
    ) where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        while !ctx.source_exhausted && ctx.in_flight.len() + ctx.ready.len() < ctx.max_lookahead {
            advance(ctx);
        }
    }

    fn emit_ready<Txs, Provider>(ctx: &mut BestTransactionsPrewarmingContext<Txs, Provider>)
    where
        Txs: BestTransactions<Item = BestTransaction>,
        Provider: StateProviderFactory + Clone + 'static,
    {
        while ctx.skipped.remove(&ctx.next_emit_sequence) {
            ctx.next_emit_sequence += 1;
        }

        while let Some(tx) = ctx.ready.remove(&ctx.next_emit_sequence) {
            let _ = ctx.transactions_tx.send(Some(tx));
            ctx.next_emit_sequence += 1;
            while ctx.skipped.remove(&ctx.next_emit_sequence) {
                ctx.next_emit_sequence += 1;
            }
        }

        if ctx.source_exhausted && ctx.in_flight.is_empty() && ctx.ready.is_empty() {
            let _ = ctx.transactions_tx.send(None);
        }
    }

    fn prewarm_transaction<Provider>(
        prewarm: PrewarmingExecutionContext<Provider>,
        sequence: u64,
        tx: BestTransaction,
    ) -> PrewarmResult
    where
        Provider: StateProviderFactory + Clone + 'static,
    {
        let mut state = prewarm.state_pool.take();
        if prewarm.is_stopped() {
            return PrewarmResult {
                sequence,
                tx,
                state,
            };
        }

        WorkerPool::with_worker_mut(|worker| {
            let Some(evm) = worker.get_or_init::<PrewarmEvmState>(|| prewarm.evm_for_ctx()) else {
                return;
            };

            evm.db_mut().start_recording(state.take_cached());

            let tx_hash = *tx.hash();

            let touched = 'prewarm: {
                if is_tip20_transfer_transaction(&tx) {
                    let touches =
                        storage_touches_for_transaction(&tx, prewarm.evm_env.block_env.beneficiary);

                    for touch in &touches {
                        if prewarm.is_stopped() {
                            break 'prewarm None;
                        }
                        if let Err(err) = touch.warm(evm) {
                            trace!(
                                target: "payload_builder",
                                %err,
                                ?tx_hash,
                                "Failed to prewarm transaction storage"
                            );
                            break 'prewarm None;
                        }
                    }

                    Some(Some(touches.len()))
                } else {
                    if prewarm.is_stopped() {
                        break 'prewarm None;
                    }

                    if let Err(err) = evm.transact_raw(tx.transaction.clone_tx_env()) {
                        trace!(
                            target: "payload_builder",
                            %err,
                            ?tx_hash,
                            "Failed to prewarm transaction by execution"
                        );
                        break 'prewarm None;
                    }

                    Some(None)
                }
            };

            let cached = evm.db_mut().finish_recording();
            state.replace_cached(cached);

            if let Some(touched) = touched {
                trace!(
                    target: "payload_builder",
                    touched,
                    ?tx_hash,
                    "Prewarmed transaction"
                );
            }
        });

        PrewarmResult {
            sequence,
            tx,
            state,
        }
    }
}

impl Drop for BestTransactionsPrewarming {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.commands_tx.send(BestTransactionsCommand::Stop);
    }
}

impl Iterator for BestTransactionsPrewarming {
    type Item = PrewarmedBestTransaction;

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(Some(tx)) = self.transactions_rx.try_recv() {
            let _ = self.commands_tx.send(BestTransactionsCommand::Advance);
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
                tx: transaction.transaction().clone(),
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
    transactions_tx: Sender<Option<PrewarmedBestTransaction>>,
    commands_tx: Sender<BestTransactionsCommand>,
    commands_rx: Receiver<BestTransactionsCommand>,
    prewarm: PrewarmingExecutionContext<Provider>,
    max_lookahead: usize,
    next_sequence: u64,
    next_emit_sequence: u64,
    source_exhausted: bool,
    in_flight: BTreeMap<u64, BestTransaction>,
    ready: BTreeMap<u64, PrewarmedBestTransaction>,
    skipped: HashSet<u64>,
}

/// Context needed to prewarm transaction storage independently of the real builder.
#[derive(Clone)]
struct PrewarmingExecutionContext<Provider> {
    provider: Provider,
    parent_hash: B256,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    stop: Arc<AtomicBool>,
    state_pool: PrewarmedStatePool,
}

impl<Provider> PrewarmingExecutionContext<Provider>
where
    Provider: StateProviderFactory + Clone + 'static,
{
    fn evm_for_ctx(&self) -> PrewarmEvmState {
        let state_provider = match self.provider.state_by_block_hash(self.parent_hash) {
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

        let state_provider = PrewarmDatabase::new(StateProviderDatabase::new(state_provider));
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
    Prewarmed(PrewarmResult),
    Invalid {
        invalid: InvalidTransaction,
        old_rx: Receiver<Option<PrewarmedBestTransaction>>,
        new_tx: Sender<Option<PrewarmedBestTransaction>>,
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

/// Result of prewarming a transaction.
#[derive(Debug)]
struct PrewarmResult {
    sequence: u64,
    tx: BestTransaction,
    state: PooledPrewarmedState,
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
    use reth_revm::cached::CachedAccount;
    use reth_storage_api::noop::NoopProvider;
    use reth_transaction_pool::{
        TransactionOrigin, ValidPoolTransaction, identifier::TransactionId,
    };
    use std::{
        collections::{HashMap, VecDeque},
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

    #[derive(Debug, Default)]
    struct OverlayTestDb {
        accounts: HashMap<Address, Option<AccountInfo>>,
        storage: HashMap<(Address, U256), U256>,
        contracts: HashMap<B256, Bytecode>,
        block_hashes: HashMap<u64, B256>,
        basic_reads: usize,
        storage_reads: usize,
        code_reads: usize,
        block_hash_reads: usize,
    }

    impl RevmDatabase for OverlayTestDb {
        type Error = Infallible;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            self.basic_reads += 1;
            Ok(self.accounts.get(&address).cloned().unwrap_or_default())
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.code_reads += 1;
            Ok(self.contracts.get(&code_hash).cloned().unwrap_or_default())
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            self.storage_reads += 1;
            Ok(*self.storage.get(&(address, index)).unwrap_or(&U256::ZERO))
        }

        fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
            self.block_hash_reads += 1;
            Ok(*self.block_hashes.get(&number).unwrap_or(&B256::ZERO))
        }
    }

    fn pooled_state(cached: CachedReads) -> PooledPrewarmedState {
        PooledPrewarmedState {
            cached: Some(cached),
            pool: PrewarmedStatePool::new(1),
        }
    }

    #[test]
    fn prewarm_database_records_worker_cache_hits_per_transaction() {
        let address = Address::random();
        let slot = U256::from(7);
        let code_hash = B256::repeat_byte(0x42);
        let block_number = 12;
        let block_hash = B256::repeat_byte(0xaa);
        let code = Bytecode::new_legacy(Bytes::from_static(&[0x01]));
        let account = AccountInfo {
            nonce: 7,
            ..Default::default()
        };

        let mut fallback = OverlayTestDb::default();
        fallback.accounts.insert(address, Some(account.clone()));
        fallback.storage.insert((address, slot), U256::from(99));
        fallback.contracts.insert(code_hash, code.clone());
        fallback.block_hashes.insert(block_number, block_hash);

        let mut db = PrewarmDatabase::new(fallback);
        db.start_recording(CachedReads::default());
        assert_eq!(db.storage(address, slot).unwrap(), U256::from(99));
        assert_eq!(db.code_by_hash(code_hash).unwrap(), code);
        assert_eq!(db.block_hash(block_number).unwrap(), block_hash);
        let first = db.finish_recording();
        assert_eq!(db.db.basic_reads, 1);
        assert_eq!(db.db.storage_reads, 1);
        assert_eq!(db.db.code_reads, 1);
        assert_eq!(db.db.block_hash_reads, 1);
        assert_eq!(
            first.accounts.get(&address).unwrap().info,
            Some(account.clone())
        );
        assert_eq!(
            first.accounts.get(&address).unwrap().storage.get(&slot),
            Some(&U256::from(99))
        );
        assert_eq!(first.contracts.get(&code_hash), Some(&code));
        assert_eq!(first.block_hashes.get(&block_number), Some(&block_hash));

        db.start_recording(CachedReads::default());
        assert_eq!(db.basic(address).unwrap(), Some(account.clone()));
        assert_eq!(db.storage(address, slot).unwrap(), U256::from(99));
        assert_eq!(db.code_by_hash(code_hash).unwrap(), code);
        assert_eq!(db.block_hash(block_number).unwrap(), block_hash);
        let second = db.finish_recording();
        assert_eq!(db.db.basic_reads, 1);
        assert_eq!(db.db.storage_reads, 1);
        assert_eq!(db.db.code_reads, 1);
        assert_eq!(db.db.block_hash_reads, 1);
        assert_eq!(second.accounts.get(&address).unwrap().info, Some(account));
        assert_eq!(
            second.accounts.get(&address).unwrap().storage.get(&slot),
            Some(&U256::from(99))
        );
        assert_eq!(second.contracts.get(&code_hash), Some(&code));
        assert_eq!(second.block_hashes.get(&block_number), Some(&block_hash));
    }

    #[test]
    fn overlay_serves_prewarmed_reads_before_fallback() {
        let address = Address::random();
        let missing = Address::random();
        let fallback_only = Address::random();
        let slot = U256::from(7);
        let fallback_slot = U256::from(8);
        let code_hash = B256::repeat_byte(0x42);
        let fallback_code_hash = B256::repeat_byte(0x43);
        let block_number = 12;
        let fallback_block_number = 13;
        let block_hash = B256::repeat_byte(0xaa);
        let fallback_block_hash = B256::repeat_byte(0xcc);
        let overlay_code = Bytecode::new_legacy(Bytes::from_static(&[0x01]));
        let fallback_code = Bytecode::new_legacy(Bytes::from_static(&[0x02]));
        let fallback_only_code = Bytecode::new_legacy(Bytes::from_static(&[0x03]));

        let overlay_account = AccountInfo {
            nonce: 7,
            ..Default::default()
        };
        let fallback_account = AccountInfo {
            nonce: 1,
            ..Default::default()
        };
        let fallback_only_account = AccountInfo {
            nonce: 3,
            ..Default::default()
        };

        let mut cached = CachedReads::default();
        cached.insert_account(
            address,
            overlay_account.clone(),
            [(slot, U256::from(99))].into_iter().collect(),
        );
        cached.accounts.insert(
            missing,
            CachedAccount {
                info: None,
                storage: Default::default(),
            },
        );
        cached.contracts.insert(code_hash, overlay_code.clone());
        cached.block_hashes.insert(block_number, block_hash);

        let mut fallback = OverlayTestDb::default();
        fallback.accounts.insert(address, Some(fallback_account));
        fallback
            .accounts
            .insert(fallback_only, Some(fallback_only_account.clone()));
        fallback.storage.insert((address, slot), U256::from(1));
        fallback
            .storage
            .insert((fallback_only, fallback_slot), U256::from(77));
        fallback.contracts.insert(code_hash, fallback_code);
        fallback
            .contracts
            .insert(fallback_code_hash, fallback_only_code.clone());
        fallback
            .block_hashes
            .insert(block_number, B256::repeat_byte(0xbb));
        fallback
            .block_hashes
            .insert(fallback_block_number, fallback_block_hash);

        let mut db = PrewarmedStateOverlay::new(fallback);
        db.set_overlay(Some(pooled_state(cached)));

        assert_eq!(db.basic(address).unwrap(), Some(overlay_account));
        assert_eq!(db.storage(address, slot).unwrap(), U256::from(99));
        assert_eq!(db.storage(missing, slot).unwrap(), U256::ZERO);
        assert_eq!(db.code_by_hash(code_hash).unwrap(), overlay_code);
        assert_eq!(db.block_hash(block_number).unwrap(), block_hash);
        assert_eq!(
            db.basic(fallback_only).unwrap(),
            Some(fallback_only_account)
        );
        assert_eq!(
            db.storage(fallback_only, fallback_slot).unwrap(),
            U256::from(77)
        );
        assert_eq!(
            db.code_by_hash(fallback_code_hash).unwrap(),
            fallback_only_code
        );
        assert_eq!(
            db.block_hash(fallback_block_number).unwrap(),
            fallback_block_hash
        );
        assert_eq!(db.db.basic_reads, 1);
        assert_eq!(db.db.storage_reads, 1);
        assert_eq!(db.db.code_reads, 1);
        assert_eq!(db.db.block_hash_reads, 1);

        db.clear_overlay();
        assert_eq!(db.basic(address).unwrap().map(|info| info.nonce), Some(1));
        assert_eq!(db.storage(address, slot).unwrap(), U256::from(1));
        assert_eq!(
            db.code_by_hash(code_hash).unwrap(),
            Bytecode::new_legacy(Bytes::from_static(&[0x02]))
        );
        assert_eq!(
            db.block_hash(block_number).unwrap(),
            B256::repeat_byte(0xbb)
        );
        assert_eq!(db.db.basic_reads, 2);
        assert_eq!(db.db.storage_reads, 2);
        assert_eq!(db.db.code_reads, 2);
        assert_eq!(db.db.block_hash_reads, 2);
    }

    #[test]
    fn prewarmed_state_pool_reuses_cleared_capacity() {
        let pool = PrewarmedStatePool::new(1);
        let retained_capacity = {
            let mut state = pool.take();
            state.cached_mut().accounts.reserve(16);
            let capacity = state.cached().accounts.capacity();
            state.cached_mut().accounts.insert(
                Address::random(),
                CachedAccount {
                    info: None,
                    storage: Default::default(),
                },
            );
            capacity
        };

        let state = pool.take();
        assert!(state.cached().accounts.is_empty());
        assert!(state.cached().accounts.capacity() >= retained_capacity);
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
            .map(|_| *prewarming.next().expect("transaction").transaction().hash())
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn prewarming_uses_bounded_lookahead_and_advances_after_consumption() {
        let sender = Address::random();
        let executor = TaskExecutor::test();
        let lookahead = (executor.prewarming_pool().current_num_threads() * 2).max(1);
        let txs = (0..lookahead + 4)
            .map(|nonce| test_tx(sender, nonce as u64))
            .collect::<Vec<_>>();
        let expected = txs.iter().map(|tx| *tx.hash()).collect::<Vec<_>>();
        let log = Arc::new(Mutex::new(TestLog::default()));

        let mut prewarming = prewarming_with_executor(executor, txs, log.clone());
        wait_until(|| log.lock().unwrap().yielded > 0);
        assert!(log.lock().unwrap().yielded <= lookahead);

        let actual = (0..expected.len())
            .map(|_| *prewarming.next().expect("transaction").transaction().hash())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        wait_until(|| log.lock().unwrap().yielded == expected.len());
    }

    #[test]
    fn empty_source_is_polled_once_and_returns_none() {
        let executor = TaskExecutor::test();
        let log = Arc::new(Mutex::new(TestLog::default()));
        let mut prewarming = prewarming_with_executor(executor, Vec::new(), log.clone());

        wait_until(|| log.lock().unwrap().empty_polls == 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 1);

        assert!(prewarming.next().is_none());
        wait_until(|| log.lock().unwrap().empty_polls == 1);
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
        assert_eq!(first.transaction().hash(), tx1.hash());

        wait_until(|| log.lock().unwrap().yielded == 3);
        prewarming.mark_invalid(
            &first,
            InvalidPoolTransactionError::Consensus(InvalidTransactionError::TxTypeNotSupported),
        );

        let next = prewarming.next().expect("non-invalidated transaction");
        assert_eq!(next.transaction().hash(), tx3.hash());
        assert_ne!(next.transaction().hash(), tx2.hash());
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
