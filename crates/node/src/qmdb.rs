//! QMDB state commitment in the node: computing each block's QMDB root during validation, and
//! keeping the on-disk QMDB in step with the finalized chain.
//!
//! [`QmdbStateRootStrategy`] wraps reth's default state-root strategy. Before the QMDB
//! activation it validates blocks against their MPT root and builds each block's QMDB batch in the
//! background (shadow mode), so operators can compare QMDB roots across validators before the
//! fork. From the activation on, the block's state root is its QMDB root.
//!
//! [`QmdbPersistenceHook`] applies each block's batch when reth persists the block, before the MDBX
//! commit, so the on-disk QMDB never falls behind the database. Validated blocks carry their batch
//! to it as their reth `BlockExt`.
//!
//! [`QmdbSync`] imports the snapshot block's state once the node has persisted it, and rebuilds and
//! applies the batches of blocks the node executed or persisted before QMDB was ready.
//!
//! [`QmdbStateBackend`] serves the applied QMDB state as reth's current state, so a node launched
//! with it keeps no hashed state tables or tries at all.

use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Instant};

use alloy::consensus::BlockHeader as _;
use alloy_primitives::{B256, U256};
use eyre::{OptionExt as _, WrapErr as _};
use metrics::{Counter, Gauge, Histogram};
use reth_chain_state::{ExecutedBlock, ForkChoiceSubscriptions};
use reth_engine_tree::{
    persistence::PersistenceHook,
    tree::state_root_strategy::{
        DefaultStateRootStrategy, LazyHashedPostState, PayloadStateRootHandle,
        PayloadStateRootJobContext, PreparedStateRootJob, StateAccessHint, StateRootHandle,
        StateRootJob, StateRootJobContext, StateRootJobOutcome, StateRootMessage,
        StateRootStrategy, StateRootTaskCancelGuard,
    },
};
use reth_ethereum::tasks::TaskExecutor;
use reth_evm::{ConfigureEvm, EvmEnv as _};
use reth_execution_types::{BlockExecutionOutput, BlockExt, state_update_to_hashed_post_state};
use reth_metrics::Metrics;
use reth_primitives_traits::{Account, RecoveredBlock};
use reth_provider::{
    BlockHashReader, BlockIdReader, BlockNumReader, CanonChainTracker, ChangeSetReader, DBProvider,
    DatabaseProviderFactory, HeaderProvider, ProviderError, ProviderResult, StateBackend,
    StateReader, StorageChangeSetReader,
};
use reth_tracing::tracing::{debug, info, warn};
use reth_trie::hashed_cursor::HashedPostStateCursorFactory;
use reth_trie_common::{HashedPostState, HashedPostStateSorted, updates::TrieUpdates};
use reth_trie_db::{DatabaseHashedCursorFactory, DatabaseHashedPostState as _};
use tempo_primitives::{Block, TempoPrimitives, TempoReceipt};
use tempo_qmdb_state::{
    BlockRef, QmdbBatch, Store, diff, import,
    layout::{self, AccountRecord},
};

/// Chooses each block's state root: the MPT root before the QMDB activation, the QMDB root from it.
#[derive(Debug)]
pub struct QmdbStateRootStrategy {
    store: Arc<Store>,
    /// Timestamp of the first block whose state root is its QMDB root; `None` keeps shadow mode.
    activation_timestamp: Option<u64>,
    default: DefaultStateRootStrategy,
    metrics: Arc<QmdbMetrics>,
}

impl QmdbStateRootStrategy {
    /// Creates a strategy over `store` that switches to QMDB roots at `activation_timestamp`.
    pub fn new(store: Arc<Store>, activation_timestamp: Option<u64>) -> Self {
        Self {
            store,
            activation_timestamp,
            default: DefaultStateRootStrategy::default(),
            metrics: Arc::new(QmdbMetrics::default()),
        }
    }

    fn is_active_at(&self, timestamp: u64) -> bool {
        self.activation_timestamp
            .is_some_and(|activation| timestamp >= activation)
    }

    /// Returns the store the strategy builds batches in.
    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// Returns the timestamp from which state roots are QMDB roots, if configured.
    pub const fn activation_timestamp(&self) -> Option<u64> {
        self.activation_timestamp
    }

    /// Returns the hook that applies batches as reth persists blocks.
    pub fn persistence_hook(&self) -> QmdbPersistenceHook {
        QmdbPersistenceHook {
            store: self.store.clone(),
            activation_timestamp: self.activation_timestamp,
            metrics: self.metrics.clone(),
        }
    }
}

impl<P, Evm> StateRootStrategy<TempoPrimitives, P, Evm> for QmdbStateRootStrategy
where
    Evm: ConfigureEvm<Primitives = TempoPrimitives>,
    DefaultStateRootStrategy: StateRootStrategy<TempoPrimitives, P, Evm>,
{
    fn prepare(
        &self,
        ctx: StateRootJobContext<'_, TempoPrimitives, P, Evm>,
    ) -> ProviderResult<PreparedStateRootJob<TempoPrimitives>> {
        let timestamp: u64 = ctx.env().evm_env.block_env().timestamp.saturating_to();
        if self.is_active_at(timestamp) {
            let job = ActiveJob {
                store: self.store.clone(),
                metrics: self.metrics.clone(),
            };
            let mut prefetch = spawn_prefetch(self.store.clone(), self.metrics.clone());
            return Ok(PreparedStateRootJob::new(Box::new(job), None)
                .with_execution_hook(prefetch.take_execution_hook())
                .with_hint_stream(prefetch.take_hint_stream()));
        }

        // Keep the default job's update streams: the MPT root still decides validity.
        let mut inner = self.default.prepare(ctx)?;
        let execution_hook = inner.take_execution_hook();
        let hint_stream = inner.take_hint_stream();
        let hashed_update_stream = inner.take_hashed_update_stream();
        let hashed_state_rx = inner.take_hashed_state_rx();
        let job = ShadowJob {
            inner,
            store: self.store.clone(),
            metrics: self.metrics.clone(),
        };
        let mut prepared = PreparedStateRootJob::new(Box::new(job), hashed_state_rx);
        if let Some(hook) = execution_hook {
            prepared = prepared.with_execution_hook(hook);
        }
        if let Some(stream) = hint_stream {
            prepared = prepared.with_hint_stream(stream);
        }
        if let Some(stream) = hashed_update_stream {
            prepared = prepared.with_hashed_update_stream(stream);
        }
        Ok(prepared)
    }

    fn prepare_payload_builder(
        &self,
        ctx: PayloadStateRootJobContext<'_, TempoPrimitives, P>,
    ) -> ProviderResult<Option<PayloadStateRootHandle>> {
        // Once active, the payload builder builds the QMDB batch from its execution output
        // itself. The handle only streams its execution into the prefetch and never yields a
        // root.
        if self.is_active_at(ctx.timestamp()) {
            let mut prefetch = spawn_prefetch(self.store.clone(), self.metrics.clone());
            let (_, state_root_rx) = std::sync::mpsc::channel();
            return Ok(Some(PayloadStateRootHandle::new(
                "qmdb-prefetch",
                Some(prefetch.take_execution_hook()),
                state_root_rx,
                None,
            )));
        }
        self.default.prepare_payload_builder(ctx)
    }
}

/// Validates against the MPT root and builds the block's QMDB batch off the critical path.
struct ShadowJob {
    inner: PreparedStateRootJob<TempoPrimitives>,
    store: Arc<Store>,
    metrics: Arc<QmdbMetrics>,
}

impl StateRootJob<TempoPrimitives> for ShadowJob {
    fn name(&self) -> &'static str {
        "qmdb-shadow"
    }

    fn finish(
        &mut self,
        block: &RecoveredBlock<Block>,
        output: Arc<BlockExecutionOutput<TempoReceipt>>,
        hashed_state: &LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let outcome = self.inner.finish(block, output.clone(), hashed_state)?;
        let block_ref = block_ref(block);
        match diff::block_writes(&output.state) {
            Ok(writes) => {
                let metrics = self.metrics.clone();
                let started = Instant::now();
                let sent = self.store.build_detached(block_ref, writes, move |result| {
                    record_shadow_build(&metrics, block_ref, started, result)
                });
                if let Err(err) = sent {
                    self.metrics.shadow_failed.increment(1);
                    warn!(target: "qmdb", %err, number = block_ref.number, "QMDB store is gone");
                }
            }
            Err(err) => {
                self.metrics.shadow_failed.increment(1);
                warn!(target: "qmdb", %err, number = block_ref.number, "block has no QMDB batch");
            }
        }
        Ok(outcome)
    }
}

/// Returns the block's QMDB root as its state root.
struct ActiveJob {
    store: Arc<Store>,
    metrics: Arc<QmdbMetrics>,
}

impl StateRootJob<TempoPrimitives> for ActiveJob {
    fn name(&self) -> &'static str {
        "qmdb"
    }

    fn finish(
        &mut self,
        block: &RecoveredBlock<Block>,
        output: Arc<BlockExecutionOutput<TempoReceipt>>,
        _hashed_state: &LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let started = Instant::now();
        let writes = diff::block_writes(&output.state).map_err(ProviderError::other)?;
        let batch = self
            .store
            .build(block_ref(block), writes)
            .map_err(ProviderError::other)?;
        self.metrics.build_duration.record(started.elapsed());
        // The MPT trie tables are no longer maintained from here on. The block carries its batch
        // to the persistence hook.
        Ok(
            StateRootJobOutcome::new(batch.root(), Arc::new(TrieUpdates::default()))
                .with_ext(Some(BlockExt::new(batch))),
        )
    }
}

/// Streams a block's execution into [`Store::prefetch`] while it runs, the way reth's sparse-trie
/// task reveals proofs as transactions execute, so that building the block's batch finds what it
/// reads cached.
///
/// The returned handle's execution hook carries each transaction's state update and its hint
/// stream the prewarming hints. The task prefetches the keys of everything that arrived while its
/// previous prefetch ran, and ends when the hook finishes the stream or both are dropped.
fn spawn_prefetch(store: Arc<Store>, metrics: Arc<QmdbMetrics>) -> StateRootHandle {
    let (updates_tx, updates_rx) = crossbeam_channel::unbounded();
    // Nothing waits on a root or a hashed state from this task, so their senders drop here.
    let (cancel_guard, _) = StateRootTaskCancelGuard::channel();
    let (_, state_root_rx) = std::sync::mpsc::channel();
    let (_, hashed_state_rx) = std::sync::mpsc::channel();
    let handle = StateRootHandle::new(
        B256::ZERO,
        updates_tx,
        cancel_guard,
        state_root_rx,
        hashed_state_rx,
    );
    let prefetch = move || {
        let mut keys = PrefetchKeys::default();
        let mut finished = false;
        while !finished && let Ok(message) = updates_rx.recv() {
            for message in std::iter::once(message).chain(updates_rx.try_iter()) {
                finished |= keys.add(message);
            }
            let (accounts, slots) = keys.take();
            if accounts.is_empty() && slots.is_empty() {
                continue;
            }
            let started = Instant::now();
            if let Err(err) = store.prefetch(accounts, slots) {
                debug!(target: "qmdb", %err, "QMDB prefetch failed");
                return;
            }
            metrics.prefetch_duration.record(started.elapsed());
        }
    };
    if let Err(err) = std::thread::Builder::new()
        .name("qmdb-prefetch".into())
        .spawn(prefetch)
    {
        warn!(target: "qmdb", %err, "failed spawning the QMDB prefetch");
    }
    handle
}

/// Keys of one block that the prefetch has yet to read, and those it already queued.
#[derive(Default)]
struct PrefetchKeys {
    accounts: Vec<layout::Key>,
    slots: Vec<layout::Key>,
    seen_accounts: HashSet<layout::Key>,
    seen_slots: HashSet<layout::Key>,
}

impl PrefetchKeys {
    /// Queues the keys `message` names that were not queued before. Returns whether the
    /// message ends the update stream.
    fn add(&mut self, message: StateRootMessage) -> bool {
        match message {
            StateRootMessage::PrefetchProofs(targets) => {
                let hint = StateAccessHint::from(targets);
                for hashed_address in hint.accounts {
                    self.account(hashed_address);
                }
                for (hashed_address, hashed_slots) in hint.storages {
                    for hashed_slot in hashed_slots {
                        self.slot(hashed_address, hashed_slot);
                    }
                }
            }
            StateRootMessage::StateUpdate(update) => {
                self.hashed(state_update_to_hashed_post_state(&update));
            }
            StateRootMessage::HashedStateUpdate(state) => self.hashed(state),
            StateRootMessage::FinishedStateUpdates => return true,
        }
        false
    }

    fn hashed(&mut self, state: HashedPostState) {
        for hashed_address in state.accounts.keys() {
            self.account(*hashed_address);
        }
        for (hashed_address, storage) in &state.storages {
            for hashed_slot in storage.storage.keys() {
                self.slot(*hashed_address, *hashed_slot);
            }
        }
    }

    fn account(&mut self, hashed_address: B256) {
        let key = layout::account_key(hashed_address);
        if self.seen_accounts.insert(key.clone()) {
            self.accounts.push(key);
        }
    }

    fn slot(&mut self, hashed_address: B256, hashed_slot: B256) {
        let key = layout::slot_key(hashed_address, hashed_slot);
        if self.seen_slots.insert(key.clone()) {
            self.slots.push(key);
        }
    }

    /// Takes the queued keys, which stay seen.
    fn take(&mut self) -> (Vec<layout::Key>, Vec<layout::Key>) {
        (
            std::mem::take(&mut self.accounts),
            std::mem::take(&mut self.slots),
        )
    }
}

/// Applies QMDB batches as reth persists blocks, before the MDBX commit.
///
/// Before the activation a failure only skips the block, which [`QmdbSync`] later replays; from
/// the activation on it aborts the save, since the database would otherwise run ahead of the
/// state commitment.
#[derive(Debug)]
pub struct QmdbPersistenceHook {
    store: Arc<Store>,
    activation_timestamp: Option<u64>,
    metrics: Arc<QmdbMetrics>,
}

impl QmdbPersistenceHook {
    fn apply(&self, block: &ExecutedBlock<TempoPrimitives>) -> Result<(), tempo_qmdb_state::Error> {
        let hash = block.recovered_block().hash();
        // Register the exact batch the block was validated or built with, in case the store's
        // copy was replaced by a rebuild.
        if let Some(batch) = block.ext().and_then(|c| c.downcast_ref::<QmdbBatch>()) {
            self.store.register(hash, batch.clone())?;
        }
        // Applies every unapplied ancestor too: they are the earlier blocks of this save.
        self.store.finalize(hash)
    }
}

impl PersistenceHook<TempoPrimitives> for QmdbPersistenceHook {
    fn on_save_state(&self, blocks: &[ExecutedBlock<TempoPrimitives>]) -> ProviderResult<()> {
        let Some(last) = blocks.last() else {
            return Ok(());
        };
        let started = Instant::now();
        let number = last.recovered_block().number();
        match self.apply(last) {
            Ok(()) => {
                self.metrics.applied_block.set(number as f64);
                self.metrics.apply_duration.record(started.elapsed());
                Ok(())
            }
            Err(err)
                if self
                    .activation_timestamp
                    .is_some_and(|activation| last.recovered_block().timestamp() >= activation) =>
            {
                Err(ProviderError::other(err))
            }
            Err(err) => {
                self.metrics.persist_skipped.increment(1);
                debug!(target: "qmdb", %err, number, "skipped applying QMDB batch on persistence");
                Ok(())
            }
        }
    }

    fn on_remove_blocks_above(&self, new_tip: u64) -> ProviderResult<()> {
        match rewind_above(&self.store, new_tip) {
            Ok(()) => {
                self.metrics.ahead_of_database.set(0.0);
                Ok(())
            }
            Err(err) if self.activation_timestamp.is_some() => Err(ProviderError::other(err)),
            Err(err) => {
                self.metrics.ahead_of_database.set(1.0);
                warn!(target: "qmdb", %err, new_tip, "failed rewinding QMDB to the database tip after an unwind; shadow roots stop until it is rebuilt");
                Ok(())
            }
        }
    }
}

/// Serves the applied QMDB state as reth's current state, in place of the hashed state tables.
///
/// The persistence hook applies each block's batch before reth commits the block, so the applied
/// state is never behind a read transaction's frontier, as [`StateBackend`] requires.
#[derive(Debug)]
pub struct QmdbStateBackend {
    store: Arc<Store>,
}

impl QmdbStateBackend {
    /// Creates a backend reading the applied state of `store`.
    pub const fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

impl StateBackend for QmdbStateBackend {
    fn account(&self, hashed_address: B256) -> ProviderResult<Option<Account>> {
        let value = self
            .store
            .get_account(layout::account_key(hashed_address))
            .map_err(ProviderError::other)?;
        Ok(value.map(|value| AccountRecord::decode(&value).into_account()))
    }

    fn storage(&self, hashed_address: B256, hashed_slot: B256) -> ProviderResult<Option<U256>> {
        let value = self
            .store
            .get_slot(layout::slot_key(hashed_address, hashed_slot))
            .map_err(ProviderError::other)?;
        Ok(value.map(|value| layout::decode_slot_value(&value)))
    }
}

/// Brings the on-disk QMDB in step with `persisted`, the database's persisted tip, at startup.
///
/// Rewinds QMDB when it is ahead, after a crash between applying a batch and the database commit.
/// With `require_level`, as when QMDB serves the node's state, it also fails unless QMDB then holds
/// exactly the state of `persisted` with its hash bound.
pub fn align_with_database(store: &Store, persisted: u64, require_level: bool) -> eyre::Result<()> {
    rewind_above(store, persisted)
        .wrap_err_with(|| format!("failed rewinding QMDB to the database tip {persisted}"))?;
    if !require_level {
        return Ok(());
    }
    let status = store.status()?;
    eyre::ensure!(
        status.applied == Some(persisted),
        "QMDB holds the state of block {:?}, not of the database tip {persisted}; run `tempo qmdb-import` on a datadir that never served state from QMDB",
        status.applied
    );
    eyre::ensure!(
        status.base.is_some(),
        "the QMDB commit journal has no record of block {persisted}'s hash"
    );
    Ok(())
}

/// Keeps the on-disk QMDB in step with the node's persisted chain.
#[derive(Debug)]
pub struct QmdbSync<P> {
    provider: P,
    store: Arc<Store>,
    /// Block whose state the import migrates. Part of the chain's definition of the QMDB root.
    snapshot: u64,
    /// Directory for the import's temporary sort files.
    sort_dir: PathBuf,
    metrics: Arc<QmdbMetrics>,
}

impl<P> QmdbSync<P>
where
    P: DatabaseProviderFactory<
            Provider: DBProvider + ChangeSetReader + StorageChangeSetReader + BlockNumReader,
        > + StateReader<Receipt = TempoReceipt>
        + BlockHashReader
        + BlockNumReader
        + BlockIdReader
        + HeaderProvider
        + CanonChainTracker
        + ForkChoiceSubscriptions
        + Send
        + Sync
        + 'static,
{
    /// Creates the sync task's state.
    pub fn new(provider: P, store: Arc<Store>, snapshot: u64, sort_dir: PathBuf) -> Self {
        Self {
            provider,
            store,
            snapshot,
            sort_dir,
            metrics: Arc::new(QmdbMetrics::default()),
        }
    }

    /// Spawns the task, which runs once now and again on every finalized block.
    ///
    /// It only needs to run until QMDB has caught up; afterwards every step is a no-op.
    ///
    /// A failed step is reported and retried on the next finalized block.
    pub fn spawn(self, executor: TaskExecutor) {
        let mut finalized = self.provider.subscribe_finalized_block().0;
        executor.spawn_blocking_task(async move {
            info!(target: "qmdb", snapshot = self.snapshot, "Started QMDB state sync");
            loop {
                if let Err(err) = self.step() {
                    self.metrics.sync_failed.increment(1);
                    warn!(target: "qmdb", %err, "QMDB sync step failed");
                }
                if finalized.changed().await.is_err() {
                    return;
                }
            }
        });
    }

    /// Imports the snapshot if needed, builds missing batches of canonical blocks, and applies
    /// every persisted block the persistence hook could not apply.
    fn step(&self) -> eyre::Result<()> {
        let persisted = self
            .provider
            .database_provider_ro()
            .wrap_err("failed opening the database")?
            .best_block_number()
            .wrap_err("failed reading the persisted block")?;
        let mut status = self.store.status()?;
        let applied = match status.applied {
            Some(applied) => applied,
            None if persisted < self.snapshot => {
                debug!(target: "qmdb", persisted, snapshot = self.snapshot, "waiting for the snapshot block");
                return Ok(());
            }
            None => {
                self.import_snapshot(persisted)?;
                self.snapshot
            }
        };
        if status.base.is_none() {
            let hash = self.canonical_hash(applied)?;
            self.store.set_base(hash)?;
            status = self.store.status()?;
        }
        self.metrics.applied_block.set(applied as f64);

        // Canonical blocks the engine executed before QMDB was ready have no batch yet.
        let tip = self
            .provider
            .best_block_number()
            .wrap_err("failed reading the canonical tip")?;
        for number in applied + 1..=tip {
            let hash = self.canonical_hash(number)?;
            if self.store.root(hash)?.is_some() {
                continue;
            }
            let header = self
                .provider
                .header_by_number(number)?
                .ok_or_eyre("canonical block has no header")?;
            let outcome = self
                .provider
                .get_state(number)?
                .ok_or_eyre("canonical block has no execution outcome")?;
            let writes = diff::block_writes(&outcome.bundle)
                .wrap_err_with(|| format!("failed diffing block {number}"))?;
            let block = BlockRef {
                number,
                hash,
                parent_hash: header.parent_hash(),
            };
            let root = self.store.build(block, writes)?.root();
            self.metrics.replayed_blocks.increment(1);
            debug!(target: "qmdb", number, %root, "replayed block into QMDB");
        }

        // Steady state, the persistence hook applies blocks as they persist. This catches up on
        // blocks persisted before their batch existed.
        let applied = self.store.status()?.applied.unwrap_or(applied);
        let target = persisted;
        if target > applied {
            let hash = self.canonical_hash(target)?;
            self.store.finalize(hash)?;
            self.metrics.applied_block.set(target as f64);
            status = self.store.status()?;
            debug!(target: "qmdb", applied = target, root = %status.root, "applied finalized QMDB batches");
        }
        self.metrics.pending.set(status.pending as f64);
        Ok(())
    }

    /// Imports the state at the end of the snapshot block: the hashed tables at `persisted`,
    /// overlaid with the reverts of every later block.
    fn import_snapshot(&self, persisted: u64) -> eyre::Result<()> {
        let started = Instant::now();
        let provider = self
            .provider
            .database_provider_ro()
            .wrap_err("failed opening the database")?;
        let reverts = if persisted > self.snapshot {
            HashedPostStateSorted::from_reverts(&provider, self.snapshot + 1..=persisted)
                .wrap_err("failed reading reverts back to the snapshot block")?
        } else {
            HashedPostStateSorted::default()
        };
        let cursors = HashedPostStateCursorFactory::new(
            DatabaseHashedCursorFactory::new(provider.tx_ref()),
            &reverts,
        );
        let keys = import::import(
            &cursors,
            &self.store,
            self.snapshot,
            self.canonical_hash(self.snapshot)?,
            Some(self.sort_dir.clone()),
        )
        .wrap_err("failed importing the snapshot state")?;
        let root = self.store.status()?.root;
        info!(
            target: "qmdb",
            snapshot = self.snapshot,
            keys,
            %root,
            elapsed = ?started.elapsed(),
            "imported the snapshot state into QMDB"
        );
        Ok(())
    }

    fn canonical_hash(&self, number: u64) -> eyre::Result<B256> {
        self.provider
            .block_hash(number)?
            .ok_or_else(|| eyre::eyre!("no canonical block {number}"))
    }
}

/// Rewinds `store` to block `tip` if it applied blocks above it.
fn rewind_above(store: &Store, tip: u64) -> Result<(), tempo_qmdb_state::Error> {
    if store.status()?.applied.is_some_and(|applied| applied > tip) {
        store.rewind_to(tip)?;
    }
    Ok(())
}

fn block_ref(block: &RecoveredBlock<Block>) -> BlockRef {
    BlockRef {
        number: block.number(),
        hash: block.hash(),
        parent_hash: block.parent_hash(),
    }
}

fn record_shadow_build(
    metrics: &QmdbMetrics,
    block: BlockRef,
    started: Instant,
    result: Result<B256, tempo_qmdb_state::Error>,
) {
    match result {
        Ok(root) => {
            metrics.build_duration.record(started.elapsed());
            debug!(target: "qmdb", number = block.number, hash = %block.hash, %root, "built QMDB root");
        }
        // Expected until the sync task has imported the snapshot and caught up.
        Err(
            tempo_qmdb_state::Error::NoBase
            | tempo_qmdb_state::Error::UnknownParent { .. }
            | tempo_qmdb_state::Error::AlreadyApplied { .. },
        ) => metrics.shadow_skipped.increment(1),
        Err(err) => {
            metrics.shadow_failed.increment(1);
            warn!(target: "qmdb", %err, number = block.number, "failed building QMDB root");
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "qmdb_state")]
struct QmdbMetrics {
    /// Time to diff, build and merkleize one block's batch.
    build_duration: Histogram,
    /// Time of one prefetch of keys that a block's execution streamed.
    prefetch_duration: Histogram,
    /// Shadow builds skipped because QMDB has not caught up with the block's parent.
    shadow_skipped: Counter,
    /// Shadow builds that failed.
    shadow_failed: Counter,
    /// Blocks replayed from the database by the sync task.
    replayed_blocks: Counter,
    /// Sync steps that failed.
    sync_failed: Counter,
    /// Last block applied to the on-disk QMDB.
    applied_block: Gauge,
    /// Unapplied batches held in memory.
    pending: Gauge,
    /// Time to apply and commit batches when reth persists blocks.
    apply_duration: Histogram,
    /// Persisted blocks whose batch could not be applied yet.
    persist_skipped: Counter,
    /// 1 when the on-disk QMDB is ahead of the database after an unwind.
    ahead_of_database: Gauge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::Header;
    use alloy_primitives::KECCAK256_EMPTY;
    use reth_primitives_traits::SealedBlock;
    use std::num::NonZeroUsize;
    use tempo_primitives::TempoHeader;
    use tempo_qmdb_state::Config;

    fn store(dir: &std::path::Path) -> Arc<Store> {
        let store = Store::open(Config {
            directory: dir.to_path_buf(),
            threads: NonZeroUsize::MIN,
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(8).unwrap(),
        })
        .unwrap();
        store
            .import_chunk(
                layout::Writes {
                    accounts: vec![],
                    slots: vec![layout::Write {
                        key: layout::slot_key(B256::repeat_byte(1), B256::ZERO),
                        value: Some(layout::slot_value(U256::from(1))),
                    }],
                },
                Some((0, B256::ZERO)),
            )
            .unwrap();
        Arc::new(store)
    }

    fn executed_block(number: u64, timestamp: u64) -> ExecutedBlock<TempoPrimitives> {
        let header = TempoHeader {
            inner: Header {
                number,
                timestamp,
                parent_hash: B256::ZERO,
                ..Default::default()
            },
            ..Default::default()
        };
        let block = SealedBlock::seal_slow(Block {
            header,
            body: Default::default(),
        });
        ExecutedBlock {
            recovered_block: Arc::new(RecoveredBlock::new_sealed(block, vec![])),
            ..Default::default()
        }
    }

    fn hook(store: Arc<Store>, activation_timestamp: Option<u64>) -> QmdbPersistenceHook {
        QmdbPersistenceHook {
            store,
            activation_timestamp,
            metrics: Arc::new(QmdbMetrics::default()),
        }
    }

    #[test]
    fn applies_the_batch_the_block_carries() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let batch = store
            .build_unregistered(
                1,
                B256::ZERO,
                layout::Writes {
                    accounts: vec![],
                    slots: vec![layout::Write {
                        key: layout::slot_key(B256::repeat_byte(1), B256::ZERO),
                        value: None,
                    }],
                },
            )
            .unwrap();
        let root = batch.root();
        let block = executed_block(1, 10).with_ext(Some(BlockExt::new(batch)));

        hook(store.clone(), Some(0))
            .on_save_state(&[block])
            .unwrap();
        let status = store.status().unwrap();
        assert_eq!(status.applied, Some(1));
        assert_eq!(status.root, root);
    }

    #[test]
    fn missing_batch_only_aborts_the_save_once_active() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let block = executed_block(1, 10);

        hook(store.clone(), None)
            .on_save_state(std::slice::from_ref(&block))
            .unwrap();
        hook(store.clone(), Some(11))
            .on_save_state(std::slice::from_ref(&block))
            .unwrap();
        assert!(
            hook(store.clone(), Some(10))
                .on_save_state(&[block])
                .is_err()
        );
        assert_eq!(store.status().unwrap().applied, Some(0));
    }

    /// Applies block 1 (hash 0x01) writing `writes` on top of the imported block 0.
    fn finalize_block_one(store: &Store, writes: layout::Writes) {
        store
            .build(
                BlockRef {
                    number: 1,
                    hash: B256::repeat_byte(1),
                    parent_hash: B256::ZERO,
                },
                writes,
            )
            .unwrap();
        store.finalize(B256::repeat_byte(1)).unwrap();
    }

    #[test]
    fn backend_serves_the_applied_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let backend = QmdbStateBackend::new(store.clone());
        let (address, slot) = (B256::repeat_byte(1), B256::ZERO);
        assert_eq!(backend.storage(address, slot).unwrap(), Some(U256::from(1)));
        assert_eq!(backend.account(address).unwrap(), None);

        let account = Account {
            nonce: 3,
            balance: U256::from(5),
            bytecode_hash: Some(B256::repeat_byte(9)),
            extension: [&[0u8][..], B256::repeat_byte(7).as_slice()]
                .concat()
                .into(),
        };
        let record = AccountRecord::new(
            account.nonce,
            account.balance,
            account.bytecode_hash,
            account.extension.as_ref(),
        )
        .unwrap();
        let writes = layout::Writes {
            accounts: vec![layout::Write {
                key: layout::account_key(address),
                value: Some(record.encode()),
            }],
            slots: vec![layout::Write {
                key: layout::slot_key(address, slot),
                value: None,
            }],
        };
        // Unapplied batches are not current state yet.
        store
            .build(
                BlockRef {
                    number: 1,
                    hash: B256::repeat_byte(1),
                    parent_hash: B256::ZERO,
                },
                writes,
            )
            .unwrap();
        assert_eq!(backend.account(address).unwrap(), None);

        store.finalize(B256::repeat_byte(1)).unwrap();
        assert_eq!(backend.account(address).unwrap(), Some(account));
        assert_eq!(backend.storage(address, slot).unwrap(), None);
    }

    #[test]
    fn backend_decodes_accounts_without_code_or_commitment() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let address = B256::repeat_byte(4);
        let record = AccountRecord::new(1, U256::ZERO, Some(KECCAK256_EMPTY), &[]).unwrap();
        finalize_block_one(
            &store,
            layout::Writes {
                accounts: vec![layout::Write {
                    key: layout::account_key(address),
                    value: Some(record.encode()),
                }],
                slots: vec![],
            },
        );
        assert_eq!(
            QmdbStateBackend::new(store).account(address).unwrap(),
            Some(Account {
                nonce: 1,
                ..Default::default()
            })
        );
    }

    #[test]
    fn unwind_rewinds_qmdb_to_the_new_tip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let root = store.status().unwrap().root;
        finalize_block_one(&store, layout::Writes::default());

        hook(store.clone(), Some(0))
            .on_remove_blocks_above(1)
            .unwrap();
        assert_eq!(store.status().unwrap().applied, Some(1));
        hook(store.clone(), Some(0))
            .on_remove_blocks_above(0)
            .unwrap();
        let status = store.status().unwrap();
        assert_eq!(
            (status.applied, status.base, status.root),
            (Some(0), Some(B256::ZERO), root)
        );
    }

    #[test]
    fn failed_unwind_only_errors_once_active() {
        // The commit journal has no record below the imported block, so QMDB cannot rewind there.
        let dir = tempfile::tempdir().unwrap();
        let imported_at_five = Store::open(Config {
            directory: dir.path().to_path_buf(),
            threads: NonZeroUsize::MIN,
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(8).unwrap(),
        })
        .unwrap();
        imported_at_five
            .import_chunk(layout::Writes::default(), Some((5, B256::repeat_byte(5))))
            .unwrap();
        let imported_at_five = Arc::new(imported_at_five);

        hook(imported_at_five.clone(), None)
            .on_remove_blocks_above(3)
            .unwrap();
        assert!(matches!(
            hook(imported_at_five.clone(), Some(0)).on_remove_blocks_above(3),
            Err(ProviderError::Other(_))
        ));
        assert_eq!(imported_at_five.status().unwrap().applied, Some(5));
    }

    #[test]
    fn align_rewinds_and_requires_level_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        finalize_block_one(&store, layout::Writes::default());

        // Ahead of the database: rewound.
        align_with_database(&store, 0, true).unwrap();
        assert_eq!(store.status().unwrap().applied, Some(0));

        // Behind the database: only an error when QMDB must serve the state.
        align_with_database(&store, 3, false).unwrap();
        let err = align_with_database(&store, 3, true).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("QMDB holds the state of block Some(0), not of the database tip 3"),
            "{err}"
        );
    }

    #[test]
    fn align_requires_an_imported_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(Config {
            directory: dir.path().to_path_buf(),
            threads: NonZeroUsize::MIN,
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(8).unwrap(),
        })
        .unwrap();
        align_with_database(&store, 0, false).unwrap();
        let err = align_with_database(&store, 0, true).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("QMDB holds the state of block None, not of the database tip 0"),
            "{err}"
        );
    }
}
