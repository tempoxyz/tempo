//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod blockstm;
mod budget;
mod metrics;
mod prewarming;

pub use blockstm::BlockStmConfig;
pub use budget::DEFAULT_BUILD_TIME_MULTIPLIER;
use crossbeam_channel::Sender;
use reth_trie_common::ordered_root::OrderedTrieRootEncodedBuilder;

use crate::{
    blockstm::{
        BlockStmAccessKey, BlockStmExecutionStats, BlockStmMetrics, BlockStmMvMemory,
        action::production::{
            BlockStmDirectTip20Execution, BlockStmDirectTip20Template, BlockStmSemanticReduction,
            BlockStmSemanticState, capture_tip20_semantic_plan, reduce_tip20_semantic_records,
        },
        executor::BlockStmAttempt,
        state_view::{
            BlockStmMvTrackingDb, BlockStmParentReadCache, BlockStmPrefixDb,
            account_write_set_from_evm_state, write_set_from_evm_state,
        },
    },
    budget::{
        BUILD_TIME_MULTIPLIER_SCALE, decay_build_time_multiplier, observed_build_time_multiplier,
        payload_budget_exhausted, scaled_build_time_multiplier,
    },
    metrics::{BlockBuildStopReason, InstrumentedFinishProvider, TempoPayloadBuilderMetrics},
    prewarming::BestTransactionsPrewarming,
};
use alloy_consensus::{BlockHeader as _, Signed, Transaction, TxLegacy, TxReceipt};
use alloy_eip7928::compute_block_access_list_hash;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    Address, B256, Bloom, Bytes, U256,
    map::{AddressMap, HashSet},
};
use alloy_rlp::{Decodable, Encodable};
use rayon::prelude::*;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
    is_better_payload,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_engine_tree::tree::{
    CachedStateMetrics, CachedStateMetricsSource, CachedStateProvider,
    instrumented_state::InstrumentedStateProvider,
};
use reth_errors::{ConsensusError, ProviderError};
use reth_evm::{
    ConfigureEvm, Database, Evm, EvmEnvFor, NextBlockEnvAttributes,
    block::{
        BlockExecutionError, BlockExecutor, BlockExecutorFactory, BlockValidationError, TxResult,
    },
    execute::{BlockAssemblerInput, WithTxEnv},
};
use reth_execution_types::BlockExecutionOutput;
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{
    Recovered, RecoveredBlock, transaction::error::InvalidTransactionError,
};
use reth_revm::{
    State,
    context::Block,
    database::StateProviderDatabase,
    db::states::bundle_state::BundleRetention,
    state::{Account, EvmState, EvmStorageSlot, TransactionId},
};
use reth_storage_api::{
    HashedPostStateProvider, StateProviderBox, StateProviderFactory, StateRootProvider,
};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_evm::{
    TempoBlockExecutionCtx, TempoEvmConfig, TempoNextBlockEnvAttributes, TempoStateAccess,
    evm::TempoEvm,
};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes, marshal_persist_estimate};
use tempo_precompiles::validator_config_v2::ValidatorConfigV2;
use tempo_primitives::{
    RecoveredSubBlock, SubBlockMetadata, TempoHeader, TempoReceipt, TempoTxEnvelope,
    subblock::PartialValidatorKey,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use tempo_revm::TempoTxEnv;
use tempo_transaction_pool::{
    StateAwareBestTransactions, TempoTransactionPool,
    best::BestTransaction,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use tokio::sync::oneshot;
use tracing::{Level, debug, debug_span, error, info, instrument, trace, warn};

const RLP_BLOCK_SIZE_SAFETY_MARGIN: usize = 128 * 1024;

/// Returns true if a subblock has any expired transactions for the given timestamp.
fn has_expired_transactions(subblock: &RecoveredSubBlock, timestamp: u64) -> bool {
    subblock.transactions.iter().any(|tx| {
        tx.as_aa().is_some_and(|tx| {
            tx.tx()
                .valid_before
                .is_some_and(|valid| valid.get() <= timestamp)
        })
    })
}

#[derive(Debug, Clone)]
struct BlockStmPoolCandidate {
    tx_index: usize,
    pool_tx: BestTransaction,
    tx_with_env: WithTxEnv<TempoTxEnv, Recovered<TempoTxEnvelope>>,
    max_regular_gas_used: u64,
    is_payment: bool,
    tx_rlp_length: usize,
    tx_debug_repr: String,
}

#[derive(Debug)]
struct BlockStmAttemptOutput {
    execution_result: Option<Result<tempo_evm::TempoTxResult, BlockExecutionError>>,
    direct_semantic_execution: Option<BlockStmDirectTip20Execution>,
    elapsed: Duration,
    semantic_plan: Option<crate::blockstm::action::production::BlockStmSemanticPlan>,
    blocking_dependency: Option<usize>,
    account_write_set: alloy_primitives::map::HashMap<Address, reth_revm::state::AccountInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockStmProductionTaskKind {
    Execution,
    Validation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockStmProductionTask {
    tx_index: usize,
    incarnation: usize,
    validation_generation: usize,
    kind: BlockStmProductionTaskKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockStmProductionQueuedTask {
    key: (usize, u8, usize, usize),
    task: BlockStmProductionTask,
}

impl BlockStmProductionQueuedTask {
    fn new(task: BlockStmProductionTask) -> Self {
        Self {
            key: (
                task.tx_index,
                blockstm_task_kind_priority(task.kind),
                task.incarnation,
                task.validation_generation,
            ),
            task,
        }
    }
}

impl PartialOrd for BlockStmProductionQueuedTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlockStmProductionQueuedTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

fn blockstm_task_kind_priority(kind: BlockStmProductionTaskKind) -> u8 {
    match kind {
        BlockStmProductionTaskKind::Validation => 0,
        BlockStmProductionTaskKind::Execution => 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockStmProductionStatus {
    Ready,
    Executing,
    Waiting,
    Executed,
    ValidationQueued,
    Validating,
    Validated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockStmProductionTxState {
    incarnation: usize,
    validation_generation: usize,
    revalidate_after_current: bool,
    status: BlockStmProductionStatus,
}

#[derive(Debug)]
struct BlockStmProductionScheduler {
    inner: Mutex<BlockStmProductionSchedulerInner>,
    available: Condvar,
}

#[derive(Debug, Default)]
struct BlockStmProductionSchedulerInner {
    queue: BinaryHeap<Reverse<BlockStmProductionQueuedTask>>,
    active: usize,
    done: bool,
}

impl BlockStmProductionScheduler {
    fn new(tx_count: usize) -> Self {
        Self {
            inner: Mutex::new(BlockStmProductionSchedulerInner {
                queue: (0..tx_count)
                    .map(|tx_index| BlockStmProductionTask {
                        tx_index,
                        incarnation: 0,
                        validation_generation: 0,
                        kind: BlockStmProductionTaskKind::Execution,
                    })
                    .map(BlockStmProductionQueuedTask::new)
                    .map(Reverse)
                    .collect(),
                active: 0,
                done: false,
            }),
            available: Condvar::new(),
        }
    }

    fn next_task(&self) -> Option<BlockStmProductionTask> {
        let mut inner = self
            .inner
            .lock()
            .expect("Block-STM production scheduler poisoned");
        loop {
            if inner.done {
                return None;
            }
            if let Some(Reverse(queued)) = inner.queue.pop() {
                inner.active += 1;
                return Some(queued.task);
            }
            if inner.active == 0 {
                inner.done = true;
                self.available.notify_all();
                return None;
            }
            inner = self
                .available
                .wait(inner)
                .expect("Block-STM production scheduler poisoned");
        }
    }

    fn push_task(&self, task: BlockStmProductionTask) {
        let mut inner = self
            .inner
            .lock()
            .expect("Block-STM production scheduler poisoned");
        if !inner.done {
            inner
                .queue
                .push(Reverse(BlockStmProductionQueuedTask::new(task)));
            self.available.notify_one();
        }
    }

    fn finish_task(&self) {
        let mut inner = self
            .inner
            .lock()
            .expect("Block-STM production scheduler poisoned");
        inner.active = inner
            .active
            .checked_sub(1)
            .expect("active Block-STM task underflow");
        if inner.queue.is_empty() && inner.active == 0 {
            inner.done = true;
            self.available.notify_all();
        } else {
            self.available.notify_one();
        }
    }
}

fn execute_blockstm_attempt(
    state_provider: &StateProviderBox,
    evm_config: &TempoEvmConfig,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    execution_ctx: TempoBlockExecutionCtx<'_>,
    prefix_cache: Arc<reth_revm::db::CacheState>,
    parent_read_cache: Arc<BlockStmParentReadCache>,
    memory: &BlockStmMvMemory,
    tx_index: usize,
    attempt: usize,
    tx: WithTxEnv<TempoTxEnv, Recovered<TempoTxEnvelope>>,
    pool_tx: &TempoPooledTransaction,
    capture_semantic_actions: bool,
    direct_semantic_template: &Arc<Mutex<Option<BlockStmDirectTip20Template>>>,
    beneficiary: Address,
) -> Result<BlockStmAttempt<BlockStmAttemptOutput>, BlockExecutionError> {
    let base_fee = evm_env.block_env.inner.basefee;
    let block_timestamp = evm_env.block_env.inner.timestamp.to::<u64>();
    let spec = evm_env.cfg_env.spec;
    let amsterdam_eip8037_enabled = evm_env.cfg_env.enable_amsterdam_eip8037;
    if capture_semantic_actions {
        let started = Instant::now();
        let template = direct_semantic_template
            .lock()
            .expect("Block-STM direct semantic template poisoned")
            .clone();
        if let Some(template) = template
            && let Some(direct_execution) = template.execute(
                tx_index,
                pool_tx,
                beneficiary,
                base_fee,
                block_timestamp,
                spec,
                amsterdam_eip8037_enabled,
            )
        {
            let semantic_plan = direct_execution.semantic_plan.clone();
            return Ok(BlockStmAttempt {
                tx_index,
                attempt,
                read_set: Default::default(),
                write_set: Default::default(),
                output: BlockStmAttemptOutput {
                    execution_result: None,
                    direct_semantic_execution: Some(direct_execution),
                    elapsed: started.elapsed(),
                    semantic_plan: Some(semantic_plan),
                    blocking_dependency: None,
                    account_write_set: Default::default(),
                },
            });
        }
    }

    let state = BlockStmPrefixDb::with_parent_read_cache(
        StateProviderDatabase::new(state_provider),
        prefix_cache,
        parent_read_cache,
    );
    let db = State::builder()
        .with_database(state)
        .with_bundle_update()
        .build();
    let tracking_db = BlockStmMvTrackingDb::new(db, memory, tx_index);
    let evm = evm_config.evm_with_env(tracking_db, evm_env);
    let mut executor = BlockExecutorFactory::create_executor(evm_config, evm, execution_ctx);

    let started = Instant::now();
    let execution_result = executor.execute_transaction_without_commit(tx);
    let elapsed = started.elapsed();
    let blocking_dependency = executor.evm().db().blocking_dependency();
    let mut read_set = executor.evm().db().read_set();
    let account_write_set = execution_result
        .as_ref()
        .map(|result| account_write_set_from_evm_state(&result.result().state))
        .unwrap_or_default();
    let mut write_set = execution_result
        .as_ref()
        .map(|result| write_set_from_evm_state(&result.result().state))
        .unwrap_or_default();
    let semantic_plan = if capture_semantic_actions {
        execution_result.as_ref().ok().and_then(|result| {
            capture_tip20_semantic_plan(tx_index, pool_tx, result, &write_set, beneficiary)
        })
    } else {
        None
    };
    if let (Some(semantic_plan), Ok(result)) = (semantic_plan.as_ref(), execution_result.as_ref())
        && blockstm_result_has_only_semantic_writes(result, semantic_plan.covered_keys())
        && let Some(template) = BlockStmDirectTip20Template::from_evm_result(
            pool_tx,
            result,
            base_fee,
            spec,
            amsterdam_eip8037_enabled,
        )
    {
        let mut guard = direct_semantic_template
            .lock()
            .expect("Block-STM direct semantic template poisoned");
        if guard.is_none() {
            *guard = Some(template);
        }
    }
    if let Some(semantic_plan) = semantic_plan.as_ref() {
        read_set = read_set.without_keys(semantic_plan.covered_keys().iter());
        write_set = write_set.without_keys(semantic_plan.covered_keys().iter());
    }

    Ok(BlockStmAttempt {
        tx_index,
        attempt,
        read_set,
        write_set,
        output: BlockStmAttemptOutput {
            execution_result: Some(execution_result),
            direct_semantic_execution: None,
            elapsed,
            semantic_plan,
            blocking_dependency,
            account_write_set,
        },
    })
}

fn record_blockstm_max_in_flight(max_in_flight: &AtomicU64, active: u64) {
    let mut observed = max_in_flight.load(Ordering::Relaxed);
    while active > observed {
        match max_in_flight.compare_exchange_weak(
            observed,
            active,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}

fn record_blockstm_duration_nanos(total: &AtomicU64, elapsed: Duration) {
    total.fetch_add(
        elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
        Ordering::AcqRel,
    );
}

fn load_blockstm_duration(total: &AtomicU64) -> Duration {
    Duration::from_nanos(total.load(Ordering::Relaxed))
}

fn schedule_blockstm_validation_for_ready_suffix(
    scheduler: &BlockStmProductionScheduler,
    states: &[Mutex<BlockStmProductionTxState>],
    start: usize,
) {
    for tx_index in start..states.len() {
        schedule_blockstm_validation(scheduler, states, tx_index);
    }
}

fn schedule_blockstm_validation(
    scheduler: &BlockStmProductionScheduler,
    states: &[Mutex<BlockStmProductionTxState>],
    tx_index: usize,
) {
    let task = {
        let mut state = states[tx_index]
            .lock()
            .expect("Block-STM production transaction state poisoned");
        match state.status {
            BlockStmProductionStatus::Executed | BlockStmProductionStatus::Validated => {
                state.validation_generation += 1;
                state.revalidate_after_current = false;
                state.status = BlockStmProductionStatus::ValidationQueued;
                Some(BlockStmProductionTask {
                    tx_index,
                    incarnation: state.incarnation,
                    validation_generation: state.validation_generation,
                    kind: BlockStmProductionTaskKind::Validation,
                })
            }
            BlockStmProductionStatus::ValidationQueued => None,
            BlockStmProductionStatus::Validating => {
                state.revalidate_after_current = true;
                None
            }
            BlockStmProductionStatus::Ready
            | BlockStmProductionStatus::Executing
            | BlockStmProductionStatus::Waiting => None,
        }
    };

    if let Some(task) = task {
        scheduler.push_task(task);
    }
}

fn blockstm_dependency_resolved(
    states: &[Mutex<BlockStmProductionTxState>],
    tx_index: usize,
) -> bool {
    let state = states[tx_index]
        .lock()
        .expect("Block-STM production transaction state poisoned");
    matches!(
        state.status,
        BlockStmProductionStatus::Executed
            | BlockStmProductionStatus::ValidationQueued
            | BlockStmProductionStatus::Validating
            | BlockStmProductionStatus::Validated
    )
}

fn schedule_blockstm_execution(
    scheduler: &BlockStmProductionScheduler,
    states: &[Mutex<BlockStmProductionTxState>],
    tx_index: usize,
) {
    let mut state = states[tx_index]
        .lock()
        .expect("Block-STM production transaction state poisoned");
    if matches!(
        state.status,
        BlockStmProductionStatus::Ready | BlockStmProductionStatus::Executing
    ) {
        return;
    }
    state.incarnation += 1;
    state.validation_generation += 1;
    state.revalidate_after_current = false;
    state.status = BlockStmProductionStatus::Ready;
    scheduler.push_task(BlockStmProductionTask {
        tx_index,
        incarnation: state.incarnation,
        validation_generation: 0,
        kind: BlockStmProductionTaskKind::Execution,
    });
}

fn schedule_blockstm_dependency_waiters(
    scheduler: &BlockStmProductionScheduler,
    states: &[Mutex<BlockStmProductionTxState>],
    dependencies: &[Mutex<Vec<usize>>],
    tx_index: usize,
) {
    let waiters = dependencies[tx_index]
        .lock()
        .expect("Block-STM dependency list poisoned")
        .drain(..)
        .collect::<Vec<_>>();
    for waiter in waiters {
        schedule_blockstm_execution(scheduler, states, waiter);
    }
}

fn register_blockstm_dependency_waiter(
    scheduler: &BlockStmProductionScheduler,
    states: &[Mutex<BlockStmProductionTxState>],
    dependencies: &[Mutex<Vec<usize>>],
    waiter_tx_index: usize,
    blocking_tx_index: Option<usize>,
) {
    let Some(blocking_tx_index) = blocking_tx_index else {
        schedule_blockstm_execution(scheduler, states, waiter_tx_index);
        return;
    };

    if blockstm_dependency_resolved(states, blocking_tx_index) {
        schedule_blockstm_execution(scheduler, states, waiter_tx_index);
        return;
    }

    {
        let mut waiters = dependencies[blocking_tx_index]
            .lock()
            .expect("Block-STM dependency list poisoned");
        if !waiters.contains(&waiter_tx_index) {
            waiters.push(waiter_tx_index);
        }
    }

    if blockstm_dependency_resolved(states, blocking_tx_index) {
        schedule_blockstm_dependency_waiters(scheduler, states, dependencies, blocking_tx_index);
    }
}

fn is_blockstm_invalidated_buffered_transaction(
    invalid: &BestTransaction,
    candidate: &BestTransaction,
) -> bool {
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

fn expand_blockstm_semantic_invalidated_transactions(
    batch: &[BlockStmPoolCandidate],
    invalid_tx_indexes: &mut HashSet<usize>,
) -> bool {
    let invalid_candidates = batch
        .iter()
        .filter(|candidate| invalid_tx_indexes.contains(&candidate.tx_index))
        .collect::<Vec<_>>();
    if invalid_candidates.is_empty() {
        return false;
    }

    let mut changed = false;
    for candidate in batch {
        if invalid_tx_indexes.contains(&candidate.tx_index) {
            continue;
        }
        if invalid_candidates.iter().any(|invalid| {
            is_blockstm_invalidated_buffered_transaction(&invalid.pool_tx, &candidate.pool_tx)
        }) {
            changed |= invalid_tx_indexes.insert(candidate.tx_index);
        }
    }

    changed
}

fn hydrate_blockstm_commit_cache<DB>(
    db: &mut DB,
    result: &tempo_evm::TempoTxResult,
) -> Result<(), DB::Error>
where
    DB: Database,
{
    for address in result.result().state.keys() {
        let _ = db.basic(*address)?;
    }
    Ok(())
}

fn blockstm_result_has_only_semantic_writes(
    result: &tempo_evm::TempoTxResult,
    covered_keys: &HashSet<BlockStmAccessKey>,
) -> bool {
    result.result().state.iter().all(|(address, account)| {
        account.info == account.original_info()
            && account.storage.iter().all(|(slot, value)| {
                !value.is_changed()
                    || covered_keys.contains(&BlockStmAccessKey::Storage {
                        address: *address,
                        slot: *slot,
                    })
            })
    })
}

fn materialize_blockstm_semantic_reduction<DB>(
    db: &mut DB,
    reduction: &BlockStmSemanticReduction,
    worker_count: usize,
) -> Result<EvmState, DB::Error>
where
    DB: Database,
{
    let mut keys = reduction.touched_keys().iter().copied().collect::<Vec<_>>();
    keys.sort_unstable();

    let storage_entries = if keys.is_empty() {
        Vec::new()
    } else {
        let worker_count = worker_count.max(1).min(keys.len());
        let chunk_len = keys.len().div_ceil(worker_count).max(1);
        keys.par_chunks(chunk_len)
            .flat_map_iter(|chunk| {
                let mut entries = Vec::<(Address, U256, Option<U256>, U256)>::new();
                for key in chunk {
                    let BlockStmAccessKey::Storage { address, slot } = *key else {
                        continue;
                    };
                    let Some(value) = reduction.storage_value(key) else {
                        continue;
                    };
                    entries.push((
                        address,
                        slot,
                        reduction.original_values().get(key).copied(),
                        value,
                    ));
                }
                entries
            })
            .collect::<Vec<_>>()
    };

    let mut changes = AddressMap::<Account>::default();

    for (address, slot, original, value) in storage_entries {
        let original = match original {
            Some(original) => original,
            None => db.storage(address, slot)?,
        };
        if original == value {
            continue;
        }
        let account = match changes.entry(address) {
            alloy_primitives::map::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            alloy_primitives::map::hash_map::Entry::Vacant(entry) => {
                let info = db.basic(address)?.unwrap_or_default();
                entry.insert(Account::from(info))
            }
        };
        account.mark_touch();
        account.storage.insert(
            slot,
            EvmStorageSlot::new_changed(original, value, TransactionId::ZERO),
        );
    }

    Ok(changes)
}

#[derive(Debug, Clone)]
pub struct TempoPayloadBuilder<Provider> {
    pool: TempoTransactionPool<Provider>,
    provider: Provider,
    executor: TaskExecutor,
    evm_config: TempoEvmConfig,
    metrics: TempoPayloadBuilderMetrics,
    cache_metrics: CachedStateMetrics,
    /// Height at which we've seen an invalid subblock.
    ///
    /// We pre-validate all of the subblock transactions when collecting subblocks, so this
    /// should never be set because subblocks with invalid transactions should never make it to the payload builder.
    ///
    /// However, due to disruptive nature of subblock-related bugs (invalid subblock
    /// we're continuously failing to apply halts block building), we protect against this by tracking
    /// last height at which we've seen an invalid subblock, and not including any subblocks
    /// at this height for any payloads.
    highest_invalid_subblock: Arc<AtomicU64>,
    /// Whether the node is configured in `--dev` miner mode.
    is_dev: bool,
    /// Whether to enable state provider metrics.
    state_provider_metrics: bool,
    /// Whether to enable prewarming of best transactions.
    enable_prewarming: bool,
    /// Whether to include block access lists in built execution payloads.
    enable_bal: bool,
    /// Learned estimate of total replayable build work divided by work at tx cutoff.
    ///
    /// This lets the builder reserve time for non-interruptible
    /// `builder_finish` without a fixed duration.
    build_time_multiplier: Arc<AtomicU64>,
    /// Block-STM payload-builder configuration.
    blockstm_config: BlockStmConfig,
}

/// Runtime settings for the Tempo payload builder.
#[derive(Debug, Clone, Copy)]
pub struct TempoPayloadBuilderConfig {
    /// Whether the node is configured in `--dev` miner mode.
    pub is_dev: bool,
    /// Whether to enable state provider metrics.
    pub state_provider_metrics: bool,
    /// Whether to enable prewarming of best transactions.
    pub enable_prewarming: bool,
    /// Initial estimate of total replayable build work divided by work at tx cutoff.
    ///
    /// `1.0` means no finish-work headroom beyond observed work so far. Values
    /// above `1.0` stop transaction execution earlier to leave room for
    /// `builder_finish`, which validators also repeat.
    pub build_time_multiplier: f64,
    /// Block-STM payload-builder configuration.
    pub blockstm_config: BlockStmConfig,
}

impl Default for TempoPayloadBuilderConfig {
    fn default() -> Self {
        Self {
            is_dev: false,
            state_provider_metrics: false,
            enable_prewarming: false,
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
            blockstm_config: BlockStmConfig::default(),
        }
    }
}

impl<Provider> TempoPayloadBuilder<Provider> {
    pub fn new(
        pool: TempoTransactionPool<Provider>,
        provider: Provider,
        executor: TaskExecutor,
        evm_config: TempoEvmConfig,
        config: TempoPayloadBuilderConfig,
    ) -> Self {
        Self {
            pool,
            provider,
            executor,
            evm_config,
            metrics: TempoPayloadBuilderMetrics::default(),
            cache_metrics: CachedStateMetrics::zeroed(CachedStateMetricsSource::Builder),
            highest_invalid_subblock: Default::default(),
            is_dev: config.is_dev,
            state_provider_metrics: config.state_provider_metrics,
            enable_prewarming: config.enable_prewarming,
            enable_bal: cfg!(feature = "bal"),
            build_time_multiplier: Arc::new(AtomicU64::new(scaled_build_time_multiplier(
                config.build_time_multiplier,
            ))),
            blockstm_config: config.blockstm_config,
        }
    }

    fn build_time_multiplier(&self) -> u64 {
        self.build_time_multiplier.load(Ordering::Relaxed)
    }

    fn update_build_time_multiplier(&self, total_work: Duration, work_at_tx_cutoff: Duration) {
        let Some(observed) = observed_build_time_multiplier(total_work, work_at_tx_cutoff) else {
            return;
        };
        let _ = self.build_time_multiplier.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| Some(decay_build_time_multiplier(current, observed)),
        );
    }
}

impl<Provider: ChainSpecProvider<ChainSpec = TempoChainSpec>> TempoPayloadBuilder<Provider> {
    /// Builds system transactions to seal the block.
    ///
    /// Returns a vector of system transactions that must be executed at the end of each block:
    /// - Subblocks signatures - validates subblock signatures
    fn build_seal_block_txs(
        &self,
        evm: &TempoEvm<impl Database>,
        subblocks: &[RecoveredSubBlock],
    ) -> Vec<Recovered<TempoTxEnvelope>> {
        if subblocks.is_empty() && evm.cfg.spec.is_t4() {
            // Post-T4, omit the subblocks metadata transaction if there are no subblocks
            return vec![];
        }

        let chain_spec = self.provider.chain_spec();
        let chain_id = Some(chain_spec.chain().id());

        // Build subblocks signatures system transaction
        let subblocks_metadata = subblocks
            .iter()
            .map(|s| s.metadata())
            .collect::<Vec<SubBlockMetadata>>();
        let subblocks_input = alloy_rlp::encode(&subblocks_metadata)
            .into_iter()
            .chain(evm.block.number.to_be_bytes_vec())
            .collect();

        let subblocks_signatures_tx = Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id,
                    nonce: 0,
                    gas_price: 0,
                    gas_limit: 0,
                    to: Address::ZERO.into(),
                    value: U256::ZERO,
                    input: subblocks_input,
                },
                TEMPO_SYSTEM_TX_SIGNATURE,
            )),
            TEMPO_SYSTEM_TX_SENDER,
        );

        vec![subblocks_signatures_tx]
    }
}

impl<Provider> PayloadBuilder for TempoPayloadBuilder<Provider>
where
    Provider:
        StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec> + Clone + 'static,
{
    type Attributes = TempoPayloadAttributes;
    type BuiltPayload = TempoBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        self.build_payload(
            args,
            |attributes| self.pool.best_transactions_with_attributes(attributes),
            false,
        )
    }

    fn on_missing_payload(
        &self,
        _args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> MissingPayloadBehaviour<Self::BuiltPayload> {
        MissingPayloadBehaviour::AwaitInProgress
    }

    fn build_empty_payload(
        &self,
        config: PayloadConfig<Self::Attributes, TempoHeader>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        self.build_payload(
            BuildArguments::new(
                Default::default(),
                None,
                None,
                config,
                Default::default(),
                Default::default(),
            ),
            |_| core::iter::empty(),
            true,
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

impl<Provider> TempoPayloadBuilder<Provider>
where
    Provider:
        StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec> + Clone + 'static,
{
    #[instrument(
        target = "payload_builder",
        skip_all,
        fields(
            id = %args.config.payload_id,
            parent_number = %args.config.parent_header.number(),
            parent_hash = %args.config.parent_header.hash()
        )
    )]
    fn build_payload<Txs>(
        &self,
        args: BuildArguments<TempoPayloadAttributes, TempoBuiltPayload>,
        best_txs: impl FnOnce(BestTransactionsAttributes) -> Txs,
        empty: bool,
    ) -> Result<BuildOutcome<TempoBuiltPayload>, PayloadBuilderError>
    where
        Txs: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>
            + Send
            + 'static,
    {
        let BuildArguments {
            cached_reads,
            execution_cache,
            mut trie_handle,
            config,
            cancel,
            best_payload,
            ..
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id,
        } = config;
        let build_once_with_shared_trie =
            // When trie handle is provided, we build the payload once so the shared trie can be reused.
            trie_handle.is_some()
            // `--dev` mode does not use the shared-trie builder flow.
            && !self.is_dev;

        macro_rules! check_cancel {
            () => {
                if cancel.is_cancelled() {
                    return Ok(BuildOutcome::Cancelled);
                }
            };
        }

        check_cancel!();

        let start = Instant::now();

        let block_time_millis =
            (attributes.timestamp_millis() - parent_header.timestamp_millis()) as f64;
        self.metrics.block_time_millis.record(block_time_millis);
        self.metrics.block_time_millis_last.set(block_time_millis);

        let state_setup_start = Instant::now();
        let _state_setup_span = debug_span!(target: "payload_builder", "state_setup").entered();
        let mut state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        if let Some(execution_cache) = &execution_cache {
            state_provider = Box::new(CachedStateProvider::new(
                state_provider,
                execution_cache.cache().clone(),
                Some(self.cache_metrics.clone()),
            ));
        }
        if self.state_provider_metrics {
            state_provider = Box::new(InstrumentedStateProvider::new(state_provider, "builder"));
        }

        let state = StateProviderDatabase::new(&state_provider);
        let mut db = State::builder()
            .with_database(Box::new(state) as Box<dyn Database<Error = ProviderError>>)
            .with_bundle_update()
            .with_bal_builder_if(self.enable_bal)
            .build();
        drop(_state_setup_span);
        self.metrics
            .state_setup_duration_seconds
            .record(state_setup_start.elapsed());

        check_cancel!();

        let chain_spec = self.provider.chain_spec();
        let is_osaka = self
            .provider
            .chain_spec()
            .is_osaka_active_at_timestamp(attributes.timestamp);
        let max_estimated_block_size = if is_osaka {
            MAX_RLP_BLOCK_SIZE.saturating_sub(RLP_BLOCK_SIZE_SAFETY_MARGIN)
        } else {
            usize::MAX
        };

        let block_gas_limit: u64 = parent_header.gas_limit();
        let shared_gas_limit =
            chain_spec.shared_gas_limit_at(attributes.timestamp, block_gas_limit);
        // Non-shared gas limit is the maximum gas available for proposer's pool transactions.
        // The remaining `shared_gas_limit` is reserved for validator subblocks.
        let non_shared_gas_limit = block_gas_limit - shared_gas_limit;
        let general_gas_limit = chain_spec.general_gas_limit_at(
            attributes.timestamp,
            block_gas_limit,
            shared_gas_limit,
        );
        let hardfork = chain_spec.tempo_hardfork_at(attributes.timestamp);

        let mut cumulative_gas_used = 0;
        let mut cumulative_state_gas_used = 0u64;
        let mut non_payment_gas_used = 0;
        // initial block size usage - size of withdrawals plus 1Kb of overhead for the block header
        let mut block_size_used = attributes
            .withdrawals
            .as_ref()
            .map(|w| w.length())
            .unwrap_or(0)
            + 1024
            + attributes.extra_data().length();
        let mut payment_transactions = 0u64;
        let mut pool_transactions_yielded = 0u64;
        let mut pool_transactions_included = 0u64;
        let mut total_fees = U256::ZERO;

        // If building an empty payload, don't include any subblocks
        //
        // Also don't include any subblocks if we've seen an invalid subblock
        // at this height or above.
        let mut subblocks = if empty
            || self.highest_invalid_subblock.load(Ordering::Relaxed) > parent_header.number()
        {
            vec![]
        } else {
            attributes.subblocks()
        };

        subblocks.retain(|subblock| {
            // Edge case: remove subblocks with expired transactions
            //
            // We pre-validate all of the subblocks on top of parent state in subblocks service
            // which leaves the only reason for transactions to get invalidated by expiry of
            // `valid_before` field.
            if has_expired_transactions(subblock, attributes.timestamp) {
                self.metrics.inc_subblocks_expired();
                return false;
            }

            // Account for the subblock's size
            block_size_used += subblock.total_tx_size();

            true
        });

        let subblock_fee_recipients = subblocks
            .iter()
            .map(|subblock| {
                (
                    PartialValidatorKey::from_slice(&subblock.validator()[..15]),
                    subblock.fee_recipient,
                )
            })
            .collect();

        let next_block_attrs = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: block_gas_limit,
                parent_beacon_block_root: attributes.parent_beacon_block_root,
                withdrawals: attributes.withdrawals.clone().map(Into::into),
                extra_data: attributes.extra_data().clone(),
                slot_number: attributes.slot_number,
            },
            general_gas_limit,
            shared_gas_limit,
            timestamp_millis_part: attributes.timestamp_millis_part(),
            consensus_context: attributes.consensus_context(),
            subblock_fee_recipients,
        };
        let evm_env = self
            .evm_config
            .next_evm_env(&parent_header, &next_block_attrs)
            .map_err(PayloadBuilderError::other)?;
        let execution_ctx = self
            .evm_config
            .context_for_next_block(&parent_header, next_block_attrs)
            .map_err(PayloadBuilderError::other)?;
        let evm = self.evm_config.evm_with_env(&mut db, evm_env);
        let mut executor =
            ConfigureEvm::create_executor(&self.evm_config, evm, execution_ctx.clone());

        check_cancel!();

        // Override the fee recipient with the on-chain value from the V2
        // validator config contract, if available.
        maybe_override_fee_recipient(&mut executor, &attributes);

        if let Some(ref handle) = trie_handle {
            executor.set_state_hook(Some(Box::new(handle.state_hook())));
        }

        executor.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;
        executor.evm_mut().db_mut().bump_bal_index();

        check_cancel!();

        debug!("building new payload");

        let (roots_tx, roots_rx) = self.spawn_roots_task();

        // Prepare system transactions before actual block building and account for their size.
        let prepare_system_txs_start = Instant::now();
        let system_txs = self.build_seal_block_txs(executor.evm(), &subblocks);
        for tx in &system_txs {
            block_size_used += tx.inner().length();
        }
        let prepare_system_txs_elapsed = prepare_system_txs_start.elapsed();
        self.metrics
            .prepare_system_transactions_duration_seconds
            .record(prepare_system_txs_elapsed);

        let base_fee = executor.evm().block().basefee;
        let pool_fetch_start = Instant::now();
        let best_txs = best_txs(BestTransactionsAttributes::new(
            base_fee,
            executor
                .evm()
                .block()
                .blob_gasprice()
                .map(|gasprice| gasprice as u64),
        ));
        // Wrap best transactions into state-aware wrapper to skip transactions that
        // get invalidated by already-executed ones.
        let enable_best_txs_prewarming = self.enable_prewarming && !self.blockstm_config.enabled;
        let mut best_txs = StateAwareBestTransactions::new(if enable_best_txs_prewarming {
            Box::new(BestTransactionsPrewarming::new(
                self.executor.clone(),
                self.provider.clone(),
                execution_cache,
                parent_header.hash(),
                executor.evm().evm_env(),
                best_txs,
            )) as Box<dyn BestTransactions<Item = _>>
        } else {
            Box::new(best_txs)
        });
        self.metrics
            .pool_fetch_duration_seconds
            .record(pool_fetch_start.elapsed());

        let execution_start = Instant::now();
        let _block_fill_span = debug_span!(target: "payload_builder", "block_fill").entered();
        let mut skipped_oversized_block = false;
        let mut invalid_pool_transaction_execution_attempts = 0u64;
        let mut normal_transaction_fill_idle_elapsed = Duration::ZERO;
        // Consensus builds carry a remaining proposal budget. When present, the
        // builder stops pool tx execution before projected proposer and validator
        // work would consume that window.
        let payload_build_budget = attributes.payload_build_budget();
        let build_time_multiplier = self.build_time_multiplier();
        let marshal_persist = marshal_persist_estimate();
        let mut blockstm_stats = BlockStmExecutionStats::default();
        let mut blockstm_batch_setup_elapsed = Duration::ZERO;
        let mut blockstm_prefix_cache_clone_elapsed = Duration::ZERO;
        let mut blockstm_worker_elapsed = Duration::ZERO;
        let mut blockstm_attempt_wall_elapsed_sum = Duration::ZERO;
        let mut blockstm_evm_execution_elapsed_sum = Duration::ZERO;
        let mut blockstm_publish_elapsed_sum = Duration::ZERO;
        let mut blockstm_validation_elapsed_sum = Duration::ZERO;
        let mut blockstm_fast_semantic_elapsed = Duration::ZERO;
        let mut blockstm_fast_commit_elapsed = Duration::ZERO;
        let mut blockstm_semantic_lane_build_elapsed = Duration::ZERO;
        let mut blockstm_semantic_lane_reduce_elapsed = Duration::ZERO;
        let mut blockstm_semantic_materialize_elapsed = Duration::ZERO;
        let mut blockstm_semantic_commit_elapsed = Duration::ZERO;
        let mut blockstm_validation_tasks = 0u64;
        let mut blockstm_publish_tasks = 0u64;
        let mut blockstm_read_keys = 0u64;
        let mut blockstm_write_keys = 0u64;
        let mut blockstm_account_write_keys = 0u64;
        let mut blockstm_semantic_plans = 0u64;
        let mut blockstm_direct_semantic_executions = 0u64;
        let mut blockstm_semantic_lanes_reduced = 0u64;
        let mut blockstm_semantic_fixpoint_iterations = 0u64;
        let mut blockstm_semantic_invalid_txs = 0u64;
        let block_build_stop_reason = if self.blockstm_config.enabled && !empty {
            let max_batch_len = self
                .blockstm_config
                .workers
                .max(1)
                .saturating_mul(512)
                .clamp(1, 16_384);
            let parent_hash = parent_header.hash();
            let mut pending_candidates = VecDeque::<BlockStmPoolCandidate>::new();
            let mut next_blockstm_tx_index = 0usize;
            let mut semantic_state = BlockStmSemanticState::default();

            'blockstm_pool_fill: loop {
                check_cancel!();

                if let Some(build_budget) = payload_build_budget {
                    let elapsed = start.elapsed();
                    if payload_budget_exhausted(
                        elapsed,
                        normal_transaction_fill_idle_elapsed,
                        build_time_multiplier,
                        build_budget,
                        marshal_persist,
                        block_size_used,
                    ) {
                        let estimated_marshal_persist = marshal_persist.estimate(block_size_used);
                        debug!(
                            target: "payload_builder",
                            ?elapsed,
                            ?normal_transaction_fill_idle_elapsed,
                            ?build_budget,
                            ?estimated_marshal_persist,
                            block_size_used,
                            build_time_multiplier = build_time_multiplier as f64
                                / BUILD_TIME_MULTIPLIER_SCALE as f64,
                            "stopping pool transaction execution before payload build budget is exhausted"
                        );
                        break BlockBuildStopReason::BuildBudget;
                    }
                }

                let mut batch = Vec::with_capacity(max_batch_len);
                let mut reserved_gas_used = cumulative_gas_used;
                let mut reserved_non_payment_gas_used = non_payment_gas_used;
                let mut reserved_block_size_used = block_size_used;
                let mut exhausted_pool = false;

                while batch.len() < max_batch_len {
                    let candidate = if let Some(candidate) = pending_candidates.pop_front() {
                        candidate
                    } else {
                        let Some(pool_tx) = best_txs.next() else {
                            exhausted_pool = true;
                            break;
                        };
                        pool_transactions_yielded += 1;

                        let max_regular_gas_used = core::cmp::min(
                            pool_tx.gas_limit(),
                            executor.evm().cfg.tx_gas_limit_cap.unwrap_or(u64::MAX),
                        );
                        let is_payment = if hardfork.is_t5() {
                            pool_tx.transaction.is_payment()
                        } else {
                            pool_tx.transaction.inner().is_payment_v1()
                        };
                        let tx_rlp_length = pool_tx.transaction.encoded_length();
                        let tx_debug_repr = tracing::enabled!(Level::TRACE)
                            .then(|| format!("{:?}", pool_tx.transaction))
                            .unwrap_or_default();
                        let tx_with_env = pool_tx.transaction.clone_into_with_tx_env();
                        let tx_index = next_blockstm_tx_index;
                        next_blockstm_tx_index += 1;

                        BlockStmPoolCandidate {
                            tx_index,
                            pool_tx,
                            tx_with_env,
                            max_regular_gas_used,
                            is_payment,
                            tx_rlp_length,
                            tx_debug_repr,
                        }
                    };

                    if reserved_gas_used + candidate.max_regular_gas_used > non_shared_gas_limit {
                        if batch.is_empty() {
                            if cumulative_gas_used > 0 {
                                break 'blockstm_pool_fill BlockBuildStopReason::GasLimit;
                            }
                            best_txs.mark_invalid(
                                &candidate.pool_tx,
                                InvalidPoolTransactionError::ExceedsGasLimit(
                                    candidate.pool_tx.gas_limit(),
                                    non_shared_gas_limit - reserved_gas_used,
                                ),
                            );
                            self.metrics
                                .inc_pool_tx_skipped("exceeds_non_shared_gas_limit");
                            continue;
                        }

                        pending_candidates.push_front(candidate);
                        break;
                    }

                    if !candidate.is_payment
                        && reserved_non_payment_gas_used + candidate.max_regular_gas_used
                            > general_gas_limit
                    {
                        if batch.is_empty() {
                            best_txs.mark_invalid(
                                &candidate.pool_tx,
                                InvalidPoolTransactionError::Other(Box::new(
                                    TempoPoolTransactionError::ExceedsNonPaymentLimit,
                                )),
                            );
                            self.metrics
                                .inc_pool_tx_skipped("exceeds_general_gas_limit");
                            continue;
                        }

                        pending_candidates.push_front(candidate);
                        break;
                    }

                    let estimated_block_size_with_tx =
                        reserved_block_size_used + candidate.tx_rlp_length;
                    if estimated_block_size_with_tx > max_estimated_block_size {
                        if batch.is_empty() {
                            if block_size_used > 0 {
                                break 'blockstm_pool_fill BlockBuildStopReason::RlpBlockSizeLimit;
                            }
                            if candidate.is_payment {
                                payment_transactions += 1;
                            }
                            best_txs.mark_invalid(
                                &candidate.pool_tx,
                                InvalidPoolTransactionError::OversizedData {
                                    size: estimated_block_size_with_tx,
                                    limit: MAX_RLP_BLOCK_SIZE,
                                },
                            );
                            self.metrics.inc_pool_tx_skipped("oversized_block");
                            skipped_oversized_block = true;
                            continue;
                        }

                        pending_candidates.push_front(candidate);
                        break;
                    }

                    reserved_gas_used += candidate.max_regular_gas_used;
                    if !candidate.is_payment {
                        reserved_non_payment_gas_used += candidate.max_regular_gas_used;
                    }
                    reserved_block_size_used += candidate.tx_rlp_length;
                    batch.push(candidate);
                }

                if batch.is_empty() {
                    if exhausted_pool {
                        if build_once_with_shared_trie
                            && payload_build_budget.is_some()
                            && cumulative_gas_used < non_shared_gas_limit
                        {
                            std::thread::sleep(Duration::from_millis(1));
                            normal_transaction_fill_idle_elapsed += Duration::from_millis(1);
                            continue;
                        }

                        let stop_reason = if cumulative_gas_used >= non_shared_gas_limit {
                            BlockBuildStopReason::GasLimit
                        } else if skipped_oversized_block {
                            BlockBuildStopReason::RlpBlockSizeLimit
                        } else {
                            BlockBuildStopReason::TxPoolEmpty
                        };
                        break stop_reason;
                    }

                    continue;
                }

                let batch_setup_started = Instant::now();
                let prefix_cache_clone_started = Instant::now();
                let prefix_cache = Arc::new(executor.evm_mut().db_mut().cache.clone());
                blockstm_prefix_cache_clone_elapsed += prefix_cache_clone_started.elapsed();
                let parent_read_cache = Arc::new(BlockStmParentReadCache::default());
                let evm_env = executor.evm().evm_env();
                let execution_ctx = execution_ctx.clone();
                let beneficiary = executor.evm().block().beneficiary;
                let batch_first_tx_index = batch[0].tx_index;
                let worker_count = self.blockstm_config.workers.max(1);
                let tip20_actions = self.blockstm_config.tip20_actions;
                let attempt_slots = (0..batch.len())
                    .map(|_| Mutex::new(None))
                    .collect::<Vec<_>>();
                let memory = BlockStmMvMemory::default();
                let states = (0..batch.len())
                    .map(|_| {
                        Mutex::new(BlockStmProductionTxState {
                            incarnation: 0,
                            validation_generation: 0,
                            revalidate_after_current: false,
                            status: BlockStmProductionStatus::Ready,
                        })
                    })
                    .collect::<Vec<_>>();
                let dependencies = (0..batch.len())
                    .map(|_| Mutex::new(Vec::<usize>::new()))
                    .collect::<Vec<_>>();
                let scheduler = BlockStmProductionScheduler::new(batch.len());
                let direct_semantic_template =
                    Arc::new(Mutex::new(None::<BlockStmDirectTip20Template>));
                let worker_error = Mutex::new(None);
                let in_flight = AtomicU64::new(0);
                let max_in_flight = AtomicU64::new(0);
                let speculative_executions = AtomicU64::new(0);
                let conflicts = AtomicU64::new(0);
                let reexecutions = AtomicU64::new(0);
                let attempt_wall_nanos = AtomicU64::new(0);
                let evm_execution_nanos = AtomicU64::new(0);
                let publish_nanos = AtomicU64::new(0);
                let validation_nanos = AtomicU64::new(0);
                let validation_task_count = AtomicU64::new(0);
                let publish_task_count = AtomicU64::new(0);
                let read_key_count = AtomicU64::new(0);
                let write_key_count = AtomicU64::new(0);
                let account_write_key_count = AtomicU64::new(0);
                let semantic_plan_count = AtomicU64::new(0);
                let direct_semantic_count = AtomicU64::new(0);
                blockstm_batch_setup_elapsed += batch_setup_started.elapsed();

                let worker_started = Instant::now();
                self.executor.prewarming_pool().in_place_scope(|scope| {
                    let batch_ref = &batch;
                    for _ in 0..worker_count {
                        let batch = batch_ref;
                        let provider = self.provider.clone();
                        let evm_config = &self.evm_config;
                        let evm_env = evm_env.clone();
                        let execution_ctx = execution_ctx.clone();
                        let prefix_cache = prefix_cache.clone();
                        let parent_read_cache = parent_read_cache.clone();
                        let direct_semantic_template = direct_semantic_template.clone();
                        let attempt_slots = &attempt_slots;
                        let states = &states;
                        let dependencies = &dependencies;
                        let scheduler = &scheduler;
                        let memory = &memory;
                        let worker_error = &worker_error;
                        let in_flight = &in_flight;
                        let max_in_flight = &max_in_flight;
                        let speculative_executions = &speculative_executions;
                        let conflicts = &conflicts;
                        let reexecutions = &reexecutions;
                        let attempt_wall_nanos = &attempt_wall_nanos;
                        let evm_execution_nanos = &evm_execution_nanos;
                        let publish_nanos = &publish_nanos;
                        let validation_nanos = &validation_nanos;
                        let validation_task_count = &validation_task_count;
                        let publish_task_count = &publish_task_count;
                        let read_key_count = &read_key_count;
                        let write_key_count = &write_key_count;
                        let account_write_key_count = &account_write_key_count;
                        let semantic_plan_count = &semantic_plan_count;
                        let direct_semantic_count = &direct_semantic_count;

                        scope.spawn(move |_| {
                            let mut state_provider = None;
                            while let Some(task) = scheduler.next_task() {
                                if worker_error
                                    .lock()
                                    .expect("Block-STM worker error poisoned")
                                    .is_some()
                                {
                                    scheduler.finish_task();
                                    break;
                                }

                                match task.kind {
                                    BlockStmProductionTaskKind::Execution => {
                                        let stale_task = {
                                            let mut state = states[task.tx_index]
                                                .lock()
                                                .expect("Block-STM production transaction state poisoned");
                                            if state.incarnation != task.incarnation
                                                || state.status != BlockStmProductionStatus::Ready
                                            {
                                                true
                                            } else {
                                                state.status = BlockStmProductionStatus::Executing;
                                                false
                                            }
                                        };
                                        if stale_task {
                                            scheduler.finish_task();
                                            continue;
                                        }

                                        let candidate = &batch[task.tx_index];
                                        if state_provider.is_none() {
                                            match provider.state_by_block_hash(parent_hash) {
                                                Ok(provider) => state_provider = Some(provider),
                                                Err(err) => {
                                                    let mut worker_error = worker_error
                                                        .lock()
                                                        .expect(
                                                            "Block-STM worker error poisoned",
                                                        );
                                                    if worker_error.is_none() {
                                                        *worker_error = Some(
                                                            BlockExecutionError::other(err),
                                                        );
                                                    }
                                                    scheduler.finish_task();
                                                    continue;
                                                }
                                            }
                                        }
                                        let state_provider = state_provider
                                            .as_ref()
                                            .expect("Block-STM state provider initialized");
                                        let active = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                                        record_blockstm_max_in_flight(max_in_flight, active);
                                        let attempt_started = Instant::now();
                                        let attempt = execute_blockstm_attempt(
                                            state_provider,
                                            evm_config,
                                            evm_env.clone(),
                                            execution_ctx.clone(),
                                            prefix_cache.clone(),
                                            parent_read_cache.clone(),
                                            memory,
                                            candidate.tx_index,
                                            task.incarnation,
                                            candidate.tx_with_env.clone(),
                                            &candidate.pool_tx.transaction,
                                            tip20_actions,
                                            &direct_semantic_template,
                                            beneficiary,
                                        );
                                        record_blockstm_duration_nanos(
                                            attempt_wall_nanos,
                                            attempt_started.elapsed(),
                                        );
                                        in_flight.fetch_sub(1, Ordering::AcqRel);
                                        speculative_executions.fetch_add(1, Ordering::AcqRel);

                                        match attempt {
                                            Ok(attempt) => {
                                                record_blockstm_duration_nanos(
                                                    evm_execution_nanos,
                                                    attempt.output.elapsed,
                                                );
                                                read_key_count.fetch_add(
                                                    attempt.read_set.len() as u64,
                                                    Ordering::AcqRel,
                                                );
                                                write_key_count.fetch_add(
                                                    attempt.write_set.len() as u64,
                                                    Ordering::AcqRel,
                                                );
                                                account_write_key_count.fetch_add(
                                                    attempt.output.account_write_set.len() as u64,
                                                    Ordering::AcqRel,
                                                );
                                                if attempt.output.semantic_plan.is_some() {
                                                    semantic_plan_count
                                                        .fetch_add(1, Ordering::AcqRel);
                                                }
                                                if attempt
                                                    .output
                                                    .direct_semantic_execution
                                                    .is_some()
                                                {
                                                    direct_semantic_count
                                                        .fetch_add(1, Ordering::AcqRel);
                                                }
                                                if let Some(blocking_tx_index) =
                                                    attempt.output.blocking_dependency
                                                {
                                                    let blocking_batch_index = blocking_tx_index
                                                        .checked_sub(batch_first_tx_index)
                                                        .filter(|index| *index < batch.len());
                                                    {
                                                        let mut state = states[task.tx_index]
                                                            .lock()
                                                            .expect("Block-STM production transaction state poisoned");
                                                        if state.incarnation == task.incarnation {
                                                            state.status =
                                                                BlockStmProductionStatus::Waiting;
                                                        }
                                                    }
                                                    register_blockstm_dependency_waiter(
                                                        scheduler,
                                                        states,
                                                        dependencies,
                                                        task.tx_index,
                                                        blocking_batch_index,
                                                    );
                                                } else {
                                                    let version =
                                                        crate::blockstm::BlockStmVersion::new(
                                                            candidate.tx_index,
                                                            task.incarnation,
                                                        );
                                                    let publish_started = Instant::now();
                                                    memory.publish_value(
                                                        version,
                                                        &attempt.write_set,
                                                    );
                                                    memory.publish_account_values(
                                                        version,
                                                        &attempt.output.account_write_set,
                                                    );
                                                    record_blockstm_duration_nanos(
                                                        publish_nanos,
                                                        publish_started.elapsed(),
                                                    );
                                                    publish_task_count
                                                        .fetch_add(1, Ordering::AcqRel);
                                                    let publishes_mv_writes =
                                                        !attempt.write_set.is_empty()
                                                            || !attempt
                                                                .output
                                                                .account_write_set
                                                                .is_empty();
                                                    let should_revalidate_suffix = {
                                                        let mut slot = attempt_slots[task.tx_index]
                                                            .lock()
                                                            .expect("Block-STM attempt slot poisoned");
                                                        let should_revalidate = slot.as_ref().map_or(
                                                            publishes_mv_writes,
                                                            |previous: &BlockStmAttempt<
                                                                BlockStmAttemptOutput,
                                                            >| {
                                                                let previously_published_mv_writes =
                                                                    !previous.write_set.is_empty()
                                                                        || !previous
                                                                            .output
                                                                            .account_write_set
                                                                            .is_empty();
                                                                (publishes_mv_writes
                                                                    || previously_published_mv_writes)
                                                                    && (previous.write_set
                                                                        != attempt.write_set
                                                                        || previous
                                                                            .output
                                                                            .account_write_set
                                                                            != attempt
                                                                                .output
                                                                                .account_write_set)
                                                            },
                                                        );
                                                        *slot = Some(attempt);
                                                        should_revalidate
                                                    };
                                                    {
                                                        let mut state = states[task.tx_index]
                                                            .lock()
                                                            .expect("Block-STM production transaction state poisoned");
                                                        if state.incarnation == task.incarnation {
                                                            state.status =
                                                                BlockStmProductionStatus::Executed;
                                                        }
                                                    }
                                                    schedule_blockstm_dependency_waiters(
                                                        scheduler,
                                                        states,
                                                        dependencies,
                                                        task.tx_index,
                                                    );
                                                    schedule_blockstm_validation(
                                                        scheduler,
                                                        states,
                                                        task.tx_index,
                                                    );
                                                    if should_revalidate_suffix {
                                                        schedule_blockstm_validation_for_ready_suffix(
                                                            scheduler,
                                                            states,
                                                            task.tx_index + 1,
                                                        );
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                let mut worker_error = worker_error
                                                    .lock()
                                                    .expect("Block-STM worker error poisoned");
                                                if worker_error.is_none() {
                                                    *worker_error = Some(err);
                                                }
                                            }
                                        }
                                    }
                                    BlockStmProductionTaskKind::Validation => {
                                        let stale_task = {
                                            let mut state = states[task.tx_index]
                                                .lock()
                                                .expect("Block-STM production transaction state poisoned");
                                            if state.incarnation != task.incarnation
                                                || state.validation_generation
                                                    != task.validation_generation
                                                || state.status
                                                    != BlockStmProductionStatus::ValidationQueued
                                            {
                                                true
                                            } else {
                                                state.status = BlockStmProductionStatus::Validating;
                                                false
                                            }
                                        };
                                        if stale_task {
                                            scheduler.finish_task();
                                            continue;
                                        }

                                        let validation_result = {
                                            let slot = attempt_slots[task.tx_index]
                                                .lock()
                                                .expect("Block-STM attempt slot poisoned");
                                            if let Some(attempt) = slot.as_ref() {
                                                if attempt.attempt != task.incarnation {
                                                    Some(Ok(()))
                                                } else {
                                                    validation_task_count
                                                        .fetch_add(1, Ordering::AcqRel);
                                                    let validation_started = Instant::now();
                                                    let result = memory.validate_reads(
                                                        batch[task.tx_index].tx_index,
                                                        &attempt.read_set,
                                                    );
                                                    record_blockstm_duration_nanos(
                                                        validation_nanos,
                                                        validation_started.elapsed(),
                                                    );
                                                    Some(result)
                                                }
                                            } else {
                                                None
                                            }
                                        };
                                        let Some(validation_result) = validation_result else {
                                            let mut state = states[task.tx_index]
                                                .lock()
                                                .expect("Block-STM production transaction state poisoned");
                                            if state.incarnation == task.incarnation
                                                && state.validation_generation
                                                    == task.validation_generation
                                                && state.status
                                                    == BlockStmProductionStatus::Validating
                                            {
                                                state.status = BlockStmProductionStatus::Executed;
                                            }
                                            scheduler.finish_task();
                                            continue;
                                        };
                                        match validation_result {
                                            Ok(()) => {
                                                let task = {
                                                    let mut state = states[task.tx_index]
                                                        .lock()
                                                        .expect("Block-STM production transaction state poisoned");
                                                    if state.incarnation == task.incarnation
                                                        && state.validation_generation
                                                            == task.validation_generation
                                                        && state.status
                                                            == BlockStmProductionStatus::Validating
                                                    {
                                                        if state.revalidate_after_current {
                                                            state.validation_generation += 1;
                                                            state.revalidate_after_current = false;
                                                            state.status =
                                                                BlockStmProductionStatus::ValidationQueued;
                                                            Some(BlockStmProductionTask {
                                                                tx_index: task.tx_index,
                                                                incarnation: task.incarnation,
                                                                validation_generation: state
                                                                    .validation_generation,
                                                                kind: BlockStmProductionTaskKind::Validation,
                                                            })
                                                        } else {
                                                            state.status =
                                                                BlockStmProductionStatus::Validated;
                                                            None
                                                        }
                                                    } else {
                                                        None
                                                    }
                                                };
                                                if let Some(task) = task {
                                                    scheduler.push_task(task);
                                                }
                                            }
                                            Err(_) => {
                                                conflicts.fetch_add(1, Ordering::AcqRel);
                                                reexecutions.fetch_add(1, Ordering::AcqRel);
                                                {
                                                    let slot = attempt_slots[task.tx_index]
                                                        .lock()
                                                        .expect("Block-STM attempt slot poisoned");
                                                    if let Some(attempt) = slot.as_ref()
                                                        && attempt.attempt == task.incarnation
                                                    {
                                                        let version =
                                                            crate::blockstm::BlockStmVersion::new(
                                                                batch[task.tx_index].tx_index,
                                                                task.incarnation,
                                                            );
                                                        memory.mark_estimate(
                                                            version,
                                                            &attempt.write_set,
                                                        );
                                                        memory.mark_account_estimates(
                                                            version,
                                                            &attempt.output.account_write_set,
                                                        );
                                                    }
                                                }
                                                schedule_blockstm_execution(
                                                    scheduler,
                                                    states,
                                                    task.tx_index,
                                                );
                                                schedule_blockstm_validation_for_ready_suffix(
                                                    scheduler,
                                                    states,
                                                    task.tx_index + 1,
                                                );
                                            }
                                        }
                                    }
                                }

                                scheduler.finish_task();
                            }
                        });
                    }
                });
                blockstm_worker_elapsed += worker_started.elapsed();
                blockstm_attempt_wall_elapsed_sum += load_blockstm_duration(&attempt_wall_nanos);
                blockstm_evm_execution_elapsed_sum += load_blockstm_duration(&evm_execution_nanos);
                blockstm_publish_elapsed_sum += load_blockstm_duration(&publish_nanos);
                blockstm_validation_elapsed_sum += load_blockstm_duration(&validation_nanos);
                blockstm_validation_tasks += validation_task_count.load(Ordering::Relaxed);
                blockstm_publish_tasks += publish_task_count.load(Ordering::Relaxed);
                blockstm_read_keys += read_key_count.load(Ordering::Relaxed);
                blockstm_write_keys += write_key_count.load(Ordering::Relaxed);
                blockstm_account_write_keys += account_write_key_count.load(Ordering::Relaxed);
                blockstm_semantic_plans += semantic_plan_count.load(Ordering::Relaxed);
                blockstm_direct_semantic_executions +=
                    direct_semantic_count.load(Ordering::Relaxed);
                if let Some(err) = worker_error
                    .into_inner()
                    .expect("Block-STM worker error poisoned")
                {
                    return Err(PayloadBuilderError::evm(err));
                }

                blockstm_stats.max_in_flight_real_evm_executions = blockstm_stats
                    .max_in_flight_real_evm_executions
                    .max(max_in_flight.load(Ordering::Relaxed));
                blockstm_stats.speculative_executions_total +=
                    speculative_executions.load(Ordering::Relaxed);
                blockstm_stats.conflicts_total += conflicts.load(Ordering::Relaxed);
                blockstm_stats.reexecutions_total += reexecutions.load(Ordering::Relaxed);

                let mut attempt_slots = attempt_slots
                    .into_iter()
                    .map(|slot| slot.into_inner().expect("Block-STM attempt slot poisoned"))
                    .collect::<Vec<_>>();
                let mut invalidated = Vec::<BestTransaction>::new();

                let fast_semantic_started = Instant::now();
                let mut fast_attempt_indices = Vec::with_capacity(batch.len());
                let fast_semantic_reduction = {
                    let block_timestamp = executor.evm().block().timestamp.to::<u64>();
                    let mut fast_gas_used = cumulative_gas_used;
                    let mut fast_non_payment_gas_used = non_payment_gas_used;
                    let mut fast_block_size_used = block_size_used;
                    let mut eligible = true;

                    for (batch_index, candidate) in batch.iter().enumerate() {
                        if fast_gas_used + candidate.max_regular_gas_used > non_shared_gas_limit {
                            eligible = false;
                            break;
                        }
                        if !candidate.is_payment
                            && fast_non_payment_gas_used + candidate.max_regular_gas_used
                                > general_gas_limit
                        {
                            eligible = false;
                            break;
                        }
                        if fast_block_size_used + candidate.tx_rlp_length > max_estimated_block_size
                        {
                            eligible = false;
                            break;
                        }

                        let Some(attempt) = attempt_slots[batch_index].as_ref() else {
                            eligible = false;
                            break;
                        };
                        let Some(semantic_plan) = attempt.output.semantic_plan.as_ref() else {
                            eligible = false;
                            break;
                        };
                        if attempt.output.direct_semantic_execution.is_none() {
                            let Some(Ok(result)) = &attempt.output.execution_result else {
                                eligible = false;
                                break;
                            };
                            if !blockstm_result_has_only_semantic_writes(
                                result,
                                semantic_plan.covered_keys(),
                            ) {
                                eligible = false;
                                break;
                            }
                        }
                        fast_attempt_indices.push(batch_index);

                        fast_gas_used += candidate.max_regular_gas_used;
                        if !candidate.is_payment {
                            fast_non_payment_gas_used += candidate.max_regular_gas_used;
                        }
                        fast_block_size_used += candidate.tx_rlp_length;
                    }

                    if eligible {
                        let semantic_records = fast_attempt_indices
                            .iter()
                            .map(|batch_index| {
                                let attempt = attempt_slots[*batch_index]
                                    .as_ref()
                                    .expect("fast semantic eligibility checked attempts");
                                attempt
                                    .output
                                    .semantic_plan
                                    .as_ref()
                                    .and_then(|plan| plan.to_record(attempt.attempt))
                            })
                            .collect::<Option<Vec<_>>>();

                        let mut semantic_invalid_tx_indexes = HashSet::default();
                        let mut final_reduction = None;
                        let mut local_lane_build_elapsed = Duration::ZERO;
                        let mut local_lane_reduce_elapsed = Duration::ZERO;
                        let mut local_lanes_reduced = 0u64;
                        let mut local_fixpoint_iterations = 0u64;

                        if let Some(semantic_records) = semantic_records {
                            loop {
                                let active_records = semantic_records
                                    .iter()
                                    .filter(|record| {
                                        !semantic_invalid_tx_indexes.contains(&record.tx_index())
                                    })
                                    .cloned()
                                    .collect::<Vec<_>>();
                                let reduction = match reduce_tip20_semantic_records(
                                    executor.evm_mut().db_mut(),
                                    &active_records,
                                    block_timestamp,
                                    worker_count,
                                ) {
                                    Ok(reduction) => reduction,
                                    Err(_) => {
                                        eligible = false;
                                        break;
                                    }
                                };
                                local_lane_build_elapsed += reduction.timings.lane_build_elapsed;
                                local_lane_reduce_elapsed += reduction.timings.lane_reduce_elapsed;
                                local_lanes_reduced += reduction.lane_count as u64;
                                local_fixpoint_iterations += reduction.fixpoint_iterations as u64;

                                let before_invalid_count = semantic_invalid_tx_indexes.len();
                                semantic_invalid_tx_indexes
                                    .extend(reduction.invalid_tx_indexes().iter().copied());
                                expand_blockstm_semantic_invalidated_transactions(
                                    &batch,
                                    &mut semantic_invalid_tx_indexes,
                                );

                                if semantic_invalid_tx_indexes.len() == before_invalid_count {
                                    final_reduction = Some(reduction);
                                    break;
                                }
                            }
                        } else {
                            eligible = false;
                        }

                        blockstm_semantic_lane_build_elapsed += local_lane_build_elapsed;
                        blockstm_semantic_lane_reduce_elapsed += local_lane_reduce_elapsed;
                        blockstm_semantic_lanes_reduced += local_lanes_reduced;
                        blockstm_semantic_fixpoint_iterations += local_fixpoint_iterations;
                        blockstm_semantic_invalid_txs += semantic_invalid_tx_indexes.len() as u64;

                        eligible
                            .then_some(final_reduction)
                            .flatten()
                            .map(|reduction| (reduction, semantic_invalid_tx_indexes))
                    } else {
                        None
                    }
                };
                blockstm_fast_semantic_elapsed += fast_semantic_started.elapsed();

                if let Some((semantic_reduction, semantic_invalid_tx_indexes)) =
                    fast_semantic_reduction
                {
                    executor.reserve_receipts(batch.len());

                    let fast_commit_started = Instant::now();
                    for (batch_index, candidate) in batch.iter().enumerate() {
                        check_cancel!();

                        if semantic_invalid_tx_indexes.contains(&candidate.tx_index) {
                            best_txs.mark_invalid(
                                &candidate.pool_tx,
                                InvalidPoolTransactionError::Consensus(
                                    InvalidTransactionError::TxTypeNotSupported,
                                ),
                            );
                            self.metrics.inc_pool_tx_skipped("invalid_tx");
                            invalidated.push(candidate.pool_tx.clone());
                            pending_candidates.retain(|pending| {
                                !is_blockstm_invalidated_buffered_transaction(
                                    &candidate.pool_tx,
                                    &pending.pool_tx,
                                )
                            });
                            let _ = attempt_slots[batch_index].take();
                            continue;
                        }

                        if candidate.is_payment {
                            payment_transactions += 1;
                        }

                        let attempt = attempt_slots[batch_index]
                            .take()
                            .expect("Block-STM attempt must be available");
                        let BlockStmAttempt { output, .. } = attempt;
                        let BlockStmAttemptOutput {
                            execution_result,
                            direct_semantic_execution,
                            elapsed,
                            semantic_plan,
                            ..
                        } = output;
                        let semantic_plan =
                            semantic_plan.expect("fast semantic batch requires semantic plans");

                        blockstm_stats.semantic_actions_total +=
                            semantic_plan.action_count() as u64;
                        blockstm_stats.committed_txs_total += 1;
                        if attempt.attempt == 0 {
                            blockstm_stats.reused_speculative_results_total += 1;
                        }
                        trace!(?elapsed, "Transaction executed through Block-STM");

                        let (commit, block_gas_used, state_gas_used, validator_fee) =
                            if let Some(direct_execution) = direct_semantic_execution {
                                (
                                    direct_execution.commit,
                                    direct_execution.block_gas_used,
                                    direct_execution.state_gas_used,
                                    direct_execution.validator_fee,
                                )
                            } else {
                                let result = execution_result
                                    .expect("fast semantic batch only contains attempted txs")
                                    .expect("fast semantic batch only contains valid txs");
                                let block_gas_used = result.block_gas_used();
                                let state_gas_used = result.state_gas_used();
                                let validator_fee = result.validator_fee();
                                (
                                    result.into_stripped_commit_unchecked(),
                                    block_gas_used,
                                    state_gas_used,
                                    validator_fee,
                                )
                            };

                        cumulative_gas_used += block_gas_used;
                        cumulative_state_gas_used += state_gas_used;
                        if !candidate.is_payment {
                            non_payment_gas_used += block_gas_used;
                        }
                        total_fees += validator_fee;

                        executor.commit_prepared_stripped_transaction(commit);
                        executor.evm_mut().db_mut().bump_bal_index();
                        let _ = roots_tx.send((
                            BuilderTx::Pooled(candidate.pool_tx.clone()),
                            executor.receipts().last().unwrap().clone(),
                        ));

                        pool_transactions_included += 1;
                        block_size_used += candidate.tx_rlp_length;
                    }
                    blockstm_fast_commit_elapsed += fast_commit_started.elapsed();

                    let semantic_materialize_started = Instant::now();
                    let semantic_changes = materialize_blockstm_semantic_reduction(
                        executor.evm_mut().db_mut(),
                        &semantic_reduction,
                        worker_count,
                    )
                    .map_err(|err| PayloadBuilderError::evm(BlockExecutionError::other(err)))?;
                    blockstm_semantic_materialize_elapsed += semantic_materialize_started.elapsed();
                    semantic_state.apply_reduction(&semantic_reduction);
                    best_txs.on_state_changes(&semantic_changes);
                    if !semantic_changes.is_empty() {
                        let semantic_commit_started = Instant::now();
                        executor.commit_semantic_state_changes(semantic_changes);
                        blockstm_semantic_commit_elapsed += semantic_commit_started.elapsed();
                    }

                    continue;
                }
                for (batch_index, candidate) in batch.iter().enumerate() {
                    if invalidated.iter().any(|invalid| {
                        is_blockstm_invalidated_buffered_transaction(invalid, &candidate.pool_tx)
                    }) {
                        continue;
                    }

                    if cumulative_gas_used + candidate.max_regular_gas_used > non_shared_gas_limit {
                        best_txs.mark_invalid(
                            &candidate.pool_tx,
                            InvalidPoolTransactionError::ExceedsGasLimit(
                                candidate.pool_tx.gas_limit(),
                                non_shared_gas_limit - cumulative_gas_used,
                            ),
                        );
                        self.metrics
                            .inc_pool_tx_skipped("exceeds_non_shared_gas_limit");
                        invalidated.push(candidate.pool_tx.clone());
                        pending_candidates.retain(|pending| {
                            !is_blockstm_invalidated_buffered_transaction(
                                &candidate.pool_tx,
                                &pending.pool_tx,
                            )
                        });
                        continue;
                    }
                    if !candidate.is_payment
                        && non_payment_gas_used + candidate.max_regular_gas_used > general_gas_limit
                    {
                        best_txs.mark_invalid(
                            &candidate.pool_tx,
                            InvalidPoolTransactionError::Other(Box::new(
                                TempoPoolTransactionError::ExceedsNonPaymentLimit,
                            )),
                        );
                        self.metrics
                            .inc_pool_tx_skipped("exceeds_general_gas_limit");
                        invalidated.push(candidate.pool_tx.clone());
                        pending_candidates.retain(|pending| {
                            !is_blockstm_invalidated_buffered_transaction(
                                &candidate.pool_tx,
                                &pending.pool_tx,
                            )
                        });
                        continue;
                    }

                    check_cancel!();

                    if candidate.is_payment {
                        payment_transactions += 1;
                    }

                    let estimated_block_size_with_tx = block_size_used + candidate.tx_rlp_length;
                    if estimated_block_size_with_tx > max_estimated_block_size {
                        best_txs.mark_invalid(
                            &candidate.pool_tx,
                            InvalidPoolTransactionError::OversizedData {
                                size: estimated_block_size_with_tx,
                                limit: MAX_RLP_BLOCK_SIZE,
                            },
                        );
                        self.metrics.inc_pool_tx_skipped("oversized_block");
                        skipped_oversized_block = true;
                        invalidated.push(candidate.pool_tx.clone());
                        pending_candidates.retain(|pending| {
                            !is_blockstm_invalidated_buffered_transaction(
                                &candidate.pool_tx,
                                &pending.pool_tx,
                            )
                        });
                        continue;
                    }

                    let attempt = attempt_slots[batch_index]
                        .take()
                        .expect("Block-STM attempt must be available");

                    let BlockStmAttempt { output, .. } = attempt;
                    let BlockStmAttemptOutput {
                        execution_result,
                        elapsed,
                        mut semantic_plan,
                        ..
                    } = output;

                    let direct_attempt = execution_result.is_none();
                    let mut result = match execution_result {
                        Some(Ok(result)) => result,
                        Some(Err(err)) => {
                            if let BlockExecutionError::Validation(
                                BlockValidationError::InvalidTx { error, .. },
                            ) = &err
                            {
                                invalid_pool_transaction_execution_attempts += 1;

                                if error.is_nonce_too_low() {
                                    trace!(%error, tx = %candidate.tx_debug_repr, "skipping nonce too low transaction");
                                    self.metrics.inc_pool_tx_skipped("nonce_too_low");
                                } else {
                                    trace!(%error, tx = %candidate.tx_debug_repr, "skipping invalid transaction and its descendants");
                                    best_txs.mark_invalid(
                                        &candidate.pool_tx,
                                        InvalidPoolTransactionError::Consensus(
                                            InvalidTransactionError::TxTypeNotSupported,
                                        ),
                                    );
                                    self.metrics.inc_pool_tx_skipped("invalid_tx");
                                    invalidated.push(candidate.pool_tx.clone());
                                    pending_candidates.retain(|pending| {
                                        !is_blockstm_invalidated_buffered_transaction(
                                            &candidate.pool_tx,
                                            &pending.pool_tx,
                                        )
                                    });
                                }
                                continue;
                            } else {
                                return Err(PayloadBuilderError::evm(err));
                            }
                        }
                        None => {
                            match executor
                                .execute_transaction_without_commit(candidate.tx_with_env.clone())
                            {
                                Ok(result) => result,
                                Err(err) => {
                                    if let BlockExecutionError::Validation(
                                        BlockValidationError::InvalidTx { error, .. },
                                    ) = &err
                                    {
                                        invalid_pool_transaction_execution_attempts += 1;

                                        if error.is_nonce_too_low() {
                                            trace!(%error, tx = %candidate.tx_debug_repr, "skipping nonce too low transaction");
                                            self.metrics.inc_pool_tx_skipped("nonce_too_low");
                                        } else {
                                            trace!(%error, tx = %candidate.tx_debug_repr, "skipping invalid transaction and its descendants");
                                            best_txs.mark_invalid(
                                                &candidate.pool_tx,
                                                InvalidPoolTransactionError::Consensus(
                                                    InvalidTransactionError::TxTypeNotSupported,
                                                ),
                                            );
                                            self.metrics.inc_pool_tx_skipped("invalid_tx");
                                            invalidated.push(candidate.pool_tx.clone());
                                            pending_candidates.retain(|pending| {
                                                !is_blockstm_invalidated_buffered_transaction(
                                                    &candidate.pool_tx,
                                                    &pending.pool_tx,
                                                )
                                            });
                                        }
                                        continue;
                                    } else {
                                        return Err(PayloadBuilderError::evm(err));
                                    }
                                }
                            }
                        }
                    };
                    if direct_attempt {
                        let write_set = write_set_from_evm_state(&result.result().state);
                        semantic_plan = capture_tip20_semantic_plan(
                            candidate.tx_index,
                            &candidate.pool_tx.transaction,
                            &result,
                            &write_set,
                            beneficiary,
                        )
                        .or(semantic_plan);
                    }

                    if let Some(semantic_plan) = semantic_plan {
                        let block_timestamp = executor.evm().block().timestamp.to::<u64>();
                        match semantic_state.apply_plan(
                            executor.evm_mut().db_mut(),
                            &semantic_plan,
                            &mut result,
                            block_timestamp,
                        ) {
                            Ok(_resolved_write_set) => {
                                blockstm_stats.semantic_actions_total +=
                                    semantic_plan.action_count() as u64;
                            }
                            Err(err) => {
                                trace!(%err, tx = %candidate.tx_debug_repr, "skipping semantically invalid transaction and its descendants");
                                best_txs.mark_invalid(
                                    &candidate.pool_tx,
                                    InvalidPoolTransactionError::Consensus(
                                        InvalidTransactionError::TxTypeNotSupported,
                                    ),
                                );
                                self.metrics.inc_pool_tx_skipped("invalid_tx");
                                invalidated.push(candidate.pool_tx.clone());
                                pending_candidates.retain(|pending| {
                                    !is_blockstm_invalidated_buffered_transaction(
                                        &candidate.pool_tx,
                                        &pending.pool_tx,
                                    )
                                });
                                continue;
                            }
                        }
                    }

                    blockstm_stats.committed_txs_total += 1;
                    if attempt.attempt == 0 {
                        blockstm_stats.reused_speculative_results_total += 1;
                    }
                    trace!(?elapsed, "Transaction executed through Block-STM");

                    cumulative_gas_used += result.block_gas_used();
                    cumulative_state_gas_used += result.state_gas_used();
                    if !candidate.is_payment {
                        non_payment_gas_used += result.block_gas_used();
                    }
                    total_fees += result.validator_fee();
                    best_txs.on_new_result(&result);

                    hydrate_blockstm_commit_cache(executor.evm_mut().db_mut(), &result)
                        .map_err(|err| PayloadBuilderError::evm(BlockExecutionError::other(err)))?;
                    executor.commit_transaction(result);
                    executor.evm_mut().db_mut().bump_bal_index();
                    let _ = roots_tx.send((
                        BuilderTx::Pooled(candidate.pool_tx.clone()),
                        executor.receipts().last().unwrap().clone(),
                    ));

                    pool_transactions_included += 1;
                    block_size_used += candidate.tx_rlp_length;
                }
            }
        } else {
            loop {
                check_cancel!();

                if let Some(build_budget) = payload_build_budget {
                    let elapsed = start.elapsed();
                    if payload_budget_exhausted(
                        elapsed,
                        normal_transaction_fill_idle_elapsed,
                        build_time_multiplier,
                        build_budget,
                        marshal_persist,
                        block_size_used,
                    ) {
                        let estimated_marshal_persist = marshal_persist.estimate(block_size_used);
                        debug!(
                            target: "payload_builder",
                            ?elapsed,
                            ?normal_transaction_fill_idle_elapsed,
                            ?build_budget,
                            ?estimated_marshal_persist,
                            block_size_used,
                            build_time_multiplier = build_time_multiplier as f64
                                / BUILD_TIME_MULTIPLIER_SCALE as f64,
                            "stopping pool transaction execution before payload build budget is exhausted"
                        );
                        break BlockBuildStopReason::BuildBudget;
                    }
                }

                let Some(pool_tx) = best_txs.next() else {
                    if build_once_with_shared_trie
                        && payload_build_budget.is_some()
                        && cumulative_gas_used < non_shared_gas_limit
                    {
                        std::thread::sleep(Duration::from_millis(1));
                        normal_transaction_fill_idle_elapsed += Duration::from_millis(1);
                        continue;
                    }
                    let stop_reason = if cumulative_gas_used >= non_shared_gas_limit {
                        BlockBuildStopReason::GasLimit
                    } else if skipped_oversized_block {
                        BlockBuildStopReason::RlpBlockSizeLimit
                    } else {
                        BlockBuildStopReason::TxPoolEmpty
                    };
                    break stop_reason;
                };
                pool_transactions_yielded += 1;

                let max_regular_gas_used = core::cmp::min(
                    pool_tx.gas_limit(),
                    executor.evm().cfg.tx_gas_limit_cap.unwrap_or(u64::MAX),
                );

                // Ensure we still have capacity for this transaction within the non-shared gas limit.
                // The remaining `shared_gas_limit` is reserved for validator subblocks and must not
                // be consumed by proposer's pool transactions.
                if cumulative_gas_used + max_regular_gas_used > non_shared_gas_limit {
                    // Mark this transaction as invalid since it doesn't fit
                    // The iterator will handle lane switching internally when appropriate
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::ExceedsGasLimit(
                            pool_tx.gas_limit(),
                            non_shared_gas_limit - cumulative_gas_used,
                        ),
                    );
                    self.metrics
                        .inc_pool_tx_skipped("exceeds_non_shared_gas_limit");
                    continue;
                }

                let is_payment = if hardfork.is_t5() {
                    pool_tx.transaction.is_payment()
                } else {
                    pool_tx.transaction.inner().is_payment_v1()
                };

                // If the tx is not a payment and will exceed the general gas limit
                // mark the tx as invalid and continue
                if !is_payment && non_payment_gas_used + max_regular_gas_used > general_gas_limit {
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::Other(Box::new(
                            TempoPoolTransactionError::ExceedsNonPaymentLimit,
                        )),
                    );
                    self.metrics
                        .inc_pool_tx_skipped("exceeds_general_gas_limit");
                    continue;
                }

                check_cancel!();
                if is_payment {
                    payment_transactions += 1;
                }

                let tx_rlp_length = pool_tx.transaction.encoded_length();
                let estimated_block_size_with_tx = block_size_used + tx_rlp_length;

                if estimated_block_size_with_tx > max_estimated_block_size {
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::OversizedData {
                            size: estimated_block_size_with_tx,
                            limit: MAX_RLP_BLOCK_SIZE,
                        },
                    );
                    self.metrics.inc_pool_tx_skipped("oversized_block");
                    skipped_oversized_block = true;
                    continue;
                }

                let tx_debug_repr = tracing::enabled!(Level::TRACE)
                    .then(|| format!("{:?}", pool_tx.transaction))
                    .unwrap_or_default();

                let tx_with_env = pool_tx.transaction.clone_into_with_tx_env();
                let execution_result =
                    executor.execute_transaction_with_result_closure(tx_with_env, |result| {
                        cumulative_gas_used += result.block_gas_used();
                        cumulative_state_gas_used += result.state_gas_used();
                        if !is_payment {
                            non_payment_gas_used += result.block_gas_used();
                        }

                        // Score payload value by the validator-credited fee amount that the
                        // FeeManager precompile actually wrote during this transaction.
                        total_fees += result.validator_fee();

                        // Notify transactions iterator about the new state.
                        best_txs.on_new_result(result);
                    });

                if let Err(err) = execution_result {
                    if let BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                        error,
                        ..
                    }) = &err
                    {
                        invalid_pool_transaction_execution_attempts += 1;

                        if error.is_nonce_too_low() {
                            // if the nonce is too low, we can skip this transaction
                            trace!(%error, tx = %tx_debug_repr, "skipping nonce too low transaction");
                            self.metrics.inc_pool_tx_skipped("nonce_too_low");
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            trace!(%error, tx = %tx_debug_repr, "skipping invalid transaction and its descendants");
                            best_txs.mark_invalid(
                                &pool_tx,
                                InvalidPoolTransactionError::Consensus(
                                    InvalidTransactionError::TxTypeNotSupported,
                                ),
                            );
                            self.metrics.inc_pool_tx_skipped("invalid_tx");
                        }
                        continue;
                    } else {
                        return Err(PayloadBuilderError::evm(err));
                    }
                };
                trace!("Transaction executed");
                executor.evm_mut().db_mut().bump_bal_index();
                let _ = roots_tx.send((
                    BuilderTx::Pooled(pool_tx.clone()),
                    executor.receipts().last().unwrap().clone(),
                ));

                pool_transactions_included += 1;
                block_size_used += tx_rlp_length;
            }
        };
        let elapsed_at_tx_cutoff = start.elapsed();
        let validation_work_at_tx_cutoff =
            elapsed_at_tx_cutoff.saturating_sub(normal_transaction_fill_idle_elapsed);
        drop(_block_fill_span);
        self.metrics
            .inc_block_build_stop_reason(block_build_stop_reason);
        if self.blockstm_config.enabled && !empty {
            blockstm_stats.built_blocks_total = 1;
            debug!(
                target: "payload_builder",
                speculative = blockstm_stats.speculative_executions_total,
                committed = blockstm_stats.committed_txs_total,
                reused_speculative = blockstm_stats.reused_speculative_results_total,
                conflicts = blockstm_stats.conflicts_total,
                reexecutions = blockstm_stats.reexecutions_total,
                serial_fallback = blockstm_stats.serial_fallback_total,
                max_in_flight = blockstm_stats.max_in_flight_real_evm_executions,
                semantic_actions = blockstm_stats.semantic_actions_total,
                ?blockstm_batch_setup_elapsed,
                ?blockstm_prefix_cache_clone_elapsed,
                ?blockstm_worker_elapsed,
                ?blockstm_attempt_wall_elapsed_sum,
                ?blockstm_evm_execution_elapsed_sum,
                ?blockstm_publish_elapsed_sum,
                ?blockstm_validation_elapsed_sum,
                blockstm_validation_tasks,
                blockstm_publish_tasks,
                blockstm_read_keys,
                blockstm_write_keys,
                blockstm_account_write_keys,
                blockstm_semantic_plans,
                blockstm_direct_semantic_executions,
                ?blockstm_fast_semantic_elapsed,
                ?blockstm_fast_commit_elapsed,
                ?blockstm_semantic_lane_build_elapsed,
                ?blockstm_semantic_lane_reduce_elapsed,
                ?blockstm_semantic_materialize_elapsed,
                ?blockstm_semantic_commit_elapsed,
                blockstm_semantic_lanes_reduced,
                blockstm_semantic_fixpoint_iterations,
                blockstm_semantic_invalid_txs,
                "Block-STM production execution stats"
            );
            BlockStmMetrics.emit_block(blockstm_stats);
        }
        let normal_transaction_fill_elapsed = execution_start.elapsed();
        self.metrics
            .total_normal_transaction_fill_duration_seconds
            .record(normal_transaction_fill_elapsed);
        self.metrics
            .normal_transaction_fill_idle_duration_seconds
            .record(normal_transaction_fill_idle_elapsed);
        self.metrics
            .payment_transactions
            .record(payment_transactions as f64);
        self.metrics
            .payment_transactions_last
            .set(payment_transactions as f64);

        check_cancel!();

        // check if we have a better block or received more subblocks
        if !is_better_payload(best_payload.as_ref(), total_fees)
            && !is_more_subblocks(best_payload.as_ref(), &subblocks)
        {
            // Release db
            drop(executor);
            drop(db);
            // can skip building the block
            return Ok(BuildOutcome::Aborted {
                fees: total_fees,
                cached_reads,
            });
        }

        let subblocks_start = Instant::now();
        let _subblock_txs_span =
            debug_span!(target: "payload_builder", "execute_subblock_txs").entered();
        let subblocks_count = subblocks.len() as f64;
        let mut subblock_transactions = 0f64;
        // Apply subblock transactions
        for subblock in subblocks {
            let subblock_start = Instant::now();
            let mut subblock_tx_count = 0f64;

            for tx in subblock.into_recovered_iter() {
                if let Err(err) = executor.execute_transaction(&tx) {
                    if let BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                        ..
                    }) = &err
                    {
                        error!(
                            ?err,
                            "subblock transaction failed execution, aborting payload building"
                        );
                        self.highest_invalid_subblock
                            .store(executor.evm().block().number.to(), Ordering::Relaxed);
                        self.metrics.inc_build_failure("subblock_invalid_tx");
                        return Err(PayloadBuilderError::evm(err));
                    } else {
                        return Err(PayloadBuilderError::evm(err));
                    }
                }
                executor.evm_mut().db_mut().bump_bal_index();

                subblock_tx_count += 1.0;
                let _ = roots_tx.send((
                    BuilderTx::Owned(Box::new(tx)),
                    executor.receipts().last().unwrap().clone(),
                ));
            }

            self.metrics
                .subblock_execution_duration_seconds
                .record(subblock_start.elapsed());
            self.metrics
                .subblock_transaction_count
                .record(subblock_tx_count);
            subblock_transactions += subblock_tx_count;
        }
        drop(_subblock_txs_span);
        let total_subblock_transaction_execution_elapsed = subblocks_start.elapsed();
        self.metrics
            .total_subblock_transaction_execution_duration_seconds
            .record(total_subblock_transaction_execution_elapsed);
        self.metrics.subblocks.record(subblocks_count);
        self.metrics.subblocks_last.set(subblocks_count);
        self.metrics
            .subblock_transactions
            .record(subblock_transactions);
        self.metrics
            .subblock_transactions_last
            .set(subblock_transactions);

        // Apply system transactions
        let system_txs_execution_start = Instant::now();
        let _system_txs_span =
            debug_span!(target: "payload_builder", "execute_system_txs").entered();
        for system_tx in system_txs {
            executor
                .execute_transaction(&system_tx)
                .map_err(PayloadBuilderError::evm)?;
            executor.evm_mut().db_mut().bump_bal_index();

            let _ = roots_tx.send((
                BuilderTx::Owned(Box::new(system_tx)),
                executor.receipts().last().unwrap().clone(),
            ));
        }
        drop(_system_txs_span);
        let system_txs_execution_elapsed = system_txs_execution_start.elapsed();
        self.metrics
            .system_transactions_execution_duration_seconds
            .record(system_txs_execution_elapsed);

        let total_transaction_execution_elapsed = normal_transaction_fill_elapsed
            + total_subblock_transaction_execution_elapsed
            + system_txs_execution_elapsed;
        self.metrics
            .total_transaction_execution_duration_seconds
            .record(total_transaction_execution_elapsed);

        let payload_finalization_start = Instant::now();
        let _finish_span = debug_span!(target: "payload_builder", "finish_block").entered();
        let finish_provider = InstrumentedFinishProvider {
            inner: &*state_provider,
            metrics: self.metrics.clone(),
        };

        check_cancel!();

        let builder_finish_start = Instant::now();

        // Drop the roots task handle to trigger finalization
        drop(roots_tx);

        let (evm, execution_result) = executor.finish()?;
        let evm_env = evm.into_env();

        // merge all transitions into bundle state before deriving the hashed post-state
        db.merge_transitions(BundleRetention::Reverts);

        let hashed_state = if let Some(Ok(hashed_state)) = trie_handle
            .as_mut()
            .map(|handle| handle.take_hashed_state_rx().recv())
        {
            hashed_state
        } else {
            finish_provider.hashed_post_state(&db.bundle_state)
        };

        let (state_root_outcome, sparse_trie_state_root_wait_elapsed) =
            if let Some(mut handle) = trie_handle {
                let state_root_wait_start = Instant::now();
                let _span = debug_span!(target: "payload_builder", "await_state_root").entered();
                match handle.state_root() {
                    Ok(outcome) => {
                        let elapsed = state_root_wait_start.elapsed();
                        self.metrics
                            .sparse_trie_state_root_wait_duration_seconds
                            .record(elapsed);
                        debug!(
                            target: "payload_builder",
                            id = %payload_id,
                            state_root = ?outcome.state_root,
                            "received state root from sparse trie"
                        );
                        Some((outcome, elapsed))
                    }
                    Err(err) => {
                        warn!(
                            target: "payload_builder",
                            id = %payload_id,
                            %err,
                            "sparse trie failed, falling back to sync state root"
                        );
                        None
                    }
                }
            } else {
                None
            }
            .unzip();

        let block_access_list = db.take_built_alloy_bal();
        let block_access_list_hash = block_access_list
            .as_ref()
            .map(|bal| compute_block_access_list_hash(bal.as_slice()));

        let (state_root, trie_updates) = if let Some(outcome) = state_root_outcome {
            (outcome.state_root, outcome.trie_updates)
        } else {
            let (state_root, trie_updates) = finish_provider
                .state_root_with_updates(hashed_state.clone())
                .map_err(BlockExecutionError::other)?;

            (state_root, Arc::new(trie_updates))
        };

        let (transactions_root, receipts_root, receipts_bloom, transactions, senders) = roots_rx
            .blocking_recv()
            .map_err(PayloadBuilderError::other)?;

        let block = self.evm_config.block_assembler.assemble_block(
            BlockAssemblerInput::new(
                evm_env,
                execution_ctx,
                &parent_header,
                transactions,
                &execution_result,
                &db.bundle_state,
                &finish_provider,
                state_root,
                block_access_list_hash,
            ),
            Some(transactions_root),
            Some(receipts_root),
            Some(receipts_bloom),
        )?;

        let block = RecoveredBlock::new_unhashed(block, senders);
        let builder_finish_elapsed = builder_finish_start.elapsed();
        self.metrics
            .builder_finish_duration_seconds
            .record(builder_finish_elapsed);
        drop(_finish_span);
        let payload_finalization_elapsed = payload_finalization_start.elapsed();
        self.metrics
            .payload_finalization_duration_seconds
            .record(payload_finalization_elapsed);

        let total_transactions = block.transaction_count();
        self.metrics
            .total_transactions
            .record(total_transactions as f64);
        self.metrics
            .total_transactions_last
            .set(total_transactions as f64);

        let gas_used = block.gas_used();
        self.metrics.gas_used.record(gas_used as f64);
        self.metrics.gas_used_last.set(gas_used as f64);
        self.metrics
            .state_gas_used
            .record(cumulative_state_gas_used as f64);
        self.metrics
            .state_gas_used_last
            .set(cumulative_state_gas_used as f64);
        self.metrics
            .general_gas_used_last
            .set(non_payment_gas_used as f64);
        self.metrics
            .payment_gas_used_last
            .set(cumulative_gas_used as f64 - non_payment_gas_used as f64);
        self.metrics
            .general_gas_limit_last
            .set(general_gas_limit as f64);
        self.metrics
            .payment_gas_limit_last
            .set(non_shared_gas_limit as f64 - general_gas_limit as f64);
        self.metrics
            .shared_gas_limit_last
            .set(shared_gas_limit as f64);

        let requests = chain_spec
            .is_prague_active_at_timestamp(attributes.timestamp)
            .then(|| execution_result.requests.clone());

        let rlp_length = block.rlp_length();

        if is_osaka && rlp_length > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        let pool_transactions_inclusion_ratio = if pool_transactions_yielded == 0 {
            0.0
        } else {
            pool_transactions_included as f64 / pool_transactions_yielded as f64
        };
        self.metrics
            .pool_transactions_yielded
            .record(pool_transactions_yielded as f64);
        self.metrics
            .pool_transactions_yielded_last
            .set(pool_transactions_yielded as f64);
        self.metrics
            .pool_transactions_included
            .record(pool_transactions_included as f64);
        self.metrics
            .pool_transactions_included_last
            .set(pool_transactions_included as f64);
        self.metrics
            .invalid_pool_transaction_execution_attempts
            .record(invalid_pool_transaction_execution_attempts as f64);
        self.metrics
            .pool_transactions_inclusion_ratio
            .record(pool_transactions_inclusion_ratio);
        self.metrics
            .pool_transactions_inclusion_ratio_last
            .set(pool_transactions_inclusion_ratio);

        let elapsed = start.elapsed();
        let validation_work_duration = elapsed.saturating_sub(normal_transaction_fill_idle_elapsed);
        if payload_build_budget.is_some() {
            self.update_build_time_multiplier(
                validation_work_duration,
                validation_work_at_tx_cutoff,
            );
        }
        self.metrics.payload_build_duration_seconds.record(elapsed);
        let gas_per_second = block.gas_used() as f64 / elapsed.as_secs_f64();
        self.metrics.gas_per_second.record(gas_per_second);
        self.metrics.gas_per_second_last.set(gas_per_second);
        self.metrics.rlp_block_size_bytes.record(rlp_length as f64);
        self.metrics
            .rlp_block_size_bytes_last
            .set(rlp_length as f64);

        info!(
            parent_hash = ?block.parent_hash(),
            number = block.number(),
            hash = ?block.hash(),
            timestamp = block.timestamp_millis(),
            gas_limit = block.gas_limit(),
            gas_used,
            cumulative_state_gas_used,
            extra_data = %block.extra_data(),
            subblocks_count,
            payment_transactions,
            pool_transactions_yielded,
            pool_transactions_included,
            invalid_pool_transaction_execution_attempts,
            pool_transactions_inclusion_ratio,
            subblock_transactions,
            total_transactions,
            ?elapsed,
            ?validation_work_duration,
            ?normal_transaction_fill_elapsed,
            ?normal_transaction_fill_idle_elapsed,
            ?total_subblock_transaction_execution_elapsed,
            ?system_txs_execution_elapsed,
            ?total_transaction_execution_elapsed,
            ?sparse_trie_state_root_wait_elapsed,
            ?builder_finish_elapsed,
            "Built payload"
        );

        let block = Arc::new(block);
        let block_access_list: Option<Bytes> =
            block_access_list.map(|block_access_list| alloy_rlp::encode(&block_access_list).into());
        let eth_payload = EthBuiltPayload::new(block.clone(), total_fees, requests, None);

        let execution_output = BlockExecutionOutput {
            result: execution_result,
            state: db.take_bundle(),
        };

        let executed_block = BuiltPayloadExecutedBlock {
            recovered_block: block,
            execution_output: Arc::new(execution_output),
            hashed_state: Arc::new(hashed_state),
            trie_updates,
        };

        let payload = TempoBuiltPayload::new(
            eth_payload,
            block_access_list,
            Some(executed_block),
            validation_work_duration,
            rlp_length,
        );

        drop(db);
        if build_once_with_shared_trie {
            Ok(BuildOutcome::Freeze(payload))
        } else {
            Ok(BuildOutcome::Better {
                payload,
                cached_reads,
            })
        }
    }

    #[expect(clippy::type_complexity)]
    fn spawn_roots_task(
        &self,
    ) -> (
        Sender<(BuilderTx, TempoReceipt)>,
        oneshot::Receiver<(B256, B256, Bloom, Vec<TempoTxEnvelope>, Vec<Address>)>,
    ) {
        let (transactions_tx, transactions_rx) =
            crossbeam_channel::unbounded::<(BuilderTx, TempoReceipt)>();
        let (result_tx, result_rx) = oneshot::channel();

        self.executor
            .spawn_blocking_named("builder-roots-task", || {
                let mut transactions = Vec::new();
                let mut senders = Vec::new();

                let mut transactions_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_bloom = Bloom::ZERO;

                let mut buf = Vec::new();

                for (tx, receipt) in transactions_rx.into_iter() {
                    let (tx, sender) = tx.into_parts();
                    buf.clear();
                    tx.encode_2718(&mut buf);
                    transactions_root.push_next(&buf);
                    transactions.push(tx);
                    senders.push(sender);

                    let receipt = receipt.with_bloom_ref();

                    buf.clear();
                    receipt.encode_2718(&mut buf);
                    receipts_root.push_next(&buf);
                    receipts_bloom |= receipt.bloom();
                }
                let transactions_root = transactions_root.finalize();
                let receipts_root = receipts_root.finalize();
                let _ = result_tx.send((
                    transactions_root,
                    receipts_root,
                    receipts_bloom,
                    transactions,
                    senders,
                ));
            });

        (transactions_tx, result_rx)
    }
}

pub fn is_more_subblocks(
    best_payload: Option<&TempoBuiltPayload>,
    subblocks: &[RecoveredSubBlock],
) -> bool {
    let Some(best_payload) = best_payload else {
        return false;
    };
    let Some(best_metadata) = best_payload
        .block()
        .body()
        .transactions
        .iter()
        .rev()
        .filter(|tx| tx.is_system_tx())
        .find_map(|tx| Vec::<SubBlockMetadata>::decode(&mut tx.input().as_ref()).ok())
    else {
        return false;
    };

    subblocks.len() > best_metadata.len()
}

/// Overrides the block's fee recipient (beneficiary) with the value from the
/// V2 validator config contract, if the contract is active and returns a
/// non-zero address for the given `public_key`.
fn maybe_override_fee_recipient<DB: Database>(
    executor: &mut impl BlockExecutor<Evm = TempoEvm<DB>>,
    attributes: &TempoPayloadAttributes,
) {
    let Some(public_key) = attributes.proposer_public_key() else {
        return;
    };
    let ctx = executor.evm_mut().ctx_mut();
    if !ctx.cfg.spec.is_t2() {
        return;
    }

    // We are using the database as a read-only storage context to avoid modifying the journal state.
    // Reading slots here might be dangerous because they would end up being warmed and might affect gas accounting.
    match ctx.journaled_state.database.with_read_only_storage_ctx(
        ctx.cfg.spec,
        || -> Result<Option<Address>, PayloadBuilderError> {
            let parent_number = ctx.block.number.saturating_to::<u64>() - 1;

            let config = ValidatorConfigV2::default();
            if !config
                .is_initialized()
                .map_err(PayloadBuilderError::other)?
            {
                return Ok(None);
            }
            let init_height = config
                .get_initialized_at_height()
                .map_err(PayloadBuilderError::other)?;
            if init_height > parent_number {
                return Ok(None);
            }
            let on_chain = config
                .validator_by_public_key(*public_key)
                .map(|v| v.feeRecipient)
                .map_err(PayloadBuilderError::other)?;
            Ok((!on_chain.is_zero()).then_some(on_chain))
        },
    ) {
        Ok(Some(fee_recipient)) => {
            debug!(%fee_recipient, "resolved fee recipient from contract");
            executor.evm_mut().ctx_mut().block.beneficiary = fee_recipient;
        }
        Ok(None) => {}
        Err(err) => {
            warn!(%err, "failed resolving fee recipient from contract; using fallback");
        }
    }
}

#[derive(Debug)]
enum BuilderTx {
    Pooled(Arc<ValidPoolTransaction<TempoPooledTransaction>>),
    Owned(Box<Recovered<TempoTxEnvelope>>),
}

impl BuilderTx {
    fn into_parts(self) -> (TempoTxEnvelope, Address) {
        match self {
            Self::Pooled(tx) => tx.transaction.inner().clone().into_parts(),
            Self::Owned(tx) => tx.into_parts(),
        }
    }
}

#[cfg(test)]
mod blockstm_benchmark_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_primitives::{Address, B256, Bytes};
    use core::num::NonZeroU64;
    use reth_primitives_traits::Block as _;
    use tempo_primitives::{
        AASigned, Block, SignedSubBlock, SubBlock, SubBlockVersion, TempoSignature,
        TempoTransaction,
    };

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test valid_before must be non-zero")
    }

    trait TestExt {
        fn random() -> Self;
        fn with_valid_before(_: Option<NonZeroU64>) -> Self
        where
            Self: Sized,
        {
            Self::random()
        }
    }

    impl TestExt for SubBlockMetadata {
        fn random() -> Self {
            Self {
                version: SubBlockVersion::V1,
                validator: B256::random(),
                fee_recipient: Address::random(),
                signature: Bytes::new(),
            }
        }
    }

    impl TestExt for RecoveredSubBlock {
        fn random() -> Self {
            Self::with_valid_before(None)
        }

        fn with_valid_before(valid_before: Option<NonZeroU64>) -> Self {
            let tx = TempoTxEnvelope::AA(AASigned::new_unhashed(
                TempoTransaction {
                    valid_before,
                    ..Default::default()
                },
                TempoSignature::default(),
            ));
            let signed = SignedSubBlock {
                inner: SubBlock {
                    version: SubBlockVersion::V1,
                    parent_hash: B256::random(),
                    fee_recipient: Address::random(),
                    transactions: vec![tx],
                },
                signature: Bytes::new(),
            };
            Self::new_unchecked(signed, vec![Address::ZERO], B256::ZERO)
        }
    }

    fn payload_with_metadata(count: usize) -> TempoBuiltPayload {
        let metadata: Vec<_> = (0..count).map(|_| SubBlockMetadata::random()).collect();
        let input: Bytes = alloy_rlp::encode(&metadata).into();
        let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: None,
                nonce: 0,
                gas_price: 0,
                gas_limit: 0,
                to: Address::random().into(),
                value: U256::ZERO,
                input,
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ));
        let block = Block {
            header: TempoHeader::default(),
            body: BlockBody {
                transactions: vec![tx],
                ommers: vec![],
                withdrawals: None,
            },
        }
        .try_into_recovered()
        .unwrap();
        let rlp_length = block.rlp_length();
        let eth = EthBuiltPayload::new(Arc::new(block), U256::ZERO, None, None);
        TempoBuiltPayload::new(eth, None, None, Duration::ZERO, rlp_length)
    }

    #[test]
    fn test_is_more_subblocks() {
        // None payload always returns false
        assert!(!is_more_subblocks(None, &[]));
        assert!(!is_more_subblocks(None, &[RecoveredSubBlock::random()]));

        // Equal count returns false (1 == 1)
        let payload = payload_with_metadata(1);
        assert!(!is_more_subblocks(
            Some(&payload),
            &[RecoveredSubBlock::random()]
        ));

        // More subblocks returns true (2 > 1)
        assert!(is_more_subblocks(
            Some(&payload),
            &[RecoveredSubBlock::random(), RecoveredSubBlock::random()]
        ));

        // Fewer subblocks returns false (1 < 2)
        let payload = payload_with_metadata(2);
        assert!(!is_more_subblocks(
            Some(&payload),
            &[RecoveredSubBlock::random()]
        ));

        // Empty metadata, empty subblocks returns false (0 > 0 is false)
        let payload = payload_with_metadata(0);
        assert!(!is_more_subblocks(Some(&payload), &[]));

        // Empty metadata, one subblock returns true (1 > 0)
        assert!(is_more_subblocks(
            Some(&payload),
            &[RecoveredSubBlock::random()]
        ));
    }

    #[test]
    fn test_extra_data_flow_in_attributes() {
        // Test that extra_data in attributes can be accessed correctly
        let extra_data = Bytes::from(vec![42, 43, 44, 45, 46]);

        let attrs = TempoPayloadAttributes::new(None, 1, 0, extra_data.clone(), None, Vec::new);

        assert_eq!(attrs.extra_data(), &extra_data);

        // Verify the data is as expected
        let injected_data = attrs.extra_data().clone();

        assert_eq!(injected_data, extra_data);
    }

    #[test]
    fn test_has_expired_transactions_boundary() {
        // valid_before == timestamp → expired
        let subblock = RecoveredSubBlock::with_valid_before(Some(nz(1000)));
        assert!(has_expired_transactions(&subblock, 1000));

        // valid_before < timestamp → expired
        assert!(has_expired_transactions(&subblock, 1001));

        // valid_before > timestamp → NOT expired
        assert!(!has_expired_transactions(&subblock, 999));

        // No valid_before → NOT expired
        let subblock_no_expiry = RecoveredSubBlock::with_valid_before(None);
        assert!(!has_expired_transactions(&subblock_no_expiry, 1000));
    }
}
