//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod budget;
mod encode;
mod metrics;
mod prewarming;

pub use budget::DEFAULT_BUILD_TIME_MULTIPLIER;
use crossbeam_channel::{Receiver, Sender};
use reth_trie_common::ordered_root::OrderedTrieRootEncodedBuilder;

use crate::{
    budget::{
        BUILD_TIME_MULTIPLIER_SCALE, PayloadBudgetInput, decay_build_time_multiplier,
        observed_build_time_multiplier, payload_budget_decision, scaled_build_time_multiplier,
    },
    encode::{EncodedBlockTransactionList, EncodedBlockTransactionsBuilder, ExecutionBlockEncoder},
    metrics::{BlockBuildStopReason, InstrumentedFinishProvider, TempoPayloadBuilderMetrics},
    prewarming::{
        BestTransactionsPrewarming, PrewarmedTransaction, PrewarmingExecutionContext,
        SsmrReplayPrewarmer,
    },
};
use alloy_consensus::{BlockHeader as _, Signed, Transaction as _, TxLegacy, TxReceipt};
use alloy_eip7928::{BlockAccessIndex, bal::Bal};
use alloy_eips::{
    eip1559::calculate_block_gas_limit,
    eip2718::{Decodable2718, Encodable2718},
};
use alloy_primitives::{Address, B256, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{Decodable, Encodable};
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
    is_better_payload,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_engine_tree::tree::{
    CachedStateMetrics, CachedStateMetricsSource, CachedStateProvider, ExecutionCache,
    instrumented_state::InstrumentedStateProvider,
};
use reth_errors::{ConsensusError, ProviderError};
use reth_evm::{
    ConfigureEvm, Database, Evm, EvmEnvFor, ExecutionCtxFor, NextBlockEnvAttributes, OnStateHook,
    block::{BlockExecutionError, BlockExecutor, BlockValidationError},
    execute::BlockAssemblerInput,
};
use reth_execution_types::BlockExecutionOutput;
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{
    Recovered, RecoveredBlock, SignedTransaction as _, transaction::error::InvalidTransactionError,
};
use reth_revm::{
    State,
    context::Block,
    database::StateProviderDatabase,
    db::states::bundle_state::BundleRetention,
    state::{
        EvmState,
        bal::{AccountBal, AccountInfoBal, Bal as RevmBal, BalWrites, StorageBal},
    },
};
use reth_storage_api::{HashedPostStateProvider, StateProviderFactory, StateRootProvider};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_evm::{
    StorageActionReplayError, StorageActionReplayState, TempoEvmConfig,
    TempoNextBlockEnvAttributes, TempoStateAccess, TempoTxResult, evm::TempoEvm,
};
use tempo_payload_types::{
    SsmrBuilderEvent, SsmrBuilderShard, SsmrBuilderSink, SsmrReplayCommand, SsmrReplaySource,
    TempoBuiltPayload, TempoPayloadAttributes, ValidationLatencyWorkload, marshal_persist_estimate,
};
use tempo_precompiles::{storage::StorageActions, validator_config_v2::ValidatorConfigV2};
use tempo_primitives::{
    RecoveredSubBlock, SubBlockMetadata, TempoHeader, TempoReceipt, TempoTxEnvelope,
    subblock::PartialValidatorKey,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use tempo_transaction_pool::{
    StateAwareBestTransactions, TempoTransactionPool,
    best::BestTransaction,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use tokio::sync::oneshot;
use tracing::{Level, debug, debug_span, error, info, instrument, trace, warn};

/// Conservative estimate for non-transaction execution block RLP bytes.
///
/// Exact block RLP length is computed asynchronously after payload construction, so the builder uses
/// this margin together with known transaction, withdrawal, and extra-data lengths for Osaka size
/// checks and pacing estimates.
const NON_TRANSACTION_SIZE_ESTIMATE: usize = 2048;
const DEFAULT_SSMR_SHARD_TARGET_BYTES: usize = 10 * 1024;
const DEFAULT_SSMR_FIRST_SHARD_TARGET_BYTES: usize = 5 * 1024;
const SSMR_REPLAY_SOURCE_POLL_INTERVAL: Duration = Duration::from_millis(1);
// Keep recovery bounded; replay execution, BAL, and sparse-trie work also consume CPU.
const SSMR_REPLAY_RECOVERY_WORKERS: usize = 8;
const SSMR_REPLAY_RECOVERY_EVENT_QUEUE_CAPACITY: usize = 1024;
const SSMR_REPLAY_BAL_BATCH_MAX_TXS: usize = 2048;

#[derive(Debug)]
struct SsmrReplayRecoveryJob {
    shard_index: u64,
    tx_index: usize,
    encoded: Bytes,
    queued_at: Instant,
}

#[derive(Debug)]
struct SsmrRecoveredTx {
    transaction: Recovered<TempoTxEnvelope>,
    encoded: Bytes,
    tx_rlp_length: usize,
    decode_elapsed: Duration,
    recover_elapsed: Duration,
    queue_wait_elapsed: Duration,
}

#[derive(Debug)]
struct SsmrRecoveredTransaction {
    shard_index: u64,
    tx_index: usize,
    tx: SsmrRecoveredTx,
}

#[derive(Debug)]
struct SsmrPendingRecoveredShard {
    transactions: Vec<Option<SsmrRecoveredTx>>,
    block_access_list: Option<Bytes>,
    recovered_count: usize,
}

#[derive(Debug)]
struct SsmrRecoveredBatch {
    transactions: Vec<SsmrRecoveredTx>,
    block_access_list: Option<Bytes>,
    decode_elapsed: Duration,
    recover_elapsed: Duration,
    queue_wait_elapsed: Duration,
    completed_shards: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct PoolSizeSnapshot {
    pending: usize,
    queued: usize,
    total: usize,
}

impl PoolSizeSnapshot {
    fn from_pool_size(size: reth_transaction_pool::PoolSize) -> Self {
        Self {
            pending: size.pending,
            queued: size.queued,
            total: size.total,
        }
    }
}

#[derive(Debug)]
enum SsmrRecoveredReplayEvent {
    Transactions(SsmrRecoveredBatch),
    Finish {
        source_wait_elapsed: Duration,
        recovery_wall_elapsed: Duration,
        first_tx_recovery_elapsed: Option<Duration>,
        recovery_queue_wait_sum_elapsed: Duration,
        recovery_backpressure_elapsed: Duration,
        recovery_worker_count: usize,
    },
    Error(String),
}

#[derive(Debug, Default)]
struct SsmrReplayProgress {
    pending_batches: VecDeque<SsmrRecoveredBatch>,
    replay_finished: bool,
    source_wait_elapsed: Duration,
    recovery_wall_elapsed: Duration,
    first_tx_recovery_elapsed: Option<Duration>,
    recovery_queue_wait_sum_elapsed: Duration,
    recovery_backpressure_elapsed: Duration,
    execution_wait_for_recovery_elapsed: Duration,
    recovery_worker_count: usize,
    max_recovered_tx_ahead: usize,
    shards: u64,
    transactions: u64,
}

impl SsmrReplayProgress {
    fn ingest_event(
        &mut self,
        event: SsmrRecoveredReplayEvent,
        prewarmer: Option<&SsmrReplayPrewarmer>,
    ) -> Result<(), PayloadBuilderError> {
        match event {
            SsmrRecoveredReplayEvent::Transactions(batch) => {
                self.shards += batch.completed_shards;
                if batch.block_access_list.is_none()
                    && let Some(prewarmer) = prewarmer
                {
                    for tx in &batch.transactions {
                        prewarmer.prewarm(&tx.transaction);
                    }
                }
                self.pending_batches.push_back(batch);
                self.max_recovered_tx_ahead = self.max_recovered_tx_ahead.max(
                    self.pending_batches
                        .iter()
                        .map(|batch| batch.transactions.len())
                        .sum(),
                );
            }
            SsmrRecoveredReplayEvent::Finish {
                source_wait_elapsed,
                recovery_wall_elapsed,
                first_tx_recovery_elapsed,
                recovery_queue_wait_sum_elapsed,
                recovery_backpressure_elapsed,
                recovery_worker_count,
            } => {
                self.source_wait_elapsed += source_wait_elapsed;
                self.recovery_wall_elapsed += recovery_wall_elapsed;
                self.first_tx_recovery_elapsed = first_tx_recovery_elapsed;
                self.recovery_queue_wait_sum_elapsed += recovery_queue_wait_sum_elapsed;
                self.recovery_backpressure_elapsed += recovery_backpressure_elapsed;
                self.recovery_worker_count = recovery_worker_count;
                self.replay_finished = true;
            }
            SsmrRecoveredReplayEvent::Error(error) => {
                return Err(PayloadBuilderError::other(std::io::Error::other(error)));
            }
        }

        Ok(())
    }

    fn drain_ready_events(
        &mut self,
        recovered_events: &Receiver<SsmrRecoveredReplayEvent>,
        prewarmer: Option<&SsmrReplayPrewarmer>,
    ) -> Result<(), PayloadBuilderError> {
        if self.replay_finished {
            return Ok(());
        }

        loop {
            match recovered_events.try_recv() {
                Ok(event) => self.ingest_event(event, prewarmer)?,
                Err(crossbeam_channel::TryRecvError::Empty) => return Ok(()),
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    return Err(self.recovery_closed_error());
                }
            }

            if self.replay_finished {
                return Ok(());
            }
        }
    }

    fn wait_for_next_event(
        &mut self,
        recovered_events: &Receiver<SsmrRecoveredReplayEvent>,
        prewarmer: Option<&SsmrReplayPrewarmer>,
    ) -> Result<Duration, PayloadBuilderError> {
        let wait_start = Instant::now();
        let event = recovered_events.recv_timeout(SSMR_REPLAY_SOURCE_POLL_INTERVAL);
        let wait_elapsed = wait_start.elapsed();
        self.execution_wait_for_recovery_elapsed += wait_elapsed;

        match event {
            Ok(event) => self.ingest_event(event, prewarmer)?,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                return Err(self.recovery_closed_error());
            }
        }

        Ok(wait_elapsed)
    }

    fn recovery_closed_error(&self) -> PayloadBuilderError {
        warn!(
            pending_batches = self.pending_batches.len(),
            replay_finished = self.replay_finished,
            ssmr_replay_transactions = self.transactions,
            ssmr_replay_shards = self.shards,
            ssmr_replay_recovery_wall_elapsed = ?self.recovery_wall_elapsed,
            ssmr_replay_recovery_backpressure_elapsed = ?self.recovery_backpressure_elapsed,
            ssmr_replay_max_recovered_tx_ahead = self.max_recovered_tx_ahead,
            "SSMR replay recovery closed before finish"
        );
        PayloadBuilderError::other(std::io::Error::other(
            "SSMR replay recovery closed before finish",
        ))
    }

    fn collect_ready_bal_batches(
        &mut self,
        first_batch: SsmrRecoveredBatch,
    ) -> Vec<SsmrRecoveredBatch> {
        let mut tx_count = first_batch.transactions.len();
        let mut batches = vec![first_batch];
        while tx_count < SSMR_REPLAY_BAL_BATCH_MAX_TXS {
            let Some(next_batch) = self.pending_batches.front() else {
                break;
            };
            if next_batch.block_access_list.is_none() {
                break;
            }
            if tx_count > 0
                && tx_count + next_batch.transactions.len() > SSMR_REPLAY_BAL_BATCH_MAX_TXS
            {
                break;
            }
            let Some(next_batch) = self.pending_batches.pop_front() else {
                break;
            };
            tx_count += next_batch.transactions.len();
            batches.push(next_batch);
        }
        batches
    }
}

#[derive(Debug, Default)]
struct SsmrReplayRecoveryState {
    pending_shards: BTreeMap<u64, SsmrPendingRecoveredShard>,
    next_ready_shard_index: u64,
    next_ready_tx_index: usize,
    inflight_recovery_jobs: usize,
    recovery_queue_wait_sum_elapsed: Duration,
    recovery_backpressure_elapsed: Duration,
    first_tx_recovery_elapsed: Option<Duration>,
}

impl SsmrPendingRecoveredShard {
    fn new(tx_count: usize, block_access_list: Option<Bytes>) -> Self {
        Self {
            transactions: std::iter::repeat_with(|| None).take(tx_count).collect(),
            block_access_list,
            recovered_count: 0,
        }
    }

    fn insert(&mut self, recovered: SsmrRecoveredTransaction) -> Result<(), String> {
        let tx_index = recovered.tx_index;
        let Some(slot) = self.transactions.get_mut(tx_index) else {
            return Err(format!(
                "SSMR replay recovered transaction index {tx_index} outside shard length {}",
                self.transactions.len()
            ));
        };
        if slot.is_some() {
            return Err(format!(
                "SSMR replay recovered duplicate transaction index {tx_index}"
            ));
        }

        *slot = Some(recovered.tx);
        self.recovered_count += 1;

        Ok(())
    }

    fn len(&self) -> usize {
        self.transactions.len()
    }
}

impl SsmrRecoveredBatch {
    fn push(&mut self, tx: SsmrRecoveredTx) {
        self.decode_elapsed += tx.decode_elapsed;
        self.recover_elapsed += tx.recover_elapsed;
        self.queue_wait_elapsed += tx.queue_wait_elapsed;
        self.transactions.push(tx);
    }

    fn has_work(&self) -> bool {
        !self.transactions.is_empty() || self.completed_shards > 0
    }
}

impl SsmrReplayRecoveryState {
    fn insert_recovered_transaction(
        &mut self,
        recovered: SsmrRecoveredTransaction,
    ) -> Result<(), String> {
        let shard_index = recovered.shard_index;
        let Some(shard) = self.pending_shards.get_mut(&shard_index) else {
            return Err(format!("SSMR replay recovered unknown shard {shard_index}"));
        };

        shard.insert(recovered)
    }

    fn drain_ready_batch(
        &mut self,
        recovery_wall_start: Option<&Instant>,
    ) -> Result<Option<SsmrRecoveredBatch>, String> {
        let mut batch = SsmrRecoveredBatch {
            transactions: Vec::new(),
            block_access_list: None,
            decode_elapsed: Duration::ZERO,
            recover_elapsed: Duration::ZERO,
            queue_wait_elapsed: Duration::ZERO,
            completed_shards: 0,
        };

        let Some((shard_len, recovered_count)) = self
            .pending_shards
            .get(&self.next_ready_shard_index)
            .map(|shard| (shard.len(), shard.recovered_count))
        else {
            return Ok(None);
        };

        if recovered_count < shard_len {
            return Ok(None);
        }

        while self.next_ready_tx_index < shard_len {
            let tx = self
                .pending_shards
                .get_mut(&self.next_ready_shard_index)
                .and_then(|shard| shard.transactions[self.next_ready_tx_index].take());
            let Some(tx) = tx else {
                return Ok(None);
            };

            if self.next_ready_shard_index == 0
                && self.next_ready_tx_index == 0
                && self.first_tx_recovery_elapsed.is_none()
                && let Some(start) = recovery_wall_start
            {
                self.first_tx_recovery_elapsed = Some(start.elapsed());
            }

            self.next_ready_tx_index += 1;
            batch.push(tx);
        }

        let Some(shard) = self.pending_shards.remove(&self.next_ready_shard_index) else {
            return Err(format!(
                "SSMR replay lost ready shard {}",
                self.next_ready_shard_index
            ));
        };
        debug_assert_eq!(shard.recovered_count, shard_len);
        batch.block_access_list = shard.block_access_list;
        self.next_ready_shard_index += 1;
        self.next_ready_tx_index = 0;
        batch.completed_shards += 1;

        Ok(batch.has_work().then_some(batch))
    }
}

fn recover_ssmr_replay_transaction(
    job: SsmrReplayRecoveryJob,
) -> Result<SsmrRecoveredTransaction, String> {
    let SsmrReplayRecoveryJob {
        shard_index,
        tx_index,
        encoded,
        queued_at,
    } = job;
    let queue_wait_elapsed = queued_at.elapsed();
    let tx_rlp_length = encoded.len();

    let decode_start = Instant::now();
    let tx = TempoTxEnvelope::decode_2718_exact(encoded.as_ref())
        .map_err(|error| format!("failed decoding SSMR replay transaction: {error}"))?;
    let decode_elapsed = decode_start.elapsed();

    let recover_start = Instant::now();
    let sender = tx
        .try_recover()
        .map_err(|error| format!("failed recovering SSMR replay transaction: {error}"))?;
    let recover_elapsed = recover_start.elapsed();

    Ok(SsmrRecoveredTransaction {
        shard_index,
        tx_index,
        tx: SsmrRecoveredTx {
            transaction: Recovered::new_unchecked(tx, sender),
            encoded,
            tx_rlp_length,
            decode_elapsed,
            recover_elapsed,
            queue_wait_elapsed,
        },
    })
}

fn send_ssmr_replay_event(
    ready_tx: &Sender<SsmrRecoveredReplayEvent>,
    event: SsmrRecoveredReplayEvent,
    recovery_backpressure_elapsed: &mut Duration,
) -> bool {
    let send_start = Instant::now();
    let sent = ready_tx.send(event).is_ok();
    *recovery_backpressure_elapsed += send_start.elapsed();
    sent
}

fn ssmr_replay_recovery_worker_count() -> usize {
    SSMR_REPLAY_RECOVERY_WORKERS
}

fn forward_ssmr_replay_recovered_transaction(
    ready_tx: &Sender<SsmrRecoveredReplayEvent>,
    event: Result<SsmrRecoveredTransaction, String>,
    state: &mut SsmrReplayRecoveryState,
    recovery_wall_start: Option<&Instant>,
) -> bool {
    state.inflight_recovery_jobs = state.inflight_recovery_jobs.saturating_sub(1);
    let recovered = match event {
        Ok(recovered) => recovered,
        Err(error) => {
            let _ = send_ssmr_replay_event(
                ready_tx,
                SsmrRecoveredReplayEvent::Error(error),
                &mut state.recovery_backpressure_elapsed,
            );
            return false;
        }
    };

    if let Err(error) = state.insert_recovered_transaction(recovered) {
        let _ = send_ssmr_replay_event(
            ready_tx,
            SsmrRecoveredReplayEvent::Error(error),
            &mut state.recovery_backpressure_elapsed,
        );
        return false;
    }

    forward_all_ssmr_replay_ready_batches(ready_tx, state, recovery_wall_start)
}

fn forward_all_ssmr_replay_ready_batches(
    ready_tx: &Sender<SsmrRecoveredReplayEvent>,
    state: &mut SsmrReplayRecoveryState,
    recovery_wall_start: Option<&Instant>,
) -> bool {
    loop {
        let batch = match state.drain_ready_batch(recovery_wall_start) {
            Ok(Some(batch)) => batch,
            Ok(None) => return true,
            Err(error) => {
                let _ = send_ssmr_replay_event(
                    ready_tx,
                    SsmrRecoveredReplayEvent::Error(error),
                    &mut state.recovery_backpressure_elapsed,
                );
                return false;
            }
        };

        state.recovery_queue_wait_sum_elapsed += batch.queue_wait_elapsed;

        if !send_ssmr_replay_event(
            ready_tx,
            SsmrRecoveredReplayEvent::Transactions(batch),
            &mut state.recovery_backpressure_elapsed,
        ) {
            return false;
        }
    }
}

fn insert_ssmr_replay_shard(
    ready_tx: &Sender<SsmrRecoveredReplayEvent>,
    state: &mut SsmrReplayRecoveryState,
    shard_index: u64,
    tx_count: usize,
    block_access_list: Option<Bytes>,
) -> bool {
    if state
        .pending_shards
        .insert(
            shard_index,
            SsmrPendingRecoveredShard::new(tx_count, block_access_list),
        )
        .is_some()
    {
        let _ = send_ssmr_replay_event(
            ready_tx,
            SsmrRecoveredReplayEvent::Error(format!("SSMR replay duplicate shard {shard_index}")),
            &mut state.recovery_backpressure_elapsed,
        );
        return false;
    }

    true
}

fn spawn_ssmr_replay_recovery(
    executor: TaskExecutor,
    replay_source: SsmrReplaySource,
) -> Receiver<SsmrRecoveredReplayEvent> {
    let recovery_worker_count = ssmr_replay_recovery_worker_count();
    let (ready_tx, ready_rx) =
        crossbeam_channel::bounded(SSMR_REPLAY_RECOVERY_EVENT_QUEUE_CAPACITY);
    let (job_tx, job_rx) = crossbeam_channel::unbounded::<SsmrReplayRecoveryJob>();
    let (recovered_tx, recovered_rx) =
        crossbeam_channel::bounded(SSMR_REPLAY_RECOVERY_EVENT_QUEUE_CAPACITY);

    executor.spawn_blocking(move || {
        for worker_index in 0..recovery_worker_count {
            let job_rx = job_rx.clone();
            let recovered_tx = recovered_tx.clone();
            if let Err(error) = std::thread::Builder::new()
                .name(format!("ssmr-replay-recovery-worker-{worker_index}"))
                .spawn(move || {
                    while let Ok(job) = job_rx.recv() {
                        let event = recover_ssmr_replay_transaction(job);
                        if recovered_tx.send(event).is_err() {
                            return;
                        }
                    }
                })
            {
                let _ = ready_tx.send(SsmrRecoveredReplayEvent::Error(format!(
                    "failed spawning SSMR replay recovery worker: {error}"
                )));
                return;
            }
        }
        drop(job_rx);
        drop(recovered_tx);

        let mut next_shard_index = 0u64;
        let mut recovery_state = SsmrReplayRecoveryState::default();
        let mut recovery_wall_start = None;
        let mut source_wait_elapsed = Duration::ZERO;

        loop {
            while let Ok(event) = recovered_rx.try_recv() {
                if !forward_ssmr_replay_recovered_transaction(
                    &ready_tx,
                    event,
                    &mut recovery_state,
                    recovery_wall_start.as_ref(),
                ) {
                    return;
                }
            }

            let wait_start = Instant::now();
            let command = replay_source.recv_timeout(SSMR_REPLAY_SOURCE_POLL_INTERVAL);
            source_wait_elapsed += wait_start.elapsed();

            match command {
                Ok(SsmrReplayCommand::Shard {
                    transactions,
                    block_access_list,
                }) => {
                    let shard_index = next_shard_index;
                    next_shard_index += 1;
                    if recovery_wall_start.is_none() {
                        recovery_wall_start = Some(Instant::now());
                    }
                    let tx_count = transactions.len();
                    let bal_bytes = block_access_list
                        .as_ref()
                        .map(|bal| bal.len())
                        .unwrap_or_default();
                    debug!(
                        ssmr_replay_shard_index = shard_index,
                        ssmr_replay_shard_transactions = tx_count,
                        ssmr_replay_shard_bal_bytes = bal_bytes,
                        ssmr_replay_inflight_recovery_jobs = recovery_state.inflight_recovery_jobs,
                        ssmr_replay_pending_shards = recovery_state.pending_shards.len(),
                        "SSMR replay source received shard"
                    );
                    if !insert_ssmr_replay_shard(
                        &ready_tx,
                        &mut recovery_state,
                        shard_index,
                        tx_count,
                        block_access_list,
                    ) {
                        return;
                    }
                    if tx_count == 0 {
                        if !forward_all_ssmr_replay_ready_batches(
                            &ready_tx,
                            &mut recovery_state,
                            recovery_wall_start.as_ref(),
                        ) {
                            return;
                        }
                        continue;
                    }
                    for (tx_index, encoded) in transactions.into_iter().enumerate() {
                        recovery_state.inflight_recovery_jobs += 1;
                        if job_tx
                            .send(SsmrReplayRecoveryJob {
                                shard_index,
                                tx_index,
                                encoded,
                                queued_at: Instant::now(),
                            })
                            .is_err()
                        {
                            let _ = send_ssmr_replay_event(
                                &ready_tx,
                                SsmrRecoveredReplayEvent::Error(
                                    "SSMR replay recovery workers closed before finish".to_string(),
                                ),
                                &mut recovery_state.recovery_backpressure_elapsed,
                            );
                            return;
                        }
                    }
                }
                Ok(SsmrReplayCommand::Finish) => {
                    debug!(
                        ssmr_replay_shards_received = next_shard_index,
                        ssmr_replay_inflight_recovery_jobs = recovery_state.inflight_recovery_jobs,
                        ssmr_replay_pending_shards = recovery_state.pending_shards.len(),
                        "SSMR replay source received finish"
                    );
                    drop(job_tx);
                    while recovery_state.inflight_recovery_jobs > 0 {
                        match recovered_rx.recv() {
                            Ok(event) => {
                                if !forward_ssmr_replay_recovered_transaction(
                                    &ready_tx,
                                    event,
                                    &mut recovery_state,
                                    recovery_wall_start.as_ref(),
                                ) {
                                    return;
                                }
                            }
                            Err(_) => {
                                let _ = send_ssmr_replay_event(
                                    &ready_tx,
                                    SsmrRecoveredReplayEvent::Error(
                                        "SSMR replay recovery closed before finish".to_string(),
                                    ),
                                    &mut recovery_state.recovery_backpressure_elapsed,
                                );
                                return;
                            }
                        }
                    }
                    if !forward_all_ssmr_replay_ready_batches(
                        &ready_tx,
                        &mut recovery_state,
                        recovery_wall_start.as_ref(),
                    ) {
                        return;
                    }
                    if !recovery_state.pending_shards.is_empty() {
                        let _ = send_ssmr_replay_event(
                            &ready_tx,
                            SsmrRecoveredReplayEvent::Error(
                                "SSMR replay recovery finished with incomplete shards".to_string(),
                            ),
                            &mut recovery_state.recovery_backpressure_elapsed,
                        );
                        return;
                    }

                    let _ = ready_tx.send(SsmrRecoveredReplayEvent::Finish {
                        source_wait_elapsed,
                        recovery_wall_elapsed: recovery_wall_start
                            .map(|start| start.elapsed())
                            .unwrap_or_default(),
                        first_tx_recovery_elapsed: recovery_state.first_tx_recovery_elapsed,
                        recovery_queue_wait_sum_elapsed: recovery_state
                            .recovery_queue_wait_sum_elapsed,
                        recovery_backpressure_elapsed: recovery_state.recovery_backpressure_elapsed,
                        recovery_worker_count,
                    });
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    warn!(
                        ssmr_replay_shards_received = next_shard_index,
                        ssmr_replay_inflight_recovery_jobs = recovery_state.inflight_recovery_jobs,
                        ssmr_replay_pending_shards = recovery_state.pending_shards.len(),
                        "SSMR replay source closed before finish"
                    );
                    let _ = send_ssmr_replay_event(
                        &ready_tx,
                        SsmrRecoveredReplayEvent::Error(
                            "SSMR replay source closed before finish".to_string(),
                        ),
                        &mut recovery_state.recovery_backpressure_elapsed,
                    );
                    return;
                }
            }
        }
    });

    ready_rx
}

struct SsmrBalReplayJob {
    output_index: usize,
    bal_start_index: usize,
    global_index: usize,
    transactions: Vec<SsmrRecoveredTx>,
    bal: Arc<RevmBal>,
}

impl SsmrBalReplayJob {
    fn split_into(self, target_tx_count: usize, jobs: &mut Vec<Self>) {
        let target_tx_count = target_tx_count.max(1);
        if self.transactions.len() <= target_tx_count {
            jobs.push(self);
            return;
        }

        let Self {
            output_index,
            bal_start_index,
            global_index,
            transactions,
            bal,
        } = self;
        let mut chunk_start = 0usize;
        let mut chunk = Vec::with_capacity(target_tx_count);
        for tx in transactions {
            chunk.push(tx);
            if chunk.len() == target_tx_count {
                let chunk_len = chunk.len();
                jobs.push(Self {
                    output_index: output_index + chunk_start,
                    bal_start_index: bal_start_index + chunk_start,
                    global_index: global_index + chunk_start,
                    transactions: std::mem::take(&mut chunk),
                    bal: Arc::clone(&bal),
                });
                chunk_start += chunk_len;
                chunk = Vec::with_capacity(target_tx_count);
            }
        }

        if !chunk.is_empty() {
            jobs.push(Self {
                output_index: output_index + chunk_start,
                bal_start_index: bal_start_index + chunk_start,
                global_index: global_index + chunk_start,
                transactions: chunk,
                bal,
            });
        }
    }
}

struct SsmrBalReplayOutput {
    output_index: usize,
    global_index: usize,
    tx: SsmrRecoveredTx,
    is_payment: bool,
    result: TempoTxResult,
    started_at: Instant,
    finished_at: Instant,
}

struct SsmrPreparedBalReplay {
    jobs: Vec<SsmrBalReplayJob>,
    tx_count: usize,
    bal_decode_elapsed: Duration,
}

struct SsmrBalReplayScheduler {
    job_tx: Option<Sender<SsmrBalReplayJob>>,
    result_rx: Receiver<Result<SsmrBalReplayOutput, String>>,
    outputs: BTreeMap<usize, SsmrBalReplayOutput>,
    next_output_index: usize,
    next_commit_index: usize,
    worker_execute_elapsed: Duration,
    ordered_commit_elapsed: Duration,
}

impl SsmrBalReplayScheduler {
    fn new(
        job_tx: Sender<SsmrBalReplayJob>,
        result_rx: Receiver<Result<SsmrBalReplayOutput, String>>,
    ) -> Self {
        Self {
            job_tx: Some(job_tx),
            result_rx,
            outputs: BTreeMap::new(),
            next_output_index: 0,
            next_commit_index: 0,
            worker_execute_elapsed: Duration::ZERO,
            ordered_commit_elapsed: Duration::ZERO,
        }
    }

    fn has_pending_outputs(&self) -> bool {
        self.next_commit_index < self.next_output_index
    }

    fn enqueue(&mut self, prepared: SsmrPreparedBalReplay) -> Result<(), PayloadBuilderError> {
        let Some(job_tx) = &self.job_tx else {
            return Err(PayloadBuilderError::other(std::io::Error::other(
                "SSMR BAL replay scheduler closed",
            )));
        };

        for job in prepared.jobs {
            job_tx.send(job).map_err(|_| {
                PayloadBuilderError::other(std::io::Error::other("SSMR BAL replay workers closed"))
            })?;
        }
        self.next_output_index += prepared.tx_count;
        Ok(())
    }

    fn close(&mut self) {
        self.job_tx.take();
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_ready_outputs<E>(
        &mut self,
        wait_for_all: bool,
        executor: &mut E,
        roots_tx: &Sender<(BuilderTx, TempoReceipt)>,
        cumulative_gas_used: &mut u64,
        cumulative_state_gas_used: &mut u64,
        non_payment_gas_used: &mut u64,
        payment_transactions: &mut u64,
        reverted_transactions: &mut u64,
        total_fees: &mut U256,
        pool_transactions_yielded: &mut u64,
        pool_transactions_included: &mut u64,
        replay_transactions: &mut u64,
        tx_gas_limit_cap: u64,
        non_shared_gas_limit: u64,
        general_gas_limit: u64,
    ) -> Result<usize, PayloadBuilderError>
    where
        E: BlockExecutor<
                Transaction = TempoTxEnvelope,
                Receipt = TempoReceipt,
                Result = TempoTxResult,
            >,
    {
        let mut committed = 0usize;
        loop {
            committed += self.commit_available_outputs(
                executor,
                roots_tx,
                cumulative_gas_used,
                cumulative_state_gas_used,
                non_payment_gas_used,
                payment_transactions,
                reverted_transactions,
                total_fees,
                pool_transactions_yielded,
                pool_transactions_included,
                replay_transactions,
                tx_gas_limit_cap,
                non_shared_gas_limit,
                general_gas_limit,
            )?;

            if wait_for_all && self.has_pending_outputs() {
                let output = self.result_rx.recv().map_err(|_| {
                    PayloadBuilderError::other(std::io::Error::other(
                        "SSMR BAL replay workers closed",
                    ))
                })?;
                self.insert_output(output)?;
                continue;
            }

            match self.result_rx.try_recv() {
                Ok(output) => {
                    self.insert_output(output)?;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    if self.has_pending_outputs() {
                        return Err(PayloadBuilderError::other(std::io::Error::other(
                            "SSMR BAL replay workers closed",
                        )));
                    }
                    break;
                }
            }
        }

        Ok(committed)
    }

    fn insert_output(
        &mut self,
        output: Result<SsmrBalReplayOutput, String>,
    ) -> Result<(), PayloadBuilderError> {
        let output =
            output.map_err(|error| PayloadBuilderError::other(std::io::Error::other(error)))?;
        if output.output_index >= self.next_output_index {
            return Err(PayloadBuilderError::other(std::io::Error::other(
                "SSMR BAL replay worker returned out-of-range output",
            )));
        }
        self.worker_execute_elapsed = self.worker_execute_elapsed.max(
            output
                .finished_at
                .saturating_duration_since(output.started_at),
        );
        if self.outputs.insert(output.output_index, output).is_some() {
            return Err(PayloadBuilderError::other(std::io::Error::other(
                "SSMR BAL replay worker returned duplicate output",
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_available_outputs<E>(
        &mut self,
        executor: &mut E,
        roots_tx: &Sender<(BuilderTx, TempoReceipt)>,
        cumulative_gas_used: &mut u64,
        cumulative_state_gas_used: &mut u64,
        non_payment_gas_used: &mut u64,
        payment_transactions: &mut u64,
        reverted_transactions: &mut u64,
        total_fees: &mut U256,
        pool_transactions_yielded: &mut u64,
        pool_transactions_included: &mut u64,
        replay_transactions: &mut u64,
        tx_gas_limit_cap: u64,
        non_shared_gas_limit: u64,
        general_gas_limit: u64,
    ) -> Result<usize, PayloadBuilderError>
    where
        E: BlockExecutor<
                Transaction = TempoTxEnvelope,
                Receipt = TempoReceipt,
                Result = TempoTxResult,
            >,
    {
        let mut committed = 0usize;
        while let Some(output) = self.outputs.remove(&self.next_commit_index) {
            debug_assert_eq!(output.global_index, self.next_commit_index);
            let ordered_commit_start = Instant::now();
            let max_regular_gas_used =
                core::cmp::min(output.tx.transaction.inner().gas_limit(), tx_gas_limit_cap);
            if *cumulative_gas_used + max_regular_gas_used > non_shared_gas_limit {
                return Err(PayloadBuilderError::evm(BlockExecutionError::Validation(
                    BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                        transaction_gas_limit: output.tx.transaction.inner().gas_limit(),
                        block_available_gas: non_shared_gas_limit - *cumulative_gas_used,
                    },
                )));
            }
            if !output.is_payment
                && *non_payment_gas_used + max_regular_gas_used > general_gas_limit
            {
                return Err(PayloadBuilderError::other(
                    TempoPoolTransactionError::ExceedsNonPaymentLimit,
                ));
            }

            *cumulative_gas_used += output.result.block_gas_used();
            *cumulative_state_gas_used += output.result.state_gas_used();
            if output.is_payment {
                *payment_transactions += 1;
            } else {
                *non_payment_gas_used += output.result.block_gas_used();
            }
            *total_fees += output.result.validator_fee();

            let _ = executor.commit_transaction(output.result);
            let receipt = executor.receipts().last().unwrap().clone();
            if !receipt.success {
                *reverted_transactions += 1;
            }
            let _ = roots_tx.send((
                BuilderTx::Owned {
                    tx: Box::new(output.tx.transaction),
                    encoded_2718: Some(output.tx.encoded),
                },
                receipt,
            ));
            self.ordered_commit_elapsed += ordered_commit_start.elapsed();
            self.next_commit_index += 1;
            *pool_transactions_yielded += 1;
            *pool_transactions_included += 1;
            *replay_transactions += 1;
            committed += 1;
        }
        Ok(committed)
    }
}

fn ssmr_bal_replay_target_job_tx_count(tx_count: usize, worker_limit: usize) -> usize {
    let target_job_count = worker_limit.max(1).min(tx_count.max(1));
    tx_count.div_ceil(target_job_count).max(1)
}

#[derive(Debug, Default)]
struct SsmrReplayBalHistory {
    bal: RevmBal,
}

impl SsmrReplayBalHistory {
    fn apply_to(&self, shard_bal: &mut RevmBal) {
        for (address, shard_account) in shard_bal.accounts.iter_mut() {
            let Some(history_account) = self.bal.accounts.get(address) else {
                continue;
            };
            apply_account_bal_history(shard_account, history_account);
        }
    }

    fn record(&mut self, shard_bal: &RevmBal) {
        for (address, shard_account) in &shard_bal.accounts {
            let history_account = self.bal.accounts.entry(*address).or_default();
            record_account_bal_history(history_account, shard_account);
        }
    }
}

fn apply_bal_history_writes<T>(writes: &mut BalWrites<T>, history: &BalWrites<T>)
where
    T: PartialEq + Clone,
{
    let Some((_, value)) = history.writes.last() else {
        return;
    };

    match writes.writes.first_mut() {
        Some((index, existing)) if *index == BlockAccessIndex::PRE_EXECUTION => {
            *existing = value.clone();
        }
        _ => writes
            .writes
            .insert(0, (BlockAccessIndex::PRE_EXECUTION, value.clone())),
    }
}

fn record_bal_history_writes<T>(history: &mut BalWrites<T>, writes: &BalWrites<T>)
where
    T: PartialEq + Clone,
{
    let Some((_, value)) = writes.writes.last() else {
        return;
    };

    history.force_update(BlockAccessIndex::PRE_EXECUTION, value.clone());
}

fn apply_account_bal_history(account: &mut AccountBal, history: &AccountBal) {
    apply_bal_history_writes(&mut account.account_info.nonce, &history.account_info.nonce);
    apply_bal_history_writes(
        &mut account.account_info.balance,
        &history.account_info.balance,
    );
    apply_bal_history_writes(&mut account.account_info.code, &history.account_info.code);

    for (key, writes) in account.storage.storage.iter_mut() {
        if let Some(history_writes) = history.storage.storage.get(key) {
            apply_bal_history_writes(writes, history_writes);
        }
    }
}

fn record_account_bal_history(history: &mut AccountBal, account: &AccountBal) {
    record_bal_history_writes(&mut history.account_info.nonce, &account.account_info.nonce);
    record_bal_history_writes(
        &mut history.account_info.balance,
        &account.account_info.balance,
    );
    record_bal_history_writes(&mut history.account_info.code, &account.account_info.code);

    for (key, writes) in &account.storage.storage {
        let history_writes = history.storage.storage.entry(*key).or_default();
        record_bal_history_writes(history_writes, writes);
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_ssmr_bal_replay_batches(
    batches: Vec<SsmrRecoveredBatch>,
    bal_history: &mut SsmrReplayBalHistory,
    starting_output_index: usize,
    worker_limit: usize,
    is_osaka: bool,
    estimated_rlp_block_size: &mut usize,
) -> Result<SsmrPreparedBalReplay, PayloadBuilderError> {
    let bal_decode_start = Instant::now();
    let mut shard_jobs = Vec::new();
    let mut tx_count = 0usize;

    for batch in batches {
        let Some(encoded_bal) = batch.block_access_list else {
            return Err(PayloadBuilderError::other(std::io::Error::other(
                "SSMR BAL replay shard missing BAL data",
            )));
        };
        let mut encoded_bal_ref = encoded_bal.as_ref();
        let alloy_bal = Bal::decode(&mut encoded_bal_ref).map_err(PayloadBuilderError::other)?;
        let revm_bal = RevmBal::try_from(Vec::<_>::from(alloy_bal)).map_err(|error| {
            PayloadBuilderError::other(std::io::Error::other(format!("{error:?}")))
        })?;
        let mut effective_bal = revm_bal.clone();
        bal_history.apply_to(&mut effective_bal);
        bal_history.record(&revm_bal);
        let revm_bal = Arc::new(effective_bal);

        let output_index = starting_output_index + tx_count;
        let mut transactions = Vec::with_capacity(batch.transactions.len());
        for tx in batch.transactions {
            let estimated_block_size_with_tx = *estimated_rlp_block_size + tx.tx_rlp_length;
            if is_osaka && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE {
                return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                    rlp_length: estimated_block_size_with_tx,
                    max_rlp_length: MAX_RLP_BLOCK_SIZE,
                }));
            }
            *estimated_rlp_block_size = estimated_block_size_with_tx;

            transactions.push(tx);
            tx_count += 1;
        }

        if !transactions.is_empty() {
            shard_jobs.push(SsmrBalReplayJob {
                output_index,
                bal_start_index: 0,
                global_index: output_index,
                transactions,
                bal: revm_bal,
            });
        }
    }

    let target_job_tx_count = ssmr_bal_replay_target_job_tx_count(tx_count, worker_limit);
    let mut jobs = Vec::with_capacity(worker_limit.min(tx_count.max(1)));
    for job in shard_jobs {
        job.split_into(target_job_tx_count, &mut jobs);
    }

    Ok(SsmrPreparedBalReplay {
        jobs,
        tx_count,
        bal_decode_elapsed: bal_decode_start.elapsed(),
    })
}

#[allow(clippy::too_many_arguments)]
fn run_ssmr_bal_replay_worker<Provider>(
    job_rx: Receiver<SsmrBalReplayJob>,
    result_tx: Sender<Result<SsmrBalReplayOutput, String>>,
    cancelled: Arc<AtomicBool>,
    provider: Provider,
    execution_cache: Option<ExecutionCache>,
    parent_hash: B256,
    evm_config: TempoEvmConfig,
    evm_env: EvmEnvFor<TempoEvmConfig>,
    ctx: ExecutionCtxFor<'_, TempoEvmConfig>,
    beneficiary: Address,
    is_t5: bool,
) where
    Provider: StateProviderFactory
        + ChainSpecProvider<ChainSpec = TempoChainSpec>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let state_provider = match provider.state_by_block_hash(parent_hash) {
        Ok(mut state_provider) => {
            if let Some(cache) = execution_cache {
                state_provider = Box::new(CachedStateProvider::new_prewarm(state_provider, cache));
            }
            state_provider
        }
        Err(error) => {
            let error = format!("failed opening SSMR replay state: {error}");
            while job_rx.recv().is_ok() {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
                if result_tx.send(Err(error.clone())).is_err() {
                    return;
                }
            }
            return;
        }
    };

    let state = StateProviderDatabase::new(&state_provider);
    let mut db = State::builder()
        .with_database(Box::new(state) as Box<dyn Database<Error = ProviderError>>)
        .with_bundle_update()
        .build();
    let evm = evm_config.evm_with_env(&mut db, evm_env);
    let mut worker_executor = evm_config.create_executor(evm, ctx);
    worker_executor.evm_mut().ctx_mut().block.beneficiary = beneficiary;

    while let Ok(job) = job_rx.recv() {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let result =
            (|| -> Result<(), String> {
                let job_started_at = Instant::now();
                worker_executor
                    .evm_mut()
                    .db_mut()
                    .set_bal(Some(Arc::clone(&job.bal)));
                for (bal_index, tx) in job.transactions.into_iter().enumerate() {
                    worker_executor.evm_mut().db_mut().set_bal_index(
                        BlockAccessIndex::from_tx_index((job.bal_start_index + bal_index) as u64),
                    );
                    let is_payment = if is_t5 {
                        tx.transaction.inner().is_payment_v2()
                    } else {
                        tx.transaction.inner().is_payment_v1()
                    };
                    let result = worker_executor
                        .execute_transaction_without_commit(&tx.transaction)
                        .map_err(|error| format!("SSMR BAL replay transaction failed: {error}"))?;

                    if result_tx
                        .send(Ok(SsmrBalReplayOutput {
                            output_index: job.output_index + bal_index,
                            global_index: job.global_index + bal_index,
                            tx,
                            is_payment,
                            result,
                            started_at: job_started_at,
                            finished_at: Instant::now(),
                        }))
                        .is_err()
                    {
                        return Ok(());
                    }
                }

                Ok(())
            })();

        if let Err(error) = result {
            let _ = result_tx.send(Err(error));
            return;
        }
    }
}

/// Source of transactions for payload building.
enum PayloadTransactions {
    Sequential(StateAwareBestTransactions<Box<dyn BestTransactions<Item = BestTransaction>>>),
    Prewarming(StateAwareBestTransactions<BestTransactionsPrewarming>),
    Parallel(BestTransactionsPrewarming),
}

impl PayloadTransactions {
    /// Returns the next transaction, if available.
    fn next(&mut self) -> Option<PrewarmedTransaction> {
        match self {
            Self::Sequential(txs) => txs.next().map(PrewarmedTransaction::without_replay),
            Self::Prewarming(txs) => txs.next(),
            Self::Parallel(planner) => planner.next(),
        }
    }

    /// Mark the transaction as invalid.
    fn mark_invalid(&mut self, tx: &PrewarmedTransaction, kind: InvalidPoolTransactionError) {
        match self {
            Self::Sequential(txs) => txs.mark_invalid(&tx.tx, kind),
            Self::Prewarming(txs) => txs.mark_invalid(tx, kind),
            Self::Parallel(prewarming) => prewarming.mark_invalid(tx, kind),
        }
    }

    /// Notify the iterator of a new result.
    ///
    /// Noop for [`Self::Parallel`], as it doesn't use the [`StateAwareBestTransactions`] iterator.
    fn on_new_result(&mut self, result: &TempoTxResult) {
        match self {
            Self::Sequential(txs) => txs.on_new_result(result),
            Self::Prewarming(txs) => txs.on_new_result(result),
            Self::Parallel(_) => {
                // Parallel does not use state-aware best transactions iterator.
            }
        }
    }

    /// Number of transactions skipped by the state-aware iterator because their
    /// tracked TIP20 balance was insufficient.
    fn balance_skips(&self) -> u64 {
        match self {
            Self::Sequential(txs) => txs.balance_skips(),
            Self::Prewarming(txs) => txs.balance_skips(),
            Self::Parallel(_) => 0,
        }
    }

    /// Number of transactions skipped by the state-aware iterator because they
    /// were already invalidated by this payload build.
    fn tracked_invalid_skips(&self) -> u64 {
        match self {
            Self::Sequential(txs) => txs.tracked_invalid_skips(),
            Self::Prewarming(txs) => txs.tracked_invalid_skips(),
            Self::Parallel(_) => 0,
        }
    }

    /// Replaces the underlying transaction source, preserving state-aware
    /// invalidations for matching sequential/prewarming variants.
    fn replace_with(&mut self, replacement: Self) {
        match (self, replacement) {
            (Self::Sequential(txs), Self::Sequential(replacement)) => {
                txs.replace_inner(replacement.into_inner());
            }
            (Self::Prewarming(txs), Self::Prewarming(replacement)) => {
                txs.replace_inner(replacement.into_inner());
            }
            (this, replacement) => {
                *this = replacement;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TempoPayloadBuilder<Provider> {
    pool: TempoTransactionPool<Provider>,
    provider: Provider,
    executor: TaskExecutor,
    config: TempoPayloadBuilderConfig,
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
    /// Whether to include block access lists in built execution payloads.
    enable_bal: bool,
    /// Learned estimate of total replayable build work divided by work at tx cutoff.
    ///
    /// This lets the builder reserve time for non-interruptible
    /// `builder_finish` without a fixed duration.
    build_time_multiplier: Arc<AtomicU64>,
}

/// Runtime settings for the Tempo payload builder.
#[derive(Debug, Clone, Copy)]
pub struct TempoPayloadBuilderConfig {
    /// Desired gas limit.
    ///
    /// If not set, the parent gas limit is used.
    pub desired_gas_limit: Option<u64>,
    /// Whether the node is configured in `--dev` miner mode.
    pub is_dev: bool,
    /// Whether to enable state provider metrics.
    pub state_provider_metrics: bool,
    /// Whether to enable prewarming of best transactions.
    pub enable_prewarming: bool,
    /// Whether payload builds should skip state-root computation.
    pub skip_state_root: bool,
    /// Whether to enable speculative parallel payload-builder planning.
    pub enable_parallel: bool,
    /// Initial estimate of total replayable build work divided by work at tx cutoff.
    ///
    /// `1.0` means no finish-work headroom beyond observed work so far. Values
    /// above `1.0` stop transaction execution earlier to leave room for
    /// `builder_finish`, which validators also repeat.
    pub build_time_multiplier: f64,
}

impl TempoPayloadBuilderConfig {
    /// Returns the gas limit for the next block based on the parent gas limit and an optional
    /// target from payload attributes.
    ///
    /// If [`TempoPayloadBuilderConfig::desired_gas_limit`] is [`None`], the parent gas limit is used.
    pub fn gas_limit_with_target(
        &self,
        parent_gas_limit: u64,
        target_gas_limit: Option<u64>,
    ) -> u64 {
        calculate_block_gas_limit(
            parent_gas_limit,
            target_gas_limit
                .or(self.desired_gas_limit)
                .unwrap_or(parent_gas_limit),
        )
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
            config,
            evm_config,
            metrics: TempoPayloadBuilderMetrics::default(),
            cache_metrics: CachedStateMetrics::zeroed(CachedStateMetricsSource::Builder),
            highest_invalid_subblock: Default::default(),
            enable_bal: cfg!(feature = "bal"),
            build_time_multiplier: Arc::new(AtomicU64::new(scaled_build_time_multiplier(
                config.build_time_multiplier,
            ))),
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
        best_txs: impl Fn(BestTransactionsAttributes) -> Txs,
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
            ..
        } = config;
        let ssmr_replay_source = attributes.ssmr_replay_source();
        let is_ssmr_replay = ssmr_replay_source.is_some();
        let build_once_with_shared_trie =
            // SSMR replay sources are one-shot streams, so the job must not try to rebuild.
            is_ssmr_replay ||
            // When trie handle is provided, we build the payload once so the shared trie can be reused.
            (trie_handle.is_some()
            // `--dev` mode does not use the shared-trie builder flow.
            && !self.config.is_dev);

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
        if self.config.state_provider_metrics {
            state_provider = Box::new(InstrumentedStateProvider::new(state_provider, "builder"));
        }

        let state = StateProviderDatabase::new(&state_provider);
        let mut db = State::builder()
            .with_database(Box::new(state) as Box<dyn Database<Error = ProviderError>>)
            .with_bundle_update()
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

        let block_gas_limit = self
            .config
            .gas_limit_with_target(parent_header.gas_limit(), attributes.target_gas_limit);
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
        let mut estimated_rlp_block_size = attributes
            .withdrawals
            .as_ref()
            .map(|w| w.length())
            .unwrap_or(0)
            + NON_TRANSACTION_SIZE_ESTIMATE
            + attributes.extra_data().length();
        let mut payment_transactions = 0u64;
        let mut reverted_transactions = 0u64;
        let mut pool_transactions_yielded = 0u64;
        let mut pool_transactions_included = 0u64;
        let mut parallel_transactions_executed = 0u64;
        let mut total_fees = U256::ZERO;

        // If building an empty payload, don't include any subblocks
        //
        // Also don't include any subblocks if we've seen an invalid subblock
        // at this height or above.
        let mut subblocks = if empty
            || is_ssmr_replay
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
            if subblock.has_expired_transactions(attributes.timestamp) {
                self.metrics.inc_subblocks_expired();
                return false;
            }

            // Account for the subblock's size
            estimated_rlp_block_size += subblock.total_tx_size();

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

        let next_attributes = TempoNextBlockEnvAttributes {
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
            .next_evm_env(&parent_header, &next_attributes)
            .map_err(PayloadBuilderError::other)?;
        let ctx = self
            .evm_config
            .context_for_next_block(&parent_header, next_attributes)
            .map_err(PayloadBuilderError::other)?;

        let evm = self.evm_config.evm_with_env(&mut db, evm_env);
        let mut executor = self.evm_config.create_executor(evm, ctx.clone());

        check_cancel!();

        // Override the fee recipient with the on-chain value from the V2
        // validator config contract, if available.
        maybe_override_fee_recipient(&mut executor, &attributes);

        let bal_task_handle = if self.enable_bal {
            let bal_task_handle =
                self.spawn_bal_task(trie_handle.as_ref().map(|handle| handle.state_hook()));
            executor
                .evm_mut()
                .db_mut()
                .set_state_hook(Some(Box::new(bal_task_handle.state_hook())));
            Some(bal_task_handle)
        } else {
            if let Some(ref handle) = trie_handle {
                executor
                    .evm_mut()
                    .db_mut()
                    .set_state_hook(Some(Box::new(handle.state_hook())));
            }
            None
        };

        executor.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;
        if let Some(bal_task_handle) = &bal_task_handle {
            bal_task_handle.bump_bal_index();
            executor
                .evm_mut()
                .db_mut()
                .set_state_hook(Some(Box::new(bal_task_handle.transaction_state_hook())));
        }

        check_cancel!();

        debug!("building new payload");

        let mut ssmr_packer = attributes.ssmr_builder_sink().map(|sink| {
            SsmrShardPacker::new(
                sink,
                attributes.ssmr_shard_target_bytes().unwrap_or(0),
                self.metrics.clone(),
            )
        });
        let (roots_tx, roots_rx) = self.spawn_roots_task();

        // Prepare system transactions before actual block building and account for their size.
        let prepare_system_txs_start = Instant::now();
        let system_txs = if is_ssmr_replay {
            Vec::new()
        } else {
            self.build_seal_block_txs(executor.evm(), &subblocks)
        };
        for tx in &system_txs {
            estimated_rlp_block_size += tx.inner().length();
        }
        let prepare_system_txs_elapsed = prepare_system_txs_start.elapsed();
        self.metrics
            .prepare_system_transactions_duration_seconds
            .record(prepare_system_txs_elapsed);

        if is_osaka && estimated_rlp_block_size > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: estimated_rlp_block_size,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        let execution_start = Instant::now();
        let _block_fill_span = debug_span!(target: "payload_builder", "block_fill").entered();
        let mut skipped_oversized_block = false;
        let mut invalid_pool_transaction_execution_attempts = 0u64;
        let mut normal_transaction_fill_idle_elapsed = Duration::ZERO;
        let mut normal_transaction_fill_idle_polls = 0u64;
        let mut normal_transaction_fill_iterator_refreshes = 0u64;
        let mut normal_transaction_fill_last_iterator_refresh_poll = None;
        let mut normal_transaction_fill_pool_at_start = PoolSizeSnapshot::default();
        let mut normal_transaction_fill_pool_at_first_idle = PoolSizeSnapshot::default();
        let mut normal_transaction_fill_pool_at_last_idle = PoolSizeSnapshot::default();
        let mut normal_transaction_fill_best_txs_next_elapsed = Duration::ZERO;
        let mut normal_transaction_fill_pool_tx_execution_elapsed = Duration::ZERO;
        let mut normal_transaction_fill_ssmr_pack_elapsed = Duration::ZERO;
        let mut normal_transaction_fill_roots_send_elapsed = Duration::ZERO;
        let mut normal_transaction_fill_state_aware_balance_skips = 0u64;
        let mut normal_transaction_fill_state_aware_tracked_invalid_skips = 0u64;
        let mut validation_wait_elapsed = Duration::ZERO;
        let mut ssmr_replay_wait_elapsed = Duration::ZERO;
        let ssmr_replay_pool_lookup_elapsed = Duration::ZERO;
        let ssmr_replay_pool_hits = 0u64;
        let ssmr_replay_pool_misses = 0u64;
        let mut ssmr_replay_decode_recover_elapsed = Duration::ZERO;
        let mut ssmr_replay_decode_elapsed = Duration::ZERO;
        let mut ssmr_replay_recover_elapsed = Duration::ZERO;
        let mut ssmr_replay_recovery_wait_elapsed = Duration::ZERO;
        let mut ssmr_replay_recovery_wall_elapsed = Duration::ZERO;
        let mut ssmr_replay_first_tx_recovery_elapsed = None;
        let mut ssmr_replay_recovery_queue_wait_sum_elapsed = Duration::ZERO;
        let mut ssmr_replay_recovery_backpressure_elapsed = Duration::ZERO;
        let mut ssmr_replay_execution_wait_for_recovery_elapsed = Duration::ZERO;
        let mut ssmr_replay_recovery_worker_count = 0usize;
        let mut ssmr_replay_max_recovered_tx_ahead = 0usize;
        let mut ssmr_replay_execute_elapsed = Duration::ZERO;
        let mut ssmr_replay_bal_decode_elapsed = Duration::ZERO;
        let mut ssmr_replay_bal_worker_execute_elapsed = Duration::ZERO;
        let mut ssmr_replay_bal_ordered_commit_elapsed = Duration::ZERO;
        let mut ssmr_replay_shards = 0u64;
        let mut ssmr_replay_transactions = 0u64;
        let mut ssmr_replay_bal_shards = 0u64;
        let mut ssmr_replay_serial_shards = 0u64;
        let mut ssmr_replay_missing_bal_shards = 0u64;
        let mut ssmr_replay_shard_bal_bytes_total = 0usize;
        let mut ssmr_replay_shard_bal_bytes_last = 0usize;
        let mut action_replay_state = StorageActionReplayState::default();
        // Consensus builds carry a remaining proposal budget. When present, the
        // builder stops pool tx execution before projected proposer and validator
        // work would consume that window.
        let payload_build_budget = attributes.payload_build_budget();
        let marshal_persist = marshal_persist_estimate();
        let validation_latency = attributes.validation_latency_estimate();
        let post_return_tail_budget = attributes.post_return_tail_budget();
        let static_ssmr_build_budget = payload_build_budget.is_some()
            && ssmr_packer.is_some()
            && validation_latency.is_none()
            && post_return_tail_budget == Some(Duration::ZERO);
        let build_time_multiplier = if static_ssmr_build_budget {
            BUILD_TIME_MULTIPLIER_SCALE
        } else {
            self.build_time_multiplier()
        };
        let block_build_stop_reason = if let Some(replay_source) = ssmr_replay_source {
            let recovered_events = spawn_ssmr_replay_recovery(self.executor.clone(), replay_source);
            let ssmr_replay_execution_cache =
                execution_cache.as_ref().map(|cache| cache.cache().clone());
            let ssmr_replay_prewarmer = self.config.enable_prewarming.then(|| {
                SsmrReplayPrewarmer::new(
                    self.executor.clone(),
                    self.provider.clone(),
                    execution_cache,
                    parent_header.hash(),
                    executor.evm().evm_env(),
                )
            });
            let mut replay_progress = SsmrReplayProgress::default();
            let mut replay_bal_history = SsmrReplayBalHistory::default();
            let replay_evm_env = executor.evm().evm_env();
            let replay_beneficiary = executor.evm().block().beneficiary;
            let replay_tx_gas_limit_cap = executor.evm().cfg.tx_gas_limit_cap.unwrap_or(u64::MAX);
            let replay_parent_hash = parent_header.hash();
            let bal_pool = self.executor.bal_streaming_pool();
            let worker_limit = bal_pool.current_num_threads().max(1);
            let bal_replay_cancelled = Arc::new(AtomicBool::new(false));
            let stop_reason = bal_pool.in_place_scope(
                |scope| -> Result<Option<BlockBuildStopReason>, PayloadBuilderError> {
                    let (job_tx, job_rx) = crossbeam_channel::unbounded::<SsmrBalReplayJob>();
                    let (result_tx, result_rx) =
                        crossbeam_channel::unbounded::<Result<SsmrBalReplayOutput, String>>();
                    for _ in 0..worker_limit {
                        let job_rx = job_rx.clone();
                        let result_tx = result_tx.clone();
                        let provider = self.provider.clone();
                        let execution_cache = ssmr_replay_execution_cache.clone();
                        let cancelled = Arc::clone(&bal_replay_cancelled);
                        let evm_config = self.evm_config.clone();
                        let evm_env = replay_evm_env.clone();
                        let ctx = ctx.clone();
                        scope.spawn(move |_| {
                            run_ssmr_bal_replay_worker(
                                job_rx,
                                result_tx,
                                cancelled,
                                provider,
                                execution_cache,
                                replay_parent_hash,
                                evm_config,
                                evm_env,
                                ctx,
                                replay_beneficiary,
                                hardfork.is_t5(),
                            );
                        });
                    }
                    drop(result_tx);
                    let mut bal_replay = SsmrBalReplayScheduler::new(job_tx, result_rx);

                    let stop_reason = loop {
                        if cancel.is_cancelled() {
                            bal_replay_cancelled.store(true, Ordering::Relaxed);
                            bal_replay.close();
                            break None;
                        }

                        bal_replay.drain_ready_outputs(
                            false,
                            &mut executor,
                            &roots_tx,
                            &mut cumulative_gas_used,
                            &mut cumulative_state_gas_used,
                            &mut non_payment_gas_used,
                            &mut payment_transactions,
                            &mut reverted_transactions,
                            &mut total_fees,
                            &mut pool_transactions_yielded,
                            &mut pool_transactions_included,
                            &mut replay_progress.transactions,
                            replay_tx_gas_limit_cap,
                            non_shared_gas_limit,
                            general_gas_limit,
                        )?;

                        replay_progress
                            .drain_ready_events(&recovered_events, ssmr_replay_prewarmer.as_ref())?;

                        if let Some(batch) = replay_progress.pending_batches.pop_front() {
                            if batch.block_access_list.is_some() {
                                replay_progress.drain_ready_events(
                                    &recovered_events,
                                    ssmr_replay_prewarmer.as_ref(),
                                )?;
                                let batches = replay_progress.collect_ready_bal_batches(batch);

                                for batch in &batches {
                                    ssmr_replay_decode_elapsed += batch.decode_elapsed;
                                    ssmr_replay_recover_elapsed += batch.recover_elapsed;
                                    ssmr_replay_decode_recover_elapsed +=
                                        batch.decode_elapsed + batch.recover_elapsed;

                                    let shard_bal_bytes = batch
                                        .block_access_list
                                        .as_ref()
                                        .map(|bal| bal.len())
                                        .unwrap_or_default();
                                    ssmr_replay_shard_bal_bytes_total += shard_bal_bytes;
                                    ssmr_replay_shard_bal_bytes_last = shard_bal_bytes;
                                    self.metrics
                                        .ssmr_replay_shard_bal_bytes
                                        .record(shard_bal_bytes as f64);
                                    self.metrics
                                        .ssmr_replay_shard_bal_bytes_last
                                        .set(shard_bal_bytes as f64);
                                }
                                ssmr_replay_bal_shards += batches.len() as u64;
                                let prepared = prepare_ssmr_bal_replay_batches(
                                    batches,
                                    &mut replay_bal_history,
                                    bal_replay.next_output_index,
                                    worker_limit,
                                    is_osaka,
                                    &mut estimated_rlp_block_size,
                                )?;
                                let tx_count = prepared.tx_count;
                                ssmr_replay_bal_decode_elapsed += prepared.bal_decode_elapsed;
                                bal_replay.enqueue(prepared)?;
                                trace!(
                                    ssmr_replay_batch_transactions = tx_count,
                                    "SSMR BAL replay batch scheduled"
                                );
                            } else {
                                bal_replay.drain_ready_outputs(
                                    true,
                                    &mut executor,
                                    &roots_tx,
                                    &mut cumulative_gas_used,
                                    &mut cumulative_state_gas_used,
                                    &mut non_payment_gas_used,
                                    &mut payment_transactions,
                                    &mut reverted_transactions,
                                    &mut total_fees,
                                    &mut pool_transactions_yielded,
                                    &mut pool_transactions_included,
                                    &mut replay_progress.transactions,
                                    replay_tx_gas_limit_cap,
                                    non_shared_gas_limit,
                                    general_gas_limit,
                                )?;

                                ssmr_replay_decode_elapsed += batch.decode_elapsed;
                                ssmr_replay_recover_elapsed += batch.recover_elapsed;
                                ssmr_replay_decode_recover_elapsed +=
                                    batch.decode_elapsed + batch.recover_elapsed;

                                let shard_bal_bytes = batch
                                    .block_access_list
                                    .as_ref()
                                    .map(|bal| bal.len())
                                    .unwrap_or_default();
                                ssmr_replay_shard_bal_bytes_total += shard_bal_bytes;
                                ssmr_replay_shard_bal_bytes_last = shard_bal_bytes;
                                self.metrics
                                    .ssmr_replay_shard_bal_bytes
                                    .record(shard_bal_bytes as f64);
                                self.metrics
                                    .ssmr_replay_shard_bal_bytes_last
                                    .set(shard_bal_bytes as f64);

                                ssmr_replay_serial_shards += 1;
                                ssmr_replay_missing_bal_shards += 1;
                                for tx in batch.transactions {
                                    let SsmrRecoveredTx {
                                        transaction: recovered,
                                        encoded,
                                        tx_rlp_length,
                                        decode_elapsed: _,
                                        recover_elapsed: _,
                                        queue_wait_elapsed: _,
                                    } = tx;

                                    let max_regular_gas_used = core::cmp::min(
                                        recovered.inner().gas_limit(),
                                        executor.evm().cfg.tx_gas_limit_cap.unwrap_or(u64::MAX),
                                    );
                                    if cumulative_gas_used + max_regular_gas_used
                                        > non_shared_gas_limit
                                    {
                                        return Err(PayloadBuilderError::evm(
                                            BlockExecutionError::Validation(
                                                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                                                    transaction_gas_limit: recovered.inner().gas_limit(),
                                                    block_available_gas: non_shared_gas_limit - cumulative_gas_used,
                                                },
                                            ),
                                        ));
                                    }

                                    let is_payment = if hardfork.is_t5() {
                                        recovered.inner().is_payment_v2()
                                    } else {
                                        recovered.inner().is_payment_v1()
                                    };
                                    if !is_payment
                                        && non_payment_gas_used + max_regular_gas_used
                                            > general_gas_limit
                                    {
                                        return Err(PayloadBuilderError::other(
                                            TempoPoolTransactionError::ExceedsNonPaymentLimit,
                                        ));
                                    }

                                    if is_payment {
                                        payment_transactions += 1;
                                    }

                                    let estimated_block_size_with_tx =
                                        estimated_rlp_block_size + tx_rlp_length;
                                    if is_osaka
                                        && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE
                                    {
                                        return Err(PayloadBuilderError::other(
                                            ConsensusError::BlockTooLarge {
                                                rlp_length: estimated_block_size_with_tx,
                                                max_rlp_length: MAX_RLP_BLOCK_SIZE,
                                            },
                                        ));
                                    }

                                    let execute_start = Instant::now();
                                    executor
                                        .execute_transaction_with_result_closure(
                                            &recovered,
                                            |result| {
                                                cumulative_gas_used += result.block_gas_used();
                                                cumulative_state_gas_used +=
                                                    result.state_gas_used();
                                                if !is_payment {
                                                    non_payment_gas_used +=
                                                        result.block_gas_used();
                                                }
                                                total_fees += result.validator_fee();
                                            },
                                        )
                                        .map_err(PayloadBuilderError::evm)?;
                                    ssmr_replay_execute_elapsed += execute_start.elapsed();
                                    pool_transactions_yielded += 1;
                                    pool_transactions_included += 1;
                                    replay_progress.transactions += 1;
                                    estimated_rlp_block_size += tx_rlp_length;
                                    let receipt = executor.receipts().last().unwrap().clone();
                                    if !receipt.success {
                                        reverted_transactions += 1;
                                    }
                                    let _ = roots_tx.send((
                                        BuilderTx::Owned {
                                            tx: Box::new(recovered),
                                            encoded_2718: Some(encoded),
                                        },
                                        receipt,
                                    ));
                                }
                            }

                            continue;
                        }

                        if replay_progress.replay_finished {
                            bal_replay.close();
                            bal_replay.drain_ready_outputs(
                                true,
                                &mut executor,
                                &roots_tx,
                                &mut cumulative_gas_used,
                                &mut cumulative_state_gas_used,
                                &mut non_payment_gas_used,
                                &mut payment_transactions,
                                &mut reverted_transactions,
                                &mut total_fees,
                                &mut pool_transactions_yielded,
                                &mut pool_transactions_included,
                                &mut replay_progress.transactions,
                                replay_tx_gas_limit_cap,
                                non_shared_gas_limit,
                                general_gas_limit,
                            )?;
                            ssmr_replay_bal_worker_execute_elapsed =
                                bal_replay.worker_execute_elapsed;
                            ssmr_replay_bal_ordered_commit_elapsed =
                                bal_replay.ordered_commit_elapsed;
                            ssmr_replay_execute_elapsed += ssmr_replay_bal_decode_elapsed
                                + ssmr_replay_bal_worker_execute_elapsed
                                + ssmr_replay_bal_ordered_commit_elapsed;
                            break Some(if cumulative_gas_used >= non_shared_gas_limit {
                                BlockBuildStopReason::GasLimit
                            } else {
                                BlockBuildStopReason::TxPoolEmpty
                            });
                        }

                        let wait_elapsed = replay_progress.wait_for_next_event(
                            &recovered_events,
                            ssmr_replay_prewarmer.as_ref(),
                        )?;
                        validation_wait_elapsed += wait_elapsed;
                        ssmr_replay_recovery_wait_elapsed += wait_elapsed;
                    };

                    Ok(stop_reason)
                },
            )?;
            let Some(stop_reason) = stop_reason else {
                return Ok(BuildOutcome::Cancelled);
            };

            ssmr_replay_wait_elapsed = replay_progress.source_wait_elapsed;
            ssmr_replay_recovery_wall_elapsed = replay_progress.recovery_wall_elapsed;
            ssmr_replay_first_tx_recovery_elapsed = replay_progress.first_tx_recovery_elapsed;
            ssmr_replay_recovery_queue_wait_sum_elapsed =
                replay_progress.recovery_queue_wait_sum_elapsed;
            ssmr_replay_recovery_backpressure_elapsed =
                replay_progress.recovery_backpressure_elapsed;
            ssmr_replay_execution_wait_for_recovery_elapsed =
                replay_progress.execution_wait_for_recovery_elapsed;
            ssmr_replay_recovery_worker_count = replay_progress.recovery_worker_count;
            ssmr_replay_max_recovered_tx_ahead = replay_progress.max_recovered_tx_ahead;
            ssmr_replay_shards = replay_progress.shards;
            ssmr_replay_transactions = replay_progress.transactions;

            stop_reason
        } else {
            let base_fee = executor.evm().block().basefee;
            let pool_fetch_start = Instant::now();
            normal_transaction_fill_pool_at_start =
                PoolSizeSnapshot::from_pool_size(self.pool.pool_size());
            let best_txs_attributes = BestTransactionsAttributes::new(
                base_fee,
                executor
                    .evm()
                    .block()
                    .blob_gasprice()
                    .map(|gasprice| gasprice as u64),
            );
            let prewarming_parent_hash = parent_header.hash();
            let prewarming_evm_env = executor.evm().evm_env();
            let make_best_txs = || -> PayloadTransactions {
                let raw_best_txs = best_txs(best_txs_attributes);
                let prewarm_ctx = PrewarmingExecutionContext::new(
                    self.provider.clone(),
                    self.executor.clone(),
                    execution_cache.clone(),
                    prewarming_parent_hash,
                    prewarming_evm_env.clone(),
                    self.config.enable_parallel,
                );
                if self.config.enable_prewarming {
                    if self.config.enable_parallel {
                        PayloadTransactions::Parallel(BestTransactionsPrewarming::new(
                            prewarm_ctx,
                            raw_best_txs,
                        ))
                    } else {
                        PayloadTransactions::Prewarming(StateAwareBestTransactions::new(
                            BestTransactionsPrewarming::new(prewarm_ctx, raw_best_txs),
                        ))
                    }
                } else {
                    PayloadTransactions::Sequential(StateAwareBestTransactions::new(Box::new(
                        raw_best_txs,
                    )))
                }
            };
            let mut best_txs = make_best_txs();
            self.metrics
                .pool_fetch_duration_seconds
                .record(pool_fetch_start.elapsed());

            let stop_reason = loop {
                check_cancel!();

                if let Some(build_budget) = payload_build_budget {
                    let elapsed = start.elapsed();
                    let current_workload = ValidationLatencyWorkload::new(
                        cumulative_gas_used,
                        pool_transactions_included as usize,
                    );
                    let budget_decision = payload_budget_decision(PayloadBudgetInput {
                        elapsed,
                        idle_elapsed: normal_transaction_fill_idle_elapsed,
                        multiplier: build_time_multiplier,
                        marshal_persist,
                        block_size_bytes: estimated_rlp_block_size,
                        validation_latency,
                        post_return_tail_budget,
                        current_workload,
                    });
                    if budget_decision.total_reserved >= build_budget {
                        debug!(
                            target: "payload_builder",
                            ?elapsed,
                            ?normal_transaction_fill_idle_elapsed,
                            normal_transaction_fill_idle_polls,
                            normal_transaction_fill_iterator_refreshes,
                            ?normal_transaction_fill_pool_at_start,
                            ?normal_transaction_fill_pool_at_first_idle,
                            ?normal_transaction_fill_pool_at_last_idle,
                            ?normal_transaction_fill_best_txs_next_elapsed,
                            ?normal_transaction_fill_pool_tx_execution_elapsed,
                            ?normal_transaction_fill_ssmr_pack_elapsed,
                            ?normal_transaction_fill_roots_send_elapsed,
                            state_aware_balance_skips = best_txs.balance_skips(),
                            state_aware_tracked_invalid_skips = best_txs.tracked_invalid_skips(),
                            ?build_budget,
                            predicted_builder_work = ?budget_decision.predicted_builder_work,
                            predicted_validator_work = ?budget_decision.predicted_validator_work,
                            ?post_return_tail_budget,
                            total_reserved = ?budget_decision.total_reserved,
                            marshal_persist = ?budget_decision.marshal_persist,
                            ?current_workload,
                            gas_used = cumulative_gas_used,
                            transactions = pool_transactions_included,
                            estimated_rlp_block_size,
                            build_time_multiplier = build_time_multiplier as f64
                                / BUILD_TIME_MULTIPLIER_SCALE as f64,
                            "stopping pool transaction execution before payload build budget is exhausted"
                        );
                        break BlockBuildStopReason::BuildBudget;
                    }
                }

                let next_tx_start = Instant::now();
                let next_pool_tx = best_txs.next();
                normal_transaction_fill_best_txs_next_elapsed += next_tx_start.elapsed();
                let Some(mut pool_tx) = next_pool_tx else {
                    if build_once_with_shared_trie
                        && payload_build_budget.is_some()
                        && cumulative_gas_used < non_shared_gas_limit
                    {
                        let pool_snapshot = PoolSizeSnapshot::from_pool_size(self.pool.pool_size());
                        if normal_transaction_fill_idle_polls == 0 {
                            normal_transaction_fill_pool_at_first_idle = pool_snapshot;
                        }
                        normal_transaction_fill_pool_at_last_idle = pool_snapshot;
                        let should_refresh_iterator = pool_snapshot.pending > 0
                            && match normal_transaction_fill_last_iterator_refresh_poll {
                                Some(last_refresh_poll) => {
                                    normal_transaction_fill_idle_polls
                                        .saturating_sub(last_refresh_poll)
                                        >= 16
                                }
                                None => true,
                            };
                        if should_refresh_iterator {
                            best_txs.replace_with(make_best_txs());
                            normal_transaction_fill_iterator_refreshes += 1;
                            normal_transaction_fill_last_iterator_refresh_poll =
                                Some(normal_transaction_fill_idle_polls);
                            continue;
                        }
                        normal_transaction_fill_idle_polls += 1;
                        std::thread::sleep(Duration::from_millis(1));
                        normal_transaction_fill_idle_elapsed += Duration::from_millis(1);
                        validation_wait_elapsed += Duration::from_millis(1);
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
                normal_transaction_fill_last_iterator_refresh_poll = None;
                let tx = pool_tx.tx.clone();
                pool_transactions_yielded += 1;

                let max_regular_gas_used = core::cmp::min(
                    tx.gas_limit(),
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
                            tx.gas_limit(),
                            non_shared_gas_limit - cumulative_gas_used,
                        ),
                    );
                    self.metrics
                        .inc_pool_tx_skipped("exceeds_non_shared_gas_limit");
                    continue;
                }

                let is_payment = if hardfork.is_t5() {
                    tx.transaction.is_payment()
                } else {
                    tx.transaction.inner().is_payment_v1()
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

                let tx_rlp_length = tx.transaction.encoded_length();
                let estimated_block_size_with_tx = estimated_rlp_block_size + tx_rlp_length;

                if is_osaka && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE {
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
                    .then(|| format!("{:?}", tx.transaction))
                    .unwrap_or_default();

                let result_closure = |result: &TempoTxResult| {
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
                };

                let tx_execution_start = Instant::now();
                let execution_result = if let Some(replay) = pool_tx.replay.take() {
                    parallel_transactions_executed += 1;
                    executor.execute_transaction_with_actions(
                        tx.transaction.executable(),
                        *replay,
                        result_closure,
                        bal_task_handle.is_some(),
                    )
                } else {
                    action_replay_state.invalidate_expiring_nonce_cache();
                    executor
                        .execute_transaction_with_result_closure(
                            tx.transaction.executable(),
                            result_closure,
                        )
                        .map(|_| ())
                };
                normal_transaction_fill_pool_tx_execution_elapsed += tx_execution_start.elapsed();

                if let Err(err) = execution_result {
                    match err {
                        BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                            error,
                            ..
                        }) => {
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
                        }
                        BlockExecutionError::Internal(err) => {
                            if let Some(err) =
                                StorageActionReplayError::from_internal_block_execution_error(&err)
                            {
                                invalid_pool_transaction_execution_attempts += 1;
                                best_txs.mark_invalid(
                                    &pool_tx,
                                    InvalidPoolTransactionError::Consensus(
                                        InvalidTransactionError::TxTypeNotSupported,
                                    ),
                                );
                                self.metrics.inc_pool_tx_skipped("invalid_replay");
                                trace!(
                                    target: "payload_builder",
                                    tx_hash = ?tx.hash(),
                                    ?err,
                                    "Skipping invalid replay transaction"
                                );
                                continue;
                            } else {
                                return Err(PayloadBuilderError::evm(err));
                            }
                        }
                        _ => return Err(PayloadBuilderError::evm(err)),
                    }
                }

                trace!("Transaction executed");

                pool_transactions_included += 1;
                estimated_rlp_block_size += tx_rlp_length;
                let receipt = executor.receipts().last().unwrap().clone();
                if !receipt.success {
                    reverted_transactions += 1;
                }
                let ssmr_pack_start = Instant::now();
                let encoded_2718 = maybe_push_ssmr_transaction(
                    &mut ssmr_packer,
                    bal_task_handle.as_ref(),
                    &tx.transaction,
                    tx.gas_limit(),
                );
                normal_transaction_fill_ssmr_pack_elapsed += ssmr_pack_start.elapsed();
                let roots_send_start = Instant::now();
                let _ = roots_tx.send((BuilderTx::Pooled { tx, encoded_2718 }, receipt));
                normal_transaction_fill_roots_send_elapsed += roots_send_start.elapsed();
            };

            normal_transaction_fill_state_aware_balance_skips = best_txs.balance_skips();
            normal_transaction_fill_state_aware_tracked_invalid_skips =
                best_txs.tracked_invalid_skips();
            // cancel pre-warming, if any, by dropping the iter
            drop(best_txs);
            stop_reason
        };
        let ssmr_replay_compute_elapsed = ssmr_replay_pool_lookup_elapsed
            + ssmr_replay_decode_recover_elapsed
            + ssmr_replay_execute_elapsed;

        let elapsed_at_tx_cutoff = start.elapsed();
        let validation_work_at_tx_cutoff =
            elapsed_at_tx_cutoff.saturating_sub(validation_wait_elapsed);
        drop(_block_fill_span);
        self.metrics
            .inc_block_build_stop_reason(block_build_stop_reason);
        let normal_transaction_fill_elapsed = execution_start.elapsed();
        if !is_ssmr_replay {
            self.metrics
                .total_normal_transaction_fill_duration_seconds
                .record(normal_transaction_fill_elapsed);
            self.metrics
                .normal_transaction_fill_best_txs_next_duration_seconds
                .record(normal_transaction_fill_best_txs_next_elapsed);
            self.metrics
                .normal_transaction_fill_pool_tx_execution_duration_seconds
                .record(normal_transaction_fill_pool_tx_execution_elapsed);
            self.metrics
                .normal_transaction_fill_ssmr_pack_duration_seconds
                .record(normal_transaction_fill_ssmr_pack_elapsed);
            self.metrics
                .normal_transaction_fill_roots_send_duration_seconds
                .record(normal_transaction_fill_roots_send_elapsed);
            self.metrics
                .normal_transaction_fill_idle_duration_seconds
                .record(normal_transaction_fill_idle_elapsed);
            self.metrics
                .normal_transaction_fill_idle_polls
                .record(normal_transaction_fill_idle_polls as f64);
            self.metrics
                .normal_transaction_fill_idle_polls_last
                .set(normal_transaction_fill_idle_polls as f64);
            self.metrics
                .normal_transaction_fill_state_aware_balance_skips
                .record(normal_transaction_fill_state_aware_balance_skips as f64);
            self.metrics
                .normal_transaction_fill_state_aware_balance_skips_last
                .set(normal_transaction_fill_state_aware_balance_skips as f64);
            self.metrics
                .normal_transaction_fill_state_aware_tracked_invalid_skips
                .record(normal_transaction_fill_state_aware_tracked_invalid_skips as f64);
            self.metrics
                .normal_transaction_fill_state_aware_tracked_invalid_skips_last
                .set(normal_transaction_fill_state_aware_tracked_invalid_skips as f64);
            self.metrics
                .normal_transaction_fill_pool_pending_at_start_last
                .set(normal_transaction_fill_pool_at_start.pending as f64);
            self.metrics
                .normal_transaction_fill_pool_queued_at_start_last
                .set(normal_transaction_fill_pool_at_start.queued as f64);
            self.metrics
                .normal_transaction_fill_pool_total_at_start_last
                .set(normal_transaction_fill_pool_at_start.total as f64);
            self.metrics
                .normal_transaction_fill_pool_pending_at_first_idle_last
                .set(normal_transaction_fill_pool_at_first_idle.pending as f64);
            self.metrics
                .normal_transaction_fill_pool_queued_at_first_idle_last
                .set(normal_transaction_fill_pool_at_first_idle.queued as f64);
            self.metrics
                .normal_transaction_fill_pool_total_at_first_idle_last
                .set(normal_transaction_fill_pool_at_first_idle.total as f64);
            self.metrics
                .normal_transaction_fill_pool_pending_at_last_idle_last
                .set(normal_transaction_fill_pool_at_last_idle.pending as f64);
            self.metrics
                .normal_transaction_fill_pool_queued_at_last_idle_last
                .set(normal_transaction_fill_pool_at_last_idle.queued as f64);
            self.metrics
                .normal_transaction_fill_pool_total_at_last_idle_last
                .set(normal_transaction_fill_pool_at_last_idle.total as f64);
        }
        self.metrics
            .payment_transactions
            .record(payment_transactions as f64);
        self.metrics
            .payment_transactions_last
            .set(payment_transactions as f64);

        check_cancel!();

        // check if we have a better block or received more subblocks
        if !is_ssmr_replay
            && !is_better_payload(best_payload.as_ref(), total_fees)
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

                subblock_tx_count += 1.0;
                let receipt = executor.receipts().last().unwrap().clone();
                if !receipt.success {
                    reverted_transactions += 1;
                }
                let encoded_2718 = maybe_push_ssmr_transaction(
                    &mut ssmr_packer,
                    bal_task_handle.as_ref(),
                    tx.inner(),
                    tx.inner().gas_limit(),
                );
                let _ = roots_tx.send((
                    BuilderTx::Owned {
                        tx: Box::new(tx),
                        encoded_2718,
                    },
                    receipt,
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

            let encoded_2718 = maybe_push_ssmr_transaction(
                &mut ssmr_packer,
                bal_task_handle.as_ref(),
                system_tx.inner(),
                system_tx.inner().gas_limit(),
            );
            let _ = roots_tx.send((
                BuilderTx::Owned {
                    tx: Box::new(system_tx),
                    encoded_2718,
                },
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

        if let Some(packer) = ssmr_packer.take() {
            packer.finish(bal_task_handle.as_ref());
        }

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

        // Drop the state hook to signal that execution is complete and the sparse trie task can
        // finalize the state root.
        db.set_state_hook(None);

        // Drop the BAL task sender to trigger finalization.
        let bal_rx = bal_task_handle.map(|handle| handle.into_bal_rx());

        let hashed_state = if let Some(Ok(hashed_state)) = trie_handle
            .as_mut()
            .map(|handle| handle.take_hashed_state_rx().recv())
        {
            hashed_state
        } else {
            finish_provider.hashed_post_state(&db.bundle_state)
        };

        let (state_root_outcome, sparse_trie_state_root_wait_elapsed) =
            if self.config.skip_state_root {
                debug!(
                    target: "payload_builder",
                    id = %payload_id,
                    state_root = ?parent_header.state_root(),
                    "skipping payload state-root computation"
                );
                None
            } else if let Some(mut handle) = trie_handle {
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

        let (block_access_list, block_access_list_hash) = if let Some(bal_rx) = bal_rx {
            let (bal, bal_hash) = bal_rx.blocking_recv().map_err(PayloadBuilderError::other)?;
            (Some(bal), Some(bal_hash))
        } else {
            (None, None)
        };

        let (state_root, trie_updates) = if self.config.skip_state_root {
            (parent_header.state_root(), Arc::new(Default::default()))
        } else if let Some(outcome) = state_root_outcome {
            (outcome.state_root, outcome.trie_updates)
        } else {
            let (state_root, trie_updates) = finish_provider
                .state_root_with_updates(hashed_state.clone())
                .map_err(BlockExecutionError::other)?;

            (state_root, Arc::new(trie_updates))
        };

        let RootsTaskResult {
            transactions_root,
            receipts_root,
            receipts_bloom,
            transactions,
            senders,
            encoded_block_transactions,
        } = roots_rx
            .blocking_recv()
            .map_err(PayloadBuilderError::other)?;

        let block = self.evm_config.block_assembler.assemble_block(
            BlockAssemblerInput::new(
                evm_env,
                ctx,
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
        self.metrics
            .reverted_transactions
            .record(reverted_transactions as f64);
        self.metrics
            .reverted_transactions_last
            .set(reverted_transactions as f64);

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
            .parallel_transactions_executed
            .record(parallel_transactions_executed as f64);
        self.metrics
            .parallel_transactions_executed_last
            .set(parallel_transactions_executed as f64);
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
        let validation_work_duration = elapsed.saturating_sub(validation_wait_elapsed);
        if payload_build_budget.is_some() && !static_ssmr_build_budget {
            self.update_build_time_multiplier(
                validation_work_duration,
                validation_work_at_tx_cutoff,
            );
        }
        if is_osaka && estimated_rlp_block_size > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: estimated_rlp_block_size,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }
        let recorded_block_size_bytes =
            estimated_rlp_block_size + block_access_list.as_ref().map_or(0, Encodable::length);
        let final_workload = ValidationLatencyWorkload::new(gas_used, total_transactions);
        let validation_latency_duration = validation_latency
            .and_then(|estimate| estimate.estimate(final_workload))
            .unwrap_or(validation_work_duration);

        self.metrics.payload_build_duration_seconds.record(elapsed);
        let gas_per_second = block.gas_used() as f64 / elapsed.as_secs_f64();
        self.metrics.gas_per_second.record(gas_per_second);
        self.metrics.gas_per_second_last.set(gas_per_second);
        self.metrics
            .rlp_block_size_bytes
            .record(recorded_block_size_bytes as f64);
        self.metrics
            .rlp_block_size_bytes_last
            .set(recorded_block_size_bytes as f64);
        if is_ssmr_replay {
            self.metrics
                .ssmr_replay_bal_decode_duration_seconds
                .record(ssmr_replay_bal_decode_elapsed);
            self.metrics
                .ssmr_replay_bal_worker_execute_duration_seconds
                .record(ssmr_replay_bal_worker_execute_elapsed);
            self.metrics
                .ssmr_replay_bal_ordered_commit_duration_seconds
                .record(ssmr_replay_bal_ordered_commit_elapsed);
            self.metrics
                .ssmr_replay_bal_shards
                .record(ssmr_replay_bal_shards as f64);
            self.metrics
                .ssmr_replay_serial_shards
                .record(ssmr_replay_serial_shards as f64);
            self.metrics
                .ssmr_replay_missing_bal_shards
                .record(ssmr_replay_missing_bal_shards as f64);
        }

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
            parallel_transactions_executed,
            invalid_pool_transaction_execution_attempts,
            pool_transactions_inclusion_ratio,
            subblock_transactions,
            total_transactions,
            ?elapsed,
            ?validation_work_duration,
            ?validation_latency_duration,
            ?normal_transaction_fill_elapsed,
            ?normal_transaction_fill_idle_elapsed,
            normal_transaction_fill_idle_polls,
            normal_transaction_fill_iterator_refreshes,
            ?normal_transaction_fill_pool_at_start,
            ?normal_transaction_fill_pool_at_first_idle,
            ?normal_transaction_fill_pool_at_last_idle,
            ?normal_transaction_fill_best_txs_next_elapsed,
            ?normal_transaction_fill_pool_tx_execution_elapsed,
            ?normal_transaction_fill_ssmr_pack_elapsed,
            ?normal_transaction_fill_roots_send_elapsed,
            normal_transaction_fill_state_aware_balance_skips,
            normal_transaction_fill_state_aware_tracked_invalid_skips,
            ?validation_wait_elapsed,
            ssmr_replay_enabled = is_ssmr_replay,
            ?ssmr_replay_wait_elapsed,
            ?ssmr_replay_pool_lookup_elapsed,
            ssmr_replay_pool_hits,
            ssmr_replay_pool_misses,
            ?ssmr_replay_recovery_wait_elapsed,
            ?ssmr_replay_recovery_wall_elapsed,
            ?ssmr_replay_first_tx_recovery_elapsed,
            ?ssmr_replay_recovery_queue_wait_sum_elapsed,
            ?ssmr_replay_recovery_backpressure_elapsed,
            ?ssmr_replay_execution_wait_for_recovery_elapsed,
            ssmr_replay_recovery_worker_count,
            ssmr_replay_max_recovered_tx_ahead,
            ?ssmr_replay_compute_elapsed,
            ?ssmr_replay_decode_recover_elapsed,
            ?ssmr_replay_decode_elapsed,
            ?ssmr_replay_recover_elapsed,
            ?ssmr_replay_execute_elapsed,
            ?ssmr_replay_bal_decode_elapsed,
            ?ssmr_replay_bal_worker_execute_elapsed,
            ?ssmr_replay_bal_ordered_commit_elapsed,
            ssmr_replay_shards,
            ssmr_replay_transactions,
            ssmr_replay_bal_shards,
            ssmr_replay_serial_shards,
            ssmr_replay_missing_bal_shards,
            ssmr_replay_shard_bal_bytes_total,
            ssmr_replay_shard_bal_bytes_last,
            ?total_subblock_transaction_execution_elapsed,
            ?system_txs_execution_elapsed,
            ?total_transaction_execution_elapsed,
            ?sparse_trie_state_root_wait_elapsed,
            ?builder_finish_elapsed,
            "Built payload"
        );

        let block = Arc::new(block);
        let execution_block_encoder = ExecutionBlockEncoder::new(
            block.clone(),
            estimated_rlp_block_size,
            encoded_block_transactions,
        );
        // Clone the shared cache handle into the payload before the encoder is dropped.
        let execution_block_encoded = execution_block_encoder.encoded_block();
        // Drop the encoder off-thread so its `Drop` impl can populate the cache in the background.
        self.executor.spawn_drop(execution_block_encoder);
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
            validation_latency_duration,
            estimated_rlp_block_size,
            execution_block_encoded,
        );

        drop(db);
        self.executor.spawn_drop(state_provider);
        Ok(BuildOutcome::Freeze(payload))
    }

    fn spawn_roots_task(
        &self,
    ) -> (
        Sender<(BuilderTx, TempoReceipt)>,
        oneshot::Receiver<RootsTaskResult>,
    ) {
        let (transactions_tx, transactions_rx) =
            crossbeam_channel::unbounded::<(BuilderTx, TempoReceipt)>();
        let (result_tx, result_rx) = oneshot::channel();

        self.executor
            .spawn_blocking_named("builder-roots-task", move || {
                let mut transactions = Vec::new();
                let mut senders = Vec::new();

                let mut transactions_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_bloom = Bloom::ZERO;
                let mut encoded_block_transactions = EncodedBlockTransactionsBuilder::default();
                let mut buf = Vec::new();

                for (tx, receipt) in transactions_rx.into_iter() {
                    let (tx, sender, encoded_2718) = tx.into_parts();
                    buf.clear();
                    let encoded_tx = if let Some(encoded_2718) = encoded_2718.as_ref() {
                        encoded_2718.as_ref()
                    } else {
                        tx.encode_2718(&mut buf);
                        buf.as_slice()
                    };
                    transactions_root.push_next(encoded_tx);
                    encoded_block_transactions.push(&tx, encoded_tx);
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
                let _ = result_tx.send(RootsTaskResult {
                    transactions_root,
                    receipts_root,
                    receipts_bloom,
                    transactions,
                    senders,
                    encoded_block_transactions: encoded_block_transactions.finish(),
                });
            });

        (transactions_tx, result_rx)
    }

    fn spawn_bal_task(&self, mut state_root_task_hook: Option<impl OnStateHook>) -> BalTaskHandle {
        let (task_tx, task_rx) = mpsc::channel::<BalMessage>();
        let (bal_tx, bal_rx) = oneshot::channel();
        self.executor.spawn_blocking_named("builder-bal-task", || {
            let mut bal_state = BuilderBalState::new();
            for msg in task_rx {
                match msg {
                    BalMessage::BumpIndex => {
                        bal_state.bump_index();
                    }
                    BalMessage::Snapshot {
                        first_tx_index,
                        next_tx_index,
                        reply_tx,
                    } => {
                        let snapshot = bal_state.snapshot(first_tx_index, next_tx_index);
                        let _ = reply_tx.send(snapshot);
                    }
                    BalMessage::State(state) => {
                        bal_state.commit(&state);
                        if let Some(state_root_task_hook) = &mut state_root_task_hook {
                            state_root_task_hook.on_state(state);
                        }
                    }
                    BalMessage::TransactionState(state) => {
                        bal_state.commit(&state);
                        if let Some(state_root_task_hook) = &mut state_root_task_hook {
                            state_root_task_hook.on_state(state);
                        }
                        bal_state.bump_index();
                    }
                }
            }

            drop(state_root_task_hook);
            let _ = bal_tx.send(bal_state.finish());
        });

        BalTaskHandle {
            msg_tx: task_tx,
            bal_rx,
        }
    }
}

struct BalTaskHandle {
    msg_tx: mpsc::Sender<BalMessage>,
    bal_rx: oneshot::Receiver<(Bytes, B256)>,
}

impl BalTaskHandle {
    fn state_hook(&self) -> impl OnStateHook {
        let msg_tx = self.msg_tx.clone();
        move |state: EvmState| {
            let _ = msg_tx.send(BalMessage::State(state));
        }
    }

    fn transaction_state_hook(&self) -> impl OnStateHook {
        let msg_tx = self.msg_tx.clone();
        move |state: EvmState| {
            let _ = msg_tx.send(BalMessage::TransactionState(state));
        }
    }

    fn bump_bal_index(&self) {
        let _ = self.msg_tx.send(BalMessage::BumpIndex);
    }

    fn request_snapshot_block_access_list(
        &self,
        first_tx_index: u64,
        next_tx_index: u64,
    ) -> Option<mpsc::Receiver<Option<Bytes>>> {
        let (reply_tx, reply_rx) = mpsc::channel();
        self.msg_tx
            .send(BalMessage::Snapshot {
                first_tx_index,
                next_tx_index,
                reply_tx,
            })
            .ok()?;
        Some(reply_rx)
    }

    fn into_bal_rx(self) -> oneshot::Receiver<(Bytes, B256)> {
        self.bal_rx
    }
}

enum BalMessage {
    State(EvmState),
    TransactionState(EvmState),
    BumpIndex,
    Snapshot {
        first_tx_index: u64,
        next_tx_index: u64,
        reply_tx: mpsc::Sender<Option<Bytes>>,
    },
}

struct BuilderBalState {
    full_bal: RevmBal,
    shard_filter: ShardBalFilter,
    full_index: BlockAccessIndex,
}

impl BuilderBalState {
    fn new() -> Self {
        Self {
            full_bal: RevmBal::new(),
            shard_filter: ShardBalFilter::default(),
            full_index: BlockAccessIndex::PRE_EXECUTION,
        }
    }

    fn bump_index(&mut self) {
        self.full_index.increment();
    }

    fn commit(&mut self, state: &EvmState) {
        for (address, account) in state {
            self.full_bal
                .update_account(self.full_index, *address, account);
            self.shard_filter
                .record_account(*address, account.storage.keys().copied());
        }
    }

    fn snapshot(&mut self, first_tx_index: u64, next_tx_index: u64) -> Option<Bytes> {
        let snapshot = encode_bal_range_snapshot(
            &self.full_bal,
            &self.shard_filter,
            first_tx_index,
            next_tx_index,
        );
        self.shard_filter.clear();
        snapshot
    }

    fn finish(self) -> (Bytes, B256) {
        let bal: Bal = self.full_bal.into_alloy_bal().into();
        let mut encoded = Vec::new();
        bal.encode(&mut encoded);
        let bal_hash = keccak256(&encoded);
        (encoded.into(), bal_hash)
    }
}

#[derive(Debug, Default)]
struct ShardBalFilter {
    accounts: BTreeMap<Address, BTreeSet<U256>>,
}

impl ShardBalFilter {
    fn record_account(&mut self, address: Address, keys: impl IntoIterator<Item = U256>) {
        let storage_keys = self.accounts.entry(address).or_default();
        storage_keys.extend(keys);
    }

    fn clear(&mut self) {
        self.accounts.clear();
    }
}

fn encode_bal_range_snapshot(
    full_bal: &RevmBal,
    shard_filter: &ShardBalFilter,
    first_tx_index: u64,
    next_tx_index: u64,
) -> Option<Bytes> {
    let bal: Bal = slice_bal_range(full_bal, shard_filter, first_tx_index, next_tx_index)
        .into_alloy_bal()
        .into();
    let mut encoded = Vec::new();
    bal.encode(&mut encoded);
    Some(encoded.into())
}

fn slice_bal_range(
    full_bal: &RevmBal,
    shard_filter: &ShardBalFilter,
    first_tx_index: u64,
    next_tx_index: u64,
) -> RevmBal {
    RevmBal::from_iter(
        shard_filter
            .accounts
            .iter()
            .map(|(address, filter_account)| {
                let sliced = full_bal
                    .accounts
                    .get(address)
                    .map(|full_account| {
                        slice_account_bal_range(
                            full_account,
                            filter_account,
                            first_tx_index,
                            next_tx_index,
                        )
                    })
                    .unwrap_or_default();
                (*address, sliced)
            }),
    )
}

fn slice_account_bal_range(
    full_account: &AccountBal,
    storage_keys: &BTreeSet<U256>,
    first_tx_index: u64,
    next_tx_index: u64,
) -> AccountBal {
    AccountBal {
        account_info: AccountInfoBal {
            nonce: slice_bal_writes_range(
                &full_account.account_info.nonce,
                first_tx_index,
                next_tx_index,
            ),
            balance: slice_bal_writes_range(
                &full_account.account_info.balance,
                first_tx_index,
                next_tx_index,
            ),
            code: slice_bal_writes_range(
                &full_account.account_info.code,
                first_tx_index,
                next_tx_index,
            ),
        },
        storage: StorageBal::from_iter(storage_keys.iter().map(|key| {
            let writes = full_account
                .storage
                .storage
                .get(key)
                .map(|writes| slice_bal_writes_range(writes, first_tx_index, next_tx_index))
                .unwrap_or_default();
            (*key, writes)
        })),
    }
}

fn slice_bal_writes_range<T>(
    writes: &BalWrites<T>,
    first_tx_index: u64,
    next_tx_index: u64,
) -> BalWrites<T>
where
    T: PartialEq + Clone,
{
    let mut sliced = Vec::new();
    for (index, value) in &writes.writes {
        let raw_index = index.get();
        if raw_index > first_tx_index && raw_index <= next_tx_index {
            sliced.push((
                BlockAccessIndex::new(raw_index - first_tx_index),
                value.clone(),
            ));
        }
    }

    BalWrites::new(sliced)
}

fn maybe_push_ssmr_transaction<T>(
    ssmr_packer: &mut Option<SsmrShardPacker>,
    bal_task_handle: Option<&BalTaskHandle>,
    tx: &T,
    gas_estimate: u64,
) -> Option<Bytes>
where
    T: Encodable2718,
{
    let packer = ssmr_packer.as_mut()?;

    let mut encoded = Vec::with_capacity(tx.encode_2718_len());
    tx.encode_2718(&mut encoded);
    let encoded = Bytes::from(encoded);
    if packer.push(encoded.clone(), gas_estimate) {
        packer.queue_flush(bal_task_handle);
    }
    packer.drain_ready();
    Some(encoded)
}

struct SsmrShardPacker {
    sink: SsmrBuilderSink,
    metrics: TempoPayloadBuilderMetrics,
    target_bytes: usize,
    shard_index: u64,
    first_tx_index: u64,
    next_tx_index: u64,
    cumulative_tx_bytes: u64,
    cumulative_gas_estimate: u64,
    pending_bytes: usize,
    pending_transactions: Vec<Bytes>,
    pending_shards: VecDeque<PendingSsmrShard>,
}

struct PendingSsmrShard {
    shard: SsmrBuilderShard,
    block_access_list_rx: Option<mpsc::Receiver<Option<Bytes>>>,
}

impl SsmrShardPacker {
    fn new(
        sink: SsmrBuilderSink,
        target_bytes: usize,
        metrics: TempoPayloadBuilderMetrics,
    ) -> Self {
        Self {
            sink,
            metrics,
            target_bytes: if target_bytes == 0 {
                DEFAULT_SSMR_SHARD_TARGET_BYTES
            } else {
                target_bytes
            },
            shard_index: 0,
            first_tx_index: 0,
            next_tx_index: 0,
            cumulative_tx_bytes: 0,
            cumulative_gas_estimate: 0,
            pending_bytes: 0,
            pending_transactions: Vec::new(),
            pending_shards: VecDeque::new(),
        }
    }

    fn push(&mut self, tx: Bytes, gas_estimate: u64) -> bool {
        self.pending_bytes += tx.as_ref().len();
        self.cumulative_tx_bytes += tx.as_ref().len() as u64;
        self.cumulative_gas_estimate = self.cumulative_gas_estimate.saturating_add(gas_estimate);
        self.pending_transactions.push(tx);
        self.next_tx_index += 1;

        self.pending_bytes >= self.current_target_bytes()
    }

    fn current_target_bytes(&self) -> usize {
        if self.shard_index == 0 {
            self.target_bytes.min(DEFAULT_SSMR_FIRST_SHARD_TARGET_BYTES)
        } else {
            self.target_bytes
        }
    }

    fn finish(mut self, bal_task_handle: Option<&BalTaskHandle>) {
        self.queue_flush(bal_task_handle);
        self.emit_all_pending();
        if self.shard_index == 0 {
            self.emit_shard(SsmrBuilderShard {
                shard_index: 0,
                first_tx_index: 0,
                transactions: Vec::new(),
                block_access_list: None,
                cumulative_tx_bytes: 0,
                cumulative_gas_estimate: 0,
            });
            self.shard_index = 1;
        }
        debug!(
            ssmr_builder_total_shards = self.shard_index,
            ssmr_builder_total_transactions = self.next_tx_index,
            "emitted SSMR builder end"
        );
        (self.sink)(SsmrBuilderEvent::End {
            total_shards: self.shard_index,
            total_transactions: self.next_tx_index,
        });
    }

    fn queue_flush(&mut self, bal_task_handle: Option<&BalTaskHandle>) {
        if self.pending_transactions.is_empty() {
            return;
        }

        let block_access_list_rx = bal_task_handle.and_then(|handle| {
            handle.request_snapshot_block_access_list(self.first_tx_index, self.next_tx_index)
        });
        let shard = SsmrBuilderShard {
            shard_index: self.shard_index,
            first_tx_index: self.first_tx_index,
            transactions: std::mem::take(&mut self.pending_transactions),
            block_access_list: None,
            cumulative_tx_bytes: self.cumulative_tx_bytes,
            cumulative_gas_estimate: self.cumulative_gas_estimate,
        };
        self.pending_shards.push_back(PendingSsmrShard {
            shard,
            block_access_list_rx,
        });

        self.shard_index += 1;
        self.first_tx_index = self.next_tx_index;
        self.pending_bytes = 0;
    }

    fn drain_ready(&mut self) {
        loop {
            let block_access_list = match self.pending_shards.front_mut() {
                Some(pending) => match pending.block_access_list_rx.as_mut() {
                    Some(rx) => match rx.try_recv() {
                        Ok(block_access_list) => block_access_list,
                        Err(mpsc::TryRecvError::Empty) => return,
                        Err(mpsc::TryRecvError::Disconnected) => None,
                    },
                    None => None,
                },
                None => return,
            };

            let Some(mut pending) = self.pending_shards.pop_front() else {
                return;
            };
            pending.shard.block_access_list = block_access_list;
            self.emit_shard(pending.shard);
        }
    }

    fn emit_all_pending(&mut self) {
        while let Some(mut pending) = self.pending_shards.pop_front() {
            let block_access_list = pending
                .block_access_list_rx
                .take()
                .and_then(|rx| rx.recv().ok().flatten());
            pending.shard.block_access_list = block_access_list;
            self.emit_shard(pending.shard);
        }
    }

    fn emit_shard(&self, shard: SsmrBuilderShard) {
        let bal_bytes = shard
            .block_access_list
            .as_ref()
            .map(|bal| bal.len())
            .unwrap_or_default();
        self.metrics
            .ssmr_builder_shard_bal_bytes
            .record(bal_bytes as f64);
        self.metrics
            .ssmr_builder_shard_bal_bytes_last
            .set(bal_bytes as f64);
        debug!(
            ssmr_builder_shard_index = shard.shard_index,
            ssmr_builder_first_tx_index = shard.first_tx_index,
            ssmr_builder_shard_transactions = shard.transactions.len(),
            ssmr_builder_shard_bal_bytes = bal_bytes,
            ssmr_builder_cumulative_tx_bytes = shard.cumulative_tx_bytes,
            ssmr_builder_cumulative_gas_estimate = shard.cumulative_gas_estimate,
            "emitted SSMR builder shard"
        );
        (self.sink)(SsmrBuilderEvent::Shard(shard));
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
        StorageActions::disabled(),
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
    Pooled {
        tx: Arc<ValidPoolTransaction<TempoPooledTransaction>>,
        encoded_2718: Option<Bytes>,
    },
    Owned {
        tx: Box<Recovered<TempoTxEnvelope>>,
        encoded_2718: Option<Bytes>,
    },
}

impl BuilderTx {
    fn into_parts(self) -> (TempoTxEnvelope, Address, Option<Bytes>) {
        match self {
            Self::Pooled { tx, encoded_2718 } => {
                let (tx, sender) = tx.transaction.inner().clone().into_parts();
                (tx, sender, encoded_2718)
            }
            Self::Owned { tx, encoded_2718 } => {
                let (tx, sender) = tx.into_parts();
                (tx, sender, encoded_2718)
            }
        }
    }
}

/// Result produced by the roots task while finalizing payload block data.
#[derive(Debug)]
pub(crate) struct RootsTaskResult {
    /// The root hash of the transaction trie.
    transactions_root: B256,
    /// The root hash of the receipts trie.
    receipts_root: B256,
    /// The receipts bloom filter.
    receipts_bloom: Bloom,
    /// The transactions included in the block.
    transactions: Vec<TempoTxEnvelope>,
    /// The senders of the transactions.
    senders: Vec<Address>,
    /// The RLP encoded transaction list for the block body.
    ///
    /// Since roots task already encodes every transaction for the transaction trie,
    /// we can reuse those bytes for the [`ExecutionBlockEncoder`].
    encoded_block_transactions: EncodedBlockTransactionList,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_primitives::{Address, B256, Bytes};
    use core::num::NonZeroU64;
    use reth_primitives_traits::Block as _;
    use reth_revm::state::{Account, EvmStorageSlot, TransactionId};
    use std::sync::Mutex;
    use tempo_payload_types::EncodedBlock;
    use tempo_primitives::{
        AASigned, Block, SignedSubBlock, SubBlock, SubBlockVersion, TempoSignature,
        TempoTransaction,
    };

    fn nz(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test valid_before must be non-zero")
    }

    fn ssmr_test_recovered_transaction(
        shard_index: u64,
        tx_index: usize,
    ) -> SsmrRecoveredTransaction {
        let tx = TempoTxEnvelope::Legacy(Signed::new_unhashed(
            TxLegacy {
                chain_id: None,
                nonce: tx_index as u64,
                gas_price: 0,
                gas_limit: 0,
                to: Address::ZERO.into(),
                value: U256::ZERO,
                input: Bytes::new(),
            },
            TEMPO_SYSTEM_TX_SIGNATURE,
        ));
        SsmrRecoveredTransaction {
            shard_index,
            tx_index,
            tx: SsmrRecoveredTx {
                transaction: Recovered::new_unchecked(tx, TEMPO_SYSTEM_TX_SENDER),
                encoded: Bytes::from(vec![0; tx_index + 10]),
                tx_rlp_length: tx_index + 10,
                decode_elapsed: Duration::ZERO,
                recover_elapsed: Duration::ZERO,
                queue_wait_elapsed: Duration::ZERO,
            },
        }
    }

    fn ssmr_test_recovered_batch(
        tx_count: usize,
        block_access_list: Option<Bytes>,
    ) -> SsmrRecoveredBatch {
        SsmrRecoveredBatch {
            transactions: (0..tx_count)
                .map(|tx_index| ssmr_test_recovered_transaction(0, tx_index).tx)
                .collect(),
            block_access_list,
            decode_elapsed: Duration::ZERO,
            recover_elapsed: Duration::ZERO,
            queue_wait_elapsed: Duration::ZERO,
            completed_shards: 1,
        }
    }

    #[test]
    fn ssmr_replay_recovery_waits_for_complete_shard_before_drain() {
        let mut state = SsmrReplayRecoveryState::default();
        state.pending_shards.insert(
            0,
            SsmrPendingRecoveredShard::new(3, Some(Bytes::from_static(b"bal"))),
        );

        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(0, 0))
            .unwrap();
        assert!(state.drain_ready_batch(None).unwrap().is_none());
        assert!(state.pending_shards[&0].transactions[0].is_some());

        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(0, 2))
            .unwrap();
        assert!(state.drain_ready_batch(None).unwrap().is_none());
        assert!(state.pending_shards[&0].transactions[0].is_some());
        assert!(state.pending_shards[&0].transactions[2].is_some());

        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(0, 1))
            .unwrap();
        let batch = state
            .drain_ready_batch(None)
            .unwrap()
            .expect("complete shard should drain");
        let lengths = batch
            .transactions
            .iter()
            .map(|tx| tx.tx_rlp_length)
            .collect::<Vec<_>>();
        assert_eq!(lengths, vec![10, 11, 12]);
        assert_eq!(batch.block_access_list, Some(Bytes::from_static(b"bal")));
        assert_eq!(batch.completed_shards, 1);
        assert!(state.pending_shards.is_empty());
    }

    #[test]
    fn ssmr_replay_recovery_forwards_all_ready_shards() {
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(8);
        let mut state = SsmrReplayRecoveryState::default();

        state.pending_shards.insert(
            0,
            SsmrPendingRecoveredShard::new(1, Some(Bytes::from_static(b"a"))),
        );
        state.pending_shards.insert(
            1,
            SsmrPendingRecoveredShard::new(1, Some(Bytes::from_static(b"b"))),
        );
        state.pending_shards.insert(
            2,
            SsmrPendingRecoveredShard::new(2, Some(Bytes::from_static(b"c"))),
        );

        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(2, 1))
            .unwrap();
        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(0, 0))
            .unwrap();
        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(2, 0))
            .unwrap();
        state
            .insert_recovered_transaction(ssmr_test_recovered_transaction(1, 0))
            .unwrap();

        assert!(forward_all_ssmr_replay_ready_batches(
            &ready_tx, &mut state, None
        ));
        assert!(state.pending_shards.is_empty());

        let mut batches = Vec::new();
        for _ in 0..3 {
            let event = ready_rx
                .try_recv()
                .expect("ready shard should be forwarded");
            let SsmrRecoveredReplayEvent::Transactions(batch) = event else {
                panic!("expected transaction batch");
            };
            batches.push((
                batch
                    .transactions
                    .iter()
                    .map(|tx| tx.tx_rlp_length)
                    .collect::<Vec<_>>(),
                batch.block_access_list,
                batch.completed_shards,
            ));
        }

        assert!(ready_rx.try_recv().is_err());
        assert_eq!(
            batches,
            vec![
                (vec![10], Some(Bytes::from_static(b"a")), 1),
                (vec![10], Some(Bytes::from_static(b"b")), 1),
                (vec![10, 11], Some(Bytes::from_static(b"c")), 1),
            ]
        );
    }

    #[test]
    fn ssmr_replay_collects_only_ready_bal_batches() {
        let mut progress = SsmrReplayProgress::default();
        progress
            .pending_batches
            .push_back(ssmr_test_recovered_batch(1, Some(Bytes::from_static(b"b"))));
        progress
            .pending_batches
            .push_back(ssmr_test_recovered_batch(1, None));
        progress
            .pending_batches
            .push_back(ssmr_test_recovered_batch(1, Some(Bytes::from_static(b"c"))));

        let batches = progress.collect_ready_bal_batches(ssmr_test_recovered_batch(
            1,
            Some(Bytes::from_static(b"a")),
        ));

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].block_access_list, Some(Bytes::from_static(b"a")));
        assert_eq!(batches[1].block_access_list, Some(Bytes::from_static(b"b")));
        assert_eq!(progress.pending_batches.len(), 2);
        assert!(progress.pending_batches[0].block_access_list.is_none());
    }

    #[test]
    fn ssmr_packer_flushes_ordered_shards_and_end() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: SsmrBuilderSink = Arc::new(move |event| {
            sink_events.lock().unwrap().push(event);
        });

        let mut packer = SsmrShardPacker::new(sink, 5, TempoPayloadBuilderMetrics::default());
        assert!(!packer.push(Bytes::from_static(b"aa"), 10));
        assert!(packer.push(Bytes::from_static(b"bbb"), 20));
        packer.queue_flush(None);
        assert!(!packer.push(Bytes::from_static(b"c"), 30));
        packer.finish(None);

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3);
        match &events[0] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.shard_index, 0);
                assert_eq!(shard.first_tx_index, 0);
                assert_eq!(shard.transactions.len(), 2);
                assert_eq!(shard.block_access_list, None);
                assert_eq!(shard.cumulative_tx_bytes, 5);
                assert_eq!(shard.cumulative_gas_estimate, 30);
            }
            other => panic!("expected shard, got {other:?}"),
        }
        match &events[1] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.shard_index, 1);
                assert_eq!(shard.first_tx_index, 2);
                assert_eq!(shard.transactions.len(), 1);
                assert_eq!(shard.block_access_list, None);
                assert_eq!(shard.cumulative_tx_bytes, 6);
                assert_eq!(shard.cumulative_gas_estimate, 60);
            }
            other => panic!("expected shard, got {other:?}"),
        }
        assert_eq!(
            events[2],
            SsmrBuilderEvent::End {
                total_shards: 2,
                total_transactions: 3,
            }
        );
    }

    #[test]
    fn ssmr_packer_emits_empty_stream() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: SsmrBuilderSink = Arc::new(move |event| {
            sink_events.lock().unwrap().push(event);
        });

        SsmrShardPacker::new(sink, 5, TempoPayloadBuilderMetrics::default()).finish(None);

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        match &events[0] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.shard_index, 0);
                assert_eq!(shard.first_tx_index, 0);
                assert!(shard.transactions.is_empty());
                assert_eq!(shard.block_access_list, None);
                assert_eq!(shard.cumulative_tx_bytes, 0);
                assert_eq!(shard.cumulative_gas_estimate, 0);
            }
            other => panic!("expected shard, got {other:?}"),
        }
        assert_eq!(
            events[1],
            SsmrBuilderEvent::End {
                total_shards: 1,
                total_transactions: 0,
            }
        );
    }

    #[test]
    fn ssmr_packer_attaches_bal_to_flushed_shard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: SsmrBuilderSink = Arc::new(move |event| {
            sink_events.lock().unwrap().push(event);
        });

        let mut packer = SsmrShardPacker::new(sink, 5, TempoPayloadBuilderMetrics::default());
        assert!(packer.push(Bytes::from_static(b"aaaaa"), 10));
        let (reply_tx, reply_rx) = mpsc::channel();
        packer.queue_flush(None);
        packer
            .pending_shards
            .front_mut()
            .unwrap()
            .block_access_list_rx = Some(reply_rx);
        reply_tx.send(Some(Bytes::from_static(b"bal0"))).unwrap();
        packer.drain_ready();
        packer.finish(None);

        let events = events.lock().unwrap();
        match &events[0] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.block_access_list, Some(Bytes::from_static(b"bal0")));
            }
            other => panic!("expected shard, got {other:?}"),
        }
    }

    #[test]
    fn ssmr_bal_range_rebases_local_writes_without_boundary() {
        let writes = BalWrites::new(vec![
            (BlockAccessIndex::new(1), 10u64),
            (BlockAccessIndex::new(3), 30),
            (BlockAccessIndex::new(5), 50),
            (BlockAccessIndex::new(8), 80),
        ]);

        let sliced = slice_bal_writes_range(&writes, 3, 6);

        assert_eq!(sliced.writes, vec![(BlockAccessIndex::new(2), 50),]);
    }

    fn ssmr_test_evm_state(address: Address, key: U256, original: U256, present: U256) -> EvmState {
        let mut account = Account::default();
        account.storage.insert(
            key,
            EvmStorageSlot::new_changed(original, present, TransactionId::ZERO),
        );
        EvmState::from_iter([(address, account)])
    }

    fn ssmr_decode_revm_bal(bytes: Bytes) -> RevmBal {
        let mut bytes = bytes.as_ref();
        let alloy_bal = Bal::decode(&mut bytes).expect("test BAL should decode");
        RevmBal::try_from(Vec::<_>::from(alloy_bal)).expect("test BAL should convert")
    }

    #[test]
    fn ssmr_builder_bal_snapshots_transaction_indices_without_gap() {
        let address = Address::repeat_byte(0x42);
        let key = U256::from(7);
        let mut state = BuilderBalState::new();

        state.bump_index();
        state.commit(&ssmr_test_evm_state(
            address,
            key,
            U256::ZERO,
            U256::from(11),
        ));
        state.bump_index();
        let _ = state.snapshot(0, 1).expect("first shard BAL");

        state.commit(&ssmr_test_evm_state(
            address,
            key,
            U256::from(11),
            U256::from(22),
        ));
        state.bump_index();
        let shard = ssmr_decode_revm_bal(state.snapshot(1, 2).expect("second shard BAL"));
        let writes = &shard.accounts[&address].storage.storage[&key].writes;

        assert_eq!(writes, &vec![(BlockAccessIndex::new(1), U256::from(22)),]);
    }

    #[test]
    fn ssmr_replay_bal_history_restores_boundary_locally() {
        let address = Address::repeat_byte(0x42);
        let key = U256::from(7);
        let first_shard = RevmBal::from_iter([(
            address,
            AccountBal {
                storage: StorageBal::from_iter([(
                    key,
                    BalWrites::new(vec![(BlockAccessIndex::new(1), U256::from(11))]),
                )]),
                ..Default::default()
            },
        )]);
        let mut second_shard = RevmBal::from_iter([(
            address,
            AccountBal {
                storage: StorageBal::from_iter([(
                    key,
                    BalWrites::new(vec![(BlockAccessIndex::new(1), U256::from(22))]),
                )]),
                ..Default::default()
            },
        )]);

        let mut history = SsmrReplayBalHistory::default();
        history.record(&first_shard);
        history.apply_to(&mut second_shard);
        let writes = &second_shard.accounts[&address].storage.storage[&key].writes;

        assert_eq!(
            writes,
            &vec![
                (BlockAccessIndex::PRE_EXECUTION, U256::from(11)),
                (BlockAccessIndex::new(1), U256::from(22)),
            ]
        );
    }

    #[test]
    fn ssmr_packer_flushes_first_shard_early() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let sink: SsmrBuilderSink = Arc::new(move |event| {
            sink_events.lock().unwrap().push(event);
        });

        let mut packer = SsmrShardPacker::new(
            sink,
            DEFAULT_SSMR_SHARD_TARGET_BYTES,
            TempoPayloadBuilderMetrics::default(),
        );
        assert!(!packer.push(Bytes::from(vec![0; 4 * 1024]), 10));
        assert!(packer.push(Bytes::from(vec![0; 1024]), 20));
        packer.queue_flush(None);
        assert!(!packer.push(Bytes::from(vec![0; 6 * 1024]), 30));
        packer.finish(None);

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 3);
        match &events[0] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.shard_index, 0);
                assert_eq!(shard.first_tx_index, 0);
                assert_eq!(shard.transactions.len(), 2);
                assert_eq!(shard.block_access_list, None);
                assert_eq!(
                    shard.cumulative_tx_bytes,
                    DEFAULT_SSMR_FIRST_SHARD_TARGET_BYTES as u64
                );
                assert_eq!(shard.cumulative_gas_estimate, 30);
            }
            other => panic!("expected shard, got {other:?}"),
        }
        match &events[1] {
            SsmrBuilderEvent::Shard(shard) => {
                assert_eq!(shard.shard_index, 1);
                assert_eq!(shard.first_tx_index, 2);
                assert_eq!(shard.transactions.len(), 1);
                assert_eq!(shard.block_access_list, None);
                assert_eq!(
                    shard.cumulative_tx_bytes,
                    (DEFAULT_SSMR_FIRST_SHARD_TARGET_BYTES + 6 * 1024) as u64
                );
                assert_eq!(shard.cumulative_gas_estimate, 60);
            }
            other => panic!("expected shard, got {other:?}"),
        }
        assert_eq!(
            events[2],
            SsmrBuilderEvent::End {
                total_shards: 2,
                total_transactions: 3,
            }
        );
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
        let eth = EthBuiltPayload::new(Arc::new(block), U256::ZERO, None, None);
        TempoBuiltPayload::new(
            eth,
            None,
            None,
            Duration::ZERO,
            Duration::ZERO,
            NON_TRANSACTION_SIZE_ESTIMATE,
            EncodedBlock::default(),
        )
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
    fn test_recovered_subblock_has_expired_transactions_boundary() {
        // valid_before == timestamp → expired
        let subblock = RecoveredSubBlock::with_valid_before(Some(nz(1000)));
        assert!(subblock.has_expired_transactions(1000));

        // valid_before < timestamp → expired
        assert!(subblock.has_expired_transactions(1001));

        // valid_before > timestamp → NOT expired
        assert!(!subblock.has_expired_transactions(999));

        // No valid_before → NOT expired
        let subblock_no_expiry = RecoveredSubBlock::with_valid_before(None);
        assert!(!subblock_no_expiry.has_expired_transactions(1000));
    }
}
