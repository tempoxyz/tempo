//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod encode;
mod metrics;
mod prewarming;

use crossbeam_channel::Sender;
use reth_trie_common::ordered_root::OrderedTrieRootEncodedBuilder;

use crate::{
    encode::{
        EncodedBlockTransactionList, EncodedBlockTransactionsBuilder, ExecutionBlockEncoder,
        block_transaction_length,
    },
    metrics::{BlockBuildStopReason, InstrumentedFinishProvider, TempoPayloadBuilderMetrics},
    prewarming::{BestTransactionsPrewarming, PrewarmedTransaction, PrewarmingExecutionContext},
};
use alloy_consensus::{BlockHeader as _, TxReceipt};
use alloy_eips::{eip1559::calculate_block_gas_limit, eip2718::Encodable2718};
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use alloy_rlp::Encodable;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
    is_better_payload,
};
use reth_chainspec::{ChainSpecProvider, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_engine_tree::tree::{
    CachedStateMetrics, CachedStateMetricsSource, CachedStateProvider,
    instrumented_state::InstrumentedStateProvider,
};
use reth_errors::ConsensusError;
use reth_evm::{
    BlockExecutionError, BlockExecutor, BlockExecutorFactory, BlockValidationError, ConfigureEvm,
    Database, NextBlockEnvAttributes, OnStateHook, database::StateProviderDatabase,
    execute::BlockAssemblerInput,
};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::{RecoveredBlock, transaction::error::InvalidTransactionError};
use reth_storage_api::{
    EvmStateProvider, HashedPostStateProvider, StateProvider as _, StateProviderFactory,
    StateRootProvider,
};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::{
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks, spec::SYSTEM_TX_COUNT};
use tempo_evm::{
    StorageActionReplayError, TempoEvmConfig, TempoInvalidTransaction, TempoNextBlockEnvAttributes,
    TempoStateAccess, TempoTxResult, TxLane, consensus::MAX_BLOCK_TRANSACTIONS,
    error::LaneGasExceeded,
};
use tempo_payload_types::{
    Estimator, TempoBuiltPayload, TempoPayloadAttributes, ValidationLatencyWorkload,
    estimator::FinishedBuild,
};
use tempo_primitives::{TempoHeader, TempoReceipt, TempoTxEnvelope};
use tempo_transaction_pool::{
    StateAwareBestTransactions, TempoTransactionPool, best::BestTransaction,
    transaction::TempoPoolTransactionError,
};
use tokio::sync::oneshot;
use tracing::{Level, Span, debug, debug_span, info, instrument, trace, warn};

/// Conservative estimate for non-transaction execution block RLP bytes.
///
/// Exact block RLP length is computed asynchronously after payload construction, so the builder uses
/// this margin together with known transaction, withdrawal, and extra-data lengths for Osaka size
/// checks and pacing estimates.
const NON_TRANSACTION_SIZE_ESTIMATE: usize = 2048;

/// Gas every transaction uses at least: the intrinsic gas of a plain transfer.
const MIN_TRANSACTION_GAS: u64 = 21_000;

/// Blocks for which the builder admits calls to an instance as general after one of its
/// registered payments failed the TIP-1180 execution check and was left out, and for which it
/// remembers how often the instance failed.
const DEMOTION_BLOCKS: u64 = 7_200;

/// Most instances the builder remembers as failing the execution check.
const MAX_DEMOTED_INSTANCES: usize = 4_096;

/// How the payload builder admits a transaction against its lane's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneAdmission {
    /// A TIP-1045 payment, or a transaction whose gas limit fits its lane's remaining gas.
    Fits,
    /// A transaction whose gas limit passes its lane's remaining gas: kept only if its gas used
    /// fits.
    ByGasUsed,
    /// A transaction left out of this block.
    Full,
}

/// Gas left in the budgets the builder admits transactions against, and in the budget for
/// executions it leaves out of the block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LaneState {
    /// Gas left in the general (non-payment) lane.
    general_gas_left: u64,
    /// Gas left for registered payments (TIP-1180).
    registered_gas_left: u64,
    /// Gas this payload may still execute in transactions it then leaves out, for both lanes: one
    /// general lane's worth per payload, or one transaction's where the general lane is smaller.
    discard_gas_left: u64,
    /// Gas this payload may still execute in registered payments it leaves out because they
    /// failed the execution check and did not fit the general lane, of the same size.
    failed_check_gas_left: u64,
}

impl LaneState {
    /// Returns the gas left in the lane's budget. TIP-1045 payments have no budget of their own.
    fn budget(&self, lane: TxLane) -> Option<u64> {
        match lane {
            TxLane::General => Some(self.general_gas_left),
            TxLane::Payment => None,
            TxLane::RegisteredPayment => Some(self.registered_gas_left),
        }
    }
}

/// Decides how a transaction enters its lane, given the most regular gas it can use.
///
/// Block validation bounds the general lane and the registered payment budget by the gas each
/// transaction used, so from T16 the builder admits by gas used too: a transaction whose gas limit
/// passes the remaining gas is executed and kept only if its gas used fits. It is tried only while
/// the payload's discard budget covers its whole gas limit, so a payload never executes more than
/// that budget in transactions it leaves out this way. Earlier forks admit by gas limit.
///
/// A registered payment that fits the registered budget is admitted only if it would also fit the
/// general lane should it fail the execution check, or while the failed check budget covers its
/// whole gas limit, so a payload never executes more than that budget in registered payments it
/// leaves out for failing the check.
fn lane_admission(
    hardfork: tempo_chainspec::hardfork::TempoHardfork,
    lane: TxLane,
    max_regular_gas_used: u64,
    lanes: &LaneState,
) -> LaneAdmission {
    let Some(gas_left) = lanes.budget(lane) else {
        return LaneAdmission::Fits;
    };
    if max_regular_gas_used <= gas_left {
        if lane.is_registered_payment()
            && max_regular_gas_used > lanes.general_gas_left
            && max_regular_gas_used > lanes.failed_check_gas_left
        {
            LaneAdmission::Full
        } else {
            LaneAdmission::Fits
        }
    } else if hardfork.is_t16()
        && gas_left >= MIN_TRANSACTION_GAS
        && max_regular_gas_used <= lanes.discard_gas_left
    {
        LaneAdmission::ByGasUsed
    } else {
        LaneAdmission::Full
    }
}

/// Instances whose code failed the TIP-1180 execution check in a registered payment: it called
/// code that is not registered, so those payments count toward the general lane. Shared by the
/// payloads one builder builds.
///
/// A registered payment that fails the check and does not fit the general lane is left out,
/// without paying. To keep that from repeating, the builder then admits calls to the instance
/// whose code made the call the check did not allow (and only that one) as general, by gas limit
/// against the general lane, for [`DEMOTION_BLOCKS`]. An included registered payment to it that
/// passes the check restores it, but never in the block it was demoted in, and only after a
/// back-off that doubles with each failure within [`DEMOTION_BLOCKS`] of the last one.
#[derive(Debug, Clone, Default)]
struct DemotedInstances(Arc<std::sync::Mutex<alloy_primitives::map::AddressMap<Demotion>>>);

/// What a builder remembers about an instance that failed the execution check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Demotion {
    /// The block of its latest failure.
    at: u64,
    /// Its failures, each within [`DEMOTION_BLOCKS`] of the one before.
    failures: u32,
    /// Whether a registered payment to it passed the check since its latest failure.
    restored: bool,
}

impl Demotion {
    /// Returns whether the failure is recent enough to remember at `block`.
    fn is_recent(&self, block: u64) -> bool {
        block.saturating_sub(self.at) < DEMOTION_BLOCKS
    }

    /// Returns the blocks after its latest failure from which a passing payment restores it:
    /// one block after the first failure, doubling with each further one.
    fn back_off(&self) -> u64 {
        1u64.checked_shl(self.failures.saturating_sub(1))
            .unwrap_or(u64::MAX)
            .min(DEMOTION_BLOCKS)
    }
}

impl DemotedInstances {
    fn lock(&self) -> std::sync::MutexGuard<'_, alloy_primitives::map::AddressMap<Demotion>> {
        self.0.lock().unwrap_or_else(|err| err.into_inner())
    }

    /// Returns whether any call of `tx` targets an instance demoted at `block`.
    fn any_demoted(&self, tx: &TempoTxEnvelope, block: u64) -> bool {
        let demoted = self.lock();
        !demoted.is_empty()
            && call_targets(tx).any(|target| {
                demoted
                    .get(&target)
                    .is_some_and(|demotion| !demotion.restored && demotion.is_recent(block))
            })
    }

    /// Demotes `instance`, whose code failed the execution check at `block`.
    fn demote(&self, instance: Address, block: u64) {
        let mut demoted = self.lock();
        if demoted.len() >= MAX_DEMOTED_INSTANCES && !demoted.contains_key(&instance) {
            demoted.retain(|_, demotion| demotion.is_recent(block));
            if demoted.len() >= MAX_DEMOTED_INSTANCES {
                demoted.clear();
            }
        }
        let failures = demoted
            .get(&instance)
            .filter(|demotion| demotion.is_recent(block))
            .map_or(1, |demotion| demotion.failures.saturating_add(1));
        demoted.insert(
            instance,
            Demotion {
                at: block,
                failures,
                restored: false,
            },
        );
    }

    /// Restores the instances `tx` calls, after it passed the check at `block`, where their
    /// back-off has passed.
    fn restore(&self, tx: &TempoTxEnvelope, block: u64) {
        let mut demoted = self.lock();
        if demoted.is_empty() {
            return;
        }
        for target in call_targets(tx) {
            if let Some(demotion) = demoted.get_mut(&target)
                && block.saturating_sub(demotion.at) >= demotion.back_off()
            {
                demotion.restored = true;
            }
        }
    }
}

/// Returns the addresses `tx`'s calls target.
fn call_targets(tx: &TempoTxEnvelope) -> impl Iterator<Item = Address> + '_ {
    tx.calls().filter_map(|(kind, _)| kind.to().copied())
}

/// Returns the lane rejection of an execution the executor left out because its gas used passed
/// the gas its lane had left.
fn lane_gas_exceeded(error: &BlockExecutionError) -> Option<LaneGasExceeded> {
    match error {
        BlockExecutionError::Validation(BlockValidationError::Other(error)) => {
            error.downcast_ref::<LaneGasExceeded>().copied()
        }
        _ => None,
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
    /// Proposal budget estimator that paces builds with a `payload_build_budget`.
    ///
    /// One [`tempo_payload_types::BuildPlan`] is taken from it per paced build,
    /// and the finished build's replayable work is reported back to it.
    estimator: Estimator,
    /// Instances whose registered payments failed the TIP-1180 execution check.
    demoted: DemotedInstances,
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
    /// Creates a builder that paces builds with a `payload_build_budget` using
    /// `estimator`.
    ///
    /// Stop decisions only account for the validation feedback recorded on
    /// `estimator`, so share a handle with whatever records it.
    pub fn new(
        pool: TempoTransactionPool<Provider>,
        provider: Provider,
        executor: TaskExecutor,
        evm_config: TempoEvmConfig,
        config: TempoPayloadBuilderConfig,
        estimator: Estimator,
    ) -> Self {
        Self {
            pool,
            provider,
            executor,
            config,
            evm_config,
            metrics: TempoPayloadBuilderMetrics::default(),
            cache_metrics: CachedStateMetrics::zeroed(CachedStateMetricsSource::Builder),
            estimator,
            demoted: DemotedInstances::default(),
        }
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
        self.build_payload(args, |attributes, timestamp| {
            self.pool.best_transactions_for_block(attributes, timestamp)
        })
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
            |_, _| core::iter::empty(),
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
        best_txs: impl FnOnce(BestTransactionsAttributes, u64) -> Txs,
    ) -> Result<BuildOutcome<TempoBuiltPayload>, PayloadBuilderError>
    where
        Txs: BestTransactions<Item = BestTransaction> + 'static,
    {
        let BuildArguments {
            cached_reads,
            execution_cache,
            mut state_root_handle,
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

        macro_rules! check_cancel {
            () => {
                if cancel.is_cancelled() {
                    return Ok(BuildOutcome::Cancelled);
                }
            };
        }

        check_cancel!();

        let start = Instant::now();
        // Snapshot before setup: the stop decision already charges start.elapsed().
        let payload_build_budget = attributes.payload_build_budget();

        let block_time_millis =
            (attributes.timestamp_millis() - parent_header.timestamp_millis()) as f64;
        self.metrics.block_time_millis.record(block_time_millis);
        self.metrics.block_time_millis_last.set(block_time_millis);

        let state_setup_start = Instant::now();
        let _state_setup_span = debug_span!(target: "payload_builder", "state_setup").entered();
        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let evm_state_provider = state_provider.as_ref().into_evm_state_provider();
        let cached_state_provider = execution_cache.as_ref().map(|execution_cache| {
            CachedStateProvider::new(
                &evm_state_provider,
                execution_cache.cache().clone(),
                Some(self.cache_metrics.clone()),
            )
        });
        let evm_state_provider = cached_state_provider
            .as_ref()
            .map(|provider| provider as &dyn EvmStateProvider)
            .unwrap_or(&evm_state_provider);
        let instrumented_state_provider = self
            .config
            .state_provider_metrics
            .then(|| InstrumentedStateProvider::new(evm_state_provider, "builder"));
        let evm_state_provider = instrumented_state_provider
            .as_ref()
            .map(|provider| provider as &dyn EvmStateProvider)
            .unwrap_or(evm_state_provider);

        let mut db = StateProviderDatabase::new(evm_state_provider);
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
        let general_gas_limit =
            chain_spec.general_gas_limit_at(attributes.timestamp, block_gas_limit, 0);
        let hardfork = chain_spec.tempo_hardfork_at(attributes.timestamp);
        // T17+: registered payments (TIP-1180) share this part of the payment lane.
        let registered_gas_limit = hardfork
            .registered_payment_gas_limit(block_gas_limit)
            .unwrap_or_default();

        // When consensus passes only the DKG ceremony output for a boundary block, as it does from
        // T15, the builder fills in the rest of the outcome from the parent state. Other
        // attributes, such as those of earlier boundaries or the dev-mode miner's, keep their
        // extra data as they are.
        let block_number = parent_header.number() + 1;
        let epoch_length = chain_spec
            .info
            .epoch_length()
            .unwrap_or(NonZeroU64::MIN)
            .get();
        let ceremony_output = attributes
            .dkg_ceremony_output()
            .filter(|_| block_number.saturating_add(1).is_multiple_of(epoch_length));
        let extra_data = if let Some(output) = ceremony_output {
            let output = output.clone();
            let current_epoch = block_number / epoch_length;
            let next_epoch = current_epoch + 1;
            let outcome = db
                .dkg_ceremony_config(hardfork, block_number)
                .map_err(PayloadBuilderError::other)?
                .ok_or_else(|| {
                    PayloadBuilderError::Other(
                        "ValidatorConfigV2 is not initialized as of the boundary block's parent"
                            .into(),
                    )
                })?
                .boundary_outcome(next_epoch, output);
            Bytes::from(commonware_codec::Encode::encode(&outcome))
        } else {
            attributes.extra_data().clone()
        };

        let mut cumulative_gas_used = 0;
        let mut cumulative_state_gas_used = 0u64;
        let mut non_payment_gas_used = 0;
        let mut registered_gas_used = 0;
        // Gas executed in transactions left out of the block: at most one general lane's worth,
        // or one transaction's where the general lane is smaller.
        let mut discarded_gas = 0u64;
        // Gas executed in registered payments left out of the block for failing the execution
        // check, within the same bound.
        let mut failed_check_gas = 0u64;
        let mut registered_payment_transactions = 0u64;
        let mut estimated_rlp_block_size = attributes
            .withdrawals
            .as_ref()
            .map(|w| w.length())
            .unwrap_or(0)
            + NON_TRANSACTION_SIZE_ESTIMATE
            + extra_data.length();
        let mut payment_transactions = 0u64;
        let mut reverted_transactions = 0u64;
        let mut pool_transactions_yielded = 0u64;
        let mut pool_transactions_included = 0u64;
        let mut parallel_transactions_executed = 0u64;
        let mut total_fees = U256::ZERO;

        let next_attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: block_gas_limit,
                parent_beacon_block_root: attributes.parent_beacon_block_root,
                withdrawals: attributes.withdrawals.clone().map(Into::into),
                extra_data,
                slot_number: attributes.slot_number,
            },
            general_gas_limit,
            shared_gas_limit: 0,
            timestamp_millis_part: attributes.timestamp_millis_part(),
            consensus_context: attributes.consensus_context(),
        };
        let mut evm_env = self
            .evm_config
            .next_evm_env(&parent_header, &next_attributes)
            .map_err(PayloadBuilderError::other)?;
        let ctx = self
            .evm_config
            .context_for_next_block(&parent_header, next_attributes)
            .map_err(PayloadBuilderError::other)?;

        // Resolve the configured fee recipient before moving the database into the EVM. This
        // keeps the read out of EVM2's journal and therefore out of transaction gas accounting.
        maybe_override_fee_recipient(&mut db, &mut evm_env, &attributes);

        let prewarm_evm_env = evm_env.clone();
        let assembly_evm_env = evm_env.clone();
        let evm_config = self.evm_config.clone().with_jit_support();
        let evm = evm_config.evm_with_database(db, evm_env);
        let mut executor = evm_config.create_executor(evm, ctx.clone());

        check_cancel!();

        if let Some(handle) = state_root_handle.as_mut() {
            let mut hook = handle.take_state_hook();
            executor.set_state_hook(move |state| hook.on_state(state));
        }

        executor.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;
        // The payment call registry version in the parent state keys the pool's cached
        // registered payment classifications (TIP-1180). They hold only when the pool brought them
        // up to date on this branch.
        let registry_version = executor
            .payment_call_registry_version()
            .map_err(PayloadBuilderError::evm)?;
        let discard_gas_limit = general_gas_limit.max(
            executor
                .evm()
                .version()
                .tx_gas_limit_cap
                .min(block_gas_limit),
        );
        let registry_cache_current = self.pool.registry_cache_current(
            registry_version,
            parent_header.hash(),
            parent_header.parent_hash(),
        );
        check_cancel!();

        debug!("building new payload");

        let (roots_tx, roots_rx) = self.spawn_roots_task();

        if is_osaka && estimated_rlp_block_size > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: estimated_rlp_block_size,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        let pool_fetch_start = Instant::now();
        let raw_best_txs = best_txs(
            BestTransactionsAttributes::new(
                executor.evm().block().basefee.to(),
                Some(executor.evm().block().blob_basefee.to()),
            ),
            executor.evm().block().timestamp.to(),
        );
        let prewarm_ctx = PrewarmingExecutionContext::new(
            self.provider.clone(),
            self.executor.clone(),
            execution_cache,
            parent_header.hash(),
            prewarm_evm_env,
            self.evm_config.clone(),
            self.config.enable_parallel,
        );
        let mut best_txs = if self.config.enable_prewarming {
            if self.config.enable_parallel {
                PayloadTransactions::Parallel(BestTransactionsPrewarming::new(
                    prewarm_ctx,
                    raw_best_txs,
                ))
            } else {
                PayloadTransactions::Prewarming(StateAwareBestTransactions::new(
                    BestTransactionsPrewarming::new(prewarm_ctx, raw_best_txs),
                    hardfork.fallback_fee_tokens(),
                ))
            }
        } else {
            PayloadTransactions::Sequential(StateAwareBestTransactions::new(
                Box::new(raw_best_txs),
                hardfork.fallback_fee_tokens(),
            ))
        };
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
        // Snapshot the shared estimator once so every stop decision in this
        // build uses the same multiplier, dry build finish and validation feedback.
        let build_plan = payload_build_budget
            .map(|build_budget| self.estimator.build_plan(Instant::now(), build_budget));
        let validation_latency = build_plan.and_then(|plan| plan.validation_latency());
        let block_build_stop_reason = loop {
            check_cancel!();

            if let Some(plan) = build_plan.as_ref() {
                let elapsed = start.elapsed();
                let current_workload = ValidationLatencyWorkload::new(
                    cumulative_gas_used,
                    pool_transactions_included as usize,
                );
                let budget_decision = plan.decision(
                    elapsed,
                    normal_transaction_fill_idle_elapsed,
                    current_workload,
                );
                if plan.exhausted(&budget_decision) {
                    debug!(
                        target: "payload_builder",
                        ?elapsed,
                        ?normal_transaction_fill_idle_elapsed,
                        build_budget = ?plan.build_budget,
                        predicted_builder_work = ?budget_decision.predicted_builder_work,
                        predicted_validator_work = ?budget_decision.predicted_validator_work,
                        total_reserved = ?budget_decision.total_reserved,
                        ?current_workload,
                        gas_used = cumulative_gas_used,
                        transactions = pool_transactions_included,
                        estimated_rlp_block_size,
                        build_time_multiplier = %plan.build_time_multiplier(),
                        dry_finish = ?plan.dry_finish(),
                        "stopping pool transaction execution before payload build budget is exhausted"
                    );
                    break BlockBuildStopReason::BuildBudget;
                }
            }

            // Leave room for the end-of-block system transactions.
            if executor.receipts().len() + SYSTEM_TX_COUNT >= MAX_BLOCK_TRANSACTIONS {
                break BlockBuildStopReason::TransactionCountLimit;
            }

            let Some(mut pool_tx) = best_txs.next() else {
                if payload_build_budget.is_some() && cumulative_gas_used < block_gas_limit {
                    std::thread::sleep(Duration::from_millis(1));
                    normal_transaction_fill_idle_elapsed += Duration::from_millis(1);
                    continue;
                }
                let stop_reason = if cumulative_gas_used >= block_gas_limit {
                    BlockBuildStopReason::GasLimit
                } else if skipped_oversized_block {
                    BlockBuildStopReason::RlpBlockSizeLimit
                } else {
                    BlockBuildStopReason::TxPoolEmpty
                };
                break stop_reason;
            };
            let tx = pool_tx.tx.clone();
            pool_transactions_yielded += 1;

            let max_regular_gas_used =
                core::cmp::min(tx.gas_limit(), executor.evm().version().tx_gas_limit_cap);

            // Ensure we still have capacity for this transaction within the block gas limit.
            if cumulative_gas_used + max_regular_gas_used > block_gas_limit {
                // Mark this transaction as invalid since it doesn't fit
                // The iterator will handle lane switching internally when appropriate
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::ExceedsGasLimit(
                        tx.gas_limit(),
                        block_gas_limit - cumulative_gas_used,
                    ),
                );
                self.metrics.inc_pool_tx_skipped("exceeds_block_gas_limit");
                continue;
            }

            let classified = if !hardfork.is_t17() {
                TxLane::from_payment(if hardfork.is_t15() {
                    tx.transaction.is_payment_v3()
                } else if hardfork.is_t5() {
                    tx.transaction.is_payment_v2()
                } else {
                    tx.transaction.inner().is_payment_v1()
                })
            } else if tx.transaction.is_payment_v3() {
                TxLane::Payment
            } else if registry_version == 0 {
                TxLane::General
            } else {
                // The pool caches registered payment classifications per registry version;
                // classify from the parent state, as block execution does, when it has none.
                let cached = registry_cache_current
                    .then(|| {
                        tx.transaction
                            .cached_registered_payment(registry_version, block_number)
                    })
                    .flatten();
                let is_registered = match cached {
                    Some(is_registered) => is_registered,
                    None => {
                        let classification = executor
                            .classify_registered_payment(tx.transaction.inner().inner())
                            .map_err(PayloadBuilderError::evm)?;
                        if registry_cache_current {
                            tx.transaction.cache_registered_payment(
                                registry_version,
                                block_number,
                                classification,
                            );
                        }
                        classification.is_registered_payment
                    }
                };
                if is_registered {
                    TxLane::RegisteredPayment
                } else {
                    TxLane::General
                }
            };
            // Calls to an instance that recently failed the execution check are admitted as
            // general; block execution still decides the lane.
            let lane = if classified.is_registered_payment()
                && self
                    .demoted
                    .any_demoted(tx.transaction.inner().inner(), block_number)
            {
                TxLane::General
            } else {
                classified
            };

            let lanes = LaneState {
                general_gas_left: general_gas_limit.saturating_sub(non_payment_gas_used),
                registered_gas_left: registered_gas_limit.saturating_sub(registered_gas_used),
                discard_gas_left: discard_gas_limit.saturating_sub(discarded_gas),
                failed_check_gas_left: discard_gas_limit.saturating_sub(failed_check_gas),
            };
            let admission = lane_admission(hardfork, lane, max_regular_gas_used, &lanes);
            let by_gas_used = admission == LaneAdmission::ByGasUsed;
            let lane_limit_error = |lane: TxLane| {
                InvalidPoolTransactionError::Other(Box::new(if lane.is_registered_payment() {
                    TempoPoolTransactionError::ExceedsRegisteredPaymentLimit
                } else {
                    TempoPoolTransactionError::ExceedsNonPaymentLimit
                }))
            };

            // If the tx will exceed its lane's limit, mark it as invalid and continue
            if admission == LaneAdmission::Full {
                #[cfg(feature = "fuzz")]
                antithesis_sdk::assert_reachable!(
                    "Payload builder defers a non-payment transaction at the general gas limit",
                    &serde_json::json!({ "general_gas_used": non_payment_gas_used, "general_gas_limit": general_gas_limit })
                );
                best_txs.mark_invalid(&pool_tx, lane_limit_error(lane));
                self.metrics
                    .inc_pool_tx_skipped(if lane.is_registered_payment() {
                        "exceeds_registered_gas_limit"
                    } else {
                        "exceeds_general_gas_limit"
                    });
                continue;
            }

            check_cancel!();

            let tx_rlp_length =
                block_transaction_length(&tx.transaction, tx.transaction.encoded_length());
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

            // The executor's lane, after the TIP-1180 execution check.
            let mut included_lane = lane;
            let mut result_closure = |result: &TempoTxResult| {
                cumulative_gas_used += result.block_gas_used();
                cumulative_state_gas_used += result.state_gas_used();
                included_lane = result.lane();
                match included_lane {
                    TxLane::General => non_payment_gas_used += result.block_gas_used(),
                    TxLane::Payment => {}
                    TxLane::RegisteredPayment => registered_gas_used += result.block_gas_used(),
                }

                // Score payload value by the validator-credited fee amount that the
                // FeeManager precompile actually wrote during this transaction.
                total_fees += result.validator_fee();

                // Notify transactions iterator about the new state.
                best_txs.on_new_result(result);
            };

            // A replay commits as it executes, so a transaction admitted by gas used runs afresh.
            // A transaction the executor rejects for its lane (admitted by gas used, or a
            // registered payment that failed the execution check and does not fit the general
            // lane) leaves the block as it was.
            let replay = pool_tx.replay.take().filter(|_| !by_gas_used);
            let execution_result = if let Some(replay) = replay {
                parallel_transactions_executed += 1;
                executor
                    .execute_transaction_with_actions(
                        tx.transaction.executable(),
                        *replay,
                        result_closure,
                    )
                    .map(|_| None)
            } else {
                executor.invalidate_expiring_nonce_cache();
                executor
                    .execute_transaction_without_commit(tx.transaction.executable())
                    .and_then(|result| {
                        result_closure(&result);
                        executor.commit_transaction(result).map(|_| None)
                    })
            };
            let execution_result = match execution_result {
                Err(err) => lane_gas_exceeded(&err).map(Some).ok_or(err),
                Ok(none) => Ok(none),
            };

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
                        } else if matches!(
                            TempoInvalidTransaction::from_invalid_tx_error(error.as_ref()),
                            Some(TempoInvalidTransaction::ExpiringNonceReplay)
                        ) {
                            // This exact transaction is already included, typically in the parent
                            // block before pool maintenance evicted it. Skip it without marking it
                            // invalid.
                            #[cfg(feature = "fuzz")]
                            antithesis_sdk::assert_reachable!(
                                "Payload builder skips an expiring nonce transaction already included"
                            );
                            trace!(%error, tx = %tx_debug_repr, "skipping already included expiring nonce transaction");
                            self.metrics.inc_pool_tx_skipped("expiring_nonce_replay");
                        } else {
                            // if the transaction is invalid, we can skip it and all of its
                            // descendants
                            #[cfg(feature = "fuzz")]
                            antithesis_sdk::assert_reachable!(
                                "Payload builder evicts a pool transaction that fails execution",
                                &serde_json::json!({ "error": error.to_string() })
                            );
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

            if let Ok(Some(exceeded)) = execution_result {
                discarded_gas = discarded_gas.saturating_add(exceeded.gas_used);
                // A registered payment counted toward the general lane failed the execution check:
                // demote only the instance whose code made the call the check did not allow.
                let metric =
                    if classified.is_registered_payment() && exceeded.lane == TxLane::General {
                        failed_check_gas = failed_check_gas.saturating_add(exceeded.gas_used);
                        if let Some(instance) = exceeded.failed_instance {
                            self.demoted.demote(instance, block_number);
                        }
                        "failed_execution_check"
                    } else if exceeded.lane.is_registered_payment() {
                        "exceeds_registered_gas_used"
                    } else {
                        "exceeds_general_gas_used"
                    };
                best_txs.mark_invalid(&pool_tx, lane_limit_error(exceeded.lane));
                self.metrics.inc_pool_tx_skipped(metric);
                continue;
            }

            trace!("Transaction executed");
            pool_transactions_included += 1;
            if included_lane.is_payment() {
                payment_transactions += 1;
            }
            // An included registered payment that failed the check paid for its general lane gas,
            // so it demotes nothing.
            if classified.is_registered_payment() && included_lane.is_registered_payment() {
                self.demoted
                    .restore(tx.transaction.inner().inner(), block_number);
            }
            if included_lane.is_registered_payment() {
                registered_payment_transactions += 1;
            }
            estimated_rlp_block_size += tx_rlp_length;
            let receipt = executor.receipts().last().unwrap().clone();
            if !receipt.success {
                reverted_transactions += 1;
            }
            let _ = roots_tx.send((tx, receipt));
        };

        // cancel pre-warming, if any, by dropping the iter
        drop(best_txs);

        let elapsed_at_tx_cutoff = start.elapsed();
        let validation_work_at_tx_cutoff =
            elapsed_at_tx_cutoff.saturating_sub(normal_transaction_fill_idle_elapsed);
        drop(_block_fill_span);
        self.metrics
            .inc_block_build_stop_reason(block_build_stop_reason);
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

        if !is_better_payload(best_payload.as_ref(), total_fees) {
            // Release db
            drop(executor);
            // can skip building the block
            return Ok(BuildOutcome::Aborted {
                fees: total_fees,
                cached_reads,
            });
        }

        let total_transaction_execution_elapsed = normal_transaction_fill_elapsed;
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

        let execution_output = executor.finish()?;
        let execution_result = &execution_output.result;
        let execution_state = &execution_output.state;

        let hashed_state = if let Some(Ok(hashed_state)) = state_root_handle
            .as_mut()
            .and_then(|handle| handle.try_take_hashed_state_rx())
            .map(|rx| rx.recv())
        {
            hashed_state
        } else {
            Arc::new(finish_provider.hashed_post_state(execution_state)?)
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
            } else {
                state_root_handle.and_then(|mut handle| {
                    let state_root_wait_start = Instant::now();
                    let _span =
                        debug_span!(target: "payload_builder", "await_state_root").entered();
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
                })
            }
            .unzip();

        let (state_root, trie_updates) = if self.config.skip_state_root {
            (parent_header.state_root(), Arc::new(Default::default()))
        } else if let Some(outcome) = state_root_outcome {
            (outcome.state_root, outcome.trie_updates)
        } else {
            let (state_root, trie_updates) = finish_provider
                .state_root_with_updates((*hashed_state).clone())
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
                assembly_evm_env,
                ctx,
                &parent_header,
                transactions,
                execution_result,
                execution_state,
                &finish_provider,
                state_root,
                None,
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
            .set(block_gas_limit as f64 - general_gas_limit as f64);
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
        let validation_work_duration = elapsed.saturating_sub(normal_transaction_fill_idle_elapsed);
        if payload_build_budget.is_some() {
            let finished_at = Instant::now();
            self.estimator.on_build_finished(
                finished_at,
                FinishedBuild::new(
                    validation_work_at_tx_cutoff,
                    validation_work_duration,
                    normal_transaction_fill_idle_elapsed,
                ),
            );
            self.metrics
                .build_time_multiplier_last
                .set(self.estimator.build_time_multiplier(finished_at));
        }
        if is_osaka && estimated_rlp_block_size > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: estimated_rlp_block_size,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }
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
            .record(estimated_rlp_block_size as f64);
        self.metrics
            .rlp_block_size_bytes_last
            .set(estimated_rlp_block_size as f64);

        info!(
            parent_hash = ?block.parent_hash(),
            number = block.number(),
            hash = ?block.hash(),
            timestamp = block.timestamp_millis(),
            gas_limit = block.gas_limit(),
            gas_used,
            cumulative_state_gas_used,
            extra_data = %block.extra_data(),
            payment_transactions,
            registered_payment_transactions,
            pool_transactions_yielded,
            pool_transactions_included,
            parallel_transactions_executed,
            invalid_pool_transaction_execution_attempts,
            pool_transactions_inclusion_ratio,
            total_transactions,
            ?elapsed,
            ?validation_work_duration,
            ?validation_latency_duration,
            ?normal_transaction_fill_elapsed,
            ?normal_transaction_fill_idle_elapsed,
            ?total_transaction_execution_elapsed,
            ?sparse_trie_state_root_wait_elapsed,
            ?builder_finish_elapsed,
            "Built payload"
        );

        #[cfg(feature = "fuzz")]
        {
            let consensus = tempo_evm::consensus::TempoConsensus::new(chain_spec);
            let sealed_block = block.sealed_block();
            antithesis_sdk::assert_always_less_than_or_equal_to!(
                block.gas_used(),
                block.gas_limit(),
                "Payload builder keeps block gas used within the gas limit"
            );
            antithesis_sdk::assert_always!(
                execution_result.receipts.len() == total_transactions,
                "Payload builder produces one receipt per included transaction",
                &serde_json::json!({ "receipts": execution_result.receipts.len(), "transactions": total_transactions })
            );
            let header = reth_consensus::HeaderValidator::validate_header(
                &consensus,
                sealed_block.sealed_header(),
            );
            antithesis_sdk::assert_always!(
                header.is_ok(),
                "Payload builder block header passes consensus header validation",
                &serde_json::json!({ "block_number": block.number(), "error": header.err().map(|err| err.to_string()) })
            );
            let against_parent = reth_consensus::HeaderValidator::validate_header_against_parent(
                &consensus,
                sealed_block.sealed_header(),
                &parent_header,
            );
            antithesis_sdk::assert_always!(
                against_parent.is_ok(),
                "Payload builder block header is a valid child of its parent",
                &serde_json::json!({ "block_number": block.number(), "error": against_parent.err().map(|err| err.to_string()) })
            );
            let pre_execution =
                reth_consensus::Consensus::validate_block_pre_execution(&consensus, sealed_block);
            antithesis_sdk::assert_always!(
                pre_execution.is_ok(),
                "Payload builder block body passes consensus pre-execution validation",
                &serde_json::json!({ "block_number": block.number(), "error": pre_execution.err().map(|err| err.to_string()) })
            );
            let post_execution = reth_consensus::FullConsensus::<tempo_primitives::TempoPrimitives>::validate_block_post_execution(
                &consensus,
                &block,
                execution_result,
                None,
                None,
            );
            antithesis_sdk::assert_always!(
                post_execution.is_ok(),
                "Payload builder execution outputs pass consensus post-execution validation",
                &serde_json::json!({ "block_number": block.number(), "error": post_execution.err().map(|err| err.to_string()) })
            );
        }

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

        let executed_block = BuiltPayloadExecutedBlock {
            recovered_block: block,
            execution_output: Arc::new(execution_output),
            hashed_state,
            trie_updates,
        };

        let payload = TempoBuiltPayload::new(
            eth_payload,
            Some(executed_block),
            validation_work_duration,
            validation_latency_duration,
            estimated_rlp_block_size,
            execution_block_encoded,
        );

        drop(instrumented_state_provider);
        drop(cached_state_provider);
        self.executor.spawn_drop(state_provider);
        Ok(BuildOutcome::Freeze(payload))
    }

    fn spawn_roots_task(
        &self,
    ) -> (
        Sender<(BestTransaction, TempoReceipt)>,
        oneshot::Receiver<RootsTaskResult>,
    ) {
        let (transactions_tx, transactions_rx) =
            crossbeam_channel::unbounded::<(BestTransaction, TempoReceipt)>();
        let (result_tx, result_rx) = oneshot::channel();
        let parent = Span::current();

        self.executor
            .spawn_blocking_named("builder-roots-task", move || {
                let _span =
                    debug_span!(target: "payload_builder", parent: &parent, "builder_roots")
                        .entered();
                let mut transactions = Vec::new();
                let mut senders = Vec::new();

                let mut transactions_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_bloom = Bloom::ZERO;
                let mut encoded_block_transactions = EncodedBlockTransactionsBuilder::default();

                let mut buf = Vec::new();

                for (tx, receipt) in transactions_rx.into_iter() {
                    let (tx, sender) = tx.transaction.inner().clone().into_parts();
                    buf.clear();
                    tx.encode_2718(&mut buf);
                    transactions_root.push_next(&buf);
                    encoded_block_transactions.push(&tx, &buf);
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
}

/// Overrides the block's fee recipient (beneficiary) with the value from the
/// V2 validator config contract, if the contract is active and returns a
/// non-zero address for the given `public_key`.
fn maybe_override_fee_recipient<DB: Database>(
    db: &mut DB,
    evm_env: &mut reth_evm::EvmEnvFor<TempoEvmConfig>,
    attributes: &TempoPayloadAttributes,
) {
    let Some(public_key) = attributes.proposer_public_key() else {
        return;
    };
    // T14+ executors reject blocks whose beneficiary differs from this resolution.
    match db.proposer_fee_recipient(evm_env.spec, evm_env.block.number, *public_key) {
        Ok(Some(fee_recipient)) => {
            debug!(%fee_recipient, "resolved fee recipient from contract");
            evm_env.block.beneficiary = fee_recipient;
        }
        Ok(None) => {}
        Err(err) => {
            warn!(%err, "failed resolving fee recipient from contract; using fallback");
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

    #[test]
    fn test_extra_data_flow_in_attributes() {
        // Test that extra_data in attributes can be accessed correctly
        let extra_data = Bytes::from(vec![42, 43, 44, 45, 46]);

        let attrs = TempoPayloadAttributes::new(None, 1, 0, extra_data.clone(), None);

        assert_eq!(attrs.extra_data(), &extra_data);

        // Verify the data is as expected
        let injected_data = attrs.extra_data().clone();

        assert_eq!(injected_data, extra_data);
    }

    /// The discard budget of a payload with a 30M general lane.
    const DISCARD: u64 = 30_000_000;

    /// Lanes with the failed check budget unspent.
    fn lanes(general_gas_left: u64, registered_gas_left: u64, discard_gas_left: u64) -> LaneState {
        LaneState {
            general_gas_left,
            registered_gas_left,
            discard_gas_left,
            failed_check_gas_left: DISCARD,
        }
    }

    #[test]
    fn test_lane_admission_by_gas_limit_before_t16() {
        use tempo_chainspec::hardfork::TempoHardfork;

        for hardfork in [TempoHardfork::T5, TempoHardfork::T15] {
            let state = lanes(1_000_000, 0, DISCARD);
            assert_eq!(
                lane_admission(hardfork, TxLane::General, 1_000_000, &state),
                LaneAdmission::Fits
            );
            assert_eq!(
                lane_admission(hardfork, TxLane::General, 1_000_001, &state),
                LaneAdmission::Full
            );
            assert_eq!(
                lane_admission(hardfork, TxLane::Payment, 30_000_000, &lanes(0, 0, 0)),
                LaneAdmission::Fits
            );
        }
    }

    #[test]
    fn test_lane_admission_by_gas_used_from_t16() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let t16 = TempoHardfork::T16;
        let general = |limit, gas_left, discard| {
            lane_admission(t16, TxLane::General, limit, &lanes(gas_left, 0, discard))
        };
        assert_eq!(general(1_000_000, 1_000_000, DISCARD), LaneAdmission::Fits);
        // A gas limit past the lane's remaining gas is tried and kept only if its gas used fits.
        assert_eq!(
            general(1_193_565, 1_000_000, DISCARD),
            LaneAdmission::ByGasUsed
        );
        assert_eq!(
            general(1_193_565, MIN_TRANSACTION_GAS, DISCARD),
            LaneAdmission::ByGasUsed
        );
        // Below the least gas any transaction uses, the lane is full.
        assert_eq!(
            general(1_193_565, MIN_TRANSACTION_GAS - 1, DISCARD),
            LaneAdmission::Full
        );
        assert_eq!(general(21_000, 0, DISCARD), LaneAdmission::Full);
        assert_eq!(
            lane_admission(t16, TxLane::Payment, 30_000_000, &lanes(0, 0, 0)),
            LaneAdmission::Fits
        );
        // It is tried only while the discard budget covers its whole gas limit.
        assert_eq!(
            general(1_193_565, 1_000_000, 1_193_565),
            LaneAdmission::ByGasUsed
        );
        assert_eq!(
            general(1_193_565, 1_000_000, 1_193_564),
            LaneAdmission::Full
        );
        assert_eq!(general(1_000_000, 1_000_000, 0), LaneAdmission::Fits);
    }

    /// With both lanes nearly full, discarded executions are bounded by gas, not by count: a
    /// payload executes at most one general lane's worth of transactions it then leaves out.
    #[test]
    fn test_discarded_execution_bounded_by_gas() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let cap = 30_000_000u64;
        let mut discarded = 0u64;
        let mut tries = 0;
        for lane in [TxLane::General, TxLane::RegisteredPayment] {
            loop {
                let state = lanes(
                    MIN_TRANSACTION_GAS,
                    MIN_TRANSACTION_GAS,
                    DISCARD - discarded,
                );
                match lane_admission(TempoHardfork::T17, lane, cap, &state) {
                    LaneAdmission::ByGasUsed => {
                        // A loop burns the whole gas limit; the builder leaves it out.
                        discarded += cap;
                        tries += 1;
                    }
                    LaneAdmission::Full => break,
                    LaneAdmission::Fits => unreachable!(),
                }
            }
        }
        assert_eq!(tries, 1);
        assert_eq!(discarded, DISCARD);
        // Smaller transactions keep being tried until the budget runs out.
        let state = lanes(MIN_TRANSACTION_GAS, MIN_TRANSACTION_GAS, 1_500_000);
        assert_eq!(
            lane_admission(
                TempoHardfork::T17,
                TxLane::RegisteredPayment,
                1_500_000,
                &state
            ),
            LaneAdmission::ByGasUsed
        );
    }

    #[test]
    fn test_registered_payments_admitted_against_their_own_budget() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let t17 = TempoHardfork::T17;
        // A registered payment ignores the general lane and fills the registered budget, even
        // with the discard budget spent.
        let state = lanes(0, 1_200_000, 0);
        assert_eq!(
            lane_admission(t17, TxLane::RegisteredPayment, 1_193_565, &state),
            LaneAdmission::Fits
        );
        assert_eq!(
            lane_admission(t17, TxLane::General, 21_000, &state),
            LaneAdmission::Full
        );
        // Past its remaining gas it is admitted by gas used, from the shared discard budget.
        let state = lanes(0, 1_000_000, DISCARD);
        assert_eq!(
            lane_admission(t17, TxLane::RegisteredPayment, 1_193_565, &state),
            LaneAdmission::ByGasUsed
        );
        let state = lanes(0, 1_000_000, 1_000_000);
        assert_eq!(
            lane_admission(t17, TxLane::RegisteredPayment, 1_193_565, &state),
            LaneAdmission::Full
        );
        // TIP-1045 payments are never limited by either budget.
        assert_eq!(
            lane_admission(t17, TxLane::Payment, 30_000_000, &lanes(0, 0, 0)),
            LaneAdmission::Fits
        );
    }

    #[test]
    fn test_demoted_instances_expire_and_restore() {
        let program = Address::repeat_byte(0x52);
        let call = aa(&[program], 1_500_000);
        let demoted = DemotedInstances::default();
        assert!(!demoted.any_demoted(&call, 10));
        demoted.demote(program, 10);
        assert!(demoted.any_demoted(&call, 10));
        assert!(demoted.any_demoted(&call, 10 + DEMOTION_BLOCKS - 1));
        assert!(!demoted.any_demoted(&call, 10 + DEMOTION_BLOCKS));
        // A passing payment in the block of the failure restores nothing; one in a later block
        // does.
        demoted.restore(&call, 10);
        assert!(demoted.any_demoted(&call, 10));
        demoted.restore(&call, 11);
        assert!(!demoted.any_demoted(&call, 11));
    }

    /// An instance that keeps failing stays demoted longer each time: a passing payment restores
    /// it only after a back-off that doubles with each failure, until the failures are
    /// [`DEMOTION_BLOCKS`] apart.
    #[test]
    fn test_demoted_instances_back_off() {
        let program = Address::repeat_byte(0x52);
        let call = aa(&[program], 1_500_000);
        let demoted = DemotedInstances::default();
        let mut block = 100;
        for back_off in [1, 2, 4, 8, 16] {
            demoted.demote(program, block);
            demoted.restore(&call, block + back_off - 1);
            assert!(
                demoted.any_demoted(&call, block + back_off - 1),
                "{back_off}"
            );
            block += back_off;
            demoted.restore(&call, block);
            assert!(!demoted.any_demoted(&call, block), "{back_off}");
        }
        // The back-off never passes the demotion window.
        for _ in 0..40 {
            demoted.demote(program, block);
        }
        demoted.restore(&call, block + DEMOTION_BLOCKS - 1);
        assert!(demoted.any_demoted(&call, block + DEMOTION_BLOCKS - 1));
        demoted.restore(&call, block + DEMOTION_BLOCKS);
        assert!(!demoted.any_demoted(&call, block + DEMOTION_BLOCKS));
        // A failure after a quiet window starts over.
        block += 2 * DEMOTION_BLOCKS;
        demoted.demote(program, block);
        demoted.restore(&call, block + 1);
        assert!(!demoted.any_demoted(&call, block + 1));
    }

    /// Once registered payments that fail the execution check have used the failed check budget,
    /// a registered payment is admitted only if it would fit the general lane should it fail too.
    /// The general lane and the discard budget never keep it out on their own.
    #[test]
    fn test_registered_payments_within_the_failed_check_budget() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let t17 = TempoHardfork::T17;
        let admission = |general_gas_left, failed_check_gas_left, gas_limit| {
            let lanes = LaneState {
                general_gas_left,
                registered_gas_left: REGISTERED,
                discard_gas_left: 0,
                failed_check_gas_left,
            };
            lane_admission(t17, TxLane::RegisteredPayment, gas_limit, &lanes)
        };
        assert_eq!(admission(0, DISCARD, 30_000_000), LaneAdmission::Fits);
        assert_eq!(admission(0, 1_500_000, 1_500_000), LaneAdmission::Fits);
        assert_eq!(admission(0, 1_499_999, 1_500_000), LaneAdmission::Full);
        assert_eq!(admission(1_500_000, 0, 1_500_000), LaneAdmission::Fits);
        assert_eq!(admission(1_499_999, 0, 1_500_000), LaneAdmission::Full);
        // General transactions never draw on it.
        let lanes = LaneState {
            general_gas_left: 1_500_000,
            registered_gas_left: REGISTERED,
            discard_gas_left: 0,
            failed_check_gas_left: 0,
        };
        assert_eq!(
            lane_admission(t17, TxLane::General, 1_500_000, &lanes),
            LaneAdmission::Fits
        );
    }

    const GENERAL: u64 = 30_000_000;
    const REGISTERED: u64 = 250_000_000;

    fn aa(targets: &[Address], gas_limit: u64) -> TempoTxEnvelope {
        use tempo_primitives::{TempoTransaction, transaction::Call};

        TempoTxEnvelope::AA(
            TempoTransaction {
                calls: targets
                    .iter()
                    .map(|to| Call::new(*to, Bytes::from_static(&[0xca, 0x89, 0xe4, 0x14])))
                    .collect(),
                gas_limit,
                ..Default::default()
            }
            .into_signed(alloy_primitives::Signature::test_signature().into()),
        )
    }

    /// The payload loop's admission for a transaction the pool classified as a registered payment.
    fn admitted_lane(demoted: &DemotedInstances, tx: &TempoTxEnvelope, block: u64) -> TxLane {
        if demoted.any_demoted(tx, block) {
            TxLane::General
        } else {
            TxLane::RegisteredPayment
        }
    }

    /// Alternating cheap passing payments to an instance with expensive ones that fail the
    /// execution check, in the payload loop's order: the passing payments cannot restore the
    /// instance in the block it failed in, and the failing ones stay within the failed check
    /// budget, so the payload executes at most one budget of gas it leaves out.
    #[test]
    fn test_alternating_failures_stay_within_the_failed_check_budget() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let t17 = TempoHardfork::T17;
        let block = 1_000;
        let program = Address::repeat_byte(0x77);
        let demoted = DemotedInstances::default();
        // One ordinary general transaction is already in the block.
        let general_used = 1_000_000u64;
        let mut discarded = 0u64;
        let mut failed_check = 0u64;
        let mut registered_used = 0u64;
        let lanes = |registered_used: u64, discarded: u64, failed_check: u64| LaneState {
            general_gas_left: GENERAL - general_used,
            registered_gas_left: REGISTERED - registered_used,
            discard_gas_left: DISCARD.saturating_sub(discarded),
            failed_check_gas_left: DISCARD.saturating_sub(failed_check),
        };

        for pair in 0..20 {
            // A cheap payment that passes the check is admitted and included.
            let passing = aa(&[program], 50_000);
            let lane = admitted_lane(&demoted, &passing, block);
            assert_eq!(
                lane_admission(
                    t17,
                    lane,
                    50_000,
                    &lanes(registered_used, discarded, failed_check)
                ),
                LaneAdmission::Fits,
                "pair {pair}"
            );
            registered_used += 40_000;
            demoted.restore(&passing, block);

            // An expensive payment to the same instance that fails the check.
            let failing = aa(&[program; 20], 30_000_000);
            let lane = admitted_lane(&demoted, &failing, block);
            match lane_admission(
                t17,
                lane,
                30_000_000,
                &lanes(registered_used, discarded, failed_check),
            ) {
                LaneAdmission::Full => continue,
                LaneAdmission::ByGasUsed => panic!("pair {pair}: no discard budget is left"),
                LaneAdmission::Fits => {}
            }
            // The executor: the general lane after the check, 30M used past the 29M left.
            let exceeded = LaneGasExceeded {
                lane: TxLane::General,
                gas_used: 30_000_000,
                failed_instance: Some(program),
            };
            discarded += exceeded.gas_used;
            failed_check += exceeded.gas_used;
            demoted.demote(program, block);
        }
        assert_eq!(failed_check, DISCARD);
        assert_eq!(discarded, DISCARD);

        // In the next block a passing payment restores the instance, and a failing one is tried
        // again against that payload's own budget.
        let passing = aa(&[program], 50_000);
        demoted.restore(&passing, block + 1);
        assert!(!demoted.any_demoted(&passing, block + 1));
    }

    /// A payment that fails the check names only the instance whose code made the call the check
    /// did not allow: another instance it also calls keeps its registered payments in their lane.
    #[test]
    fn test_failed_check_demotes_only_the_failing_instance() {
        use tempo_chainspec::hardfork::TempoHardfork;

        let t17 = TempoHardfork::T17;
        let block = 1_000;
        let honest = Address::repeat_byte(0x11);
        let failing = Address::repeat_byte(0x77);
        let demoted = DemotedInstances::default();

        let bundle = aa(&[failing, honest], 3_000_000);
        assert_eq!(
            admitted_lane(&demoted, &bundle, block),
            TxLane::RegisteredPayment
        );
        let exceeded = LaneGasExceeded {
            lane: TxLane::General,
            gas_used: 3_000_000,
            failed_instance: Some(failing),
        };
        demoted.demote(exceeded.failed_instance.unwrap(), block);

        let swipe = aa(&[honest], 1_500_000);
        let lane = admitted_lane(&demoted, &swipe, block);
        assert_eq!(lane, TxLane::RegisteredPayment);
        let lanes = LaneState {
            general_gas_left: 1_000_000,
            registered_gas_left: REGISTERED,
            discard_gas_left: 0,
            failed_check_gas_left: DISCARD - exceeded.gas_used,
        };
        assert_eq!(
            lane_admission(t17, lane, 1_500_000, &lanes),
            LaneAdmission::Fits
        );
        // The failing instance, and any bundle calling it, is admitted as general.
        assert!(demoted.any_demoted(&aa(&[failing], 50_000), block));
        assert!(demoted.any_demoted(&bundle, block + DEMOTION_BLOCKS - 1));
    }
}
