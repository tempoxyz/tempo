//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod budget;
mod encode;
mod metrics;
mod prewarming;

pub use budget::DEFAULT_BUILD_TIME_MULTIPLIER;
use crossbeam_channel::Sender;
use reth_trie_common::ordered_root::OrderedTrieRootEncodedBuilder;

use crate::{
    budget::{
        BUILD_TIME_MULTIPLIER_SCALE, decay_build_time_multiplier, observed_build_time_multiplier,
        payload_budget_decision, scaled_build_time_multiplier,
    },
    encode::{EncodedBlockTransactionList, EncodedBlockTransactionsBuilder, ExecutionBlockEncoder},
    metrics::{BlockBuildStopReason, InstrumentedFinishProvider, TempoPayloadBuilderMetrics},
    prewarming::BestTransactionsPrewarming,
};
use alloy_consensus::{BlockHeader as _, Signed, Transaction as _, TxLegacy, TxReceipt};
use alloy_eip7928::bal::Bal;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bloom, Bytes, U256, keccak256};
use alloy_rlp::{Decodable, Encodable};
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
    ConfigureEvm, Database, Evm, NextBlockEnvAttributes, OnStateHook,
    block::{BlockExecutionError, BlockExecutor, BlockValidationError},
    execute::BlockAssemblerInput,
};
use reth_execution_types::BlockExecutionOutput;
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{
    Recovered, RecoveredBlock, transaction::error::InvalidTransactionError,
};
use reth_revm::{
    State, context::Block, database::StateProviderDatabase,
    db::states::bundle_state::BundleRetention, state::EvmState,
};
use reth_storage_api::{HashedPostStateProvider, StateProviderFactory, StateRootProvider};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction, TransactionPool,
    ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes, TempoStateAccess, evm::TempoEvm};
use tempo_payload_types::{
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
}

impl Default for TempoPayloadBuilderConfig {
    fn default() -> Self {
        Self {
            is_dev: false,
            state_provider_metrics: false,
            enable_prewarming: true,
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
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
            ..
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
        let mut estimated_rlp_block_size = attributes
            .withdrawals
            .as_ref()
            .map(|w| w.length())
            .unwrap_or(0)
            + NON_TRANSACTION_SIZE_ESTIMATE
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
        }

        check_cancel!();

        debug!("building new payload");

        let (roots_tx, roots_rx) = self.spawn_roots_task();

        // Prepare system transactions before actual block building and account for their size.
        let prepare_system_txs_start = Instant::now();
        let system_txs = self.build_seal_block_txs(executor.evm(), &subblocks);
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
        let mut best_txs = StateAwareBestTransactions::new(if self.enable_prewarming {
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
        let validation_latency = attributes.validation_latency_estimate();
        let block_build_stop_reason = loop {
            check_cancel!();

            if let Some(build_budget) = payload_build_budget {
                let elapsed = start.elapsed();
                let current_workload = ValidationLatencyWorkload::new(
                    cumulative_gas_used,
                    pool_transactions_included as usize,
                );
                let budget_decision = payload_budget_decision(
                    elapsed,
                    normal_transaction_fill_idle_elapsed,
                    build_time_multiplier,
                    marshal_persist,
                    estimated_rlp_block_size,
                    validation_latency,
                    current_workload,
                );
                if budget_decision.total_reserved >= build_budget {
                    debug!(
                        target: "payload_builder",
                        ?elapsed,
                        ?normal_transaction_fill_idle_elapsed,
                        ?build_budget,
                        predicted_builder_work = ?budget_decision.predicted_builder_work,
                        predicted_validator_work = ?budget_decision.predicted_validator_work,
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
                .then(|| format!("{:?}", pool_tx.transaction))
                .unwrap_or_default();

            let execution_result = executor.execute_transaction_with_result_closure(
                pool_tx.transaction.executable(),
                |result| {
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
                },
            );
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
            if let Some(bal_task_handle) = &bal_task_handle {
                bal_task_handle.bump_bal_index();
            }

            pool_transactions_included += 1;
            estimated_rlp_block_size += tx_rlp_length;
            let _ = roots_tx.send((
                BuilderTx::Pooled(pool_tx),
                executor.receipts().last().unwrap().clone(),
            ));
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
                if let Some(bal_task_handle) = &bal_task_handle {
                    bal_task_handle.bump_bal_index();
                }

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
            if let Some(bal_task_handle) = &bal_task_handle {
                bal_task_handle.bump_bal_index();
            }

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

        let (block_access_list, block_access_list_hash) = if let Some(bal_rx) = bal_rx {
            let (bal, bal_hash) = bal_rx.blocking_recv().map_err(PayloadBuilderError::other)?;
            (Some(bal), Some(bal_hash))
        } else {
            (None, None)
        };

        let (state_root, trie_updates) = if let Some(outcome) = state_root_outcome {
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
            ?validation_latency_duration,
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
        if build_once_with_shared_trie {
            Ok(BuildOutcome::Freeze(payload))
        } else {
            Ok(BuildOutcome::Better {
                payload,
                cached_reads,
            })
        }
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
            .spawn_blocking_named("builder-roots-task", || {
                let mut transactions = Vec::new();
                let mut senders = Vec::new();

                let mut transactions_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_root = OrderedTrieRootEncodedBuilder::new();
                let mut receipts_bloom = Bloom::ZERO;
                let mut encoded_block_transactions = EncodedBlockTransactionsBuilder::default();

                let mut buf = Vec::new();

                for (tx, receipt) in transactions_rx.into_iter() {
                    let (tx, sender) = tx.into_parts();
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

    fn spawn_bal_task(&self, mut state_root_task_hook: Option<impl OnStateHook>) -> BalTaskHandle {
        let (task_tx, task_rx) = mpsc::channel::<BalMessage>();
        let (bal_tx, bal_rx) = oneshot::channel();
        self.executor.spawn_blocking_named("builder-bal-task", || {
            let mut bal_state =
                reth_revm::database_interface::bal::BalState::new().with_bal_builder();
            for msg in task_rx {
                match msg {
                    BalMessage::BumpIndex => {
                        bal_state.bump_bal_index();
                    }
                    BalMessage::State(state) => {
                        bal_state.commit(&state);
                        if let Some(state_root_task_hook) = &mut state_root_task_hook {
                            state_root_task_hook.on_state(state);
                        }
                    }
                }
            }

            drop(state_root_task_hook);
            let bal: Bal = bal_state.take_built_alloy_bal().unwrap().into();
            let mut encoded = Vec::new();
            bal.encode(&mut encoded);
            let bal_hash = keccak256(&encoded);

            let _ = bal_tx.send((encoded.into(), bal_hash));
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

    fn bump_bal_index(&self) {
        let _ = self.msg_tx.send(BalMessage::BumpIndex);
    }

    fn into_bal_rx(self) -> oneshot::Receiver<(Bytes, B256)> {
        self.bal_rx
    }
}

enum BalMessage {
    State(EvmState),
    BumpIndex,
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
    use tempo_payload_types::EncodedBlock;
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
