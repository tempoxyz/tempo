//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod metrics;

use crate::metrics::{InstrumentedFinishProvider, TempoPayloadBuilderMetrics};
use alloy_consensus::{BlockHeader as _, Signed, Transaction, TxLegacy};
use alloy_primitives::{Address, U256};
use alloy_rlp::{Decodable, Encodable};
use either::Either;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
    is_better_payload,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_engine_tree::tree::instrumented_state::InstrumentedStateProvider;
use reth_errors::{ConsensusError, ProviderError};
use reth_evm::{
    ConfigureEvm, Database, Evm, NextBlockEnvAttributes,
    block::{BlockExecutionError, BlockExecutor, BlockValidationError},
    execute::{BlockBuilder, BlockBuilderOutcome},
};
use reth_execution_types::BlockExecutionOutput;
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{Recovered, transaction::error::InvalidTransactionError};
use reth_revm::{
    State,
    context::{Block, BlockEnv},
    database::StateProviderDatabase,
};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, TransactionPool, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_consensus::TEMPO_SHARED_GAS_DIVISOR;
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes, evm::TempoEvm};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tempo_precompiles::{
    storage::StorageCtx, tip_fee_manager::TipFeeManager, validator_config_v2::ValidatorConfigV2,
};
use tempo_primitives::{
    RecoveredSubBlock, SubBlockMetadata, TempoHeader, TempoTxEnvelope,
    subblock::PartialValidatorKey,
    transaction::{
        calc_gas_balance_spending,
        envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
    },
};
use tempo_transaction_pool::{
    TempoTransactionPool,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use tracing::{Level, debug, debug_span, error, info, instrument, trace, warn};

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
pub struct TempoPayloadBuilder<Provider> {
    pool: TempoTransactionPool<Provider>,
    provider: Provider,
    evm_config: TempoEvmConfig,
    metrics: TempoPayloadBuilderMetrics,
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
    /// Whether to disable state cache.
    disable_state_cache: bool,
}

impl<Provider> TempoPayloadBuilder<Provider> {
    pub fn new(
        pool: TempoTransactionPool<Provider>,
        provider: Provider,
        evm_config: TempoEvmConfig,
        is_dev: bool,
        state_provider_metrics: bool,
        disable_state_cache: bool,
    ) -> Self {
        Self {
            pool,
            provider,
            evm_config,
            metrics: TempoPayloadBuilderMetrics::default(),
            highest_invalid_subblock: Default::default(),
            is_dev,
            state_provider_metrics,
            disable_state_cache,
        }
    }
}

impl<Provider: ChainSpecProvider<ChainSpec = TempoChainSpec>> TempoPayloadBuilder<Provider> {
    /// Builds system transactions to seal the block.
    ///
    /// Returns a vector of system transactions that must be executed at the end of each block:
    /// - Subblocks signatures - validates subblock signatures
    fn build_seal_block_txs(
        &self,
        block_env: &BlockEnv,
        subblocks: &[RecoveredSubBlock],
    ) -> Vec<Recovered<TempoTxEnvelope>> {
        let chain_spec = self.provider.chain_spec();
        let chain_id = Some(chain_spec.chain().id());

        // Build subblocks signatures system transaction
        let subblocks_metadata = subblocks
            .iter()
            .map(|s| s.metadata())
            .collect::<Vec<SubBlockMetadata>>();
        let subblocks_input = alloy_rlp::encode(&subblocks_metadata)
            .into_iter()
            .chain(block_env.number.to_be_bytes_vec())
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
    Provider: StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec>,
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
        Txs: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    {
        let BuildArguments {
            mut cached_reads,
            trie_handle,
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
        let build_until_interrupt =
            // When trie handle is provided, we only build the payload once, until the interrupt is triggered
            trie_handle.is_some()
            // `--dev` mode doesn't have payload building interrupts
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
        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let state_provider: Box<dyn StateProvider> = if self.state_provider_metrics {
            Box::new(InstrumentedStateProvider::new(state_provider, "builder"))
        } else {
            state_provider
        };
        let state = StateProviderDatabase::new(&state_provider);
        let mut db = State::builder()
            .with_database(if self.disable_state_cache {
                Box::new(state) as Box<dyn Database<Error = ProviderError>>
            } else {
                Box::new(cached_reads.as_db_mut(state))
            })
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
        let shared_gas_limit = block_gas_limit / TEMPO_SHARED_GAS_DIVISOR;
        // Non-shared gas limit is the maximum gas available for proposer's pool transactions.
        // The remaining `shared_gas_limit` is reserved for validator subblocks.
        let non_shared_gas_limit = block_gas_limit - shared_gas_limit;
        let general_gas_limit = chain_spec.general_gas_limit_at(
            attributes.timestamp,
            block_gas_limit,
            shared_gas_limit,
        );

        let mut cumulative_gas_used = 0;
        let mut non_payment_gas_used = 0;
        // initial block size usage - size of withdrawals plus 1Kb of overhead for the block header
        let mut block_size_used = attributes
            .withdrawals
            .as_ref()
            .map(|w| w.length())
            .unwrap_or(0)
            + 1024;
        let mut payment_transactions = 0u64;
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

        let mut builder = self
            .evm_config
            .builder_for_next_block(
                &mut db,
                &parent_header,
                TempoNextBlockEnvAttributes {
                    inner: NextBlockEnvAttributes {
                        timestamp: attributes.timestamp,
                        suggested_fee_recipient: attributes.suggested_fee_recipient,
                        prev_randao: attributes.prev_randao,
                        gas_limit: block_gas_limit,
                        parent_beacon_block_root: attributes.parent_beacon_block_root,
                        withdrawals: attributes.withdrawals.clone().map(Into::into),
                        extra_data: attributes.extra_data().clone(),
                    },
                    general_gas_limit,
                    shared_gas_limit,
                    timestamp_millis_part: attributes.timestamp_millis_part(),
                    subblock_fee_recipients,
                },
            )
            .map_err(PayloadBuilderError::other)?;

        check_cancel!();

        // Override the fee recipient with the on-chain value from the V2
        // validator config contract, if available.
        maybe_override_fee_recipient(&mut builder, &attributes);

        if let Some(ref handle) = trie_handle {
            builder
                .executor_mut()
                .set_state_hook(Some(Box::new(handle.state_hook())));
        }

        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        check_cancel!();

        debug!("building new payload");

        // Prepare system transactions before actual block building and account for their size.
        let prepare_system_txs_start = Instant::now();
        let system_txs = self.build_seal_block_txs(builder.evm().block(), &subblocks);
        for tx in &system_txs {
            block_size_used += tx.inner().length();
        }
        let prepare_system_txs_elapsed = prepare_system_txs_start.elapsed();
        self.metrics
            .prepare_system_transactions_duration_seconds
            .record(prepare_system_txs_elapsed);

        let base_fee = builder.evm_mut().block().basefee;
        let validator_fee_token = resolve_validator_fee_token(&mut builder)?;
        let pool_fetch_start = Instant::now();
        let mut best_txs = best_txs(BestTransactionsAttributes::new(
            base_fee,
            builder
                .evm_mut()
                .block()
                .blob_gasprice()
                .map(|gasprice| gasprice as u64),
        ));
        self.metrics
            .pool_fetch_duration_seconds
            .record(pool_fetch_start.elapsed());

        let execution_start = Instant::now();
        let _block_fill_span = debug_span!(target: "payload_builder", "block_fill").entered();
        loop {
            if attributes.is_interrupted() {
                break;
            }

            check_cancel!();

            let Some(pool_tx) = best_txs.next() else {
                if build_until_interrupt && cumulative_gas_used < non_shared_gas_limit {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                break;
            };

            // Ensure we still have capacity for this transaction within the non-shared gas limit.
            // The remaining `shared_gas_limit` is reserved for validator subblocks and must not
            // be consumed by proposer's pool transactions.
            if cumulative_gas_used + pool_tx.gas_limit() > non_shared_gas_limit {
                // Mark this transaction as invalid since it doesn't fit
                // The iterator will handle lane switching internally when appropriate
                best_txs.mark_invalid(
                    &pool_tx,
                    &InvalidPoolTransactionError::ExceedsGasLimit(
                        pool_tx.gas_limit(),
                        non_shared_gas_limit - cumulative_gas_used,
                    ),
                );
                self.metrics
                    .inc_pool_tx_skipped("exceeds_non_shared_gas_limit");
                continue;
            }

            // If the tx is not a payment and will exceed the general gas limit
            // mark the tx as invalid and continue
            if !pool_tx.transaction.is_payment()
                && non_payment_gas_used + pool_tx.gas_limit() > general_gas_limit
            {
                best_txs.mark_invalid(
                    &pool_tx,
                    &InvalidPoolTransactionError::Other(Box::new(
                        TempoPoolTransactionError::ExceedsNonPaymentLimit,
                    )),
                );
                self.metrics
                    .inc_pool_tx_skipped("exceeds_general_gas_limit");
                continue;
            }

            // check if the job was interrupted, if so we can skip remaining transactions
            if attributes.is_interrupted() {
                break;
            }

            check_cancel!();
            let is_payment = pool_tx.transaction.is_payment();
            if is_payment {
                payment_transactions += 1;
            }

            let tx_rlp_length = pool_tx.transaction.inner().length();
            let estimated_block_size_with_tx = block_size_used + tx_rlp_length;

            if is_osaka && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE {
                best_txs.mark_invalid(
                    &pool_tx,
                    &InvalidPoolTransactionError::OversizedData {
                        size: estimated_block_size_with_tx,
                        limit: MAX_RLP_BLOCK_SIZE,
                    },
                );
                self.metrics.inc_pool_tx_skipped("oversized_block");
                continue;
            }

            let effective_gas_price = pool_tx.transaction.effective_gas_price(Some(base_fee));

            let tx_debug_repr = tracing::enabled!(Level::TRACE)
                .then(|| format!("{:?}", pool_tx.transaction))
                .unwrap_or_default();

            let tx_with_env = pool_tx.transaction.clone().into_with_tx_env();
            let tx_execution_start = Instant::now();
            let gas_used = match builder.execute_transaction(tx_with_env) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
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
                            &InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::TxTypeNotSupported,
                            ),
                        );
                        self.metrics.inc_pool_tx_skipped("invalid_tx");
                    }
                    continue;
                }
                // this is an error that we should treat as fatal for this attempt
                Err(err) => return Err(PayloadBuilderError::evm(err)),
            };
            let elapsed = tx_execution_start.elapsed();
            self.metrics
                .transaction_execution_duration_seconds
                .record(elapsed);
            trace!(?elapsed, "Transaction executed");

            // Score payload value by actual validator payout, applying the AMM
            // haircut when the transaction's fee token differs from the validator's.
            let nominal_spending = calc_gas_balance_spending(gas_used, effective_gas_price);
            if let Some(fee_token) = pool_tx.transaction.resolved_fee_token() {
                if fee_token == validator_fee_token {
                    total_fees += nominal_spending;
                } else {
                    total_fees += tempo_precompiles::tip_fee_manager::amm::compute_amount_out(
                        nominal_spending,
                    )
                    .map_err(PayloadBuilderError::other)?;
                }
            } else {
                warn!("no resolved fee token for a pool transaction")
            }
            cumulative_gas_used += gas_used;
            if !is_payment {
                non_payment_gas_used += gas_used;
            }
            block_size_used += tx_rlp_length;
        }
        drop(_block_fill_span);
        let total_normal_transaction_execution_elapsed = execution_start.elapsed();
        self.metrics
            .total_normal_transaction_execution_duration_seconds
            .record(total_normal_transaction_execution_elapsed);
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
            drop(builder);
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
        for subblock in &subblocks {
            let subblock_start = Instant::now();
            let mut subblock_tx_count = 0f64;

            for tx in subblock.transactions_recovered() {
                if let Err(err) = builder.execute_transaction(tx.cloned()) {
                    if let BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                        ..
                    }) = &err
                    {
                        error!(
                            ?err,
                            "subblock transaction failed execution, aborting payload building"
                        );
                        self.highest_invalid_subblock
                            .store(builder.evm().block().number.to(), Ordering::Relaxed);
                        self.metrics.inc_build_failure("subblock_invalid_tx");
                        return Err(PayloadBuilderError::evm(err));
                    } else {
                        return Err(PayloadBuilderError::evm(err));
                    }
                }

                subblock_tx_count += 1.0;
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
            builder
                .execute_transaction(system_tx)
                .map_err(PayloadBuilderError::evm)?;
        }
        drop(_system_txs_span);
        let system_txs_execution_elapsed = system_txs_execution_start.elapsed();
        self.metrics
            .system_transactions_execution_duration_seconds
            .record(system_txs_execution_elapsed);

        let total_transaction_execution_elapsed = execution_start.elapsed();
        self.metrics
            .total_transaction_execution_duration_seconds
            .record(total_transaction_execution_elapsed);

        let builder_finish_start = Instant::now();
        let _finish_span = debug_span!(target: "payload_builder", "finish_block").entered();
        let finish_provider = || InstrumentedFinishProvider {
            inner: &*state_provider,
            metrics: self.metrics.clone(),
        };

        check_cancel!();

        let BlockBuilderOutcome {
            execution_result,
            block,
            hashed_state,
            trie_updates,
        } = if let Some(mut handle) = trie_handle {
            // Dropping the hook signals that execution is complete and the sparse trie task can
            // finalize the state root it has been updating incrementally.
            builder.executor_mut().set_state_hook(None);

            match handle.state_root() {
                Ok(outcome) => {
                    debug!(
                        target: "payload_builder",
                        id = %payload_id,
                        state_root = ?outcome.state_root,
                        "received state root from sparse trie"
                    );
                    builder.finish(
                        finish_provider(),
                        Some((
                            outcome.state_root,
                            Arc::unwrap_or_clone(outcome.trie_updates),
                        )),
                    )?
                }
                Err(err) => {
                    warn!(
                        target: "payload_builder",
                        id = %payload_id,
                        %err,
                        "sparse trie failed, falling back to sync state root"
                    );
                    builder.finish(finish_provider(), None)?
                }
            }
        } else {
            builder.finish(finish_provider(), None)?
        };
        drop(_finish_span);
        let builder_finish_elapsed = builder_finish_start.elapsed();
        self.metrics
            .payload_finalization_duration_seconds
            .record(builder_finish_elapsed);

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

        let sealed_block = Arc::new(block.sealed_block().clone());
        let rlp_length = sealed_block.rlp_length();

        if is_osaka && rlp_length > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length,
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        let elapsed = start.elapsed();
        self.metrics.payload_build_duration_seconds.record(elapsed);
        let gas_per_second = sealed_block.gas_used() as f64 / elapsed.as_secs_f64();
        self.metrics.gas_per_second.record(gas_per_second);
        self.metrics.gas_per_second_last.set(gas_per_second);
        self.metrics.rlp_block_size_bytes.record(rlp_length as f64);
        self.metrics
            .rlp_block_size_bytes_last
            .set(rlp_length as f64);

        info!(
            parent_hash = ?sealed_block.parent_hash(),
            number = sealed_block.number(),
            hash = ?sealed_block.hash(),
            timestamp = sealed_block.timestamp_millis(),
            gas_limit = sealed_block.gas_limit(),
            gas_used,
            extra_data = %sealed_block.extra_data(),
            subblocks_count,
            payment_transactions,
            subblock_transactions,
            total_transactions,
            ?elapsed,
            ?total_normal_transaction_execution_elapsed,
            ?total_subblock_transaction_execution_elapsed,
            ?total_transaction_execution_elapsed,
            ?builder_finish_elapsed,
            "Built payload"
        );

        let eth_payload = EthBuiltPayload::new(sealed_block, total_fees, requests);

        let execution_output = BlockExecutionOutput {
            result: execution_result,
            state: db.take_bundle(),
        };

        let executed_block = BuiltPayloadExecutedBlock {
            recovered_block: Arc::new(block),
            execution_output: Arc::new(execution_output),
            hashed_state: Either::Left(Arc::new(hashed_state)),
            trie_updates: Either::Left(Arc::new(trie_updates)),
        };

        let payload = TempoBuiltPayload::new(eth_payload, Some(executed_block));

        drop(db);
        if build_until_interrupt {
            Ok(BuildOutcome::Freeze(payload))
        } else {
            Ok(BuildOutcome::Better {
                payload,
                cached_reads,
            })
        }
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
    builder: &mut impl BlockBuilder<Executor: BlockExecutor<Evm = TempoEvm<DB>>>,
    attributes: &TempoPayloadAttributes,
) {
    let Some(public_key) = attributes.proposer_public_key() else {
        return;
    };
    let ctx = builder.evm_mut().ctx_mut();
    if !ctx.cfg.spec.is_t2() {
        return;
    }
    let parent_number = ctx.block.number.saturating_to::<u64>() - 1;
    match StorageCtx::enter_ctx(ctx, || -> Result<Option<Address>, PayloadBuilderError> {
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
    }) {
        Ok(Some(fee_recipient)) => {
            debug!(%fee_recipient, "resolved fee recipient from contract");
            builder.evm_mut().ctx_mut().block.beneficiary = fee_recipient;
        }
        Ok(None) => {}
        Err(err) => {
            warn!(%err, "failed resolving fee recipient from contract; using fallback");
        }
    }
}

/// Resolves the validator's preferred fee token.
fn resolve_validator_fee_token(
    builder: &mut impl BlockBuilder<Executor: BlockExecutor<Evm = TempoEvm<impl Database>>>,
) -> Result<Address, PayloadBuilderError> {
    let ctx = builder.evm_mut().ctx_mut();
    let beneficiary = ctx.block.beneficiary;
    StorageCtx::enter_ctx(ctx, || {
        TipFeeManager::new()
            .get_validator_token(beneficiary)
            .map_err(PayloadBuilderError::other)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_primitives::{Address, B256, Bytes, Signature};
    use core::num::NonZeroU64;
    use reth_primitives_traits::SealedBlock;
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
            Signature::test_signature(),
        ));
        let block = Block {
            header: TempoHeader::default(),
            body: BlockBody {
                transactions: vec![tx],
                ommers: vec![],
                withdrawals: None,
            },
        };
        let sealed = Arc::new(SealedBlock::seal_slow(block));
        let eth = EthBuiltPayload::new(sealed, U256::ZERO, None);
        TempoBuiltPayload::new(eth, None)
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

        let attrs =
            TempoPayloadAttributes::new(Address::ZERO, None, 1000, extra_data.clone(), Vec::new);

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
