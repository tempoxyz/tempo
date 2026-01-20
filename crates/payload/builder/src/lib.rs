//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod metrics;

use crate::metrics::TempoPayloadBuilderMetrics;
use alloy_consensus::{BlockHeader as _, Signed, Transaction, TxLegacy};
use alloy_primitives::{Address, U256};
use alloy_rlp::{Decodable, Encodable};
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
    block::{BlockExecutionError, BlockValidationError},
    execute::{BlockBuilder, BlockBuilderOutcome},
};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::PayloadBuilderAttributes;
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
    time::Instant,
};
use tempo_chainspec::TempoChainSpec;
use tempo_consensus::{TEMPO_GENERAL_GAS_DIVISOR, TEMPO_SHARED_GAS_DIVISOR};
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
use tempo_payload_types::TempoPayloadBuilderAttributes;
use tempo_primitives::{
    RecoveredSubBlock, SubBlockMetadata, TempoHeader, TempoPrimitives, TempoTxEnvelope,
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
use tracing::{Level, debug, error, info, instrument, trace, warn};

/// Returns true if a subblock has any expired transactions for the given timestamp.
fn has_expired_transactions(subblock: &RecoveredSubBlock, timestamp: u64) -> bool {
    subblock.transactions.iter().any(|tx| {
        tx.as_aa()
            .is_some_and(|tx| tx.tx().valid_before.is_some_and(|valid| valid <= timestamp))
    })
}

/// Gas limits derived from the block gas limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GasLimits {
    shared: u64,
    non_shared: u64,
    general: u64,
}

impl GasLimits {
    /// Calculates gas limits from the block gas limit.
    fn new(block_gas_limit: u64) -> Self {
        let reserved = block_gas_limit / TEMPO_SHARED_GAS_DIVISOR;
        let budget = block_gas_limit - reserved;
        let general = budget / TEMPO_GENERAL_GAS_DIVISOR;
        Self {
            shared: reserved,
            non_shared: budget,
            general,
        }
    }
}

/// Tracks cumulative resource usage during block building.
#[derive(Debug, Clone, Copy, Default)]
struct BlockBuildState {
    total_gas_used: u64,
    non_payment_gas_used: u64,
    block_size: usize,
}

impl BlockBuildState {
    /// Creates a new state with an initial block size (header overhead + withdrawals).
    fn new(initial_block_size: usize) -> Self {
        Self {
            total_gas_used: 0,
            non_payment_gas_used: 0,
            block_size: initial_block_size,
        }
    }

    /// Records a transaction's gas usage and size.
    fn add_tx(
        &mut self,
        gas_used: u64,
        rlp_length: usize,
        is_payment: bool,
    ) -> Result<(), InvalidPoolTransactionError> {
        self.total_gas_used = self.total_gas_used.checked_add(gas_used).ok_or_else(|| {
            InvalidPoolTransactionError::Other(Box::new(TempoPoolTransactionError::GasOverflow))
        })?;
        if !is_payment {
            self.non_payment_gas_used =
                self.non_payment_gas_used.checked_add(gas_used).ok_or_else(|| {
                    InvalidPoolTransactionError::Other(Box::new(
                        TempoPoolTransactionError::GasOverflow,
                    ))
                })?;
        }
        self.block_size = self.block_size.checked_add(rlp_length).ok_or_else(|| {
            InvalidPoolTransactionError::Other(Box::new(TempoPoolTransactionError::GasOverflow))
        })?;
        Ok(())
    }

    /// Accounts for additional block size (subblocks, system transactions).
    fn add_size(&mut self, size: usize) {
        self.block_size += size;
    }

    /// Checks if a transaction fits within the pool gas budget.
    fn check_gas_limit(
        &self,
        tx_gas_limit: u64,
        gas_limits: &GasLimits,
    ) -> Result<(), InvalidPoolTransactionError> {
        let total = self.total_gas_used.checked_add(tx_gas_limit).ok_or_else(|| {
            InvalidPoolTransactionError::Other(Box::new(TempoPoolTransactionError::GasOverflow))
        })?;
        if total > gas_limits.non_shared {
            return Err(InvalidPoolTransactionError::ExceedsGasLimit(
                tx_gas_limit,
                gas_limits.non_shared.saturating_sub(self.total_gas_used),
            ));
        }
        Ok(())
    }

    /// Checks if a non-payment transaction fits within the non-payment gas limit.
    fn check_non_payment_gas_limit(
        &self,
        tx_gas_limit: u64,
        is_payment: bool,
        gas_limits: &GasLimits,
    ) -> Result<(), InvalidPoolTransactionError> {
        if !is_payment {
            let total = self.non_payment_gas_used.checked_add(tx_gas_limit).ok_or_else(|| {
                InvalidPoolTransactionError::Other(Box::new(TempoPoolTransactionError::GasOverflow))
            })?;
            if total > gas_limits.general {
                return Err(InvalidPoolTransactionError::Other(Box::new(
                    TempoPoolTransactionError::ExceedsNonPaymentLimit,
                )));
            }
        }
        Ok(())
    }

    /// Checks if adding a transaction would exceed the max block size (osaka only).
    fn check_block_size(
        &self,
        tx_rlp_length: usize,
        is_osaka: bool,
    ) -> Result<(), InvalidPoolTransactionError> {
        if is_osaka {
            let estimated_size = self.block_size + tx_rlp_length;
            if estimated_size > MAX_RLP_BLOCK_SIZE {
                return Err(InvalidPoolTransactionError::OversizedData {
                    size: estimated_size,
                    limit: MAX_RLP_BLOCK_SIZE,
                });
            }
        }
        Ok(())
    }
}

/// Determines whether subblocks should be included in the payload.
///
/// Returns `false` for empty payloads or when an invalid subblock was seen at a height
/// greater than the parent block (indicating ongoing issues at this height).
fn should_include_subblocks(
    is_empty_payload: bool,
    highest_invalid_subblock: u64,
    parent_block_number: u64,
) -> bool {
    !is_empty_payload && highest_invalid_subblock <= parent_block_number
}

/// Builds execution payloads for Tempo blocks.
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
        state_provider_metrics: bool,
        disable_state_cache: bool,
    ) -> Self {
        Self {
            pool,
            provider,
            evm_config,
            metrics: TempoPayloadBuilderMetrics::default(),
            highest_invalid_subblock: Default::default(),
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
    type Attributes = TempoPayloadBuilderAttributes;
    type BuiltPayload = EthBuiltPayload<TempoPrimitives>;

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
            id = %args.config.attributes.payload_id(),
            parent_number = %args.config.parent_header.number(),
            parent_hash = %args.config.parent_header.hash()
        )
    )]
    fn build_payload<Txs>(
        &self,
        args: BuildArguments<TempoPayloadBuilderAttributes, EthBuiltPayload<TempoPrimitives>>,
        best_txs: impl FnOnce(BestTransactionsAttributes) -> Txs,
        empty: bool,
    ) -> Result<BuildOutcome<EthBuiltPayload<TempoPrimitives>>, PayloadBuilderError>
    where
        Txs: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    {
        let BuildArguments {
            mut cached_reads,
            config,
            cancel,
            best_payload,
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
        } = config;

        let start = Instant::now();

        let block_time_millis =
            (attributes.timestamp_millis() - parent_header.timestamp_millis()) as f64;
        self.metrics.block_time_millis.record(block_time_millis);
        self.metrics.block_time_millis_last.set(block_time_millis);

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

        let chain_spec = self.provider.chain_spec();
        let is_osaka = chain_spec.is_osaka_active_at_timestamp(attributes.timestamp());

        let block_gas_limit: u64 = parent_header.gas_limit();
        let gas_limits = GasLimits::new(block_gas_limit);

        // initial block size usage - size of withdrawals plus 1Kb of overhead for the block header
        let mut build_state = BlockBuildState::new(attributes.withdrawals().length() + 1024);
        let mut payment_transactions = 0u64;
        let mut total_fees = U256::ZERO;

        // If building an empty payload, don't include any subblocks
        //
        // Also don't include any subblocks if we've seen an invalid subblock
        // at this height or above.
        let mut subblocks = if should_include_subblocks(
            empty,
            self.highest_invalid_subblock.load(Ordering::Relaxed),
            parent_header.number(),
        ) {
            attributes.subblocks()
        } else {
            vec![]
        };

        subblocks.retain(|subblock| {
            // Edge case: remove subblocks with expired transactions
            //
            // We pre-validate all of the subblocks on top of parent state in subblocks service
            // which leaves the only reason for transactions to get invalidated by expiry of
            // `valid_before` field.
            if has_expired_transactions(subblock, attributes.timestamp()) {
                return false;
            }

            // Account for the subblock's size
            build_state.add_size(subblock.total_tx_size());

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
                        timestamp: attributes.timestamp(),
                        suggested_fee_recipient: attributes.suggested_fee_recipient(),
                        prev_randao: attributes.prev_randao(),
                        gas_limit: block_gas_limit,
                        parent_beacon_block_root: attributes.parent_beacon_block_root(),
                        withdrawals: Some(attributes.withdrawals().clone()),
                        extra_data: attributes.extra_data().clone(),
                    },
                    general_gas_limit: gas_limits.general,
                    shared_gas_limit: gas_limits.shared,
                    timestamp_millis_part: attributes.timestamp_millis_part(),
                    subblock_fee_recipients,
                },
            )
            .map_err(PayloadBuilderError::other)?;

        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        debug!("building new payload");

        // Prepare system transactions before actual block building and account for their size.
        let prepare_system_txs_start = Instant::now();
        let system_txs = self.build_seal_block_txs(builder.evm().block(), &subblocks);
        for tx in &system_txs {
            build_state.add_size(tx.inner().length());
        }
        let prepare_system_txs_elapsed = prepare_system_txs_start.elapsed();
        self.metrics
            .prepare_system_transactions_duration_seconds
            .record(prepare_system_txs_elapsed);

        let base_fee = builder.evm_mut().block().basefee;
        let mut best_txs = best_txs(BestTransactionsAttributes::new(
            base_fee,
            builder
                .evm_mut()
                .block()
                .blob_gasprice()
                .map(|gasprice| gasprice as u64),
        ));

        let execution_start = Instant::now();
        while let Some(pool_tx) = best_txs.next() {
            // ensure we still have capacity for this transaction
            if let Err(err) = build_state.check_gas_limit(pool_tx.gas_limit(), &gas_limits) {
                best_txs.mark_invalid(&pool_tx, &err);
                continue;
            }

            let is_payment = pool_tx.transaction.is_payment();

            // If the tx is not a payment and will exceed the non-payment gas limit
            // mark the tx as invalid and continue
            if let Err(err) = build_state.check_non_payment_gas_limit(
                pool_tx.gas_limit(),
                is_payment,
                &gas_limits,
            ) {
                best_txs.mark_invalid(&pool_tx, &err);
                continue;
            }

            // check if the job was interrupted, if so we can skip remaining transactions
            if attributes.is_interrupted() {
                break;
            }

            // check if the job was cancelled, if so we can exit early
            if cancel.is_cancelled() {
                return Ok(BuildOutcome::Cancelled);
            }

            if is_payment {
                payment_transactions += 1;
            }

            let tx_rlp_length = pool_tx.transaction.inner().length();
            if let Err(err) = build_state.check_block_size(tx_rlp_length, is_osaka) {
                best_txs.mark_invalid(&pool_tx, &err);
                continue;
            }

            let effective_gas_price = pool_tx.transaction.effective_gas_price(Some(base_fee));

            let tx_debug_repr = tracing::enabled!(Level::TRACE)
                .then(|| format!("{:?}", pool_tx.transaction))
                .unwrap_or_default();

            let tx_with_env = pool_tx.transaction.clone().into_with_tx_env();
            let execution_start = Instant::now();
            let gas_used = match builder.execute_transaction(tx_with_env) {
                Ok(gas_used) => gas_used,
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        trace!(%error, tx = %tx_debug_repr, "skipping nonce too low transaction");
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
                    }
                    continue;
                }
                // this is an error that we should treat as fatal for this attempt
                Err(err) => return Err(PayloadBuilderError::evm(err)),
            };
            let elapsed = execution_start.elapsed();
            self.metrics
                .transaction_execution_duration_seconds
                .record(elapsed);
            trace!(?elapsed, "Transaction executed");

            // update and add to total fees
            total_fees += calc_gas_balance_spending(gas_used, effective_gas_price);
            if let Err(err) = build_state.add_tx(gas_used, tx_rlp_length, is_payment) {
                best_txs.mark_invalid(&pool_tx, &err);
                continue;
            }
        }
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
        let subblocks_count = subblocks.len() as f64;
        let mut subblock_transactions = 0f64;
        // Apply subblock transactions
        for subblock in &subblocks {
            for tx in subblock.transactions_recovered() {
                if let Err(err) = builder.execute_transaction(tx.cloned()) {
                    if matches!(
                        &err,
                        BlockExecutionError::Validation(BlockValidationError::InvalidTx { .. })
                    ) {
                        error!(
                            ?err,
                            "subblock transaction failed execution, aborting payload building"
                        );
                        self.highest_invalid_subblock
                            .store(builder.evm().block().number.to(), Ordering::Relaxed);
                    }
                    return Err(PayloadBuilderError::evm(err));
                }

                subblock_transactions += 1.0;
            }
        }
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
        for system_tx in system_txs {
            builder
                .execute_transaction(system_tx)
                .map_err(PayloadBuilderError::evm)?;
        }
        let system_txs_execution_elapsed = system_txs_execution_start.elapsed();
        self.metrics
            .system_transactions_execution_duration_seconds
            .record(system_txs_execution_elapsed);

        let total_transaction_execution_elapsed = execution_start.elapsed();
        self.metrics
            .total_transaction_execution_duration_seconds
            .record(total_transaction_execution_elapsed);

        let builder_finish_start = Instant::now();
        let BlockBuilderOutcome {
            execution_result,
            block,
            ..
        } = builder.finish(&state_provider)?;
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

        let requests = chain_spec
            .is_prague_active_at_timestamp(attributes.timestamp())
            .then_some(execution_result.requests);

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

        let payload =
            EthBuiltPayload::new(attributes.payload_id(), sealed_block, total_fees, requests);

        drop(db);
        Ok(BuildOutcome::Better {
            payload,
            cached_reads,
        })
    }
}

/// Returns `true` if the given subblocks contain more entries than the best payload.
///
/// Used to determine if a new payload with more subblocks should replace the current best,
/// even if it doesn't have higher fees.
pub fn is_more_subblocks(
    best_payload: Option<&EthBuiltPayload<TempoPrimitives>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::BlockBody;
    use alloy_primitives::{Address, B256, Bytes, Signature};
    use reth_payload_builder::PayloadId;
    use reth_primitives_traits::SealedBlock;
    use tempo_primitives::{
        AASigned, Block, SignedSubBlock, SubBlock, SubBlockVersion, TempoSignature,
        TempoTransaction,
    };

    trait TestExt {
        fn random() -> Self;
        fn with_valid_before(_: Option<u64>) -> Self
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

        fn with_valid_before(valid_before: Option<u64>) -> Self {
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

    fn payload_with_metadata(count: usize) -> EthBuiltPayload<TempoPrimitives> {
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
        EthBuiltPayload::new(PayloadId::default(), sealed, U256::ZERO, None)
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

        let attrs = TempoPayloadBuilderAttributes::new(
            PayloadId::default(),
            B256::default(),
            Address::default(),
            1000,
            extra_data.clone(),
            Vec::new,
        );

        assert_eq!(attrs.extra_data(), &extra_data);

        // Verify the data is as expected
        let injected_data = attrs.extra_data().clone();

        assert_eq!(injected_data, extra_data);
    }

    #[test]
    fn test_has_expired_transactions_boundary() {
        // valid_before == timestamp → expired
        let subblock = RecoveredSubBlock::with_valid_before(Some(1000));
        assert!(has_expired_transactions(&subblock, 1000));

        // valid_before < timestamp → expired
        assert!(has_expired_transactions(&subblock, 1001));

        // valid_before > timestamp → NOT expired
        assert!(!has_expired_transactions(&subblock, 999));

        // No valid_before → NOT expired
        let subblock_no_expiry = RecoveredSubBlock::with_valid_before(None);
        assert!(!has_expired_transactions(&subblock_no_expiry, 1000));
    }

    #[test]
    fn test_gas_limits_new() {
        let limits = GasLimits::new(30_000_000);
        assert_eq!(limits.shared, 3_000_000);
        assert_eq!(limits.non_shared, 27_000_000);
        assert_eq!(limits.general, 13_500_000);

        let limits = GasLimits::new(0);
        assert_eq!(limits.shared, 0);
        assert_eq!(limits.non_shared, 0);
        assert_eq!(limits.general, 0);

        // Edge case: small value
        let limits = GasLimits::new(10);
        assert_eq!(limits.shared, 1);
        assert_eq!(limits.non_shared, 9);
        assert_eq!(limits.general, 4);
    }

    #[test]
    fn test_block_build_state() {
        let mut state = BlockBuildState::new(1024);

        // Initial state
        assert_eq!(state.total_gas_used, 0);
        assert_eq!(state.non_payment_gas_used, 0);
        assert_eq!(state.block_size, 1024);

        // Add payment tx - doesn't count toward general
        state.add_tx(21_000, 100, true).unwrap();
        assert_eq!(state.total_gas_used, 21_000);
        assert_eq!(state.non_payment_gas_used, 0);
        assert_eq!(state.block_size, 1124);

        // Add non-payment tx
        state.add_tx(50_000, 200, false).unwrap();
        assert_eq!(state.total_gas_used, 71_000);
        assert_eq!(state.non_payment_gas_used, 50_000);
        assert_eq!(state.block_size, 1324);

        // Add size only
        state.add_size(500);
        assert_eq!(state.block_size, 1824);

        // Overflow tests
        let mut overflow_state = BlockBuildState::new(0);
        overflow_state.total_gas_used = u64::MAX;
        assert!(overflow_state.add_tx(1, 0, true).is_err());

        let mut overflow_state = BlockBuildState::new(0);
        overflow_state.non_payment_gas_used = u64::MAX;
        assert!(overflow_state.add_tx(1, 0, false).is_err());

        let mut overflow_state = BlockBuildState::new(usize::MAX);
        assert!(overflow_state.add_tx(0, 1, true).is_err());
    }

    #[test]
    fn test_check_gas_limit() {
        let gas_limits = GasLimits {
            shared: 15_000_000,
            non_shared: 15_000_000,
            general: 7_500_000,
        };
        let empty_state = BlockBuildState::new(1024);

        // Can include: plenty of room
        assert!(empty_state.check_gas_limit(21_000, &gas_limits).is_ok());

        // At gas limit
        let at_limit = BlockBuildState {
            total_gas_used: gas_limits.non_shared,
            ..empty_state
        };
        assert!(at_limit.check_gas_limit(1, &gas_limits).is_err());

        // At non-payment limit
        let at_np_limit = BlockBuildState {
            non_payment_gas_used: gas_limits.general,
            ..empty_state
        };
        assert!(
            at_np_limit
                .check_non_payment_gas_limit(1, false, &gas_limits)
                .is_err()
        );
    }

    #[test]
    fn test_should_include_subblocks() {
        for (is_empty, highest_invalid, parent_num, expected) in [
            (true, 0, 100, false),    // empty payload
            (false, 0, 100, true),    // normal
            (false, 101, 100, false), // invalid > parent
            (false, 100, 100, true),  // invalid == parent (<=)
            (false, 50, 100, true),   // invalid < parent
        ] {
            assert_eq!(
                should_include_subblocks(is_empty, highest_invalid, parent_num),
                expected,
                "is_empty={is_empty}, highest_invalid={highest_invalid}, parent={parent_num}"
            );
        }
    }
}
