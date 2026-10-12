//! Zone payload builder.
//!
//! Builds zone blocks by executing `advanceTempo` system transactions (one per L1 block)
//! followed by pool transactions and a withdrawal batch finalization.

use crate::{
    WithdrawalRevealEncryptor,
    abi::{self, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS},
};
use alloy_consensus::{Signed, TxLegacy};
use alloy_eips::eip4895::Withdrawals;
use alloy_evm::Evm;
use alloy_primitives::{Bytes, U256};
use alloy_sol_types::SolCall;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_errors::ProviderError;
use reth_evm::{
    ConfigureEvm, Database, NextBlockEnvAttributes,
    execute::{BlockBuilder, BlockBuilderOutcome, BlockExecutionOutput, WithTxEnv},
};
use reth_node_api::{FullNodeTypes, NodeTypes};
use reth_node_builder::{BuilderContext, components::PayloadBuilderBuilder};
use reth_payload_builder::{EthBuiltPayload, PayloadBuilderError};
use reth_payload_primitives::{BuiltPayloadExecutedBlock, PayloadAttributes};
use reth_primitives_traits::{AlloyBlockHeader as _, Recovered};
use reth_revm::{State, database::StateProviderDatabase};
use reth_storage_api::{StateProvider, StateProviderFactory};
use reth_tasks::{TaskExecutor, cancel::CancelOnDrop};
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, PoolTransaction as _, TransactionPool,
    ValidPoolTransaction, error::InvalidPoolTransactionError,
};
use std::{error::Error, sync::Arc, time::Instant};
use tempo_evm::TempoNextBlockEnvAttributes;
use tempo_payload_types::{EncodedBlock, TempoBuiltPayload};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use tempo_transaction_pool::{
    StateAwareBestTransactions, TempoTransactionPool, transaction::TempoPooledTransaction,
};
use tracing::{error, info, warn};
use zone_chainspec::ZoneChainSpec;
use zone_evm::ZoneEvmConfig;
use zone_l1::{PreparedL1Block, TempoStateExt};
use zone_precompiles::L1StateError;
use zone_primitives::constants::MAX_RLP_BLOCK_SIZE;

use crate::{
    TempoImport, ZonePayloadAttributes, ZonePayloadTypes, prewarming::PrewarmingExecutionContext,
};

/// Default empty-batch cadence: every 120 zone blocks (~60 sec at Tempo's 500 ms block time).
pub const DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS: u64 = 120;

/// Safety margin reserved out of [`MAX_RLP_BLOCK_SIZE`] for everything in the block other than
/// pool transactions: the header, RLP list framing, `advanceTempo`, `finalizeWithdrawalBatch`
/// and the outer RLP string header.
///
/// Note: `finalizeWithdrawalBatch` is not bounded(~200 bytes per withdrawal).
/// So a large enough backlog can exceed this margin. OK because the cap is a soft target: block
/// size is not consensus-validated, so an overshoot creates a
/// warning, not a failed build. The p2p transport message cap `MAX_MESSAGE_SIZE` must stay comfortably above
/// [`MAX_RLP_BLOCK_SIZE`] so such blocks still replicate.
const BLOCK_SIZE_SAFETY_MARGIN: usize = 1024 * 1024;

/// Diagnostic retained when upstream Tempo precompile storage stringifies an [`L1StateError`].
const L1_STORAGE_UNAVAILABLE_ERROR_PREFIX: &str = "Tempo L1 storage unavailable";

/// Factory for constructing the zone payload builder.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ZonePayloadFactory {
    withdrawal_batch_interval_blocks: u64,
    withdrawal_reveal_encryptor: Option<Arc<dyn WithdrawalRevealEncryptor>>,
}

impl ZonePayloadFactory {
    /// Create a factory that finalizes empty withdrawal batches every `interval_blocks` zone blocks.
    pub fn new(withdrawal_batch_interval_blocks: u64) -> Self {
        Self {
            withdrawal_batch_interval_blocks: withdrawal_batch_interval_blocks.max(1),
            withdrawal_reveal_encryptor: None,
        }
    }

    pub fn with_withdrawal_reveal_encryptor(
        mut self,
        encryptor: Arc<dyn WithdrawalRevealEncryptor>,
    ) -> Self {
        self.withdrawal_reveal_encryptor = Some(encryptor);
        self
    }
}

impl Default for ZonePayloadFactory {
    fn default() -> Self {
        Self::new(DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS)
    }
}

impl<Node>
    PayloadBuilderBuilder<Node, TempoTransactionPool<Node::Provider, ZoneEvmConfig>, ZoneEvmConfig>
    for ZonePayloadFactory
where
    Node: FullNodeTypes,
    Node::Types: NodeTypes<
            Primitives = tempo_primitives::TempoPrimitives,
            ChainSpec = ZoneChainSpec,
            Payload = ZonePayloadTypes,
        >,
{
    type PayloadBuilder = ZonePayloadBuilder<Node::Provider>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: TempoTransactionPool<Node::Provider, ZoneEvmConfig>,
        evm_config: ZoneEvmConfig,
    ) -> eyre::Result<Self::PayloadBuilder> {
        Ok(ZonePayloadBuilder {
            pool,
            provider: ctx.provider().clone(),
            evm_config,
            task_executor: ctx.task_executor().clone(),
            withdrawal_batch_interval_blocks: self.withdrawal_batch_interval_blocks,
            withdrawal_reveal_encryptor: self.withdrawal_reveal_encryptor.clone(),
        })
    }
}

/// Zone payload builder that executes `advanceTempo` system txs + pool txs.
#[derive(Debug, Clone)]
pub struct ZonePayloadBuilder<Provider> {
    /// Transaction pool for selecting pool txs to include in the block.
    pool: TempoTransactionPool<Provider, ZoneEvmConfig>,
    /// State provider for reading chain state during block building.
    provider: Provider,
    /// Zone-specific EVM configuration (precompiles, hardfork spec, gas params).
    evm_config: ZoneEvmConfig,
    /// Runs disposable simulations on Reth's dedicated prewarming pool.
    task_executor: TaskExecutor,
    /// Number of zone blocks between withdrawal batch boundaries.
    withdrawal_batch_interval_blocks: u64,
    /// Encrypts authenticated-withdrawal sender reveal data for batch finalization.
    withdrawal_reveal_encryptor: Option<Arc<dyn WithdrawalRevealEncryptor>>,
}

impl<Provider> PayloadBuilder for ZonePayloadBuilder<Provider>
where
    Provider: StateProviderFactory + ChainSpecProvider<ChainSpec = ZoneChainSpec> + Clone + 'static,
{
    type Attributes = ZonePayloadAttributes;
    type BuiltPayload = TempoBuiltPayload;

    fn try_build(
        &self,
        args: BuildArguments<Self::Attributes, Self::BuiltPayload>,
    ) -> Result<BuildOutcome<Self::BuiltPayload>, PayloadBuilderError> {
        let BuildArguments {
            mut cached_reads,
            config,
            cancel,
            ..
        } = args;
        let PayloadConfig {
            parent_header,
            attributes,
            payload_id: _,
            parent_block_info: _,
        } = config;

        let start = Instant::now();

        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let tempo_import = attributes.tempo_import();
        let imported_headers = match tempo_import {
            TempoImport::Full(prepared) => core::slice::from_ref(&prepared.header),
            TempoImport::CheckpointOnly(headers) => headers.as_slice(),
        };
        validate_l1_continuity(state_provider.as_ref(), imported_headers)?;
        let final_imported = imported_headers.last().expect("validated nonempty import");
        let checkpoint_only = tempo_import.is_checkpoint_only();
        let follows_checkpoint_blocks = tempo_import.follows_checkpoint_blocks();
        let total_deposits = tempo_import.total_deposits();
        let enabled_tokens = tempo_import.enabled_tokens();

        if tempo_import.is_checkpoint_only() {
            info!(
                target: "zone::payload",
                zone_block = parent_header.number() + 1,
                l1_block = final_imported.inner.number,
                header_count = imported_headers.len(),
                "Including advanceTempoHeaders system tx (chain continuity OK)"
            );
        } else {
            info!(
                target: "zone::payload",
                zone_block = parent_header.number() + 1,
                l1_block = final_imported.inner.number,
                deposits = total_deposits,
                enabled_tokens,
                "Including advanceTempo system tx (chain continuity OK)"
            );
        }

        let state = StateProviderDatabase::new(state_provider.as_ref().into_evm_state_provider());
        let mut db = State::builder()
            .with_database(
                Box::new(cached_reads.as_db_mut(state)) as Box<dyn Database<Error = ProviderError>>
            )
            .with_bundle_update()
            .build();

        let chain_spec = self.provider.chain_spec();
        let chain_id = chain_spec.chain_id();

        let block_gas_limit = parent_header.gas_limit();

        let next_block_env_attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: attributes.timestamp(),
                suggested_fee_recipient: attributes.suggested_fee_recipient(),
                prev_randao: attributes.prev_randao(),
                gas_limit: block_gas_limit,
                parent_beacon_block_root: attributes.parent_beacon_block_root(),
                withdrawals: attributes.withdrawals().cloned().map(Withdrawals::new),
                extra_data: attributes.extra_data(),
                slot_number: attributes.slot_number(),
            },
            // Zones don't use Tempo L1 gas sections.
            general_gas_limit: 0,
            shared_gas_limit: 0,
            timestamp_millis_part: attributes.timestamp_millis_part(),
            consensus_context: None,
        };
        let mut builder = self
            .evm_config
            .builder_for_next_block(&mut db, &parent_header, next_block_env_attributes.clone())
            .map_err(PayloadBuilderError::other)?;
        let base_fee = builder.evm().block().basefee;
        let block_number: u64 = builder
            .evm()
            .block()
            .number
            .try_into()
            .expect("block number fits u64");

        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(%err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        // Prewarm L1 reads in parallel with canonical `advanceTempo` (the pool bounds concurrency).
        let prewarming = match tempo_import {
            TempoImport::Full(prepared) => Some(
                PrewarmingExecutionContext {
                    provider: self.provider.clone(),
                    evm_config: self.evm_config.clone(),
                    parent_hash: parent_header.hash(),
                    parent_header: (*parent_header).clone(),
                    next_block_env_attributes,
                    chain_id,
                }
                .start(&self.task_executor, prepared),
            ),
            TempoImport::CheckpointOnly(_) => None,
        };

        // Execute advanceTempo system transaction — exactly one per zone block.
        let opening_tx = match tempo_import {
            TempoImport::Full(prepared) => build_advance_tempo_tx(prepared, chain_id),
            TempoImport::CheckpointOnly(headers) => {
                build_advance_tempo_headers_tx(headers, chain_id)?
            }
        };
        builder
            .execute_transaction(opening_tx)
            .map(|_| ())
            .map_err(PayloadBuilderError::evm)
            .map_err(|err| {
                error!(
                    ?err,
                    l1_block = final_imported.inner.number,
                    deposits = total_deposits,
                    "advanceTempo system tx failed"
                );
                err
            })?;
        drop(prewarming);

        if !checkpoint_only {
            // Execute pool transactions until either all of them fit or their packed RLP bytes reach
            // the size budget
            // The block executor owns gas-capacity accounting.
            let pool_tx_size_budget = MAX_RLP_BLOCK_SIZE - BLOCK_SIZE_SAFETY_MARGIN;
            let raw_best_txs = self
                .pool
                .best_transactions_with_attributes(BestTransactionsAttributes::new(base_fee, None));
            let mut best_txs = StateAwareBestTransactions::new(raw_best_txs);
            if execute_pool_transactions(
                |tx, best_txs| {
                    builder
                        .execute_transaction_with_result_closure(tx, |result| {
                            best_txs.on_new_result(result);
                        })
                        .map(|_| ())
                },
                &mut best_txs,
                &cancel,
                pool_tx_size_budget,
            )? == PoolExecutionOutcome::Cancelled
            {
                return Ok(BuildOutcome::Cancelled);
            }

            finalize_withdrawal_batch_if_needed(
                &mut builder,
                block_number,
                self.withdrawal_batch_interval_blocks,
                follows_checkpoint_blocks,
                total_deposits > 0,
                self.withdrawal_reveal_encryptor.as_deref(),
                chain_id,
            )?;
        }

        let BlockBuilderOutcome {
            execution_result,
            hashed_state,
            trie_updates,
            block,
            block_access_list: _,
        } = builder.finish(&*state_provider, None)?;

        let requests = chain_spec
            .is_prague_active_at_timestamp(attributes.timestamp())
            .then_some(execution_result.requests.clone());

        let sealed_block = Arc::new(block.sealed_block().clone());
        let execution_block_encoded = EncodedBlock::default();
        let execution_block_size_estimate = execution_block_encoded
            .get_or_encode(sealed_block.as_ref())
            .len();
        if execution_block_size_estimate > MAX_RLP_BLOCK_SIZE {
            warn!(
                block_size_bytes = execution_block_size_estimate,
                max_rlp_block_size = MAX_RLP_BLOCK_SIZE,
                "built block exceeds the soft RLP size cap"
            );
        }

        let elapsed = start.elapsed();
        info!(
            number = sealed_block.number(),
            l1_block = final_imported.number(),
            l1_hash = ?final_imported.hash(),
            hash = ?sealed_block.hash(),
            gas_used = sealed_block.gas_used(),
            deposits = total_deposits,
            tx_count = sealed_block.transaction_count(),
            block_size_bytes = execution_block_size_estimate,
            ?elapsed,
            "Built zone payload"
        );

        let recovered_block = Arc::new(block);
        let eth_payload = EthBuiltPayload::new(recovered_block.clone(), U256::ZERO, requests, None);

        let execution_output = BlockExecutionOutput {
            result: execution_result,
            state: db.take_bundle(),
        };

        let executed_block = BuiltPayloadExecutedBlock {
            recovered_block,
            execution_output: Arc::new(execution_output),
            hashed_state: Arc::new(hashed_state),
            trie_updates: Arc::new(trie_updates),
        };

        let payload = TempoBuiltPayload::new(
            eth_payload,
            Some(executed_block),
            std::time::Duration::ZERO,
            std::time::Duration::ZERO,
            execution_block_size_estimate,
            execution_block_encoded,
        );

        // Zone payloads are deterministic (one L1 block = one zone block), so freeze
        // the payload to prevent reth from re-triggering try_build on the rebuild interval.
        // Without this, the next rebuild attempt would find the deposit queue empty.
        Ok(BuildOutcome::Freeze(payload))
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
        self.try_build(BuildArguments::new(
            Default::default(),
            None,
            None,
            config,
            Default::default(),
            Default::default(),
        ))?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

/// Validate that the prepared L1 block is the next block expected by TempoState.
fn validate_l1_continuity(
    state_provider: &dyn StateProvider,
    headers: &[reth_primitives_traits::SealedHeader<TempoHeader>],
) -> Result<(), PayloadBuilderError> {
    let stored_l1 = state_provider
        .tempo_num_hash()
        .map_err(|err| PayloadBuilderError::Internal(err.into()))?;
    let expected_block_number = stored_l1.number + 1;

    info!(
        target: "zone::payload",
        stored_l1_block_hash = %stored_l1.hash,
        expected_tempo_block_number = expected_block_number,
        "TempoState current state"
    );

    if headers.is_empty() {
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            "Tempo import contains no headers",
        )));
    }
    let mut expected_number = expected_block_number;
    let mut expected_hash = stored_l1.hash;
    for header in headers {
        if header.inner.number != expected_number {
            error!(
                target: "zone::payload",
                got = header.inner.number,
                expected = expected_number,
                "L1 block number mismatch — chain continuity broken"
            );
            return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
                format!(
                    "L1 block number mismatch: got {} expected {expected_block_number}",
                    header.inner.number
                ),
            )));
        }

        if header.inner.parent_hash != expected_hash {
            error!(
                target: "zone::payload",
                got = %header.inner.parent_hash,
                expected = %expected_hash,
                l1_block = header.inner.number,
                "L1 parent hash mismatch — chain continuity broken"
            );
            return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
                format!(
                    "L1 parent hash mismatch at block {}: got {} expected {}",
                    header.inner.number, header.inner.parent_hash, expected_hash
                ),
            )));
        }
        expected_number = expected_number.checked_add(1).ok_or_else(|| {
            PayloadBuilderError::Internal(reth_errors::RethError::msg(
                "Tempo block number overflow",
            ))
        })?;
        expected_hash = header.hash();
    }

    Ok(())
}

/// Execute the best pool transactions until the iterator is exhausted or the build is cancelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolExecutionOutcome {
    Complete,
    Cancelled,
}

/// Execute the best pool transactions, skipping any whose RLP size would push the packed pool
/// transaction bytes past `pool_tx_size_budget`.
fn execute_pool_transactions<T, F>(
    mut execute_tx: F,
    best_txs: &mut T,
    cancel: &CancelOnDrop,
    pool_tx_size_budget: usize,
) -> Result<PoolExecutionOutcome, PayloadBuilderError>
where
    T: BestTransactions<Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
    F: FnMut(
        WithTxEnv<tempo_revm::TempoTxEnv, Recovered<TempoTxEnvelope>>,
        &mut T,
    ) -> Result<(), reth_evm::block::BlockExecutionError>,
{
    let mut packed_tx_bytes = 0usize;
    while let Some(pool_tx) = best_txs.next() {
        if cancel.is_cancelled() {
            return Ok(PoolExecutionOutcome::Cancelled);
        }

        let packed_bytes_with_tx =
            packed_tx_bytes.saturating_add(pool_tx.transaction.encoded_length());
        if packed_bytes_with_tx > pool_tx_size_budget {
            best_txs.mark_invalid(
                &pool_tx,
                InvalidPoolTransactionError::OversizedData {
                    size: packed_bytes_with_tx,
                    limit: pool_tx_size_budget,
                },
            );
            continue;
        }

        let tx_with_env = pool_tx.transaction.clone().into_with_tx_env();
        match execute_tx(tx_with_env, best_txs) {
            Ok(_) => packed_tx_bytes = packed_bytes_with_tx,
            Err(reth_evm::block::BlockExecutionError::Validation(
                reth_evm::block::BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit,
                    block_available_gas,
                },
            )) => {
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::ExceedsGasLimit(
                        transaction_gas_limit,
                        block_available_gas,
                    ),
                );
            }
            Err(reth_evm::block::BlockExecutionError::Validation(
                reth_evm::block::BlockValidationError::InvalidTx { error, .. },
            )) => {
                if !error.is_nonce_too_low() {
                    best_txs.mark_invalid(
                        &pool_tx,
                        InvalidPoolTransactionError::Consensus(
                            reth_primitives_traits::transaction::error::InvalidTransactionError::TxTypeNotSupported,
                        ),
                    );
                }
            }
            Err(reth_evm::block::BlockExecutionError::Internal(
                reth_evm::block::InternalBlockExecutionError::EVM { ref error, .. },
            )) if is_l1_storage_unavailable(error.as_ref()) => {
                warn!(
                    target: "zone::payload",
                    %error,
                    tx_hash = %pool_tx.hash(),
                    "skipping pool tx due to transient RPC error"
                );
            }
            Err(err) => return Err(PayloadBuilderError::evm(err)),
        }
    }

    Ok(PoolExecutionOutcome::Complete)
}

fn is_l1_storage_unavailable(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error
            .downcast_ref::<L1StateError>()
            .is_some_and(L1StateError::is_storage_unavailable)
            || error
                .to_string()
                .contains(L1_STORAGE_UNAVAILABLE_ERROR_PREFIX)
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// Finalize a batch after processing deposits, with pending withdrawals, or at a batch boundary.
fn finalize_withdrawal_batch_if_needed<B>(
    builder: &mut B,
    block_number: u64,
    interval_blocks: u64,
    follows_checkpoint_blocks: bool,
    has_processed_deposits: bool,
    encryptor: Option<&dyn WithdrawalRevealEncryptor>,
    chain_id: u64,
) -> Result<(), PayloadBuilderError>
where
    B: BlockBuilder<Primitives = tempo_primitives::TempoPrimitives>,
{
    let pending_withdrawals =
        read_pending_withdrawals_from_outbox(builder.evm_mut(), block_number)?;
    if !should_finalize_withdrawal_batch(
        !pending_withdrawals.is_empty(),
        block_number,
        interval_blocks,
        follows_checkpoint_blocks,
        has_processed_deposits,
    ) {
        return Ok(());
    }

    let encrypted_senders = pending_withdrawals
        .iter()
        .map(|request| {
            if request.revealTo.is_empty() {
                Ok(Bytes::new())
            } else {
                let encryptor = encryptor.ok_or_else(|| {
                    PayloadBuilderError::Internal(reth_errors::RethError::msg(
                        "withdrawal reveal encryption requested but no encryptor is configured",
                    ))
                })?;
                encryptor
                    .encrypt_sender(
                        request.revealTo.as_ref(),
                        request.sender,
                        request.txHash,
                        request.fallbackNonce,
                    )
                    .map(Bytes::from)
                    .ok_or_else(|| {
                        PayloadBuilderError::Internal(reth_errors::RethError::msg(format!(
                            "failed to encrypt authenticated sender reveal for tx {}",
                            request.txHash
                        )))
                    })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let count = U256::from(pending_withdrawals.len());
    let finalize_tx =
        build_finalize_withdrawal_batch_tx(count, block_number, encrypted_senders, chain_id);
    builder
        .execute_transaction(finalize_tx)
        .map(|_| ())
        .map_err(PayloadBuilderError::evm)
        .map_err(|err| {
            error!(
                ?err,
                block_number, "finalizeWithdrawalBatch system tx failed"
            );
            err
        })
}

fn should_finalize_withdrawal_batch(
    has_pending_withdrawals: bool,
    block_number: u64,
    interval_blocks: u64,
    follows_checkpoint_blocks: bool,
    has_processed_deposits: bool,
) -> bool {
    has_pending_withdrawals
        || has_processed_deposits
        || block_number.is_multiple_of(interval_blocks)
        || follows_checkpoint_blocks
}

/// Build the `finalizeWithdrawalBatch(count)` system transaction.
///
/// This must be the **last** transaction in each finalizing zone block. It calls
/// [`IZoneOutbox.finalizeWithdrawalBatch`](crate::abi::IZoneOutbox) which:
/// - Collects up to `count` pending withdrawals
/// - Builds the withdrawal hash chain (oldest outermost)
/// - Increments `withdrawalBatchIndex`
/// - Writes `_lastBatch` to state for proof access
/// - Emits `BatchFinalized`
///
/// `count` should match the number of withdrawals represented by `encrypted_senders`.
/// `block_number` must match the current zone block number.
pub(crate) fn build_finalize_withdrawal_batch_tx(
    count: U256,
    block_number: u64,
    encrypted_senders: Vec<Bytes>,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    let calldata = abi::IZoneOutbox::finalizeWithdrawalBatchCall {
        count,
        blockNumber: block_number,
        encryptedSenders: encrypted_senders,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_OUTBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    )
}

/// Read all pending withdrawals in the ZoneOutbox
fn read_pending_withdrawals_from_outbox<E>(
    evm: &mut E,
    block_number: u64,
) -> Result<Vec<abi::IZoneOutbox::PendingWithdrawal>, PayloadBuilderError>
where
    E: Evm,
{
    let calldata = abi::IZoneOutbox::getPendingWithdrawalsCall {}.abi_encode();
    let call_result = evm
        .transact_system_call(TEMPO_SYSTEM_TX_SENDER, ZONE_OUTBOX_ADDRESS, calldata.into())
        .map_err(|err| {
            error!(
                ?err,
                block_number, "ZoneOutbox getPendingWithdrawals view call failed"
            );
            PayloadBuilderError::evm(err)
        })?;

    if !call_result.result.is_success() {
        error!(
            target: "zone::payload",
            block_number,
            result = ?call_result.result,
            "ZoneOutbox getPendingWithdrawals view call failed"
        );
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            format!("ZoneOutbox getPendingWithdrawals view failed at zone block {block_number}"),
        )));
    }
    let output = call_result.result.into_output().unwrap_or_default();

    abi::IZoneOutbox::getPendingWithdrawalsCall::abi_decode_returns(&output).map_err(|err| {
        PayloadBuilderError::Internal(reth_errors::RethError::msg(format!(
            "failed to decode getPendingWithdrawals return data: {err}"
        )))
    })
}

/// Build the `advanceTempo(header, deposits, decryptions, enabledTokens)` system transaction.
///
/// This must be called **once per L1 block** at the start of a zone block (before user txs).
/// It calls [`IZoneInbox.advanceTempo`](crate::abi::IZoneInbox) which atomically:
/// - Advances the zone's view of Tempo by processing the L1 block header
/// - Activates newly-bridged TIP-20 tokens directly in the ZoneInbox precompile
/// - Processes deposits from the queue (minting zone tokens to recipients)
/// - Validates the deposit hash chain against Tempo state
///
/// Takes a [`PreparedL1Block`] where all ECIES decryption and ABI encoding have
/// already been performed. TIP-403 policy is enforced during `advanceTempo` when
/// the deposits mint TIP-20 tokens.
pub fn build_advance_tempo_tx(
    prepared: &PreparedL1Block,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    build_advance_tempo_tx_from_parts(
        prepared.header.header(),
        prepared.queued_deposits.clone(),
        prepared.decryptions.clone(),
        prepared.enabled_tokens.clone(),
        chain_id,
    )
}

/// Consume a throwaway prepared block without cloning its calldata vectors.
pub(crate) fn build_advance_tempo_tx_owned(
    prepared: PreparedL1Block,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    build_advance_tempo_tx_from_parts(
        prepared.header.header(),
        prepared.queued_deposits,
        prepared.decryptions,
        prepared.enabled_tokens,
        chain_id,
    )
}

fn build_advance_tempo_tx_from_parts(
    header: &TempoHeader,
    deposits: Vec<abi::QueuedDeposit>,
    decryptions: Vec<abi::DecryptionData>,
    enabled_tokens: Vec<abi::EnabledToken>,
    chain_id: u64,
) -> Recovered<TempoTxEnvelope> {
    let calldata = abi::IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(header).into(),
        deposits,
        decryptions,
        enabledTokens: enabled_tokens,
    }
    .abi_encode();

    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };

    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    )
}

/// Build a checkpoint-only `advanceTempoHeaders(headers)` system transaction.
///
/// The executor requires this transaction to be the complete body of its Zone block. Portal
/// deposits and token enablements remain pending until a later full `advanceTempo` block.
pub fn build_advance_tempo_headers_tx(
    headers: &[reth_primitives_traits::SealedHeader<TempoHeader>],
    chain_id: u64,
) -> Result<Recovered<TempoTxEnvelope>, PayloadBuilderError> {
    if headers.is_empty()
        || headers.len() > zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK
    {
        return Err(PayloadBuilderError::Internal(reth_errors::RethError::msg(
            "checkpoint-only Tempo header range is empty or oversized",
        )));
    }
    let headers = headers
        .iter()
        .map(|header| alloy_rlp::encode(header.header()).into())
        .collect();
    let calldata = abi::IZoneInbox::advanceTempoHeadersCall { headers }.abi_encode();
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: ZONE_INBOX_ADDRESS.into(),
        value: U256::ZERO,
        input: calldata.into(),
    };
    Ok(Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    ))
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{Header, Signed, TxLegacy};
    use alloy_primitives::{Address, B256, U256, address};
    use alloy_sol_types::SolCall;
    use reth_primitives_traits::{Recovered, SealedHeader};
    use reth_tasks::cancel::CancelOnDrop;
    use reth_transaction_pool::{
        BestTransactions, TransactionOrigin, ValidPoolTransaction,
        error::InvalidPoolTransactionError,
        identifier::{SenderId, TransactionId},
    };
    use std::{collections::VecDeque, sync::Arc, time::Instant};
    use tempo_primitives::{
        TempoHeader, TempoTxEnvelope,
        transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
    };
    use tempo_transaction_pool::transaction::TempoPooledTransaction;

    use crate::abi::{self, DepositType, IZoneInbox};
    use zone_l1::PreparedL1Block;

    #[test]
    fn withdrawal_batch_boundary_conditions() {
        let blocks = super::DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS;

        assert_eq!(blocks, 120);
        assert!(!super::should_finalize_withdrawal_batch(
            false, 119, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            false, 120, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            true, 121, blocks, false, false
        ));
        assert!(super::should_finalize_withdrawal_batch(
            false, 150, blocks, true, false
        ));
        // Deposit-only blocks must settle before the interval to reopen portal capacity.
        assert!(super::should_finalize_withdrawal_batch(
            false, 121, blocks, false, true
        ));
    }

    #[test]
    fn zero_batch_interval_finalizes_every_block() {
        assert_eq!(
            super::ZonePayloadFactory::new(0).withdrawal_batch_interval_blocks,
            1
        );
    }

    #[test]
    fn builds_checkpoint_only_import_with_all_headers() {
        let headers = [7, 8].map(|number| {
            SealedHeader::seal_slow(TempoHeader {
                inner: Header {
                    number,
                    ..Default::default()
                },
                ..Default::default()
            })
        });

        let recovered = super::build_advance_tempo_headers_tx(&headers, 1337).unwrap();
        let TempoTxEnvelope::Legacy(signed) = recovered.inner() else {
            panic!("expected legacy transaction")
        };
        assert_eq!(signed.tx().chain_id, Some(1337));

        let call = IZoneInbox::advanceTempoHeadersCall::abi_decode(&signed.tx().input).unwrap();
        assert_eq!(call.headers.len(), 2);
        for (encoded, expected) in call.headers.iter().zip(headers) {
            let decoded: TempoHeader = alloy_rlp::decode_exact(encoded).unwrap();
            assert_eq!(decoded.inner.number, expected.inner.number);
        }
    }

    /// A [`BestTransactions`] stream backed by a fixed queue that counts size-based rejections.
    struct MockBestTransactions {
        queue: VecDeque<Arc<ValidPoolTransaction<TempoPooledTransaction>>>,
        oversized_marked: usize,
    }

    impl Iterator for MockBestTransactions {
        type Item = Arc<ValidPoolTransaction<TempoPooledTransaction>>;

        fn next(&mut self) -> Option<Self::Item> {
            self.queue.pop_front()
        }
    }

    impl BestTransactions for MockBestTransactions {
        fn mark_invalid(&mut self, _tx: &Self::Item, kind: InvalidPoolTransactionError) {
            if kind.is_oversized() {
                self.oversized_marked += 1;
            }
        }

        fn no_updates(&mut self) {}

        fn set_skip_blobs(&mut self, _skip_blobs: bool) {}
    }

    /// Build a pool transaction whose RLP-encoded length is dominated by `input_len` bytes of
    /// calldata, so tests can assemble a block of a known size.
    fn pool_tx_with_calldata(
        input_len: usize,
        nonce: u64,
    ) -> Arc<ValidPoolTransaction<TempoPooledTransaction>> {
        let tx = TxLegacy {
            chain_id: None,
            nonce,
            gas_price: 0,
            gas_limit: 0,
            to: address!("0x0000000000000000000000000000000000009999").into(),
            value: U256::ZERO,
            input: vec![0u8; input_len].into(),
        };
        let envelope = TempoTxEnvelope::Legacy(Signed::new_unhashed(tx, TEMPO_SYSTEM_TX_SIGNATURE));
        let recovered = Recovered::new_unchecked(envelope, TEMPO_SYSTEM_TX_SENDER);
        Arc::new(ValidPoolTransaction {
            transaction: TempoPooledTransaction::new(recovered),
            transaction_id: TransactionId::new(SenderId::from(0u64), nonce),
            propagate: false,
            timestamp: Instant::now(),
            origin: TransactionOrigin::External,
            authority_ids: None,
        })
    }

    /// Feed the pool loop far more large transactions than fit in the size budget, and assert it
    /// stops including them once the packed bytes reach the budget — i.e. the block is actually
    /// capped by the size gate rather than growing unbounded.
    #[test]
    fn pool_transactions_stop_at_size_budget() {
        // ~1 MiB of calldata per transaction; each has an identical encoded length (the small
        // nonces used below all encode to a single RLP byte).
        let per_tx = pool_tx_with_calldata(1_000_000, 0).encoded_length();
        assert!(
            per_tx > 1_000_000,
            "calldata should dominate the encoded size"
        );

        let budget = super::MAX_RLP_BLOCK_SIZE - super::BLOCK_SIZE_SAFETY_MARGIN;
        // How many of these transactions fit in the budget.
        let expected_fit = budget / per_tx;
        // Offer clearly more than fit so the gate must reject the tail.
        let total = expected_fit + 4;

        let queue = (0..total)
            .map(|i| pool_tx_with_calldata(1_000_000, i as u64))
            .collect::<VecDeque<_>>();
        assert!(queue.iter().all(|tx| tx.encoded_length() == per_tx));

        let mut best_txs = MockBestTransactions {
            queue,
            oversized_marked: 0,
        };
        let mut executed = 0usize;
        let cancel = CancelOnDrop::default();

        let outcome = super::execute_pool_transactions(
            |_tx, _best_txs| -> Result<(), reth_evm::block::BlockExecutionError> {
                executed += 1;
                Ok(())
            },
            &mut best_txs,
            &cancel,
            budget,
        )
        .expect("pool execution should not error");

        assert_eq!(outcome, super::PoolExecutionOutcome::Complete);

        // Only the transactions that fit were executed; the rest were rejected for size.
        assert_eq!(executed, expected_fit);
        assert_eq!(best_txs.oversized_marked, total - expected_fit);
    }

    /// Verify calldata for an internal withdrawal bounce-back followed by an
    /// encrypted user deposit.
    #[test]
    fn test_build_advance_tempo_tx_with_deposit() {
        let token = address!("0x0000000000000000000000000000000000001000");
        let sender = address!("0x0000000000000000000000000000000000001234");
        let header = TempoHeader {
            inner: Header {
                number: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        // Build a PreparedL1Block directly — this test validates
        // `build_advance_tempo_tx` calldata encoding, not `prepare`.
        let prepared = PreparedL1Block {
            header: SealedHeader::seal_slow(header),
            queued_deposits: vec![
                abi::QueuedDeposit {
                    depositType: DepositType::WithdrawalBounceBack,
                    rejected: false,
                    depositData: alloy_primitives::Bytes::from(
                        alloy_sol_types::SolValue::abi_encode(&abi::WithdrawalBounceBackDeposit {
                            token,
                            to: Address::with_last_byte(1),
                            amount: 500_000,
                        }),
                    ),
                },
                abi::QueuedDeposit {
                    depositType: DepositType::Deposit,
                    rejected: false,
                    depositData: alloy_primitives::Bytes::from(
                        alloy_sol_types::SolValue::abi_encode(&abi::Deposit {
                            token,
                            sender,
                            amount: 300_000,
                            tempoRefundRecipient: sender,
                            keyIndex: U256::ZERO,
                            encrypted: abi::DepositPayload {
                                ephemeralPubkeyX: B256::with_last_byte(0xDD),
                                ephemeralPubkeyYParity: 0x02,
                                ciphertext: vec![0xAA; 64].into(),
                                nonce: [0x05; 12].into(),
                                tag: [0x06; 16].into(),
                            },
                        }),
                    ),
                },
            ],
            decryptions: vec![abi::DecryptionData {
                sharedSecret: B256::ZERO,
                sharedSecretYParity: 0x02,
                cpProof: abi::ChaumPedersenProof {
                    s: B256::ZERO,
                    c: B256::ZERO,
                },
            }],
            enabled_tokens: vec![],
            follows_checkpoint_blocks: false,
        };

        let recovered_tx = super::build_advance_tempo_tx(&prepared, 1337);

        // Decode the calldata to verify structure.
        let envelope = recovered_tx.inner();
        let input = match envelope {
            tempo_primitives::TempoTxEnvelope::Legacy(signed) => {
                assert_eq!(signed.tx().chain_id, Some(1337));
                &signed.tx().input
            }
            _ => panic!("expected Legacy tx"),
        };
        let decoded = IZoneInbox::advanceTempoCall::abi_decode(input)
            .expect("calldata should decode as advanceTempo");

        // Should have 2 queued deposits
        assert_eq!(decoded.deposits.len(), 2, "should have 2 queued deposits");

        // The internal withdrawal bounce-back keeps its dedicated discriminator.
        assert_eq!(
            decoded.deposits[0].depositType,
            DepositType::WithdrawalBounceBack,
            "first entry should be a withdrawal bounce-back"
        );

        // Second should be Encrypted
        assert_eq!(
            decoded.deposits[1].depositType,
            DepositType::Deposit,
            "second deposit should be Encrypted"
        );

        // Should have exactly 1 DecryptionData (one per encrypted deposit)
        assert_eq!(
            decoded.decryptions.len(),
            1,
            "should have 1 DecryptionData for the encrypted deposit"
        );
    }
}
