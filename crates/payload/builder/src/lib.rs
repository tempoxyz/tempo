//! Tempo Payload Builder.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::{Signed, Transaction, TxLegacy};
use alloy_primitives::U256;
use alloy_rlp::Encodable;
use alloy_sol_types::SolCall;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, MissingPayloadBehaviour, PayloadBuilder, PayloadConfig,
    is_better_payload,
};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE;
use reth_errors::ConsensusError;
use reth_evm::{
    ConfigureEvm, Evm, NextBlockEnvAttributes,
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
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, TransactionPool, ValidPoolTransaction,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_chainspec::TempoChainSpec;
use tempo_consensus::TEMPO_NON_PAYMENT_GAS_DIVISOR;
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
use tempo_payload_types::TempoPayloadBuilderAttributes;
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, contracts::IFeeManager::executeBlockCall};
use tempo_primitives::{
    TempoPrimitives, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use tempo_transaction_pool::{
    TempoTransactionPool,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
};
use tracing::{debug, trace, warn};

#[derive(Debug, Clone)]
pub struct TempoPayloadBuilder<Provider> {
    pool: TempoTransactionPool<Provider>,
    provider: Provider,
    evm_config: TempoEvmConfig,
}

impl<Provider> TempoPayloadBuilder<Provider> {
    pub const fn new(
        pool: TempoTransactionPool<Provider>,
        provider: Provider,
        evm_config: TempoEvmConfig,
    ) -> Self {
        Self {
            pool,
            provider,
            evm_config,
        }
    }
}

impl<Provider: ChainSpecProvider> TempoPayloadBuilder<Provider> {
    /// Builds system transaction to TipFeeManager to seal the block.
    fn build_seal_block_tx(&self, block_env: &BlockEnv) -> Recovered<TempoTxEnvelope> {
        // append encoded block number to the calldata to ensure that system transactions hashes do not collide
        let input = executeBlockCall
            .abi_encode()
            .into_iter()
            .chain(block_env.number.to_be_bytes_vec())
            .collect();

        Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(self.provider.chain_spec().chain().id()),
                    nonce: 0,
                    gas_price: 0,
                    gas_limit: 0,
                    to: TIP_FEE_MANAGER_ADDRESS.into(),
                    value: U256::ZERO,
                    input,
                },
                TEMPO_SYSTEM_TX_SIGNATURE,
            )),
            TEMPO_SYSTEM_TX_SENDER,
        )
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
        self.build_payload(args, |attributes| {
            self.pool.best_transactions_with_attributes(attributes)
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
        config: PayloadConfig<Self::Attributes>,
    ) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        self.build_payload(
            BuildArguments::new(
                Default::default(),
                config,
                Default::default(),
                Default::default(),
            ),
            |_| core::iter::empty(),
        )?
        .into_payload()
        .ok_or_else(|| PayloadBuilderError::MissingPayload)
    }
}

impl<Provider> TempoPayloadBuilder<Provider>
where
    Provider: StateProviderFactory + ChainSpecProvider<ChainSpec = TempoChainSpec>,
{
    fn build_payload<Txs>(
        &self,
        args: BuildArguments<TempoPayloadBuilderAttributes, EthBuiltPayload<TempoPrimitives>>,
        best_txs: impl FnOnce(BestTransactionsAttributes) -> Txs,
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

        let state_provider = self.provider.state_by_block_hash(parent_header.hash())?;
        let state = StateProviderDatabase::new(&state_provider);
        let mut db = State::builder()
            .with_database(cached_reads.as_db_mut(state))
            .with_bundle_update()
            .build();

        let non_payment_gas_limit = parent_header.gas_limit / TEMPO_NON_PAYMENT_GAS_DIVISOR;

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
                        gas_limit: parent_header.gas_limit,
                        parent_beacon_block_root: attributes.parent_beacon_block_root(),
                        withdrawals: Some(attributes.withdrawals().clone()),
                    },
                    non_payment_gas_limit,
                },
            )
            .map_err(PayloadBuilderError::other)?;

        let chain_spec = self.provider.chain_spec();

        debug!(target: "payload_builder", id=%attributes.payload_id(), parent_header = ?parent_header.hash(), parent_number = parent_header.number, "building new payload");
        let mut cumulative_gas_used = 0;
        let block_gas_limit: u64 = builder.evm_mut().block().gas_limit;
        let base_fee = builder.evm_mut().block().basefee;

        let mut best_txs = best_txs(BestTransactionsAttributes::new(
            base_fee,
            builder
                .evm_mut()
                .block()
                .blob_gasprice()
                .map(|gasprice| gasprice as u64),
        ));
        let mut total_fees = U256::ZERO;
        let mut non_payment_gas_used = 0u64;

        builder.apply_pre_execution_changes().map_err(|err| {
            warn!(target: "payload_builder", %err, "failed to apply pre-execution changes");
            PayloadBuilderError::Internal(err.into())
        })?;

        let mut block_transactions_rlp_length = 0;
        let is_osaka = chain_spec.is_osaka_active_at_timestamp(attributes.timestamp());

        while let Some(pool_tx) = best_txs.next() {
            // ensure we still have capacity for this transaction
            if cumulative_gas_used + pool_tx.gas_limit() > block_gas_limit {
                // Mark this transaction as invalid since it doesn't fit
                // The iterator will handle lane switching internally when appropriate
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::ExceedsGasLimit(
                        pool_tx.gas_limit(),
                        block_gas_limit - cumulative_gas_used,
                    ),
                );
                continue;
            }

            // If the tx is not a payment and the non payment block space is exhausted
            // mark the tx as invalid and continue
            if !pool_tx.transaction.is_payment()
                && pool_tx.gas_limit() + non_payment_gas_used > non_payment_gas_limit
            {
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::Other(Box::new(
                        TempoPoolTransactionError::ExceedsNonPaymentLimit,
                    )),
                );
                continue;
            }

            // check if the job was cancelled, if so we can exit early
            if cancel.is_cancelled() {
                return Ok(BuildOutcome::Cancelled);
            }

            // convert tx to a signed transaction
            let tx = pool_tx.to_consensus();

            let estimated_block_size_with_tx = block_transactions_rlp_length
                + tx.inner().length()
                + attributes.withdrawals().length()
                + 1024; // 1Kb of overhead for the block header

            if is_osaka && estimated_block_size_with_tx > MAX_RLP_BLOCK_SIZE {
                best_txs.mark_invalid(
                    &pool_tx,
                    InvalidPoolTransactionError::OversizedData(
                        estimated_block_size_with_tx,
                        MAX_RLP_BLOCK_SIZE,
                    ),
                );
                continue;
            }

            let gas_used = match builder.execute_transaction(tx.clone()) {
                Ok(gas_used) => {
                    if !tx.is_payment() {
                        non_payment_gas_used += gas_used;
                    }
                    gas_used
                }
                Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx {
                    error,
                    ..
                })) => {
                    if error.is_nonce_too_low() {
                        // if the nonce is too low, we can skip this transaction
                        trace!(target: "payload_builder", %error, ?tx, "skipping nonce too low transaction");
                    } else {
                        // if the transaction is invalid, we can skip it and all of its
                        // descendants
                        trace!(target: "payload_builder", %error, ?tx, "skipping invalid transaction and its descendants");
                        best_txs.mark_invalid(
                            &pool_tx,
                            InvalidPoolTransactionError::Consensus(
                                InvalidTransactionError::TxTypeNotSupported,
                            ),
                        );
                    }
                    continue;
                }
                // this is an error that we should treat as fatal for this attempt
                Err(err) => return Err(PayloadBuilderError::evm(err)),
            };

            block_transactions_rlp_length += tx.inner().length();

            // update and add to total fees
            let miner_fee = tx
                .effective_tip_per_gas(base_fee)
                .expect("fee is always valid; execution succeeded");
            total_fees += U256::from(miner_fee) * U256::from(gas_used);
            cumulative_gas_used += gas_used;
        }

        // check if we have a better block
        if !is_better_payload(best_payload.as_ref(), total_fees) {
            // Release db
            drop(builder);
            // can skip building the block
            return Ok(BuildOutcome::Aborted {
                fees: total_fees,
                cached_reads,
            });
        }

        // Include the seal block transaction in the block
        builder
            .execute_transaction(self.build_seal_block_tx(builder.evm().block()))
            .map_err(PayloadBuilderError::evm)?;

        let BlockBuilderOutcome {
            execution_result,
            block,
            ..
        } = builder.finish(&state_provider)?;

        let requests = chain_spec
            .is_prague_active_at_timestamp(attributes.timestamp())
            .then_some(execution_result.requests);

        let sealed_block = Arc::new(block.sealed_block().clone());
        debug!(target: "payload_builder", id=%attributes.payload_id(), sealed_block_header = ?sealed_block.sealed_header(), "sealed built block");

        if is_osaka && sealed_block.rlp_length() > MAX_RLP_BLOCK_SIZE {
            return Err(PayloadBuilderError::other(ConsensusError::BlockTooLarge {
                rlp_length: sealed_block.rlp_length(),
                max_rlp_length: MAX_RLP_BLOCK_SIZE,
            }));
        }

        let payload =
            EthBuiltPayload::new(attributes.payload_id(), sealed_block, total_fees, requests);

        Ok(BuildOutcome::Better {
            payload,
            cached_reads,
        })
    }
}
