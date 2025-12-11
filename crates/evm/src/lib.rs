//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod assemble;
use alloy_consensus::{
    BlockHeader as _, Transaction, crypto::RecoveryError, transaction::TxHashRef,
};
use alloy_primitives::Address;
use alloy_rlp::Decodable;
pub use assemble::TempoBlockAssembler;
mod block;
mod context;
pub use context::{TempoBlockExecutionCtx, TempoNextBlockEnvAttributes};
mod error;
pub use error::TempoEvmError;
pub mod evm;
use std::{borrow::Cow, sync::Arc};

use alloy_evm::{
    self, Database, EvmEnv,
    block::{BlockExecutorFactory, BlockExecutorFor},
    eth::{EthBlockExecutionCtx, NextEvmEnvAttributes},
    revm::{Inspector, database::State},
};
pub use evm::TempoEvmFactory;
use reth_chainspec::EthChainSpec;
use reth_evm::{
    self, ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    FromRecoveredTx, RecoveredTx, ToTxEnv,
};
use reth_primitives_traits::{SealedBlock, SealedHeader, SignedTransaction};
use tempo_payload_types::TempoExecutionData;
use tempo_primitives::{
    Block, SubBlockMetadata, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
    subblock::PartialValidatorKey,
};

use crate::{block::TempoBlockExecutor, evm::TempoEvm};
use reth_evm_ethereum::EthEvmConfig;
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_revm::{TempoTxEnv, evm::TempoContext};
use tempo_transaction_pool::SenderRecoveryCache;

pub use tempo_revm::{TempoBlockEnv, TempoHaltReason, TempoStateAccess};

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner evm config
    pub inner: EthEvmConfig<TempoChainSpec, TempoEvmFactory>,

    /// Block assembler
    pub block_assembler: TempoBlockAssembler,

    /// Cache of recovered senders shared with the transaction pool.
    sender_recovery_cache: SenderRecoveryCache,
}

impl TempoEvmConfig {
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<TempoChainSpec>, evm_factory: TempoEvmFactory) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec.clone(), evm_factory);
        Self {
            inner,
            block_assembler: TempoBlockAssembler::new(chain_spec),
            sender_recovery_cache: SenderRecoveryCache::default(),
        }
    }

    /// Create a new [`TempoEvmConfig`] with the given chain spec, EVM factory, and sender
    /// recovery cache.
    pub fn new_with_sender_cache(
        chain_spec: Arc<TempoChainSpec>,
        evm_factory: TempoEvmFactory,
        sender_recovery_cache: SenderRecoveryCache,
    ) -> Self {
        let inner = EthEvmConfig::new_with_evm_factory(chain_spec.clone(), evm_factory);
        Self {
            inner,
            block_assembler: TempoBlockAssembler::new(chain_spec),
            sender_recovery_cache,
        }
    }

    /// Create a new [`TempoEvmConfig`] with the given chain spec and default EVM factory.
    pub fn new_with_default_factory(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self::new(chain_spec, TempoEvmFactory::default())
    }

    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        self.inner.chain_spec()
    }

    /// Returns the inner EVM config
    pub const fn inner(&self) -> &EthEvmConfig<TempoChainSpec, TempoEvmFactory> {
        &self.inner
    }
}

impl BlockExecutorFactory for TempoEvmConfig {
    type EvmFactory = TempoEvmFactory;
    type ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>;
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;

    fn evm_factory(&self) -> &Self::EvmFactory {
        self.inner.executor_factory.evm_factory()
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: TempoEvm<&'a mut State<DB>, I>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> impl BlockExecutorFor<'a, Self, DB, I>
    where
        DB: Database + 'a,
        I: Inspector<TempoContext<&'a mut State<DB>>> + 'a,
    {
        TempoBlockExecutor::new(evm, ctx, self.chain_spec())
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = TempoPrimitives;
    type Error = TempoEvmError;
    type NextBlockEnvCtx = TempoNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = TempoBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &TempoHeader) -> Result<EvmEnvFor<Self>, Self::Error> {
        let EvmEnv { cfg_env, block_env } = EvmEnv::for_eth_block(
            header,
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec()
                .blob_params_at_timestamp(header.timestamp()),
        );

        let spec = self.chain_spec().tempo_hardfork_at(header.timestamp());

        Ok(EvmEnv {
            cfg_env: cfg_env.with_spec(spec),
            block_env: TempoBlockEnv {
                inner: block_env,
                timestamp_millis_part: header.timestamp_millis_part,
            },
        })
    }

    fn next_evm_env(
        &self,
        parent: &TempoHeader,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        let EvmEnv { cfg_env, block_env } = EvmEnv::for_eth_next_block(
            parent,
            NextEvmEnvAttributes {
                timestamp: attributes.timestamp,
                suggested_fee_recipient: attributes.suggested_fee_recipient,
                prev_randao: attributes.prev_randao,
                gas_limit: attributes.gas_limit,
            },
            self.chain_spec()
                .next_block_base_fee(parent, attributes.timestamp)
                .unwrap_or_default(),
            self.chain_spec(),
            self.chain_spec().chain().id(),
            self.chain_spec()
                .blob_params_at_timestamp(attributes.timestamp),
        );

        let spec = self.chain_spec().tempo_hardfork_at(attributes.timestamp);

        Ok(EvmEnv {
            cfg_env: cfg_env.with_spec(spec),
            block_env: TempoBlockEnv {
                inner: block_env,
                timestamp_millis_part: attributes.timestamp_millis_part,
            },
        })
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error> {
        // Decode validator -> fee_recipient mapping from the subblock metadata system transaction.
        let subblock_fee_recipients = block
            .body()
            .transactions
            .iter()
            .rev()
            .filter(|tx| (*tx).to() == Some(Address::ZERO))
            .find_map(|tx| Vec::<SubBlockMetadata>::decode(&mut tx.input().as_ref()).ok())
            .ok_or(TempoEvmError::NoSubblockMetadataFound)?
            .into_iter()
            .map(|metadata| {
                (
                    PartialValidatorKey::from_slice(&metadata.validator[..15]),
                    metadata.fee_recipient,
                )
            })
            .collect();

        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: block.header().parent_hash(),
                parent_beacon_block_root: block.header().parent_beacon_block_root(),
                // no ommers in tempo
                ommers: &[],
                withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
                extra_data: block.extra_data().clone(),
            },
            general_gas_limit: block.header().general_gas_limit,
            shared_gas_limit: block.header().gas_limit()
                / tempo_consensus::TEMPO_SHARED_GAS_DIVISOR,
            // Not available when we only have a block body.
            validator_set: None,
            subblock_fee_recipients,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<TempoHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<TempoBlockExecutionCtx<'_>, Self::Error> {
        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: parent.hash(),
                parent_beacon_block_root: attributes.parent_beacon_block_root,
                ommers: &[],
                withdrawals: attributes.inner.withdrawals.map(Cow::Owned),
                extra_data: attributes.inner.extra_data,
            },
            general_gas_limit: attributes.general_gas_limit,
            shared_gas_limit: attributes.inner.gas_limit
                / tempo_consensus::TEMPO_SHARED_GAS_DIVISOR,
            // Fine to not validate during block building.
            validator_set: None,
            subblock_fee_recipients: attributes.subblock_fee_recipients,
        })
    }
}

impl ConfigureEngineEvm<TempoExecutionData> for TempoEvmConfig {
    fn evm_env_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.evm_env(&payload.block)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        let TempoExecutionData {
            block,
            validator_set,
        } = payload;
        let mut context = self.context_for_block(block)?;

        context.validator_set = validator_set.clone();

        Ok(context)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        let block = Arc::clone(&payload.block);
        let transactions =
            (0..payload.block.body().transactions.len()).map(move |i| (block.clone(), i));

        let sender_recovery_cache = self.sender_recovery_cache.clone();

        Ok((transactions, move |input| {
            RecoveredInBlock::new(input, &sender_recovery_cache)
        }))
    }
}

/// A [`reth_evm::execute::ExecutableTxFor`] implementation that contains a pointer to the
/// block and the transaction index, allowing to prepare a [`TempoTxEnv`] without having to
/// clone block or transaction.
#[derive(Clone)]
struct RecoveredInBlock {
    block: Arc<SealedBlock<Block>>,
    index: usize,
    sender: Address,
}

impl RecoveredInBlock {
    fn new(
        (block, index): (Arc<SealedBlock<Block>>, usize),
        cache: &SenderRecoveryCache,
    ) -> Result<Self, RecoveryError> {
        let tx = &block.body().transactions[index];
        let tx_hash = tx.tx_hash();

        let sender = if let Some(cached_sender) = cache.remove(tx_hash) {
            cached_sender
        } else {
            tx.try_recover()?
        };

        Ok(Self {
            block,
            index,
            sender,
        })
    }
}

impl RecoveredTx<TempoTxEnvelope> for RecoveredInBlock {
    fn tx(&self) -> &TempoTxEnvelope {
        &self.block.body().transactions[self.index]
    }

    fn signer(&self) -> &alloy_primitives::Address {
        &self.sender
    }
}

impl ToTxEnv<TempoTxEnv> for RecoveredInBlock {
    fn to_tx_env(&self) -> TempoTxEnv {
        TempoTxEnv::from_recovered_tx(self.tx(), *self.signer())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempo_chainspec::hardfork::{TempoHardfork, TempoHardforks};

    #[test]
    fn test_evm_config_can_query_tempo_hardforks() {
        // Create a test chainspec with Adagio at genesis
        let chainspec = Arc::new(tempo_chainspec::TempoChainSpec::from_genesis(
            tempo_chainspec::spec::ANDANTINO.genesis().clone(),
        ));

        let evm_config = TempoEvmConfig::new_with_default_factory(chainspec);

        // Should be able to query Tempo hardforks through the chainspec
        assert!(evm_config.chain_spec().is_adagio_active_at_timestamp(0));
        assert!(evm_config.chain_spec().is_adagio_active_at_timestamp(1000));

        // Should be able to query activation condition
        let activation = evm_config
            .chain_spec()
            .tempo_fork_activation(TempoHardfork::Adagio);
        assert_eq!(activation, reth_chainspec::ForkCondition::Timestamp(0));
    }
}
