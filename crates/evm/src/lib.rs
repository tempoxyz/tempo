//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod evm;
use std::{borrow::Cow, convert::Infallible, sync::Arc};

use alloy_eips::eip1559::INITIAL_BASE_FEE;
use alloy_evm::{EthEvmFactory, EvmFactory, eth::EthBlockExecutorFactory};
use alloy_primitives::{Address, Bytes, U256};
pub use evm::TempoEvmFactory;
use reth_chainspec::{EthChainSpec, EthereumHardforks};
use reth_ethereum_forks::{EthereumHardfork, Hardforks};
use reth_ethereum_primitives::{Block, EthPrimitives};
use reth_evm::{
    self, ConfigureEvm, EvmEnv, NextBlockEnvAttributes,
    eth::{EthBlockExecutionCtx, spec::EthExecutorSpec},
    revm::{
        context::{BlockEnv, CfgEnv},
        context_interface::block::BlobExcessGasAndPrice,
        primitives::hardfork::SpecId,
    },
};
use reth_primitives_traits::{
    AlloyBlockHeader, Header, SealedBlock, SealedHeader, constants::MAX_TX_GAS_LIMIT_OSAKA,
};

use reth_evm_ethereum::{EthBlockAssembler, RethReceiptBuilder, revm_spec};
use tempo_chainspec::TempoChainSpec;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner [`EthBlockExecutorFactory`].
    pub executor_factory:
        EthBlockExecutorFactory<RethReceiptBuilder, Arc<TempoChainSpec>, EthEvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: EthBlockAssembler<TempoChainSpec>,
}

impl TempoEvmConfig {
    /// Create a new [`TempoEvmConfig`] with the given chain spec and EVM factory.
    pub fn new(chain_spec: Arc<TempoChainSpec>, evm_factory: EthEvmFactory) -> Self {
        let executor_factory = EthBlockExecutorFactory::new(
            RethReceiptBuilder::default(),
            chain_spec.clone(),
            evm_factory,
        );

        let block_assembler = EthBlockAssembler::new(chain_spec.clone());
        Self {
            executor_factory,
            block_assembler,
        }
    }

    /// Create a new [`TempoEvmConfig`] with the given chain spec and default EVM factory.
    pub fn new_with_default_factory(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self::new(chain_spec, EthEvmFactory::default())
    }

    /// Returns the chain spec
    pub const fn chain_spec(&self) -> &Arc<TempoChainSpec> {
        self.executor_factory.spec()
    }

    /// Sets the extra data for the block assembler.
    pub fn with_extra_data(mut self, extra_data: Bytes) -> Self {
        self.block_assembler.extra_data = extra_data;
        self
    }
}

impl ConfigureEvm for TempoEvmConfig {
    type Primitives = EthPrimitives;
    type Error = Infallible;
    type NextBlockEnvCtx = NextBlockEnvAttributes;
    type BlockExecutorFactory =
        EthBlockExecutorFactory<RethReceiptBuilder, Arc<TempoChainSpec>, EthEvmFactory>;
    type BlockAssembler = EthBlockAssembler<TempoChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv {
        let blob_params = self.chain_spec().blob_params_at_timestamp(header.timestamp);
        let spec = revm_spec(self.chain_spec(), header);

        // configure evm env based on parent block
        let mut cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec(spec);

        if let Some(blob_params) = &blob_params {
            cfg_env.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        }

        if self
            .chain_spec()
            .is_osaka_active_at_timestamp(header.timestamp)
        {
            cfg_env.tx_gas_limit_cap = Some(MAX_TX_GAS_LIMIT_OSAKA);
        }

        // derive the EIP-4844 blob fees from the header's `excess_blob_gas` and the current
        // blobparams
        let blob_excess_gas_and_price =
            header
                .excess_blob_gas
                .zip(blob_params)
                .map(|(excess_blob_gas, params)| {
                    let blob_gasprice = params.calc_blob_fee(excess_blob_gas);
                    BlobExcessGasAndPrice {
                        excess_blob_gas,
                        blob_gasprice,
                    }
                });

        let block_env = BlockEnv {
            number: U256::from(header.number()),
            beneficiary: header.beneficiary(),
            timestamp: U256::from(header.timestamp()),
            difficulty: if spec >= SpecId::MERGE {
                U256::ZERO
            } else {
                header.difficulty()
            },
            prevrandao: if spec >= SpecId::MERGE {
                header.mix_hash()
            } else {
                None
            },
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            blob_excess_gas_and_price,
        };

        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        // // ensure we're not missing any timestamp based hardforks
        // let chain_spec = self.executor_factory.chain_spec();
        // let blob_params = chain_spec.blob_params_at_timestamp(attributes.timestamp);
        // let spec_id = revm_spec_by_timestamp_and_block_number(
        //     chain_spec,
        //     attributes.timestamp,
        //     parent.number() + 1,
        // );
        //
        // // configure evm env based on parent block
        // let mut cfg = CfgEnv::new()
        //     .with_chain_id(chain_spec.chain().id())
        //     .with_spec(spec_id);
        //
        // if let Some(blob_params) = &blob_params {
        //     cfg.set_max_blobs_per_tx(blob_params.max_blobs_per_tx);
        // }
        //
        // // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // // cancun now, we need to set the excess blob gas to the default value(0)
        // let blob_excess_gas_and_price = parent
        //     .maybe_next_block_excess_blob_gas(blob_params)
        //     .or_else(|| (spec_id == SpecId::CANCUN).then_some(0))
        //     .map(|excess_blob_gas| {
        //         let blob_gasprice = blob_params
        //             .unwrap_or_else(|| alloy_eips::eip7840::BlobParams::cancun())
        //             .calc_blob_fee(excess_blob_gas);
        //         BlobExcessGasAndPrice {
        //             excess_blob_gas,
        //             blob_gasprice,
        //         }
        //     });
        //
        // let mut basefee = chain_spec.next_block_base_fee(parent, attributes.timestamp);
        //
        // let mut gas_limit = attributes.gas_limit;
        //
        // // If we are on the London fork boundary, we need to multiply the parent's gas limit by the
        // // elasticity multiplier to get the new gas limit.
        // if chain_spec
        //     .fork(EthereumHardfork::London)
        //     .transitions_at_block(parent.number + 1)
        // {
        //     let elasticity_multiplier = chain_spec
        //         .base_fee_params_at_timestamp(attributes.timestamp)
        //         .elasticity_multiplier;
        //
        //     // multiply the gas limit by the elasticity multiplier
        //     gas_limit *= elasticity_multiplier as u64;
        //
        //     // set the base fee to the initial base fee from the EIP-1559 spec
        //     basefee = Some(INITIAL_BASE_FEE)
        // }
        //
        // let block_env = BlockEnv {
        //     number: U256::from(parent.number + 1),
        //     beneficiary: attributes.suggested_fee_recipient,
        //     timestamp: U256::from(attributes.timestamp),
        //     difficulty: U256::ZERO,
        //     prevrandao: Some(attributes.prev_randao),
        //     gas_limit,
        //     // calculate basefee based on parent block's gas usage
        //     basefee: basefee.unwrap_or_default(),
        //     // calculate excess gas based on parent block's blob gas usage
        //     blob_excess_gas_and_price,
        // };
        //
        // Ok((cfg, block_env).into())
        todo!()
    }

    fn context_for_block<'a>(&self, block: &'a SealedBlock<Block>) -> EthBlockExecutionCtx<'a> {
        EthBlockExecutionCtx {
            parent_hash: block.header().parent_hash,
            parent_beacon_block_root: block.header().parent_beacon_block_root,
            ommers: &block.body().ommers,
            withdrawals: block.body().withdrawals.as_ref().map(Cow::Borrowed),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader,
        attributes: Self::NextBlockEnvCtx,
    ) -> EthBlockExecutionCtx<'_> {
        EthBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            ommers: &[],
            withdrawals: attributes.withdrawals.map(Cow::Owned),
        }
    }
}
