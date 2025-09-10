//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod evm;
use std::sync::Arc;

use alloy_evm::{EthEvmFactory, EvmFactory, eth::EthBlockExecutorFactory};
pub use evm::TempoEvmFactory;

use reth_evm_ethereum::{EthBlockAssembler, RethReceiptBuilder};
use tempo_chainspec::TempoChainSpec;

// pub type TempoEvmConfig = reth_evm_ethereum::EthEvmConfig<TempoChainSpec, TempoEvmFactory>;

/// Tempo-related EVM configuration.
#[derive(Debug, Clone)]
pub struct TempoEvmConfig {
    /// Inner [`EthBlockExecutorFactory`].
    pub executor_factory:
        EthBlockExecutorFactory<RethReceiptBuilder, Arc<TempoChainSpec>, EthEvmFactory>,
    /// Ethereum block assembler.
    pub block_assembler: EthBlockAssembler<TempoChainSpec>,
}
