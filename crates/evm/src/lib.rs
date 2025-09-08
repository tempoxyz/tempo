//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod evm;
pub use evm::TempoEvmFactory;

use tempo_chainspec::TempoChainSpec;

pub type TempoEvmConfig = reth_evm_ethereum::EthEvmConfig<TempoChainSpec, TempoEvmFactory>;
