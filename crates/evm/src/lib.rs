//! Tempo EVM implementation.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod action_replay;
#[cfg(feature = "reth")]
mod assemble;
mod block;
mod common;
#[cfg(feature = "reth")]
mod config;
#[cfg(feature = "reth")]
pub mod consensus;
mod context;
#[cfg(feature = "engine")]
mod engine;
mod env;
#[cfg(feature = "reth")]
pub mod error;
pub mod evm;
mod fee_manager;
mod handler;
mod instructions;
#[cfg(feature = "jit")]
pub mod jit;
#[cfg(feature = "reth")]
mod reth_block;
mod signature_gas;
#[cfg(test)]
mod test_utils;
mod transaction;
pub mod transaction_error;

pub use action_replay::{
    ExpiringNonceReplay, StorageActionReplay, StorageActionReplayError, StorageActionReplayOutcome,
    StorageActionReplayState,
};
#[cfg(feature = "reth")]
pub use assemble::TempoBlockAssembler;
pub use block::{
    ExecutorState, TempoBlockExecutor, TempoBlockRules, TempoReceiptBuilder, TempoTxResult,
};
pub use common::{TempoStateAccess, TempoTx};
#[cfg(feature = "reth")]
pub use config::TempoEvmConfig;
pub use context::TempoBlockExecutionCtx;
#[cfg(feature = "reth")]
pub use context::TempoNextBlockEnvAttributes;
pub use env::TempoEvmEnv;
#[cfg(feature = "reth")]
pub use error::TempoEvmError;
pub use evm::{PrecompilesBuilder, SYSTEM_CALL_GAS_LIMIT, TempoEvm, TempoEvmFactory};
pub use fee_manager::{
    FeeTokenResolver, ProtocolFeeContext, ProtocolFeeManager, ResolvedFeeToken, TempoFeeManager,
};
pub use handler::{
    TempoBlockEnv, TempoBlockExt, TempoConfig, TempoConfigSelector, TempoEvmExt, TempoEvmTypes,
    TempoTxResultExt, build_tempo_evm, configurable_account::account_access_gas,
    tempo_execution_config, tempo_opcode_config, tempo_tx_registry,
};
pub use transaction::{ExecutionContext, RecoveredTxEnvelope, TempoAaTx, TempoEvmTx, TempoTxEnv};
pub use transaction_error::{FeePaymentError, TempoInvalidTransaction};
#[cfg(feature = "genesis")]
pub mod genesis;

#[cfg(feature = "engine")]
use rayon as _;
