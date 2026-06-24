//! Tempo revm specific implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

// Suppress unused_crate_dependencies warning for tracing
#[cfg(not(test))]
use tracing as _;

mod common;
pub use common::{TempoStateAccess, TempoTx};
pub mod error;
pub mod evm;
pub mod exec;
mod fee_manager;
pub mod gas_credits;
pub mod gas_params;
pub mod handler;
mod instructions;
mod tx;

pub use error::{TempoHaltReason, TempoInvalidTransaction};
pub use evm::TempoEvm;
pub use fee_manager::{ProtocolFeeManager, TempoFeeManager};
pub use handler::{ValidationContext, calculate_aa_batch_intrinsic_gas};
pub use revm::interpreter::instructions::utility::IntoAddress;
pub use tempo_primitives::TempoBlockEnv;
pub use tx::{TempoBatchCallEnv, TempoTxEnv};
