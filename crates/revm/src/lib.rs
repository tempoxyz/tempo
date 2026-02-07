//! Tempo revm specific implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod block;
// Suppress unused_crate_dependencies warning for tracing
#[cfg(not(test))]
use tracing as _;

mod common;
pub use common::{TempoStateAccess, TempoTx};
pub mod error;
pub mod evm;
pub mod exec;
pub mod gas_params;
pub mod handler;
mod instructions;
mod tx;

pub use block::TempoBlockEnv;
pub use error::{TempoHaltReason, TempoInvalidTransaction};
pub use evm::TempoEvm;
pub use gas_params::{
    EXISTING_NONCE_KEY_GAS, EXPIRING_NONCE_GAS, NEW_NONCE_KEY_GAS, count_access_list,
    tip1000_intrinsic_gas,
};
pub use handler::calculate_aa_batch_intrinsic_gas;
pub use revm::interpreter::instructions::utility::IntoAddress;
pub use tx::{TempoBatchCallEnv, TempoTxEnv};
