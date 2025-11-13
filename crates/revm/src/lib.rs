//! Tempo revm specific implementations.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod block;
// Suppress unused_crate_dependencies warning for tracing
#[cfg(not(test))]
use tracing as _;

mod common;
pub use common::{TempoStateAccess, TempoTx};
pub mod error;
pub mod evm;
pub mod exec;
pub mod handler;
mod instructions;
mod tx;

pub use block::TempoBlockEnv;
pub use error::TempoInvalidTransaction;
pub use evm::TempoEvm;
pub use tx::{AATxEnv, TempoTxEnv};
