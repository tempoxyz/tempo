//! Tempo RPC types.

mod header;
pub use header::TempoHeaderResponse;

mod native_multisig;
#[cfg(feature = "revm")]
#[doc(hidden)]
pub use native_multisig::create_mock_native_multisig_signature;
pub use native_multisig::{
    MultisigSimulationApproval, MultisigSimulationNestedSpec, MultisigSimulationPrimitiveApproval,
    MultisigSimulationSpec,
};

mod request;
pub use request::{FeeToken, TempoCallBuilderExt, TempoTransactionRequest};

mod receipt;
pub use receipt::TempoTransactionReceipt;

#[cfg(feature = "revm")]
mod revm_compat;

#[cfg(feature = "reth")]
mod reth_compat;

/// Various helper types for paginated queries.
pub mod pagination;
