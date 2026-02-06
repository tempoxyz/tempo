//! Regression testing framework for the Tempo execution layer.
//!
//! Executes test vectors against the EVM, validates transaction outcomes, and generates
//! fingerprints for regression detection.

pub mod abi_encode;
pub mod database;
pub mod executor;
pub mod fingerprint;
pub mod genesis;
pub mod state_capture;
pub mod vector;

pub use database::VectorDatabase;
pub use executor::{
    Log, TxExecutionResult, VectorExecutionResult, VectorExecutor, validate_tx_outcomes,
};
pub use fingerprint::{Fingerprint, LogFingerprint, TxFingerprint};
pub use state_capture::{FieldValue, PostExecutionState, PrecompileFieldValues};
pub use vector::{AccountState, Prestate, TxOutcome};
