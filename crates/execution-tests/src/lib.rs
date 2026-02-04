//! Precompile test framework for Tempo.
//!
//! This crate provides a framework for testing precompiles using JSON test vectors.

pub mod database;
pub mod executor;
pub mod fingerprint;
pub mod state_capture;
pub mod vector;

pub use database::VectorDatabase;
pub use executor::{ExecutionResult_, Log, TxExecutionResult, VectorExecutor, validate_tx_outcomes};
pub use fingerprint::{Fingerprint, LogFingerprint, TxFingerprint};
pub use state_capture::{FieldValue, PostExecutionState, PrecompileFieldValues};
pub use vector::{AccountState, Prestate, TxOutcome};
