//! Shared helpers for ABI-level precompile integration tests.

#![allow(dead_code)]

use alloy::primitives::Bytes;
use evm2::precompiles::{PrecompileError, PrecompileHalt, PrecompileResult};

/// How a precompile call ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrecompileStatus {
    Success,
    Revert,
    Halt(PrecompileHalt),
}

/// Outcome of a precompile call and the gas it charged to the storage context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PrecompileOutput {
    pub(crate) status: PrecompileStatus,
    pub(crate) bytes: Bytes,
    pub(crate) gas_used: u64,
}

impl PrecompileOutput {
    /// Classifies `result`. Reverts and halts are outputs; fatal errors panic.
    #[track_caller]
    pub(crate) fn new(result: PrecompileResult, gas_used: u64) -> Self {
        let (status, bytes) = match result {
            Ok(output) => (PrecompileStatus::Success, output.into_bytes()),
            Err(PrecompileError::Revert(bytes)) => (PrecompileStatus::Revert, bytes),
            Err(PrecompileError::Halt(halt)) => (PrecompileStatus::Halt(halt), Bytes::new()),
            Err(error) => panic!("precompile call failed the frame: {error}"),
        };
        Self {
            status,
            bytes,
            gas_used,
        }
    }

    pub(crate) const fn is_revert(&self) -> bool {
        matches!(self.status, PrecompileStatus::Revert)
    }
}
