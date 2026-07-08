//! Errors surfaced by the lthash state-root pipeline.

use alloy_primitives::B256;
use reth_errors::ProviderError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum LthashError {
    #[error("lthash task dropped without returning an outcome")]
    OutcomeClosed,
    #[error("lthash update stream closed before FinishedUpdates")]
    UpdatesClosed,
    #[error("failed to build lthash parent-state provider")]
    ProviderBuild(#[source] ProviderError),
    #[error(
        "stored lthash accumulator at height {number} hashes to {stored_root}, expected parent root {parent_state_root}"
    )]
    AccumulatorRootMismatch {
        parent_state_root: B256,
        stored_root: B256,
        number: u64,
    },
    #[error("stored lthash accumulator at height {number} failed to decode")]
    AccumulatorCorrupt { number: u64 },
    #[error("lthash old account read failed for {hashed_address}")]
    AccountRead {
        hashed_address: B256,
        source: ProviderError,
    },
    #[error("lthash old storage read failed for {hashed_address}/{hashed_slot}")]
    StorageRead {
        hashed_address: B256,
        hashed_slot: B256,
        source: ProviderError,
    },
}
