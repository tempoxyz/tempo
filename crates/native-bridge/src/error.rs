use alloy_primitives::B256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("config error: {0}")]
    Config(String),

    #[error("chain watcher error: {0}")]
    ChainWatcher(String),

    #[error("BLS signing error: {0}")]
    Signing(String),

    #[error("signature aggregation error: {0}")]
    Aggregation(String),

    #[error("submission error: {0}")]
    Submission(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("threshold not reached: have {have}, need {need}")]
    ThresholdNotReached { have: usize, need: usize },

    #[error("duplicate partial from validator {index}")]
    DuplicatePartial { index: u32 },

    #[error("message already processed: {0}")]
    AlreadyProcessed(B256),

    #[error("gossip error: {0}")]
    Gossip(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BridgeError>;
