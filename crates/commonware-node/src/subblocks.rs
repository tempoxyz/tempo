use alloy_primitives::B256;
use commonware_cryptography::ed25519::Signature;
use futures::channel::mpsc;
use tempo_primitives::TempoTxEnvelope;

#[derive(Debug, Clone)]
pub struct SubBlock {
    /// Hash of the parent block. This subblock can only be included as
    /// part of the block building on top of the specified parent.
    pub parent_hash: B256,
    /// Transactions included in the subblock.
    pub transactions: Vec<TempoTxEnvelope>,
    /// Signature of the subblock.
    pub signature: Signature,
}

/// Task for collecting and broadcasting subblocks.
pub struct SubBlockService {
    rx: mpsc::Receiver<>
}
