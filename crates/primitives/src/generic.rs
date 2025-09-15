use crate::{TempoTxEnvelope, TempoTxType};
use alloy_consensus::{Block, BlockBody, Header, Receipt};
use reth_primitives_traits::NodePrimitives;

/// A [`NodePrimitives`] implementation for Tempo.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TempoPrimitives;

impl NodePrimitives for TempoPrimitives {
    type Block = Block<TempoTxEnvelope>;
    type BlockHeader = Header;
    type BlockBody = BlockBody<TempoTxEnvelope>;
    type SignedTx = TempoTxEnvelope;
    type Receipt = Receipt<TempoTxType>;
}
