//! Tempo primitive types

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_consensus::{Block, BlockBody, Header};
use reth_ethereum_primitives::Receipt;
use reth_primitives_traits::NodePrimitives;

pub mod transaction;
pub use transaction::{FEE_TOKEN_TX_TYPE_ID, TempoTxEnvelope, TempoTxType, TxFeeToken};

/// A [`NodePrimitives`] implementation for Tempo.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TempoPrimitives;

impl NodePrimitives for TempoPrimitives {
    type Block = Block<TempoTxEnvelope>;
    type BlockHeader = Header;
    type BlockBody = BlockBody<TempoTxEnvelope>;
    type SignedTx = TempoTxEnvelope;
    type Receipt = Receipt<TempoTxType>;
}
