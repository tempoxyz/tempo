//! Tempo primitive types

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub use alloy_consensus::Header;
use alloy_primitives::Log;
use reth_ethereum_primitives::EthereumReceipt;
use reth_primitives_traits::NodePrimitives;

pub mod transaction;
pub use transaction::{FEE_TOKEN_TX_TYPE_ID, TempoTxEnvelope, TempoTxType, TxFeeToken};

/// Tempo block.
pub type Block = alloy_consensus::Block<TempoTxEnvelope>;

/// Tempo block body.
pub type BlockBody = alloy_consensus::BlockBody<TempoTxEnvelope>;

/// Tempo receipt.
pub type TempoReceipt<L = Log> = EthereumReceipt<TempoTxType, L>;

/// A [`NodePrimitives`] implementation for Tempo.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TempoPrimitives;

impl NodePrimitives for TempoPrimitives {
    type Block = Block;
    type BlockHeader = Header;
    type BlockBody = BlockBody;
    type SignedTx = TempoTxEnvelope;
    type Receipt = TempoReceipt;
}
