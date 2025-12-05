//! Tempo primitive types

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg), allow(unexpected_cfgs))]

pub use alloy_consensus::Header;
use alloy_primitives::Log;
use reth_ethereum_primitives::EthereumReceipt;
use reth_primitives_traits::NodePrimitives;

pub mod transaction;
pub use transaction::{
    AASigned, FEE_TOKEN_TX_TYPE_ID, MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH,
    SECP256K1_SIGNATURE_LENGTH, SignatureType, TEMPO_GAS_PRICE_SCALING_FACTOR, TEMPO_TX_TYPE_ID,
    TempoSignature, TempoTransaction, TempoTxEnvelope, TempoTxType, TxFeeToken,
    derive_p256_address,
};

mod header;
pub use header::TempoHeader;

mod receipt;
pub use receipt::TempoReceiptEnvelope;

pub mod subblock;
pub use subblock::{
    RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockMetadata, SubBlockVersion,
};

/// Tempo block.
pub type Block = alloy_consensus::Block<TempoTxEnvelope, TempoHeader>;

/// Tempo block body.
pub type BlockBody = alloy_consensus::BlockBody<TempoTxEnvelope, TempoHeader>;

/// Tempo receipt.
pub type TempoReceipt<L = Log> = EthereumReceipt<TempoTxType, L>;

/// A [`NodePrimitives`] implementation for Tempo.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TempoPrimitives;

impl NodePrimitives for TempoPrimitives {
    type Block = Block;
    type BlockHeader = TempoHeader;
    type BlockBody = BlockBody;
    type SignedTx = TempoTxEnvelope;
    type Receipt = TempoReceipt;
}
