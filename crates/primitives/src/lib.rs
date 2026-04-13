//! Tempo primitive types

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg), allow(unexpected_cfgs))]

pub use alloy_consensus::Header;

pub mod transaction;
pub use transaction::{
    AASigned, MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    SignatureType, TEMPO_GAS_PRICE_SCALING_FACTOR, TEMPO_TX_TYPE_ID, TempoSignature,
    TempoTransaction, TempoTxEnvelope, TempoTxType, derive_p256_address,
};

mod header;
pub use header::TempoHeader;

pub mod subblock;
pub use subblock::{
    RecoveredSubBlock, SignedSubBlock, SubBlock, SubBlockMetadata, SubBlockVersion,
};

extern crate alloc;

use once_cell as _;

/// Tempo block.
pub type Block = alloy_consensus::Block<TempoTxEnvelope, TempoHeader>;

/// Tempo block body.
pub type BlockBody = alloy_consensus::BlockBody<TempoTxEnvelope, TempoHeader>;

#[cfg(feature = "reth")]
mod reth_compat;

/// Tempo receipt.
/// Implements reth trait bounds when the `reth` feature is enabled.
#[cfg(feature = "reth")]
pub use reth_compat::TempoReceipt;
#[cfg(not(feature = "reth"))]
pub type TempoReceipt<L = alloy_primitives::Log> = alloy_consensus::EthereumReceipt<TempoTxType, L>;

/// Marker type for Tempo node primitives.
/// Implements [`reth_primitives_traits::NodePrimitives`] when the `reth` feature is enabled.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TempoPrimitives;
