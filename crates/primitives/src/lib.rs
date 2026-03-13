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

/// A [`NodePrimitives`] implementation for Tempo.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct TempoPrimitives;

#[cfg(feature = "reth")]
mod reth_compat;
#[cfg(feature = "reth")]
pub use reth_compat::TempoReceipt;
