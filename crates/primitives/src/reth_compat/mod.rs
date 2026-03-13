//! Reth-specific trait implementations for Tempo primitives.
//!
//! This module consolidates all `reth`/`reth-codec`/`serde-bincode-compat` trait
//! implementations so they can be cleanly removed when publishing `tempo-alloy`
//! without reth dependencies.

use alloy_primitives::Log;
use reth_ethereum_primitives::EthereumReceipt;
use reth_primitives_traits::NodePrimitives;

use crate::{Block, BlockBody, TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType};

/// Tempo receipt.
pub type TempoReceipt<L = Log> = EthereumReceipt<TempoTxType, L>;

impl NodePrimitives for TempoPrimitives {
    type Block = Block;
    type BlockHeader = TempoHeader;
    type BlockBody = BlockBody;
    type SignedTx = TempoTxEnvelope;
    type Receipt = TempoReceipt;
}

mod header;

mod subblock;

pub(crate) mod transaction;
