//! Core types used throughout the Reth-Malachite integration.
//!
//! This module defines fundamental types that bridge between Reth's blockchain
//! types and Malachite's consensus types. These types handle the representation
//! of addresses, blocks as consensus values, and proposal structures.
//!
//! # Key Types
//!
//! - [`Address`]: A 20-byte Ethereum-style address
//! - [`Value`]: Wraps a Reth block as the consensus value
//! - [`ValueId`]: Unique identifier for values (block hash)
//! - [`ProposalPart`]: Components of a consensus proposal
//! - Various proposal-related types for the consensus protocol

use alloy_primitives::B256;
use bytes::Bytes;
use malachitebft_core_types::Round;
use malachitebft_signing_ed25519::Signature;
use reth_ethereum_primitives::Block;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Address([u8; 20]);

impl Address {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 20 {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub const ZERO: Self = Self([0u8; 20]);
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub struct ValueId(B256);

impl ValueId {
    pub const fn new(hash: B256) -> Self {
        Self(hash)
    }

    pub const fn as_b256(&self) -> &B256 {
        &self.0
    }

    // Keep as_u64 for compatibility during migration
    pub fn as_u64(&self) -> u64 {
        // Take the first 8 bytes of the hash as u64
        u64::from_be_bytes(self.0[..8].try_into().unwrap())
    }
}

impl From<B256> for ValueId {
    fn from(hash: B256) -> Self {
        Self::new(hash)
    }
}

impl From<u64> for ValueId {
    fn from(value: u64) -> Self {
        // For backwards compatibility, create a B256 from u64
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_be_bytes());
        Self::new(B256::from(bytes))
    }
}

impl fmt::Display for ValueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The value to decide on
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub struct Value(B256);

impl Value {
    /// Creates a new Value from a hash
    pub const fn new(hash: B256) -> Self {
        Self(hash)
    }

    /// Creates a Value from a Block
    pub fn from_block(block: &Block) -> Self {
        Self(block.header.hash_slow())
    }

    /// Gets the hash
    pub const fn hash(&self) -> B256 {
        self.0
    }

    pub fn id(&self) -> ValueId {
        ValueId::from(self.0)
    }

    pub fn size_bytes(&self) -> usize {
        // A hash is always 32 bytes
        32
    }
}

impl From<B256> for Value {
    fn from(hash: B256) -> Self {
        Self(hash)
    }
}

impl From<&Block> for Value {
    fn from(block: &Block) -> Self {
        Self::from_block(block)
    }
}

impl malachitebft_core_types::Value for Value {
    type Id = ValueId;

    fn id(&self) -> ValueId {
        self.id()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalData {
    pub bytes: Bytes,
}

impl ProposalData {
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    pub fn size_bytes(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl fmt::Debug for ProposalData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProposalData")
            .field("bytes", &"<...>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalPart {
    Init(ProposalInit),
    Data(ProposalData),
    Fin(ProposalFin),
}

impl ProposalPart {
    pub fn get_type(&self) -> &'static str {
        match self {
            Self::Init(_) => "init",
            Self::Data(_) => "data",
            Self::Fin(_) => "fin",
        }
    }

    pub fn as_init(&self) -> Option<&ProposalInit> {
        match self {
            Self::Init(init) => Some(init),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&ProposalData> {
        match self {
            Self::Data(data) => Some(data),
            _ => None,
        }
    }

    pub fn size_bytes(&self) -> usize {
        match self {
            Self::Init(_) => std::mem::size_of::<ProposalInit>(),
            Self::Data(data) => data.size_bytes(),
            Self::Fin(_) => std::mem::size_of::<ProposalFin>(),
        }
    }
}

/// A part of a value for a height, round. Identified in this scope by the sequence.
///
/// The `block_hash` field is used for verification purposes. Since consensus now operates
/// on block hashes (Value == BlockHash) rather than full blocks, we need to ensure that
/// the block data streamed in ProposalData chunks corresponds to the hash that validators
/// are actually voting on. This prevents corruption or tampering during transmission.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProposalInit {
    pub height: crate::height::Height,
    pub round: Round,
    pub proposer: Address,
    /// The hash of the block being proposed. Used to verify that the reconstructed
    /// block from ProposalData chunks matches the intended consensus value.
    pub block_hash: B256,
}

impl ProposalInit {
    pub fn new(
        height: crate::height::Height,
        round: Round,
        proposer: Address,
        block_hash: B256,
    ) -> Self {
        Self {
            height,
            round,
            proposer,
            block_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalFin {
    pub signature: Signature,
}

impl ProposalFin {
    pub fn new(signature: Signature) -> Self {
        Self { signature }
    }
}

impl PartialOrd for ProposalData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProposalData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl std::hash::Hash for ProposalData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl PartialOrd for ProposalFin {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProposalFin {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signature.to_bytes().cmp(&other.signature.to_bytes())
    }
}

impl std::hash::Hash for ProposalFin {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.signature.to_bytes().hash(state);
    }
}

impl PartialOrd for ProposalPart {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProposalPart {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (ProposalPart::Init(a), ProposalPart::Init(b)) => a.cmp(b),
            (ProposalPart::Data(a), ProposalPart::Data(b)) => a.cmp(b),
            (ProposalPart::Fin(a), ProposalPart::Fin(b)) => a.cmp(b),
            (ProposalPart::Init(_), _) => std::cmp::Ordering::Less,
            (ProposalPart::Data(_), ProposalPart::Init(_)) => std::cmp::Ordering::Greater,
            (ProposalPart::Data(_), ProposalPart::Fin(_)) => std::cmp::Ordering::Less,
            (ProposalPart::Fin(_), _) => std::cmp::Ordering::Greater,
        }
    }
}

impl std::hash::Hash for ProposalPart {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            ProposalPart::Init(init) => {
                0u8.hash(state);
                init.hash(state);
            }
            ProposalPart::Data(data) => {
                1u8.hash(state);
                data.hash(state);
            }
            ProposalPart::Fin(fin) => {
                2u8.hash(state);
                fin.hash(state);
            }
        }
    }
}

impl malachitebft_core_types::ProposalPart<crate::context::MalachiteContext> for ProposalPart {
    fn is_first(&self) -> bool {
        matches!(self, Self::Init(_))
    }

    fn is_last(&self) -> bool {
        matches!(self, Self::Fin(_))
    }
}
