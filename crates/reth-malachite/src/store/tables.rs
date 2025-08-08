//! Database table definitions for consensus data.

use crate::{
    Value,
    codec::{ProtoCodec, decode_commit_certificate, encode_commit_certificate},
    context::MalachiteContext,
    height::Height,
};
use alloy_primitives::B256;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_codec::Codec;
use malachitebft_core_types::{CommitCertificate, Round};
use reth_db::{
    DatabaseError, TableSet, TableType, TableViewer,
    table::{Compress, Decode, Decompress, Encode, TableInfo},
    tables,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Key for storing decided values and certificates by height
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HeightKey(pub u64);

impl From<Height> for HeightKey {
    fn from(height: Height) -> Self {
        Self(height.0)
    }
}

impl From<HeightKey> for Height {
    fn from(key: HeightKey) -> Self {
        Height(key.0)
    }
}

/// Key for storing undecided proposals
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProposalKey {
    pub height: u64,
    pub round: u32,
    pub value_id_hash: [u8; 32],
}

impl ProposalKey {
    pub fn new(height: Height, round: Round, value_id: &crate::ValueId) -> Self {
        // Copy the B256 hash directly
        let value_id_hash = value_id.as_b256().0;

        Self {
            height: height.0,
            round: round.as_u32().unwrap_or(0),
            value_id_hash,
        }
    }
}

/// Stored decided value with certificate
#[derive(Debug, Clone)]
pub struct DecidedValue {
    pub value: Value,
    pub certificate: CommitCertificate<MalachiteContext>,
}

// Manual serde implementation for DecidedValue (required by tables! macro but not used)
impl Serialize for DecidedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // This is not actually used, as we implement Compress/Decompress
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for DecidedValue {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // This is not actually used, as we implement Compress/Decompress
        panic!("DecidedValue deserialization should use Decompress trait")
    }
}

/// Stored undecided proposal
#[derive(Debug, Clone)]
pub struct StoredProposal {
    pub proposal: ProposedValue<MalachiteContext>,
}

// Manual serde implementation for StoredProposal (required by tables! macro but not used)
impl Serialize for StoredProposal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // This is not actually used, as we implement Compress/Decompress
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for StoredProposal {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // This is not actually used, as we implement Compress/Decompress
        panic!("StoredProposal deserialization should use Decompress trait")
    }
}

// Implement reth database traits for HeightKey
impl Encode for HeightKey {
    type Encoded = [u8; 8];

    fn encode(self) -> Self::Encoded {
        self.0.to_be_bytes()
    }
}

impl Decode for HeightKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 8 {
            return Err(DatabaseError::Decode);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(value);
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

// Implement reth database traits for ProposalKey
impl Encode for ProposalKey {
    type Encoded = [u8; 44]; // 8 + 4 + 32

    fn encode(self) -> Self::Encoded {
        let mut encoded = [0u8; 44];
        encoded[0..8].copy_from_slice(&self.height.to_be_bytes());
        encoded[8..12].copy_from_slice(&self.round.to_be_bytes());
        encoded[12..44].copy_from_slice(&self.value_id_hash);
        encoded
    }
}

impl Decode for ProposalKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 44 {
            return Err(DatabaseError::Decode);
        }

        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&value[0..8]);
        let height = u64::from_be_bytes(height_bytes);

        let mut round_bytes = [0u8; 4];
        round_bytes.copy_from_slice(&value[8..12]);
        let round = u32::from_be_bytes(round_bytes);

        let mut value_id_hash = [0u8; 32];
        value_id_hash.copy_from_slice(&value[12..44]);

        Ok(Self {
            height,
            round,
            value_id_hash,
        })
    }
}

// Implement compression for DecidedValue using protobuf
impl Compress for DecidedValue {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        // Encode value and certificate separately
        let mut data = Vec::new();

        // Encode value (serialize the block)
        let value_bytes = crate::app::encode_value(&self.value).to_vec();
        let value_len = value_bytes.len() as u32;
        data.extend_from_slice(&value_len.to_le_bytes());
        data.extend_from_slice(&value_bytes);

        // Encode certificate
        if let Ok(cert_proto) = encode_commit_certificate(&self.certificate) {
            use prost::Message;
            let cert_bytes = cert_proto.encode_to_vec();
            let cert_len = cert_bytes.len() as u32;
            data.extend_from_slice(&cert_len.to_le_bytes());
            data.extend_from_slice(&cert_bytes);
        }

        data
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let compressed = self.clone().compress();
        buf.put_slice(&compressed);
    }
}

impl Decompress for DecidedValue {
    fn decompress(mut value: &[u8]) -> Result<Self, DatabaseError> {
        use prost::Message;

        // Decode value length and data
        if value.len() < 4 {
            return Err(DatabaseError::Decode);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&value[..4]);
        let value_len = u32::from_le_bytes(len_bytes) as usize;
        value = &value[4..];

        if value.len() < value_len {
            return Err(DatabaseError::Decode);
        }
        let value_data = value[..value_len].to_vec();
        value = &value[value_len..];

        // Decode certificate length and data
        if value.len() < 4 {
            return Err(DatabaseError::Decode);
        }
        len_bytes.copy_from_slice(&value[..4]);
        let cert_len = u32::from_le_bytes(len_bytes) as usize;
        value = &value[4..];

        if value.len() < cert_len {
            return Err(DatabaseError::Decode);
        }
        let cert_bytes = &value[..cert_len];

        // Decode certificate
        let cert_proto = crate::proto::CommitCertificate::decode(cert_bytes)
            .map_err(|_| DatabaseError::Decode)?;
        let certificate =
            decode_commit_certificate(cert_proto).map_err(|_| DatabaseError::Decode)?;

        // Decode value from bytes
        let value = crate::app::decode_value(bytes::Bytes::from(value_data))
            .ok_or(DatabaseError::Decode)?;

        Ok(DecidedValue { value, certificate })
    }
}

// Implement compression for StoredProposal using protobuf
impl Compress for StoredProposal {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        // Use the ProtoCodec to encode the ProposedValue
        ProtoCodec
            .encode(&self.proposal)
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default()
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let compressed = self.clone().compress();
        buf.put_slice(&compressed);
    }
}

impl Decompress for StoredProposal {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        // Use the ProtoCodec to decode the ProposedValue
        let proposal = ProtoCodec
            .decode(bytes::Bytes::from(value.to_vec()))
            .map_err(|_| DatabaseError::Decode)?;

        Ok(StoredProposal { proposal })
    }
}

/// Key for storing blocks by hash
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockKey(pub B256);

impl From<B256> for BlockKey {
    fn from(hash: B256) -> Self {
        Self(hash)
    }
}

/// Stored block data
#[derive(Debug, Clone)]
pub struct StoredBlock {
    pub block: reth_primitives::Block,
}

// Manual serde implementation for StoredBlock (required by tables! macro but not used)
impl Serialize for StoredBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // This is not actually used, as we implement Compress/Decompress
        serializer.serialize_unit()
    }
}

impl<'de> Deserialize<'de> for StoredBlock {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // This is not actually used, as we implement Compress/Decompress
        panic!("StoredBlock deserialization should use Decompress trait")
    }
}

// Implement reth database traits for BlockKey
impl Encode for BlockKey {
    type Encoded = [u8; 32];

    fn encode(self) -> Self::Encoded {
        self.0.0
    }
}

impl Decode for BlockKey {
    fn decode(value: &[u8]) -> Result<Self, DatabaseError> {
        if value.len() != 32 {
            return Err(DatabaseError::Decode);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(value);
        Ok(Self(B256::from(bytes)))
    }
}

// Implement compression for StoredBlock
impl Compress for StoredBlock {
    type Compressed = Vec<u8>;

    fn compress(self) -> Self::Compressed {
        // Use our encode_block function to serialize the block
        crate::app::encode_block(&self.block).to_vec()
    }

    fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
        let compressed = self.clone().compress();
        buf.put_slice(&compressed);
    }
}

impl Decompress for StoredBlock {
    fn decompress(value: &[u8]) -> Result<Self, DatabaseError> {
        // Use our decode_block function to deserialize the block
        let block = crate::app::decode_block(bytes::Bytes::from(value.to_vec()))
            .ok_or(DatabaseError::Decode)?;

        Ok(StoredBlock { block })
    }
}

// Define the tables
tables! {
    /// Table for storing decided values (committed blocks)
    table DecidedValues {
        type Key = HeightKey;
        type Value = DecidedValue;
    }

    /// Table for storing undecided proposals
    table UndecidedProposals {
        type Key = ProposalKey;
        type Value = StoredProposal;
    }

    /// Table for storing the latest consensus state
    table ConsensusState {
        type Key = Vec<u8>;
        type Value = Vec<u8>;
    }

    /// Table for storing blocks by hash
    table Blocks {
        type Key = BlockKey;
        type Value = StoredBlock;
    }
}
