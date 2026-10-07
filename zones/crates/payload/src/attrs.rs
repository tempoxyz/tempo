//! Zone payload types.
//!
//! Owns the full payload attribute types for the zone, wrapping Ethereum
//! payload attributes and adding L1 block data plus the millisecond timestamp
//! portion. This avoids pulling in Tempo-specific concepts the zone doesn't
//! use (interrupts, subblocks, DKG extra-data).

use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_engine::{PayloadAttributes as EthPayloadAttributes, PayloadId};
use alloy_rpc_types_eth::Withdrawal;
use reth_node_api::{
    InvalidPayloadAttributesError, NewPayloadError, PayloadTypes, PayloadValidator,
};
use reth_payload_primitives::PayloadAttributes;
use reth_primitives_traits::{AlloyBlockHeader, SealedBlock, SealedHeader};
use serde::{Deserialize, Serialize};
use tempo_node::engine::TempoEngineValidator;
use tempo_payload_types::{TempoBuiltPayload, TempoExecutionData};
use tempo_primitives::{Block, TempoHeader};
use zone_l1::PreparedL1Block;

/// Explicit opening Tempo system-call variant for a Zone payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TempoImport {
    Full(Box<PreparedL1Block>),
    CheckpointOnly(Vec<SealedHeader<TempoHeader>>),
}

impl TempoImport {
    pub(crate) fn is_checkpoint_only(&self) -> bool {
        matches!(self, Self::CheckpointOnly(_))
    }

    pub(crate) fn follows_checkpoint_blocks(&self) -> bool {
        match self {
            Self::Full(prepared) => prepared.follows_checkpoint_blocks,
            Self::CheckpointOnly(_) => false,
        }
    }

    pub(crate) fn total_deposits(&self) -> usize {
        match self {
            Self::Full(prepared) => prepared.queued_deposits.len(),
            Self::CheckpointOnly(_) => 0,
        }
    }

    pub(crate) fn enabled_tokens(&self) -> usize {
        match self {
            Self::Full(prepared) => prepared.enabled_tokens.len(),
            Self::CheckpointOnly(_) => 0,
        }
    }
}

/// Zone RPC payload attributes — the type that flows through FCU.
///
/// Carries standard Ethereum attributes, a millisecond timestamp portion, and
/// the prepared L1 block whose deposits should be included in this zone block.
/// The L1 data is set by the ZoneEngine before sending
/// FCU and is skipped during (de)serialisation since it only travels through
/// in-process channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePayloadAttributes {
    /// Standard Ethereum payload attributes.
    pub inner: EthPayloadAttributes,

    /// Milliseconds portion of the timestamp (0–999).
    pub timestamp_millis_part: u64,

    /// Prepared L1 block to process in this zone block. Every zone block
    /// processes exactly one L1 block via `advanceTempo`. Decryption and ABI
    /// encoding have already been performed by the engine; TIP-403 policy is
    /// enforced during `advanceTempo` when the deposits mint TIP-20 tokens.
    pub tempo_import: TempoImport,
}

impl reth_node_api::PayloadAttributes for ZonePayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        reth_payload_primitives::payload_id(parent_hash, &self.inner)
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals.as_ref()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number
    }
}

impl ZonePayloadAttributes {
    /// Returns a reference to the prepared L1 block data.
    pub fn tempo_import(&self) -> &TempoImport {
        &self.tempo_import
    }

    /// Returns the extra data for the block header (always empty for zones).
    pub fn extra_data(&self) -> Bytes {
        Bytes::default()
    }

    /// Returns the milliseconds portion of the timestamp.
    pub fn timestamp_millis_part(&self) -> u64 {
        self.timestamp_millis_part
    }

    pub fn suggested_fee_recipient(&self) -> Address {
        self.inner.suggested_fee_recipient
    }

    pub fn prev_randao(&self) -> B256 {
        self.inner.prev_randao
    }
}

/// Zone payload types.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ZonePayloadTypes;

impl PayloadTypes for ZonePayloadTypes {
    type ExecutionData = TempoExecutionData;
    type BuiltPayload = TempoBuiltPayload;
    type PayloadAttributes = ZonePayloadAttributes;

    fn block_to_payload(
        block: SealedBlock<Block>,
        bal: Option<alloy_primitives::Bytes>,
    ) -> Self::ExecutionData {
        TempoExecutionData {
            block: block.into(),
            block_access_list: bal,
        }
    }
}

impl PayloadValidator<ZonePayloadTypes> for TempoEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: TempoExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        let TempoExecutionData {
            block,
            block_access_list: _,
        } = payload;
        Ok(block.into_sealed_block())
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &ZonePayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        if PayloadAttributes::timestamp(attr) < AlloyBlockHeader::timestamp(header) {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}
