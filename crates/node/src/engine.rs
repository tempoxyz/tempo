use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_node_api::{InvalidPayloadAttributesError, NewPayloadError, PayloadValidator};
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block, TempoHeader};

/// Type encapsulating Tempo engine validation logic.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEngineValidator;

impl TempoEngineValidator {
    /// Creates a new [`TempoEngineValidator`] with the given chain spec.
    pub fn new() -> Self {
        Self {}
    }
}

impl PayloadValidator<TempoPayloadTypes> for TempoEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: TempoExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        let TempoExecutionData {
            block,
            block_access_list: _,
            validator_set: _,
        } = payload;
        Ok(block.into_sealed_block())
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure the payload attributes strictly advance time at millisecond resolution.
        //
        // Tempo blocks are sub-second, so a header carries whole seconds in `timestamp`
        // plus a `timestamp_millis_part`. Comparing only whole seconds here would accept
        // attributes that move *backwards* within the same second (e.g. parent at 100.900s,
        // attributes at 100.100s), which the authoritative consensus check
        // (`TempoConsensus::validate_header_against_parent`) then rejects — a wasted build.
        // Match that rule: block time must strictly increase in milliseconds.
        if attr.timestamp_millis() <= header.timestamp_millis() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}
