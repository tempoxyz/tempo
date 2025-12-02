use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_node_api::{InvalidPayloadAttributesError, NewPayloadError, PayloadValidator};
use reth_primitives_traits::{AlloyBlockHeader as _, RecoveredBlock};
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

    fn ensure_well_formed_payload(
        &self,
        payload: TempoExecutionData,
    ) -> Result<RecoveredBlock<Block>, NewPayloadError> {
        let TempoExecutionData { block, validator_set: _ } = payload;
        block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure that payload attributes timestamp is not in the past
        if attr.inner.timestamp < header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}
