use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_node_api::{InvalidPayloadAttributesError, NewPayloadError, PayloadValidator};
use reth_primitives_traits::SealedBlock;
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
        } = payload;
        Ok(block.into_sealed_block())
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure that payload attributes timestamp is not in the past. Tempo blocks carry a
        // sub-second part, so compare at millisecond precision like header validation does.
        if attr.timestamp_millis() < header.timestamp_millis() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    fn header_at(timestamp: u64, timestamp_millis_part: u64) -> TempoHeader {
        let mut header = TempoHeader::default();
        header.inner.timestamp = timestamp;
        header.timestamp_millis_part = timestamp_millis_part;
        header
    }

    fn attrs_at(timestamp: u64, timestamp_millis_part: u64) -> TempoPayloadAttributes {
        TempoPayloadAttributes::new(None, timestamp, timestamp_millis_part, Bytes::new(), None)
    }

    #[test]
    fn attributes_timestamp_is_checked_at_millisecond_precision() {
        let validator = TempoEngineValidator::new();
        let parent = header_at(100, 500);

        for (timestamp, millis_part, accepted) in [
            (99, 900, false),
            (100, 100, false),
            (100, 500, true),
            (100, 501, true),
            (101, 0, true),
        ] {
            let result = validator.validate_payload_attributes_against_header(
                &attrs_at(timestamp, millis_part),
                &parent,
            );
            assert_eq!(
                result.is_ok(),
                accepted,
                "{timestamp}.{millis_part:03}: {result:?}"
            );
            if !accepted {
                assert!(matches!(
                    result,
                    Err(InvalidPayloadAttributesError::InvalidTimestamp)
                ));
            }
        }
    }
}
