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
        let TempoExecutionData { block } = payload;
        Ok(block.into_sealed_block())
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Mirrors the strict millisecond ordering TempoConsensus enforces against the parent.
        if attr.timestamp_millis() <= header.timestamp_millis() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use reth_primitives_traits::Header;
    use test_case::test_case;

    fn header(timestamp: u64, timestamp_millis_part: u64) -> TempoHeader {
        TempoHeader {
            timestamp_millis_part,
            inner: Header {
                timestamp,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn attributes(timestamp: u64, timestamp_millis_part: u64) -> TempoPayloadAttributes {
        TempoPayloadAttributes::new(None, timestamp, timestamp_millis_part, Bytes::new(), None)
    }

    #[test_case(10, 500, 10, 499; "same second lower millis")]
    #[test_case(10, 500, 10, 500; "same millisecond")]
    #[test_case(10, 500, 9, 999; "earlier second")]
    fn rejects_non_increasing_millis_timestamp(
        parent_secs: u64,
        parent_millis: u64,
        attr_secs: u64,
        attr_millis: u64,
    ) {
        assert!(matches!(
            TempoEngineValidator::new().validate_payload_attributes_against_header(
                &attributes(attr_secs, attr_millis),
                &header(parent_secs, parent_millis),
            ),
            Err(InvalidPayloadAttributesError::InvalidTimestamp)
        ));
    }

    #[test_case(10, 500, 10, 501; "same second higher millis")]
    #[test_case(10, 999, 11, 0; "next second")]
    fn accepts_increasing_millis_timestamp(
        parent_secs: u64,
        parent_millis: u64,
        attr_secs: u64,
        attr_millis: u64,
    ) {
        assert!(
            TempoEngineValidator::new()
                .validate_payload_attributes_against_header(
                    &attributes(attr_secs, attr_millis),
                    &header(parent_secs, parent_millis),
                )
                .is_ok()
        );
    }
}
