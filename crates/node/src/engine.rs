use alloy_rpc_types_engine::ExecutionData;
use reth_ethereum::{Block, engine::EthPayloadAttributes, primitives::Header};
use reth_node_api::{
    EngineApiMessageVersion, EngineApiValidator, EngineObjectValidationError,
    InvalidPayloadAttributesError, NewPayloadError, PayloadOrAttributes, PayloadValidator,
};
use reth_node_ethereum::{EthEngineTypes, EthereumEngineValidator};
use reth_primitives_traits::RecoveredBlock;
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;

/// Type encapsulating Tempo engine validation logic. Wraps an inner [`EthereumEngineValidator`].
pub struct TempoEngineValidator {
    inner: EthereumEngineValidator<TempoChainSpec>,
}

impl TempoEngineValidator {
    /// Creates a new [`TempoEngineValidator`] with the given chain spec.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            inner: EthereumEngineValidator::new(chain_spec),
        }
    }
}

impl PayloadValidator<EthEngineTypes> for TempoEngineValidator {
    type Block = Block;

    fn ensure_well_formed_payload(
        &self,
        payload: ExecutionData,
    ) -> Result<RecoveredBlock<Block>, NewPayloadError> {
        PayloadValidator::<EthEngineTypes>::ensure_well_formed_payload(&self.inner, payload)
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &EthPayloadAttributes,
        header: &Header,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure that payload attributes timestamp is not in the past
        if attr.timestamp < header.timestamp {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

impl EngineApiValidator<EthEngineTypes> for TempoEngineValidator {
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, ExecutionData, EthPayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        EngineApiValidator::<EthEngineTypes>::validate_version_specific_fields(
            &self.inner,
            version,
            payload_or_attrs,
        )
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &EthPayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        EngineApiValidator::<EthEngineTypes>::ensure_well_formed_attributes(
            &self.inner,
            version,
            attributes,
        )
    }
}
