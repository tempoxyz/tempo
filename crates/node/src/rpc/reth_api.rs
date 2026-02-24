use alloy_primitives::Bytes;
use alloy_rpc_types_engine::PayloadStatus;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_builder::ConsensusEngineHandle;
use reth_primitives_traits::SealedBlock;
use std::sync::Arc;
use tempo_payload_types::TempoExecutionData;

use crate::TempoPayloadTypes;

/// `reth_` namespace RPC trait.
#[rpc(server, namespace = "reth")]
pub trait TempoRethApi {
    /// Accepts an RLP-encoded block, decodes it, converts it to `ExecutionData`,
    /// and submits it to the engine for execution.
    #[method(name = "newPayload")]
    async fn new_payload(&self, block: Bytes) -> RpcResult<PayloadStatus>;
}

/// Tempo-specific `reth_` namespace implementation.
#[derive(Debug, Clone)]
pub struct TempoRethRpc {
    engine_handle: ConsensusEngineHandle<TempoPayloadTypes>,
}

impl TempoRethRpc {
    /// Create a new `reth_` namespace RPC handler.
    pub fn new(engine_handle: ConsensusEngineHandle<TempoPayloadTypes>) -> Self {
        Self { engine_handle }
    }
}

#[async_trait::async_trait]
impl TempoRethApiServer for TempoRethRpc {
    async fn new_payload(&self, block: Bytes) -> RpcResult<PayloadStatus> {
        let block: tempo_primitives::Block = alloy_rlp::Decodable::decode(&mut block.as_ref())
            .map_err(|e| {
                jsonrpsee::types::ErrorObject::owned(
                    jsonrpsee::types::error::INVALID_PARAMS_CODE,
                    format!("failed to RLP-decode block: {e}"),
                    None::<()>,
                )
            })?;

        let sealed = SealedBlock::seal_slow(block);
        let execution_data = TempoExecutionData {
            block: Arc::new(sealed),
            validator_set: None,
        };

        let status = self
            .engine_handle
            .new_payload(execution_data)
            .await
            .map_err(|e| {
                jsonrpsee::types::ErrorObject::owned(
                    jsonrpsee::types::error::INTERNAL_ERROR_CODE,
                    format!("engine error: {e}"),
                    None::<()>,
                )
            })?;

        Ok(status)
    }
}
