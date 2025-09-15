//! Tempo payload types.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::{EthBuiltPayload, EthPayloadBuilderAttributes};
use reth_ethereum_primitives::Block;
use reth_node_api::{ExecutionPayload, PayloadBuilderAttributes, PayloadTypes};
use reth_primitives_traits::SealedBlock;
use serde::{Deserialize, Serialize};

/// Payload types for Tempo node.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TempoPayloadTypes;

/// Execution data for Tempo node. Simply wraps a sealed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoExecutionData(pub SealedBlock<Block>);

impl ExecutionPayload for TempoExecutionData {
    fn parent_hash(&self) -> alloy_primitives::B256 {
        self.0.parent_hash
    }

    fn block_hash(&self) -> alloy_primitives::B256 {
        self.0.hash()
    }

    fn block_number(&self) -> u64 {
        self.0.number
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.0
            .body()
            .withdrawals
            .as_ref()
            .map(|withdrawals| &withdrawals.0)
    }

    fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> {
        self.0.parent_beacon_block_root
    }

    fn timestamp(&self) -> u64 {
        self.0.timestamp
    }

    fn gas_used(&self) -> u64 {
        self.0.gas_used
    }
}

impl PayloadTypes for TempoPayloadTypes {
    type PayloadAttributes =
        <Self::PayloadBuilderAttributes as PayloadBuilderAttributes>::RpcPayloadAttributes;
    type PayloadBuilderAttributes = EthPayloadBuilderAttributes;
    type ExecutionData = TempoExecutionData;
    type BuiltPayload = EthBuiltPayload;

    fn block_to_payload(block: SealedBlock<Block>) -> Self::ExecutionData {
        TempoExecutionData(block)
    }
}
