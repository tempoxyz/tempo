//! Tempo payload types.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod attrs;

use alloy_primitives::B256;
pub use attrs::{InterruptHandle, TempoPayloadAttributes, TempoPayloadBuilderAttributes};

use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_api::{ExecutionPayload, PayloadBuilderAttributes, PayloadTypes};
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock};
use serde::{Deserialize, Serialize};
use tempo_primitives::{Block, TempoPrimitives};

/// Payload types for Tempo node.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TempoPayloadTypes;

/// Execution data for Tempo node. Simply wraps a sealed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoExecutionData {
    /// The built block.
    pub block: SealedBlock<Block>,
    /// Validator set active at the time this block was built.
    pub validator_set: Option<Vec<B256>>,
}

impl ExecutionPayload for TempoExecutionData {
    fn parent_hash(&self) -> alloy_primitives::B256 {
        self.block.parent_hash()
    }

    fn block_hash(&self) -> alloy_primitives::B256 {
        self.block.hash()
    }

    fn block_number(&self) -> u64 {
        self.block.number()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.block.body().withdrawals.as_ref().map(|withdrawals| &withdrawals.0)
    }

    fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> {
        self.block.parent_beacon_block_root()
    }

    fn timestamp(&self) -> u64 {
        self.block.timestamp()
    }

    fn gas_used(&self) -> u64 {
        self.block.gas_used()
    }
}

impl PayloadTypes for TempoPayloadTypes {
    type PayloadAttributes =
        <Self::PayloadBuilderAttributes as PayloadBuilderAttributes>::RpcPayloadAttributes;
    type PayloadBuilderAttributes = TempoPayloadBuilderAttributes;
    type ExecutionData = TempoExecutionData;
    type BuiltPayload = EthBuiltPayload<TempoPrimitives>;

    fn block_to_payload(block: SealedBlock<Block>) -> Self::ExecutionData {
        TempoExecutionData { block, validator_set: None }
    }
}
