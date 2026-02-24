//! Tempo payload types.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod attrs;

use alloy_primitives::B256;
pub use attrs::{InterruptHandle, TempoPayloadAttributes, TempoPayloadBuilderAttributes};
use std::sync::Arc;

use alloy_eips::eip7685::Requests;
use alloy_primitives::U256;
use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_api::{BlockBody, ExecutionPayload, PayloadBuilderAttributes, PayloadTypes};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock};
use serde::{Deserialize, Serialize};
use tempo_primitives::{Block, TempoPrimitives};

/// Payload types for Tempo node.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TempoPayloadTypes;

/// Built payload type for Tempo node.
///
/// Wraps [`EthBuiltPayload`] and optionally includes the executed block data
/// to enable the engine tree fast path (skipping re-execution for self-built payloads).
#[derive(Debug, Clone)]
pub struct TempoBuiltPayload {
    /// The inner built payload.
    inner: EthBuiltPayload<TempoPrimitives>,
    /// The executed block data, used to skip re-execution in the engine tree.
    executed_block: Option<BuiltPayloadExecutedBlock<TempoPrimitives>>,
}

impl TempoBuiltPayload {
    /// Creates a new [`TempoBuiltPayload`].
    pub fn new(
        inner: EthBuiltPayload<TempoPrimitives>,
        executed_block: Option<BuiltPayloadExecutedBlock<TempoPrimitives>>,
    ) -> Self {
        Self {
            inner,
            executed_block,
        }
    }
}

impl BuiltPayload for TempoBuiltPayload {
    type Primitives = TempoPrimitives;

    fn block(&self) -> &SealedBlock<Block> {
        self.inner.block()
    }

    fn fees(&self) -> U256 {
        self.inner.fees()
    }

    fn executed_block(&self) -> Option<BuiltPayloadExecutedBlock<Self::Primitives>> {
        self.executed_block.clone()
    }

    fn requests(&self) -> Option<Requests> {
        self.inner.requests()
    }
}

/// Execution data for Tempo node. Simply wraps a sealed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoExecutionData {
    /// The built block.
    pub block: Arc<SealedBlock<Block>>,
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
        self.block
            .body()
            .withdrawals
            .as_ref()
            .map(|withdrawals| &withdrawals.0)
    }

    fn parent_beacon_block_root(&self) -> Option<alloy_primitives::B256> {
        self.block.parent_beacon_block_root()
    }

    fn timestamp(&self) -> u64 {
        self.block.timestamp()
    }

    fn transaction_count(&self) -> usize {
        self.block.body().transaction_count()
    }

    fn gas_used(&self) -> u64 {
        self.block.gas_used()
    }

    fn block_access_list(&self) -> Option<&alloy_primitives::Bytes> {
        None
    }
}

impl PayloadTypes for TempoPayloadTypes {
    type ExecutionData = TempoExecutionData;
    type BuiltPayload = TempoBuiltPayload;
    type PayloadAttributes =
        <Self::PayloadBuilderAttributes as PayloadBuilderAttributes>::RpcPayloadAttributes;
    type PayloadBuilderAttributes = TempoPayloadBuilderAttributes;

    fn block_to_payload(block: SealedBlock<Block>) -> Self::ExecutionData {
        TempoExecutionData {
            block: Arc::new(block),
            validator_set: None,
        }
    }
}
