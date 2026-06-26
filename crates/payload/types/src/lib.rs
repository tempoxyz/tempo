//! Tempo payload types.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod attrs;
mod budget;

use alloy_primitives::{B256, Bytes};
pub use attrs::TempoPayloadAttributes;
pub use budget::{
    MarshalPersistEstimator, ValidationLatencyEstimate, ValidationLatencyEstimator,
    ValidationLatencyWorkload, marshal_persist_estimate, observe_marshal_persist,
};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use alloy_eips::eip7685::Requests;
use alloy_primitives::U256;
use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_api::{BlockBody, ExecutionPayload, PayloadTypes};
use reth_payload_primitives::{BuiltPayload, BuiltPayloadExecutedBlock};
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock, SealedOrRecoveredBlock};
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
    /// RLP-encoded EIP-7928 block access list, when generated for this payload.
    block_access_list: Option<Bytes>,
    /// The executed block data, used to skip re-execution in the engine tree.
    executed_block: Option<BuiltPayloadExecutedBlock<TempoPrimitives>>,
    /// Replayable builder work for this payload.
    ///
    /// This excludes proposer-only idle waiting, but includes transaction
    /// execution and non-interruptible `builder_finish`.
    validation_work_duration: Duration,
    /// Time validators are expected to spend validating this payload.
    validation_latency_duration: Duration,
    /// Approximate execution block RLP size estimate used for pacing and builder-side limits.
    execution_block_size_estimate: usize,
    /// Shared cache for the encoded execution block bytes.
    execution_block_encoded: EncodedBlock,
}

impl TempoBuiltPayload {
    /// Creates a new [`TempoBuiltPayload`].
    pub fn new(
        inner: EthBuiltPayload<TempoPrimitives>,
        block_access_list: Option<Bytes>,
        executed_block: Option<BuiltPayloadExecutedBlock<TempoPrimitives>>,
        validation_work_duration: Duration,
        validation_latency_duration: Duration,
        execution_block_size_estimate: usize,
        execution_block_encoded: EncodedBlock,
    ) -> Self {
        Self {
            inner,
            block_access_list,
            executed_block,
            validation_work_duration,
            validation_latency_duration,
            execution_block_size_estimate,
            execution_block_encoded,
        }
    }

    /// Converts the built payload into owned execution payload parts.
    pub fn into_execution_payload(self) -> (SealedBlock<Block>, Option<Bytes>) {
        (
            Arc::unwrap_or_clone(self.inner.block_arc().clone()).into_sealed_block(),
            self.block_access_list,
        )
    }

    /// Converts the built payload into consensus block parts without cloning the execution block.
    pub fn into_consensus_execution_payload(
        self,
    ) -> (SealedOrRecoveredBlock<Block>, Option<Bytes>, EncodedBlock) {
        let execution_block = SealedOrRecoveredBlock::recovered_arc(self.inner.block_arc().clone());

        (
            execution_block,
            self.block_access_list,
            self.execution_block_encoded,
        )
    }

    /// Returns the approximate execution block RLP size estimate.
    pub fn execution_block_size_estimate(&self) -> usize {
        self.execution_block_size_estimate
    }

    /// Returns replayable builder work for this payload.
    pub fn validation_work_duration(&self) -> Duration {
        self.validation_work_duration
    }

    /// Returns the time validators are expected to spend validating this payload.
    pub fn validation_latency_duration(&self) -> Duration {
        self.validation_latency_duration
    }

    /// Converts the built payload into [`TempoExecutionData`].
    pub fn into_execution_data(self) -> TempoExecutionData {
        let (block, block_access_list, _) = self.into_consensus_execution_payload();
        TempoExecutionData {
            block,
            block_access_list,
            validator_set: None,
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

    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }
}

/// Execution data for Tempo node. Simply wraps a sealed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoExecutionData {
    /// The built block.
    #[serde(with = "serde_sealed_or_recovered_block")]
    pub block: SealedOrRecoveredBlock<Block>,
    /// RLP-encoded EIP-7928 block access list, when supplied with the payload.
    pub block_access_list: Option<Bytes>,
    /// Validator set active at the time this block was built.
    pub validator_set: Option<Vec<B256>>,
}

/// Serde helper for preserving the legacy plain block JSON shape.
///
/// `SealedOrRecoveredBlock` normally serializes through `SealedBlock`, which exposes the
/// `SealedHeader` wrapper as an extra nested `header`. Consensus RPC and execution payload JSON
/// historically used `tempo_primitives::Block`, so this keeps those wire formats stable.
pub mod serde_sealed_or_recovered_block {
    use reth_primitives_traits::{SealedBlock, SealedOrRecoveredBlock};
    use tempo_primitives::Block;

    pub fn serialize<S>(
        block: &SealedOrRecoveredBlock<Block>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(serde::Serialize)]
        struct BlockRef<'a> {
            header: &'a tempo_primitives::TempoHeader,
            body: &'a tempo_primitives::BlockBody,
        }

        serde::Serialize::serialize(
            &BlockRef {
                header: block.header(),
                body: block.body(),
            },
            serializer,
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SealedOrRecoveredBlock<Block>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct BlockParts {
            header: tempo_primitives::TempoHeader,
            body: tempo_primitives::BlockBody,
        }

        let BlockParts { header, body } = serde::Deserialize::deserialize(deserializer)?;
        Ok(SealedBlock::seal_slow(Block { header, body }).into())
    }
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

    fn gas_limit(&self) -> u64 {
        self.block.gas_limit()
    }

    fn slot_number(&self) -> Option<u64> {
        self.block.slot_number()
    }

    fn block_access_list(&self) -> Option<&Bytes> {
        self.block_access_list.as_ref()
    }
}

impl From<TempoBuiltPayload> for TempoExecutionData {
    fn from(value: TempoBuiltPayload) -> Self {
        value.into_execution_data()
    }
}

impl PayloadTypes for TempoPayloadTypes {
    type ExecutionData = TempoExecutionData;
    type BuiltPayload = TempoBuiltPayload;
    type PayloadAttributes = TempoPayloadAttributes;

    fn block_to_payload(block: SealedBlock<Block>, bal: Option<Bytes>) -> Self::ExecutionData {
        TempoExecutionData {
            block: block.into(),
            block_access_list: bal,
            validator_set: None,
        }
    }
}

/// Shared cache for an execution-layer block encoded as RLP bytes.
///
/// Clones share the same once-initialized slot for lazy, one-time computation of the encoded bytes.
/// For example, a payload builder can hand this cache to consumers while a background task encodes
/// the block as it is prepared for proposal.
#[derive(Clone, Debug, Default)]
pub struct EncodedBlock(Arc<OnceLock<Bytes>>);

impl EncodedBlock {
    pub fn new(bytes: Bytes) -> Self {
        Self(Arc::new(OnceLock::from(bytes)))
    }

    /// Returns cached encoded bytes when they are already available.
    pub fn get(&self) -> Option<&Bytes> {
        self.0.get()
    }

    /// Returns cached encoded bytes, encoding `block` first if the cache is empty.
    pub fn get_or_encode<T>(&self, block: &T) -> &Bytes
    where
        T: alloy_rlp::Encodable,
    {
        self.get_or_encode_with(|| {
            let mut encoded = Vec::new();
            block.encode(&mut encoded);
            encoded.into()
        })
    }

    /// Returns cached encoded bytes, filling the cache with `encode` if it is empty.
    pub fn get_or_encode_with(&self, encode: impl FnOnce() -> Bytes) -> &Bytes {
        self.0.get_or_init(encode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_data_roundtrips_legacy_plain_block_json() {
        let fixture = serde_json::json!({
            "block": {
                "body": {
                    "ommers": [],
                    "transactions": [],
                    "withdrawals": null
                },
                "header": {
                    "difficulty": "0x0",
                    "extraData": "0x",
                    "gasLimit": "0x0",
                    "gasUsed": "0x0",
                    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mainBlockGeneralGasLimit": "0x0",
                    "miner": "0x0000000000000000000000000000000000000000",
                    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "0x0000000000000000",
                    "number": "0x0",
                    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "sharedGasLimit": "0x0",
                    "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                    "timestamp": "0x0",
                    "timestampMillisPart": "0x0",
                    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                }
            },
            "block_access_list": null,
            "validator_set": null
        });

        let execution_data: TempoExecutionData = serde_json::from_value(fixture.clone()).unwrap();
        let roundtripped = serde_json::to_value(execution_data).unwrap();

        assert_eq!(roundtripped, fixture);
    }
}
