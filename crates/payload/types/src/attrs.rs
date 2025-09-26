use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes;
use alloy_rpc_types_eth::Withdrawals;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_node_api::PayloadBuilderAttributes;
use std::{
    convert::Infallible,
    sync::{Arc, atomic, atomic::Ordering},
};

/// Container type for all components required to build a payload.
///
/// The `TempoPayloadBuilderAttributes` has an additional feature of interrupting payload.
#[derive(Debug, Clone)]
pub struct TempoPayloadBuilderAttributes {
    inner: EthPayloadBuilderAttributes,
    interrupt: Arc<atomic::AtomicBool>,
}

impl TempoPayloadBuilderAttributes {
    /// Creates new `TempoPayloadBuilderAttributes` with `inner` attributes.
    pub fn new(inner: EthPayloadBuilderAttributes) -> Self {
        Self {
            inner,
            interrupt: Arc::new(atomic::AtomicBool::new(false)),
        }
    }

    /// Returns the `interrupt` flag. If true, it marks that a payload is requested to stop
    /// processing any more transactions.
    pub fn is_interrupted(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed)
    }
}

impl PayloadBuilderAttributes for TempoPayloadBuilderAttributes {
    type RpcPayloadAttributes = PayloadAttributes;
    type Error = Infallible;

    fn try_new(
        parent: B256,
        rpc_payload_attributes: Self::RpcPayloadAttributes,
        version: u8,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self::new(EthPayloadBuilderAttributes::try_new(
            parent,
            rpc_payload_attributes,
            version,
        )?))
    }

    fn payload_id(&self) -> alloy_rpc_types_engine::payload::PayloadId {
        self.inner.payload_id()
    }

    fn parent(&self) -> B256 {
        self.inner.parent()
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn suggested_fee_recipient(&self) -> Address {
        self.inner.suggested_fee_recipient()
    }

    fn prev_randao(&self) -> B256 {
        self.inner.prev_randao()
    }

    fn withdrawals(&self) -> &Withdrawals {
        self.inner.withdrawals()
    }
}
