use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::{PayloadAttributes, PayloadId};
use alloy_rpc_types_eth::Withdrawals;
use reth_ethereum_engine_primitives::EthPayloadBuilderAttributes;
use reth_node_api::PayloadBuilderAttributes;
use std::{
    convert::Infallible,
    sync::{Arc, atomic, atomic::Ordering},
};

/// A handle for a payload interrupt flag.
///
/// Can be fired using [`InterruptHandle::interrupt`].
#[derive(Debug, Clone, Default)]
pub struct InterruptHandle(Arc<atomic::AtomicBool>);

impl InterruptHandle {
    /// Turns on the interrupt flag on the associated payload.
    pub fn interrupt(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Container type for all components required to build a payload.
///
/// The `TempoPayloadBuilderAttributes` has an additional feature of interrupting payload.
#[derive(Debug, Clone)]
pub struct TempoPayloadBuilderAttributes {
    inner: EthPayloadBuilderAttributes,
    interrupt: InterruptHandle,
    timestamp_millis_part: u64,
}

impl TempoPayloadBuilderAttributes {
    /// Creates new `TempoPayloadBuilderAttributes` with `inner` attributes.
    pub fn new(
        id: PayloadId,
        parent: B256,
        suggested_fee_recipient: Address,
        timestamp_millis: u64,
    ) -> Self {
        Self {
            inner: EthPayloadBuilderAttributes {
                id,
                parent,
                timestamp: timestamp_millis / 1000,
                suggested_fee_recipient,
                prev_randao: B256::ZERO,
                withdrawals: Withdrawals::default(),
                parent_beacon_block_root: Some(B256::ZERO),
            },
            interrupt: InterruptHandle::default(),
            timestamp_millis_part: timestamp_millis % 1000,
        }
    }

    /// Returns the `interrupt` flag. If true, it marks that a payload is requested to stop
    /// processing any more transactions.
    pub fn is_interrupted(&self) -> bool {
        self.interrupt.0.load(Ordering::Relaxed)
    }

    /// Returns a cloneable [`InterruptHandle`] for turning on the `interrupt` flag.
    pub fn interrupt_handle(&self) -> &InterruptHandle {
        &self.interrupt
    }

    /// Returns the milliseconds portion of the timestamp.
    pub fn timestamp_millis_part(&self) -> u64 {
        self.timestamp_millis_part
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
        let inner = EthPayloadBuilderAttributes::try_new(parent, rpc_payload_attributes, version)?;
        Ok(Self {
            inner,
            interrupt: InterruptHandle::default(),
            timestamp_millis_part: 0,
        })
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
