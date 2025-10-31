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
/// It also carries optional DKG data to be included in the block's extra_data field.
#[derive(Debug, Clone)]
pub struct TempoPayloadBuilderAttributes {
    inner: EthPayloadBuilderAttributes,
    interrupt: InterruptHandle,
    timestamp_millis_part: u64,
    optional_extra_data: Option<Vec<u8>>,
}

impl TempoPayloadBuilderAttributes {
    /// Creates new `TempoPayloadBuilderAttributes` with `inner` attributes.
    pub fn new(
        id: PayloadId,
        parent: B256,
        suggested_fee_recipient: Address,
        timestamp_millis: u64,
    ) -> Self {
        let (seconds, millis) = (timestamp_millis / 1000, timestamp_millis % 1000);
        Self {
            inner: EthPayloadBuilderAttributes {
                id,
                parent,
                timestamp: seconds,
                suggested_fee_recipient,
                prev_randao: B256::ZERO,
                withdrawals: Withdrawals::default(),
                parent_beacon_block_root: Some(B256::ZERO),
            },
            interrupt: InterruptHandle::default(),
            timestamp_millis_part: millis,
            optional_extra_data: None,
        }
    }

    /// Creates new `TempoPayloadBuilderAttributes` with optional DKG extra data.
    pub fn with_optional_extra_data(
        id: PayloadId,
        parent: B256,
        suggested_fee_recipient: Address,
        timestamp_millis: u64,
        extra_data: Option<Vec<u8>>,
    ) -> Self {
        let mut attrs = Self::new(id, parent, suggested_fee_recipient, timestamp_millis);
        attrs.optional_extra_data = extra_data;
        attrs
    }

    /// Returns the optional extra data to be included in the block header.
    pub fn optional_extra_data(&self) -> Option<&Vec<u8>> {
        self.optional_extra_data.as_ref()
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

// Required by reth's e2e-test-utils for integration tests.
// The test utilities need to convert from standard Ethereum payload attributes
// to custom chain-specific attributes.
impl From<EthPayloadBuilderAttributes> for TempoPayloadBuilderAttributes {
    fn from(inner: EthPayloadBuilderAttributes) -> Self {
        Self {
            inner,
            interrupt: InterruptHandle::default(),
            timestamp_millis_part: 0,
            optional_extra_data: None,
        }
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
        Ok(Self {
            inner: EthPayloadBuilderAttributes::try_new(parent, rpc_payload_attributes, version)?,
            interrupt: InterruptHandle::default(),
            timestamp_millis_part: 0,
            optional_extra_data: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attributes_without_extra_data() {
        let parent = B256::default();
        let id = PayloadId::default();
        let recipient = Address::default();
        let timestamp_millis = 1000;

        let attrs = TempoPayloadBuilderAttributes::new(id, parent, recipient, timestamp_millis);

        assert_eq!(attrs.optional_extra_data(), None);
        assert_eq!(attrs.parent(), parent);
        assert_eq!(attrs.suggested_fee_recipient(), recipient);
        assert_eq!(attrs.timestamp(), 1); // 1000 ms / 1000 = 1 second
    }

    #[test]
    fn test_attributes_with_optional_extra_data() {
        let parent = B256::default();
        let id = PayloadId::default();
        let recipient = Address::default();
        let timestamp_millis = 1000;
        let extra_data = vec![1, 2, 3, 4, 5];

        let attrs = TempoPayloadBuilderAttributes::with_optional_extra_data(
            id,
            parent,
            recipient,
            timestamp_millis,
            Some(extra_data.clone()),
        );

        assert_eq!(attrs.optional_extra_data(), Some(&extra_data));
        assert_eq!(attrs.parent(), parent);
        assert_eq!(attrs.suggested_fee_recipient(), recipient);
    }

    #[test]
    fn test_attributes_with_extra_data_none() {
        let parent = B256::default();
        let id = PayloadId::default();
        let recipient = Address::default();
        let timestamp_millis = 1000;

        let attrs = TempoPayloadBuilderAttributes::with_optional_extra_data(
            id,
            parent,
            recipient,
            timestamp_millis,
            None,
        );

        assert_eq!(attrs.optional_extra_data(), None);
    }
}
