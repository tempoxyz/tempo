use alloy_primitives::{Address, B256, Bytes};
use alloy_rpc_types_engine::PayloadId;
use alloy_rpc_types_eth::Withdrawals;
use reth_ethereum_engine_primitives::{EthPayloadAttributes, EthPayloadBuilderAttributes};
use reth_node_api::{PayloadAttributes, PayloadBuilderAttributes};
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    sync::{Arc, atomic, atomic::Ordering},
};
use tempo_primitives::RecoveredSubBlock;

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

    /// Returns whether the interrupt flag is set.
    pub fn is_interrupted(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Container type for all components required to build a payload.
///
/// The `TempoPayloadBuilderAttributes` has an additional feature of interrupting payload.
///
/// It also carries DKG data to be included in the block's extra_data field.
#[derive(derive_more::Debug, Clone)]
pub struct TempoPayloadBuilderAttributes {
    inner: EthPayloadBuilderAttributes,
    interrupt: InterruptHandle,
    timestamp_millis_part: u64,
    /// DKG ceremony data to include in the block's extra_data header field.
    ///
    /// This is empty when no DKG data is available (e.g., when the DKG manager
    /// hasn't produced ceremony outcomes yet, or when DKG operations fail).
    extra_data: Bytes,
    #[debug(skip)]
    subblocks: Arc<dyn Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static>,
}

impl TempoPayloadBuilderAttributes {
    /// Creates new `TempoPayloadBuilderAttributes` with `inner` attributes.
    pub fn new(
        id: PayloadId,
        parent: B256,
        suggested_fee_recipient: Address,
        timestamp_millis: u64,
        extra_data: Bytes,
        subblocks: impl Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static,
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
            extra_data,
            subblocks: Arc::new(subblocks),
        }
    }

    /// Returns the extra data to be included in the block header.
    pub fn extra_data(&self) -> &Bytes {
        &self.extra_data
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

    /// Returns the timestamp in milliseconds.
    pub fn timestamp_millis(&self) -> u64 {
        self.inner.timestamp().saturating_mul(1000).saturating_add(self.timestamp_millis_part)
    }

    /// Returns the subblocks.
    pub fn subblocks(&self) -> Vec<RecoveredSubBlock> {
        (self.subblocks)()
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
            extra_data: Bytes::default(),
            subblocks: Arc::new(Vec::new),
        }
    }
}

impl PayloadBuilderAttributes for TempoPayloadBuilderAttributes {
    type RpcPayloadAttributes = TempoPayloadAttributes;
    type Error = Infallible;

    fn try_new(
        parent: B256,
        rpc_payload_attributes: Self::RpcPayloadAttributes,
        version: u8,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let TempoPayloadAttributes {
            inner,
            timestamp_millis_part,
        } = rpc_payload_attributes;
        Ok(Self {
            inner: EthPayloadBuilderAttributes::try_new(parent, inner, version)?,
            interrupt: InterruptHandle::default(),
            timestamp_millis_part,
            extra_data: Bytes::default(),
            subblocks: Arc::new(Vec::new),
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

/// Tempo RPC payload attributes configuration.
#[derive(Debug, Clone, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut)]
#[serde(rename_all = "camelCase")]
pub struct TempoPayloadAttributes {
    /// Inner [`EthPayloadAttributes`].
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    pub inner: EthPayloadAttributes,

    /// Milliseconds portion of the timestamp.
    #[serde(with = "alloy_serde::quantity")]
    pub timestamp_millis_part: u64,
}

impl PayloadAttributes for TempoPayloadAttributes {
    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn withdrawals(&self) -> Option<&Vec<alloy_rpc_types_eth::Withdrawal>> {
        self.inner.withdrawals()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
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

        let attrs = TempoPayloadBuilderAttributes::new(
            id,
            parent,
            recipient,
            timestamp_millis,
            Bytes::default(),
            Vec::new,
        );

        assert_eq!(attrs.extra_data(), &Bytes::default());
        assert_eq!(attrs.parent(), parent);
        assert_eq!(attrs.suggested_fee_recipient(), recipient);
        assert_eq!(attrs.timestamp(), 1); // 1000 ms / 1000 = 1 second
    }

    #[test]
    fn test_attributes_with_extra_data() {
        let parent = B256::default();
        let id = PayloadId::default();
        let recipient = Address::default();
        let timestamp_millis = 1000;
        let extra_data = Bytes::from(vec![1, 2, 3, 4, 5]);

        let attrs = TempoPayloadBuilderAttributes::new(
            id,
            parent,
            recipient,
            timestamp_millis,
            extra_data.clone(),
            Vec::new,
        );

        assert_eq!(attrs.extra_data(), &extra_data);
        assert_eq!(attrs.parent(), parent);
        assert_eq!(attrs.suggested_fee_recipient(), recipient);
    }

    #[test]
    fn test_attributes_with_empty_extra_data() {
        let parent = B256::default();
        let id = PayloadId::default();
        let recipient = Address::default();
        let timestamp_millis = 1000;

        let attrs = TempoPayloadBuilderAttributes::new(
            id,
            parent,
            recipient,
            timestamp_millis,
            Bytes::default(),
            Vec::new,
        );

        assert_eq!(attrs.extra_data(), &Bytes::default());
    }
}
