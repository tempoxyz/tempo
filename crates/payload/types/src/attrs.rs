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
        self.inner
            .timestamp()
            .saturating_mul(1000)
            .saturating_add(self.timestamp_millis_part)
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
    use alloy_rpc_types_eth::Withdrawal;

    trait TestExt: Sized {
        fn random() -> Self;
        fn with_timestamp(self, millis: u64) -> Self;
        fn with_subblocks(
            self,
            f: impl Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static,
        ) -> Self;
    }

    impl TestExt for TempoPayloadBuilderAttributes {
        fn random() -> Self {
            Self::new(
                PayloadId::default(),
                B256::random(),
                Address::random(),
                1000,
                Bytes::default(),
                Vec::new,
            )
        }

        fn with_timestamp(mut self, millis: u64) -> Self {
            self.inner.timestamp = millis / 1000;
            self.timestamp_millis_part = millis % 1000;
            self
        }

        fn with_subblocks(
            mut self,
            f: impl Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static,
        ) -> Self {
            self.subblocks = Arc::new(f);
            self
        }
    }

    #[test]
    fn test_interrupt_handle() {
        // Default state
        let handle = InterruptHandle::default();
        assert!(!handle.is_interrupted());

        // Interrupt sets flag
        handle.interrupt();
        assert!(handle.is_interrupted());

        // Clone shares state
        let handle2 = handle.clone();
        assert!(handle2.is_interrupted());

        // New handle via clone before interrupt
        let fresh = InterruptHandle::default();
        let cloned = fresh.clone();
        assert!(!cloned.is_interrupted());
        fresh.interrupt();
        assert!(cloned.is_interrupted()); // shared atomic

        // Multiple interrupts are idempotent
        handle.interrupt();
        handle.interrupt();
        assert!(handle.is_interrupted());
    }

    #[test]
    fn test_builder_attributes_construction() {
        let parent = B256::random();
        let id = PayloadId::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let recipient = Address::random();
        let extra_data = Bytes::from(vec![1, 2, 3, 4, 5]);
        let timestamp_millis = 1500; // 1s + 500ms

        // With extra_data
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
        assert_eq!(attrs.payload_id(), id);
        assert_eq!(attrs.timestamp(), 1);
        assert_eq!(attrs.timestamp_millis_part(), 500);

        // Hardcoded in ::new()
        assert_eq!(attrs.prev_randao(), B256::ZERO);
        assert_eq!(attrs.parent_beacon_block_root(), Some(B256::ZERO));
        assert!(attrs.withdrawals().is_empty());

        // Without extra_data
        let attrs2 = TempoPayloadBuilderAttributes::new(
            id,
            parent,
            recipient,
            timestamp_millis + 500, // 1.5 seconds + 500ms
            Bytes::default(),
            Vec::new,
        );
        assert_eq!(attrs2.extra_data(), &Bytes::default());
        assert_eq!(attrs2.timestamp(), 2);
        assert_eq!(attrs2.timestamp_millis_part(), 0);
    }

    #[test]
    fn test_builder_attributes_interrupt_integration() {
        let attrs = TempoPayloadBuilderAttributes::random();

        // Initially not interrupted
        assert!(!attrs.is_interrupted());

        // Get handle and interrupt
        let handle = attrs.interrupt_handle().clone();
        handle.interrupt();

        // Both see interrupted state
        assert!(attrs.is_interrupted());
        assert!(handle.is_interrupted());

        // Multiple handle accesses return same underlying state
        let handle2 = attrs.interrupt_handle();
        assert!(handle2.is_interrupted());
    }

    #[test]
    fn test_builder_attributes_timestamp_handling() {
        // Exact second boundary
        let attrs = TempoPayloadBuilderAttributes::random().with_timestamp(3000);
        assert_eq!(attrs.timestamp(), 3);
        assert_eq!(attrs.timestamp_millis_part(), 0);
        assert_eq!(attrs.timestamp_millis(), 3000);

        // With milliseconds remainder
        let attrs = TempoPayloadBuilderAttributes::random().with_timestamp(3999);
        assert_eq!(attrs.timestamp(), 3);
        assert_eq!(attrs.timestamp_millis_part(), 999);
        assert_eq!(attrs.timestamp_millis(), 3999);

        // Zero timestamp
        let attrs = TempoPayloadBuilderAttributes::random().with_timestamp(0);
        assert_eq!(attrs.timestamp(), 0);
        assert_eq!(attrs.timestamp_millis_part(), 0);
        assert_eq!(attrs.timestamp_millis(), 0);

        // Large timestamp (no overflow due to saturating ops)
        let large_ts = u64::MAX / 1000 * 1000;
        let attrs = TempoPayloadBuilderAttributes::random().with_timestamp(large_ts + 500);
        assert_eq!(attrs.timestamp_millis_part(), 500);
        assert!(attrs.timestamp_millis() >= large_ts);
    }

    #[test]
    fn test_builder_attributes_subblocks() {
        use std::sync::atomic::AtomicUsize;

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();

        let attrs = TempoPayloadBuilderAttributes::random().with_subblocks(move || {
            count_clone.fetch_add(1, Ordering::SeqCst);
            Vec::new()
        });

        // Closure invoked each call
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
        let _ = attrs.subblocks();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        let _ = attrs.subblocks();
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_from_eth_payload_builder_attributes() {
        let eth_attrs = EthPayloadBuilderAttributes {
            id: PayloadId::new([9, 8, 7, 6, 5, 4, 3, 2]),
            parent: B256::random(),
            timestamp: 1000,
            suggested_fee_recipient: Address::random(),
            prev_randao: B256::random(),
            withdrawals: Withdrawals::new(vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: Address::random(),
                amount: 100,
            }]),
            parent_beacon_block_root: Some(B256::random()),
        };

        let tempo_attrs: TempoPayloadBuilderAttributes = eth_attrs.clone().into();

        // Inner fields preserved
        assert_eq!(tempo_attrs.payload_id(), eth_attrs.id);
        assert_eq!(tempo_attrs.parent(), eth_attrs.parent);
        assert_eq!(tempo_attrs.timestamp(), eth_attrs.timestamp);
        assert_eq!(
            tempo_attrs.suggested_fee_recipient(),
            eth_attrs.suggested_fee_recipient
        );
        assert_eq!(tempo_attrs.prev_randao(), eth_attrs.prev_randao);
        assert_eq!(tempo_attrs.withdrawals().len(), 1);
        assert_eq!(
            tempo_attrs.parent_beacon_block_root(),
            eth_attrs.parent_beacon_block_root
        );

        // Tempo-specific defaults
        assert_eq!(tempo_attrs.timestamp_millis_part(), 0);
        assert_eq!(tempo_attrs.extra_data(), &Bytes::default());
        assert!(!tempo_attrs.is_interrupted());
        assert!(tempo_attrs.subblocks().is_empty());
    }

    #[test]
    fn test_try_new_from_rpc_attributes() {
        let rpc_attrs = TempoPayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp: 100,
                prev_randao: B256::random(),
                suggested_fee_recipient: Address::random(),
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::random()),
            },
            timestamp_millis_part: 750,
        };

        let parent = B256::random();
        let result = TempoPayloadBuilderAttributes::try_new(parent, rpc_attrs, 3);
        assert!(result.is_ok());

        let attrs = result.unwrap();
        assert_eq!(attrs.parent(), parent);
        assert_eq!(attrs.timestamp(), 100);
        assert_eq!(attrs.timestamp_millis_part(), 750);
        assert_eq!(attrs.timestamp_millis(), 100_750);
        assert_eq!(attrs.extra_data(), &Bytes::default());
        assert!(!attrs.is_interrupted());
    }

    #[test]
    fn test_tempo_payload_attributes_serde() {
        let timestamp = 1234567890;
        let timestamp_millis_part = 999;
        let attrs = TempoPayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::random(),
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::random()),
            },
            timestamp_millis_part,
        };

        // Roundtrip
        let json = serde_json::to_string(&attrs).unwrap();
        assert!(json.contains("timestampMillisPart"));

        let deserialized: TempoPayloadAttributes = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.inner.timestamp, timestamp);
        assert_eq!(deserialized.timestamp_millis_part, timestamp_millis_part);

        // Deref works
        assert_eq!(attrs.timestamp, timestamp);

        // DerefMut works
        let mut attrs = attrs;
        attrs.timestamp = 123;
        assert_eq!(attrs.inner.timestamp, 123);
    }

    #[test]
    fn test_tempo_payload_attributes_trait_impl() {
        let withdrawal_addr = Address::random();
        let beacon_root = B256::random();

        let attrs = TempoPayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp: 9999,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::random(),
                withdrawals: Some(vec![Withdrawal {
                    index: 0,
                    validator_index: 1,
                    address: withdrawal_addr,
                    amount: 500,
                }]),
                parent_beacon_block_root: Some(beacon_root),
            },
            timestamp_millis_part: 123,
        };

        // PayloadAttributes trait methods
        assert_eq!(PayloadAttributes::timestamp(&attrs), 9999);
        assert_eq!(attrs.withdrawals().unwrap().len(), 1);
        assert_eq!(attrs.withdrawals().unwrap()[0].address, withdrawal_addr);
        assert_eq!(attrs.parent_beacon_block_root(), Some(beacon_root));

        // None cases
        let attrs_none = TempoPayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp: 1,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::random(),
                withdrawals: None,
                parent_beacon_block_root: None,
            },
            timestamp_millis_part: 0,
        };
        assert!(attrs_none.withdrawals().is_none());
        assert!(attrs_none.parent_beacon_block_root().is_none());
    }
}
