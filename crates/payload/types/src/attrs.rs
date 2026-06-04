use alloy_primitives::{Address, B256, Bytes, Keccak256};
use alloy_rpc_types_engine::PayloadId;
use alloy_rpc_types_eth::Withdrawal;
use reth_ethereum_engine_primitives::EthPayloadAttributes;
use reth_node_api::PayloadAttributes;
use reth_primitives_traits::{AlloyBlockHeader as _, SealedHeader};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_primitives::{RecoveredSubBlock, TempoConsensusContext, TempoHeader};

/// Container type for all components required to build a payload.
///
/// It also carries DKG data to be included in the block's extra_data field.
#[derive(
    derive_more::Debug, Clone, Serialize, Deserialize, derive_more::Deref, derive_more::DerefMut,
)]
#[serde(rename_all = "camelCase")]
pub struct TempoPayloadAttributes {
    /// Inner [`EthPayloadAttributes`].
    #[deref]
    #[deref_mut]
    #[serde(flatten)]
    inner: EthPayloadAttributes,
    /// Shared build-control state for consensus payloads.
    ///
    /// This lets consensus start replayable build work before the proposal
    /// context exists, then attach proposer timing later without resetting
    /// elapsed build accounting.
    #[serde(skip)]
    payload_build_control: Option<PayloadBuildControl>,
    /// Noncanonical BAL-backed parent state for speculative child builds.
    #[serde(skip)]
    speculative_parent: Option<SpeculativePayloadParent>,
    /// Pool transactions already mined in the parent block and ineligible for this child payload.
    #[debug(skip)]
    #[serde(skip)]
    excluded_pool_transaction_hashes: Arc<[B256]>,
    /// Whether this payload may expose executed block state to the node builder insertion fast path.
    #[serde(skip, default = "default_publish_executed_block")]
    publish_executed_block: bool,
    /// Local diagnostic label for how this payload build was started.
    #[serde(skip)]
    build_reason: Option<&'static str>,
    /// Milliseconds portion of the timestamp.
    timestamp_millis_part: u64,
    /// DKG ceremony data to include in the block's extra_data header field.
    ///
    /// This is empty when no DKG data is available (e.g., when the DKG manager
    /// hasn't produced ceremony outcomes yet, or when DKG operations fail).
    extra_data: Bytes,
    /// The proposer's public key used to resolve the fee recipient from the
    /// validator config contract. When `None`, `suggested_fee_recipient` from
    /// the inner attributes is used as-is.
    proposer_public_key: Option<B256>,
    /// Consensus view for this block
    consensus_context: Option<TempoConsensusContext>,
    /// Subblocks closure.
    #[debug(skip)]
    #[serde(skip, default = "default_subblocks")]
    subblocks: Arc<dyn Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static>,
}

impl Default for TempoPayloadAttributes {
    fn default() -> Self {
        Self::from(EthPayloadAttributes::default())
    }
}

impl TempoPayloadAttributes {
    /// Creates new `TempoPayloadAttributes` with `inner` attributes.
    ///
    /// The inner `suggested_fee_recipient` is always `Address::ZERO`; the
    /// real beneficiary is resolved from the validator config v2 contract by
    /// the payload builder.
    pub fn new(
        proposer_public_key: Option<B256>,
        timestamp: u64,
        timestamp_millis_part: u64,
        extra_data: Bytes,
        consensus_context: Option<TempoConsensusContext>,
        subblocks: impl Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: EthPayloadAttributes {
                timestamp,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                withdrawals: Some(Default::default()),
                parent_beacon_block_root: Some(B256::ZERO),
                slot_number: None,
            },
            payload_build_control: None,
            speculative_parent: None,
            excluded_pool_transaction_hashes: Vec::new().into(),
            publish_executed_block: true,
            build_reason: None,
            timestamp_millis_part,
            extra_data,
            proposer_public_key,
            consensus_context,
            subblocks: Arc::new(subblocks),
        }
    }

    /// Returns the extra data to be included in the block header.
    pub fn extra_data(&self) -> &Bytes {
        &self.extra_data
    }

    /// Returns the proposer's public key.
    pub fn proposer_public_key(&self) -> Option<&B256> {
        self.proposer_public_key.as_ref()
    }

    /// Sets the shared build-control handle for this payload build.
    pub fn with_payload_build_control(mut self, control: PayloadBuildControl) -> Self {
        self.payload_build_control = Some(control);
        self
    }

    /// Sets the BAL-backed speculative parent for this payload build.
    pub fn with_speculative_parent(mut self, parent: SpeculativePayloadParent) -> Self {
        self.speculative_parent = Some(parent);
        self
    }

    /// Sets pool transaction hashes that must not be considered for this payload.
    pub fn with_excluded_pool_transaction_hashes(
        mut self,
        hashes: impl IntoIterator<Item = B256>,
    ) -> Self {
        self.excluded_pool_transaction_hashes = hashes.into_iter().collect::<Vec<_>>().into();
        self
    }

    /// Suppresses the node builder's self-built executed-block insertion fast path.
    ///
    /// This is required for speculative consensus builds: they may be abandoned if
    /// the view times out, so their executed state must not be inserted before
    /// consensus accepts the block.
    pub fn without_executed_block_fast_path(mut self) -> Self {
        self.publish_executed_block = false;
        self
    }

    /// Sets the local diagnostic label for how this payload build was started.
    pub fn with_build_reason(mut self, reason: &'static str) -> Self {
        self.build_reason = Some(reason);
        self
    }

    /// Returns the shared build-control handle, if this is a controlled build.
    pub fn payload_build_control(&self) -> Option<&PayloadBuildControl> {
        self.payload_build_control.as_ref()
    }

    /// Returns the BAL-backed speculative parent, if any.
    pub fn speculative_parent(&self) -> Option<&SpeculativePayloadParent> {
        self.speculative_parent.as_ref()
    }

    /// Returns pool transaction hashes that must not be considered for this payload.
    pub fn excluded_pool_transaction_hashes(&self) -> &[B256] {
        self.excluded_pool_transaction_hashes.as_ref()
    }

    /// Returns whether this payload may expose executed block state for self-built insertion.
    pub fn publish_executed_block(&self) -> bool {
        self.publish_executed_block
    }

    /// Returns the local diagnostic label for how this payload build was started.
    pub fn build_reason(&self) -> Option<&'static str> {
        self.build_reason
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

    /// Returns the consensus context
    pub fn consensus_context(&self) -> Option<TempoConsensusContext> {
        self.consensus_context
    }

    /// Returns the subblocks.
    pub fn subblocks(&self) -> Vec<RecoveredSubBlock> {
        (self.subblocks)()
    }
}

// Required by reth's e2e-test-utils for integration tests.
// The test utilities need to convert from standard Ethereum payload attributes
// to custom chain-specific attributes.
impl From<EthPayloadAttributes> for TempoPayloadAttributes {
    fn from(inner: EthPayloadAttributes) -> Self {
        Self {
            inner,
            payload_build_control: None,
            speculative_parent: None,
            excluded_pool_transaction_hashes: Vec::new().into(),
            publish_executed_block: true,
            build_reason: None,
            timestamp_millis_part: 0,
            extra_data: Bytes::default(),
            proposer_public_key: None,
            consensus_context: None,
            subblocks: Arc::new(Vec::new),
        }
    }
}

/// Parent data used when a speculative child is built before its parent block is canonical.
#[derive(Clone, Debug)]
pub struct SpeculativePayloadParent {
    /// Header of the block this payload builds on.
    parent_header: Arc<SealedHeader<TempoHeader>>,
    /// RLP-encoded BAL sidecar for the parent block.
    block_access_list: Bytes,
}

impl SpeculativePayloadParent {
    /// Creates a speculative parent descriptor.
    pub fn new(parent_header: SealedHeader<TempoHeader>, block_access_list: Bytes) -> Self {
        Self {
            parent_header: Arc::new(parent_header),
            block_access_list,
        }
    }

    /// Returns the parent header.
    pub fn parent_header(&self) -> Arc<SealedHeader<TempoHeader>> {
        self.parent_header.clone()
    }

    /// Returns the parent block hash.
    pub fn parent_hash(&self) -> B256 {
        self.parent_header.hash()
    }

    /// Returns the parent-of-parent block hash used as the base state.
    pub fn base_parent_hash(&self) -> B256 {
        self.parent_header.parent_hash()
    }

    /// Returns the RLP-encoded BAL sidecar for the parent block.
    pub fn block_access_list(&self) -> &Bytes {
        &self.block_access_list
    }
}

/// Shared control state for a consensus payload build.
///
/// The handle is intentionally cloneable and internally synchronized so the
/// consensus actor can attach proposer timing while the payload builder is
/// already running on a blocking worker.
#[derive(Clone, Debug)]
pub struct PayloadBuildControl {
    inner: Arc<PayloadBuildControlInner>,
}

#[derive(Debug)]
struct PayloadBuildControlInner {
    proposal_return_budget: Mutex<Duration>,
    builder_start: Instant,
    proposal_timing_attached: AtomicBool,
    cancelled: AtomicBool,
    proposal_timing: Mutex<Option<ProposalTiming>>,
    proposal_timing_changed: Condvar,
}

#[derive(Clone, Debug)]
struct ProposalTiming {
    payload_context: PayloadProposalContext,
}

/// Consensus payload fields that may be attached after speculative execution starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadProposalContext {
    extra_data: Bytes,
    consensus_context: TempoConsensusContext,
}

impl PayloadProposalContext {
    /// Returns the extra data to seal into the header.
    pub fn extra_data(&self) -> &Bytes {
        &self.extra_data
    }

    /// Returns the final consensus context to seal into the header.
    pub fn consensus_context(&self) -> TempoConsensusContext {
        self.consensus_context
    }
}

/// Immutable view of the current build-control state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadBuildControlSnapshot {
    proposal_return_budget: Duration,
    builder_elapsed: Duration,
}

impl PayloadBuildControl {
    /// Creates a build-control handle whose dispatch clock starts now.
    pub fn new(proposal_return_budget: Duration) -> Self {
        Self::new_at(proposal_return_budget, Instant::now())
    }

    /// Creates a build-control handle with an explicit dispatch start time.
    pub fn new_at(proposal_return_budget: Duration, builder_start: Instant) -> Self {
        Self {
            inner: Arc::new(PayloadBuildControlInner {
                proposal_return_budget: Mutex::new(proposal_return_budget),
                builder_start,
                proposal_timing_attached: AtomicBool::new(false),
                cancelled: AtomicBool::new(false),
                proposal_timing: Mutex::new(None),
                proposal_timing_changed: Condvar::new(),
            }),
        }
    }

    /// Attaches proposal timing and the consensus fields needed to seal this payload.
    pub fn attach_proposal_context(
        &self,
        extra_data: Bytes,
        consensus_context: TempoConsensusContext,
    ) -> Result<(), ProposalTimingAlreadyAttached> {
        let mut proposal_timing = self.proposal_timing();
        if proposal_timing.is_some() {
            return Err(ProposalTimingAlreadyAttached);
        }

        *proposal_timing = Some(ProposalTiming {
            payload_context: PayloadProposalContext {
                extra_data,
                consensus_context,
            },
        });
        self.inner
            .proposal_timing_attached
            .store(true, Ordering::Release);
        self.inner.proposal_timing_changed.notify_all();
        Ok(())
    }

    /// Attaches proposal context and tightens the replayable work budget.
    ///
    /// Speculative builds start with the verify-time budget. Once `handle_propose`
    /// knows the actual proposal window, the running builder must observe the
    /// smaller remaining budget without resetting elapsed build accounting.
    pub fn attach_proposal_context_with_budget(
        &self,
        extra_data: Bytes,
        consensus_context: TempoConsensusContext,
        proposal_return_budget: Duration,
    ) -> Result<(), ProposalTimingAlreadyAttached> {
        let mut proposal_timing = self.proposal_timing();
        if proposal_timing.is_some() {
            return Err(ProposalTimingAlreadyAttached);
        }

        self.tighten_proposal_return_budget_locked(proposal_return_budget);
        *proposal_timing = Some(ProposalTiming {
            payload_context: PayloadProposalContext {
                extra_data,
                consensus_context,
            },
        });
        self.inner
            .proposal_timing_attached
            .store(true, Ordering::Release);
        self.inner.proposal_timing_changed.notify_all();
        Ok(())
    }

    /// Returns true once proposer timing has been attached.
    pub fn proposal_timing_attached(&self) -> bool {
        self.inner.proposal_timing_attached.load(Ordering::Acquire)
    }

    /// Requests cancellation of the associated payload build.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.proposal_timing_changed.notify_all();
    }

    /// Returns true once cancellation has been requested for this build.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Returns the attached proposal context, if one has been provided.
    pub fn proposal_context(&self) -> Option<PayloadProposalContext> {
        self.proposal_timing()
            .as_ref()
            .map(|timing| timing.payload_context.clone())
    }

    /// Waits until proposal context is attached or `should_cancel` returns true.
    pub fn wait_for_proposal_context_while(
        &self,
        should_cancel: impl Fn() -> bool,
    ) -> Result<PayloadProposalContext, PayloadProposalContextCancelled> {
        let mut proposal_timing = self.proposal_timing();
        loop {
            if let Some(payload_context) = proposal_timing
                .as_ref()
                .map(|timing| timing.payload_context.clone())
            {
                return Ok(payload_context);
            }
            if self.is_cancelled() || should_cancel() {
                return Err(PayloadProposalContextCancelled);
            }

            let (guard, _) = self
                .inner
                .proposal_timing_changed
                .wait_timeout(proposal_timing, Duration::from_millis(1))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proposal_timing = guard;
        }
    }

    /// Waits up to `timeout` for proposal context to attach.
    pub fn wait_for_proposal_context_timeout_while(
        &self,
        timeout: Duration,
        should_cancel: impl Fn() -> bool,
    ) -> Result<Option<PayloadProposalContext>, PayloadProposalContextCancelled> {
        let deadline = Instant::now() + timeout;
        let mut proposal_timing = self.proposal_timing();
        loop {
            if let Some(payload_context) = proposal_timing
                .as_ref()
                .map(|timing| timing.payload_context.clone())
            {
                return Ok(Some(payload_context));
            }
            if self.is_cancelled() || should_cancel() {
                return Err(PayloadProposalContextCancelled);
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            if remaining.is_zero() {
                return Ok(None);
            }

            let (guard, wait_result) = self
                .inner
                .proposal_timing_changed
                .wait_timeout(proposal_timing, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            proposal_timing = guard;
            if wait_result.timed_out() {
                continue;
            }
        }
    }

    /// Returns a consistent snapshot of the control state at `Instant::now()`.
    pub fn snapshot(&self) -> PayloadBuildControlSnapshot {
        self.snapshot_at(Instant::now())
    }

    /// Returns a consistent snapshot of the control state at `now`.
    pub fn snapshot_at(&self, now: Instant) -> PayloadBuildControlSnapshot {
        PayloadBuildControlSnapshot {
            proposal_return_budget: *self.proposal_return_budget(),
            builder_elapsed: now.saturating_duration_since(self.inner.builder_start),
        }
    }

    fn tighten_proposal_return_budget_locked(&self, proposal_return_budget: Duration) {
        let mut current_budget = self.proposal_return_budget();
        if proposal_return_budget < *current_budget {
            *current_budget = proposal_return_budget;
        }
    }

    fn proposal_return_budget(&self) -> MutexGuard<'_, Duration> {
        self.inner
            .proposal_return_budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn proposal_timing(&self) -> MutexGuard<'_, Option<ProposalTiming>> {
        self.inner
            .proposal_timing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl PayloadBuildControlSnapshot {
    /// Returns the full proposal return budget for this build.
    pub fn proposal_return_budget(&self) -> Duration {
        self.proposal_return_budget
    }

    /// Returns elapsed time since verify-time dispatch.
    ///
    /// Callers that wait for late proposal context must subtract that
    /// non-replayable wait before using this as validator work.
    pub fn builder_elapsed(&self) -> Duration {
        self.builder_elapsed
    }
}

/// Error returned when proposal timing is attached more than once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalTimingAlreadyAttached;

impl fmt::Display for ProposalTimingAlreadyAttached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("proposal timing is already attached to this payload build")
    }
}

impl Error for ProposalTimingAlreadyAttached {}

/// Error returned when a speculative payload is cancelled before proposal context is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadProposalContextCancelled;

impl fmt::Display for PayloadProposalContextCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("payload build was cancelled before proposal context was attached")
    }
}

impl Error for PayloadProposalContextCancelled {}

impl PayloadAttributes for TempoPayloadAttributes {
    fn payload_id(&self, parent_hash: &B256) -> PayloadId {
        // XXX: derives the payload ID from the parent so that
        // overlong payload builds will eventually succeed on the
        // next iteration: if all other nodes take equally as long,
        // the consensus engine will kill the proposal task. Then eventually
        // consensus will circle back to an earlier node, which then
        // has the chance of picking up the old payload.
        //
        // The consensus context (epoch, view, parent_view, proposer) is
        // mixed into the ID so that distinct consensus rounds proposing on
        // the same parent block produce distinct payload IDs and do not
        // collide in the payload builder cache.
        payload_id_from_parent_and_context(parent_hash, self.consensus_context.as_ref())
    }

    fn timestamp(&self) -> u64 {
        self.inner.timestamp()
    }

    fn parent_beacon_block_root(&self) -> Option<B256> {
        self.inner.parent_beacon_block_root()
    }

    fn withdrawals(&self) -> Option<&Vec<Withdrawal>> {
        self.inner.withdrawals()
    }

    fn slot_number(&self) -> Option<u64> {
        self.inner.slot_number()
    }
}

/// Constructs a [`PayloadId`] from the first 8 bytes of `block_hash`.
fn payload_id_from_block_hash(block_hash: &B256) -> PayloadId {
    PayloadId::new(
        <[u8; 8]>::try_from(&block_hash[0..8])
            .expect("a 32 byte array always has more than 8 bytes"),
    )
}

/// Constructs a [`PayloadId`] from the parent block hash and consensus context.
///
/// When `consensus_context` is `None`, this is equivalent to
/// [`payload_id_from_block_hash`] for backwards compatibility with pre-fork
/// blocks. Otherwise the parent hash and each field of the consensus context
/// are streamed into a Keccak256 hasher and the first 8 bytes of the digest
/// form the ID.
fn payload_id_from_parent_and_context(
    parent_hash: &B256,
    consensus_context: Option<&TempoConsensusContext>,
) -> PayloadId {
    let Some(ctx) = consensus_context else {
        return payload_id_from_block_hash(parent_hash);
    };

    let mut hasher = Keccak256::new();
    hasher.update(parent_hash);
    hasher.update(ctx.epoch.to_be_bytes());
    hasher.update(ctx.view.to_be_bytes());
    hasher.update(ctx.parent_view.to_be_bytes());
    hasher.update(B256::from(&ctx.proposer));
    let digest = hasher.finalize();

    PayloadId::new(
        <[u8; 8]>::try_from(&digest[0..8]).expect("a 32 byte array always has more than 8 bytes"),
    )
}

fn default_subblocks() -> Arc<dyn Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static> {
    Arc::new(Vec::new)
}

const fn default_publish_executed_block() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_rpc_types_eth::Withdrawal;
    use tempo_primitives::ed25519::PublicKey;

    trait TestExt: Sized {
        fn random() -> Self;
        fn with_timestamp(self, millis: u64) -> Self;
        fn with_subblocks(
            self,
            f: impl Fn() -> Vec<RecoveredSubBlock> + Send + Sync + 'static,
        ) -> Self;
    }

    impl TestExt for TempoPayloadAttributes {
        fn random() -> Self {
            Self::new(
                None,
                1, // 1s
                0,
                Bytes::default(),
                None,
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
    fn test_builder_attributes_construction() {
        let parent = B256::random();
        let extra_data = Bytes::from(vec![1, 2, 3, 4, 5]);

        // With extra_data
        let attrs = TempoPayloadAttributes::new(
            None,
            1,
            500, // 1.5s
            extra_data.clone(),
            None,
            Vec::new,
        );
        assert_eq!(attrs.extra_data(), &extra_data);
        assert_eq!(attrs.suggested_fee_recipient, Address::ZERO);
        assert_eq!(
            attrs.payload_id(&parent),
            payload_id_from_block_hash(&parent)
        );
        assert_eq!(attrs.timestamp(), 1);
        assert_eq!(attrs.timestamp_millis_part(), 500);
        assert!(attrs.excluded_pool_transaction_hashes().is_empty());
        assert!(attrs.publish_executed_block());
        assert_eq!(attrs.build_reason(), None);

        let attrs_with_reason = attrs.clone().with_build_reason("test");
        assert_eq!(attrs_with_reason.build_reason(), Some("test"));

        // Hardcoded in ::new()
        assert_eq!(attrs.prev_randao, B256::ZERO);
        assert_eq!(attrs.parent_beacon_block_root(), Some(B256::ZERO));
        assert!(attrs.withdrawals().is_some_and(|w| w.is_empty()));

        // Without extra_data
        let attrs2 = TempoPayloadAttributes::new(
            None,
            2, // +500ms
            0,
            Bytes::default(),
            None,
            Vec::new,
        );
        assert_eq!(attrs2.extra_data(), &Bytes::default());
        assert_eq!(attrs2.timestamp(), 2);
        assert_eq!(attrs2.timestamp_millis_part(), 0);
    }

    #[test]
    fn test_builder_attributes_excluded_pool_transaction_hashes() {
        let hash_a = B256::random();
        let hash_b = B256::random();
        let attrs = TempoPayloadAttributes::random()
            .with_excluded_pool_transaction_hashes([hash_a, hash_b, hash_a]);

        assert_eq!(
            attrs.excluded_pool_transaction_hashes(),
            &[hash_a, hash_b, hash_a]
        );
    }

    #[test]
    fn test_builder_attributes_executed_block_fast_path_control() {
        let attrs = TempoPayloadAttributes::random();
        assert!(attrs.publish_executed_block());

        let attrs = attrs.without_executed_block_fast_path();
        assert!(!attrs.publish_executed_block());

        let json = serde_json::to_string(&attrs).unwrap();
        let deserialized: TempoPayloadAttributes = serde_json::from_str(&json).unwrap();
        assert!(deserialized.publish_executed_block());
    }

    #[test]
    fn test_builder_attributes_timestamp_handling() {
        // Exact second boundary
        let attrs = TempoPayloadAttributes::random().with_timestamp(3000);
        assert_eq!(attrs.timestamp(), 3);
        assert_eq!(attrs.timestamp_millis_part(), 0);
        assert_eq!(attrs.timestamp_millis(), 3000);

        // With milliseconds remainder
        let attrs = TempoPayloadAttributes::random().with_timestamp(3999);
        assert_eq!(attrs.timestamp(), 3);
        assert_eq!(attrs.timestamp_millis_part(), 999);
        assert_eq!(attrs.timestamp_millis(), 3999);

        // Zero timestamp
        let attrs = TempoPayloadAttributes::random().with_timestamp(0);
        assert_eq!(attrs.timestamp(), 0);
        assert_eq!(attrs.timestamp_millis_part(), 0);
        assert_eq!(attrs.timestamp_millis(), 0);

        // Large timestamp (no overflow due to saturating ops)
        let large_ts = u64::MAX / 1000 * 1000;
        let attrs = TempoPayloadAttributes::random().with_timestamp(large_ts + 500);
        assert_eq!(attrs.timestamp_millis_part(), 500);
        assert!(attrs.timestamp_millis() >= large_ts);
    }

    #[test]
    fn test_builder_attributes_subblocks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();

        let attrs = TempoPayloadAttributes::random().with_subblocks(move || {
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
        let eth_attrs = EthPayloadAttributes {
            timestamp: 1000,
            suggested_fee_recipient: Address::random(),
            prev_randao: B256::random(),
            withdrawals: Some(Default::default()),
            parent_beacon_block_root: Some(B256::random()),
            slot_number: None,
        };

        let tempo_attrs: TempoPayloadAttributes = eth_attrs.clone().into();

        // Inner fields preserved
        let parent = B256::random();
        assert_eq!(
            tempo_attrs.payload_id(&parent),
            payload_id_from_block_hash(&parent)
        );
        assert_eq!(tempo_attrs.timestamp(), eth_attrs.timestamp);
        assert_eq!(
            tempo_attrs.suggested_fee_recipient,
            eth_attrs.suggested_fee_recipient
        );
        assert_eq!(tempo_attrs.prev_randao, eth_attrs.prev_randao);
        assert_eq!(tempo_attrs.withdrawals().as_ref().map(|w| w.len()), Some(0));
        assert_eq!(
            tempo_attrs.parent_beacon_block_root(),
            eth_attrs.parent_beacon_block_root
        );

        // Tempo-specific defaults
        assert_eq!(tempo_attrs.timestamp_millis_part(), 0);
        assert_eq!(tempo_attrs.extra_data(), &Bytes::default());
        assert!(tempo_attrs.subblocks().is_empty());
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
                slot_number: None,
            },
            timestamp_millis_part,
            ..Default::default()
        };

        // Roundtrip
        let json = serde_json::to_string(&attrs).unwrap();
        assert!(json.contains("timestampMillisPart"));

        let deserialized: TempoPayloadAttributes = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.inner.timestamp, timestamp);
        assert_eq!(deserialized.timestamp_millis_part, timestamp_millis_part);
        assert_eq!(deserialized.build_reason(), None);

        // Deref works
        assert_eq!(attrs.timestamp, timestamp);

        // DerefMut works
        let mut attrs = attrs;
        attrs.timestamp = 123;
        assert_eq!(attrs.inner.timestamp, 123);
    }

    #[test]
    fn payload_build_control_tracks_verify_time_and_late_proposal_attach() {
        let builder_start = Instant::now();
        let control = PayloadBuildControl::new_at(Duration::from_millis(300), builder_start);

        let before_attach = control.snapshot_at(builder_start + Duration::from_millis(25));
        assert_eq!(
            before_attach.proposal_return_budget(),
            Duration::from_millis(300)
        );
        assert_eq!(before_attach.builder_elapsed(), Duration::from_millis(25));
        assert!(!control.proposal_timing_attached());

        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };
        control
            .attach_proposal_context(Bytes::default(), consensus_context)
            .unwrap();

        let after_attach = control.snapshot_at(builder_start + Duration::from_millis(75));
        assert_eq!(after_attach.builder_elapsed(), Duration::from_millis(75));
        assert!(control.proposal_timing_attached());
    }

    #[test]
    fn payload_build_control_tightens_budget_on_late_proposal_attach() {
        let builder_start = Instant::now();
        let control = PayloadBuildControl::new_at(Duration::from_millis(300), builder_start);
        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };

        control
            .attach_proposal_context_with_budget(
                Bytes::default(),
                consensus_context,
                Duration::from_millis(120),
            )
            .unwrap();

        let after_attach = control.snapshot_at(builder_start + Duration::from_millis(75));
        assert_eq!(
            after_attach.proposal_return_budget(),
            Duration::from_millis(120)
        );
        assert_eq!(after_attach.builder_elapsed(), Duration::from_millis(75));
        assert!(control.proposal_timing_attached());
    }

    #[test]
    fn payload_build_control_late_attach_does_not_extend_budget() {
        let builder_start = Instant::now();
        let control = PayloadBuildControl::new_at(Duration::from_millis(300), builder_start);
        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };

        control
            .attach_proposal_context_with_budget(
                Bytes::default(),
                consensus_context,
                Duration::from_millis(500),
            )
            .unwrap();

        assert_eq!(
            control
                .snapshot_at(builder_start + Duration::from_millis(75))
                .proposal_return_budget(),
            Duration::from_millis(300)
        );
    }

    #[test]
    fn payload_build_control_attaches_and_waits_for_proposal_context() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));
        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };
        let extra_data = Bytes::from_static(b"dkg");

        control
            .attach_proposal_context(extra_data.clone(), consensus_context)
            .unwrap();

        let context = control
            .wait_for_proposal_context_while(|| false)
            .expect("proposal context should be attached");
        assert_eq!(context.extra_data(), &extra_data);
        assert_eq!(context.consensus_context(), consensus_context);
        assert_eq!(control.proposal_context(), Some(context));
    }

    #[test]
    fn payload_build_control_timeout_wait_returns_pending_context() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));

        assert_eq!(
            control
                .wait_for_proposal_context_timeout_while(Duration::from_millis(1), || false)
                .expect("timeout wait should not cancel"),
            None
        );
    }

    #[test]
    fn payload_build_control_timeout_wait_returns_attached_context() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));
        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };
        let extra_data = Bytes::from_static(b"dkg");

        control
            .attach_proposal_context(extra_data.clone(), consensus_context)
            .unwrap();

        let context = control
            .wait_for_proposal_context_timeout_while(Duration::from_millis(1), || false)
            .expect("timeout wait should observe attached context")
            .expect("proposal context should be attached");
        assert_eq!(context.extra_data(), &extra_data);
        assert_eq!(context.consensus_context(), consensus_context);
    }

    #[test]
    fn payload_build_control_wait_cancel_is_observable() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));

        assert_eq!(
            control.wait_for_proposal_context_while(|| true),
            Err(PayloadProposalContextCancelled)
        );
    }

    #[test]
    fn payload_build_control_cancel_is_observable() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));

        assert!(!control.is_cancelled());
        control.cancel();
        assert!(control.is_cancelled());
        assert_eq!(
            control.wait_for_proposal_context_while(|| false),
            Err(PayloadProposalContextCancelled)
        );
    }

    #[test]
    fn payload_build_control_rejects_double_attach() {
        let control = PayloadBuildControl::new(Duration::from_millis(300));
        let consensus_context = TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer: PublicKey::from_seed([0xab; 32]),
        };
        control
            .attach_proposal_context(Bytes::default(), consensus_context)
            .unwrap();

        assert_eq!(
            control.attach_proposal_context(Bytes::default(), consensus_context),
            Err(ProposalTimingAlreadyAttached)
        );
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
                slot_number: None,
            },
            timestamp_millis_part: 123,
            ..Default::default()
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
                slot_number: None,
            },
            timestamp_millis_part: 0,
            ..Default::default()
        };
        assert!(attrs_none.withdrawals().is_none());
        assert!(attrs_none.parent_beacon_block_root().is_none());
    }

    #[test]
    fn payload_id_includes_consensus_context() {
        let parent = B256::random();
        let proposer = PublicKey::from_seed([0xab; 32]);

        let mk = |ctx: Option<TempoConsensusContext>| -> PayloadId {
            let mut attrs = TempoPayloadAttributes::random();
            attrs.consensus_context = ctx;
            attrs.payload_id(&parent)
        };

        let no_ctx = mk(None);
        let ctx_a = mk(Some(TempoConsensusContext {
            epoch: 1,
            view: 1,
            parent_view: 0,
            proposer,
        }));
        let ctx_b = mk(Some(TempoConsensusContext {
            epoch: 1,
            view: 2,
            parent_view: 1,
            proposer,
        }));
        let ctx_c = mk(Some(TempoConsensusContext {
            epoch: 2,
            view: 1,
            parent_view: 0,
            proposer,
        }));
        let ctx_d = mk(Some(TempoConsensusContext {
            epoch: 1,
            view: 1,
            parent_view: 0,
            proposer: PublicKey::from_seed([0xcd; 32]),
        }));

        // Without context, falls back to parent-hash-only ID.
        assert_eq!(no_ctx, payload_id_from_block_hash(&parent));

        // Each distinct consensus context produces a distinct ID, and all
        // differ from the no-context fallback.
        let ids = [no_ctx, ctx_a, ctx_b, ctx_c, ctx_d];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "payload ids {i} and {j} collide");
            }
        }

        // Same context on the same parent is deterministic.
        let ctx_a_again = mk(Some(TempoConsensusContext {
            epoch: 1,
            view: 1,
            parent_view: 0,
            proposer,
        }));
        assert_eq!(ctx_a, ctx_a_again);

        // Different parent with the same context yields a different ID.
        let other_parent = B256::random();
        let mut attrs = TempoPayloadAttributes::random();
        attrs.consensus_context = Some(TempoConsensusContext {
            epoch: 1,
            view: 1,
            parent_view: 0,
            proposer,
        });
        assert_ne!(attrs.payload_id(&parent), attrs.payload_id(&other_parent));
    }
}
