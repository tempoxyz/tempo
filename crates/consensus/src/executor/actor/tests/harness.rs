//! Test doubles and a driver for exercising the executor actor against a
//! controllable execution layer and marshal actor.
//!
//! The execution-layer fake is *stateful*: it maintains a block tree, a
//! canonical index, and a finalized marker the way a real engine would, and
//! accepts/rejects payloads and forkchoice updates against that state by
//! default. The actor's trickiest logic (`finalization_target`,
//! the stale-FCU guard in `submit_forkchoice_update`) reads the canonical
//! index and expects it to be consistent with previously accepted forkchoice
//! updates; a stateful fake keeps that consistency without per-test
//! scripting. Fault injection (scripted payload statuses, FCU rejections,
//! call gating) is layered on top.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use alloy_primitives::{B256, Bytes, U256};
use alloy_rpc_types_engine::{
    ForkchoiceState, ForkchoiceUpdated, PayloadId, PayloadStatus, PayloadStatusEnum,
};
use commonware_consensus::{
    Heightable as _, Reporter as _,
    marshal::Update,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_runtime::{Clock as _, Handle, Supervisor as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use parking_lot::Mutex;
use reth_ethereum::rpc::eth::primitives::BlockNumHash;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_core::primitives::{RecoveredBlock, SealedBlock};
use tempo_node::TempoExecutionData;
use tempo_payload_types::{EncodedBlock, TempoBuiltPayload, TempoPayloadAttributes};
use tempo_primitives::{Block as TempoBlock, TempoConsensusContext, TempoHeader};
use tokio::sync::oneshot;

use crate::{
    consensus::{Digest, block::Block},
    executor::{Config, ExecutionLayer, Mailbox, Marshal, init},
};

/// The genesis digest all harness chains hang off.
pub(super) const GENESIS: Digest = Digest(B256::repeat_byte(0x1e));

/// How many 1ms polls [`Harness::wait_until`] attempts before failing.
const WAIT_ATTEMPTS: usize = 5_000;

pub(super) fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

/// Builds a block constructed in `view` at `height` on top of `parent`.
pub(super) fn make_block(view: u64, height: u64, parent: Digest) -> Block {
    Block::from_execution_block_unchecked(
        SealedBlock::seal_slow(TempoBlock {
            header: TempoHeader {
                inner: alloy_consensus::Header {
                    number: height,
                    parent_hash: parent.0,
                    ..Default::default()
                },
                consensus_context: Some(TempoConsensusContext {
                    epoch: 0,
                    view,
                    parent_view: view.saturating_sub(1),
                    proposer: tempo_primitives::ed25519::PublicKey::from_seed(42),
                }),
                ..Default::default()
            },
            body: Default::default(),
        }),
        None,
    )
}

/// Wraps `block` in a [`TempoBuiltPayload`] the way the payload builder
/// would deliver it.
pub(super) fn built_payload(block: &Block) -> TempoBuiltPayload {
    let recovered = RecoveredBlock::new_sealed(block.block().clone(), Vec::new());
    TempoBuiltPayload::new(
        EthBuiltPayload::new(Arc::new(recovered), U256::ZERO, None, None),
        None,
        None,
        Duration::ZERO,
        Duration::ZERO,
        0,
        EncodedBlock::default(),
    )
}

/// Payload attributes for build requests; contents are irrelevant to the
/// executor, which passes them through opaquely.
pub(super) fn attributes() -> TempoPayloadAttributes {
    TempoPayloadAttributes::new(None, 0, 0, Bytes::new(), None, Vec::new)
}

/// A recorded engine-API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ElCall {
    NewPayload(Digest),
    Fcu {
        head: Digest,
        finalized: Digest,
        with_attrs: bool,
    },
    Resolve(PayloadId),
}

struct ElState {
    /// Blocks known to the execution layer: hash -> (height, parent hash).
    blocks: HashMap<B256, (u64, B256)>,
    /// The canonical index: height -> hash, derived from accepted
    /// forkchoice updates (plus seeded history).
    canonical: BTreeMap<u64, B256>,
    head: B256,
    finalized: Option<BlockNumHash>,
}

struct FakeExecutionInner {
    genesis: B256,
    state: Mutex<ElState>,
    calls: Mutex<Vec<ElCall>>,
    /// Scripted new-payload outcomes keyed by block hash, consumed in order.
    /// A scripted `Ok(Valid)` still marks the block as known to the execution layer.
    payload_overrides: Mutex<HashMap<B256, VecDeque<Result<PayloadStatusEnum, &'static str>>>>,
    /// Scripted FCU statuses consumed in order before default behavior.
    fcu_overrides: Mutex<VecDeque<PayloadStatusEnum>>,
    /// Rejects every FCU while set.
    reject_all_fcus: AtomicBool,
    /// Accepts attribute-carrying FCUs without registering a payload build.
    suppress_payload_ids: AtomicBool,
    /// Returns a payload ID without registering a job under it.
    omit_payload_job: AtomicBool,
    next_payload_id: AtomicU64,
    /// Sender halves of registered payload build jobs, for the test to
    /// deliver (or abort) builds.
    payload_senders: Mutex<HashMap<PayloadId, oneshot::Sender<TempoBuiltPayload>>>,
    /// Receiver halves handed out on `resolve_payload`.
    payload_receivers: Mutex<HashMap<PayloadId, oneshot::Receiver<TempoBuiltPayload>>>,
    /// Payloads to auto-deliver to the next registered build jobs.
    scripted_builds: Mutex<VecDeque<TempoBuiltPayload>>,
    /// Blocks servable through `block_by_digest`.
    bodies: Mutex<HashMap<B256, Block>>,
}

/// A stateful fake of the execution layer.
#[derive(Clone)]
pub(super) struct FakeExecution {
    inner: Arc<FakeExecutionInner>,
}

impl FakeExecution {
    /// A fake whose chain consists only of the genesis block, with no
    /// finalized marker set.
    pub(super) fn new() -> Self {
        let genesis = GENESIS.0;
        Self {
            inner: Arc::new(FakeExecutionInner {
                genesis,
                state: Mutex::new(ElState {
                    blocks: HashMap::from([(genesis, (0, B256::ZERO))]),
                    canonical: BTreeMap::from([(0, genesis)]),
                    head: genesis,
                    finalized: None,
                }),
                calls: Mutex::new(Vec::new()),
                payload_overrides: Mutex::new(HashMap::new()),
                fcu_overrides: Mutex::new(VecDeque::new()),
                reject_all_fcus: AtomicBool::new(false),
                suppress_payload_ids: AtomicBool::new(false),
                omit_payload_job: AtomicBool::new(false),
                next_payload_id: AtomicU64::new(1),
                payload_senders: Mutex::new(HashMap::new()),
                payload_receivers: Mutex::new(HashMap::new()),
                scripted_builds: Mutex::new(VecDeque::new()),
                bodies: Mutex::new(HashMap::new()),
            }),
        }
    }

    // ---- state seeding ----

    /// Seeds `block` as known and canonical, moving the head onto it.
    pub(super) fn seed_canonical_block(&self, block: &Block) {
        let mut state = self.inner.state.lock();
        let (height, digest, parent) = (
            block.height().get(),
            block.digest().0,
            block.parent_digest().0,
        );
        state.blocks.insert(digest, (height, parent));
        state.canonical.insert(height, digest);
        state.head = digest;
    }

    pub(super) fn set_finalized(&self, height: u64, digest: Digest) {
        self.inner.state.lock().finalized = Some(BlockNumHash::new(height, digest.0));
    }

    /// Makes `block` servable through `block_by_digest`.
    pub(super) fn add_body(&self, block: Block) {
        self.inner.bodies.lock().insert(block.digest().0, block);
    }

    // ---- fault injection ----

    /// Scripts the outcome of the next new-payload request carrying the block
    /// with `digest`. Scripted outcomes stack in FIFO order and take precedence
    /// over the default parent-known behavior. `Ok(PayloadStatusEnum::Invalid)`
    /// models a successfully delivered Engine API response that rejects the
    /// payload, while `Err` models a request or transport failure before the
    /// execution layer returns any payload status.
    pub(super) fn script_new_payload(
        &self,
        digest: Digest,
        outcome: Result<PayloadStatusEnum, &'static str>,
    ) {
        self.inner
            .payload_overrides
            .lock()
            .entry(digest.0)
            .or_default()
            .push_back(outcome);
    }

    /// Scripts the status of the next forkchoice update, whatever its target.
    pub(super) fn script_fcu(&self, status: PayloadStatusEnum) {
        self.inner.fcu_overrides.lock().push_back(status);
    }

    /// Rejects all forkchoice updates until re-enabled.
    pub(super) fn reject_all_fcus(&self, reject: bool) {
        self.inner.reject_all_fcus.store(reject, Ordering::SeqCst);
    }

    /// Accepts attribute-carrying FCUs without returning a payload ID,
    /// simulating an execution layer that failed to register the build.
    pub(super) fn suppress_payload_ids(&self, suppress: bool) {
        self.inner
            .suppress_payload_ids
            .store(suppress, Ordering::SeqCst);
    }

    /// Returns payload IDs from build FCUs without registering their jobs,
    /// making payload resolution report that no job exists under the ID.
    pub(super) fn omit_payload_job(&self, omit: bool) {
        self.inner.omit_payload_job.store(omit, Ordering::SeqCst);
    }

    // NOTE: the fake deliberately offers no way to hold a new-payload or
    // FCU response open. The actor paces those futures
    // (`Pacer::pace`), and the deterministic runtime *blocks* when a paced
    // future is still pending at its pace deadline - a test-side gate can
    // then never be released, deadlocking the test. To keep the execution
    // task slot occupied over a stretch of virtual time, script a SYNCING
    // payload status instead: the actor's own postpone-retry pause holds
    // the slot without a pending execution-layer future.

    // ---- payload builds ----

    /// Auto-delivers `payload` to the next payload build registered by an
    /// attribute-carrying FCU.
    pub(super) fn script_built_payload(&self, payload: TempoBuiltPayload) {
        self.inner.scripted_builds.lock().push_back(payload);
    }

    /// The IDs of registered builds that have not been delivered or aborted.
    pub(super) fn pending_payload_jobs(&self) -> Vec<PayloadId> {
        self.inner.payload_senders.lock().keys().copied().collect()
    }

    /// Delivers `payload` for the build registered under `payload_id`.
    pub(super) fn deliver_payload(&self, payload_id: PayloadId, payload: TempoBuiltPayload) {
        let sender = self
            .inner
            .payload_senders
            .lock()
            .remove(&payload_id)
            .expect("no payload job registered under the ID");
        let _ = sender.send(payload);
    }

    /// Aborts the build registered under `payload_id`: resolving it will
    /// report a build failure.
    pub(super) fn abort_payload(&self, payload_id: PayloadId) {
        self.inner.payload_senders.lock().remove(&payload_id);
    }

    // ---- observation ----

    pub(super) fn calls(&self) -> Vec<ElCall> {
        self.inner.calls.lock().clone()
    }

    pub(super) fn new_payloads(&self) -> Vec<Digest> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                ElCall::NewPayload(digest) => Some(digest),
                _ => None,
            })
            .collect()
    }

    pub(super) fn fcus(&self) -> Vec<(Digest, Digest, bool)> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                ElCall::Fcu {
                    head,
                    finalized,
                    with_attrs,
                } => Some((head, finalized, with_attrs)),
                _ => None,
            })
            .collect()
    }

    pub(super) fn head(&self) -> Digest {
        Digest(self.inner.state.lock().head)
    }

    pub(super) fn finalized(&self) -> Option<(u64, Digest)> {
        self.inner
            .state
            .lock()
            .finalized
            .map(|nh| (nh.number, Digest(nh.hash)))
    }

    pub(super) fn knows_block(&self, digest: Digest) -> bool {
        self.inner.state.lock().blocks.contains_key(&digest.0)
    }

    fn record(&self, call: ElCall) {
        self.inner.calls.lock().push(call);
    }

    /// Applies an accepted forkchoice update to the fake chain state.
    fn apply_forkchoice(&self, fcu: &ForkchoiceState) -> PayloadStatusEnum {
        let mut state = self.inner.state.lock();
        let Some(&(head_height, _)) = state.blocks.get(&fcu.head_block_hash) else {
            return PayloadStatusEnum::Syncing;
        };

        // Rebuild the canonical index: everything above the new head is
        // gone; the head's ancestry becomes canonical down to where it
        // links up with the existing index.
        state.canonical.split_off(&(head_height + 1));
        let mut digest = fcu.head_block_hash;
        let mut height = head_height;
        loop {
            if state.canonical.insert(height, digest) == Some(digest) {
                break;
            }
            if height == 0 {
                break;
            }
            let Some(&(_, parent)) = state.blocks.get(&digest) else {
                break;
            };
            digest = parent;
            height -= 1;
        }
        state.head = fcu.head_block_hash;

        if let Some(&(finalized_height, _)) = state.blocks.get(&fcu.finalized_block_hash) {
            state.finalized = Some(BlockNumHash::new(finalized_height, fcu.finalized_block_hash));
        }

        PayloadStatusEnum::Valid
    }
}

impl ExecutionLayer for FakeExecution {
    fn finalized_num_hash(&self) -> Option<BlockNumHash> {
        self.inner.state.lock().finalized
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis
    }

    fn canonical_block_hash(&self, height: u64) -> eyre::Result<Option<B256>> {
        Ok(self.inner.state.lock().canonical.get(&height).copied())
    }

    fn block_by_digest(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        Ok(self.inner.bodies.lock().get(&digest.0).cloned())
    }

    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static {
        let block = Block::from_execution_block_unchecked(payload.block, None);
        let (digest, height, parent) = (
            block.digest().0,
            block.height().get(),
            block.parent_digest().0,
        );
        self.record(ElCall::NewPayload(Digest(digest)));

        let scripted = self
            .inner
            .payload_overrides
            .lock()
            .get_mut(&digest)
            .and_then(VecDeque::pop_front);
        let outcome = scripted.unwrap_or_else(|| {
            Ok(if self.inner.state.lock().blocks.contains_key(&parent) {
                PayloadStatusEnum::Valid
            } else {
                PayloadStatusEnum::Syncing
            })
        });
        let result = match outcome {
            Ok(status) => {
                if status == PayloadStatusEnum::Valid {
                    self.inner
                        .state
                        .lock()
                        .blocks
                        .insert(digest, (height, parent));
                }
                Ok(PayloadStatus::from_status(status))
            }
            Err(error) => Err(eyre::eyre!(error)),
        };

        async move { result }
    }

    fn fork_choice_updated(
        &self,
        state: ForkchoiceState,
        attributes: Option<TempoPayloadAttributes>,
    ) -> impl Future<Output = eyre::Result<ForkchoiceUpdated>> + Send + 'static {
        self.record(ElCall::Fcu {
            head: Digest(state.head_block_hash),
            finalized: Digest(state.finalized_block_hash),
            with_attrs: attributes.is_some(),
        });

        let scripted = self.inner.fcu_overrides.lock().pop_front();
        let status = if self.inner.reject_all_fcus.load(Ordering::SeqCst) {
            PayloadStatusEnum::Invalid {
                validation_error: "rejected by test".into(),
            }
        } else if let Some(status) = scripted {
            status
        } else {
            self.apply_forkchoice(&state)
        };

        let mut response = ForkchoiceUpdated::from_status(status);
        if response.is_valid()
            && attributes.is_some()
            && !self.inner.suppress_payload_ids.load(Ordering::SeqCst)
        {
            let payload_id = PayloadId::new(
                self.inner
                    .next_payload_id
                    .fetch_add(1, Ordering::SeqCst)
                    .to_be_bytes(),
            );
            if !self.inner.omit_payload_job.load(Ordering::SeqCst) {
                let (sender, receiver) = oneshot::channel();
                match self.inner.scripted_builds.lock().pop_front() {
                    Some(payload) => {
                        let _ = sender.send(payload);
                    }
                    None => {
                        self.inner.payload_senders.lock().insert(payload_id, sender);
                    }
                }
                self.inner
                    .payload_receivers
                    .lock()
                    .insert(payload_id, receiver);
            }
            response = response.with_payload_id(payload_id);
        }

        async move { Ok(response) }
    }

    fn resolve_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Option<eyre::Result<TempoBuiltPayload>>> + Send + 'static {
        self.record(ElCall::Resolve(payload_id));
        let receiver = self.inner.payload_receivers.lock().remove(&payload_id);
        async move {
            match receiver {
                Some(receiver) => Some(
                    receiver
                        .await
                        .map_err(|_| eyre::eyre!("payload build was aborted")),
                ),
                None => None,
            }
        }
    }
}

struct FakeMarshalInner {
    /// Finalized blocks served through `get_block`, keyed by height.
    blocks: Mutex<HashMap<u64, Block>>,
    /// Finalization info served through `get_info`, keyed by height.
    infos: Mutex<HashMap<u64, Digest>>,
    /// Open digest subscriptions the test can fulfill or drop.
    subscriptions: Mutex<Vec<(Digest, Round, oneshot::Sender<Arc<Block>>)>>,
    /// Every subscription ever made, in order.
    subscribe_log: Mutex<Vec<(Digest, Round)>>,
    get_block_log: Mutex<Vec<u64>>,
}

/// A fake of the marshal actor's mailbox.
#[derive(Clone)]
pub(super) struct FakeMarshal {
    inner: Arc<FakeMarshalInner>,
}

impl FakeMarshal {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(FakeMarshalInner {
                blocks: Mutex::new(HashMap::new()),
                infos: Mutex::new(HashMap::new()),
                subscriptions: Mutex::new(Vec::new()),
                subscribe_log: Mutex::new(Vec::new()),
                get_block_log: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Serves `block` through `get_block` at its height.
    pub(super) fn add_block(&self, block: Block) {
        self.inner.blocks.lock().insert(block.height().get(), block);
    }

    /// Serves finalization info for `height` through `get_info`.
    pub(super) fn add_info(&self, height: u64, digest: Digest) {
        self.inner.infos.lock().insert(height, digest);
    }

    /// Digests (and fetch rounds) of the currently open subscriptions.
    ///
    /// Subscriptions whose receiver the actor dropped are pruned: they are
    /// no longer open.
    pub(super) fn open_subscriptions(&self) -> Vec<(Digest, Round)> {
        let mut subscriptions = self.inner.subscriptions.lock();
        subscriptions.retain(|(_, _, sender)| !sender.is_closed());
        subscriptions
            .iter()
            .map(|(digest, round, _)| (*digest, *round))
            .collect()
    }

    /// Every subscription ever opened, in order.
    pub(super) fn subscribe_log(&self) -> Vec<(Digest, Round)> {
        self.inner.subscribe_log.lock().clone()
    }

    /// Heights requested through `get_block`, in order.
    pub(super) fn get_block_log(&self) -> Vec<u64> {
        self.inner.get_block_log.lock().clone()
    }

    /// Fulfills the open subscription for `digest` with `block`.
    ///
    /// Returns false if no subscription for the digest is open.
    pub(super) fn fulfill_subscription(&self, digest: Digest, block: Block) -> bool {
        let mut subscriptions = self.inner.subscriptions.lock();
        let Some(position) = subscriptions.iter().position(|(d, ..)| *d == digest) else {
            return false;
        };
        let (_, _, sender) = subscriptions.swap_remove(position);
        sender.send(Arc::new(block)).is_ok()
    }

    /// Drops the open subscription for `digest`, simulating marshal giving
    /// up on the block. Returns false if none is open.
    pub(super) fn drop_subscription(&self, digest: Digest) -> bool {
        let mut subscriptions = self.inner.subscriptions.lock();
        let Some(position) = subscriptions.iter().position(|(d, ..)| *d == digest) else {
            return false;
        };
        subscriptions.swap_remove(position);
        true
    }
}

impl Marshal for FakeMarshal {
    fn get_block(&self, height: Height) -> impl Future<Output = Option<Block>> + Send {
        self.inner.get_block_log.lock().push(height.get());
        let block = self.inner.blocks.lock().get(&height.get()).cloned();
        async move { block }
    }

    fn get_info(&self, height: Height) -> impl Future<Output = Option<(Height, Digest)>> + Send {
        let info = self
            .inner
            .infos
            .lock()
            .get(&height.get())
            .map(|digest| (height, *digest));
        async move { info }
    }

    fn subscribe_by_digest(
        &self,
        digest: Digest,
        notarized_in: Round,
    ) -> oneshot::Receiver<Arc<Block>> {
        self.inner.subscribe_log.lock().push((digest, notarized_in));
        let (sender, receiver) = oneshot::channel();
        self.inner
            .subscriptions
            .lock()
            .push((digest, notarized_in, sender));
        receiver
    }
}

/// Options for starting the actor under test.
pub(super) struct HarnessOptions {
    pub(super) finalized_floor: u64,
    pub(super) finalized_tip: (Round, u64, Digest),
    pub(super) fcu_heartbeat_interval: Duration,
    pub(super) public_key: Option<commonware_cryptography::ed25519::PublicKey>,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            finalized_floor: 0,
            finalized_tip: (Round::zero(), 0, GENESIS),
            // Keeps the heartbeat out of tests that do not target it.
            fcu_heartbeat_interval: Duration::from_secs(3_600),
            public_key: None,
        }
    }
}

/// The actor under test together with its fakes and mailbox.
pub(super) struct Harness {
    pub(super) context: deterministic::Context,
    pub(super) execution: FakeExecution,
    pub(super) marshal: FakeMarshal,
    pub(super) mailbox: Mailbox,
    pub(super) actor: Handle<()>,
}

impl Harness {
    /// Starts the actor on a genesis-only chain: empty fakes, floor and tip
    /// at genesis.
    pub(super) fn start_at_genesis(context: &deterministic::Context) -> Self {
        Self::start(
            context,
            FakeExecution::new(),
            FakeMarshal::new(),
            HarnessOptions::default(),
        )
    }

    pub(super) fn start(
        context: &deterministic::Context,
        execution: FakeExecution,
        marshal: FakeMarshal,
        options: HarnessOptions,
    ) -> Self {
        let (actor, mailbox) = init(
            context.child("executor"),
            Config {
                execution_node: execution.clone(),
                finalized_floor: Height::new(options.finalized_floor),
                finalized_tip: (
                    options.finalized_tip.0,
                    Height::new(options.finalized_tip.1),
                    options.finalized_tip.2,
                ),
                marshal: marshal.clone(),
                fcu_heartbeat_interval: options.fcu_heartbeat_interval,
                public_key: options.public_key,
            },
        )
        .expect("executor actor should initialize");
        let actor = actor.start();
        Self {
            context: context.child("harness"),
            execution,
            marshal,
            mailbox,
            actor,
        }
    }

    /// Polls `cond` (sleeping 1ms of virtual time between attempts) until it
    /// holds, panicking after [`WAIT_ATTEMPTS`].
    pub(super) async fn wait_until(&self, mut cond: impl FnMut() -> bool) {
        for _ in 0..WAIT_ATTEMPTS {
            if cond() {
                return;
            }
            self.context.sleep(Duration::from_millis(1)).await;
        }
        panic!("condition was not met before the test deadline");
    }

    /// Lets the actor run for `duration` of virtual time.
    pub(super) fn run_for(&self, duration: Duration) -> impl Future<Output = ()> + use<> {
        let context = self.context.child("run_for");
        async move { context.sleep(duration).await }
    }

    /// Reports a new finalized network tip.
    pub(super) fn deliver_tip(&mut self, round: Round, height: u64, digest: Digest) {
        assert!(
            self.mailbox
                .report(Update::Tip(round, Height::new(height), digest))
                .accepted(),
            "actor should accept the finalized tip",
        );
    }

    /// Delivers a finalized block, returning the acknowledgement waiter.
    ///
    /// The waiter resolves once the actor acknowledges the block, and fails
    /// if the actor drops the block without acknowledging it.
    pub(super) fn deliver_finalized(
        &mut self,
        block: Block,
    ) -> impl Future<Output = Result<(), commonware_utils::acknowledgement::Canceled>> + use<> {
        let (ack, waiter) = Exact::handle();
        assert!(
            self.mailbox
                .report(Update::Block(block.into(), ack))
                .accepted(),
            "actor should accept the finalized block",
        );
        waiter
    }

    /// Reports `parent` (notarized in `parent_view`) as the pending head via
    /// a consensus context at `context_view`.
    pub(super) fn report_pending_head(&self, context_view: u64, parent_view: u64, parent: Digest) {
        self.mailbox
            .report_pending_head(Context {
                round: round(context_view),
                leader: tempo_primitives::ed25519::PublicKey::from_seed(42).to_inner(),
                parent: (View::new(parent_view), parent),
            })
            .expect("actor should accept the pending-head report");
    }

    /// Requests validation of `block`, resolving to the verdict.
    pub(super) fn verify(
        &self,
        round: Round,
        block: Block,
    ) -> impl Future<Output = eyre::Result<Option<Duration>>> + use<> {
        let mailbox = self.mailbox.clone();
        async move { mailbox.verify_block(round, block, None).await }
    }

    /// Requests a proposal build on top of `parent`, returning the payload
    /// subscription.
    pub(super) fn build(
        &self,
        round: Round,
        height: u64,
        parent: Digest,
    ) -> futures::channel::oneshot::Receiver<TempoBuiltPayload> {
        self.mailbox
            .build_proposal(round, Height::new(height), parent, attributes())
            .expect("actor should accept the build request")
    }
}
