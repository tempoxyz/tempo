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
use commonware_runtime::{Clock, Handle, Metrics, Spawner, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use eyre::{Report, WrapErr as _};
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
    make_block_with_proposer(
        view,
        height,
        parent,
        tempo_primitives::ed25519::PublicKey::from_seed(42),
    )
}

pub(super) fn make_block_with_proposer(
    view: u64,
    height: u64,
    parent: Digest,
    proposer: tempo_primitives::ed25519::PublicKey,
) -> Block {
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
                    proposer,
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

/// Test constructor for the executor's forkchoice-state convention.
pub(super) trait ForkchoiceStateExt {
    /// Constructs a state from its `(finalized, head)` pair, setting safe to
    /// finalized as the executor does.
    fn from_finalized_head(finalized: Digest, head: Digest) -> Self;
}

impl ForkchoiceStateExt for ForkchoiceState {
    fn from_finalized_head(finalized: Digest, head: Digest) -> Self {
        Self {
            head_block_hash: head.0,
            safe_block_hash: finalized.0,
            finalized_block_hash: finalized.0,
        }
    }
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

enum ScriptedResult<T> {
    Immediate(Result<T, &'static str>),
    Delayed {
        response: Result<T, &'static str>,
        release: oneshot::Receiver<()>,
    },
}

impl<T> ScriptedResult<T> {
    async fn resolve(self) -> Result<T, &'static str> {
        match self {
            Self::Immediate(result) => result,
            Self::Delayed { response, release } => match release.await {
                Ok(()) => response,
                Err(_) => Err("delayed scripted result sender was dropped"),
            },
        }
    }
}

struct ScriptedResults<K, T>(Mutex<Vec<(K, VecDeque<T>)>>);

enum NextScriptedResult<T> {
    Unscripted,
    Scripted(T),
    Exhausted,
}

impl<K, T> ScriptedResults<K, T>
where
    K: Eq,
{
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    fn push(&self, key: K, result: T) {
        let mut scripts = self.0.lock();
        if let Some((_, results)) = scripts.iter_mut().find(|(existing, _)| existing == &key) {
            results.push_back(result);
        } else {
            scripts.push((key, VecDeque::from([result])));
        }
    }

    fn script(&self, key: K, results: impl IntoIterator<Item = T>) {
        let results = results.into_iter().collect::<VecDeque<_>>();
        assert!(!results.is_empty(), "a scripted sequence must not be empty");
        let mut scripts = self.0.lock();
        assert!(
            !scripts.iter().any(|(existing, _)| existing == &key),
            "a script must provide the complete sequence in one call",
        );
        scripts.push((key, results));
    }

    fn pop(&self, key: &K) -> Option<T> {
        self.0
            .lock()
            .iter_mut()
            .find(|(existing, _)| existing == key)
            .and_then(|(_, results)| results.pop_front())
    }

    fn next_scripted(&self, key: &K) -> NextScriptedResult<T> {
        let mut scripts = self.0.lock();
        let Some((_, results)) = scripts.iter_mut().find(|(existing, _)| existing == key) else {
            return NextScriptedResult::Unscripted;
        };
        match results.pop_front() {
            Some(result) => NextScriptedResult::Scripted(result),
            None => NextScriptedResult::Exhausted,
        }
    }
}

struct FakeExecutionInner {
    genesis: B256,
    state: Mutex<ElState>,
    calls: Mutex<Vec<ElCall>>,
    /// Complete new-payload outcome sequences keyed by block hash. A digest
    /// absent from this map uses the fake's stateful default behavior; a
    /// digest present in it must not receive more calls than scripted.
    /// A scripted `Ok(Valid)` still marks the block as known to the execution layer.
    payload_overrides: ScriptedResults<B256, ScriptedResult<PayloadStatusEnum>>,
    /// Validator sets received with new-payload requests, keyed by block hash.
    payload_validator_sets: Mutex<Vec<(Digest, Option<Vec<B256>>)>>,
    /// Payload attributes received with forkchoice-update requests.
    payload_attributes: Mutex<Vec<TempoPayloadAttributes>>,
    /// Complete FCU outcome sequences keyed by forkchoice state. An absent
    /// state uses the fake's stateful default; a present state must not receive
    /// more calls than scripted.
    fcu_overrides: ScriptedResults<ForkchoiceState, Result<PayloadStatusEnum, &'static str>>,
    /// Scripted canonical-hash lookup outcomes keyed by height.
    canonical_hash_overrides: ScriptedResults<u64, Result<Option<B256>, &'static str>>,
    /// Scripted block lookup outcomes keyed by digest.
    block_overrides: ScriptedResults<B256, Result<Option<Block>, &'static str>>,
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
    /// Payload resolutions dropped before the builder returned a result.
    canceled_payload_jobs: Mutex<Vec<PayloadId>>,
    /// Payloads to auto-deliver to the next registered build jobs.
    scripted_builds: Mutex<VecDeque<TempoBuiltPayload>>,
    /// Blocks servable through `block_by_digest`.
    bodies: Mutex<HashMap<B256, Block>>,
}

/// Records cancellation when an unresolved fake payload future is dropped.
struct PayloadResolutionGuard {
    inner: Arc<FakeExecutionInner>,
    payload_id: PayloadId,
    completed: bool,
}

impl Drop for PayloadResolutionGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.inner.payload_senders.lock().remove(&self.payload_id);
        self.inner
            .canceled_payload_jobs
            .lock()
            .push(self.payload_id);
    }
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
                payload_overrides: ScriptedResults::new(),
                payload_validator_sets: Mutex::new(Vec::new()),
                payload_attributes: Mutex::new(Vec::new()),
                fcu_overrides: ScriptedResults::new(),
                canonical_hash_overrides: ScriptedResults::new(),
                block_overrides: ScriptedResults::new(),
                reject_all_fcus: AtomicBool::new(false),
                suppress_payload_ids: AtomicBool::new(false),
                omit_payload_job: AtomicBool::new(false),
                next_payload_id: AtomicU64::new(1),
                payload_senders: Mutex::new(HashMap::new()),
                payload_receivers: Mutex::new(HashMap::new()),
                canceled_payload_jobs: Mutex::new(Vec::new()),
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

    /// Appends a new-payload response for `digest` to its scripted sequence.
    /// Requests consume responses in FIFO order; a request beyond the supplied
    /// responses fails the test instead of falling back to default behavior.
    ///
    /// A digest without a script uses the stateful default: `Valid` if its
    /// parent is known to the fake execution layer, otherwise `Syncing`.
    /// `Ok(PayloadStatusEnum::Invalid)` models a successfully delivered Engine
    /// API response that rejects the payload, while `Err` models a request or
    /// transport failure before the execution layer returns any payload status.
    pub(super) fn script_new_payload(
        &self,
        digest: Digest,
        response: Result<PayloadStatusEnum, &'static str>,
    ) {
        self.inner
            .payload_overrides
            .push(digest.0, ScriptedResult::Immediate(response));
    }

    /// Appends a delayed new-payload response for `digest` and returns the
    /// sender that releases it.
    pub(super) fn script_delayed_new_payload(
        &self,
        digest: Digest,
        response: Result<PayloadStatusEnum, &'static str>,
    ) -> oneshot::Sender<()> {
        let (sender, release) = oneshot::channel();
        self.inner
            .payload_overrides
            .push(digest.0, ScriptedResult::Delayed { response, release });
        sender
    }

    /// Scripts the complete sequence of outcomes for `state`.
    /// Each matching request consumes one outcome in FIFO order; a matching
    /// request beyond the supplied sequence fails the test instead of falling
    /// back to default behavior. Payload attributes do not participate in
    /// matching; another forkchoice state uses the stateful default.
    ///
    /// The default applies the requested forkchoice state, returning `Valid`
    /// when the head is known and `Syncing` otherwise. A scripted `Ok(Valid)`
    /// also applies the state, keeping the fake's response and state coherent.
    /// `Ok(Invalid)` models a delivered Engine API rejection, while `Err`
    /// models a request or transport failure before a status is returned.
    pub(super) fn script_fcu(
        &self,
        state: ForkchoiceState,
        outcomes: impl IntoIterator<Item = Result<PayloadStatusEnum, &'static str>>,
    ) {
        self.inner.fcu_overrides.script(state, outcomes);
    }

    /// Scripts the outcome of the next canonical block lookup at `height`.
    pub(super) fn script_canonical_block_hash(
        &self,
        height: u64,
        outcome: Result<Option<B256>, &'static str>,
    ) {
        self.inner.canonical_hash_overrides.push(height, outcome);
    }

    /// Scripts the outcome of the next block lookup for `digest`.
    pub(super) fn script_block_by_digest(
        &self,
        digest: Digest,
        outcome: Result<Option<Block>, &'static str>,
    ) {
        self.inner.block_overrides.push(digest.0, outcome);
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

    pub(super) fn canceled_payload_jobs(&self) -> Vec<PayloadId> {
        self.inner.canceled_payload_jobs.lock().clone()
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

    pub(super) fn payload_validator_sets(&self) -> Vec<(Digest, Option<Vec<B256>>)> {
        self.inner.payload_validator_sets.lock().clone()
    }

    pub(super) fn payload_attributes(&self) -> Vec<TempoPayloadAttributes> {
        self.inner.payload_attributes.lock().clone()
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
            state.finalized = Some(BlockNumHash::new(
                finalized_height,
                fcu.finalized_block_hash,
            ));
        }

        PayloadStatusEnum::Valid
    }
}

impl ExecutionLayer for FakeExecution {
    fn finalized_num_hash(&self) -> BlockNumHash {
        self.inner
            .state
            .lock()
            .finalized
            .unwrap_or_else(|| BlockNumHash::new(0, self.genesis_hash()))
    }

    fn genesis_hash(&self) -> B256 {
        self.inner.genesis
    }

    fn canonical_block_hash(&self, height: u64) -> eyre::Result<Option<B256>> {
        if let Some(outcome) = self.inner.canonical_hash_overrides.pop(&height) {
            return outcome.map_err(Report::msg).wrap_err_with(|| {
                format!("scripted canonical block lookup failed at height `{height}`")
            });
        }
        Ok(self.inner.state.lock().canonical.get(&height).copied())
    }

    fn block_by_digest(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        if let Some(outcome) = self.inner.block_overrides.pop(&digest.0) {
            return outcome
                .map_err(Report::msg)
                .wrap_err_with(|| format!("scripted block lookup failed for `{digest}"));
        }
        Ok(self.inner.bodies.lock().get(&digest.0).cloned())
    }

    fn new_payload(
        &self,
        payload: TempoExecutionData,
    ) -> impl Future<Output = eyre::Result<PayloadStatus>> + Send + 'static {
        let validator_set = payload.validator_set.clone();
        let block = Block::from_execution_block_unchecked(payload.block, None);
        let (digest, height, parent) = (
            block.digest().0,
            block.height().get(),
            block.parent_digest().0,
        );
        self.record(ElCall::NewPayload(Digest(digest)));
        self.inner
            .payload_validator_sets
            .lock()
            .push((Digest(digest), validator_set));
        let scripted_result = match self.inner.payload_overrides.next_scripted(&digest) {
            NextScriptedResult::Scripted(result) => Some(result),
            NextScriptedResult::Unscripted => None,
            NextScriptedResult::Exhausted => panic!(
                "new-payload request for `{}` exceeded its scripted outcome sequence",
                Digest(digest),
            ),
        };
        let inner = self.inner.clone();

        async move {
            let outcome = match scripted_result {
                Some(result) => result.resolve().await,
                None => Ok(if inner.state.lock().blocks.contains_key(&parent) {
                    PayloadStatusEnum::Valid
                } else {
                    PayloadStatusEnum::Syncing
                }),
            };
            let status = outcome.map_err(Report::msg).wrap_err_with(|| {
                format!(
                    "scripted new-payload request failed for `{}`",
                    Digest(digest)
                )
            })?;
            if status == PayloadStatusEnum::Valid {
                inner.state.lock().blocks.insert(digest, (height, parent));
            }
            Ok(PayloadStatus::from_status(status))
        }
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
        if let Some(attributes) = attributes.as_ref() {
            self.inner
                .payload_attributes
                .lock()
                .push(attributes.clone());
        }

        let outcome = if self.inner.reject_all_fcus.load(Ordering::SeqCst) {
            Ok(PayloadStatusEnum::Invalid {
                validation_error: "rejected by test".into(),
            })
        } else {
            match self.inner.fcu_overrides.next_scripted(&state) {
                NextScriptedResult::Scripted(Ok(PayloadStatusEnum::Valid)) => {
                    let applied = self.apply_forkchoice(&state);
                    assert_eq!(
                        applied,
                        PayloadStatusEnum::Valid,
                        "scripted VALID FCU could not be applied to the fake state: {state:?}",
                    );
                    Ok(PayloadStatusEnum::Valid)
                }
                NextScriptedResult::Scripted(outcome) => outcome,
                NextScriptedResult::Unscripted => Ok(self.apply_forkchoice(&state)),
                NextScriptedResult::Exhausted => {
                    panic!("FCU request exceeded its scripted outcome sequence: {state:?}")
                }
            }
        };

        let outcome = outcome.map_err(Report::msg).wrap_err_with(|| {
            format!(
                "scripted forkchoice update failed for head `{}`",
                Digest(state.head_block_hash)
            )
        });
        let result = match outcome {
            Ok(status) => {
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
                Ok(response)
            }
            Err(error) => Err(error),
        };

        async move { result }
    }

    fn resolve_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = Option<eyre::Result<TempoBuiltPayload>>> + Send + 'static {
        self.record(ElCall::Resolve(payload_id));
        let receiver = self.inner.payload_receivers.lock().remove(&payload_id);
        let mut guard = receiver.as_ref().map(|_| PayloadResolutionGuard {
            inner: self.inner.clone(),
            payload_id,
            completed: false,
        });
        async move {
            match receiver {
                Some(receiver) => {
                    let result = receiver
                        .await
                        .map_err(|_| Report::msg("payload build was aborted"));
                    guard
                        .as_mut()
                        .expect("guard exists with receiver")
                        .completed = true;
                    Some(result)
                }
                None => None,
            }
        }
    }
}

struct MarshalSubscription {
    digest: Digest,
    notarized_in: Round,
    sender: oneshot::Sender<Arc<Block>>,
}

struct MarshalSubscriptions(Mutex<Vec<MarshalSubscription>>);

impl MarshalSubscriptions {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    fn subscribe(&self, digest: Digest, notarized_in: Round) -> oneshot::Receiver<Arc<Block>> {
        let (sender, receiver) = oneshot::channel();
        self.0.lock().push(MarshalSubscription {
            digest,
            notarized_in,
            sender,
        });
        receiver
    }

    fn open(&self) -> Vec<(Digest, Round)> {
        let mut subscriptions = self.0.lock();
        subscriptions.retain(|subscription| !subscription.sender.is_closed());
        subscriptions
            .iter()
            .map(|subscription| (subscription.digest, subscription.notarized_in))
            .collect()
    }

    fn fulfill(&self, digest: Digest, block: Block) -> bool {
        self.take(digest)
            .is_some_and(|subscription| subscription.sender.send(Arc::new(block)).is_ok())
    }

    fn discard(&self, digest: Digest) -> bool {
        self.take(digest).is_some()
    }

    fn take(&self, digest: Digest) -> Option<MarshalSubscription> {
        let mut subscriptions = self.0.lock();
        let position = subscriptions
            .iter()
            .position(|subscription| subscription.digest == digest)?;
        Some(subscriptions.swap_remove(position))
    }
}

struct FakeMarshalInner {
    /// Finalized blocks served through `get_block`, keyed by height.
    blocks: Mutex<HashMap<u64, Block>>,
    /// Finalization info served through `get_info`, keyed by height.
    infos: Mutex<HashMap<u64, Digest>>,
    /// Open digest subscriptions the test can fulfill or drop.
    subscriptions: MarshalSubscriptions,
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
                subscriptions: MarshalSubscriptions::new(),
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
        self.inner.subscriptions.open()
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
        self.inner.subscriptions.fulfill(digest, block)
    }

    /// Drops the open subscription for `digest`, simulating marshal giving
    /// up on the block. Returns false if none is open.
    pub(super) fn drop_subscription(&self, digest: Digest) -> bool {
        self.inner.subscriptions.discard(digest)
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
        self.inner.subscriptions.subscribe(digest, notarized_in)
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

/// Builder for an executor actor harness with default execution and marshal
/// fakes.
pub(super) struct HarnessBuilder {
    execution: FakeExecution,
    marshal: FakeMarshal,
    options: HarnessOptions,
}

impl Default for HarnessBuilder {
    fn default() -> Self {
        Self {
            execution: FakeExecution::new(),
            marshal: FakeMarshal::new(),
            options: HarnessOptions::default(),
        }
    }
}

impl HarnessBuilder {
    pub(super) fn execution(mut self, execution: FakeExecution) -> Self {
        self.execution = execution;
        self
    }

    pub(super) fn marshal(mut self, marshal: FakeMarshal) -> Self {
        self.marshal = marshal;
        self
    }

    pub(super) fn harness_options(mut self, options: HarnessOptions) -> Self {
        self.options = options;
        self
    }

    pub(super) fn start<TContext>(self, context: &TContext) -> Harness<TContext>
    where
        TContext: Clock + Metrics + Spawner,
    {
        self.try_start(context)
            .expect("executor actor should initialize")
    }

    pub(super) fn try_start<TContext>(self, context: &TContext) -> eyre::Result<Harness<TContext>>
    where
        TContext: Clock + Metrics + Spawner,
    {
        let Self {
            execution,
            marshal,
            options,
        } = self;
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
        )?;
        let actor = actor.start();
        Ok(Harness {
            context: context.child("harness"),
            execution,
            marshal,
            mailbox,
            actor,
        })
    }
}

/// The actor under test together with its fakes and mailbox.
pub(super) struct Harness<TContext = deterministic::Context> {
    pub(super) context: TContext,
    pub(super) execution: FakeExecution,
    pub(super) marshal: FakeMarshal,
    pub(super) mailbox: Mailbox,
    pub(super) actor: Handle<()>,
}

impl Harness {
    pub(super) fn builder() -> HarnessBuilder {
        HarnessBuilder::default()
    }
}

impl<TContext> Harness<TContext>
where
    TContext: Clock + Metrics + Spawner,
{
    /// Starts the actor on a genesis-only chain: empty fakes, floor and tip
    /// at genesis.
    pub(super) fn start_at_genesis(context: &TContext) -> Self {
        Harness::builder().start(context)
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
    pub(super) fn run_for(&self, duration: Duration) -> impl Future<Output = ()> + use<TContext> {
        let context = self.context.child("run_for");
        async move { context.sleep(duration).await }
    }

    pub(super) fn metrics(&self) -> String {
        self.context.encode()
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
    ) -> impl Future<Output = Result<(), commonware_utils::acknowledgement::Canceled>> + use<TContext>
    {
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
    ) -> impl Future<Output = eyre::Result<Option<Duration>>> + use<TContext> {
        self.verify_with_validator_set(round, block, None)
    }

    pub(super) fn verify_with_validator_set(
        &self,
        round: Round,
        block: Block,
        validator_set: Option<Vec<B256>>,
    ) -> impl Future<Output = eyre::Result<Option<Duration>>> + use<TContext> {
        let mailbox = self.mailbox.clone();
        async move { mailbox.verify_block(round, block, validator_set).await }
    }

    /// Requests a proposal build on top of `parent`, returning the payload
    /// subscription.
    pub(super) fn build(
        &self,
        round: Round,
        parent: Digest,
    ) -> futures::channel::oneshot::Receiver<TempoBuiltPayload> {
        self.build_with_attributes(round, parent, attributes())
    }

    pub(super) fn build_with_attributes(
        &self,
        round: Round,
        parent: Digest,
        attributes: TempoPayloadAttributes,
    ) -> futures::channel::oneshot::Receiver<TempoBuiltPayload> {
        self.mailbox
            .build_proposal(round, parent, attributes)
            .expect("actor should accept the build request")
    }
}

#[cfg(test)]
mod scripted_results_tests {
    use super::{NextScriptedResult, ScriptedResults};

    #[test]
    fn absent_and_exhausted_scripts_are_distinct() {
        let results = ScriptedResults::<u8, Result<u8, &'static str>>::new();

        assert!(matches!(
            results.next_scripted(&1),
            NextScriptedResult::Unscripted
        ));

        results.script(1, [Ok(7)]);
        assert!(matches!(
            results.next_scripted(&1),
            NextScriptedResult::Scripted(Ok(7))
        ));
        assert!(matches!(
            results.next_scripted(&1),
            NextScriptedResult::Exhausted
        ));
    }
}
