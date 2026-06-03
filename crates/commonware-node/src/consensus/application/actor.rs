//! The actor running the application event loop.
//!
//! # On the usage of the commonware-pacer
//!
//! The actor will contain `Pacer::pace` calls for all interactions
//! with the execution layer. This is a no-op in production because the
//! commonware tokio runtime ignores these. However, these are critical in
//! e2e tests using the commonware deterministic runtime: since the execution
//! layer is still running on the tokio runtime, these calls signal the
//! deterministic runtime to spend real life time to wait for the execution
//! layer calls to complete.

use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use alloy_consensus::BlockHeader;
#[cfg(feature = "bal")]
use alloy_consensus::transaction::TxHashRef as _;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::PayloadId;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    simplex::Plan,
    types::{Epoch, Epocher as _, FixedEpocher, Height, HeightDelta, Round, View},
};
use commonware_cryptography::{certificate::Provider as _, ed25519::PublicKey};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    ContextCell, FutureExt as _, Handle, Metrics as _, Pacer, Spawner, Storage, spawn_cell,
};
use prometheus_client::metrics::counter::Counter;

use commonware_utils::{SystemTimeExt, acknowledgement::Acknowledgement};
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::{
    StreamExt as _, TryFutureExt as _,
    channel::{mpsc, oneshot},
    future::try_join,
};
use rand_08::{CryptoRng, Rng};
use reth_node_builder::{Block as _, ConsensusEngineHandle, PayloadKind};
#[cfg(feature = "bal")]
use reth_payload_builder::{BuildNewPayload, PayloadBuilderError};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};
use tempo_telemetry_util::display_duration;

use reth_provider::{BlockHashReader as _, BlockReader as _, BlockSource};
#[cfg(feature = "bal")]
use tempo_payload_types::SpeculativePayloadParent;
use tempo_payload_types::{
    PayloadBuildControl, TempoBuiltPayloadExecutedBlock, TempoPayloadAttributes,
    marshal_persist_estimate, observe_marshal_persist,
};
use tempo_primitives::TempoConsensusContext;
#[cfg(feature = "bal")]
use tokio::sync::{Mutex as AsyncMutex, oneshot as tokio_oneshot};
use tracing::{Level, debug, info, info_span, instrument, warn};

use super::{
    Mailbox,
    ingress::{Broadcast, Genesis, Message, Propose, Verify},
};
#[cfg(feature = "bal")]
use crate::fast_path::FastPathPayloadCache;
use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    subblocks,
    utils::OptionFuture,
};

pub(in crate::consensus) struct Actor<TContext, TState = Uninit> {
    context: ContextCell<TContext>,
    mailbox: mpsc::Receiver<Message>,

    inner: Inner<TState>,
}

struct BuildProposalArgs<'a> {
    propose_start: Instant,
    parent_view: View,
    parent_digest: Digest,
    round: Round,
    payload_id_rx: &'a mut Option<PendingPayloadId>,
    leader: PublicKey,
}

enum PendingPayloadId {
    Canonical(oneshot::Receiver<eyre::Result<PayloadId>>),
    #[cfg(feature = "bal")]
    Speculative(tokio_oneshot::Receiver<Result<PayloadId, PayloadBuilderError>>),
    Ready(PayloadId),
}

impl PendingPayloadId {
    fn ready(payload_id: PayloadId) -> Self {
        Self::Ready(payload_id)
    }

    async fn recv(&mut self) -> eyre::Result<PayloadId> {
        match self {
            Self::Canonical(rx) => (&mut *rx)
                .await
                .wrap_err("executor dropped response")?
                .wrap_err("failed requesting a new payload build"),
            #[cfg(feature = "bal")]
            Self::Speculative(rx) => (&mut *rx)
                .await
                .wrap_err("payload builder dropped speculative payload id response")?
                .wrap_err("failed starting speculative payload build"),
            Self::Ready(payload_id) => Ok(*payload_id),
        }
    }
}

struct ProposalReturn {
    time: SystemTime,
    block_size_bytes: usize,
    fast_path_executed_block: Option<TempoBuiltPayloadExecutedBlock>,
}

#[cfg(feature = "bal")]
#[derive(Clone, Debug, Default)]
struct SpeculativeBuildRegistry {
    active: Arc<AsyncMutex<Option<SpeculativeBuild>>>,
    current_control: Arc<AsyncMutex<Option<PayloadBuildControl>>>,
}

#[cfg(feature = "bal")]
#[derive(Debug)]
struct SpeculativeBuild {
    parent_digest: Digest,
    parent_height: Height,
    build_control: PayloadBuildControl,
    payload_id_rx: Option<tokio_oneshot::Receiver<Result<PayloadId, PayloadBuilderError>>>,
    payload_id: Option<PayloadId>,
}

#[cfg(feature = "bal")]
impl Drop for SpeculativeBuild {
    fn drop(&mut self) {
        self.build_control.cancel();
    }
}

#[cfg(feature = "bal")]
impl SpeculativeBuildRegistry {
    async fn replace(&self, execution_node: Arc<TempoFullNode>, build: SpeculativeBuild) {
        self.track_build_control(build.build_control.clone()).await;
        let old = self.active.lock().await.replace(build);
        if let Some(old) = old {
            Self::spawn_cancel(execution_node, old, "replaced_by_new_verify");
        }
    }

    async fn stop_active(&self, execution_node: Arc<TempoFullNode>, reason: &'static str) {
        self.cancel_current_control(reason).await;
        if let Some(build) = self.active.lock().await.take() {
            Self::spawn_cancel(execution_node, build, reason);
        }
    }

    fn request_stop_active(&self, execution_node: Arc<TempoFullNode>, reason: &'static str) {
        let mut needs_async_cleanup = false;

        match self.current_control.try_lock() {
            Ok(mut current_control) => {
                if let Some(control) = current_control.take() {
                    control.cancel();
                    debug!(
                        reason,
                        "cancelled current speculative payload build control"
                    );
                }
            }
            Err(_) => {
                needs_async_cleanup = true;
                debug!(
                    reason,
                    "scheduling speculative payload build control cancellation"
                );
            }
        }

        match self.active.try_lock() {
            Ok(mut active) => {
                if let Some(build) = active.take() {
                    Self::spawn_cancel(execution_node.clone(), build, reason);
                }
            }
            Err(_) => {
                needs_async_cleanup = true;
                debug!(
                    reason,
                    "scheduling speculative payload build registry cleanup"
                );
            }
        }

        if needs_async_cleanup {
            let registry = self.clone();
            let task_executor = execution_node.task_executor.clone();
            task_executor.spawn_task(async move {
                registry.stop_active(execution_node, reason).await;
            });
        }
    }

    async fn stop_if_finalized_past_parent(
        &self,
        execution_node: Arc<TempoFullNode>,
        finalized_height: Height,
        reason: &'static str,
    ) {
        let Some(build) = ({
            let mut active = self.active.lock().await;
            if active
                .as_ref()
                .is_some_and(|build| finalized_height > build.parent_height)
            {
                active.take()
            } else {
                None
            }
        }) else {
            return;
        };
        build.build_control.cancel();
        Self::spawn_cancel(execution_node, build, reason);
    }

    async fn take_matching(&self, parent_digest: Digest) -> Option<SpeculativeBuild> {
        let mut active = self.active.lock().await;
        if active
            .as_ref()
            .is_some_and(|build| build.parent_digest == parent_digest)
        {
            active.take()
        } else {
            None
        }
    }

    async fn track_build_control(&self, build_control: PayloadBuildControl) {
        self.current_control.lock().await.replace(build_control);
    }

    async fn cancel_current_control(&self, reason: &'static str) {
        let Some(control) = self.current_control.lock().await.take() else {
            return;
        };
        control.cancel();
        debug!(
            reason,
            "cancelled current speculative payload build control"
        );
    }

    fn spawn_cancel(
        execution_node: Arc<TempoFullNode>,
        mut build: SpeculativeBuild,
        reason: &'static str,
    ) {
        build.build_control.cancel();
        debug!(
            parent.digest = %build.parent_digest,
            parent.height = %build.parent_height,
            reason,
            "scheduled speculative payload build cancellation",
        );

        let task_executor = execution_node.task_executor.clone();
        // Cancelling can wait for payload-id delivery and pending payload resolution.
        // Keep that work on the execution-side task executor so a stale build
        // cannot consume the consensus view budget before block verification starts.
        task_executor.spawn_task(async move {
            build.cancel(execution_node.as_ref(), reason).await;
        });
    }
}

#[cfg(feature = "bal")]
impl SpeculativeBuild {
    async fn payload_id(&mut self) -> eyre::Result<PayloadId> {
        if let Some(payload_id) = self.payload_id {
            return Ok(payload_id);
        }
        let rx = self
            .payload_id_rx
            .take()
            .ok_or_eyre("speculative payload id receiver was already consumed")?;
        let payload_id = rx
            .await
            .wrap_err("payload builder dropped speculative payload id response")?
            .wrap_err("failed starting speculative payload build")?;
        self.payload_id = Some(payload_id);
        Ok(payload_id)
    }

    async fn cancel(&mut self, execution_node: &TempoFullNode, reason: &'static str) {
        let payload_id = match self.payload_id().await {
            Ok(payload_id) => payload_id,
            Err(error) => {
                warn!(
                    %error,
                    parent.digest = %self.parent_digest,
                    parent.height = %self.parent_height,
                    reason,
                    "speculative payload build was not started before cancellation",
                );
                return;
            }
        };

        let fut = match execution_node
            .payload_builder_handle
            .resolve_kind_fut(payload_id, PayloadKind::WaitForPending)
            .await
        {
            Ok(Some(fut)) => fut,
            Ok(None) => {
                debug!(
                    %payload_id,
                    parent.digest = %self.parent_digest,
                    parent.height = %self.parent_height,
                    reason,
                    "speculative payload build was already gone before cancellation",
                );
                return;
            }
            Err(error) => {
                warn!(
                    %error,
                    %payload_id,
                    parent.digest = %self.parent_digest,
                    parent.height = %self.parent_height,
                    reason,
                    "failed resolving speculative payload while cancelling build",
                );
                return;
            }
        };
        drop(fut);
        debug!(
            %payload_id,
            parent.digest = %self.parent_digest,
            parent.height = %self.parent_height,
            reason,
            "cancelled speculative payload build",
        );
    }
}

impl<TContext, TState> Actor<TContext, TState> {
    pub(super) fn mailbox(&self) -> &Mailbox {
        &self.inner.my_mailbox
    }
}

impl<TContext> Actor<TContext, Uninit>
where
    TContext: Pacer
        + governor::clock::Clock
        + Rng
        + CryptoRng
        + Spawner
        + Storage
        + commonware_runtime::Metrics,
{
    pub(super) async fn init(config: super::Config<TContext>) -> eyre::Result<Self> {
        let (tx, rx) = mpsc::channel(config.mailbox_size);
        let my_mailbox = Mailbox::from_sender(tx);

        let metrics = Metrics::init(&config.context);

        Ok(Self {
            context: ContextCell::new(config.context),
            mailbox: rx,

            inner: Inner {
                public_key: config.public_key,
                epoch_strategy: config.epoch_strategy,

                proposal_return_budget: config.proposal_return_budget,

                my_mailbox,
                marshal: config.marshal,

                execution_node: config.execution_node,
                #[cfg(feature = "bal")]
                fast_path_payloads: config.fast_path_payloads,
                executor: config.executor,

                subblocks: config.subblocks,

                scheme_provider: config.scheme_provider,

                metrics,

                state: Uninit(()),
            },
        })
    }

    /// Runs the actor until it is externally stopped.
    async fn run_until_stopped(self, dkg_manager: crate::dkg::manager::Mailbox) {
        let Self {
            context,
            mailbox,
            inner,
        } = self;
        // TODO(janis): should be placed under a shutdown signal so we don't
        // just stall on startup.
        let Ok(initialized) = inner.into_initialized(dkg_manager).await else {
            // Drop the error because into_initialized generates an error event.
            return;
        };

        Actor {
            context,
            mailbox,
            inner: initialized,
        }
        .run_until_stopped()
        .await
    }

    pub(in crate::consensus) fn start(
        mut self,
        dkg_manager: crate::dkg::manager::Mailbox,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run_until_stopped(dkg_manager))
    }
}

impl<TContext> Actor<TContext, Init>
where
    TContext: Pacer
        + governor::clock::Clock
        + Rng
        + CryptoRng
        + Spawner
        + Storage
        + commonware_runtime::Metrics,
{
    async fn run_until_stopped(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            self.handle_message(msg);
        }
    }

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Broadcast(broadcast) => {
                self.context.with_label("broadcast").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_broadcast(*broadcast)
                });
            }
            Message::Finalized(finalized) => {
                self.context.with_label("finalized").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_finalized(*finalized)
                });
            }
            Message::Genesis(genesis) => {
                self.context.with_label("genesis").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_genesis(genesis, context)
                });
            }
            Message::Propose(propose) => {
                self.context.with_label("propose").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_propose(*propose, context)
                });
            }
            Message::Verify(verify) => {
                self.context.with_label("verify").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_verify(*verify, context)
                });
            }
        }
    }
}

#[derive(Clone)]
struct Inner<TState> {
    public_key: PublicKey,
    epoch_strategy: FixedEpocher,
    // Local proposal window after reserving network propagation time.
    proposal_return_budget: Duration,

    my_mailbox: Mailbox,

    marshal: crate::alias::marshal::Mailbox,

    execution_node: Arc<TempoFullNode>,
    #[cfg(feature = "bal")]
    fast_path_payloads: FastPathPayloadCache,
    executor: crate::executor::Mailbox,
    subblocks: Option<subblocks::Mailbox>,
    scheme_provider: SchemeProvider,

    metrics: Metrics,

    state: TState,
}

impl Inner<Init> {
    #[instrument(
        skip_all,
        fields(%digest),
    )]
    async fn handle_broadcast(self, Broadcast { digest, plan }: Broadcast) {
        let (round, recipients) = match plan {
            Plan::Propose { round } => (round, Recipients::All),
            Plan::Forward { round, recipients } => (round, recipients),
        };
        self.marshal.forward(round, digest, recipients).await;
    }

    async fn handle_finalized(self, update: Update<Block>) {
        let finalized_height = match update {
            Update::Tip(_, height, _) => height,
            Update::Block(block, ack) => {
                let height = block.height();
                ack.acknowledge();
                height
            }
        };

        #[cfg(not(feature = "bal"))]
        let _ = finalized_height;

        #[cfg(feature = "bal")]
        self.state
            .speculative_builds
            .stop_if_finalized_past_parent(
                self.execution_node.clone(),
                finalized_height,
                "finalized_past_speculative_parent",
            )
            .await;
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %genesis.epoch,
        ),
        ret(Display),
        err(level = Level::ERROR)
    )]
    async fn handle_genesis<TContext: commonware_runtime::Clock>(
        self,
        mut genesis: Genesis,
        context: TContext,
    ) -> eyre::Result<Digest> {
        // The last block of the previous epoch is the genesis of the current
        // epoch. Only epoch 0/height 0 is special cased because first height
        // of epoch 0 == genesis of epoch 0.
        let boundary = match genesis.epoch.previous() {
            None => Height::zero(),
            Some(previous_epoch) => self
                .epoch_strategy
                .last(previous_epoch)
                .expect("epoch strategy is for all epochs"),
        };

        let mut attempts = 0;
        let epoch_genesis = loop {
            attempts += 1;
            if let Ok(Some(hash)) = self.execution_node.provider.block_hash(boundary.get()) {
                break Digest(hash);
            } else if let Some((_, digest)) = self.marshal.get_info(boundary).await {
                break digest;
            } else {
                info_span!("fetch_genesis_digest").in_scope(|| {
                    info!(
                        boundary.height = %boundary,
                        attempts,
                        "neither marshal actor nor execution layer had the \
                        boundary block of the previous epoch available; \
                        waiting 2s before trying again"
                    );
                });
                select!(
                    () = genesis.response.closed() => {
                        return Err(eyre!("genesis request was cancelled"));
                    },

                    _ = context.sleep(Duration::from_secs(2)) => {
                        continue;
                    },
                );
            }
        };
        genesis.response.send(epoch_genesis).map_err(|_| {
            eyre!("failed returning parent digest for epoch: return channel was already closed")
        })?;
        Ok(epoch_genesis)
    }

    /// Handles a [`Propose`] request.
    #[instrument(
        skip_all,
        fields(
            epoch = %request.round.epoch(),
            view = %request.round.view(),
            parent.view = %request.parent.0,
            parent.digest = %request.parent.1,
        ),
        err(level = Level::WARN),
    )]
    async fn handle_propose<TContext: Pacer>(
        self,
        request: Propose,
        context: TContext,
    ) -> eyre::Result<()> {
        let Propose {
            parent: (parent_view, parent_digest),
            mut response,
            round,
            leader,
            started_at: propose_start,
        } = request;

        let proposal_digest = {
            let mut payload_id_rx: Option<PendingPayloadId> = None;
            let mut proposal = Box::pin(async {
                // Follow the commonware marshal::standard::inline application:
                //
                // >On leader recovery, marshal may already hold a verified block
                // >for this round (persisted by a pre-crash propose whose
                // >notarize vote never reached the journal).
                //
                // >The parent context recovered by simplex may differ from the one
                // >the cached block was built against, so the stored block is not safe to reuse
                // >and building a fresh block would land on the same prunable
                // >archive index and be silently dropped.
                //
                // >Skip this view and let the voter nullify it via timeout.
                //
                // TODO: we are diverging from commonware in that we return the digest
                // here. Is that ok or can that cause problems?
                //
                // `marshal.get_verified` can take a long time if marshal is busy
                // persisting the parent block, so we race it with payload building to
                // avoid delaying the usual proposal path. If it finds a verified block,
                // we always prefer that block and skip the newly built proposal,
                // even when payload construction finishes first.
                let already_verified = OptionFuture::some(self.marshal.get_verified(round));
                futures::pin_mut!(already_verified);

                let mut proposal = Box::pin(self.clone().build_proposal(
                    context.clone(),
                    BuildProposalArgs {
                        propose_start,
                        parent_view,
                        parent_digest,
                        round,
                        payload_id_rx: &mut payload_id_rx,
                        leader,
                    },
                ));

                let (block, proposal_return) = tokio::select! {
                    biased;

                    Some(block) = &mut already_verified => {
                        drop(proposal);
                        self.cancel_payload_build(
                            &mut payload_id_rx,
                            "proposal_already_verified_on_restart",
                        );
                        debug!("skipping proposal: verified block already exists for round on restart");
                        (block, None)
                    },

                    res = &mut proposal => {
                        let proposal = res.wrap_err("failed creating a proposal")?;

                        // Make sure that we get a response from the already_verified future before proposing.
                        if already_verified.is_none() {
                            proposal
                        } else {
                            if let Some(block) = already_verified.await {
                                debug!("skipping proposal: verified block already exists for round on restart");
                                (block, None)
                            } else {
                                proposal
                            }
                        }
                    },
                };

                let digest = block.digest();
                if let Some(proposal_return) = proposal_return {
                    #[cfg(feature = "bal")]
                    let block_height = block.height();
                    #[cfg(feature = "bal")]
                    let block_hash = block.block_hash();
                    let fast_path_executed_block = proposal_return.fast_path_executed_block;

                    let persist_start = Instant::now();
                    if !self.marshal.proposed(round, block).await {
                        bail!("marshal actor rejected persisting proposal");
                    }
                    observe_marshal_persist(
                        proposal_return.block_size_bytes,
                        persist_start.elapsed(),
                    );

                    if let Some(executed_block) = fast_path_executed_block {
                        #[cfg(feature = "bal")]
                        {
                            self.fast_path_payloads.insert(
                                digest,
                                block_height,
                                block_hash,
                                executed_block,
                            );
                            debug!(
                                proposal.digest = %digest,
                                proposal.height = %block_height,
                                proposal.hash = %block_hash,
                                "cached gated built payload for finalization fast path",
                            );
                        }

                        #[cfg(not(feature = "bal"))]
                        let _ = executed_block;
                    }

                    // Keep waiting for the remaining return time, if there's anything left after building the block.
                    context.sleep_until(proposal_return.time).await;
                }

                eyre::Ok(digest)
            });

            tokio::select! {
                () = response.closed() => {
                    drop(proposal);
                    self.cancel_payload_build(
                        &mut payload_id_rx,
                        "proposal_response_channel_closed",
                    );

                    return Err(eyre!(
                        "proposal return channel was closed by consensus \
                        engine before block could be proposed; aborting"
                    ))
                },

                res = &mut proposal => {
                    res?
                },
            }
        };

        info!(
            proposal.digest = %proposal_digest,
            "constructed proposal",
        );

        response.send(proposal_digest).map_err(|_| {
            eyre!(
                "failed returning proposal to consensus engine: response \
                channel was already closed"
            )
        })?;

        Ok(())
    }

    /// Verifies a [`Verify`] request.
    ///
    /// this method only renders a decision on the `verify.response`
    /// channel if it was able to come to a boolean decision. If it was
    /// unable to refute or prove the validity of the block it will
    /// return an error and drop the response channel.
    ///
    /// Conditions for which no decision could be made are usually:
    /// no block could be read from the syncer or communication with the
    /// execution layer failed.
    #[instrument(
        skip_all,
        fields(
            epoch = %verify.round.epoch(),
            view = %verify.round.view(),
            digest = %verify.payload,
            parent.view = %verify.parent.0,
            parent.digest = %verify.parent.1,
            proposer = %verify.proposer,
        ),
        err,
    )]
    async fn handle_verify<TContext: Pacer>(
        self,
        verify: Verify,
        context: TContext,
    ) -> eyre::Result<()> {
        let Verify {
            parent,
            payload,
            proposer,
            mut response,
            round,
        } = verify;
        #[cfg(feature = "bal")]
        self.state
            .speculative_builds
            .request_stop_active(self.execution_node.clone(), "new_handle_verify");

        let result = select!(
            () = response.closed() => {
                Err(eyre!(
                    "verification return channel was closed by consensus \
                    engine before block could be validated; aborting"
                ))
            },

            res = self.clone().verify(context, parent, payload, proposer, round) => {
                res.wrap_err("block verification failed")
            }
        )?;

        if response.send(result).is_err() {
            warn!("received dropped channel before verification result could be returned");
        }

        Ok(())
    }

    fn cancel_payload_build(
        &self,
        payload_id_rx: &mut Option<PendingPayloadId>,
        reason: &'static str,
    ) {
        let Some(mut pending) = payload_id_rx.take() else {
            return;
        };

        let execution_node = self.execution_node.clone();
        let task_executor = execution_node.task_executor.clone();
        task_executor.spawn_task(async move {
            let payload_id = match pending.recv().await {
                Ok(payload_id) => payload_id,
                Err(error) => {
                    warn!(%error, reason, "payload build was not started before cancellation");
                    return;
                }
            };

            let fut = match execution_node
                .payload_builder_handle
                .resolve_kind_fut(payload_id, PayloadKind::WaitForPending)
                .await
            {
                Ok(Some(fut)) => fut,
                Ok(None) => {
                    debug!(%payload_id, reason, "payload build was already gone before cancellation");
                    return;
                }
                Err(error) => {
                    warn!(%error, %payload_id, reason, "failed resolving payload while cancelling build");
                    return;
                }
            };
            drop(fut);
        });
    }

    async fn proposal_extra_data(
        &self,
        parent: &Block,
        parent_digest: Digest,
        round: Round,
    ) -> eyre::Result<Bytes> {
        let parent_epoch_info = self
            .epoch_strategy
            .containing(parent.height())
            .expect("epoch strategy is for all heights");

        if parent_epoch_info.last() == parent.height().next()
            && parent_epoch_info.epoch() == round.epoch()
        {
            let outcome = self
                .state
                .dkg_manager
                .get_dkg_outcome(parent_digest, parent.height())
                .await
                .wrap_err("failed getting public dkg ceremony outcome")?;
            ensure!(
                round.epoch().next() == outcome.epoch,
                "outcome is for epoch `{}`, but we are trying to include the \
                outcome for epoch `{}`",
                outcome.epoch,
                round.epoch().next(),
            );
            info!(
                %outcome.epoch,
                outcome.network_identity = %outcome.network_identity(),
                outcome.dealers = ?outcome.dealers(),
                outcome.players = ?outcome.players(),
                outcome.next_players = ?outcome.next_players(),
                "received DKG outcome; will include in payload builder attributes",
            );
            Ok(outcome.encode().into())
        } else {
            match self.state.dkg_manager.get_dealer_log(round.epoch()).await {
                Err(error) => {
                    warn!(
                        %error,
                        "failed getting signed dealer log for current epoch \
                        because actor dropped response channel",
                    );
                    Ok(Bytes::default())
                }
                Ok(None) => Ok(Bytes::default()),
                Ok(Some(log)) => {
                    info!(
                        "received signed dealer log; will include in payload \
                        builder attributes"
                    );
                    Ok(log.encode().into())
                }
            }
        }
    }

    async fn verify_proposal_parent<TContext: Pacer>(
        &self,
        context: TContext,
        parent_epoch: Epoch,
        parent: &Block,
    ) -> eyre::Result<()> {
        if !verify_block(
            context,
            parent_epoch,
            &self.epoch_strategy,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            parent,
            parent.parent_digest(),
            &self.scheme_provider,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?
        {
            bail!("the proposal parent block is not valid");
        }

        Ok(())
    }

    async fn build_proposal<TContext: Pacer>(
        self,
        context: TContext,
        args: BuildProposalArgs<'_>,
    ) -> eyre::Result<(Block, Option<ProposalReturn>)> {
        let BuildProposalArgs {
            propose_start,
            parent_view,
            parent_digest,
            round,
            payload_id_rx,
            leader,
        } = args;

        let parent = get_parent(
            &self.execution_node,
            round,
            parent_digest,
            parent_view,
            &self.marshal,
        )
        .await?;
        #[cfg(feature = "bal")]
        let parent = {
            self.ensure_block_access_list_sidecar(parent, round, parent_view, parent_digest)
                .await?
        };

        debug!(height = %parent.height(), "retrieved parent block",);

        let parent_epoch_info = self
            .epoch_strategy
            .containing(parent.height())
            .expect("epoch strategy is for all heights");

        // If in the same epoch, re-propose the parent if the parent is the last height
        // of the epoch. parent.height+1 should be proposed as the first block of the
        // next epoch.
        if parent_epoch_info.last() == parent.height() && parent_epoch_info.epoch() == round.epoch()
        {
            if !self.marshal.verified(round, parent.clone()).await {
                bail!("marshal rejected re-proposed boundary block");
            }
            info!("parent is last height of epoch; re-proposing parent");
            return Ok((parent, None));
        }

        let is_genesis_parent = parent.height().is_zero()
            || parent_epoch_info.last() == parent.height()
                && parent_epoch_info.epoch().next() == round.epoch();

        // Query DKG manager for ceremony data before building or attaching payload.
        let extra_data = self
            .proposal_extra_data(&parent, parent_digest, round)
            .await?;

        // Use current timestamp but make sure that if parent's timestamp is in the future, we account for that.
        //
        // We don't expect this being hit in practice because we validate the
        // timestamp is not in the future during EL validation.
        let mut epoch_millis = context.current().epoch_millis();
        if epoch_millis <= parent.timestamp_millis() {
            self.metrics.parent_ahead_of_local_time.inc();
            epoch_millis = parent.timestamp_millis() + 1
        };

        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        let consensus_context = Some(TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent_view.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&leader),
        });

        let parent_hash = parent.block_hash();
        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let marshal_persist = marshal_persist_estimate();
        #[cfg(feature = "bal")]
        let nullified_view_recovery =
            !is_genesis_parent && is_nullified_view_recovery(round, parent_view);

        #[cfg(feature = "bal")]
        if let Some(mut speculative_build) = self
            .state
            .speculative_builds
            .take_matching(parent_digest)
            .await
        {
            self.state
                .speculative_builds
                .track_build_control(speculative_build.build_control.clone())
                .await;
            let consensus_context = consensus_context
                .expect("proposal consensus context is constructed immediately above");
            let build_budget = if nullified_view_recovery {
                Duration::ZERO
            } else {
                self.proposal_return_budget
                    .saturating_sub(propose_start.elapsed())
            };
            speculative_build
                .build_control
                .attach_proposal_context_with_budget(extra_data, consensus_context, build_budget)
                .map_err(|error| eyre!("failed attaching speculative proposal context: {error}"))?;
            self.metrics
                .speculative_payload_builds_reused_by_propose
                .inc();
            debug!(
                parent.digest = %parent_digest,
                parent.height = %parent.height(),
                "attached proposal context to speculative BAL payload build"
            );

            if !is_genesis_parent {
                if let Err(error) = self
                    .verify_proposal_parent(context.clone(), parent_epoch_info.epoch(), &parent)
                    .await
                {
                    SpeculativeBuildRegistry::spawn_cancel(
                        self.execution_node.clone(),
                        speculative_build,
                        "proposal_parent_validation_failed",
                    );
                    return Err(error);
                }
            }

            let (proposal, proposal_return) = self
                .resolve_speculative_proposal_payload(
                    &context,
                    &mut speculative_build,
                    payload_id_rx,
                    propose_start,
                    Instant::now(),
                    nullified_view_recovery,
                )
                .await?;

            return Ok((proposal, Some(proposal_return)));
        }

        // Send the proposal parent to execution layer to cover edge cases when
        // we were not asked to verify it and are missing it in the EL. For a
        // matching speculative build, proposal context is attached before this
        // check so replayable builder work can continue while validation runs.
        if !is_genesis_parent {
            self.verify_proposal_parent(context.clone(), parent_epoch_info.epoch(), &parent)
                .await?;
        }

        #[cfg(feature = "bal")]
        if !is_genesis_parent {
            let consensus_context = consensus_context
                .expect("proposal consensus context is constructed immediately above");
            let build_budget = if nullified_view_recovery {
                Duration::ZERO
            } else {
                self.proposal_return_budget
                    .saturating_sub(propose_start.elapsed())
            };
            let build_control = PayloadBuildControl::new(build_budget);
            build_control
                .attach_proposal_context(extra_data.clone(), consensus_context)
                .map_err(|error| {
                    eyre!("failed attaching propose-time speculative proposal context: {error}")
                })?;
            if nullified_view_recovery {
                self.metrics
                    .speculative_payload_builds_started_from_propose_recovery
                    .inc();
                debug!(
                    parent.digest = %parent.digest(),
                    parent.height = %parent.height(),
                    parent.view = %parent_view,
                    round.view = %round.view(),
                    "limiting missing-slot BAL proposal fallback after nullified view recovery"
                );
            }

            let mut speculative_build = self
                .dispatch_speculative_payload_build(
                    &context,
                    &parent,
                    build_control,
                    extra_data,
                    Some(consensus_context),
                    "missing_slot_handle_propose",
                )
                .await
                .wrap_err("failed starting missing-slot speculative BAL payload build")?;
            debug!(
                parent.digest = %parent.digest(),
                parent.height = %parent.height(),
                "started speculative BAL payload build from handle_propose after missing verify slot"
            );
            self.metrics
                .speculative_payload_builds_started_from_propose_fallback
                .inc();

            let (proposal, proposal_return) = self
                .resolve_speculative_proposal_payload(
                    &context,
                    &mut speculative_build,
                    payload_id_rx,
                    propose_start,
                    Instant::now(),
                    nullified_view_recovery,
                )
                .await?;

            return Ok((proposal, Some(proposal_return)));
        }

        // Give the builder only the proposal window that remains when payload
        // construction is requested. This accounts for a late `handle_propose`
        // start instead of resetting the budget at builder entry.
        let build_budget = self
            .proposal_return_budget
            .saturating_sub(propose_start.elapsed());
        let build_control = PayloadBuildControl::new(build_budget);
        build_control
            .attach_proposal_context(
                extra_data.clone(),
                consensus_context
                    .expect("proposal consensus context is constructed immediately above"),
            )
            .expect("new payload build control cannot already have proposal timing");
        let attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context,
            move || {
                self.subblocks
                    .as_ref()
                    .and_then(|s| s.get_subblocks(parent_hash).ok())
                    .unwrap_or_default()
            },
        )
        .with_payload_build_control(build_control);

        // Share the dispatch receiver with the cancel branch so that, if cancellation
        // hits between dispatch send and receiving `payload_id`, the cancel branch can
        // still drain the rx, learn `payload_id`, and cancel the now-registered job.
        let payload_build_start = Instant::now();
        *payload_id_rx = Some(PendingPayloadId::Canonical(
            self.state
                .executor
                .canonicalize_and_build(parent.height(), parent.digest(), attrs)?,
        ));

        let payload_id = payload_id_rx
            .as_mut()
            .expect("just set")
            .recv()
            .await
            .wrap_err("failed receiving payload id")?;

        // Replace the slot with the resolved id so the cancel branch can keep
        // unconditionally waiting for a `PayloadId` and immediately get this job.
        *payload_id_rx = Some(PendingPayloadId::ready(payload_id));

        let payload = self
            .execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, reth_node_builder::PayloadKind::WaitForPending)
            .pace(&context, Duration::from_millis(20))
            .await
            // XXX: this returns Option<Result<_, _>>; drilling into
            // resolve_kind this really seems to resolve to None if no
            // payload_id was found.
            .ok_or_eyre("no payload found under provided id")
            .and_then(|rsp| rsp.map_err(Into::<eyre::Report>::into))
            .wrap_err_with(|| format!("failed getting payload for payload ID `{payload_id}`"))?;

        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_elapsed = payload.validation_work_duration();
        let block_size_bytes = payload.rlp_block_size_bytes();
        let validator_marshal_persist = marshal_persist.estimate(block_size_bytes);
        let proposal_elapsed = propose_start.elapsed();
        // Pace proposal return from the original propose start. Validators still
        // need to repeat replayable build work and marshal persistence, so leave
        // room for those costs before returning the proposal.
        let return_delay = proposal_return_delay(
            self.proposal_return_budget,
            proposal_elapsed,
            payload_validation_elapsed,
            validator_marshal_persist,
            false,
        );
        debug!(
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            validation_time = %display_duration(payload_validation_elapsed),
            validator_marshal_persist = %display_duration(validator_marshal_persist),
            return_time = %display_duration(return_delay),
            block_size_bytes,
            "sleeping before returning proposal"
        );
        let proposal_return_time = context.current() + return_delay;

        let (block, block_access_list) = payload.into_execution_payload();
        let proposal = Block::from_execution_block_with_encoded_size(
            block,
            block_access_list,
            block_size_bytes,
        )
        .wrap_err("payload builder produced an invalid block access list")?;

        Ok((
            proposal,
            Some(ProposalReturn {
                time: proposal_return_time,
                block_size_bytes,
                fast_path_executed_block: None,
            }),
        ))
    }

    #[cfg(feature = "bal")]
    async fn ensure_block_access_list_sidecar(
        &self,
        block: Block,
        round: Round,
        block_view: View,
        block_digest: Digest,
    ) -> eyre::Result<Block> {
        if block.block().header().block_access_list_hash().is_some()
            && block.block_access_list().is_none()
        {
            self.marshal
                .subscribe_by_digest(Some(Round::new(round.epoch(), block_view)), block_digest)
                .await
                .await
                .map_err(|_| eyre!("syncer dropped channel before the BAL sidecar block was sent"))
        } else {
            Ok(block)
        }
    }

    #[cfg(feature = "bal")]
    async fn dispatch_speculative_payload_build<TContext: commonware_runtime::Clock>(
        &self,
        context: &TContext,
        block: &Block,
        build_control: PayloadBuildControl,
        extra_data: Bytes,
        consensus_context: Option<TempoConsensusContext>,
        reason: &'static str,
    ) -> eyre::Result<SpeculativeBuild> {
        self.state
            .speculative_builds
            .track_build_control(build_control.clone())
            .await;
        let block_access_list = block.required_block_access_list().clone();

        let mut epoch_millis = context.current().epoch_millis();
        if epoch_millis <= block.header().timestamp_millis() {
            self.metrics.parent_ahead_of_local_time.inc();
            epoch_millis = block.header().timestamp_millis() + 1;
        }
        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);
        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let parent_hash = block.block_hash();
        let parent_transaction_hashes = block
            .body()
            .transactions()
            .map(|tx| *tx.tx_hash())
            .collect::<Vec<_>>();

        let (trie_handle, cache) = tempo_node::speculative_bal_payload_builder_inputs(
            &self.execution_node,
            block.block(),
            &block_access_list,
        )
        .await?;
        debug!(
            parent.digest = %block.digest(),
            parent.height = %block.height(),
            parent.hash = %block.block_hash(),
            parent.state_root = %block.state_root(),
            reason,
            "prepared private BAL sparse-trie input for speculative payload build"
        );

        let attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context,
            Vec::new,
        )
        .with_payload_build_control(build_control.clone())
        .with_speculative_parent(SpeculativePayloadParent::new(
            block.sealed_header().clone(),
            block_access_list,
        ))
        .with_excluded_pool_transaction_hashes(parent_transaction_hashes)
        .without_executed_block_fast_path();

        let payload_id_rx =
            self.execution_node
                .payload_builder_handle
                .send_new_payload(BuildNewPayload {
                    attributes: attrs,
                    parent_hash,
                    cache,
                    trie_handle: Some(trie_handle),
                });

        Ok(SpeculativeBuild {
            parent_digest: block.digest(),
            parent_height: block.height(),
            build_control,
            payload_id_rx: Some(payload_id_rx),
            payload_id: None,
        })
    }

    #[cfg(feature = "bal")]
    async fn resolve_speculative_proposal_payload<TContext: Pacer>(
        &self,
        context: &TContext,
        speculative_build: &mut SpeculativeBuild,
        payload_id_rx: &mut Option<PendingPayloadId>,
        propose_start: Instant,
        payload_build_start: Instant,
        return_immediately: bool,
    ) -> eyre::Result<(Block, ProposalReturn)> {
        if payload_id_rx.is_none() {
            *payload_id_rx = Some(if let Some(payload_id) = speculative_build.payload_id {
                PendingPayloadId::ready(payload_id)
            } else {
                PendingPayloadId::Speculative(
                    speculative_build
                        .payload_id_rx
                        .take()
                        .ok_or_eyre("speculative payload id receiver was already consumed")?,
                )
            });
        }

        let payload_id = payload_id_rx
            .as_mut()
            .expect("speculative cancel receiver was just installed")
            .recv()
            .await
            .wrap_err("failed receiving speculative payload id")?;
        speculative_build.payload_id = Some(payload_id);
        *payload_id_rx = Some(PendingPayloadId::ready(payload_id));

        let payload = self
            .execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .pace(context, Duration::from_millis(20))
            .await
            .ok_or_eyre("no speculative payload found under provided id")
            .and_then(|rsp| rsp.map_err(Into::<eyre::Report>::into))
            .wrap_err_with(|| {
                format!("failed getting speculative payload for payload ID `{payload_id}`")
            })?;

        let marshal_persist = marshal_persist_estimate();
        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_elapsed = payload.validation_work_duration();
        let block_size_bytes = payload.rlp_block_size_bytes();
        let validator_marshal_persist = marshal_persist.estimate(block_size_bytes);
        let proposal_elapsed = propose_start.elapsed();
        let return_delay = proposal_return_delay(
            self.proposal_return_budget,
            proposal_elapsed,
            payload_validation_elapsed,
            validator_marshal_persist,
            return_immediately,
        );
        debug!(
            %payload_id,
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            validation_time = %display_duration(payload_validation_elapsed),
            validator_marshal_persist = %display_duration(validator_marshal_persist),
            return_time = %display_duration(return_delay),
            return_immediately,
            block_size_bytes,
            "resolved speculative proposal return timing"
        );
        let proposal_return_time = context.current() + return_delay;

        let (block, block_access_list, fast_path_executed_block) =
            payload.into_execution_payload_with_gated_fast_path();
        let proposal = Block::from_execution_block(block, block_access_list)
            .wrap_err("payload builder produced an invalid block access list")?;
        ensure!(
            proposal.parent_digest() == speculative_build.parent_digest,
            "speculative payload parent `{}` did not match requested parent `{}`",
            proposal.parent_digest(),
            speculative_build.parent_digest,
        );
        ensure!(
            proposal.height() == speculative_build.parent_height.next(),
            "speculative payload height `{}` did not extend parent height `{}`",
            proposal.height(),
            speculative_build.parent_height,
        );
        if let Some(expected_context) = speculative_build.build_control.proposal_context() {
            ensure!(
                proposal.header().consensus_context == Some(expected_context.consensus_context()),
                "speculative payload consensus context did not match attached proposal context",
            );
            ensure!(
                proposal.header().extra_data() == expected_context.extra_data(),
                "speculative payload extra data did not match attached proposal context",
            );
        }

        Ok((
            proposal,
            ProposalReturn {
                time: proposal_return_time,
                block_size_bytes,
                fast_path_executed_block,
            },
        ))
    }

    #[cfg(feature = "bal")]
    async fn start_speculative_build<TContext: commonware_runtime::Clock>(
        &self,
        context: &TContext,
        block: &Block,
    ) -> eyre::Result<()> {
        if let Some(consensus_context) = block.header().consensus_context {
            if consensus_context.view > consensus_context.parent_view.saturating_add(1) {
                debug!(
                    parent.digest = %block.digest(),
                    parent.height = %block.height(),
                    block.view = consensus_context.view,
                    parent.view = consensus_context.parent_view,
                    "skipping verify-time speculative BAL payload build after view gap"
                );
                return Ok(());
            }
        }

        let build_control = PayloadBuildControl::new(self.proposal_return_budget);
        let build = self
            .dispatch_speculative_payload_build(
                context,
                block,
                build_control,
                Bytes::default(),
                None,
                "handle_verify",
            )
            .await?;

        self.state
            .speculative_builds
            .replace(self.execution_node.clone(), build)
            .await;
        self.metrics
            .speculative_payload_builds_started_from_verify
            .inc();

        debug!(
            parent.digest = %block.digest(),
            parent.height = %block.height(),
            "started speculative BAL payload build from handle_verify"
        );

        Ok(())
    }

    async fn verify<TContext: Pacer>(
        self,
        context: TContext,
        (parent_view, parent_digest): (View, Digest),
        payload: Digest,
        proposer: PublicKey,
        round: Round,
    ) -> eyre::Result<bool> {
        let block_fetch_start = Instant::now();
        debug!("subscribing to proposal block for verification");
        let block_request = self
            .marshal
            .subscribe_by_digest(Some(round), payload)
            .await
            .map_err(|_| {
                eyre!("marshal actor dropped channel before the block-to-verified was sent")
            });

        let (block, parent) = try_join(
            block_request,
            get_parent(
                &self.execution_node,
                round,
                parent_digest,
                parent_view,
                &self.marshal,
            ),
        )
        .await
        .wrap_err("failed getting required blocks")?;
        debug!(
            elapsed = ?block_fetch_start.elapsed(),
            block.height = %block.height(),
            parent.height = %parent.height(),
            "fetched proposal block and parent for verification"
        );

        // Can only repropose at the end of an epoch.
        //
        // NOTE: fetching block and parent twice (in the case block == parent)
        // seems wasteful, but both run concurrently, should finish almost
        // immediately, and happen very rarely. It's better to optimize for the
        // general case.
        if payload == parent_digest {
            let epoch_info = self
                .epoch_strategy
                .containing(block.height())
                .expect("epoch strategy is for all heights");
            if epoch_info.last() == block.height() && epoch_info.epoch() == round.epoch() {
                if !self.marshal.verified(round, block).await {
                    bail!("marshal actor refused to persist verified re-proposed block");
                }
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        if let Err(reason) = verify_header(
            &block,
            (parent_view, parent_digest),
            round,
            &self.state.dkg_manager,
            &self.epoch_strategy,
            &proposer,
        )
        .await
        {
            warn!(%reason, "header could not be verified; failing block");
            return Ok(false);
        }

        #[cfg(feature = "bal")]
        // Dispatch B+1 before validating B. Reth only snapshots B-1 synchronously; the BAL parent
        // prep and B+1 execution run while B validation is in flight.
        if let Err(error) = self.start_speculative_build(&context, &block).await {
            warn!(
                %error,
                block.digest = %block.digest(),
                block.height = %block.height(),
                "failed starting speculative BAL payload build; continuing validation"
            );
        }

        debug!("validating proposal block against execution layer");
        if let Err(error) = self
            .state
            .executor
            .canonicalize_head(parent.height(), parent.digest())
            .await
        {
            tracing::warn!(
                %error,
                parent.height = %parent.height(),
                parent.digest = %parent.digest(),
                "failed updating canonical head to parent; trying to go on",
            );
        }

        let is_good = match verify_block(
            context,
            round.epoch(),
            &self.epoch_strategy,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &block,
            parent_digest,
            &self.scheme_provider,
        )
        .await
        {
            Ok(is_good) => is_good,
            Err(error) => {
                #[cfg(feature = "bal")]
                self.state
                    .speculative_builds
                    .stop_active(self.execution_node.clone(), "parent_validation_error")
                    .await;
                return Err(error).wrap_err("failed verifying block against execution layer");
            }
        };

        let block_height = block.height();
        let block_digest = block.digest();

        if is_good {
            // Persist the block in the marshal actor and execution layer.
            if !self.marshal.verified(round, block).await {
                bail!("marshal actor refused to persist verified block");
            }

            // FIXME: move this into the certification step?
            self.state
                .executor
                .canonicalize_head(block_height, block_digest)
                .await
                .wrap_err("failed making the verified proposal the head of the canonical chain")?;
        } else {
            #[cfg(feature = "bal")]
            self.state
                .speculative_builds
                .stop_active(self.execution_node.clone(), "parent_validation_failed")
                .await;
        }
        Ok(is_good)
    }
}

impl Inner<Uninit> {
    /// Returns a fully initialized actor using runtime information.
    ///
    /// This includes:
    ///
    /// 1. reading the last finalized digest from the consensus marshaller.
    /// 2. starting the canonical chain engine and storing its handle.
    #[instrument(skip_all, err)]
    async fn into_initialized(
        self,
        dkg_manager: crate::dkg::manager::Mailbox,
    ) -> eyre::Result<Inner<Init>> {
        let initialized = Inner {
            public_key: self.public_key,
            epoch_strategy: self.epoch_strategy,
            proposal_return_budget: self.proposal_return_budget,
            my_mailbox: self.my_mailbox,
            marshal: self.marshal,
            execution_node: self.execution_node,
            #[cfg(feature = "bal")]
            fast_path_payloads: self.fast_path_payloads,
            executor: self.executor.clone(),
            state: Init {
                dkg_manager,
                executor: self.executor.clone(),
                #[cfg(feature = "bal")]
                speculative_builds: SpeculativeBuildRegistry::default(),
            },
            subblocks: self.subblocks,
            scheme_provider: self.scheme_provider,
            metrics: self.metrics,
        };

        Ok(initialized)
    }
}

#[cfg(feature = "bal")]
fn is_nullified_view_recovery(round: Round, parent_view: View) -> bool {
    round.view() > parent_view.next()
}

fn proposal_return_delay(
    proposal_return_budget: Duration,
    proposal_elapsed: Duration,
    payload_validation_elapsed: Duration,
    validator_marshal_persist: Duration,
    return_immediately: bool,
) -> Duration {
    if return_immediately {
        Duration::ZERO
    } else {
        proposal_return_budget
            .saturating_sub(proposal_elapsed)
            .saturating_sub(payload_validation_elapsed)
            .saturating_sub(validator_marshal_persist)
    }
}

/// Marker type to signal that the actor is not fully initialized.
#[derive(Clone, Debug)]
pub(in crate::consensus) struct Uninit(());

/// Carries the runtime initialized state of the application.
#[derive(Clone, Debug)]
struct Init {
    dkg_manager: crate::dkg::manager::Mailbox,
    /// The communication channel to the executor agent.
    executor: crate::executor::Mailbox,
    #[cfg(feature = "bal")]
    speculative_builds: SpeculativeBuildRegistry,
}

/// Verifies `block` given its `parent` against the execution layer.
///
/// Returns whether the block is valid or not. Returns an error if validation
/// was not possible, for example if communication with the execution layer
/// failed.
///
/// Reason the reason for why a block was not valid is communicated as a
/// tracing event.
#[instrument(
    skip_all,
    fields(
        %epoch,
        epoch_length,
        block.parent_digest = %block.parent_digest(),
        block.digest = %block.digest(),
        block.height = %block.height(),
        block.timestamp = block.timestamp(),
        parent.digest = %parent_digest,
    )
)]
async fn verify_block<TContext: Pacer>(
    context: TContext,
    epoch: Epoch,
    epoch_strategy: &FixedEpocher,
    engine: ConsensusEngineHandle<TempoPayloadTypes>,
    block: &Block,
    parent_digest: Digest,
    scheme_provider: &SchemeProvider,
) -> eyre::Result<bool> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");
    if epoch_info.epoch() != epoch {
        info!("block does not belong to this epoch");
        return Ok(false);
    }
    if block.parent_hash() != *parent_digest {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(false);
    }

    // Scheme registration precedes engine creation, so the scheme must exist
    let scheme = scheme_provider
        .scoped(epoch)
        .ok_or_eyre("cannot determine participants in the current epoch")?;

    let validator_set = Some(
        scheme
            .participants()
            .into_iter()
            .map(|p| B256::from_slice(p))
            .collect(),
    );
    let (block, block_access_list) = block.clone().into_parts();
    let execution_data = TempoExecutionData {
        block: Arc::new(block),
        block_access_list,
        validator_set,
    };
    let payload_status = engine
        .new_payload(execution_data)
        .pace(&context, Duration::from_millis(50))
        .await
        .wrap_err("failed sending `new payload` message to execution layer to validate block")?;
    match payload_status.status {
        PayloadStatusEnum::Valid => Ok(true),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(false)
        }
        PayloadStatusEnum::Accepted => {
            bail!(
                "failed validating block because payload was accepted, meaning \
                that this was not actually executed by the execution layer for some reason"
            )
        }
        PayloadStatusEnum::Syncing => {
            bail!(
                "failed validating block because payload is still syncing, \
                this means the parent block was available to the consensus \
                layer but not the execution layer"
            )
        }
    }
}

#[instrument(skip_all, err(Display))]
async fn verify_header(
    block: &Block,
    parent: (View, Digest),
    round: Round,
    dkg_manager: &crate::dkg::manager::Mailbox,
    epoch_strategy: &FixedEpocher,
    proposer: &PublicKey,
) -> eyre::Result<()> {
    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");

    let ctx = block
        .header()
        .consensus_context
        .ok_or_eyre("missing consensus context")?;

    let expected_ctx = TempoConsensusContext {
        epoch: round.epoch().get(),
        view: round.view().get(),
        parent_view: parent.0.get(),
        proposer: crate::utils::public_key_to_tempo_primitive(proposer),
    };

    ensure!(
        ctx == expected_ctx,
        "mismatch in consensus context for block `{}`. expected `{expected_ctx:?}`. got `{ctx:?}`",
        block.digest()
    );

    if epoch_info.last() == block.height() {
        info!(
            "on last block of epoch; verifying that the boundary block \
            contains the correct DKG outcome",
        );
        let our_outcome = dkg_manager
            .get_dkg_outcome(parent.1, block.height().saturating_sub(HeightDelta::new(1)))
            .await
            .wrap_err(
                "failed getting public dkg ceremony outcome; cannot verify end \
                of epoch block",
            )?;
        let block_outcome = OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref())
            .wrap_err(
                "failed decoding extra data header as DKG ceremony \
                outcome; cannot verify end of epoch block",
            )?;
        if our_outcome != block_outcome {
            // Emit the log here so that it's structured. The error would be annoying to read.
            warn!(
                our.epoch = %our_outcome.epoch,
                our.players = ?our_outcome.players(),
                our.next_players = ?our_outcome.next_players(),
                our.sharing = ?our_outcome.sharing(),
                our.is_next_full_dkg = ?our_outcome.is_next_full_dkg,
                block.epoch = %block_outcome.epoch,
                block.players = ?block_outcome.players(),
                block.next_players = ?block_outcome.next_players(),
                block.sharing = ?block_outcome.sharing(),
                block.is_next_full_dkg = ?block_outcome.is_next_full_dkg,
                "our public dkg outcome does not match what's stored \
                in the block",
            );
            return Err(eyre!(
                "our public dkg outcome does not match what's \
                stored in the block header extra_data field; they must \
                match so that the end-of-block is valid",
            ));
        }
    } else if !block.header().extra_data().is_empty() {
        let bytes = block.header().extra_data().to_vec();
        let dealer = dkg_manager
            .verify_dealer_log(round.epoch(), bytes)
            .await
            .wrap_err("failed request to verify DKG dealing")?;
        ensure!(
            &dealer == proposer,
            "proposer `{proposer}` is not the dealer `{dealer}` of the dealing \
            in the block",
        );
    }

    Ok(())
}

async fn get_parent(
    execution_node: &TempoFullNode,
    round: Round,
    parent_digest: Digest,
    parent_view: View,
    marshal: &crate::alias::marshal::Mailbox,
) -> eyre::Result<Block> {
    if let Some(parent) = execution_node
        .provider
        .find_block_by_hash(parent_digest.0, BlockSource::Any)
        .wrap_err_with(|| {
            format!("failed querying execution layer for parent block `{parent_digest}`")
        })?
    {
        // EL database reads do not include commonware sidecars.
        Ok(Block::from_execution_block_unchecked(parent.seal(), None))
    } else {
        marshal
            .subscribe_by_digest(Some(Round::new(round.epoch(), parent_view)), parent_digest)
            .await
            .await
            .map_err(|_| eyre!("syncer dropped channel before the parent block was sent"))
    }
}

#[derive(Clone)]
struct Metrics {
    parent_ahead_of_local_time: Counter,
    #[cfg(feature = "bal")]
    speculative_payload_builds_started_from_verify: Counter,
    #[cfg(feature = "bal")]
    speculative_payload_builds_reused_by_propose: Counter,
    #[cfg(feature = "bal")]
    speculative_payload_builds_started_from_propose_fallback: Counter,
    #[cfg(feature = "bal")]
    speculative_payload_builds_started_from_propose_recovery: Counter,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let parent_ahead_of_local_time = Counter::default();
        context.register(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time",
            parent_ahead_of_local_time.clone(),
        );
        #[cfg(feature = "bal")]
        let speculative_payload_builds_started_from_verify = {
            let counter = Counter::default();
            context.register(
                "speculative_payload_builds_started_from_verify",
                "number of BAL speculative payload builds started from block verification",
                counter.clone(),
            );
            counter
        };
        #[cfg(feature = "bal")]
        let speculative_payload_builds_reused_by_propose = {
            let counter = Counter::default();
            context.register(
                "speculative_payload_builds_reused_by_propose",
                "number of BAL speculative payload builds started by verification and reused by proposal",
                counter.clone(),
            );
            counter
        };
        #[cfg(feature = "bal")]
        let speculative_payload_builds_started_from_propose_fallback = {
            let counter = Counter::default();
            context.register(
                "speculative_payload_builds_started_from_propose_fallback",
                "number of BAL speculative payload builds started from proposal because no verify-started build was available",
                counter.clone(),
            );
            counter
        };
        #[cfg(feature = "bal")]
        let speculative_payload_builds_started_from_propose_recovery = {
            let counter = Counter::default();
            context.register(
                "speculative_payload_builds_started_from_propose_recovery",
                "number of BAL proposal fallback builds limited after nullified view recovery",
                counter.clone(),
            );
            counter
        };

        Self {
            parent_ahead_of_local_time,
            #[cfg(feature = "bal")]
            speculative_payload_builds_started_from_verify,
            #[cfg(feature = "bal")]
            speculative_payload_builds_reused_by_propose,
            #[cfg(feature = "bal")]
            speculative_payload_builds_started_from_propose_fallback,
            #[cfg(feature = "bal")]
            speculative_payload_builds_started_from_propose_recovery,
        }
    }
}

#[cfg(all(test, feature = "bal"))]
mod tests {
    use super::*;

    #[test]
    fn nullified_view_recovery_detects_view_gap_after_parent() {
        let parent_view = View::new(27);

        assert!(!is_nullified_view_recovery(
            Round::new(Epoch::new(0), View::new(28)),
            parent_view
        ));
        assert!(is_nullified_view_recovery(
            Round::new(Epoch::new(0), View::new(29)),
            parent_view
        ));
        assert!(is_nullified_view_recovery(
            Round::new(Epoch::new(0), View::new(270)),
            parent_view
        ));
    }

    #[test]
    fn recovery_proposal_return_delay_is_zero() {
        assert_eq!(
            proposal_return_delay(
                Duration::from_millis(500),
                Duration::from_millis(40),
                Duration::from_millis(30),
                Duration::from_millis(20),
                true,
            ),
            Duration::ZERO
        );
        assert_eq!(
            proposal_return_delay(
                Duration::from_millis(500),
                Duration::from_millis(40),
                Duration::from_millis(30),
                Duration::from_millis(20),
                false,
            ),
            Duration::from_millis(410)
        );
    }
}
