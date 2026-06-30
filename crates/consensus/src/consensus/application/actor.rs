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
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use alloy_consensus::BlockHeader;
use alloy_eips::Encodable2718;
use alloy_primitives::{B256, Bytes, keccak256};
use commonware_codec::{Encode as _, EncodeSize as _, ReadExt as _};
use commonware_consensus::{
    Heightable as _,
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

use commonware_utils::SystemTimeExt;
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::{StreamExt as _, channel::mpsc, future::try_join};
use rand_08::{CryptoRng, Rng};
use reth_node_builder::{BuiltPayload, ConsensusEngineHandle};
use reth_primitives_traits::BlockBody as _;
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};
use tempo_telemetry_util::display_duration;

use reth_provider::{BlockHashReader as _, BlockReader as _, BlockSource};
use tempo_payload_types::{
    TempoBuiltPayload, TempoPayloadAttributes, ValidationLatencyEstimator,
    ValidationLatencyWorkload, marshal_persist_estimate, observe_marshal_persist,
};
use tempo_primitives::TempoConsensusContext;
use tracing::{Level, debug, info, info_span, instrument, trace, warn};

use super::{
    Mailbox,
    ingress::{Broadcast, Genesis, Message, Propose, Verify},
};
use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    ssmr::{
        self, ProposalStream, SsmrCompleteStream, SsmrStreamSnapshot, SsmrTranscript, StreamKey,
    },
    subblocks,
    utils::OptionFuture,
};

pub(in crate::consensus) struct Actor<TContext, TState = Uninit> {
    context: ContextCell<TContext>,
    mailbox: mpsc::Receiver<Message>,

    inner: Inner<TState>,
}

struct BuildProposalArgs {
    propose_start: Instant,
    parent_view: View,
    parent_digest: Digest,
    round: Round,
    leader: PublicKey,
}

const SSMR_SNAPSHOT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SSMR_WAIT_PROGRESS_LOG_INTERVAL: Duration = Duration::from_millis(250);
const BLOCK_SUBSCRIBE_EL_POLL_INTERVAL: Duration = Duration::from_millis(10);
const SSMR_STATIC_BUILD_BUDGET: Duration = Duration::from_millis(400);

struct ProposalReturn {
    /// Earliest time the built proposal may be returned to consensus.
    ///
    /// After the proposal is persisted locally, the actor sleeps until this time
    /// so early builds still respect the proposal pacing budget.
    return_at: SystemTime,
    /// Approximate encoded proposal size used for marshal-persist pacing.
    ///
    /// This is a reasonably close estimate derived during payload building, not the exact final
    /// encoded block size.
    block_size_estimate_bytes: usize,
}

struct SsmrStreamRetirement {
    ssmr: Option<ssmr::Mailbox>,
    key: Option<StreamKey>,
}

impl SsmrStreamRetirement {
    fn retire_now(&mut self) {
        if let Some(key) = self.key.take()
            && let Some(ssmr) = &self.ssmr
        {
            ssmr.retire_stream(key);
        }
    }
}

impl Drop for SsmrStreamRetirement {
    fn drop(&mut self) {
        self.retire_now();
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
        + commonware_runtime::Clock
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

                my_mailbox,
                marshal: config.marshal,

                execution_node: config.execution_node,
                executor: config.executor,
                proposal_budget: config.proposal_budget,

                subblocks: config.subblocks,
                ssmr: config.ssmr,

                scheme_provider: config.scheme_provider,
                validation_latency_estimator: Default::default(),

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
        + commonware_runtime::Clock
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

    my_mailbox: Mailbox,

    marshal: crate::alias::marshal::Mailbox,

    execution_node: Arc<TempoFullNode>,
    executor: crate::executor::Mailbox,
    proposal_budget: crate::consensus::proposal_budget::ProposalBudgetHandle,
    subblocks: Option<subblocks::Mailbox>,
    ssmr: Option<ssmr::Mailbox>,
    scheme_provider: SchemeProvider,
    validation_latency_estimator: Arc<Mutex<ValidationLatencyEstimator>>,

    metrics: Metrics,

    state: TState,
}

impl<TState> Inner<TState> {
    async fn ssmr_stream_snapshot(&self, block: &Block) -> Option<SsmrStreamSnapshot> {
        let key = ssmr_stream_key_for_block(block)?;
        self.ssmr.as_ref()?.get_stream_snapshot(key).await
    }

    fn evict_ssmr_streams_through_height(&self, height: Height) {
        if let Some(ssmr) = &self.ssmr {
            ssmr.evict_streams_through_height(height.get());
        }
    }

    fn retire_ssmr_stream_on_drop(&self, block: &Block) -> SsmrStreamRetirement {
        SsmrStreamRetirement {
            ssmr: self.ssmr.clone(),
            key: ssmr_stream_key_for_block(block),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SsmrWaitSnapshotState {
    has_stream: bool,
    started: bool,
    end_received: bool,
    received_shards: u64,
    expected_shards: Option<u64>,
    received_transactions: u64,
    expected_transactions: Option<u64>,
    buffered_bytes: usize,
    next_missing_shard: Option<u64>,
    next_execution_shard: u64,
    optimistic_execution_started: bool,
    optimistic_execution_finalizing: bool,
    optimistic_execution_failed: bool,
    optimistic_payload_ready: bool,
}

impl SsmrWaitSnapshotState {
    fn from_snapshot(snapshot: Option<&SsmrStreamSnapshot>) -> Self {
        let Some(snapshot) = snapshot else {
            return Self {
                has_stream: false,
                started: false,
                end_received: false,
                received_shards: 0,
                expected_shards: None,
                received_transactions: 0,
                expected_transactions: None,
                buffered_bytes: 0,
                next_missing_shard: None,
                next_execution_shard: 0,
                optimistic_execution_started: false,
                optimistic_execution_finalizing: false,
                optimistic_execution_failed: false,
                optimistic_payload_ready: false,
            };
        };

        Self {
            has_stream: true,
            started: snapshot.started,
            end_received: snapshot.end_received,
            received_shards: snapshot.received_shards,
            expected_shards: snapshot.expected_shards,
            received_transactions: snapshot.received_transactions,
            expected_transactions: snapshot.expected_transactions,
            buffered_bytes: snapshot.buffered_bytes,
            next_missing_shard: snapshot.next_missing_shard,
            next_execution_shard: snapshot.next_execution_shard,
            optimistic_execution_started: snapshot.optimistic_execution_started,
            optimistic_execution_finalizing: snapshot.optimistic_execution_finalizing,
            optimistic_execution_failed: snapshot.optimistic_execution_failed,
            optimistic_payload_ready: snapshot.optimistic_payload_ready,
        }
    }
}

impl Inner<Init> {
    async fn wait_for_started_ssmr_stream<TContext>(
        &self,
        context: &TContext,
        block: &Block,
        mut snapshot: Option<SsmrStreamSnapshot>,
    ) -> SsmrCompleteStream
    where
        TContext: commonware_runtime::Clock,
    {
        let wait_start = Instant::now();
        let mut last_log_state = None;
        let mut last_log_at = Instant::now();
        loop {
            let log_state = SsmrWaitSnapshotState::from_snapshot(snapshot.as_ref());
            if last_log_state != Some(log_state)
                || last_log_at.elapsed() >= SSMR_WAIT_PROGRESS_LOG_INTERVAL
            {
                debug!(
                    block.digest = %block.digest(),
                    block.height = %block.height(),
                    wait_elapsed = ?wait_start.elapsed(),
                    stream.has_stream = log_state.has_stream,
                    stream.started = log_state.started,
                    stream.end_received = log_state.end_received,
                    stream.received_shards = log_state.received_shards,
                    stream.expected_shards = ?log_state.expected_shards,
                    stream.received_transactions = log_state.received_transactions,
                    stream.expected_transactions = ?log_state.expected_transactions,
                    stream.buffered_bytes = log_state.buffered_bytes,
                    stream.next_missing_shard = ?log_state.next_missing_shard,
                    stream.next_execution_shard = log_state.next_execution_shard,
                    optimistic.started = log_state.optimistic_execution_started,
                    optimistic.finalizing = log_state.optimistic_execution_finalizing,
                    optimistic.failed = log_state.optimistic_execution_failed,
                    optimistic.ready = log_state.optimistic_payload_ready,
                    "waiting for SSMR stream"
                );
                last_log_state = Some(log_state);
                last_log_at = Instant::now();
            }

            if let Some(current) = snapshot.take() {
                if let Some(stream) = current.complete.as_ref()
                    && stream.optimistic_payload.is_none()
                {
                    trace!(
                        block.digest = %block.digest(),
                        block.height = %block.height(),
                        optimistic.finalizing = stream.optimistic_execution_finalizing,
                        optimistic.failed = stream.optimistic_execution_failed,
                        "waiting for SSMR optimistic payload"
                    );
                }
                if !ssmr_snapshot_waiting_for_optimistic_payload(&current)
                    && let Some(stream) = current.complete
                {
                    debug!(
                        block.digest = %block.digest(),
                        block.height = %block.height(),
                        wait_elapsed = ?wait_start.elapsed(),
                        stream.received_shards = log_state.received_shards,
                        stream.expected_shards = ?log_state.expected_shards,
                        stream.received_transactions = log_state.received_transactions,
                        stream.expected_transactions = ?log_state.expected_transactions,
                        stream.next_execution_shard = log_state.next_execution_shard,
                        "SSMR stream ready for proposal verification"
                    );
                    return stream;
                }
            }

            context.sleep(SSMR_SNAPSHOT_POLL_INTERVAL).await;
            snapshot = self.ssmr_stream_snapshot(block).await;
        }
    }

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

        let proposal_block = {
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
                // `marshal.get_verified` can take a long time if marshal is busy
                // persisting the parent block, so we race it with payload building to
                // avoid delaying the usual proposal path. If it finds a verified block,
                // we always prefer that block and skip the newly built proposal,
                // even when payload construction finishes first.
                let already_verified = OptionFuture::some(self.marshal.get_verified(round));
                futures::pin_mut!(already_verified);

                let mut proposal = Box::pin(self.clone().propose(
                    context.clone(),
                    BuildProposalArgs {
                        propose_start,
                        parent_view,
                        parent_digest,
                        round,
                        leader,
                    },
                ));

                let proposal_result = tokio::select! {
                    biased;

                    Some(block) = &mut already_verified => {
                        debug!("skipping proposal: verified block already exists for round on restart");
                        Ok((block, None))
                    },

                    res = &mut proposal => {
                        res.wrap_err("failed creating a proposal")
                    },
                };

                // already_verified blocks are always preferred, even if
                // building a block failed.
                let (block, proposal_return) = if already_verified.is_some()
                    && let Some(block) = already_verified.await
                {
                    debug!("skipping proposal: verified block already exists for round on restart");
                    (block, None)
                } else {
                    proposal_result?
                };

                if let Some(proposal_return) = proposal_return {
                    let persist_start = Instant::now();
                    if !self.marshal.proposed(round, block.clone()).await {
                        bail!("marshal actor rejected persisting proposal");
                    }
                    observe_marshal_persist(
                        proposal_return.block_size_estimate_bytes,
                        persist_start.elapsed(),
                    );

                    // Keep waiting for the remaining return time, if there's anything left after building the block.
                    context.sleep_until(proposal_return.return_at).await;
                }

                eyre::Ok(block)
            });

            tokio::select! {
                () = response.closed() => {
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

        let proposal_digest = proposal_block.digest();
        info!(
            proposal.digest = %proposal_digest,
            "constructed proposal",
        );
        self.evict_ssmr_streams_through_height(proposal_block.height());

        self.proposal_budget
            .record_proposal_return(round, proposal_digest);
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
    async fn handle_verify<TContext: Pacer + commonware_runtime::Clock>(
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
        let VerifyResult {
            result,
            block,
            parent,
        } = select!(
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
        // Keep large block drops out of the pre-response path.
        drop((block, parent));

        Ok(())
    }

    async fn propose<TContext: Pacer>(
        self,
        context: TContext,
        args: BuildProposalArgs,
    ) -> eyre::Result<(Block, Option<ProposalReturn>)> {
        let BuildProposalArgs {
            propose_start,
            parent_view,
            parent_digest,
            round,
            leader,
        } = args;

        let parent = subscribe(
            &context,
            &self.execution_node,
            Round::new(round.epoch(), parent_view),
            parent_digest,
            &self.marshal,
            BlockResolution::Any,
        )
        .await?;

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
            // If the header has a block access list hash but the block itself doesn't
            // it likely means that the block was fetched from reth database and we need to
            // additionally fetch the BAL from commonware.
            let parent = if parent.block().header().block_access_list_hash().is_some()
                && parent.block_access_list().is_none()
            {
                self.marshal
                    .subscribe_by_digest(
                        Some(Round::new(round.epoch(), parent_view)),
                        parent_digest,
                    )
                    .await
                    .await
                    .map_err(|_| eyre!("syncer dropped channel before the parent block was sent"))?
            } else {
                parent
            };
            if !self.marshal.verified(round, parent.clone()).await {
                bail!("marshal rejected re-proposed boundary block");
            }
            info!("parent is last height of epoch; re-proposing parent");
            return Ok((parent, None));
        }

        let is_genesis_parent = parent.height().is_zero()
            || parent_epoch_info.last() == parent.height()
                && parent_epoch_info.epoch().next() == round.epoch();

        // Send the proposal parent to execution layer to cover edge cases when
        // we were not asked to to verify it (and hence are missing it in the
        // EL).
        //
        // If proposing the first block of an epoch, its parent
        // (genesis/boundary block) must exist and be finalized, so we can skip
        // it.
        if !is_genesis_parent
            && verify_block(
                context.clone(),
                parent_epoch_info.epoch(),
                &self.epoch_strategy,
                self.execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .clone(),
                &parent,
                // It is safe to not verify the parent of the parent because this block is already notarized.
                parent.parent_digest(),
                &self.scheme_provider,
                None,
            )
            .await
            .wrap_err("failed verifying block against execution layer")?
            .is_none()
        {
            bail!("the proposal parent block is not valid");
        }

        // Query DKG manager for ceremony data before building payload
        // This data will be passed to the payload builder via attributes
        let extra_data = if parent_epoch_info.last() == parent.height().next()
            && parent_epoch_info.epoch() == round.epoch()
        {
            // At epoch boundary: include public ceremony outcome
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
            outcome.encode().into()
        } else {
            // Regular block: try to include DKG dealer log.
            match self.state.dkg_manager.get_dealer_log(round.epoch()).await {
                Err(error) => {
                    warn!(
                        %error,
                        "failed getting signed dealer log for current epoch \
                        because actor dropped response channel",
                    );
                    Bytes::default()
                }
                Ok(None) => Bytes::default(),
                Ok(Some(log)) => {
                    info!(
                        "received signed dealer log; will include in payload \
                        builder attributes"
                    );
                    log.encode().into()
                }
            }
        };

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

        let consensus_context = TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent_view.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&leader),
        };

        let parent_hash = parent.block_hash();
        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let marshal_persist = marshal_persist_estimate();
        let use_static_ssmr_budget = self.ssmr.is_some();
        let proposal_pacing = self.proposal_budget.pacing(false);
        // Give the builder only the proposal window that remains when payload
        // construction is requested. This accounts for a late `handle_propose`
        // start instead of resetting the budget at builder entry.
        let build_budget = if use_static_ssmr_budget {
            SSMR_STATIC_BUILD_BUDGET.saturating_sub(propose_start.elapsed())
        } else {
            proposal_pacing
                .proposal_return_budget
                .saturating_sub(propose_start.elapsed())
        };
        let validation_latency_estimate = if use_static_ssmr_budget {
            None
        } else {
            self.validation_latency_estimator
                .lock()
                .ok()
                .and_then(|estimator| estimator.estimate())
        };
        let post_return_tail_budget = if use_static_ssmr_budget {
            Some(Duration::ZERO)
        } else {
            proposal_pacing.post_return_tail
        };
        let block_gas_limit = parent.header().gas_limit();
        let chain_spec = self.execution_node.chain_spec();
        let shared_gas_limit = chain_spec.shared_gas_limit_at(timestamp, block_gas_limit);
        let general_gas_limit =
            chain_spec.general_gas_limit_at(timestamp, block_gas_limit, shared_gas_limit);
        let ssmr_stream = self.ssmr.as_ref().map(|ssmr| {
            let shard_target_bytes = ssmr.shard_target_bytes();
            let stream_key = StreamKey::new(
                parent_digest.0,
                parent.height().next().get(),
                timestamp,
                timestamp_millis_part,
                consensus_context,
            );
            let stream = ProposalStream {
                stream_key,
                parent_height: parent.height().get(),
                extra_data: extra_data.clone(),
                gas_limit: block_gas_limit,
                general_gas_limit,
                shared_gas_limit,
                shard_target_bytes: shard_target_bytes as u64,
                bal_enabled: cfg!(feature = "bal"),
            };
            (ssmr.builder_sink(stream), shard_target_bytes)
        });
        let subblocks = self.subblocks.clone();
        let mut attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            Some(consensus_context),
            move || {
                subblocks
                    .as_ref()
                    .and_then(|s| s.get_subblocks(parent_hash).ok())
                    .unwrap_or_default()
            },
        )
        .with_payload_build_budget(build_budget)
        .with_validation_latency_estimate(validation_latency_estimate)
        .with_post_return_tail_budget(post_return_tail_budget);
        if let Some((sink, shard_target_bytes)) = ssmr_stream {
            attrs = attrs.with_ssmr_builder_sink(sink, shard_target_bytes);
        }

        // Subscribe to the payload build. The executor owns the build job
        // and runs it to completion; dropping the receiver (for example
        // because the proposal was cancelled) tells it that the payload is
        // no longer wanted.
        let payload_build_start = Instant::now();
        let payload = self
            .state
            .executor
            .canonicalize_and_build(parent.height(), parent.digest(), attrs)?
            .await
            .wrap_err(
                "executor dropped the payload channel: the build failed (the \
                executor logs the cause) or the executor shut down",
            )?;

        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_work_elapsed = payload.validation_work_duration();
        let validation_latency_elapsed = payload.validation_latency_duration();
        let execution_block_rlp_size_estimate_bytes = payload.execution_block_size_estimate();
        let (block, block_access_list, execution_block_encoded) =
            payload.into_consensus_execution_payload();
        let block_access_list_size_bytes = block_access_list
            .as_ref()
            .map_or(0, |block_access_list| block_access_list.encode_size());
        let proposal = Block::from_execution_block_with_encoded_cache(
            block,
            block_access_list,
            execution_block_encoded,
        )
        .wrap_err("payload builder produced an invalid block access list")?;
        let block_size_estimate_bytes =
            execution_block_rlp_size_estimate_bytes + block_access_list_size_bytes;
        let validator_marshal_persist = marshal_persist.estimate(block_size_estimate_bytes);
        let proposal_elapsed = propose_start.elapsed();
        // Pace proposal return from the original propose start. Validators still
        // need the reserved post-return tail before returning the proposal.
        // Before SSMR has learned a tail, keep the conservative validator-work
        // reserve used by the normal proposal path.
        let mut return_delay = if use_static_ssmr_budget {
            SSMR_STATIC_BUILD_BUDGET.saturating_sub(proposal_elapsed)
        } else {
            proposal_pacing
                .proposal_return_budget
                .saturating_sub(proposal_elapsed)
        };
        if !use_static_ssmr_budget && proposal_pacing.post_return_tail.is_none() {
            return_delay = return_delay
                .saturating_sub(validation_latency_elapsed)
                .saturating_sub(validator_marshal_persist);
        }
        debug!(
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            payload_validation_work = %display_duration(payload_validation_work_elapsed),
            validation_latency_time = %display_duration(validation_latency_elapsed),
            validator_marshal_persist = %display_duration(validator_marshal_persist),
            post_return_tail_budget = ?post_return_tail_budget,
            return_time = %display_duration(return_delay),
            execution_block_rlp_size_estimate_bytes,
            block_size_estimate_bytes,
            "sleeping before returning proposal"
        );
        let return_at = context.current() + return_delay;

        Ok((
            proposal,
            Some(ProposalReturn {
                return_at,
                block_size_estimate_bytes,
            }),
        ))
    }

    async fn verify<TContext: Pacer>(
        self,
        context: TContext,
        (parent_view, parent_digest): (View, Digest),
        payload: Digest,
        proposer: PublicKey,
        round: Round,
    ) -> eyre::Result<VerifyResult> {
        let (mut block, parent) = try_join(
            subscribe(
                &context,
                &self.execution_node,
                round,
                payload,
                &self.marshal,
                BlockResolution::Any,
            ),
            subscribe(
                &context,
                &self.execution_node,
                Round::new(round.epoch(), parent_view),
                parent_digest,
                &self.marshal,
                BlockResolution::Any,
            ),
        )
        .await
        .wrap_err("failed getting required blocks")?;
        let mut ssmr_retirement = self.retire_ssmr_stream_on_drop(&block);

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
                ssmr_retirement.retire_now();
                if !self.marshal.verified(round, block).await {
                    bail!("marshal actor refused to persist verified re-proposed block");
                }
                return Ok(VerifyResult {
                    result: true,
                    block: None,
                    parent: Some(parent),
                });
            } else {
                ssmr_retirement.retire_now();
                return Ok(VerifyResult {
                    result: false,
                    block: Some(block),
                    parent: Some(parent),
                });
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
            ssmr_retirement.retire_now();
            return Ok(VerifyResult {
                result: false,
                block: Some(block),
                parent: Some(parent),
            });
        }

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

        let mut optimistic_payload = None;
        let mut ssmr_fallback_validation = false;
        if self.ssmr.is_some() {
            let snapshot = self.ssmr_stream_snapshot(&block).await;
            let stream = self
                .wait_for_started_ssmr_stream(&context, &block, snapshot)
                .await;
            match reconcile_ssmr_transcript(&block, &stream.transcript) {
                Ok(true) => {
                    self.metrics.ssmr_final_reconciliations.inc();
                    match stream.optimistic_payload {
                        Some(payload) => {
                            match reconcile_ssmr_optimistic_payload(&block, &payload) {
                                Ok(()) => {
                                    if block.missing_required_sidecars() {
                                        block = block_from_ssmr_optimistic_payload(&payload)?;
                                    }
                                    optimistic_payload = Some(payload);
                                    debug!(
                                        block.digest = %block.digest(),
                                        block.height = %block.height(),
                                        "final proposal matches complete SSMR transcript and optimistic artifact"
                                    );
                                }
                                Err(mismatch) => {
                                    ssmr_fallback_validation = true;
                                    self.metrics.ssmr_fallback_validation_count.inc();
                                    log_ssmr_optimistic_payload_mismatch(
                                        &block, &payload, &mismatch,
                                    );
                                }
                            }
                        }
                        None => unreachable!("SSMR verify waits until optimistic payload is ready"),
                    }
                }
                Ok(false) => {
                    ssmr_fallback_validation = true;
                    self.metrics.ssmr_final_reconciliation_mismatches.inc();
                    self.metrics.ssmr_fallback_validation_count.inc();
                    warn!(
                        block.digest = %block.digest(),
                        block.height = %block.height(),
                        "complete SSMR transcript did not match final proposal; falling back to normal validation"
                    );
                }
                Err(error) => {
                    ssmr_fallback_validation = true;
                    self.metrics.ssmr_final_reconciliation_mismatches.inc();
                    self.metrics.ssmr_fallback_validation_count.inc();
                    warn!(
                        %error,
                        block.digest = %block.digest(),
                        block.height = %block.height(),
                        "failed reconciling SSMR transcript; falling back to normal validation"
                    );
                }
            }
        } else {
            ssmr_fallback_validation = true;
            self.metrics.ssmr_missing_shards_at_proposal.inc();
            self.metrics.ssmr_fallback_validation_count.inc();
            debug!(
                block.digest = %block.digest(),
                block.height = %block.height(),
                "no SSMR stream for proposal; using normal validation"
            );
        }
        if ssmr_fallback_validation {
            ssmr_retirement.retire_now();
        }
        if block.missing_required_sidecars() {
            debug!(
                block.digest = %block.digest(),
                block.height = %block.height(),
                "proposal block is missing required consensus sidecars; waiting for marshal block"
            );
            block = subscribe(
                &context,
                &self.execution_node,
                round,
                payload,
                &self.marshal,
                BlockResolution::RequireConsensusSidecars,
            )
            .await?;
        }
        let optimistic_validation_observation = optimistic_payload.as_ref().map(|payload| {
            (
                ValidationLatencyWorkload::new(
                    payload.block().gas_used(),
                    payload.block().body().transaction_count(),
                ),
                payload.validation_work_duration(),
            )
        });
        let validation_duration = verify_block(
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
            optimistic_payload,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?;
        ssmr_retirement.retire_now();
        if let Some(duration) = validation_duration
            && let Ok(mut estimator) = self.validation_latency_estimator.lock()
        {
            let (workload, duration) = optimistic_validation_observation.unwrap_or_else(|| {
                (
                    ValidationLatencyWorkload::new(
                        block.block().gas_used(),
                        block.block().body().transaction_count(),
                    ),
                    duration,
                )
            });
            estimator.observe(block.height().get(), workload, duration);
        }
        let is_good = validation_duration.is_some();

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

            return Ok(VerifyResult {
                result: true,
                block: None,
                parent: Some(parent),
            });
        }

        Ok(VerifyResult {
            result: false,
            block: Some(block),
            parent: Some(parent),
        })
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
            my_mailbox: self.my_mailbox,
            marshal: self.marshal,
            execution_node: self.execution_node,
            executor: self.executor.clone(),
            proposal_budget: self.proposal_budget,
            state: Init {
                dkg_manager,
                executor: self.executor.clone(),
            },
            subblocks: self.subblocks,
            ssmr: self.ssmr,
            scheme_provider: self.scheme_provider,
            validation_latency_estimator: self.validation_latency_estimator,
            metrics: self.metrics,
        };

        Ok(initialized)
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
}

struct VerifyResult {
    /// Whether consensus should accept the verified proposal.
    ///
    /// This is the value sent through `Verify::response`: `true` accepts the
    /// proposal, `false` rejects it.
    result: bool,
    /// The proposed block when it was not moved into the verified marshal state.
    block: Option<Block>,
    /// The parent block fetched to verify the proposal.
    parent: Option<Block>,
}

/// Verifies `block` given its `parent` against the execution layer.
///
/// Returns EL validation duration when validation reached the execution layer
/// and succeeded, or `None` if the block is invalid. Returns an error if
/// validation was not possible, for example if communication with the execution
/// layer failed.
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
#[allow(clippy::too_many_arguments)]
async fn verify_block<TContext: Pacer>(
    context: TContext,
    epoch: Epoch,
    epoch_strategy: &FixedEpocher,
    engine: ConsensusEngineHandle<TempoPayloadTypes>,
    block: &Block,
    parent_digest: Digest,
    scheme_provider: &SchemeProvider,
    optimistic_payload: Option<TempoBuiltPayload>,
) -> eyre::Result<Option<Duration>> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");
    if epoch_info.epoch() != epoch {
        info!("block does not belong to this epoch");
        return Ok(None);
    }
    if block.parent_hash() != *parent_digest {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(None);
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
    let execution_data = TempoExecutionData {
        block: block.execution_block().clone(),
        block_access_list: block.block_access_list().cloned(),
        validator_set,
        executed_block: optimistic_payload.and_then(|payload| payload.executed_block()),
    };
    let validation_start = Instant::now();
    let payload_status = engine
        .new_payload(execution_data)
        .pace(&context, Duration::from_millis(50))
        .await
        .wrap_err("failed sending `new payload` message to execution layer to validate block")?;
    match payload_status.status {
        PayloadStatusEnum::Valid => Ok(Some(validation_start.elapsed())),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(None)
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

fn ssmr_stream_key_for_block(block: &Block) -> Option<StreamKey> {
    let header = block.header();
    Some(StreamKey::new(
        block.parent_digest().0,
        block.height().get(),
        header.timestamp(),
        header.timestamp_millis_part,
        header.consensus_context?,
    ))
}

fn reconcile_ssmr_transcript(block: &Block, transcript: &SsmrTranscript) -> eyre::Result<bool> {
    if Some(transcript.key()) != ssmr_stream_key_for_block(block) {
        return Ok(false);
    }

    let streamed_transactions = transcript
        .ordered_transactions()
        .wrap_err("SSMR transcript was incomplete")?;
    let block_transactions = &block.block().body().transactions;
    if streamed_transactions.len() != block_transactions.len() {
        return Ok(false);
    }

    let mut encoded = Vec::new();
    for (streamed, transaction) in streamed_transactions.iter().zip(block_transactions) {
        encoded.clear();
        transaction.encode_2718(&mut encoded);
        if streamed.as_ref() != encoded.as_slice() {
            return Ok(false);
        }
    }

    Ok(true)
}

fn reconcile_ssmr_optimistic_payload(
    block: &Block,
    payload: &TempoBuiltPayload,
) -> Result<(), SsmrOptimisticPayloadMismatch> {
    if payload.block() != block.block() {
        return Err(SsmrOptimisticPayloadMismatch::ExecutionBlock);
    }
    if let Some(block_access_list) = block.block_access_list()
        && payload.block_access_list() != Some(block_access_list)
    {
        return Err(SsmrOptimisticPayloadMismatch::BlockAccessList);
    }
    Ok(())
}

fn log_ssmr_optimistic_payload_mismatch(
    block: &Block,
    payload: &TempoBuiltPayload,
    mismatch: &SsmrOptimisticPayloadMismatch,
) {
    let proposal = block.block();
    let optimistic = payload.block();
    let proposal_header = proposal.header();
    let optimistic_header = optimistic.header();
    let proposal_block_access_list = block.block_access_list();
    let optimistic_block_access_list = payload.block_access_list();
    let proposal_block_access_list_hash =
        proposal_block_access_list.map(|bytes| keccak256(bytes.as_ref()));
    let optimistic_block_access_list_hash =
        optimistic_block_access_list.map(|bytes| keccak256(bytes.as_ref()));

    warn!(
        ?mismatch,
        block.digest = %block.digest(),
        block.height = %block.height(),
        proposal.has_required_sidecars = !block.missing_required_sidecars(),
        proposal.hash = %proposal.hash(),
        optimistic.hash = %optimistic.hash(),
        proposal.tx_count = proposal.body().transaction_count(),
        optimistic.tx_count = optimistic.body().transaction_count(),
        proposal.gas_used = proposal_header.gas_used(),
        optimistic.gas_used = optimistic_header.gas_used(),
        proposal.state_root = %proposal_header.state_root(),
        optimistic.state_root = %optimistic_header.state_root(),
        proposal.receipts_root = %proposal_header.receipts_root(),
        optimistic.receipts_root = %optimistic_header.receipts_root(),
        proposal.transactions_root = %proposal_header.transactions_root(),
        optimistic.transactions_root = %optimistic_header.transactions_root(),
        proposal.block_access_list_header_hash = ?proposal_header.block_access_list_hash(),
        optimistic.block_access_list_header_hash = ?optimistic_header.block_access_list_hash(),
        proposal.block_access_list_bytes_hash = ?proposal_block_access_list_hash,
        optimistic.block_access_list_bytes_hash = ?optimistic_block_access_list_hash,
        proposal.block_access_list_size_bytes =
            proposal_block_access_list.map_or(0, |bytes| bytes.as_ref().len()),
        optimistic.block_access_list_size_bytes =
            optimistic_block_access_list.map_or(0, |bytes| bytes.as_ref().len()),
        logs_bloom_matches = proposal_header.logs_bloom() == optimistic_header.logs_bloom(),
        requests_hash_matches = proposal_header.requests_hash() == optimistic_header.requests_hash(),
        "SSMR optimistic artifact does not match final proposal; falling back to normal validation"
    );
}

fn block_from_ssmr_optimistic_payload(payload: &TempoBuiltPayload) -> eyre::Result<Block> {
    let (execution_block, block_access_list, execution_block_encoded) =
        payload.clone().into_consensus_execution_payload();
    Block::from_execution_block_with_encoded_cache(
        execution_block,
        block_access_list,
        execution_block_encoded,
    )
    .wrap_err("SSMR optimistic payload produced an invalid block access list")
}

#[derive(Debug)]
enum SsmrOptimisticPayloadMismatch {
    ExecutionBlock,
    BlockAccessList,
}

fn ssmr_snapshot_waiting_for_optimistic_payload(snapshot: &SsmrStreamSnapshot) -> bool {
    if !snapshot.started {
        return true;
    }

    match snapshot.complete.as_ref() {
        Some(stream) => stream.optimistic_payload.is_none(),
        None => true,
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

/// Resolves a block by digest.
///
/// Checks the EL first. If the block is not available there, or if the caller
/// needs sidecars that EL storage does not retain, subscribes to the CL and
/// waits until the complete consensus block becomes available.
#[instrument(skip_all, fields(%round, %digest), err, ret(Display))]
async fn subscribe<TContext: commonware_runtime::Clock>(
    context: &TContext,
    execution_node: &TempoFullNode,
    round: Round,
    digest: Digest,
    marshal: &crate::alias::marshal::Mailbox,
    resolution: BlockResolution,
) -> eyre::Result<Block> {
    if let Some(block) = find_block_in_execution_layer(execution_node, digest)? {
        if resolution.accepts(&block) {
            return Ok(block);
        }
        debug!(
            "execution layer block is missing required consensus sidecars; waiting for marshal block"
        );
    }

    let block_rx = marshal.subscribe_by_digest(Some(round), digest).await;
    futures::pin_mut!(block_rx);
    loop {
        select! {
            result = &mut block_rx => {
                return result.map_err(|_| eyre!("syncer dropped channel before the parent block was sent"));
            },
            _ = context.sleep(BLOCK_SUBSCRIBE_EL_POLL_INTERVAL) => {
                if let Some(block) = find_block_in_execution_layer(execution_node, digest)?
                    && resolution.accepts(&block)
                {
                    return Ok(block);
                }
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockResolution {
    Any,
    RequireConsensusSidecars,
}

impl BlockResolution {
    fn accepts(self, block: &Block) -> bool {
        self == Self::Any || !block.missing_required_sidecars()
    }
}

fn find_block_in_execution_layer(
    execution_node: &TempoFullNode,
    digest: Digest,
) -> eyre::Result<Option<Block>> {
    execution_node
        .provider
        .find_sealed_or_recovered_block(digest.0, BlockSource::Any)
        .wrap_err_with(|| format!("failed querying execution layer for block `{digest}`"))
        .map(|block| {
            block.map(|block| {
                // EL database reads do not include commonware sidecars.
                Block::from_execution_block_unchecked(block, None)
            })
        })
}

#[derive(Clone)]
struct Metrics {
    parent_ahead_of_local_time: Counter,
    ssmr_missing_shards_at_proposal: Counter,
    ssmr_final_reconciliations: Counter,
    ssmr_final_reconciliation_mismatches: Counter,
    ssmr_fallback_validation_count: Counter,
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
        let ssmr_missing_shards_at_proposal = Counter::default();
        context.register(
            "ssmr_missing_shards_at_proposal",
            "number of proposal verifications without a complete SSMR transcript",
            ssmr_missing_shards_at_proposal.clone(),
        );
        let ssmr_final_reconciliations = Counter::default();
        context.register(
            "ssmr_final_reconciliations",
            "number of final proposals that matched a complete SSMR transcript",
            ssmr_final_reconciliations.clone(),
        );
        let ssmr_final_reconciliation_mismatches = Counter::default();
        context.register(
            "ssmr_final_reconciliation_mismatches",
            "number of complete SSMR transcripts that did not match the final proposal",
            ssmr_final_reconciliation_mismatches.clone(),
        );
        let ssmr_fallback_validation_count = Counter::default();
        context.register(
            "ssmr_fallback_validation_count",
            "number of proposal verifications that used the normal execution validation path",
            ssmr_fallback_validation_count.clone(),
        );

        Self {
            parent_ahead_of_local_time,
            ssmr_missing_shards_at_proposal,
            ssmr_final_reconciliations,
            ssmr_final_reconciliation_mismatches,
            ssmr_fallback_validation_count,
        }
    }
}
