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
    time::{Duration, Instant},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::PayloadId;
use commonware_codec::{Encode as _, ReadExt as _};
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
use futures::{
    StreamExt as _, TryFutureExt as _,
    channel::{mpsc, oneshot},
    future::try_join,
};
use rand_08::{CryptoRng, Rng};
use reth_ethereum::chainspec::EthChainSpec as _;
use reth_node_builder::{Block as _, BuiltPayload, ConsensusEngineHandle, PayloadKind};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks as _};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};
use tempo_telemetry_util::display_duration;

use reth_provider::{BlockHashReader as _, BlockReader as _};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::TempoConsensusContext;
use tracing::{Level, debug, info, info_span, instrument, warn};

use super::{
    Mailbox,
    ingress::{Broadcast, Genesis, Message, Propose, Verify},
};
use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    subblocks,
};

pub(in crate::consensus) struct Actor<TContext, TState = Uninit> {
    context: ContextCell<TContext>,
    mailbox: mpsc::Receiver<Message>,

    inner: Inner<TState>,
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
                fee_recipient: config.fee_recipient,
                epoch_strategy: config.epoch_strategy,

                payload_resolve_time: config.payload_resolve_time,
                payload_return_time: config.payload_return_time,

                my_mailbox,
                marshal: config.marshal,

                execution_node: config.execution_node,
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
    fee_recipient: Option<alloy_primitives::Address>,
    epoch_strategy: FixedEpocher,
    payload_resolve_time: Duration,
    payload_return_time: Duration,

    my_mailbox: Mailbox,

    marshal: crate::alias::marshal::Mailbox,

    execution_node: TempoFullNode,
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
        } = request;

        let mut payload_id_rx: Option<oneshot::Receiver<eyre::Result<PayloadId>>> = None;

        let proposal_digest = select!(
            () = response.closed() => {
                if let Some(rx) = payload_id_rx.as_mut() {
                    let id = rx
                        .await
                        .wrap_err("executor dropped response")?
                        .wrap_err("failed requesting a new payload build")?;
                    let fut = self
                        .execution_node
                        .payload_builder_handle
                        .resolve_kind_fut(id, PayloadKind::WaitForPending)
                        .await
                        .wrap_err("failed resolving payload")?;
                    drop(fut);
                }

                Err(eyre!(
                    "proposal return channel was closed by consensus \
                    engine before block could be proposed; aborting"
                ))
           },

            res = self.clone().propose(
                context.clone(),
                parent_view,
                parent_digest,
                round,
                &mut payload_id_rx,
                leader,
            ) => {
                res.wrap_err("failed creating a proposal")
            }
        )?;

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

    async fn propose<TContext: Pacer>(
        self,
        context: TContext,
        parent_view: View,
        parent_digest: Digest,
        round: Round,
        payload_id_rx: &mut Option<oneshot::Receiver<eyre::Result<PayloadId>>>,
        leader: PublicKey,
    ) -> eyre::Result<Digest> {
        let propose_start = Instant::now();

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
        if let Some(block) = self.marshal.get_verified(round).await {
            debug!("skipping proposal: verified block already exists for round on restart");
            return Ok(block.digest());
        }

        let parent = get_parent(
            &self.execution_node,
            round,
            parent_digest,
            parent_view,
            &self.marshal,
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
            if !self.marshal.verified(round, parent.clone()).await {
                bail!("marshal rejected re-proposed boundary block");
            }
            info!("parent is last height of epoch; re-proposing parent");
            return Ok(parent_digest);
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
            && !verify_block(
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
            )
            .await
            .wrap_err("failed verifying block against execution layer")?
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

        let consensus_context = if self
            .execution_node
            .chain_spec()
            .is_t4_active_at_timestamp(timestamp)
        {
            Some(TempoConsensusContext {
                epoch: round.epoch().get(),
                view: round.view().get(),
                parent_view: parent_view.get(),
                proposer: crate::utils::public_key_to_tempo_primitive(&leader),
            })
        } else {
            None
        };

        let parent_hash = parent.block_hash();
        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let attrs = TempoPayloadAttributes::new(
            self.fee_recipient.unwrap_or_default(),
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
        );

        let interrupt_handle = attrs.interrupt_handle().clone();

        // Share the dispatch receiver with the cancel branch so that, if cancellation
        // hits between dispatch send and receiving `payload_id`, the cancel branch can
        // still drain the rx, learn `payload_id`, and cancel the now-registered job.
        *payload_id_rx = Some(self.state.executor.canonicalize_and_build(
            parent.height(),
            parent.digest(),
            attrs,
        )?);

        let payload_id = payload_id_rx
            .as_mut()
            .expect("just set")
            .await
            .wrap_err("executor dropped response")?
            .wrap_err("failed requesting a new payload build")?;

        // Replace the slot with a pre-filled oneshot so the cancel branch can keep
        // unconditionally awaiting `payload_id_rx` and immediately get back `payload_id`.
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(payload_id));
        *payload_id_rx = Some(rx);

        let elapsed = propose_start.elapsed();
        let remaining_resolve = self.payload_resolve_time.saturating_sub(elapsed);
        let remaining_return = self.payload_return_time.saturating_sub(elapsed);
        debug!(
            elapsed = %display_duration(elapsed),
            resolve_time = %display_duration(remaining_resolve),
            return_time = %display_duration(remaining_return),
            "sleeping before payload builder resolving"
        );

        // Start the timer for `remaining_return`
        //
        // This guarantees that we will not propose the block too early, and waits for at least
        // `remaining_return` (`payload_return_time` minus time already spent in propose),
        // plus whatever time is needed to finish building the block.
        let payload_return_time = context.current() + remaining_return;

        // Give payload builder at least `remaining_resolve` until we interrupt it.
        //
        // The interrupt doesn't mean we'll immediately get the payload back,
        // but only signals the builder to stop executing transactions,
        // and start calculating the state root and sealing the block.
        context.sleep(remaining_resolve).await;

        interrupt_handle.interrupt();

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

        let proposal = Block::from_execution_block(payload.block().clone());
        let digest = proposal.digest();
        if !self.marshal.proposed(round, proposal).await {
            bail!("marshal actor rejected persisting proposal");
        }

        // Keep waiting for the remaining return time, if there's anything left after building the block.
        context.sleep_until(payload_return_time).await;

        Ok(digest)
    }

    async fn verify<TContext: Pacer>(
        self,
        context: TContext,
        (parent_view, parent_digest): (View, Digest),
        payload: Digest,
        proposer: PublicKey,
        round: Round,
    ) -> eyre::Result<bool> {
        let block_request = self
            .marshal
            .subscribe_by_digest(None, payload)
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
            self.execution_node.chain_spec().as_ref(),
            &self.state.dkg_manager,
            &self.epoch_strategy,
            &proposer,
        )
        .await
        {
            warn!(%reason, "header could not be verified; failing block");
            return Ok(false);
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

        let is_good = verify_block(
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
        .wrap_err("failed verifying block against execution layer")?;

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
            fee_recipient: self.fee_recipient,
            epoch_strategy: self.epoch_strategy,
            payload_resolve_time: self.payload_resolve_time,
            payload_return_time: self.payload_return_time,
            my_mailbox: self.my_mailbox,
            marshal: self.marshal,
            execution_node: self.execution_node,
            executor: self.executor.clone(),
            state: Init {
                dkg_manager,
                executor: self.executor.clone(),
            },
            subblocks: self.subblocks,
            scheme_provider: self.scheme_provider,
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
    let block = block.clone().into_inner();
    let execution_data = TempoExecutionData {
        block: Arc::new(block),
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
    chainspec: &TempoChainSpec,
    dkg_manager: &crate::dkg::manager::Mailbox,
    epoch_strategy: &FixedEpocher,
    proposer: &PublicKey,
) -> eyre::Result<()> {
    let epoch_info = epoch_strategy
        .containing(block.height())
        .expect("epoch strategy is for all heights");

    if chainspec.is_t4_active_at_timestamp(block.timestamp()) {
        let ctx = block
            .header()
            .consensus_context
            .ok_or_eyre("missing consensus context after t4 activation")?;

        let expected_ctx = TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent.0.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(proposer),
        };

        if ctx != expected_ctx {
            bail!("mismatching block consensus context");
        }
    } else if block.header().consensus_context.is_some() {
        bail!("block consensus context set prior to activation");
    }

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
    let genesis_digest = execution_node.chain_spec().genesis_hash();
    if parent_digest == Digest(genesis_digest) {
        let genesis_block = Block::from_execution_block(
            execution_node
                .provider
                .block_by_number(0)
                .map_or_else(
                    |e| Err(eyre::Report::new(e)),
                    |block| block.ok_or_eyre("execution layer did not have block"),
                )
                .wrap_err("execution layer did not have the genesis block")?
                .seal(),
        );
        Ok(genesis_block)
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

        Self {
            parent_ahead_of_local_time,
        }
    }
}
