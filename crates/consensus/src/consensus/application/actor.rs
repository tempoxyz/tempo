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
use alloy_primitives::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Encode as _, EncodeSize as _, ReadExt as _};
use commonware_consensus::{
    Heightable as _,
    marshal::core::DigestFallback,
    simplex::{Plan, types::Context},
    types::{Epocher as _, FixedEpocher, HeightDelta, Round, View},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::{
    ContextCell, Handle, Pacer, Spawner, Storage, Supervisor, spawn_cell,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

use commonware_utils::SystemTimeExt;
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use rand_core::{CryptoRng, Rng};
use reth_primitives_traits::BlockBody as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tempo_telemetry_util::display_duration;

use reth_provider::{BlockReader as _, BlockSource};
use tempo_payload_types::{
    Estimator, EstimatorSnapshot, ProposalExpectation, TempoPayloadAttributes,
    ValidationLatencyWorkload,
};
use tempo_primitives::TempoConsensusContext;
use tracing::{Level, debug, info, instrument, warn};

use super::{
    Mailbox,
    ingress::{Broadcast, Message, Propose, Verify},
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

pub(in crate::consensus) struct Actor<TContext, TState = Uninit> {
    context: ContextCell<TContext>,
    mailbox: mailbox::Receiver<Message>,

    inner: Inner<TState>,
}

struct BuildProposalArgs {
    propose_start: Instant,
    parent_view: View,
    parent_digest: Digest,
    round: Round,
    leader: PublicKey,
}

struct ProposalReturn {
    /// Earliest time the built proposal may be returned to consensus.
    ///
    /// After the proposal is persisted locally, the actor sleeps until this time
    /// so early builds still respect the proposal pacing budget.
    return_at: SystemTime,
    /// What validators are expected to spend on this proposal.
    ///
    /// Handed to the estimator when the proposal is returned so the network
    /// sample completed by the notarization only measures propagation and
    /// votes. The block size is an estimate derived during payload building,
    /// not the exact final encoded size.
    expectation: ProposalExpectation,
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
        let (tx, rx) = mailbox::new(config.context.child("mailbox"), config.mailbox_size);
        let my_mailbox = Mailbox::from_sender(tx);

        let metrics = Metrics::init(&config.context);

        Ok(Self {
            context: ContextCell::new(config.context),
            mailbox: rx,

            inner: Inner {
                public_key: config.public_key,
                epoch_strategy: config.epoch_strategy,

                estimator: config.estimator,

                my_mailbox,
                marshal: config.marshal,

                execution_node: config.execution_node,
                executor: config.executor,

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
        while let Some(msg) = self.mailbox.recv().await {
            self.handle_message(msg);
        }
    }

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Broadcast(broadcast) => {
                self.context.child("broadcast").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_broadcast(*broadcast)
                });
            }
            Message::Propose(propose) => {
                if propose.response.is_closed() {
                    return;
                }

                self.context.child("propose").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_propose(*propose, context)
                });
            }
            Message::Verify(verify) => {
                if verify.response.is_closed() {
                    return;
                }

                self.context.child("verify").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_verify(*verify)
                });
            }
        }
    }
}

#[derive(Clone)]
struct Inner<TState> {
    public_key: PublicKey,
    epoch_strategy: FixedEpocher,
    /// Shared proposal budget estimator: owns the network reservation and
    /// the validation, persistence and build feedback.
    estimator: Arc<Estimator>,

    my_mailbox: Mailbox,

    marshal: crate::alias::marshal::Mailbox,

    execution_node: Arc<TempoFullNode>,
    executor: crate::executor::Mailbox,

    metrics: Metrics,

    state: TState,
}

impl Inner<Init> {
    #[instrument(skip_all, fields(%digest))]
    async fn handle_broadcast(self, Broadcast { digest, plan }: Broadcast) {
        let (round, recipients) = match plan {
            Plan::Propose { round } => (round, Recipients::All),
            Plan::Forward { round, recipients } => (round, recipients),
        };

        self.marshal.forward(round, digest, recipients);
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
    async fn handle_propose<TContext: Pacer + Supervisor>(
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

        // Report the parent we are asked to build on as the pending head,
        // so that the executor can get started on bringing the execution
        // layer to the right state. On the happy path there should always
        // be enough headroom between this and the eventual request to build
        // a block.
        //
        // If the EL is not (yet) in the correct state to build a block the
        // build will fail fast.
        debug!("reporting notarized tip");
        if let Err(error) = self.executor.report_pending_head(Context {
            round,
            leader: leader.clone(),
            parent: (parent_view, parent_digest),
        }) {
            warn!(%error, "failed reporting the proposal parent as the pending head");
        }

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
                    &context,
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
                    let block_size_bytes = block.encode_size();
                    let persist_start = Instant::now();
                    if !self.marshal.verified(round, block.clone()).await {
                        bail!("marshal actor rejected persisting proposal");
                    }
                    self.estimator.on_marshal_persist(
                        Instant::now(),
                        block_size_bytes,
                        persist_start.elapsed(),
                    );

                    // Keep waiting for the remaining return time, if there's anything left after building the block.
                    context.sleep_until(proposal_return.return_at).await;
                    // The proposal leaves this node now; the header timestamp
                    // of the block built on top of it completes the network
                    // sample, so record the return on the same clock.
                    self.estimator.on_proposal_returned(
                        Instant::now(),
                        context.current().epoch_millis(),
                        (round.epoch().get(), round.view().get()),
                        proposal_return.expectation,
                    );
                    self.metrics.observe_estimator(&self.estimator.snapshot());
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
        err(level = Level::INFO),
    )]
    async fn handle_verify(self, verify: Verify) -> eyre::Result<()> {
        let Verify {
            parent,
            payload,
            proposer,
            mut response,
            round,
        } = verify;
        let VerifyResult { result, block } = select!(
            () = response.closed() => {
                Err(eyre!(
                    "verification return channel was closed by consensus \
                    engine before block could be validated; aborting"
                ))
            },

            res = self.clone().verify(parent, payload, proposer, round) => {
                res.wrap_err("block verification failed")
            }
        )?;

        if response.send(result).is_err() {
            warn!("received dropped channel before verification result could be returned");
        }
        // Keep large block drops out of the pre-response path.
        drop(block);

        Ok(())
    }

    async fn propose<TContext: Pacer>(
        self,
        context: &TContext,
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
            &self.execution_node,
            Round::new(round.epoch(), parent_view),
            parent_digest,
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
            // If the header has a block access list hash but the block itself doesn't
            // it likely means that the block was fetched from reth database and we need to
            // additionally fetch the BAL from commonware.
            let parent = if parent.block().header().block_access_list_hash().is_some()
                && parent.block_access_list().is_none()
            {
                let round = Round::new(round.epoch(), parent_view);
                (*self
                    .marshal
                    .subscribe_by_digest(parent_digest, DigestFallback::FetchByRound { round })
                    .await
                    .map_err(|_| {
                        eyre!("syncer dropped channel before the parent block was sent")
                    })?)
                .clone()
            } else {
                parent
            };
            if !self.marshal.verified(round, parent.clone()).await {
                bail!("marshal rejected re-proposed boundary block");
            }
            info!("parent is last height of epoch; re-proposing parent");
            return Ok((parent, None));
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
                round.epoch().next() == outcome.epoch(),
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
            self.metrics.parent_ahead_of_local_time.metric().inc();
            epoch_millis = parent.timestamp_millis() + 1
        };

        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        // If this node also proposed the parent, this build start is what the
        // chain waited for; complete that network sample.
        self.estimator.on_child_block_built(
            Instant::now(),
            (round.epoch().get(), parent_view.get()),
            round.view().get(),
            epoch_millis,
        );

        let consensus_context = Some(TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent_view.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&leader),
        });

        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        let marshal_persist = self.estimator.marshal_persist();
        // The proposal window is the target block time minus the learned
        // network reservation. Give the builder only what remains of it when
        // payload construction is requested, accounting for a late
        // `handle_propose` start instead of resetting the budget at builder entry.
        let proposal_budget = self.estimator.proposal_budget();
        let build_budget = proposal_budget
            .return_budget
            .saturating_sub(propose_start.elapsed());
        let validation_latency_estimate = self.estimator.validation_latency_estimate();
        let attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context,
        )
        .with_payload_build_budget(build_budget)
        .with_validation_latency_estimate(validation_latency_estimate);

        // Subscribe to the payload build. The executor owns the build job
        // and runs it to completion; dropping the receiver (for example
        // because the proposal was cancelled) tells it that the payload is
        // no longer wanted.
        let payload_build_start = Instant::now();
        let payload = self
            .state
            .executor
            .build_proposal(round, parent.digest(), attrs)?
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
        let proposal = Block::from_execution_block_unchecked_with_encoded_cache(
            block,
            block_access_list,
            execution_block_encoded,
        );
        let block_size_estimate_bytes =
            execution_block_rlp_size_estimate_bytes + block_access_list_size_bytes;
        let validator_marshal_persist = marshal_persist.estimate(block_size_estimate_bytes);
        // Validators' expected work on this block, scaled to its actual size.
        // The pacing estimate above is a floor that never scales down; using
        // it to credit validators would under-count the network for blocks
        // smaller than the recent ones this node validated.
        let expected_validator_work = self
            .estimator
            .expected_validation(ValidationLatencyWorkload::new(
                proposal.block().gas_used(),
                proposal.block().body().transaction_count(),
            ))
            .unwrap_or(validation_latency_elapsed);
        let proposal_elapsed = propose_start.elapsed();
        // Pace proposal return from the original propose start. Validators still
        // need to repeat replayable build work and marshal persistence, so leave
        // room for those costs before returning the proposal.
        let return_delay = proposal_budget
            .return_budget
            .saturating_sub(proposal_elapsed)
            .saturating_sub(validation_latency_elapsed)
            .saturating_sub(validator_marshal_persist);
        debug!(
            return_budget = %display_duration(proposal_budget.return_budget),
            network_reserve = %display_duration(proposal_budget.network_reserve),
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            payload_validation_work = %display_duration(payload_validation_work_elapsed),
            validation_latency_time = %display_duration(validation_latency_elapsed),
            expected_validator_work = %display_duration(expected_validator_work),
            validator_marshal_persist = %display_duration(validator_marshal_persist),
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
                expectation: ProposalExpectation {
                    block_size_bytes: block_size_estimate_bytes,
                    validator_work: expected_validator_work,
                    validator_persist: validator_marshal_persist,
                },
            }),
        ))
    }

    #[instrument(
        skip_all,
        fields(
            %parent_view,
            %parent_digest,
            %round,
            proposal = %payload,
            %proposer,
        ),
        err(level = Level::WARN),
    )]
    async fn verify(
        self,
        (parent_view, parent_digest): (View, Digest),
        payload: Digest,
        proposer: PublicKey,
        round: Round,
    ) -> eyre::Result<VerifyResult> {
        // Report the parent we are asked to verify against as the pending
        // head, so that the executor keeps driving the execution layer
        // towards it even if this verification is aborted.
        if let Err(error) = self.executor.report_pending_head(Context {
            round,
            leader: proposer.clone(),
            parent: (parent_view, parent_digest),
        }) {
            warn!(%error, "failed reporting the verify parent as the pending head");
        }

        let block = subscribe(&self.execution_node, round, payload, &self.marshal)
            .await
            .wrap_err("failed getting proposal block")?;

        // Can only repropose at the end of an epoch.
        if payload == parent_digest {
            let epoch_info = self
                .epoch_strategy
                .containing(block.height())
                .expect("epoch strategy is for all heights");
            if epoch_info.last() == block.height() && epoch_info.epoch() == round.epoch() {
                if !self.marshal.verified(round, block).await {
                    bail!("marshal actor refused to persist verified re-proposed block");
                }
                return Ok(VerifyResult {
                    result: true,
                    block: None,
                });
            } else {
                return Ok(VerifyResult {
                    result: false,
                    block: Some(block),
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
            return Ok(VerifyResult {
                result: false,
                block: Some(block),
            });
        }

        // If this node proposed the parent, the child's timestamp is when the
        // next leader could build on it: the network sample for that proposal.
        if let Some(consensus_context) = block.header().consensus_context {
            self.estimator.on_child_block_built(
                Instant::now(),
                (consensus_context.epoch, consensus_context.parent_view),
                consensus_context.view,
                block.timestamp_millis(),
            );
        }

        let validation_duration = verify_block(
            round,
            &self.epoch_strategy,
            &self.state.executor,
            &block,
            parent_digest,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?;
        if let Some(duration) = validation_duration {
            self.estimator.on_block_verified(
                block.height().get(),
                ValidationLatencyWorkload::new(
                    block.block().gas_used(),
                    block.block().body().transaction_count(),
                ),
                duration,
            );
        }
        let is_good = validation_duration.is_some();

        if is_good {
            // Persist the verified block in the marshal actor. Validators
            // persist every block, so most persistence samples come from here.
            let block_size_bytes = block.encode_size();
            let persist_start = Instant::now();
            if !self.marshal.verified(round, block).await {
                bail!("marshal actor refused to persist verified block");
            }
            self.estimator.on_marshal_persist(
                Instant::now(),
                block_size_bytes,
                persist_start.elapsed(),
            );
            self.metrics.observe_estimator(&self.estimator.snapshot());

            return Ok(VerifyResult {
                result: true,
                block: None,
            });
        }

        Ok(VerifyResult {
            result: false,
            block: Some(block),
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
            estimator: self.estimator,
            my_mailbox: self.my_mailbox,
            marshal: self.marshal,
            execution_node: self.execution_node,
            executor: self.executor.clone(),
            state: Init {
                dkg_manager,
                executor: self.executor.clone(),
            },
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
}

/// Validates `block` against the execution layer through the executor
/// actor, which serializes the new-payload request with all other
/// execution-layer work and records the block's body for the
/// notarized-chain convergence.
///
/// Returns the EL validation duration when validation reached the execution
/// layer and succeeded, or `None` if the block is invalid. Returns an error
/// if validation was not possible, for example if the execution layer does
/// not know the block's parent or the request was superseded by a
/// newer-round request.
async fn verify_block(
    round: Round,
    epoch_strategy: &FixedEpocher,
    executor: &crate::executor::Mailbox,
    block: &Block,
    parent_digest: Digest,
) -> eyre::Result<Option<Duration>> {
    let epoch = round.epoch();
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

    executor.verify_block(round, block.clone()).await
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
/// Checks the EL first. If the block is not available there, subscribes to the
/// CL and waits until the block becomes available.
#[instrument(skip_all, fields(%round, %digest), err, ret(Display))]
async fn subscribe(
    execution_node: &TempoFullNode,
    round: Round,
    digest: Digest,
    marshal: &crate::alias::marshal::Mailbox,
) -> eyre::Result<Block> {
    let block = if let Some(block) = execution_node
        .provider
        .find_sealed_or_recovered_block(digest.0, BlockSource::Any)
        .wrap_err_with(|| format!("failed querying execution layer for parent block `{digest}`"))?
    {
        // EL database reads do not include commonware sidecars.
        Block::from_execution_block_unchecked(block, None)
    } else {
        (*marshal
            .subscribe_by_digest(digest, DigestFallback::FetchByRound { round })
            .await
            .map_err(|_| eyre!("syncer dropped channel before the parent block was sent"))?)
        .clone()
    };
    Ok(block)
}

#[derive(Clone)]
struct Metrics {
    parent_ahead_of_local_time: Counter,
    /// Network reservation currently subtracted from the target block time.
    estimator_network_reserve_ms: Gauge,
    /// Learned network time before clamping, zero until a proposal completed.
    estimator_network_observed_ms: Gauge,
    /// Proposal return budget handed to the next proposal.
    estimator_proposal_return_budget_ms: Gauge,
    /// Recent P90 execution-layer validation time.
    estimator_validation_latency_p90_ms: Gauge,
    /// Marshal persistence cost per encoded byte.
    estimator_marshal_persist_ns_per_byte: Gauge,
    /// Build time multiplier in thousandths.
    estimator_build_time_multiplier_permille: Gauge,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let parent_ahead_of_local_time = context.counter(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time",
        );

        Self {
            parent_ahead_of_local_time,
            estimator_network_reserve_ms: context.gauge(
                "estimator_network_reserve_ms",
                "time reserved for proposal propagation and votes, in milliseconds",
            ),
            estimator_network_observed_ms: context.gauge(
                "estimator_network_observed_ms",
                "learned proposal propagation and vote time before clamping, in milliseconds",
            ),
            estimator_proposal_return_budget_ms: context.gauge(
                "estimator_proposal_return_budget_ms",
                "local proposal return budget for the next proposal, in milliseconds",
            ),
            estimator_validation_latency_p90_ms: context.gauge(
                "estimator_validation_latency_p90_ms",
                "recent p90 execution-layer block validation time, in milliseconds",
            ),
            estimator_marshal_persist_ns_per_byte: context.gauge(
                "estimator_marshal_persist_ns_per_byte",
                "learned marshal persistence cost per encoded block byte, in nanoseconds",
            ),
            estimator_build_time_multiplier_permille: context.gauge(
                "estimator_build_time_multiplier_permille",
                "payload build time multiplier in use, in thousandths",
            ),
        }
    }

    fn observe_estimator(&self, snapshot: &EstimatorSnapshot) {
        let millis = |duration: Duration| duration.as_millis().min(i64::MAX as u128) as i64;
        self.estimator_network_reserve_ms
            .set(millis(snapshot.network_reserve));
        self.estimator_network_observed_ms
            .set(snapshot.network_observed.map_or(0, millis));
        self.estimator_proposal_return_budget_ms
            .set(millis(snapshot.proposal_return_budget));
        self.estimator_validation_latency_p90_ms
            .set(snapshot.validation_latency_p90.map_or(0, millis));
        self.estimator_marshal_persist_ns_per_byte
            .set(snapshot.marshal_persist_ns_per_byte.min(i64::MAX as u64) as i64);
        self.estimator_build_time_multiplier_permille
            .set((snapshot.build_time_multiplier * 1000.0).round() as i64);
    }
}
