//! Tempo's block building and verification.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_consensus::BlockHeader;
use alloy_primitives::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{Update, ancestry::Ancestry},
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Context},
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::MinSig},
    ed25519::PublicKey,
};
use commonware_runtime::{
    Clock, Spawner,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{Acknowledgement as _, SystemTimeExt as _};
use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{FutureExt as _, StreamExt as _, channel::oneshot};
use rand_core::Rng;
use reth_primitives_traits::BlockBody as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_payload_types::{
    TempoPayloadAttributes, ValidationLatencyEstimator, ValidationLatencyWorkload,
};
use tempo_primitives::TempoConsensusContext;
use tempo_telemetry_util::display_duration;
use tracing::{Level, debug, info, instrument, warn};

use super::parent_state::TempoParentState;
use crate::{
    consensus::{Digest, block::Block},
    executor::DeferredExtraData,
};

pub(in crate::consensus) struct Config<TContext> {
    /// Registers the application's metrics; spawns its work.
    pub(in crate::consensus) context: TContext,

    /// This node's ed25519 public key, used to look up the fee recipient from
    /// the validator config v2 contract.
    pub(in crate::consensus) public_key: PublicKey,

    pub(in crate::consensus) executor: crate::executor::Mailbox,

    pub(in crate::consensus) dkg_manager: crate::dkg::manager::Mailbox,

    /// Reads the part of a boundary block's DKG outcome that comes from the
    /// post-state of its parent.
    pub(in crate::consensus) parent_state: TempoParentState,

    /// Local proposal return budget, excluding the network propagation allowance.
    ///
    /// Starts at `target_block_time - network_budget` when the application is
    /// called. Commonware's parent fetch happens beforehand and is not charged
    /// against this budget. Proposal preparation time is deducted before handing
    /// the remaining budget to the payload builder.
    pub(in crate::consensus) proposal_return_budget: Duration,

    /// The epoch strategy used by tempo, to map block heights to epochs.
    pub(in crate::consensus) epoch_strategy: FixedEpocher,
}

/// Tempo's block builder and verifier, see the module documentation.
#[derive(Clone)]
pub(crate) struct Inner {
    public_key: PublicKey,
    epoch_strategy: FixedEpocher,
    /// Local proposal window after reserving network propagation time.
    proposal_return_budget: Duration,

    executor: crate::executor::Mailbox,
    dkg_manager: crate::dkg::manager::Mailbox,
    parent_state: TempoParentState,
    validation_latency_estimator: Arc<Mutex<ValidationLatencyEstimator>>,

    metrics: Metrics,
}

impl Inner {
    pub(in crate::consensus) fn new<TContext: commonware_runtime::Metrics>(
        config: Config<TContext>,
    ) -> Self {
        Self {
            public_key: config.public_key,
            epoch_strategy: config.epoch_strategy,
            proposal_return_budget: config.proposal_return_budget,
            executor: config.executor,
            dkg_manager: config.dkg_manager,
            parent_state: config.parent_state,
            validation_latency_estimator: Default::default(),
            metrics: Metrics::init(&config.context),
        }
    }

    /// Builds a block on `parent` through the executor and paces its return.
    #[instrument(
        skip_all,
        fields(
            epoch = %context.round.epoch(),
            view = %context.round.view(),
            parent.view = %context.parent.0,
            parent.digest = %context.parent.1,
            parent.height = %parent.height(),
        ),
        err(level = Level::WARN),
    )]
    async fn build<TContext: Clock>(
        &self,
        runtime: &TContext,
        context: Context<Digest, PublicKey>,
        parent: &Arc<Block>,
        propose_start: Instant,
    ) -> eyre::Result<Block> {
        self.executor
            .report_pending_head(context.round, context.parent)?;

        let Context {
            round,
            leader,
            parent: (parent_view, parent_digest),
        } = context;

        let (extra_data, deferred_extra_data) = if self.is_boundary(parent.height().next()) {
            // The boundary block carries the DKG outcome.
            //
            // Part of it is read from the post-state of the parent,
            // so the executor resolves it only after the parent returned VALID.
            //
            // The DKG actor reads no chain state, so it starts on the
            // ceremony output now, while the executor works on the parent.
            let ceremony = self.dkg_manager.subscribe_dkg_ceremony(Arc::clone(parent));
            (
                Bytes::default(),
                Some(self.boundary_dkg_outcome(round.epoch(), parent.digest(), ceremony)),
            )
        } else {
            // Regular block: try to include DKG dealer log.
            let extra_data = match self.dkg_manager.get_dealer_log(round.epoch()).await {
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
            };
            (extra_data, None)
        };

        // Use current timestamp but make sure that if parent's timestamp is in the future, we account for that.
        let mut epoch_millis = runtime.current().epoch_millis();
        if epoch_millis <= parent.timestamp_millis() {
            self.metrics.parent_ahead_of_local_time.metric().inc();
            epoch_millis = parent.timestamp_millis() + 1
        };

        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        let consensus_context = Some(TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent_view.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&leader),
        });

        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        // Give the builder only the proposal window that remains when payload
        // construction is requested.
        let build_budget = self
            .proposal_return_budget
            .saturating_sub(propose_start.elapsed());
        let validation_latency_estimate = self
            .validation_latency_estimator
            .lock()
            .ok()
            .and_then(|estimator| estimator.estimate());
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
            .executor
            .build_proposal(
                Context {
                    round,
                    leader,
                    parent: (parent_view, parent_digest),
                },
                attrs,
                deferred_extra_data,
            )?
            .await
            .wrap_err(
                "executor dropped the payload channel: the build failed (the \
                executor logs the cause) or the executor shut down",
            )?;

        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_work_elapsed = payload.validation_work_duration();
        let validation_latency_elapsed = payload.validation_latency_duration();
        let (block, block_access_list, execution_block_encoded) =
            payload.into_consensus_execution_payload();
        let proposal = Block::from_execution_block_unchecked_with_encoded_cache(
            block,
            block_access_list,
            execution_block_encoded,
        );
        let proposal_elapsed = propose_start.elapsed();
        // Pace proposal return from the propose start. Validators still need
        // to repeat replayable build work, so leave room for it before
        // returning the proposal.
        let return_delay = self
            .proposal_return_budget
            .saturating_sub(proposal_elapsed)
            .saturating_sub(validation_latency_elapsed);
        debug!(
            proposal.digest = %proposal.digest(),
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            payload_validation_work = %display_duration(payload_validation_work_elapsed),
            validation_latency_time = %display_duration(validation_latency_elapsed),
            return_time = %display_duration(return_delay),
            "sleeping before returning proposal"
        );
        runtime.sleep_until(runtime.current() + return_delay).await;

        Ok(proposal)
    }

    /// Returns the DKG outcome of a boundary block in `epoch` as deferred
    /// extra data. The executor resolves it with the parent once the parent
    /// returned VALID, so the post-state of the parent is available.
    ///
    /// `ceremony` is the request for the ceremony output on the parent
    /// `parent_digest`.
    fn boundary_dkg_outcome(
        &self,
        epoch: Epoch,
        parent_digest: Digest,
        ceremony: oneshot::Receiver<Output<MinSig, PublicKey>>,
    ) -> DeferredExtraData {
        let parent_state = self.parent_state.clone();
        let epoch_strategy = self.epoch_strategy.clone();
        DeferredExtraData::new(move |parent| {
            async move {
                ensure!(
                    parent.digest() == parent_digest,
                    "the executor built on `{}`, but the DKG ceremony was requested \
                    for `{parent_digest}`",
                    parent.digest(),
                );
                let output = ceremony
                    .await
                    .wrap_err("failed getting public dkg ceremony outcome")?;
                let outcome = parent_state.boundary_outcome(&epoch_strategy, &parent, output)?;
                ensure!(
                    epoch.next() == outcome.epoch(),
                    "outcome is for epoch `{}`, but we are trying to include the \
                    outcome for epoch `{}`",
                    outcome.epoch,
                    epoch.next(),
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
            }
            .boxed()
        })
    }

    /// Returns whether the block at `height` is the last block of its epoch,
    /// which carries the DKG outcome.
    fn is_boundary(&self, height: Height) -> bool {
        self.epoch_strategy
            .containing(height)
            .expect("epoch strategy is for all heights")
            .last()
            == height
    }

    /// Checks the header of a proposal before it is handed to the execution
    /// layer: the consensus context it claims and the DKG data in `extra_data`.
    ///
    /// For a boundary block, this only decodes the DKG outcome and returns it.
    /// [`Self::verify_boundary_outcome`] compares it after execution.
    #[instrument(skip_all, err(Display))]
    async fn verify_header(
        &self,
        block: &Block,
        context: &Context<Digest, PublicKey>,
    ) -> eyre::Result<Option<OnchainDkgOutcome>> {
        let round = context.round;
        let proposer = &context.leader;

        // Commonware's Deferred wrapper already checks the embedded consensus
        // context, but Inline (immediate mode) does not, so we must check it here.
        let ctx = block
            .header()
            .consensus_context
            .ok_or_eyre("missing consensus context")?;

        let expected_ctx = TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: context.parent.0.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(proposer),
        };

        ensure!(
            ctx == expected_ctx,
            "mismatch in consensus context for block `{}`. expected `{expected_ctx:?}`. got `{ctx:?}`",
            block.digest()
        );

        if self.is_boundary(block.height()) {
            let proposed_outcome =
                OnchainDkgOutcome::read(&mut block.header().extra_data().as_ref()).wrap_err(
                    "failed decoding extra data header as DKG ceremony \
                    outcome; cannot verify end of epoch block",
                )?;
            return Ok(Some(proposed_outcome));
        }

        if !block.header().extra_data().is_empty() {
            let bytes = block.header().extra_data().clone();
            let dealer = match self
                .dkg_manager
                .verify_dealer_log(round.epoch(), bytes)
                .await
            {
                Ok(dealer) => dealer.ok_or_eyre("invalid DKG dealer log")?,
                Err(reason) => {
                    warn!(%reason, "DKG dealer log verification unavailable; abstaining");
                    return std::future::pending().await;
                }
            };
            ensure!(
                &dealer == proposer,
                "proposer `{proposer}` is not the dealer `{dealer}` of the dealing \
                in the block",
            );
        }

        Ok(None)
    }

    /// Checks that a boundary block contains the DKG outcome that this node
    /// calculates for the block's `parent`.
    ///
    /// The DKG actor gives the ceremony output, and the rest of the outcome is
    /// read from the parent's state. The engine has that state once it has
    /// executed the boundary block, also when the parent is on a fork that is
    /// not canonical. So call this only after the executor has accepted the
    /// boundary block. If this node cannot calculate the outcome, that says
    /// nothing about the block. The future then stays pending and the vote is
    /// not cast.
    ///
    /// `ceremony` is the request for the ceremony output on `parent`.
    #[instrument(skip_all, err(Display))]
    async fn verify_boundary_outcome(
        &self,
        parent: &Block,
        ceremony: oneshot::Receiver<Output<MinSig, PublicKey>>,
        proposed_outcome: &OnchainDkgOutcome,
    ) -> eyre::Result<()> {
        info!("verifying that the boundary block contains the correct DKG outcome");
        let output = match ceremony.await {
            Ok(output) => output,
            Err(reason) => {
                warn!(%reason, "DKG ceremony output unavailable; abstaining");
                return std::future::pending().await;
            }
        };
        let our_outcome =
            match self
                .parent_state
                .boundary_outcome(&self.epoch_strategy, parent, output)
            {
                Ok(outcome) => outcome,
                Err(reason) => {
                    warn!(%reason, "DKG outcome unavailable; abstaining");
                    return std::future::pending().await;
                }
            };
        if &our_outcome != proposed_outcome {
            // Emit the log here so that it's structured. The error would be annoying to read.
            warn!(
                our.epoch = %our_outcome.epoch,
                our.players = ?our_outcome.players(),
                our.next_players = ?our_outcome.next_players(),
                our.sharing = ?our_outcome.sharing(),
                our.is_next_full_dkg = ?our_outcome.is_next_full_dkg,
                proposed.epoch = %proposed_outcome.epoch,
                proposed.players = ?proposed_outcome.players(),
                proposed.next_players = ?proposed_outcome.next_players(),
                proposed.sharing = ?proposed_outcome.sharing(),
                proposed.is_next_full_dkg = ?proposed_outcome.is_next_full_dkg,
                "our public dkg outcome does not match what's stored \
                in the block",
            );
            return Err(eyre!(
                "our public dkg outcome does not match what's \
                stored in the block header extra_data field; they must \
                match so that the end-of-block is valid",
            ));
        }
        Ok(())
    }
}

impl<TContext> commonware_consensus::Application<TContext> for Inner
where
    TContext: Rng + Spawner + commonware_runtime::Metrics + Clock,
{
    type SigningScheme = Scheme<PublicKey, MinSig>;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();

    /// Builds a block on the parent the wrapper resolved. A build that fails
    /// skips the proposal; the executor logs the cause.
    async fn propose(
        &mut self,
        (runtime, context): (TContext, Self::Context),
        mut ancestry: impl Ancestry<Block>,
        (): (),
    ) -> Option<Block> {
        let propose_start = Instant::now();
        let parent = ancestry.next().await?;
        match self.build(&runtime, context, &parent, propose_start).await {
            Ok(block) => {
                info!(proposal.digest = %block.digest(), "constructed proposal");
                Some(block)
            }
            Err(_logged) => None,
        }
    }

    /// Decides whether this node votes for the block. The wrapper has already
    /// checked that the block belongs to the round's epoch and extends the
    /// context's parent. A verdict the executor cannot reach leaves the vote
    /// uncast: the future stays pending until consensus cancels it.
    #[instrument(
        skip_all,
        fields(
            epoch = %context.round.epoch(),
            view = %context.round.view(),
            parent.view = %context.parent.0,
            parent.digest = %context.parent.1,
            proposer = %context.leader,
            digest = tracing::field::Empty,
        ),
    )]
    async fn verify(
        &mut self,
        (runtime, context): (TContext, Self::Context),
        mut ancestry: impl Ancestry<Block>,
    ) -> bool {
        // The consensus parent remains a convergence target even if this
        // proposal's header is invalid or its verification cannot complete
        // with our current local state.
        if let Err(error) = self
            .executor
            .report_pending_head(context.round, context.parent)
        {
            warn!(%error, "executor could not record the consensus parent; abstaining");
            return std::future::pending().await;
        }

        let Some(block) = ancestry.next().await else {
            warn!("ancestry ended before yielding the block to verify; abstaining");
            return std::future::pending().await;
        };
        tracing::Span::current().record("digest", tracing::field::display(block.digest()));

        // Only a boundary block needs its parent. The DKG actor reads no chain
        // state, so it can work on the ceremony output of a boundary block
        // while the header is checked and the block is executed.
        let boundary = if self.is_boundary(block.height()) {
            let Some(parent) = ancestry.next().await else {
                warn!("ancestry ended before yielding the parent; abstaining");
                return std::future::pending().await;
            };
            let ceremony = self.dkg_manager.subscribe_dkg_ceremony(Arc::clone(&parent));
            Some((parent, ceremony))
        } else {
            None
        };

        let proposed_outcome = match self.verify_header(&block, &context).await {
            Ok(proposed_outcome) => proposed_outcome,
            Err(reason) => {
                warn!(%reason, "header could not be verified; failing block");
                return false;
            }
        };

        match self.executor.verify_block(context, (*block).clone()).await {
            Ok(Some(duration)) => {
                if let Ok(mut estimator) = self.validation_latency_estimator.lock() {
                    estimator.observe(
                        block.height().get(),
                        ValidationLatencyWorkload::new(
                            block.block().gas_used(),
                            block.block().body().transaction_count(),
                        ),
                        duration,
                    );
                }
                // The EL has checked timestamp encoding and parent ordering.
                // Only the local clock gates voting: in deferred mode this
                // delays certification, while notarization may happen earlier.
                wait_until_timestamp(&runtime, block.timestamp_millis()).await;
            }
            Ok(None) => return false,
            Err(error) => {
                warn!(%error, "executor could not verify the block; abstaining");
                return std::future::pending().await;
            }
        }

        // Only a boundary block carries a DKG outcome. Compare it after
        // `verify_block`: our outcome reads the parent's state, which the
        // engine has only once it has executed the block.
        match proposed_outcome {
            None => true,
            Some(outcome) => {
                let (parent, ceremony) =
                    boundary.expect("`verify_header` decodes an outcome only for a boundary block");
                self.verify_boundary_outcome(&parent, ceremony, &outcome)
                    .await
                    .is_ok()
            }
        }
    }
}

impl Reporter for Inner {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// Waits for a validated block's timestamp without making a validity decision.
async fn wait_until_timestamp(runtime: &impl Clock, timestamp: u64) {
    while runtime.current().epoch_millis() < timestamp {
        runtime
            .sleep_until(std::time::UNIX_EPOCH + Duration::from_millis(timestamp))
            .await;
    }
}

#[derive(Clone)]
struct Metrics {
    parent_ahead_of_local_time: Counter,
}

impl Metrics {
    fn init<TContext: commonware_runtime::Metrics>(context: &TContext) -> Self {
        let parent_ahead_of_local_time = context.counter(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time when proposing",
        );

        Self {
            parent_ahead_of_local_time,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn future_header_waits_for_local_clock_before_certification() {
        deterministic::Runner::default().start(|context| async move {
            let now = context.current().epoch_millis();
            let mut verification = std::pin::pin!(wait_until_timestamp(&context, now + 100));
            assert!(verification.as_mut().now_or_never().is_none());
            context.sleep(Duration::from_millis(99)).await;
            assert!(verification.as_mut().now_or_never().is_none());
            context.sleep(Duration::from_millis(1)).await;
            verification.await;
            // A validator whose clock has caught up reaches the same verdict.
            assert!(
                wait_until_timestamp(&context, now + 100)
                    .now_or_never()
                    .is_some()
            );
        });
    }
}
