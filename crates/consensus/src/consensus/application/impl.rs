//! Tempo's block building and verification.

use std::{
    num::NonZeroU64,
    sync::Arc,
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
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    Digested, Digestible as _,
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::MinSig},
    ed25519::PublicKey,
};
use commonware_runtime::{
    Clock, Spawner,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_utils::{Acknowledgement as _, SystemTimeExt as _};
use eyre::{OptionExt as _, WrapErr as _, ensure};
use futures::{FutureExt as _, StreamExt as _, channel::oneshot};
use rand_core::Rng;
use reth_evm::database::StateProviderDatabase;
use reth_primitives_traits::BlockBody as _;
use reth_provider::StateProviderFactory as _;
use tempo_chainspec::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_evm::{BoundaryOutcomeChecks, TempoStateAccess as _};
use tempo_node::TempoFullNode;
use tempo_payload_types::{
    Estimator, ProposalKey, ProposalTiming, TempoPayloadAttributes, ValidationLatencyWorkload,
};
use tempo_primitives::TempoConsensusContext;
use tempo_telemetry_util::display_duration;
use tracing::{Level, debug, info, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    executor::DeferredCeremonyOutput,
};

pub(in crate::consensus) struct Config<TContext> {
    /// Registers the application's metrics; spawns its work.
    pub(in crate::consensus) context: TContext,

    /// This node's ed25519 public key, used to look up the fee recipient from
    /// the validator config v2 contract.
    pub(in crate::consensus) public_key: PublicKey,

    pub(in crate::consensus) executor: crate::executor::Mailbox,

    pub(in crate::consensus) dkg_manager: crate::dkg::manager::Mailbox,

    /// Proposal pacing and execution feedback shared with the payload builder.
    pub(in crate::consensus) estimator: Estimator,

    /// The epoch strategy used by tempo, to map block heights to epochs.
    pub(in crate::consensus) epoch_strategy: FixedEpocher,

    /// Boundary blocks whose DKG outcome execution checked against the parent state.
    pub(in crate::consensus) boundary_outcome_checks: BoundaryOutcomeChecks,

    /// Reads the parent state to check a boundary block again when execution
    /// recorded no verdict on it.
    pub(in crate::consensus) execution_node: Arc<TempoFullNode>,
}

/// Tempo's block builder and verifier, see the module documentation.
#[derive(Clone)]
pub(crate) struct Inner {
    public_key: PublicKey,
    epoch_strategy: FixedEpocher,
    /// Shared proposal pacing and execution feedback.
    estimator: Estimator,

    executor: crate::executor::Mailbox,
    dkg_manager: crate::dkg::manager::Mailbox,
    boundary_outcome_checks: BoundaryOutcomeChecks,
    execution_node: Arc<TempoFullNode>,

    metrics: Metrics,
}

impl Inner {
    pub(in crate::consensus) fn new<TContext: commonware_runtime::Metrics>(
        config: Config<TContext>,
    ) -> Self {
        Self {
            public_key: config.public_key,
            epoch_strategy: config.epoch_strategy,
            estimator: config.estimator,
            executor: config.executor,
            dkg_manager: config.dkg_manager,
            boundary_outcome_checks: config.boundary_outcome_checks,
            execution_node: config.execution_node,
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
        parent: &Digested<Block>,
        propose_start: Instant,
    ) -> eyre::Result<Block> {
        self.executor
            .report_pending_head(context.round, context.parent)?;

        let Context {
            round,
            leader,
            parent: (parent_view, parent_digest),
        } = context;

        let (extra_data, deferred_ceremony_output) = if self.is_boundary(parent.height().next()) {
            // The boundary block carries the DKG outcome. Consensus supplies the
            // ceremony output on the parent, and the payload builder fills in
            // the rest from the parent state.
            //
            // The DKG actor reads no chain state, so it starts on the
            // ceremony output now, while the executor delivers the parent.
            let ceremony = self.dkg_manager.subscribe_dkg_ceremony(parent.clone());
            (
                Bytes::default(),
                Some(deferred_ceremony_output(parent.digest(), ceremony)),
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

        // The proposal window opens at the clock reading the header timestamp is taken
        // from: block times are measured between header timestamps, so pacing from any
        // earlier instant would charge the preparation above twice, here and in the
        // previous proposer's network sample.
        let window_opened = Instant::now();
        let mut epoch_millis = runtime.current().epoch_millis();

        // Use current timestamp but make sure that if parent's timestamp is in the future, we account for that.
        if epoch_millis <= parent.inner().timestamp_millis() {
            self.metrics.parent_ahead_of_local_time.metric().inc();
            epoch_millis = parent.inner().timestamp_millis() + 1
        };

        // Match the stamped header so a lagging local clock does not inflate network samples.
        let window_opened_millis = epoch_millis;
        let (timestamp, timestamp_millis_part) = (epoch_millis / 1000, epoch_millis % 1000);

        let consensus_context = Some(TempoConsensusContext {
            epoch: round.epoch().get(),
            view: round.view().get(),
            parent_view: parent_view.get(),
            proposer: crate::utils::public_key_to_tempo_primitive(&leader),
        });

        let proposer_public_key = crate::utils::public_key_to_b256(&self.public_key);
        // Charge preparation only through the peer-timeout cap, not twice to
        // adjacent proposers' windows.
        let proposal_budget = self.estimator.start_proposal(
            window_opened,
            window_opened.saturating_duration_since(propose_start),
        );
        let return_budget = proposal_budget.return_budget();
        let build_budget = return_budget.saturating_sub(window_opened.elapsed());
        let attrs = TempoPayloadAttributes::new(
            Some(proposer_public_key),
            timestamp,
            timestamp_millis_part,
            extra_data,
            consensus_context,
        )
        .with_payload_build_budget(build_budget);

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
                deferred_ceremony_output,
            )?
            .await
            .wrap_err(
                "executor dropped the payload channel: the build failed (the \
                executor logs the cause) or the executor shut down",
            )?;

        let payload_build_elapsed = payload_build_start.elapsed();
        let payload_validation_work_elapsed = payload.validation_work_duration();
        let validation_latency_elapsed = payload.validation_latency_duration();
        let (block, execution_block_encoded) = payload.into_consensus_execution_payload();
        let proposal = Block::from_execution_block_unchecked_with_encoded_cache(
            block,
            execution_block_encoded,
        );
        let proposal_elapsed = window_opened.elapsed();
        // Reserve the full validation estimate when pacing an early-finished proposal.
        let return_after = return_budget.saturating_sub(validation_latency_elapsed);
        let return_delay = return_after.saturating_sub(proposal_elapsed);
        // Sample eligibility follows the builder's capped replay reserve, so builds that
        // return on its schedule are not mistaken for overruns when validators are slower.
        let sampling_replay_reserve =
            validation_latency_elapsed.min(payload_validation_work_elapsed);
        // Add replay before comparing budgets so a saturated target cannot hide excess work.
        let spent = return_budget.max(proposal_elapsed.saturating_add(sampling_replay_reserve));
        debug!(
            proposal.digest = %proposal.digest(),
            proposal_elapsed = %display_duration(proposal_elapsed),
            build_time = %display_duration(payload_build_elapsed),
            payload_validation_work = %display_duration(payload_validation_work_elapsed),
            validation_latency_time = %display_duration(validation_latency_elapsed),
            return_time = %display_duration(return_delay),
            "sleeping before returning proposal"
        );
        runtime
            .sleep(return_after.saturating_sub(window_opened.elapsed()))
            .await;

        // Record both clocks at return; the estimator owns sampling eligibility.
        let recorded = self.estimator.on_proposal_returned(
            Instant::now(),
            proposal_budget,
            ProposalTiming {
                key: ProposalKey {
                    epoch: round.epoch().get(),
                    view: round.view().get(),
                },
                window_opened_millis,
                returned_millis: runtime.current().epoch_millis(),
                elapsed: spent,
            },
        );
        if !recorded {
            debug!(
                proposal.digest = %proposal.digest(),
                overrun = %display_duration(spent.saturating_sub(return_budget)),
                "proposal overran its return budget; taking no network sample"
            );
        }

        #[cfg(feature = "fuzz")]
        antithesis_sdk::assert_sometimes!(
            round.view().get().saturating_sub(parent_view.get()) > 1,
            "Proposal builds on a parent from before a nullified view",
            &serde_json::json!({
                "epoch": round.epoch().get(),
                "view": round.view().get(),
                "parent_view": parent_view.get(),
            })
        );

        Ok(proposal)
    }

    /// Checks the DKG outcome of the boundary block `block` against the state
    /// of its parent, as execution does, and records the verdict. For a block
    /// on which execution recorded no verdict.
    ///
    /// Fails if the parent state cannot be read, such as for a parent that is
    /// not on the canonical chain.
    fn recheck_boundary_outcome(
        &self,
        block: &Block,
        proposed: &OnchainDkgOutcome,
    ) -> eyre::Result<bool> {
        let header = block.header();
        let chain_spec = self.execution_node.chain_spec();
        let state = self
            .execution_node
            .provider
            .state_by_block_hash(header.parent_hash())
            .wrap_err("failed reading the parent state")?;
        let block_number = header.number();
        let config = StateProviderDatabase::new(state)
            .dkg_ceremony_config(
                chain_spec.tempo_hardfork_at(header.timestamp()),
                block_number,
            )
            .wrap_err("failed reading ValidatorConfigV2 in the parent state")?;
        // Before ValidatorConfigV2 was initialized, the players came from
        // ValidatorConfig V1.
        let matches = config.is_none_or(|config| {
            let epoch_length = chain_spec
                .info
                .epoch_length()
                .unwrap_or(NonZeroU64::MIN)
                .get();
            config.boundary_outcome(block_number / epoch_length + 1, proposed.output.clone())
                == *proposed
        });
        info!(
            matches,
            "checked the boundary block's DKG outcome against the parent state again"
        );
        self.boundary_outcome_checks
            .record(block.digest().0, matches);
        Ok(matches)
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
    /// [`Self::verify_boundary_output`] compares its ceremony output after
    /// execution, and execution checks the rest of it at this node's request.
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
            let proposed_outcome = OnchainDkgOutcome::read(&mut commonware_codec::Copying(
                block.header().extra_data().as_ref(),
            ))
            .wrap_err(
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

    /// Checks that a boundary block contains the DKG ceremony output that this
    /// node calculates for the block's `parent`. Execution checks the rest of
    /// the outcome against the parent state when this node asks it to.
    ///
    /// If this node cannot calculate the output, that says nothing about the
    /// block. The future then stays pending and the vote is not cast.
    ///
    /// `ceremony` is the request for the ceremony output on the parent.
    #[instrument(skip_all, err(Display))]
    async fn verify_boundary_output(
        &self,
        ceremony: oneshot::Receiver<Output<MinSig, PublicKey>>,
        proposed_outcome: &OnchainDkgOutcome,
    ) -> eyre::Result<()> {
        info!("verifying that the boundary block contains the correct DKG ceremony output");
        let output = match ceremony.await {
            Ok(output) => output,
            Err(reason) => {
                warn!(%reason, "DKG ceremony output unavailable; abstaining");
                return std::future::pending().await;
            }
        };
        ensure!(
            output == proposed_outcome.output,
            "our DKG ceremony output does not match the one stored in the \
            block header extra_data field",
        );
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
    ) -> Option<Digested<Block>> {
        let propose_start = Instant::now();
        let parent = ancestry.next().await?;
        match self.build(&runtime, context, &parent, propose_start).await {
            Ok(block) => {
                let digest = block.digest();
                info!(proposal.digest = %digest, "constructed proposal");
                Some(Digested::precomputed(block, digest))
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

        // Only a boundary block needs its parent, to request the ceremony
        // output on it. The DKG actor reads no chain state, so it can work on
        // the ceremony output while the header is checked and the block is
        // executed.
        let ceremony = if self.is_boundary(block.height()) {
            let Some(parent) = ancestry.next().await else {
                warn!("ancestry ended before yielding the parent; abstaining");
                return std::future::pending().await;
            };
            Some(self.dkg_manager.subscribe_dkg_ceremony(parent))
        } else {
            None
        };

        let proposed_outcome = match self.verify_header(block.inner(), &context).await {
            Ok(proposed_outcome) => proposed_outcome,
            Err(reason) => {
                warn!(%reason, "header could not be verified; failing block");
                return false;
            }
        };

        match self.executor.verify_block(context, block.clone()).await {
            Ok(Some(duration)) => {
                self.estimator.on_block_verified(
                    block.height().get(),
                    ValidationLatencyWorkload::new(
                        block.inner().block().gas_used(),
                        block.inner().block().body().transaction_count(),
                    ),
                    duration,
                );
                // The EL has checked timestamp encoding and parent ordering.
                // Only the local clock gates voting: in deferred mode this
                // delays certification, while notarization may happen earlier.
                wait_until_timestamp(&runtime, block.inner().timestamp_millis()).await;
            }
            Ok(None) => return false,
            Err(error) => {
                warn!(%error, "executor could not verify the block; abstaining");
                return std::future::pending().await;
            }
        }

        // Only a boundary block carries a DKG outcome. Every execution of it
        // checks all of it but the ceremony output against the parent state,
        // including one the execution layer ran without being asked to enforce
        // the check, such as a block it buffered until its parent arrived. If
        // no verdict is recorded, for example because later executions pushed
        // it out, the check runs again here.
        match proposed_outcome {
            None => true,
            Some(outcome) => {
                match self.boundary_outcome_checks.verdict(block.digest().0) {
                    Some(true) => {}
                    Some(false) => {
                        warn!(
                            "the boundary block's DKG outcome does not match the parent \
                            state; failing block"
                        );
                        return false;
                    }
                    None => match self.recheck_boundary_outcome(block.inner(), &outcome) {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(
                                "the boundary block's DKG outcome does not match the parent \
                                state; failing block"
                            );
                            return false;
                        }
                        Err(error) => {
                            warn!(
                                %error,
                                "execution recorded no verdict on the boundary block's DKG \
                                outcome, and the parent state could not be read; abstaining"
                            );
                            return std::future::pending().await;
                        }
                    },
                }
                let ceremony =
                    ceremony.expect("`verify_header` decodes an outcome only for a boundary block");
                self.verify_boundary_output(ceremony, &outcome)
                    .await
                    .is_ok()
            }
        }
    }
}

impl Reporter for Inner {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(block, ack) = update {
            // Only finalized children supply canonical sampling observations.
            // Derive the parent's epoch from its height, not the child's epoch.
            if let Some(ctx) = block.inner().header().consensus_context
                && let Some(parent_height) = block.height().previous()
            {
                let parent_epoch = self
                    .epoch_strategy
                    .containing(parent_height)
                    .expect("epoch strategy is for all heights");
                if self.estimator.on_child_block_finalized(
                    Instant::now(),
                    ProposalKey {
                        epoch: parent_epoch.epoch().get(),
                        view: ctx.parent_view,
                    },
                    ProposalKey {
                        epoch: ctx.epoch,
                        view: ctx.view,
                    },
                    block.inner().timestamp_millis(),
                ) {
                    self.metrics.network_samples.metric().inc();
                }
            }
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
    network_samples: Counter,
}

impl Metrics {
    fn init<TContext: commonware_runtime::Metrics>(context: &TContext) -> Self {
        let parent_ahead_of_local_time = context.counter(
            "parent_ahead_of_local_time",
            "number of times the parent block timestamp was ahead of local time when proposing",
        );

        let network_samples = context.counter(
            "network_samples",
            "number of network samples recorded from finalized successors of own proposals",
        );
        Self {
            parent_ahead_of_local_time,
            network_samples,
        }
    }
}

/// Defers the DKG ceremony output on the parent `parent_digest` until the
/// executor has delivered that parent.
///
/// `ceremony` is the request for the ceremony output on that parent.
fn deferred_ceremony_output(
    parent_digest: Digest,
    ceremony: oneshot::Receiver<Output<MinSig, PublicKey>>,
) -> DeferredCeremonyOutput {
    DeferredCeremonyOutput::new(move |parent| {
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
            info!(
                output.network_identity = %output.public().public(),
                output.dealers = ?output.dealers(),
                output.players = ?output.players(),
                "received DKG ceremony output; will include in payload builder attributes",
            );
            Ok(output)
        }
        .boxed()
    })
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
