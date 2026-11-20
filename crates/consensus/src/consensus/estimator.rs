//! Feeds finalized blocks back into the proposal [`Estimator`].
//!
//! A finalized block whose parent this node proposed gives the estimator a
//! network sample: the time from the parent's return to the child's header
//! timestamp. [`Reporter`] takes marshal's updates and records those samples.

use std::{sync::atomic::AtomicU64, time::Instant};

use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _,
    marshal::Update,
    types::{Epocher as _, FixedEpocher},
};
use commonware_runtime::telemetry::metrics::{Counter, MetricsExt as _, Registered};
use commonware_utils::Acknowledgement as _;
use tempo_payload_types::{Estimator, EstimatorSnapshot, ProposalKey};

use crate::consensus::Block;

/// Records network samples from finalized blocks; installed as one of marshal's reporters.
#[derive(Clone)]
pub(crate) struct Reporter {
    estimator: Estimator,
    epoch_strategy: FixedEpocher,
    metrics: Metrics,
}

impl Reporter {
    pub(crate) fn new(
        estimator: Estimator,
        epoch_strategy: FixedEpocher,
        metrics: Metrics,
    ) -> Self {
        Self {
            estimator,
            epoch_strategy,
            metrics,
        }
    }
}

impl commonware_consensus::Reporter for Reporter {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Block(block, ack) = update {
            // Sampling only feeds pacing, so marshal need not wait for it.
            ack.acknowledge();
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
            self.metrics
                .observe(&self.estimator.snapshot(Instant::now()));
        }
        Feedback::Ok
    }
}

/// The estimator's metrics, updated by the application after its own
/// proposals and by [`Reporter`] after finalized blocks.
#[derive(Clone)]
pub(crate) struct Metrics {
    network_samples: Counter,
    /// Network reservation the most recent own proposal subtracted from the
    /// target block time.
    network_reserve_seconds: FloatGauge,
    /// Unclamped adaptive network reservation target, including warm-up and
    /// fast rise. Zero in fixed mode or without live network feedback.
    network_target_seconds: FloatGauge,
    /// Proposal return budget of the most recent own proposal.
    proposal_return_budget_seconds: FloatGauge,
    /// Recent P90 execution-layer validation time.
    validation_latency_p90_seconds: FloatGauge,
    /// Build time multiplier in use.
    build_time_multiplier: FloatGauge,
    /// Finish a build reserves once its pool ran dry.
    dry_build_finish_seconds: FloatGauge,
}

/// A gauge that holds a fractional value, such as seconds or a ratio.
type FloatGauge = Registered<prometheus_client::metrics::gauge::Gauge<f64, AtomicU64>>;

impl Metrics {
    pub(crate) fn init<TContext: commonware_runtime::Metrics>(context: &TContext) -> Self {
        let float_gauge = |name: &str, help: &str| -> FloatGauge {
            context.register(name, help, Default::default())
        };

        Self {
            network_samples: context.counter(
                "network_samples",
                "number of network samples recorded from finalized successors of own proposals",
            ),
            network_reserve_seconds: float_gauge(
                "estimator_network_reserve_seconds",
                "network allowance covering propagation, votes, unprojected validation and next-proposal preparation",
            ),
            network_target_seconds: float_gauge(
                "estimator_network_target_seconds",
                "unclamped adaptive network reservation target including warm-up and fast rise; zero in fixed mode or without live samples",
            ),
            proposal_return_budget_seconds: float_gauge(
                "estimator_proposal_return_budget_seconds",
                "local proposal return budget of the most recent own proposal",
            ),
            validation_latency_p90_seconds: float_gauge(
                "estimator_validation_latency_p90_seconds",
                "recent p90 execution-layer block validation time",
            ),
            build_time_multiplier: float_gauge(
                "estimator_build_time_multiplier",
                "payload build time multiplier in use",
            ),
            dry_build_finish_seconds: float_gauge(
                "estimator_dry_build_finish_seconds",
                "finish reserved by payload builds whose pool ran dry",
            ),
        }
    }

    pub(crate) fn observe(&self, snapshot: &EstimatorSnapshot) {
        self.network_reserve_seconds
            .set(snapshot.network_reserve.as_secs_f64());
        self.network_target_seconds
            .set(snapshot.network_target.map_or(0.0, |d| d.as_secs_f64()));
        self.proposal_return_budget_seconds
            .set(snapshot.proposal_return_budget.as_secs_f64());
        self.validation_latency_p90_seconds.set(
            snapshot
                .validation_latency_p90
                .map_or(0.0, |d| d.as_secs_f64()),
        );
        self.build_time_multiplier
            .set(snapshot.build_time_multiplier);
        self.dry_build_finish_seconds
            .set(snapshot.dry_build_finish.as_secs_f64());
    }
}
