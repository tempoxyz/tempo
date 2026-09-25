//! Feeds view outcomes into the shared proposal budget estimator.

use std::sync::Arc;

use commonware_actor::Feedback;
use commonware_consensus::{Reporter, simplex::types::Activity};
use tempo_payload_types::Estimator;

/// Wraps the marshal's simplex reporter and records views that were
/// nullified, so the estimator drops the pending network sample of a
/// proposal the chain never built on.
///
/// Successful proposals complete their sample through the header timestamp of
/// the block built on top of them, which the application actor observes when
/// it verifies or builds that block.
#[derive(Clone)]
pub(super) struct EstimatorReporter {
    inner: crate::alias::marshal::Mailbox,
    estimator: Arc<Estimator>,
}

impl EstimatorReporter {
    pub(super) fn new(inner: crate::alias::marshal::Mailbox, estimator: Arc<Estimator>) -> Self {
        Self { inner, estimator }
    }
}

impl Reporter for EstimatorReporter {
    type Activity = <crate::alias::marshal::Mailbox as Reporter>::Activity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Activity::Nullification(nullification) = &activity {
            let round = nullification.round();
            self.estimator
                .on_view_abandoned((round.epoch().get(), round.view().get()));
        }
        self.inner.report(activity)
    }
}
