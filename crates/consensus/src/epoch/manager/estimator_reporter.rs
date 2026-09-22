//! Feeds notarization timing into the shared proposal budget estimator.

use std::{sync::Arc, time::Instant};

use commonware_actor::Feedback;
use commonware_consensus::{Reporter, simplex::types::Activity};
use tempo_payload_types::Estimator;

/// Wraps the marshal's simplex reporter and records when this node learns
/// that a view was notarized or nullified.
///
/// The estimator only keeps samples for proposals this node returned itself,
/// so feeding it every notarization is cheap and lets it complete the
/// return-to-notarization round trip of its own proposals.
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
        let now = Instant::now();
        match &activity {
            Activity::Notarization(notarization) | Activity::Certification(notarization) => {
                let round = notarization.round();
                self.estimator
                    .on_notarized(now, (round.epoch().get(), round.view().get()));
            }
            Activity::Nullification(nullification) => {
                let round = nullification.round();
                self.estimator
                    .on_view_abandoned((round.epoch().get(), round.view().get()));
            }
            _ => {}
        }
        self.inner.report(activity)
    }
}
