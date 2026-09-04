//! Reporter implementations for various standard types.

use crate::Reporter;
use commonware_actor::Feedback;
use std::marker::PhantomData;

/// An implementation of [Reporter] for an optional [Reporter].
///
/// This is useful for reporting activity to a [Reporter] that may not be present.
/// Reporting is ignored if the [Reporter] is `None`.
impl<A: Send, R: Reporter<Activity = A>> Reporter for Option<R> {
    type Activity = A;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Some(reporter) = self else {
            return Feedback::Ok;
        };
        reporter.report(activity)
    }
}

/// A struct used to report activity to multiple [Reporter]s (which may or may not be present).
#[derive(Clone)]
pub struct Reporters<A, R1, R2> {
    r1: Option<R1>,
    r2: Option<R2>,

    _phantom: PhantomData<A>,
}

impl<A, R1, R2> Reporter for Reporters<A, R1, R2>
where
    A: Clone + Send + 'static,
    R1: Reporter<Activity = A>,
    R2: Reporter<Activity = A>,
{
    type Activity = A;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // This approach avoids cloning activity, if possible.
        match (&mut self.r1, &mut self.r2) {
            (Some(r1), Some(r2)) => combine(r1.report(activity.clone()), r2.report(activity)),
            (Some(r1), None) => r1.report(activity),
            (None, Some(r2)) => r2.report(activity),
            (None, None) => Feedback::Ok,
        }
    }
}

const fn combine(a: Feedback, b: Feedback) -> Feedback {
    match (a, b) {
        (Feedback::Closed, _) | (_, Feedback::Closed) => Feedback::Closed,
        (Feedback::Backoff, _) | (_, Feedback::Backoff) => Feedback::Backoff,
        (Feedback::Ok, Feedback::Ok) => Feedback::Ok,
    }
}

impl<A, R1, R2> From<(Option<R1>, Option<R2>)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (Option<R1>, Option<R2>)) -> Self {
        Self {
            r1,
            r2,
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(Option<R1>, R2)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (Option<R1>, R2)) -> Self {
        Self {
            r1,
            r2: Some(r2),
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(R1, Option<R2>)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (R1, Option<R2>)) -> Self {
        Self {
            r1: Some(r1),
            r2,
            _phantom: PhantomData,
        }
    }
}

impl<A, R1, R2> From<(R1, R2)> for Reporters<A, R1, R2> {
    fn from((r1, r2): (R1, R2)) -> Self {
        Self {
            r1: Some(r1),
            r2: Some(r2),
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::Feedback;
    use commonware_utils::acknowledgement::{Acknowledgement, Exact};
    use futures::FutureExt;

    #[derive(Clone, Debug)]
    struct SimpleAcknowledger;

    impl crate::Reporter for SimpleAcknowledger {
        type Activity = Exact;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            activity.acknowledge();
            Feedback::Ok
        }
    }

    #[test]
    fn optional_branch_acknowledges() {
        let mut reporters = Reporters::<Exact, SimpleAcknowledger, SimpleAcknowledger>::from((
            Some(SimpleAcknowledger),
            None,
        ));

        let (ack, waiter) = Exact::handle();
        assert_eq!(reporters.report(ack), Feedback::Ok);

        assert!(
            waiter.now_or_never().unwrap().is_ok(),
            "Waiter did not resolve successfully"
        );
    }

    #[test]
    fn absent_reporter_ignores_activity() {
        let mut reporter = Option::<SimpleAcknowledger>::None;
        let (ack, waiter) = Exact::handle();
        assert_eq!(reporter.report(ack), Feedback::Ok);
        assert!(waiter.now_or_never().unwrap().is_err());
    }

    #[test]
    fn combine_returns_worst_feedback() {
        assert_eq!(
            combine(Feedback::Closed, Feedback::Backoff),
            Feedback::Closed
        );
        assert_eq!(combine(Feedback::Backoff, Feedback::Ok), Feedback::Backoff);
        assert_eq!(combine(Feedback::Ok, Feedback::Ok), Feedback::Ok);
    }
}
