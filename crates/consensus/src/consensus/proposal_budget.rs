use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use commonware_consensus::types::Round;
use tracing::{debug, warn};

use super::Digest;

const MIN_TAIL_BUDGET: Duration = Duration::from_millis(10);
const MIN_PROPOSAL_BUDGET: Duration = Duration::from_millis(50);
const MAX_TRACKED_PROPOSALS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProposalPacing {
    /// Local proposal window before the post-return tail starts.
    pub(crate) proposal_return_budget: Duration,
    /// Observed time from returning our proposal to seeing its notarization.
    ///
    /// When present, this replaces the normal validator-side reserve for SSMR.
    pub(crate) post_return_tail: Option<Duration>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProposalBudgetHandle {
    inner: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    target_block_time: Duration,
    static_network_budget: Duration,
    max_tail_budget: Duration,
    tail_budget: Option<Duration>,
    proposal_returns: BTreeMap<Round, (Digest, u64)>,
    latest_observed_round: Option<Round>,
}

impl ProposalBudgetHandle {
    pub(crate) fn new(target_block_time: Duration, static_network_budget: Duration) -> Self {
        let max_tail_budget = target_block_time
            .saturating_sub(MIN_PROPOSAL_BUDGET)
            .max(MIN_TAIL_BUDGET);

        Self {
            inner: Arc::new(Mutex::new(State {
                target_block_time,
                static_network_budget,
                max_tail_budget,
                tail_budget: None,
                proposal_returns: BTreeMap::new(),
                latest_observed_round: None,
            })),
        }
    }

    pub(crate) fn pacing(&self, use_adaptive_tail: bool) -> ProposalPacing {
        let state = self.inner.lock().expect("proposal budget lock poisoned");
        let post_return_tail = use_adaptive_tail.then_some(state.tail_budget).flatten();
        let proposal_return_budget = if let Some(tail) = post_return_tail {
            state.target_block_time.saturating_sub(tail)
        } else {
            state
                .target_block_time
                .saturating_sub(state.static_network_budget)
        };

        ProposalPacing {
            proposal_return_budget,
            post_return_tail,
        }
    }

    pub(crate) fn record_proposal_return(&self, round: Round, digest: Digest) {
        self.record_proposal_return_at(round, digest, now_millis());
    }

    pub(crate) fn observe_notarization(&self, round: Round, digest: Digest, seen_at_millis: u64) {
        self.observe_notarization_at(round, digest, seen_at_millis);
    }

    fn record_proposal_return_at(&self, round: Round, digest: Digest, returned_at_millis: u64) {
        let mut state = self.inner.lock().expect("proposal budget lock poisoned");
        state
            .proposal_returns
            .insert(round, (digest, returned_at_millis));
        while state.proposal_returns.len() > MAX_TRACKED_PROPOSALS {
            state.proposal_returns.pop_first();
        }
    }

    fn observe_notarization_at(&self, round: Round, digest: Digest, seen_at_millis: u64) {
        let mut state = self.inner.lock().expect("proposal budget lock poisoned");
        if state
            .latest_observed_round
            .is_some_and(|latest| latest >= round)
        {
            return;
        }

        let Some((proposal_digest, returned_at_millis)) = state.proposal_returns.remove(&round)
        else {
            return;
        };
        if proposal_digest != digest {
            debug!(
                ?round,
                expected = ?proposal_digest,
                observed = ?digest,
                "ignoring notarization for different local proposal digest"
            );
            return;
        }

        let Some(elapsed_millis) = seen_at_millis.checked_sub(returned_at_millis) else {
            warn!(
                ?round,
                returned_at_millis,
                seen_at_millis,
                "ignoring notarization tail with non-monotonic wall clock"
            );
            return;
        };

        let sample = clamp_tail(Duration::from_millis(elapsed_millis), state.max_tail_budget);
        let next_tail = match state.tail_budget {
            Some(current) => ewma(current, sample),
            None => sample,
        };
        state.tail_budget = Some(next_tail);
        state.latest_observed_round = Some(round);
        state
            .proposal_returns
            .retain(|&proposal_round, _| proposal_round > round);

        debug!(
            ?round,
            observed_tail = ?sample,
            adaptive_tail = ?next_tail,
            proposal_return_budget = ?state.target_block_time.saturating_sub(next_tail),
            "updated adaptive proposal budget from local notarization tail"
        );
    }
}

fn clamp_tail(tail: Duration, max_tail_budget: Duration) -> Duration {
    tail.clamp(MIN_TAIL_BUDGET, max_tail_budget)
}

fn ewma(current: Duration, sample: Duration) -> Duration {
    let next = current
        .as_nanos()
        .saturating_mul(3)
        .saturating_add(sample.as_nanos())
        / 4;
    Duration::from_nanos(next.min(u128::from(u64::MAX)) as u64)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use commonware_consensus::types::{Epoch, View};

    use super::*;

    fn round(view: u64) -> Round {
        Round::new(Epoch::new(0), View::new(view))
    }

    fn digest(byte: u8) -> Digest {
        Digest(B256::repeat_byte(byte))
    }

    #[test]
    fn uses_static_budget_before_samples() {
        let budget =
            ProposalBudgetHandle::new(Duration::from_millis(550), Duration::from_millis(50));

        assert_eq!(
            budget.pacing(true),
            ProposalPacing {
                proposal_return_budget: Duration::from_millis(500),
                post_return_tail: None,
            }
        );
    }

    #[test]
    fn learns_tail_from_matching_local_proposal() {
        let budget =
            ProposalBudgetHandle::new(Duration::from_millis(550), Duration::from_millis(50));

        budget.record_proposal_return_at(round(1), digest(1), 1_000);
        budget.observe_notarization_at(round(1), digest(1), 1_100);

        assert_eq!(
            budget.pacing(true),
            ProposalPacing {
                proposal_return_budget: Duration::from_millis(450),
                post_return_tail: Some(Duration::from_millis(100)),
            }
        );
    }

    #[test]
    fn ignores_notarization_for_another_digest() {
        let budget =
            ProposalBudgetHandle::new(Duration::from_millis(550), Duration::from_millis(50));

        budget.record_proposal_return_at(round(1), digest(1), 1_000);
        budget.observe_notarization_at(round(1), digest(2), 1_100);

        assert_eq!(budget.pacing(true).post_return_tail, None);
    }

    #[test]
    fn static_pacing_ignores_adaptive_samples() {
        let budget =
            ProposalBudgetHandle::new(Duration::from_millis(550), Duration::from_millis(50));

        budget.record_proposal_return_at(round(1), digest(1), 1_000);
        budget.observe_notarization_at(round(1), digest(1), 1_100);

        assert_eq!(
            budget.pacing(false),
            ProposalPacing {
                proposal_return_budget: Duration::from_millis(500),
                post_return_tail: None,
            }
        );
    }
}
