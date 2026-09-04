use super::round::Round;
use crate::{
    simplex::{
        elector::{Config as ElectorConfig, Elector},
        interesting,
        metrics::{Leader, Timeout, TimeoutReason},
        min_active,
        scheme::Scheme,
        types::{
            Artifact, Certificate, Context, Finalization, Finalize, Notarization, Notarize,
            Nullification, Nullify, Proposal,
        },
        Floor,
    },
    types::{Epoch, Participant, Round as Rnd, View, ViewDelta},
    Viewable,
};
use commonware_cryptography::{certificate, Digest};
use commonware_runtime::{
    telemetry::metrics::{CounterFamily, Gauge, GaugeExt, MetricsExt as _},
    Clock, Metrics,
};
use commonware_utils::futures::Aborter;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{replace, take},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn, Span};

/// The view number of the genesis block.
const GENESIS_VIEW: View = View::zero();

/// Reasons a proposal's ancestry cannot yet produce a verification context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum ParentPayloadError {
    #[error("proposal view {proposal_view} is not after parent view {parent_view}")]
    ParentNotBeforeProposal {
        proposal_view: View,
        parent_view: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} below last finalized view {last_finalized}"
    )]
    ParentBeforeFinalized {
        proposal_view: View,
        parent_view: View,
        last_finalized: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} but view {missing_view} is not nullified"
    )]
    MissingNullification {
        proposal_view: View,
        parent_view: View,
        missing_view: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} but the parent is not certified"
    )]
    ParentNotCertified {
        proposal_view: View,
        parent_view: View,
    },
}

impl ParentPayloadError {
    /// Returns whether the ancestry error permanently invalidates the proposal.
    const fn invalid_proposal(self) -> bool {
        match self {
            Self::ParentNotBeforeProposal { .. } | Self::ParentBeforeFinalized { .. } => true,
            Self::MissingNullification { .. } | Self::ParentNotCertified { .. } => false,
        }
    }
}

/// Configuration for initializing [`State`].
pub struct Config<S: certificate::Scheme, L: ElectorConfig<S>> {
    pub scheme: S,
    pub elector: L,
    pub epoch: Epoch,
    pub activity_timeout: ViewDelta,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
}

/// Per-[Epoch] state machine.
///
/// Tracks proposals and certificates for each view. Vote aggregation and verification
/// is handled by the [crate::simplex::actors::batcher].
pub struct State<E: Clock + CryptoRng + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest> {
    context: E,
    scheme: S,
    elector: L::Elector,
    epoch: Epoch,
    activity_timeout: ViewDelta,
    leader_timeout: Duration,
    certification_timeout: Duration,
    timeout_retry: Duration,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,

    certification_candidates: BTreeSet<View>,
    outstanding_certifications: BTreeSet<View>,

    current_view: Gauge,
    tracked_views: Gauge,
    timeouts: CounterFamily<Timeout>,
    nullifications: CounterFamily<Leader<S::PublicKey>>,
}

impl<E: Clock + CryptoRng + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest>
    State<E, S, L, D>
{
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        let current_view = context.gauge("current_view", "current view");
        let tracked_views = context.gauge("tracked_views", "tracked views");
        let timeouts = context.family("timeouts", "timed out views");
        let nullifications = context.family("nullifications", "nullifications");

        // Build elector with participants
        let elector = cfg.elector.build(cfg.scheme.participants());

        Self {
            context,
            scheme: cfg.scheme,
            elector,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            leader_timeout: cfg.leader_timeout,
            certification_timeout: cfg.certification_timeout,
            timeout_retry: cfg.timeout_retry,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
            certification_candidates: BTreeSet::new(),
            outstanding_certifications: BTreeSet::new(),
            current_view,
            tracked_views,
            timeouts,
            nullifications,
        }
    }

    /// Seeds the state machine with the genesis payload and advances into view 1.
    pub fn set_genesis(&mut self, genesis: D) {
        self.genesis = Some(genesis);
        self.enter_view(GENESIS_VIEW.next());
        self.set_leader(GENESIS_VIEW.next(), None);
    }

    /// Seeds the state machine from the configured floor.
    pub fn set_floor(&mut self, floor: Floor<S, D>) -> Option<Finalization<S, D>> {
        match floor {
            Floor::Genesis(genesis) => {
                self.set_genesis(genesis);
                None
            }
            Floor::Finalized(finalization) => {
                let returned = finalization.clone();
                self.add_finalization(finalization);
                Some(returned)
            }
        }
    }

    /// Returns the epoch managed by this state machine.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the view currently being driven.
    pub const fn current_view(&self) -> View {
        self.view
    }

    /// Returns the highest finalized view we have observed.
    pub const fn last_finalized(&self) -> View {
        self.last_finalized
    }

    /// Returns the lowest view that must remain in memory to satisfy the activity timeout.
    pub const fn min_active(&self) -> View {
        min_active(self.activity_timeout, self.last_finalized)
    }

    /// Returns whether `pending` is still relevant for progress, optionally allowing future views.
    pub fn is_interesting(&self, pending: View, allow_future: bool) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            allow_future,
        )
    }

    /// Returns true when the local signer is the participant with index `idx`.
    pub fn is_me(&self, idx: Participant) -> bool {
        self.scheme.me().is_some_and(|me| me == idx)
    }

    /// Advances the view and updates the leader.
    ///
    /// If `seed` is `None`, this **must** be the first view after genesis (view 1).
    /// For all subsequent views, a seed derived from the previous view's certificate
    /// must be provided.
    fn enter_view(&mut self, view: View) -> bool {
        if view <= self.view {
            return false;
        }

        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let certification_deadline = now + self.certification_timeout;

        let round = self.create_round(view);
        round.open_span();
        round.set_deadlines(leader_deadline, certification_deadline);
        self.view = view;

        // Update metrics
        let _ = self.current_view.try_set(view.get());
        true
    }

    /// Sets the leader for the given view if it is not already set.
    fn set_leader(&mut self, view: View, certificate: Option<&S::Certificate>) {
        let leader = self.elector.elect(Rnd::new(self.epoch, view), certificate);
        let round = self.create_round(view);
        if round.leader().is_some() {
            return;
        }
        round.set_leader(leader);
    }

    /// Ensures a round exists for the given view.
    fn create_round(&mut self, view: View) -> &mut Round<S, D> {
        self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.scheme.clone(),
                Rnd::new(self.epoch, view),
                self.context.current(),
            )
        })
    }

    /// Returns the root span for `view`, or a disabled span if the view is not
    /// tracked or already decided.
    pub fn view_span(&self, view: View) -> Span {
        self.views
            .get(&view)
            .map(|round| round.span())
            .unwrap_or_else(Span::none)
    }

    /// Closes the root span of every decided view (at or below the finalized
    /// view) so each view trace ends when the chain commits it rather than when
    /// the round is later pruned.
    pub fn close_decided_spans(&mut self) {
        for (_, round) in self.views.range_mut(..=self.last_finalized) {
            round.close_span();
        }
    }

    /// Returns the root span for `view` and the finalized view, the two state
    /// values a batcher update carries.
    pub fn batcher_context(&self, view: View) -> (Span, View) {
        (self.view_span(view), self.last_finalized)
    }

    /// Returns the deadline for the next timeout (leader, certification, or retry).
    pub fn next_timeout_deadline(&mut self) -> SystemTime {
        let now = self.context.current();
        let timeout_retry = self.timeout_retry;
        let round = self.create_round(self.view);
        round.next_timeout_deadline(now, timeout_retry)
    }

    /// Constructs a nullify vote for the current view, if eligible.
    ///
    /// Returns `Some((is_retry, nullify))` where `is_retry` is true when this is not the first
    /// nullify emission for `view`. Returns `None` if `view` is not the current view or if we
    /// have already broadcast a finalize vote for this view.
    pub fn construct_nullify(&mut self, view: View) -> Option<(bool, Nullify<S>)> {
        if view != self.view {
            return None;
        }
        let is_retry = self.create_round(view).construct_nullify()?;
        let nullify = Nullify::sign::<D>(&self.scheme, Rnd::new(self.epoch, view))?;
        if !is_retry {
            let round = self.create_round(view);
            let reason = if round.proposal().is_some() {
                TimeoutReason::CertificationTimeout
            } else {
                TimeoutReason::LeaderTimeout
            };
            let (reason, _) = round.set_timeout_reason(reason);
            if let Some(leader) = round.leader() {
                self.timeouts
                    .get_or_create(&Timeout::new(&leader.key, reason))
                    .inc();
            }
        }
        Some((is_retry, nullify))
    }

    /// Returns the best certificate for `view` to help peers enter `view + 1`.
    ///
    /// Finalization is strongest, then nullification, then notarization.
    pub fn get_best_certificate(&self, view: View) -> Option<Certificate<S, D>> {
        if view == GENESIS_VIEW {
            return None;
        }

        // Prefer finalizations since they are the strongest proof available.
        // Prefer nullifications over notarizations because a nullification
        // overwrites an uncertified notarization (if we only heard notarizations,
        // we may never exit a view with an uncertifiable notarization).
        #[allow(clippy::option_if_let_else)]
        if let Some(finalization) = self.finalization(view).cloned() {
            Some(Certificate::Finalization(finalization))
        } else if let Some(nullification) = self.nullification(view).cloned() {
            Some(Certificate::Nullification(nullification))
        } else if let Some(notarization) = self.notarization(view).cloned() {
            Some(Certificate::Notarization(notarization))
        } else {
            warn!(%view, "entry certificate not found");
            None
        }
    }

    /// Inserts a notarization certificate and prepares the next view's leader.
    ///
    /// Does not advance into the next view until certification passes.
    /// Adds to certification candidates if successful.
    pub fn add_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = notarization.view();
        // Do not advance to the next view until the certification passes
        self.set_leader(view.next(), Some(&notarization.certificate));
        let result = self.create_round(view).add_notarization(notarization);
        if result.0 && view > self.last_finalized {
            self.certification_candidates.insert(view);
        }
        result
    }

    /// Inserts a nullification certificate and advances into the next view.
    ///
    /// Unlike finalization, nullification does not cancel pending certification work for the
    /// same view. The next proposer may build on a certified notarization we haven't finished processing
    /// yet and stopping here could halt the network (stability relies on coming to a shared understanding
    /// of what can be considered a valid parent, otherwise two regions of the network could build on ancestries
    /// the other considers invalid with no way to resolve the conflict).
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();
        self.enter_view(view.next());
        self.set_leader(view.next(), Some(&nullification.certificate));

        // Track nullification metric per leader (if we know who the leader was)
        let round = self.create_round(view);
        let added = round.add_nullification(nullification);
        let leader = added.then(|| round.leader()).flatten();
        if let Some(leader) = leader {
            self.nullifications.get_or_create_by(&leader.key).inc();
        }

        added
    }

    /// Inserts a finalization certificate, updates the finalized height, and advances the view.
    pub fn add_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = finalization.view();
        if view > self.last_finalized {
            self.last_finalized = view;

            // Prune certification candidates at or below finalized view.
            // Finalization is definitive, so these certifications are no longer relevant.
            self.certification_candidates.retain(|v| *v > view);

            // Abort outstanding certifications at or below finalized view for the same reason.
            let keep = self.outstanding_certifications.split_off(&view.next());
            for v in replace(&mut self.outstanding_certifications, keep) {
                if let Some(round) = self.views.get_mut(&v) {
                    round.abort_certify();
                }
            }
        }

        self.enter_view(view.next());
        self.set_leader(view.next(), Some(&finalization.certificate));
        self.create_round(view).add_finalization(finalization)
    }

    /// Construct a notarize vote for this view when we're ready to sign.
    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_notarize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Notarize::sign(&self.scheme, candidate)
    }

    /// Construct a finalize vote if the round provides a candidate.
    pub fn construct_finalize(&mut self, view: View) -> Option<Finalize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_finalize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Finalize::sign(&self.scheme, candidate)
    }

    /// Construct a notarization certificate once the round has quorum.
    pub fn broadcast_notarization(&mut self, view: View) -> Option<Notarization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_notarization())
    }

    /// Return a notarization certificate, if one exists.
    pub fn notarization(&self, view: View) -> Option<&Notarization<S, D>> {
        self.views.get(&view).and_then(|round| round.notarization())
    }

    /// Return a nullification certificate, if one exists.
    pub fn nullification(&self, view: View) -> Option<&Nullification<S>> {
        self.views
            .get(&view)
            .and_then(|round| round.nullification())
    }

    /// Return a finalization certificate, if one exists.
    pub fn finalization(&self, view: View) -> Option<&Finalization<S, D>> {
        self.views.get(&view).and_then(|round| round.finalization())
    }

    /// Returns the proposal for `view` if it is eligible for forwarding.
    pub fn forwardable_proposal(&self, view: View) -> Option<Proposal<D>> {
        let round = self.views.get(&view)?;
        if round.finalization().is_some() || round.is_certified() {
            return round.proposal().cloned();
        }
        None
    }

    /// Construct a nullification certificate once the round has quorum.
    pub fn broadcast_nullification(&mut self, view: View) -> Option<Nullification<S>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_nullification())
    }

    /// Construct a finalization certificate once the round has quorum.
    pub fn broadcast_finalization(&mut self, view: View) -> Option<Finalization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_finalization())
    }

    /// Replays a journaled artifact into the appropriate round during recovery.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        self.create_round(artifact.view()).replay(artifact);
    }

    /// Returns the leader index for `view` if we already entered it.
    pub fn leader_index(&self, view: View) -> Option<Participant> {
        self.views
            .get(&view)
            .and_then(|round| round.leader().map(|leader| leader.idx))
    }

    /// Returns how long `view` has been live based on the clock samples stored by its round.
    pub fn elapsed_since_start(&self, view: View) -> Option<Duration> {
        let now = self.context.current();
        self.views
            .get(&view)
            .map(|round| round.elapsed_since_start(now))
    }

    /// Immediately expires `view` on first timeout, forcing deadlines to trigger on the next tick.
    ///
    /// If the round has already been marked timed out, this preserves the existing
    /// retry schedule.
    ///
    /// This only records the first timeout reason for the view. Metrics are emitted
    /// when the first timeout nullify vote is constructed.
    pub fn trigger_timeout(&mut self, view: View, reason: TimeoutReason) {
        if view != self.view {
            return;
        }

        let now = self.context.current();
        let round = self.create_round(view);
        let (_, is_first_timeout) = round.set_timeout_reason(reason);
        if is_first_timeout {
            round.set_deadlines(now, now);
        }
    }

    /// Attempt to propose a new block.
    pub fn try_propose(&mut self) -> Option<Context<D, S::PublicKey>> {
        // Perform fast checks before lookback
        let view = self.view;
        if view == GENESIS_VIEW {
            return None;
        }
        if !self
            .views
            .get_mut(&view)
            .expect("view must exist")
            .should_propose()
        {
            return None;
        }

        // Look for parent
        let parent = self.find_parent(view);
        let (parent_view, parent_payload) = match parent {
            Ok(parent) => parent,
            Err(missing) => {
                debug!(%view, %missing, "missing parent during proposal");
                return None;
            }
        };
        let leader = self
            .views
            .get_mut(&view)
            .expect("view must exist")
            .try_propose()?;
        Some(Context {
            round: Rnd::new(self.epoch, view),
            leader: leader.key,
            parent: (parent_view, parent_payload),
        })
    }

    /// Records a locally constructed proposal once the automaton finishes building it.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> bool {
        self.views
            .get_mut(&proposal.view())
            .map(|round| round.proposed(proposal))
            .unwrap_or(false)
    }

    /// Sets a proposal received from the batcher (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(&mut self, view: View, proposal: Proposal<D>) -> bool {
        self.create_round(view).set_proposal(proposal)
    }

    /// Attempt to verify a proposed block.
    ///
    /// Unlike during proposal, we don't use a verification opportunity
    /// to backfill missing certificates (a malicious proposer could
    /// ask us to fetch junk).
    #[allow(clippy::type_complexity)]
    pub fn try_verify(&mut self) -> Option<(Context<D, S::PublicKey>, Proposal<D>)> {
        let view = self.view;
        let (leader, proposal) = self.views.get(&view)?.should_verify()?;
        let parent_payload = match self.parent_payload(&proposal) {
            Ok(parent_payload) => parent_payload,
            Err(err) => {
                if err.invalid_proposal() {
                    warn!(round = ?proposal.round, ?err, "proposal failed verification");
                    self.trigger_timeout(view, TimeoutReason::InvalidProposal);
                } else {
                    debug!(
                        %view,
                        ?proposal,
                        ?err,
                        "proposal exists but ancestry is not yet certified"
                    );
                }
                return None;
            }
        };
        if !self.views.get_mut(&view)?.try_verify() {
            return None;
        }
        let context = Context {
            round: proposal.round,
            leader: leader.key,
            parent: (proposal.parent, parent_payload),
        };
        Some((context, proposal))
    }

    /// Marks proposal verification as complete when the peer payload validates.
    pub fn verified(&mut self, view: View) -> bool {
        self.views
            .get_mut(&view)
            .map(|round| round.verified())
            .unwrap_or(false)
    }

    /// Store the abort handle for an in-flight certification request.
    pub fn set_certify_handle(&mut self, view: View, handle: Aborter) {
        let Some(round) = self.views.get_mut(&view) else {
            return;
        };
        round.set_certify_handle(handle);
        self.outstanding_certifications.insert(view);
    }

    /// Takes all certification candidates and returns proposals ready for certification.
    pub fn certify_candidates(&mut self) -> Vec<Proposal<D>> {
        let candidates = take(&mut self.certification_candidates);
        candidates
            .into_iter()
            .filter_map(|view| {
                if view <= self.last_finalized {
                    return None;
                }
                let candidate = self.views.get_mut(&view)?.try_certify()?;
                Some(candidate)
            })
            .collect()
    }

    /// Marks proposal certification as complete and returns the notarization.
    ///
    /// Returns `None` if the view was already pruned. Otherwise returns the notarization
    /// regardless of success/failure.
    pub fn certified(&mut self, view: View, is_success: bool) -> Option<Notarization<S, D>> {
        let round = self.views.get_mut(&view)?;
        round.certified(is_success);
        if is_success {
            // Clear deadlines if the certification was successful
            round.clear_deadlines();
        }

        // Remove from outstanding since certification is complete
        self.outstanding_certifications.remove(&view);

        // Get notarization before advancing state
        let notarization = round
            .notarization()
            .cloned()
            .expect("notarization must exist for certified view");

        if is_success {
            self.enter_view(view.next());
        } else {
            self.trigger_timeout(view, TimeoutReason::FailedCertification);
        }

        Some(notarization)
    }

    /// Drops any views that fall below the activity horizon and returns them for logging.
    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let kept = self.views.split_off(&min);
        let removed = replace(&mut self.views, kept).into_keys().collect();

        // Update metrics
        let _ = self.tracked_views.try_set(self.views.len());
        removed
    }

    /// Returns the payload of the proposal if it is certified (including finalized).
    fn is_certified(&self, view: View) -> Option<&D> {
        // Special case for genesis view
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        // Check for explicit certification
        let round = self.views.get(&view)?;
        if round.finalization().is_some() || round.is_certified() {
            return Some(&round.proposal().expect("proposal must exist").payload);
        }
        None
    }

    /// Returns true if the view is nullified.
    fn is_nullified(&self, view: View) -> bool {
        // Special case for genesis view (although it should also not be in the views map).
        if view == GENESIS_VIEW {
            return false;
        }

        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        round.nullification().is_some()
    }

    /// Returns true if certification for the view was aborted due to finalization.
    #[cfg(test)]
    pub fn is_certify_aborted(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.is_certify_aborted())
    }

    /// Finds the parent payload for a given view by walking backwards through
    /// the chain, skipping nullified views until finding a certified payload.
    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        // If the view is the genesis view, consider it to be its own parent.
        let mut cursor = view.previous().unwrap_or(GENESIS_VIEW);

        loop {
            // Return the first certified (including finalized) parent.
            if let Some(parent) = self.is_certified(cursor) {
                return Ok((cursor, *parent));
            }

            // If the view is also not nullified, there is a gap in certificates.
            if !self.is_nullified(cursor) {
                return Err(cursor);
            }

            cursor = cursor.previous().expect("cursor must not wrap");
        }
    }

    /// Returns the payload of the proposal's parent if:
    /// - It is less-than the proposal view.
    /// - It is greater-than-or-equal-to the last finalized view.
    /// - It is certified (or finalized, which implies certification).
    /// - There exist nullifications for all views between it and the proposal view.
    fn parent_payload(&self, proposal: &Proposal<D>) -> Result<D, ParentPayloadError> {
        // Sanity check that the parent view is less than the proposal view.
        let (view, parent) = (proposal.view(), proposal.parent);
        if view <= parent {
            return Err(ParentPayloadError::ParentNotBeforeProposal {
                proposal_view: view,
                parent_view: parent,
            });
        }

        // Ignore any requests for outdated parent views.
        if parent < self.last_finalized {
            return Err(ParentPayloadError::ParentBeforeFinalized {
                proposal_view: view,
                parent_view: parent,
                last_finalized: self.last_finalized,
            });
        }

        // Check that there are nullifications for all views between the parent and the proposal view.
        if let Some(missing_view) =
            View::range(parent.next(), view).find(|v| !self.is_nullified(*v))
        {
            return Err(ParentPayloadError::MissingNullification {
                proposal_view: view,
                parent_view: parent,
                missing_view,
            });
        }

        // May return `None` if the parent view is not yet either:
        // - notarized and certified
        // - finalized
        self.is_certified(parent)
            .copied()
            .ok_or(ParentPayloadError::ParentNotCertified {
                proposal_view: view,
                parent_view: parent,
            })
    }

    /// Returns the certificate for the parent of the proposal at the given view.
    pub fn parent_certificate(&mut self, view: View) -> Option<Certificate<S, D>> {
        let parent = {
            let view = self.views.get(&view)?.proposal()?.parent;
            self.views.get(&view)?
        };

        if let Some(f) = parent.finalization().cloned() {
            return Some(Certificate::Finalization(f));
        }
        if let Some(n) = parent.notarization().cloned() {
            return Some(Certificate::Notarization(n));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        elector::RoundRobin,
        scheme::ed25519,
        types::{Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner, Supervisor as _};
    use commonware_utils::futures::AbortablePool;
    use std::time::Duration;

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

    #[test_traced]
    fn decided_views_close_their_view_span() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(7);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            // Finalize view 2, advancing the finalized view and entering view 3.
            let finalize_view = View::new(2);
            let finalize_round = Rnd::new(epoch, finalize_view);
            let proposal =
                Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([7u8; 32]));
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let finalization = Finalization::from_finalizes(&verifier, votes.iter(), &Sequential)
                .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.last_finalized(), finalize_view);

            // Finalizing does not close entered spans on its own; follow-up work
            // for an entered view can still run under the span until notification
            // completes. This finalization skips over view 2, so that prepared
            // future view never opened a span.
            assert!(!state.view_span(View::new(1)).is_none());
            assert!(state.view_span(finalize_view).is_none());
            assert!(!state.view_span(View::new(3)).is_none());

            // Closing decided spans releases every view at or below the
            // finalized view, while the active view keeps its span.
            state.close_decided_spans();
            assert!(state.view_span(View::new(1)).is_none());
            assert!(state.view_span(finalize_view).is_none());
            assert!(!state.view_span(View::new(3)).is_none());
        });
    }

    #[test]
    fn certificate_candidates_respect_force_flag() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(11),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            // Add notarization
            let notarize_view = View::new(3);
            let notarize_round = Rnd::new(Epoch::new(11), notarize_view);
            let notarize_proposal =
                Proposal::new(notarize_round, GENESIS_VIEW, Sha256Digest::from([50u8; 32]));
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, notarize_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);

            // Produce candidate once
            assert!(state.broadcast_notarization(notarize_view).is_some());
            assert!(state.broadcast_notarization(notarize_view).is_none());
            assert!(state.notarization(notarize_view).is_some());

            // Add nullification
            let nullify_view = View::new(4);
            let nullify_round = Rnd::new(Epoch::new(11), nullify_view);
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, nullify_round).expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            state.add_nullification(nullification);

            // Produce candidate once
            assert!(state.broadcast_nullification(nullify_view).is_some());
            assert!(state.broadcast_nullification(nullify_view).is_none());
            assert!(state.nullification(nullify_view).is_some());

            // Add finalization
            let finalize_view = View::new(5);
            let finalize_round = Rnd::new(Epoch::new(11), finalize_view);
            let finalize_proposal =
                Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([51u8; 32]));
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, finalize_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Produce candidate once
            assert!(state.broadcast_finalization(finalize_view).is_some());
            assert!(state.broadcast_finalization(finalize_view).is_none());
            assert!(state.finalization(finalize_view).is_some());
        });
    }

    #[test]
    fn timeout_helpers_reuse_and_reset_deadlines() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[0].clone(); // leader of view 1
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: local_scheme.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Should return same deadline until something done
            let first = state.next_timeout_deadline();
            let second = state.next_timeout_deadline();
            assert_eq!(first, second, "cached deadline should be reused");

            // Timeout-mode nullify: first emission should not be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view())
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout is not a retry");

            // Set retry deadline
            context.sleep(Duration::from_secs(2)).await;
            let later = context.current();

            // Confirm retry deadline is set
            let third = state.next_timeout_deadline();
            assert_eq!(third, later + retry, "new retry scheduled after timeout");

            // Confirm retry deadline remains set
            let fourth = state.next_timeout_deadline();
            assert_eq!(fourth, third, "retry deadline should be set");

            // Confirm works if later is far in the future
            context.sleep(Duration::from_secs(10)).await;
            let fifth = state.next_timeout_deadline();
            assert_eq!(fifth, later + retry, "retry deadline should be set");

            // Timeout-mode nullify: second emission should be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view())
                .expect("retry timeout nullify should exist");
            assert!(was_retry, "subsequent timeout should be treated as retry");

            // Confirm retry deadline is set
            let sixth = state.next_timeout_deadline();
            let later = context.current();
            assert_eq!(sixth, later + retry, "retry deadline should be set");
        });
    }

    #[test]
    fn nullify_preserves_retry_backoff_after_first_timeout_vote() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(30),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout should not be marked as retry");

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.timeouts.get_or_create(&label).get(),
                1,
                "first timeout nullify should record a leader-timeout metric"
            );

            context.sleep(Duration::from_secs(2)).await;
            let now = context.current();
            let retry_deadline = state.next_timeout_deadline();
            assert_eq!(
                retry_deadline,
                now + retry,
                "first retry should honor configured nullify backoff"
            );

            // Repeated timeout hints for the same view should not reset retry backoff.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            assert_eq!(
                state.next_timeout_deadline(),
                retry_deadline,
                "retry backoff should be preserved after repeated timeout hints"
            );
        });
    }

    #[test]
    fn nullify_without_reason_reuses_first_recorded_reason() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(31),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            state.trigger_timeout(view, TimeoutReason::MissingProposal);
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let missing = Timeout::new(leader_key, TimeoutReason::MissingProposal);
            let leader_timeout = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(state.timeouts.get_or_create(&missing).get(), 1);
            assert_eq!(state.timeouts.get_or_create(&leader_timeout).get(), 0);

            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("retry timeout nullify should exist");
            assert!(was_retry);
            assert_eq!(state.timeouts.get_or_create(&missing).get(), 1);
        });
    }

    #[test]
    fn notarization_keeps_certification_timeout_pending_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(32),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), view),
                GENESIS_VIEW,
                Sha256Digest::from([52u8; 32]),
            );

            // Proposal arrival clears leader timeout and leaves only the certification timeout.
            assert!(state.set_proposal(view, proposal.clone()));
            let certification_deadline = state.next_timeout_deadline();
            assert_eq!(
                certification_deadline,
                context.current() + Duration::from_secs(2)
            );

            // Receiving a notarization should not clear the certification timeout while certification is pending.
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, votes.iter(), &Sequential)
                .expect("notarization");
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());
            assert_eq!(
                state.next_timeout_deadline(),
                certification_deadline,
                "certification timeout must continue to bound certification latency"
            );

            // If certification stalls beyond the certification timeout, timeout handling should fire immediately.
            context.sleep(Duration::from_secs(3)).await;
            assert!(
                state.next_timeout_deadline() <= context.current(),
                "stalled certification should leave the view timed out"
            );
        });
    }

    #[test]
    fn expire_old_round_is_noop() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(12),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Expiring a non-current view should do nothing.
            let deadline_v1 = state.next_timeout_deadline();
            state.trigger_timeout(View::zero(), TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(1));
            assert_eq!(state.next_timeout_deadline(), deadline_v1);
            assert!(
                !state.views.contains_key(&View::zero()),
                "old round should not be created when expire is ignored"
            );

            // Move to view 2 so view 1 becomes stale.
            let view_1 = View::new(1);
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(state.epoch(), view_1))
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullify");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(2));

            let deadline_v2 = state.next_timeout_deadline();
            state.trigger_timeout(view_1, TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(state.next_timeout_deadline(), deadline_v2);
        });
    }

    #[test]
    fn entering_next_view_resets_expired_timeout_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let leader_timeout = Duration::from_secs(1);
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(13),
                activity_timeout: ViewDelta::new(3),
                leader_timeout,
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view_1 = state.current_view();
            assert_eq!(view_1, View::new(1));

            // Force the current view into timeout mode and schedule a retry.
            state.trigger_timeout(view_1, TimeoutReason::LeaderTimeout);
            assert!(
                state.next_timeout_deadline() <= context.current(),
                "current view should be expired after timeout is triggered"
            );
            let (was_retry, _) = state
                .construct_nullify(view_1)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            let retry_deadline = state.next_timeout_deadline();
            assert_eq!(
                retry_deadline,
                context.current() + retry,
                "timed-out view should schedule a retry"
            );

            // Advancing into the next view must install fresh deadlines instead of reusing
            // the expired/retrying state from the previous view.
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(state.epoch(), view_1))
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullify");
            assert!(state.add_nullification(nullification));

            let view_2 = state.current_view();
            assert_eq!(view_2, View::new(2));
            let next_deadline = state.next_timeout_deadline();
            assert_eq!(
                next_deadline,
                context.current() + leader_timeout,
                "next view should start with a fresh leader timeout"
            );
            assert_ne!(
                next_deadline, retry_deadline,
                "next view must not inherit the previous view retry deadline"
            );
        });
    }

    #[test]
    fn nullify_only_records_metric_once() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(12),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let leader = state.leader_index(view).unwrap();
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderNullify);

            // Fast-path trigger should not record metrics until we emit nullify.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            let expired_at = state.next_timeout_deadline();
            context.sleep(Duration::from_secs(1)).await;

            // Repeated timeout hints before emitting nullify should preserve the first timeout.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.next_timeout_deadline(),
                expired_at,
                "repeated timeout hints should not reset the expired deadline"
            );
            assert_eq!(state.timeouts.get_or_create(&label).get(), 0);

            // First emitted nullify should record the metric.
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            // Re-triggering with a different reason should preserve the first reason.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("retry timeout nullify should exist");
            assert!(was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            // No metric should be emitted for the later reason.
            let other_label = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(state.timeouts.get_or_create(&other_label).get(), 0);
        });
    }

    #[test]
    fn construct_nullify_current_view_only() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[0].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());
            let current = state.current_view();
            let next = current.next();

            // Non-current views are not eligible.
            assert!(state.construct_nullify(next).is_none());

            // Observe a nullification for current view, which advances us to the next view.
            let current_round = Rnd::new(Epoch::new(4), current);
            let current_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, current_round).expect("nullify")
                })
                .collect();
            let current_nullification =
                Nullification::from_nullifies(&verifier, &current_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(current_nullification));
            assert_eq!(state.current_view(), next);

            // Past views remain ineligible even if they have a nullification certificate.
            assert!(state.construct_nullify(current).is_none());

            // Timeout path on current view: first attempt then retry.
            let (was_retry, _) = state
                .construct_nullify(next)
                .expect("first timeout nullify for current view should be emitted");
            assert!(!was_retry);
            let (was_retry, _) = state
                .construct_nullify(next)
                .expect("retry timeout nullify for current view should be emitted");
            assert!(was_retry);
        });
    }

    #[test]
    fn round_prunes_with_min_active() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add initial rounds
            for view in 0..5 {
                state.create_round(View::new(view));
            }

            // Create finalization for view 20
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(20)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_a.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Update last finalize to be in the future
            let removed = state.prune();
            assert_eq!(
                removed,
                vec![
                    View::new(0),
                    View::new(1),
                    View::new(2),
                    View::new(3),
                    View::new(4)
                ]
            );
            assert_eq!(state.views.len(), 2); // 20 and 21
        });
    }

    #[test]
    fn parent_payload_returns_parent_digest() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[2].clone(); // leader of view 1
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Create proposal
            let parent_view = View::new(1);
            let parent_payload = Sha256Digest::from([1u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            // Attempt to get parent payload without certificate
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                parent_view,
                Sha256Digest::from([9u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentNotCertified {
                    proposal_view: View::new(2),
                    parent_view,
                })
            );

            // Add notarization certificate
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .unwrap();
            state.add_notarization(notarization);

            // The parent is still not certified
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentNotCertified {
                    proposal_view: View::new(2),
                    parent_view,
                })
            );

            // Set certify handle then certify the parent
            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(parent_view, handle);
            state.certified(parent_view, true);
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_certificate_prefers_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[1].clone(); // leader of view 2
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add notarization for parent view
            let parent_round = Rnd::new(state.epoch(), View::new(1));
            let parent_proposal =
                Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([11u8; 32]));
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization.clone());

            // Insert proposal at view 2 with parent at view 1
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), View::new(2)),
                View::new(1),
                Sha256Digest::from([22u8; 32]),
            );
            state.proposed(proposal);

            // parent_certificate returns the notarization
            let cert = state.parent_certificate(View::new(2)).unwrap();
            assert!(matches!(cert, Certificate::Notarization(n) if n == notarization));

            // Add finalization for the same parent view
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization.clone());

            // parent_certificate now returns the finalization (preferred)
            let cert = state.parent_certificate(View::new(2)).unwrap();
            assert!(matches!(cert, Certificate::Finalization(f) if f == finalization));
        });
    }

    #[test]
    fn parent_payload_errors_without_nullification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                activity_timeout: ViewDelta::new(5),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Create parent proposal and certificate
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([2u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .unwrap();
            state.add_notarization(notarization);
            state.create_round(View::new(2));

            // Attempt to get parent payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                parent_view,
                Sha256Digest::from([3u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::MissingNullification {
                    proposal_view: View::new(3),
                    parent_view,
                    missing_view: View::new(2),
                })
            );
        });
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                activity_timeout: ViewDelta::new(5),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add nullification certificate for view 1
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(1)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential).unwrap();
            state.add_nullification(nullification);

            // Get genesis payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([8u8; 32]),
            );
            let genesis = Sha256Digest::from([0u8; 32]);
            assert_eq!(state.parent_payload(&proposal), Ok(genesis));
        });
    }

    #[test]
    fn parent_payload_rejects_parent_before_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add finalization
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_a.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Attempt to verify before finalized
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(4)),
                View::new(2),
                Sha256Digest::from([6u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentBeforeFinalized {
                    proposal_view: View::new(4),
                    parent_view: View::new(2),
                    last_finalized: View::new(3),
                })
            );
        });
    }

    #[test]
    fn try_verify_fast_paths_parent_before_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                },
            );
            state.set_genesis(test_genesis());

            // Finalize view 3 so view 4 is current and any parent below 3 is permanently invalid.
            let finalized_view = View::new(3);
            let finalized_proposal = Proposal::new(
                Rnd::new(epoch, finalized_view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, finalized_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Inject a proposal whose parent is below the finalized floor.
            let view = state.current_view();
            assert_eq!(view, View::new(4));
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(2),
                Sha256Digest::from([6u8; 32]),
            );
            assert!(state.set_proposal(view, proposal));

            let initial_deadline = state.next_timeout_deadline();
            assert!(initial_deadline > context.current());

            // Permanent ancestry errors should immediately expire the timeout.
            assert!(state.try_verify().is_none());
            assert!(state.next_timeout_deadline() <= context.current());
        });
    }

    #[test]
    fn try_verify_waits_for_missing_parent_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { verifier, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: verifier,
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                },
            );
            state.set_genesis(test_genesis());

            // Move into view 2 without certifying view 1 so the parent could still arrive later.
            assert!(state.enter_view(View::new(2)));
            state.set_leader(View::new(2), None);

            // Inject a proposal whose parent is missing certification but is not permanently invalid.
            let proposal = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                View::new(1),
                Sha256Digest::from([7u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal));

            let initial_deadline = state.next_timeout_deadline();
            assert!(initial_deadline > context.current());

            // Missing parent certification should wait instead of forcing an immediate timeout.
            assert!(state.try_verify().is_none());
            assert_eq!(state.next_timeout_deadline(), initial_deadline);
        });
    }

    /// Replaying a local notarize vote for a leader-owned proposal should
    /// restore the proposal as verified and suppress duplicate vote construction.
    #[test]
    fn replayed_local_notarize_restores_verified_leader_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let epoch = Epoch::new(2);
            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(1),
                Sha256Digest::from([42u8; 32]),
            );
            let local_vote = Notarize::sign(&schemes[0], proposal.clone()).expect("notarize");

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            // Enter the view where we are the leader.
            assert!(state.enter_view(view));
            state.set_leader(view, None);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));

            // Replay our own notarize vote.
            state.replay(&Artifact::Notarize(local_vote));

            // Proposal should be restored in the round.
            let round = state.views.get(&view).expect("replayed round must exist");
            assert_eq!(round.proposal(), Some(&proposal));

            // No duplicate notarize vote should be constructed.
            assert!(
                state.construct_notarize(view).is_none(),
                "replay should restore that we already emitted the local notarize vote"
            );

            // No verification request should be emitted (leader-owned).
            assert!(state.try_verify().is_none());

            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);
        });
    }

    #[test]
    fn certify_external_candidates_for_leader_controlled_views() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let epoch = Epoch::new(2);
            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());
            assert!(state.enter_view(view));
            state.set_leader(view, None);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0], proposal);
        });
    }

    #[test]
    fn replay_restores_conflict_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let mut scheme_iter = schemes.into_iter();
            let local_scheme = scheme_iter.next().unwrap();
            let other_schemes: Vec<_> = scheme_iter.collect();
            let epoch: Epoch = Epoch::new(3);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: local_scheme.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());
            let view = View::new(4);
            let round = Rnd::new(epoch, view);
            let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([21u8; 32]));
            let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([22u8; 32]));
            let local_vote = Notarize::sign(&local_scheme, proposal_a).unwrap();

            // Replay local notarize vote
            state.replay(&Artifact::Notarize(local_vote.clone()));

            // Add conflicting notarization certificate and replay
            let votes_b: Vec<_> = other_schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
                .collect();
            let conflicting = Notarization::from_notarizes(&verifier, votes_b.iter(), &Sequential)
                .expect("certificate");
            state.add_notarization(conflicting.clone());
            state.replay(&Artifact::Notarization(conflicting.clone()));

            // Shouldn't finalize the certificate's proposal (proposal_b)
            assert!(state.construct_finalize(view).is_none());

            // Restart state and replay
            let mut restarted = State::new(
                context.child("state_restarted"),
                Config {
                    scheme: local_scheme,
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                },
            );
            restarted.set_genesis(test_genesis());
            restarted.replay(&Artifact::Notarize(local_vote));
            restarted.add_notarization(conflicting.clone());
            restarted.replay(&Artifact::Notarization(conflicting));

            // Shouldn't finalize the certificate's proposal (proposal_b)
            assert!(restarted.construct_finalize(view).is_none());
        });
    }

    #[test]
    fn certification_lifecycle() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Helper to create notarization for a view
            let make_notarization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|s| Notarize::sign(s, proposal.clone()).unwrap())
                    .collect();
                Notarization::from_notarizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            // Helper to create finalization for a view
            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|s| Finalize::sign(s, proposal.clone()).unwrap())
                    .collect();
                Finalization::from_finalizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let mut pool = AbortablePool::<()>::default();

            // Add notarizations for views 3-8
            for i in 3..=8u64 {
                state.add_notarization(make_notarization(View::new(i)));
            }

            // All 6 views should be candidates
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 6);

            // Set certify handles for views 3, 4, 5, 7 (NOT 6 or 8)
            for i in [3u64, 4, 5, 7] {
                let handle = pool.push(futures::future::pending());
                state.set_certify_handle(View::new(i), handle);
            }

            // Candidates empty (consumed by certify_candidates, handles block re-fetching)
            assert!(state.certify_candidates().is_empty());

            // Complete certification for view 7 (success)
            let notarization = state.certified(View::new(7), true);
            assert!(notarization.is_some());

            // View 7 should not be aborted (it was certified successfully)
            assert!(!state.is_certify_aborted(View::new(7)));

            // Add finalization for view 5 - aborts handles for views 3, 4, 5
            state.add_finalization(make_finalization(View::new(5)));

            // Verify views 3, 4, 5 had their certification aborted
            assert!(state.is_certify_aborted(View::new(3)));
            assert!(state.is_certify_aborted(View::new(4)));
            assert!(state.is_certify_aborted(View::new(5)));

            // View 7 still not aborted (was certified, and 7 > 5)
            assert!(!state.is_certify_aborted(View::new(7)));

            // Views 6, 8 never had handles set, so they're not aborted (still Ready)
            assert!(!state.is_certify_aborted(View::new(6)));
            assert!(!state.is_certify_aborted(View::new(8)));

            // Candidates empty: 3-5 finalized, 6/8 consumed, 7 certified
            assert!(state.certify_candidates().is_empty());

            // Add view 9, should be returned as candidate
            state.add_notarization(make_notarization(View::new(9)));
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(9));

            // Set handle for view 9, add view 10
            let handle9 = pool.push(futures::future::pending());
            state.set_certify_handle(View::new(9), handle9);
            state.add_notarization(make_notarization(View::new(10)));

            // View 10 returned (view 9 has handle)
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(10));

            // Finalize view 9 - aborts view 9's handle
            state.add_finalization(make_finalization(View::new(9)));
            assert!(state.is_certify_aborted(View::new(9)));

            // Add view 11, should be returned
            state.add_notarization(make_notarization(View::new(11)));
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(11));
        });
    }

    #[test]
    fn certify_candidates_skips_views_at_or_below_last_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let make_notarization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                Notarization::from_notarizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                Finalization::from_finalizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let stale_view = View::new(2);
            let live_view = View::new(3);

            state.add_notarization(make_notarization(stale_view));
            state.add_notarization(make_notarization(live_view));
            state.add_finalization(make_finalization(stale_view));

            // Reinsert a stale candidate to exercise the defensive finalized-view guard.
            state.certification_candidates.insert(stale_view);
            assert_eq!(state.last_finalized(), stale_view);

            // The stale round still looks certifiable without the finalized-view filter.
            assert!(state
                .views
                .get_mut(&stale_view)
                .expect("stale round must exist")
                .try_certify()
                .is_some());

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), live_view);
        });
    }

    #[test]
    fn nullification_keeps_notarization_as_certification_candidate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);
        });
    }

    #[test]
    fn nullification_does_not_abort_inflight_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([24u8; 32]),
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);

            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(view, handle);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert!(!state.is_certify_aborted(view));

            // Late certification completion is still accepted until the view is finalized.
            assert!(state.certified(view, true).is_some());
            assert!(state.is_certified(view).is_some());
        });
    }

    #[test]
    fn nullification_then_late_certification_allows_child_to_build_on_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let local_scheme = schemes[0].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(2);
            let child_view = parent_view.next();
            let payload = Sha256Digest::from([91u8; 32]);
            let proposal =
                Proposal::new(Rnd::new(Epoch::new(1), parent_view), GENESIS_VIEW, payload);

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), parent_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            // With RoundRobin and 4 participants, epoch=1 implies view=3 leader is index 0 (our signer).
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            // Before late certification arrives, we cannot build a child because parent ancestry
            // is still incomplete for this node.
            assert!(state.try_propose().is_none());

            // Late certification after nullification is still recorded.
            assert!(state.certified(parent_view, true).is_some());

            // Child proposal selection should build on the now-certified parent view.
            let propose_context = state
                .try_propose()
                .expect("child view should be able to build on certified parent");
            assert_eq!(propose_context.round.view(), child_view);
            assert_eq!(propose_context.parent, (parent_view, payload));
        });
    }

    #[test]
    fn nullification_then_late_certification_unblocks_follower_verify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            // With RoundRobin (epoch=1), child view=3 has leader index 0, so signer index 1 is a follower.
            let local_scheme = schemes[1].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(2);
            let child_view = parent_view.next();
            let parent_payload = Sha256Digest::from([77u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), parent_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), child_view);
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            // Proposal at child view depends on the parent view.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([78u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal.clone()));

            // Before late certification of parent, follower cannot verify this child proposal.
            assert!(state.try_verify().is_none());

            // Late certification after nullification should unblock parent check for verification.
            assert!(state.certified(parent_view, true).is_some());
            let verified = state.try_verify();
            assert!(verified.is_some());
            let (ctx, proposal) = verified.expect("verify context should exist");
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    #[test]
    fn late_nullification_unblocks_follower_verify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            // With RoundRobin (epoch=1), view 3 leader is index 0, so signer index 1 is a follower.
            let local_scheme = schemes[1].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_secs(30),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(1);
            let blocked_view = parent_view.next();
            let child_view = blocked_view.next();
            let parent_payload = Sha256Digest::from([88u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            // Certify the parent view, but leave the intermediate view missing its nullification.
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            // Move into the child view as a follower and inject a proposal that depends on view 1.
            assert!(state.enter_view(child_view));
            state.set_leader(child_view, None);
            assert_eq!(state.current_view(), child_view);
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([89u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal.clone()));

            // Missing nullification should stall verification without expiring the timeout.
            let initial_deadline = state.next_timeout_deadline();
            assert!(initial_deadline > context.current());
            assert!(state.try_verify().is_none());
            assert_eq!(state.next_timeout_deadline(), initial_deadline);

            // Once the intermediate nullification arrives, the same proposal should become verifiable.
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), blocked_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            let verified = state.try_verify().expect("verify context should exist");
            let (ctx, proposal) = verified;
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    #[test]
    fn only_notarize_before_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());
            let view = state.current_view();

            // Set proposal
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            state.set_proposal(view, proposal);

            // We should not want to verify (already timeout)
            assert!(state.try_verify().is_some());
            assert!(state.verified(view));

            // Timeout path emits a first-attempt nullify.
            let (retry, _) = state
                .construct_nullify(view)
                .expect("timeout nullify should exist");
            assert!(!retry);

            // Attempt to notarize after timeout
            assert!(state.construct_notarize(view).is_none());
        });
    }
}
