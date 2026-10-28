use super::{super::Kind, round::Round};
use crate::{
    Viewable,
    simplex::{
        Floor, Lookahead, Viewport,
        elector::Elector,
        metrics::{Leader, Timeout, TimeoutReason},
        scheme::Scheme,
        types::{
            Artifact, Certificate, Context, Finalization, Finalize, Notarization, Notarize,
            Nullification, Nullify, Proposal,
        },
    },
    types::{Epoch, Participant, Round as Rnd, TermLength, View, ViewDelta},
};
use commonware_cryptography::{Digest, certificate};
use commonware_runtime::{
    Clock, Metrics,
    telemetry::metrics::{Counter, CounterFamily, Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::futures::Aborter;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{replace, take},
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, warn};

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
        "intra-term proposal view {proposal_view} skips views between parent view {parent_view} and itself"
    )]
    IntraTermProposalSkipsViews {
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
            Self::ParentNotBeforeProposal { .. }
            | Self::IntraTermProposalSkipsViews { .. }
            | Self::ParentBeforeFinalized { .. } => true,
            Self::MissingNullification { .. } | Self::ParentNotCertified { .. } => false,
        }
    }
}

/// Outcome of [State::try_verify].
pub enum Verify<S: Scheme<D>, D: Digest> {
    Ready(Context<D, S::PublicKey>, Proposal<D>),
    Resolve {
        proposal: View,
        view: View,
        kind: Kind,
        target: S::PublicKey,
    },
    Wait,
}

/// A certificate fetch justified by a blocked certification (see
/// [`State::certify_candidates`]).
pub struct CertificateFetch {
    /// View of the candidate that exposed the missing certificate.
    pub proposal: View,
    /// View whose notarization is needed.
    pub view: View,
}

/// Configuration for initializing [`State`].
pub struct Config<S: certificate::Scheme, L: Elector<S>> {
    pub scheme: S,
    pub elector: L,
    pub epoch: Epoch,
    pub view_retention: ViewDelta,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub skip_budget: u64,
}

/// Per-[Epoch] state machine.
///
/// Tracks proposals and certificates for each view. Vote aggregation and verification
/// is handled by the [crate::simplex::actors::batcher].
pub struct State<E: Clock + CryptoRng + Metrics, S: Scheme<D>, L: Elector<S>, D: Digest> {
    context: E,
    scheme: S,
    elector: L,
    epoch: Epoch,

    /// Cached term length and local optimistic-lookahead policy.
    lookahead: Lookahead,
    view_retention: ViewDelta,
    leader_timeout: Duration,
    certification_timeout: Duration,
    timeout_retry: Duration,
    skip_budget: u64,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,

    /// Monotone cursor for the oldest entered, unfinalized view (the anchor of
    /// the stall timeout). See [`Self::next_stall_timeout`].
    stall_anchor: View,

    /// Views for which we have voted to nullify.
    ///
    /// Used to enforce the term safety rule that suppresses later same-term
    /// finalize votes until a covering finalization is observed.
    nullify_views: BTreeSet<View>,

    /// Views for which we have nullification certificates. Used to answer term-level
    /// nullification queries efficiently (for parent validation and entry certificate fallback)
    /// without scanning all tracked rounds.
    nullification_views: BTreeSet<View>,

    /// Views with a local certification rejection not covered by finalization.
    /// A rejected view cannot support same-term descendant ancestry.
    /// Every entry remains above the retention floor, so [`Self::prune`] skips
    /// this set.
    failed_certifications: BTreeSet<View>,

    certification_candidates: BTreeSet<View>,
    outstanding_certifications: BTreeSet<View>,

    current_view: Gauge,
    tracked_views: Gauge,
    issuance_window_probes: Counter,
    timeouts: CounterFamily<Timeout>,
    nullifications: CounterFamily<Leader<S::PublicKey>>,
}

impl<E: Clock + CryptoRng + Metrics, S: Scheme<D>, L: Elector<S>, D: Digest> State<E, S, L, D> {
    /// Returns true when `view` is within the optimistic *issuance* window:
    /// a directly-notarized anchor exists and `view` sits at most
    /// `optimistic_views` hops above the anchor's child (see
    /// [`Lookahead::issuance_floor`]).
    ///
    /// The scanned range spans at most `optimistic_views + 1` views, so
    /// reading the rounds directly is cheap and avoids maintaining a parallel
    /// index that could drift from them.
    fn in_issuance_window(&self, view: View) -> bool {
        let Some(floor) = self.lookahead.issuance_floor(view) else {
            return false;
        };
        // Genesis anchors the window until the first notarization lands.
        if floor == GENESIS_VIEW {
            return true;
        }

        let mut probes = 0;
        let in_window = self.views.range(floor..view).any(|(_, round)| {
            probes += 1;
            round.is_directly_notarized()
        });
        self.issuance_window_probes.inc_by(probes);
        in_window
    }

    /// Returns true when `pending` is inside the optimistic issuance window
    /// opened by directly-notarized `anchor`.
    fn in_issuance_window_from(&self, anchor: View, pending: View) -> bool {
        anchor < pending
            && self
                .lookahead
                .issuance_floor(pending)
                .is_some_and(|floor| floor <= anchor)
    }

    /// Returns the lowest tracked view at or above `from`.
    ///
    /// A cursor keeps the forward scans in [`Self::try_propose`] and
    /// [`Self::try_verify`] allocation-free and lets their bodies take
    /// `&mut self`.
    fn next_tracked_view(&self, from: View) -> Option<View> {
        self.views.range(from..).next().map(|(&view, _)| view)
    }

    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        let current_view = context.gauge("current_view", "current view");
        let tracked_views = context.gauge("tracked_views", "tracked views");
        let issuance_window_probes = context.counter(
            "issuance_window_probes",
            "rounds inspected for optimistic issuance anchors",
        );
        let timeouts = context.family("timeouts", "timed out views");
        let nullifications = context.family("nullifications", "nullifications");

        let lookahead = Lookahead::new(&cfg.elector.terms());
        Self {
            context,
            scheme: cfg.scheme,
            elector: cfg.elector,
            epoch: cfg.epoch,
            lookahead,
            view_retention: cfg.view_retention,
            leader_timeout: cfg.leader_timeout,
            certification_timeout: cfg.certification_timeout,
            timeout_retry: cfg.timeout_retry,
            skip_budget: cfg.skip_budget,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
            stall_anchor: GENESIS_VIEW,
            nullify_views: BTreeSet::new(),
            nullification_views: BTreeSet::new(),
            failed_certifications: BTreeSet::new(),
            certification_candidates: BTreeSet::new(),
            outstanding_certifications: BTreeSet::new(),
            current_view,
            tracked_views,
            issuance_window_probes,
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
        self.viewport().floor()
    }

    /// Returns the term length of the elector.
    const fn term_length(&self) -> TermLength {
        self.lookahead.term_length
    }

    /// Returns the window of views this state machine tracks.
    const fn viewport(&self) -> Viewport {
        Viewport {
            finalized: self.last_finalized,
            current: self.view,
            view_retention: self.view_retention,
            lookahead: self.lookahead,
        }
    }

    /// Returns whether a vote for `pending` is tracked (see [Viewport::admits_vote]).
    pub fn admits_vote(&self, pending: View) -> bool {
        self.viewport().admits_vote(pending)
    }

    /// Returns whether a certificate for `pending` is tracked (see
    /// [Viewport::admits_certificate]).
    pub const fn admits_certificate(&self, pending: View) -> bool {
        self.viewport().admits_certificate(pending)
    }

    /// Returns whether `view` is eligible for locally emitted work under this
    /// node's lookahead policy.
    fn admits_outbound(&self, view: View) -> bool {
        self.lookahead.admits(self.view, view)
    }

    /// Returns true when the local signer is the participant with index `idx`.
    pub fn is_me(&self, idx: Participant) -> bool {
        self.scheme.me().is_some_and(|me| me == idx)
    }

    /// Advances the view.
    fn enter_view(&mut self, view: View) -> bool {
        if view <= self.view {
            return false;
        }

        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let certification_deadline = now + self.certification_timeout;
        let stall_deadline = self
            .elector
            .terms()
            .stall_timeout()
            .map(|timeout| now + timeout);

        let round = self.create_round(view);
        round.mark_entered(now);
        round.open_span();
        round.set_deadlines(leader_deadline, certification_deadline, stall_deadline);
        self.view = view;

        // Update metrics
        let _ = self.current_view.try_set(view.get());
        true
    }

    /// Returns true if the round for `view` exists and has a leader.
    fn leader_is_set(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.leader().is_some())
    }

    /// Sets the leader for the given view if it is not already set.
    fn set_leader(&mut self, view: View, certificate: Option<&S::Certificate>) {
        if self.leader_is_set(view) {
            return;
        }
        let leader = self.elector.elect(Rnd::new(self.epoch, view), certificate);
        self.create_round(view).set_leader(leader);
    }

    /// Copies the same-term stable leader into an optimistic successor.
    fn inherit_leader(&mut self, from: View, to: View) {
        if self.leader_is_set(to) {
            return;
        }
        let Some(leader) = self.views.get(&from).and_then(|round| round.leader()) else {
            return;
        };
        self.create_round(to).set_leader(leader.idx);
    }

    /// Ensures a round exists for the given view.
    fn create_round(&mut self, view: View) -> &mut Round<S, D> {
        self.views
            .entry(view)
            .or_insert_with(|| Round::new(self.scheme.clone(), Rnd::new(self.epoch, view)))
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

    /// Returns the next timeout deadline and its reason.
    pub fn next_timeout(&mut self) -> (SystemTime, TimeoutReason) {
        let now = self.context.current();
        let timeout_retry = self.timeout_retry;
        let allow_latched_timeout = self.has_skip_budget();
        let round_timeout = {
            // The current round always has a pending timeout:
            // `Round::next_timeout` only returns `None` for rounds that are
            // finalized, broadcast a finalize, or are certified with a
            // proposal, and `certified` and `add_finalization` enter the next
            // view before a round reaches any of those states.
            let round = self
                .views
                .get_mut(&self.view)
                .expect("current round must exist");
            round
                .next_timeout(now, timeout_retry, allow_latched_timeout)
                .expect("current round must always have a timeout")
        };

        // Once the current view is retrying a nullify, retry cadence should be governed
        // by timeout_retry. An older expired same-term stall deadline may still
        // exist for the first unfinalized view in the term.
        if matches!(round_timeout.1, TimeoutReason::Retry) {
            return round_timeout;
        }

        // The stall anchor only overrides a round timeout that has not
        // itself expired: when both are due, the round's reason (e.g. a latched
        // LeaderNullify or InvalidProposal) is the more diagnostic label for
        // the nullify metric.
        self.next_stall_timeout()
            .filter(|&deadline| deadline <= round_timeout.0 && now < round_timeout.0)
            .map(|deadline| (deadline, TimeoutReason::StallTimeout))
            .unwrap_or(round_timeout)
    }

    /// Returns whether the current term has skip budget remaining.
    const fn has_skip_budget(&self) -> bool {
        let term_length = self.term_length();
        let first_unfinalized = self.last_finalized.next().term_index(term_length);
        let current = self.view.term_index(term_length);
        let spent = current
            .checked_sub(first_unfinalized)
            .expect("current term must not precede the first unfinalized term");
        spent < self.skip_budget
    }

    /// Returns the oldest entered, unfinalized view's stall deadline in
    /// the current term, advancing the cached anchor past skipped rounds.
    ///
    /// Returns `None` when no stall timeout is configured (rounds never
    /// arm a deadline).
    fn next_stall_timeout(&mut self) -> Option<SystemTime> {
        let term_start = self.view.term_start(self.term_length());
        let unfinalized_view = self.last_finalized.next().max(term_start);

        // The oldest unfinalized view may never have been entered (e.g., we
        // jumped past it by certifying a future notarization), and a skipped
        // round never acquires a deadline (views are entered in order), so we
        // anchor on the oldest entered, unfinalized view in the current term.
        // `stall_anchor` advances monotonically past skipped rounds,
        // keeping the scan amortized constant time (it always terminates by
        // the current view's round, which was entered).
        let start = self.stall_anchor.max(unfinalized_view);
        let (anchor, deadline) = self
            .views
            .range(start..=self.view)
            .find_map(|(view, round)| round.stall_deadline().map(|d| (*view, d)))?;
        self.stall_anchor = anchor;
        Some(deadline)
    }

    /// Constructs a nullify vote for the current view, if eligible.
    ///
    /// `reason` labels why the view timed out (as returned by
    /// [`Self::next_timeout`]) and is only used for metrics. Retries are not
    /// counted because the timeout metric tracks timed-out views, not rebroadcasts.
    ///
    /// Returns `Some((is_retry, nullify))` where `is_retry` is true when this is not the first
    /// nullify emission for `view`. Returns `None` if `view` is not the current view or if we
    /// have already broadcast a finalize vote for this view.
    pub fn construct_nullify(
        &mut self,
        view: View,
        reason: TimeoutReason,
    ) -> Option<(bool, Nullify<S>)> {
        if view != self.view {
            return None;
        }
        let (is_retry, leader) = {
            let round = self.create_round(view);
            (round.construct_nullify()?, round.leader())
        };
        let nullify = Nullify::sign::<D>(&self.scheme, Rnd::new(self.epoch, view))?;
        self.nullify_views.insert(view);
        if !is_retry && let Some(leader) = leader {
            self.timeouts
                .get_or_create(&Timeout::new(&leader.key, reason))
                .inc();
        }
        Some((is_retry, nullify))
    }

    /// Returns the best certificate to help peers enter the current view.
    ///
    /// Finalization is strongest, then nullification, then notarization.
    ///
    /// With stable leaders, if the current view follows a skipped term, prefer
    /// a nullification from that term over a notarization at the previous view.
    /// The nullification is what proves the skipped views were abandoned, which
    /// is the evidence peers need to align on the same fork and enter the new
    /// term without timing out again while searching for skipped-view evidence.
    pub fn get_best_certificate(&self) -> Option<Certificate<S, D>> {
        let prev = self
            .view
            .previous()
            .expect("we should never be in the genesis view");

        // The genesis view has no certificates.
        if prev == GENESIS_VIEW {
            return None;
        }

        // Check if there was a finalization in the previous view
        if let Some(finalization) = self.finalization(prev).cloned() {
            return Some(Certificate::Finalization(finalization));
        }

        // At a term boundary, prefer the highest nullification from the previous
        // term because it proves the skipped views were abandoned.
        if self.view.is_term_start(self.term_length())
            && let Some(nullification) = self
                .highest_nullification_in_term(prev)
                .and_then(|v| self.nullification(v).cloned())
        {
            return Some(Certificate::Nullification(nullification));
        }

        // Check if there was a notarization in the previous view
        if let Some(notarization) = self.notarization(prev).cloned() {
            return Some(Certificate::Notarization(notarization));
        }

        warn!(%prev, "entry certificate not found");
        None
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
        self.set_leader(view.next(), Some(&notarization.certificate));
        let result = self.create_round(view).add_notarization(notarization);
        if result.0 {
            if view > self.last_finalized {
                self.certification_candidates.insert(view);
            }
            self.slide_optimistic_frontier(view);
        }
        result
    }

    /// Inserts a nullification certificate and advances to the first view of the next term.
    /// When `term_length` is 1 this is equivalent to advancing by one view.
    ///
    /// Unlike finalization, nullification does not cancel pending certification work for the
    /// same view. The next proposer may build on a certified notarization we haven't finished processing
    /// yet and stopping here could halt the network (stability relies on coming to a shared understanding
    /// of what can be considered a valid parent, otherwise two regions of the network could build on ancestries
    /// the other considers invalid with no way to resolve the conflict).
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();

        // Skip to the start of the next term. This needs no finalization
        // guard: a nullification below `last_finalized` in an earlier term
        // targets a view at or below it (`enter_view` only advances), and one
        // in the same term cannot exist (see [Same-Term Vote
        // Safety](crate::simplex#same-term-vote-safety)).
        let next_view = view.next_term_start(self.term_length());
        self.enter_view(next_view);
        self.set_leader(next_view, Some(&nullification.certificate));

        // Track nullification metric per leader (if we know who the leader was)
        let round = self.create_round(view);
        let added = round.add_nullification(nullification);
        let leader = added.then(|| round.leader()).flatten();
        self.nullification_views.insert(view);
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

            // Finalization overrides local certification rejections at or
            // below its view.
            self.failed_certifications = self.failed_certifications.split_off(&view.next());

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
        let result = self.create_round(view).add_finalization(finalization);
        if result.0 {
            self.wake_certification_child(view);
            self.slide_optimistic_frontier(view);
        }
        result
    }

    /// Returns true when an optimistic in-term `view` has locally usable
    /// ancestry for its immediate parent. Only meaningful inside
    /// [`Self::in_issuance_window`].
    ///
    /// This must use the same ancestry rule as proposal construction. A stricter
    /// rule can permanently lose a one-shot vote, while a looser rule can sign
    /// ancestry the local automaton rejected.
    ///
    /// One abstention is tolerated: a parent whose certification failed
    /// rejects the child's one-shot vote. A later parent finalization
    /// restores the ancestry but does not retry the vote: construction runs
    /// only for the view an event touches, and the finalization touches the
    /// parent. Reaching this case requires the network to finalize a proposal
    /// our automaton rejected, and that finalization proves a quorum advanced
    /// without our vote.
    fn optimistic_parent_ready(&self, view: View) -> bool {
        let Some(parent) = self.previous_in_term(view) else {
            return true;
        };

        self.optimistic_ancestry_payload(parent).is_some()
    }

    /// Construct a notarize vote for this view when we're ready to sign.
    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        if !self.admits_outbound(view) {
            return None;
        }
        // Check the cheap round-local eligibility before the ancestry gates
        // below, which re-resolve parent payloads on every event otherwise.
        if !self.views.get(&view)?.can_construct_notarize() {
            return None;
        }
        // Optimistic views wait for local evidence of their parent; anything
        // outside the issuance window carries certified ancestry already.
        if self.in_issuance_window(view) && !self.optimistic_parent_ready(view) {
            return None;
        }
        if !self.verification_matches(view) {
            return None;
        }
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_notarize().cloned())?;
        self.prepare_optimistic_successor(view);

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Notarize::sign(&self.scheme, candidate)
    }

    /// Construct a finalize vote if the round provides a candidate and it is safe to do so.
    ///
    /// The term safety rule applies: a prior same-term nullify vote blocks the
    /// finalize vote unless an observed finalization covers it (see
    /// [Same-Term Vote Safety](crate::simplex#same-term-vote-safety)).
    ///
    /// Indirect notarization can make a view usable as ancestry, but does not
    /// replace the local certification requirement for finalization.
    pub fn construct_finalize(&mut self, view: View) -> Option<Finalize<S, D>> {
        // We don't need to finalize views that are already finalized.
        if view <= self.last_finalized {
            return None;
        }

        // Certificates can create rounds arbitrarily far ahead. Do not vote
        // until the view is admissible under this node's lookahead policy.
        if !self.admits_outbound(view) {
            return None;
        }

        // Blocked by a same-term nullify vote unless an observed finalization
        // covers it (proving that nullification can never form). The plain
        // comparison suffices for coverage: the nullify vote is at or above
        // term_start(view) and last_finalized < view, so a finalization at or
        // above the nullify vote necessarily lies in the same term.
        if let Some(nullified) = self
            .highest_local_nullify_in_term(view)
            .filter(|nullified| *nullified > self.last_finalized)
        {
            debug!(%view, %nullified, "withholding finalize vote due to same-term nullify");
            return None;
        }

        // Optimistic notarize votes can notarize a child ahead of its parent's
        // certification, and finalization must not run ahead of that anchor.
        // Certification already applies this, so it only matters when replay
        // restores a certified round without re-running that precheck.
        if !self.explicit_parent_ready(view) {
            return None;
        }
        let candidate = self.views.get_mut(&view)?.construct_finalize()?.clone();

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

    /// Returns the proposal for `view` if it is eligible for forwarding
    /// (see [`Round::forwardable_proposal`]).
    pub fn forwardable_proposal(&self, view: View) -> Option<Proposal<D>> {
        self.views.get(&view)?.forwardable_proposal().cloned()
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
    ///
    /// Restores round-level broadcast flags (via [`Round::replay`]) and
    /// tracking sets (`nullify_views`, `nullification_views`, and
    /// `failed_certifications`) so that term-safety and ancestry checks work
    /// correctly after a restart. Replaying a local notarize vote also restores
    /// the optimistic successor prepared by live vote construction. Unlike
    /// [`Self::add_nullification`] (which the actor's replay loop also calls,
    /// making the `nullification_views` insert idempotent on that path), this
    /// never advances the view.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        if let Artifact::Nullify(n) = artifact {
            self.nullify_views.insert(n.view());
        }
        if let Artifact::Nullification(n) = artifact {
            self.nullification_views.insert(n.view());
        }
        if matches!(artifact, Artifact::Certification(_, false))
            && artifact.view() > self.last_finalized
        {
            self.failed_certifications.insert(artifact.view());
        }
        self.create_round(artifact.view()).replay(artifact);
        if matches!(artifact, Artifact::Notarize(_)) {
            self.prepare_optimistic_successor(artifact.view());
        }
    }

    /// Returns the leader index for `view` if we already entered it.
    pub fn leader_index(&self, view: View) -> Option<Participant> {
        self.views
            .get(&view)
            .and_then(|round| round.leader().map(|leader| leader.idx))
    }

    /// Returns how long ago the local node started work on `view` (see
    /// [`Round::elapsed_since_start`]), or None if the view is untracked or
    /// was never started.
    pub fn elapsed_since_start(&self, view: View) -> Option<Duration> {
        let now = self.context.current();
        self.views
            .get(&view)
            .and_then(|round| round.elapsed_since_start(now))
    }

    /// Immediately expires `view` on its first timeout when skip budget is
    /// available, forcing a timeout to fire on the next tick. Otherwise, the
    /// timeout remains latched until budget becomes available.
    ///
    /// If the round has already been marked timed out, this preserves the existing
    /// retry schedule.
    ///
    /// This only latches the first timeout for the view (see
    /// [`Round::latch_timeout`]); the latched reason is delivered back through
    /// [`Self::next_timeout`] when the timeout fires.
    ///
    /// [`Self::next_timeout`] only polls the current round, so views already
    /// advanced past are ignored: their latch would have no reader. Failures
    /// for tracked optimistic future views latch on their round without
    /// nullifying early. The buffered proposal suppresses the leader timeout
    /// and its verification request is consumed, so a dropped latch would
    /// stall the view until certification timeout once it becomes current.
    pub fn trigger_timeout(&mut self, view: View, reason: TimeoutReason) {
        if view < self.view {
            return;
        }

        let now = self.context.current();
        let Some(round) = self.views.get_mut(&view) else {
            return;
        };
        // An inactivity timeout is only a hint that the leader is silent; a
        // buffered unequivocated proposal proves the leader is active, so
        // ignore it (other timeout reasons still latch).
        if matches!(reason, TimeoutReason::Inactivity) && round.has_unequivocated_proposal() {
            return;
        }
        round.latch_timeout(now, reason);
    }

    /// Returns proposal context for the lowest locally admissible tracked view
    /// ready to propose.
    pub fn try_propose(&mut self) -> Option<Context<D, S::PublicKey>> {
        // Nothing above the next term start is admissible (see
        // [`Self::admits_outbound`]), so bound the scan rather than walking every
        // tracked future round (certificates can land arbitrarily far ahead).
        // Ascending order gives the current view precedence over optimistic work.
        let limit = self.view.next_term_start(self.term_length());
        let mut cursor = self.view;
        while let Some(view) = self.next_tracked_view(cursor) {
            if view > limit {
                break;
            }
            cursor = view.next();
            if view == GENESIS_VIEW {
                continue;
            }
            if !self.admits_outbound(view) {
                continue;
            }
            if !self
                .views
                .get(&view)
                .is_some_and(|round| round.should_propose())
            {
                continue;
            }

            // Resolve ancestry before claiming the one-shot build request so a
            // missing parent leaves the round eligible for a later retry.
            let (parent_view, parent_payload) = match self.find_parent(view) {
                Ok(parent) => parent,
                Err(missing) => {
                    debug!(%view, %missing, "missing parent during proposal");
                    continue;
                }
            };
            let Some(leader) = self
                .views
                .get_mut(&view)
                .and_then(|round| round.try_propose())
            else {
                continue;
            };
            return Some(Context {
                round: Rnd::new(self.epoch, view),
                leader: leader.key,
                parent: (parent_view, parent_payload),
            });
        }
        None
    }

    /// Records a locally constructed proposal once the automaton finishes building it.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> bool {
        let now = self.context.current();
        self.views
            .get_mut(&proposal.view())
            .map(|round| round.proposed(now, proposal))
            .unwrap_or(false)
    }

    /// Sets a proposal received from the batcher (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(&mut self, view: View, proposal: Proposal<D>) -> bool {
        self.prepare_optimistic_successor(view);
        self.create_round(view).set_proposal(proposal)
    }

    /// Returns the ancestry fetch a verification error justifies, if any.
    ///
    /// An uncertified parent inside the optimistic issuance window is pending,
    /// not missing: its certificate is still forming from live vote traffic,
    /// so there is nothing to fetch yet. If we fall behind, our issuance
    /// anchor freezes and newer proposals leave the window (see
    /// [`Self::in_issuance_window`]), so the fetch resumes.
    fn resolve_ancestry(&self, err: &ParentPayloadError) -> Option<(View, Kind)> {
        match err {
            ParentPayloadError::MissingNullification { missing_view, .. } => {
                Some((*missing_view, Kind::Nullification))
            }
            ParentPayloadError::ParentNotCertified {
                proposal_view,
                parent_view,
            } => {
                if self.in_issuance_window(*proposal_view) {
                    return None;
                }
                Some((*parent_view, Kind::Notarization))
            }
            _ => None,
        }
    }

    /// Returns work for the lowest locally admissible tracked proposal awaiting
    /// verification.
    ///
    /// Missing ancestry is requested from the proposal's elected leader
    /// (see [`Self::resolve_ancestry`] for when an error justifies a fetch).
    pub fn try_verify(&mut self) -> Verify<S, D> {
        // Bound the scan as in [`Self::try_propose`].
        // Ascending order gives the current view precedence over optimistic work.
        let limit = self.view.next_term_start(self.term_length());
        let mut cursor = self.view;
        while let Some(view) = self.next_tracked_view(cursor) {
            if view > limit {
                break;
            }
            cursor = view.next();
            if !self.admits_outbound(view) {
                continue;
            }
            let Some((leader, proposal)) = self
                .views
                .get(&view)
                .and_then(|round| round.pending_verification())
            else {
                continue;
            };

            // Validate ancestry before claiming the request. Invalid structure
            // times out the view; missing evidence either waits for live
            // certification or produces one targeted fetch.
            let parent_payload = match self.parent_payload(&proposal) {
                Ok(parent_payload) => parent_payload,
                Err(err) => {
                    if err.invalid_proposal() {
                        warn!(round = ?proposal.round, ?err, "proposal failed verification");
                        self.trigger_timeout(view, TimeoutReason::InvalidProposal);
                        continue;
                    }
                    debug!(
                        %view,
                        ?proposal,
                        ?err,
                        "proposal exists but ancestry is not yet certified"
                    );
                    let Some((missing, kind)) = self.resolve_ancestry(&err) else {
                        continue;
                    };
                    if !self
                        .views
                        .get_mut(&view)
                        .expect("tracked round must exist")
                        .request(missing)
                    {
                        continue;
                    }
                    return Verify::Resolve {
                        proposal: proposal.view(),
                        view: missing,
                        kind,
                        target: leader.key,
                    };
                }
            };
            let Some(round) = self.views.get_mut(&view) else {
                continue;
            };
            if !round.request_verify() {
                continue;
            }
            round.set_verifying(proposal.clone(), parent_payload);
            return Verify::Ready(
                Context {
                    round: proposal.round,
                    leader: leader.key,
                    parent: (proposal.parent, parent_payload),
                },
                proposal,
            );
        }
        Verify::Wait
    }

    /// Returns true when a verification completion describes a proposal or
    /// parent we have since replaced, discarding the stale binding.
    ///
    /// A same-view certificate can replace the proposal while the request is in
    /// flight without advancing the voter. An optimistic child's parent can
    /// likewise be displaced before it certifies. In either case, the
    /// completion says nothing about the proposal and ancestry we now hold.
    ///
    /// A replacement proposal is certificate-backed and proceeds through
    /// certification. A proposal with a displaced parent still commits to its
    /// original parent, so it cannot be reverified under the replacement parent.
    /// The proposal's view resolves through a peer's notarization of that proposal
    /// or the timeout/nullification path.
    ///
    /// Discarding a stale rejection trades latency, not safety. Only parent
    /// displacement can delay the view until the certification timeout instead
    /// of an immediate nullify. The displacing certificate identifies the
    /// equivocating leader, whom the voter blocks. Each Byzantine leader can
    /// cause this delay at most once. Later views skip that leader at the leader
    /// timeout.
    fn verification_is_stale(&mut self, view: View) -> bool {
        if self.verification_matches(view) {
            return false;
        }
        if let Some(round) = self.views.get_mut(&view) {
            round.clear_verifying();
        }
        true
    }

    /// Marks proposal verification as complete when the peer payload validates.
    pub fn verified(&mut self, view: View) -> bool {
        if self.verification_is_stale(view) {
            return false;
        }
        self.views
            .get_mut(&view)
            .map(|round| round.verified())
            .unwrap_or(false)
    }

    /// Latches `reason` after the automaton rejected or dropped a proposal.
    ///
    /// Discards a stale verdict so it cannot forfeit the view after its
    /// proposal or resolved parent has been replaced.
    pub fn verification_failed(&mut self, view: View, reason: TimeoutReason) {
        if self.verification_is_stale(view) {
            return;
        }
        self.trigger_timeout(view, reason);
    }

    /// Store the abort handle for an in-flight certification request.
    pub fn set_certify_handle(&mut self, view: View, handle: Aborter) {
        let Some(round) = self.views.get_mut(&view) else {
            return;
        };
        round.set_certify_handle(handle);
        self.outstanding_certifications.insert(view);
    }

    /// Queues a blocked immediate same-term child when `parent` certifies or
    /// finalizes.
    fn wake_certification_child(&mut self, parent: View) {
        let child = parent.next();
        if self.previous_in_term(child) != Some(parent)
            || child <= self.last_finalized
            || !self
                .views
                .get(&child)
                .is_some_and(|round| round.notarization().is_some())
        {
            return;
        }
        self.certification_candidates.insert(child);
    }

    /// Takes newly notarized or unblocked certification candidates and returns
    /// proposals ready for certification, plus fetches for missing parent
    /// certificates (see [`Self::certification_fetch`]).
    pub fn certify_candidates(&mut self) -> (Vec<Proposal<D>>, Vec<CertificateFetch>) {
        let candidates = take(&mut self.certification_candidates);
        let mut ready = Vec::new();
        let mut fetches = Vec::new();
        for view in candidates {
            if view <= self.last_finalized {
                continue;
            }

            let Some(proposal) = self
                .views
                .get(&view)
                .and_then(|round| round.proposal())
                .cloned()
            else {
                continue;
            };
            if let Err(err) = self.certification_parent_ready(&proposal) {
                if err.invalid_proposal() {
                    warn!(round = ?proposal.round, ?err, "proposal failed certification precheck");
                } else {
                    // Dormant candidates wake only through
                    // [`Self::wake_certification_child`]. Therefore,
                    // [`Self::certification_parent_ready`] may block only on an
                    // uncertified parent.
                    assert!(
                        matches!(err, ParentPayloadError::ParentNotCertified { .. }),
                        "blocked candidate has no wake: {err:?}"
                    );
                    fetches.extend(self.certification_fetch(&err));
                }
                continue;
            }

            if let Some(candidate) = self
                .views
                .get_mut(&view)
                .and_then(|round| round.try_certify())
            {
                ready.push(candidate);
            }
        }
        (ready, fetches)
    }

    /// Returns the fetch a blocked certification justifies, if any.
    ///
    /// A candidate whose parent is uncertified but notarized locally completes
    /// on its own: the parent's certification is already pending. Without the
    /// parent's notarization, no later event delivers it. Peers broadcast a
    /// certificate once, and the candidate's own certificate proves the votes
    /// that could form it have stopped circulating. The certificate must be
    /// fetched, or the voter can never certify another view in the term.
    fn certification_fetch(&self, err: &ParentPayloadError) -> Option<CertificateFetch> {
        let ParentPayloadError::ParentNotCertified {
            proposal_view,
            parent_view,
        } = err
        else {
            return None;
        };
        if self.notarization(*parent_view).is_some() {
            return None;
        }

        // Verification can request this parent only from the proposal's leader.
        // Certification bypasses that request latch. If the fetch is in flight,
        // the resolver removes its target. The candidate remains dormant until
        // its parent arrives, so this request does not repeat.
        //
        // Only mid-term candidates require the previous view as their parent,
        // so the candidate and parent are in the same term. Any validator can
        // hold the parent's notarization, so certification sends this request
        // without a target.
        Some(CertificateFetch {
            proposal: *proposal_view,
            view: *parent_view,
        })
    }

    /// Marks proposal certification as complete and returns the notarization.
    ///
    /// Returns `None` if the view was already pruned. Otherwise returns the notarization
    /// regardless of success/failure.
    pub fn certified(&mut self, view: View, is_success: bool) -> Option<Notarization<S, D>> {
        let round = self.views.get_mut(&view)?;
        round.certified(is_success);

        // Get notarization before advancing state
        let notarization = round
            .notarization()
            .cloned()
            .expect("notarization must exist for certified view");

        // Remove from outstanding since certification is complete
        self.outstanding_certifications.remove(&view);
        if !is_success && view > self.last_finalized {
            self.failed_certifications.insert(view);
        }

        if is_success {
            // Keep the stall deadline armed after certification so the
            // term-level timeout can still abandon a term that certifies but
            // never finalizes.
            self.enter_view(view.next());
            self.wake_certification_child(view);
        } else {
            self.trigger_timeout(view, TimeoutReason::FailedCertification);
        }

        Some(notarization)
    }

    /// Drops tracked rounds below the activity horizon and stale safety-evidence indexes.
    ///
    /// The activity horizon retains all safety evidence that can still matter:
    /// gate-relevant nullify votes are above `last_finalized` (votes at or
    /// below it are healed by the covering finalization), and same-term vote
    /// safety guarantees no current-term nullification exists at or below
    /// `last_finalized`, so both sets only hold load-bearing entries above
    /// `min_active`.
    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let kept = self.views.split_off(&min);
        let removed = replace(&mut self.views, kept).into_keys().collect();
        self.nullification_views = self.nullification_views.split_off(&min);
        self.nullify_views = self.nullify_views.split_off(&min);

        // Update metrics
        let _ = self.tracked_views.try_set(self.views.len());
        removed
    }

    // ---- Ancestry rules ----
    //
    // The `*_ancestry_payload` resolvers answer what payload a view may
    // contribute as ancestry. Verification and proposal go through
    // `ancestry_payload_for_child`, which picks the optimistic rule inside the
    // issuance window and the explicit rule outside it.
    //
    // The `*_parent_ready` predicates answer whether a view's immediate parent
    // is settled enough to act on. Certification and finalization require
    // `explicit_parent_ready`. Notarize issuance uses `optimistic_parent_ready`,
    // which delegates to `optimistic_ancestry_payload` so issuance and proposal
    // construction share one ancestry rule.

    /// Returns the payload of `view`'s explicitly certified (or finalized)
    /// proposal, the strongest form of ancestry.
    fn explicit_ancestry_payload(&self, view: View) -> Option<&D> {
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        // Check for explicit certification
        self.views.get(&view)?.certified_payload()
    }

    /// Returns the highest view in `view`'s term, at or below `view`, with a
    /// tracked nullification certificate.
    fn highest_nullification_in_term(&self, view: View) -> Option<View> {
        self.nullification_views
            .range(view.covering_range(self.term_length()))
            .next_back()
            .copied()
    }

    /// Returns the highest view below `view` in `view`'s term that we voted to nullify.
    fn highest_local_nullify_in_term(&self, view: View) -> Option<View> {
        let term_start = view.term_start(self.term_length());
        self.nullify_views
            .range(term_start..view)
            .next_back()
            .copied()
    }

    /// Resolves `parent`'s payload under the ancestry rule `child` is
    /// entitled to: optimistic ancestry inside the issuance window, explicit
    /// certification outside it.
    fn ancestry_payload_for_child(&self, child: View, parent: View) -> Option<&D> {
        if self.in_issuance_window(child) {
            return self.optimistic_ancestry_payload(parent);
        }
        self.explicit_ancestry_payload(parent)
    }

    /// Returns true when `view` or a same-term predecessor has an unresolved
    /// local certification rejection. Intra-term proposals link every
    /// intermediate view; term starts instead require explicit ancestry.
    fn has_failed_optimistic_ancestry(&self, view: View) -> bool {
        self.failed_certifications
            .range(view.term_start(self.term_length())..=view)
            .next()
            .is_some()
    }

    /// Returns the payload of a parent usable as *optimistic* ancestry: a
    /// certificate-backed payload when one exists, otherwise our own verified,
    /// unequivocated, notarize-broadcast proposal; recursively, so the whole
    /// uncertified chain rests on views we voted for ourselves.
    fn optimistic_ancestry_payload(&self, view: View) -> Option<&D> {
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        let round = self.views.get(&view)?;

        // Serve directly-certified ancestry from the stored certificate so it
        // is always payload the certificate actually supports, independent of
        // the slot's proposal bookkeeping.
        if round.is_directly_notarized() {
            if self.has_failed_optimistic_ancestry(view) {
                return None;
            }
            return round.certificate_ancestry_payload();
        }

        // `view` may only be used as optimistic same-term ancestry when its
        // child is within the optimistic lookahead window.
        if !self.in_issuance_window(view.next()) {
            return None;
        }

        if !round.has_unequivocated_proposal()
            || !round.broadcast_notarize()
            || !round.is_verified()
        {
            return None;
        }

        let proposal = round.proposal()?;
        if proposal.parent < self.last_finalized {
            return None;
        }
        if let Some(missing_view) = self.first_unnullified_view(proposal.parent, proposal.view()) {
            debug!(%view, %missing_view, "optimistic ancestor missing nullification");
            return None;
        }
        self.optimistic_ancestry_payload(proposal.parent)?;
        Some(&proposal.payload)
    }

    /// Pushes the optimistic frontier one view, so stable leaders can chain
    /// proposals. Called when we sign a notarize vote or receive the leader's
    /// proposal for a view.
    fn prepare_optimistic_successor(&mut self, view: View) {
        let next = view.next();
        if !self.in_issuance_window(next) {
            return;
        }
        self.inherit_leader(view, next);
    }

    /// Re-extends the optimistic frontier (the highest same-term view stamped
    /// with the term's stable leader, and so able to accept a proposal before
    /// its ancestry certifies) through the issuance window that `view`'s
    /// notarization just opened. Every direct anchor slides its own window when
    /// first inserted, so this walk is bounded by the triggering anchor alone.
    fn slide_optimistic_frontier(&mut self, view: View) {
        let mut frontier = view;
        let mut next = frontier.next();
        while self.in_issuance_window_from(view, next) {
            self.inherit_leader(frontier, next);
            frontier = next;
            next = frontier.next();
        }
    }

    fn verification_matches(&self, view: View) -> bool {
        // Bindings are recorded only for peer proposals (in try_verify). A locally
        // built proposal is never completed through this verification path.
        let Some(round) = self.views.get(&view) else {
            return true;
        };
        let Some((verifying, parent_payload)) = round.verifying() else {
            return true;
        };
        let Some(proposal) = round.proposal() else {
            return false;
        };
        if proposal != verifying {
            return false;
        }
        self.parent_payload(proposal)
            .is_ok_and(|payload| payload == *parent_payload)
    }

    fn previous_in_term(&self, view: View) -> Option<View> {
        if view == GENESIS_VIEW || view.is_term_start(self.term_length()) {
            return None;
        }
        Some(
            view.previous()
                .expect("non-genesis non-term-start views must have a predecessor"),
        )
    }

    /// Returns the first non-nullified view in the open interval (after, before).
    ///
    /// A nullification nullifies all views in the rest of its term.
    fn first_unnullified_view(&self, after: View, before: View) -> Option<View> {
        let mut cursor = after.next();
        while cursor < before {
            if self.highest_nullification_in_term(cursor).is_none() {
                return Some(cursor);
            }
            cursor = cursor.next_term_start(self.term_length());
        }
        None
    }

    /// Returns true if certification for the view was aborted due to finalization.
    #[cfg(test)]
    pub fn is_certify_aborted(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.is_certify_aborted())
    }

    /// Finds the parent payload for a given view: the highest certified view
    /// below `view`, if it has no missing required nullification. When there is
    /// no certified view below `view`, the parent is the genesis view and the
    /// genesis payload.
    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        if !view.is_term_start(self.term_length()) {
            let parent = view
                .previous()
                .expect("non-genesis views must have a previous view");
            let payload = self.ancestry_payload_for_child(view, parent);
            return payload
                .copied()
                .map(|payload| (parent, payload))
                .ok_or(parent);
        }

        // Find the highest certified view below `view`, or use genesis when none.
        let result = self
            .views
            .range(..view)
            .rev()
            .find_map(|(&v, round)| round.certified_payload().map(|p| (v, p)));
        let (candidate, payload) = match result {
            Some((v, p)) => (v, p),
            None => (
                GENESIS_VIEW,
                self.genesis
                    .as_ref()
                    .expect("genesis must be set when finding parent with no certified views"),
            ),
        };

        // If there are any missing nullifications, return an error.
        // Any lower certified views would also result in an error.
        if let Some(missing_view) = self.first_unnullified_view(candidate, view) {
            return Err(missing_view);
        }

        // Return the valid parent
        Ok((candidate, *payload))
    }

    /// Returns the payload of the proposal's parent if:
    /// - It is less-than the proposal view.
    /// - It is greater-than-or-equal-to the last finalized view.
    /// - It is certified (or finalized, which implies certification).
    /// - All views between it and the proposal view have been nullified.
    fn parent_payload(&self, proposal: &Proposal<D>) -> Result<D, ParentPayloadError> {
        self.validate_parent_span(proposal)?;
        let (view, parent) = (proposal.view(), proposal.parent);

        // May return `None` if the parent view is not yet either:
        // - notarized and certified
        // - finalized
        let payload = self.ancestry_payload_for_child(view, parent);
        payload
            .copied()
            .ok_or(ParentPayloadError::ParentNotCertified {
                proposal_view: view,
                parent_view: parent,
            })
    }

    /// Returns whether certification may run for a proposal.
    ///
    /// Optimistic notarize votes can make a same-term child notarized before
    /// its immediate parent has certified, but certification waits for explicit
    /// certified or finalized parent ancestry.
    ///
    /// Exempting term-start views is sound because this precheck exists only
    /// to close the intra-term optimistic gap, which term starts cannot be in:
    /// they are never issued optimistically (see
    /// [`Lookahead::issuance_floor`](crate::simplex::Lookahead)), so a
    /// term-start proposal can only have been verified through explicit
    /// ancestry.
    fn certification_parent_ready(&self, proposal: &Proposal<D>) -> Result<(), ParentPayloadError> {
        let (view, parent) = (proposal.view(), proposal.parent);
        Self::ensure_parent_precedes(view, parent)?;

        if view.is_term_start(self.term_length()) {
            return Ok(());
        }

        // Intra-term views share the structural rules (the nullification check
        // is trivially satisfied once contiguity holds).
        self.validate_parent_span(proposal)?;

        if self.explicit_parent_ready(view) {
            return Ok(());
        }

        Err(ParentPayloadError::ParentNotCertified {
            proposal_view: view,
            parent_view: parent,
        })
    }

    /// Returns true when `view`'s immediate in-term parent is explicitly
    /// certified (or finalized), the ancestry that certification and
    /// finalization both require. Term starts have no in-term parent and always pass.
    fn explicit_parent_ready(&self, view: View) -> bool {
        self.previous_in_term(view)
            .is_none_or(|parent| self.explicit_ancestry_payload(parent).is_some())
    }

    /// Ensures the parent view strictly precedes the proposal view.
    fn ensure_parent_precedes(view: View, parent: View) -> Result<(), ParentPayloadError> {
        if view <= parent {
            return Err(ParentPayloadError::ParentNotBeforeProposal {
                proposal_view: view,
                parent_view: parent,
            });
        }
        Ok(())
    }

    /// Validates the structural link between a proposal and its parent view.
    fn validate_parent_span(&self, proposal: &Proposal<D>) -> Result<(), ParentPayloadError> {
        let (view, parent) = (proposal.view(), proposal.parent);
        Self::ensure_parent_precedes(view, parent)?;

        // Ignore any requests for outdated parent views.
        if parent < self.last_finalized {
            return Err(ParentPayloadError::ParentBeforeFinalized {
                proposal_view: view,
                parent_view: parent,
                last_finalized: self.last_finalized,
            });
        }

        // Check that intra-term proposals do not skip any views.
        if !view.is_term_start(self.term_length()) && view != parent.next() {
            return Err(ParentPayloadError::IntraTermProposalSkipsViews {
                proposal_view: view,
                parent_view: parent,
            });
        }

        // Check that required nullifications exist between the parent and proposal views.
        if let Some(missing_view) = self.first_unnullified_view(parent, view) {
            return Err(ParentPayloadError::MissingNullification {
                proposal_view: view,
                parent_view: parent,
                missing_view,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        elector::{Config as _, RoundRobin, RoundRobinElector, Terms},
        scheme::ed25519,
        types::{Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal},
    };
    use commonware_cryptography::{
        certificate::{Scheme as _, mocks::Fixture},
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZU32, futures::AbortablePool, non_empty};
    use std::time::Duration;

    fn round_robin<S: certificate::Scheme>(scheme: &S) -> RoundRobinElector<S> {
        <RoundRobin>::default().build(scheme.participants())
    }

    fn round_robin_with_term<S: certificate::Scheme>(
        scheme: &S,
        term_length: TermLength,
        stall_timeout: Duration,
        optimistic_views: ViewDelta,
    ) -> RoundRobinElector<S> {
        <RoundRobin>::default()
            .with_term(term_length, stall_timeout, optimistic_views)
            .build(scheme.participants())
    }

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

    /// Builds an epoch-9 proposal for the certification-fetch tests.
    fn fetch_proposal(view: u64, parent: u64, payload: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Rnd::new(Epoch::new(9), View::new(view)),
            View::new(parent),
            Sha256Digest::from([payload; 32]),
        )
    }

    /// Notarizes and certifies view 1 so later views have certified ancestry.
    fn certify_first_view(
        state: &mut TestState,
        verifier: &ed25519::Scheme,
        schemes: &[ed25519::Scheme],
    ) {
        let proposal = fetch_proposal(1, 0, 101);
        let notarization = build_notarization(verifier, schemes, &proposal);
        assert!(state.add_notarization(notarization).0);
        let (ready, fetches) = state.certify_candidates();
        assert_eq!(ready.len(), 1);
        assert!(fetches.is_empty());
        assert!(state.certified(View::new(1), true).is_some());
    }

    fn build_notarization(
        verifier: &ed25519::Scheme,
        schemes: &[ed25519::Scheme],
        proposal: &Proposal<Sha256Digest>,
    ) -> Notarization<ed25519::Scheme, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        Notarization::from_notarizes(verifier, non_empty![@votes.iter()], &Sequential)
            .expect("notarization")
    }

    fn build_nullification(
        verifier: &ed25519::Scheme,
        schemes: &[ed25519::Scheme],
        round: Rnd,
    ) -> Nullification<ed25519::Scheme> {
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("nullify"))
            .collect();
        Nullification::from_nullifies(verifier, non_empty![@&votes], &Sequential)
            .expect("nullification")
    }

    fn build_finalization(
        verifier: &ed25519::Scheme,
        schemes: &[ed25519::Scheme],
        proposal: &Proposal<Sha256Digest>,
    ) -> Finalization<ed25519::Scheme, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
            .collect();
        Finalization::from_finalizes(verifier, non_empty![@votes.iter()], &Sequential)
            .expect("finalization")
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
                    elector: round_robin(&verifier),
                    epoch,
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: verifier.participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // Finalize view 2, advancing the finalized view and entering view 3.
            let finalize_view = View::new(2);
            let finalize_round = Rnd::new(epoch, finalize_view);
            let proposal =
                Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([7u8; 32]));
            let finalization = build_finalization(&verifier, &schemes, &proposal);
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

    type TestState = State<
        deterministic::Context,
        ed25519::Scheme,
        RoundRobinElector<ed25519::Scheme>,
        Sha256Digest,
    >;

    fn setup_state(
        context: &mut deterministic::Context,
        validators: usize,
        epoch: u64,
        view_retention: u64,
        term_length: u32,
        skip_budget: u64,
    ) -> (Fixture<ed25519::Scheme>, TestState) {
        let namespace = b"ns".to_vec();
        let fixture = ed25519::fixture(
            context,
            &namespace,
            validators.try_into().expect("validator count fits in u32"),
        );
        let elector = match term_length {
            1 => round_robin(&fixture.verifier),
            _ => round_robin_with_term(
                &fixture.verifier,
                TermLength::new(NZU32!(term_length)),
                Duration::from_secs(30),
                ViewDelta::new(0),
            ),
        };
        let state = State::new(
            context.child("state"),
            Config {
                scheme: fixture.verifier.clone(),
                elector,
                epoch: Epoch::new(epoch),
                view_retention: ViewDelta::new(view_retention),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget,
            },
        );
        let mut state = state;
        state.set_genesis(test_genesis());
        (fixture, state)
    }

    /// Like [setup_state], but signs as `schemes[signer]` (rather than the
    /// verifier) and parameterizes `optimistic_views`.
    #[allow(clippy::too_many_arguments)]
    fn setup_state_with(
        context: &mut deterministic::Context,
        validators: usize,
        signer: usize,
        epoch: u64,
        view_retention: u64,
        term_length: TermLength,
        optimistic_views: ViewDelta,
        skip_budget: u64,
    ) -> (Fixture<ed25519::Scheme>, TestState) {
        let namespace = b"ns".to_vec();
        let fixture = ed25519::fixture(
            context,
            &namespace,
            validators.try_into().expect("validator count fits in u32"),
        );
        let scheme = fixture.schemes[signer].clone();
        let elector = if term_length == TermLength::ONE {
            round_robin(&scheme)
        } else {
            round_robin_with_term(
                &scheme,
                term_length,
                Duration::from_secs(4),
                optimistic_views,
            )
        };
        let mut state = State::new(
            context.child("state"),
            Config {
                scheme,
                elector,
                epoch: Epoch::new(epoch),
                view_retention: ViewDelta::new(view_retention),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget,
            },
        );
        state.set_genesis(test_genesis());
        (fixture, state)
    }

    /// Proposes `payload` at view 1 (on top of genesis) and broadcasts our
    /// notarize vote for it, returning the proposal.
    fn propose_and_notarize_view1(state: &mut TestState, payload: u8) -> Proposal<Sha256Digest> {
        let proposal = Proposal::new(
            Rnd::new(state.epoch(), View::new(1)),
            GENESIS_VIEW,
            Sha256Digest::from([payload; 32]),
        );
        state.create_round(View::new(1));
        assert!(state.proposed(proposal.clone()));
        assert!(state.construct_notarize(View::new(1)).is_some());
        proposal
    }

    /// An elector that panics if asked to elect a leader without a certificate
    /// (past view 1). Optimistic successors must inherit the stable leader
    /// instead of running a fresh election.
    #[derive(Clone)]
    struct RequireCertificateElector<S> {
        term_length: TermLength,
        _phantom: std::marker::PhantomData<S>,
    }

    impl<S: certificate::Scheme> Elector<S> for RequireCertificateElector<S> {
        fn terms(&self) -> Terms {
            Terms::stable(self.term_length, Duration::from_secs(30), ViewDelta::new(1))
        }

        fn elect(&self, round: Rnd, certificate: Option<&S::Certificate>) -> Participant {
            assert!(
                certificate.is_some() || round.view() == View::new(1),
                "certificate required after view 1"
            );
            Participant::new(0)
        }
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
                    elector: round_robin(&verifier),
                    epoch: Epoch::new(11),
                    view_retention: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: verifier.participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // Add notarization
            let notarize_view = View::new(3);
            let notarize_round = Rnd::new(Epoch::new(11), notarize_view);
            let notarize_proposal =
                Proposal::new(notarize_round, GENESIS_VIEW, Sha256Digest::from([50u8; 32]));
            let notarization = build_notarization(&verifier, &schemes, &notarize_proposal);
            state.add_notarization(notarization);

            // Produce candidate once
            assert!(state.broadcast_notarization(notarize_view).is_some());
            assert!(state.broadcast_notarization(notarize_view).is_none());
            assert!(state.notarization(notarize_view).is_some());

            // Add nullification
            let nullify_view = View::new(4);
            let nullify_round = Rnd::new(Epoch::new(11), nullify_view);
            let nullification = build_nullification(&verifier, &schemes, nullify_round);
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
            let finalization = build_finalization(&verifier, &schemes, &finalize_proposal);
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
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(4),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                skip_budget: local_scheme.participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Should return same deadline until something done
            let first = state.next_timeout();
            let second = state.next_timeout();
            assert_eq!(first, second, "cached timeout should be reused");

            // Timeout-mode nullify: first emission should not be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view(), TimeoutReason::LeaderTimeout)
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout is not a retry");

            // Set retry deadline
            context.sleep(Duration::from_secs(2)).await;
            let later = context.current();

            // Confirm retry deadline is set
            let third = state.next_timeout();
            assert_eq!(
                third,
                (later + retry, TimeoutReason::Retry),
                "new retry scheduled after timeout"
            );

            // Confirm retry deadline remains set
            let fourth = state.next_timeout();
            assert_eq!(fourth, third, "retry deadline should be set");

            // Confirm works if later is far in the future
            context.sleep(Duration::from_secs(10)).await;
            let fifth = state.next_timeout();
            assert_eq!(
                fifth,
                (later + retry, TimeoutReason::Retry),
                "retry deadline should be set"
            );

            // Timeout-mode nullify: second emission should be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view(), TimeoutReason::Retry)
                .expect("retry timeout nullify should exist");
            assert!(was_retry, "subsequent timeout should be treated as retry");

            // Confirm retry deadline is set
            let sixth = state.next_timeout();
            let later = context.current();
            assert_eq!(
                sixth,
                (later + retry, TimeoutReason::Retry),
                "retry deadline should be set"
            );
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(30),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view, TimeoutReason::LeaderTimeout)
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout should not be marked as retry");

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.timeouts.get_or_create(&label).get(),
                1,
                "first nullify should record a leader-timeout metric"
            );

            context.sleep(Duration::from_secs(2)).await;
            let now = context.current();
            let retry_deadline = state.next_timeout();
            assert_eq!(
                retry_deadline,
                (now + retry, TimeoutReason::Retry),
                "first retry should honor configured nullify backoff"
            );

            // Repeated timeout hints for the same view should not reset retry backoff.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            assert_eq!(
                state.next_timeout(),
                retry_deadline,
                "retry backoff should be preserved after repeated timeout hints"
            );
        });
    }

    #[test]
    fn nullify_records_reason_from_next_timeout() {
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(31),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // The latched reason is delivered through next_timeout (mirroring
            // the actor) and recorded by the nullify metric.
            let view = state.current_view();
            state.trigger_timeout(view, TimeoutReason::MissingProposal);
            let (_, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::MissingProposal);
            let (was_retry, _) = state
                .construct_nullify(view, reason)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let missing = Timeout::new(leader_key, TimeoutReason::MissingProposal);
            let leader_timeout = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(state.timeouts.get_or_create(&missing).get(), 1);
            assert_eq!(state.timeouts.get_or_create(&leader_timeout).get(), 0);

            // Retries are governed by the retry cadence regardless of the
            // reason passed.
            let (_, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::Retry);
            let (was_retry, _) = state
                .construct_nullify(view, reason)
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(32),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
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
            let certification_deadline = state.next_timeout();
            assert_eq!(
                certification_deadline,
                (
                    context.current() + Duration::from_secs(2),
                    TimeoutReason::CertificationTimeout,
                )
            );

            // Receiving a notarization should not clear the certification timeout while certification is pending.
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());
            assert_eq!(
                state.next_timeout(),
                certification_deadline,
                "certification timeout must continue to bound certification latency"
            );

            // If certification stalls beyond the certification timeout, timeout handling should fire immediately.
            context.sleep(Duration::from_secs(3)).await;
            assert!(
                state.next_timeout().0 <= context.current(),
                "stalled certification should leave the view timed out"
            );
        });
    }

    #[test]
    fn stall_timeout_tracks_oldest_unfinalized_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(33),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let oldest_deadline = context.current() + Duration::from_secs(4);

            let certify_view = |state: &mut TestState,
                                schemes: &[ed25519::Scheme],
                                verifier: &ed25519::Scheme,
                                view: View,
                                parent: View,
                                payload: [u8; 32]| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(33), view),
                    parent,
                    Sha256Digest::from(payload),
                );
                assert!(state.set_proposal(view, proposal.clone()));
                assert!(matches!(state.try_verify(), Verify::Ready(..)));
                assert!(state.verified(view));
                let notarization = build_notarization(verifier, schemes, &proposal);
                assert!(state.add_notarization(notarization).0);
            };

            certify_view(
                &mut state,
                &schemes,
                &verifier,
                View::new(1),
                GENESIS_VIEW,
                [1u8; 32],
            );
            context.sleep(Duration::from_secs(1)).await;
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            certify_view(
                &mut state,
                &schemes,
                &verifier,
                View::new(2),
                View::new(1),
                [2u8; 32],
            );
            context.sleep(Duration::from_millis(1500)).await;
            assert!(state.certified(View::new(2), true).is_some());
            assert_eq!(state.current_view(), View::new(3));
            let v3_certification_deadline = context.current() + Duration::from_secs(2);

            let proposal_v3 = Proposal::new(
                Rnd::new(Epoch::new(33), View::new(3)),
                View::new(2),
                Sha256Digest::from([3u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), proposal_v3));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(3)));

            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::StallTimeout,),
                "oldest unfinalized view in the term should drive the timeout"
            );

            context.sleep(Duration::from_secs(2)).await;
            // Once the round's own timeout has also expired, its reason takes
            // precedence over the older anchor (more diagnostic for metrics).
            assert_eq!(
                state.next_timeout(),
                (
                    v3_certification_deadline,
                    TimeoutReason::CertificationTimeout,
                )
            );
        });
    }

    #[test]
    fn stall_timeout_ignores_prior_terms() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(12),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(34),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(11),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            context.sleep(Duration::from_secs(3)).await;

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(34), View::new(1)));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(4));
            let leader_deadline = context.current() + Duration::from_secs(10);

            // At this point the same-term deadline from view 1 has elapsed, but
            // the current view's leader deadline has not. If prior-term same-term
            // deadlines leaked, they would win here.
            context.sleep(Duration::from_millis(9500)).await;
            assert_eq!(
                state.next_timeout(),
                (leader_deadline, TimeoutReason::LeaderTimeout)
            );
        });
    }

    #[test]
    fn retry_takes_precedence_over_expired_same_term_timeout() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let retry = Duration::from_millis(3);
            let same_term_timeout = Duration::from_millis(30);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    same_term_timeout,
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(35),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_millis(10),
                certification_timeout: Duration::from_millis(20),
                timeout_retry: retry,
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let oldest_deadline = context.current() + same_term_timeout;

            // Certify view 1 late enough that its same-term stall deadline expires
            // after we enter view 2, then ensure view 2 nullify retries are rate-limited.
            let view_1 = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(35), view_1),
                GENESIS_VIEW,
                Sha256Digest::from([35u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            assert!(state.add_notarization(notarization).0);

            context.sleep(Duration::from_millis(25)).await;
            assert!(state.certified(view_1, true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            context.sleep(Duration::from_millis(5)).await;
            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::StallTimeout,)
            );

            let view_2 = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view_2, TimeoutReason::StallTimeout)
                .expect("same-term timeout should nullify current view");
            assert!(!was_retry);

            assert_eq!(
                state.next_timeout(),
                (context.current() + retry, TimeoutReason::Retry),
                "expired same-term deadline must not override nullify retry cadence"
            );
        });
    }

    #[test]
    fn local_nullify_preserves_stall_timeout() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let same_term_timeout = Duration::from_secs(4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    same_term_timeout,
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(36),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view_1 = state.current_view();
            let oldest_deadline = context.current() + same_term_timeout;

            // Mirror the actor's timeout sequence: trigger_timeout records the
            // reason (and must not disturb the stall deadline), then the
            // nullify vote is constructed.
            state.trigger_timeout(view_1, TimeoutReason::LeaderTimeout);
            let (was_retry, _) = state
                .construct_nullify(view_1, TimeoutReason::LeaderTimeout)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);

            let proposal = Proposal::new(
                Rnd::new(Epoch::new(36), view_1),
                GENESIS_VIEW,
                Sha256Digest::from([36u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            assert!(state.add_notarization(notarization).0);

            context.sleep(same_term_timeout).await;
            assert!(state.certified(view_1, true).is_some());
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::StallTimeout,),
                "oldest unfinalized view should remain tracked after local nullify"
            );
        });
    }

    #[test]
    fn stall_timeout_survives_certificate_jump() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let stall_timeout = Duration::from_secs(4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(5)),
                    stall_timeout,
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(7),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            assert_eq!(state.current_view(), View::new(1));

            // Certify a notarization for view 7 (term [6,10]) while at view 1,
            // jumping straight to view 8. The oldest unfinalized view in the
            // new term (view 6) was never entered and has no deadline.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(7), View::new(7)),
                GENESIS_VIEW,
                Sha256Digest::from([7u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            assert!(state.add_notarization(notarization).0);
            let entered = context.current();
            assert!(state.certified(View::new(7), true).is_some());
            assert_eq!(state.current_view(), View::new(8));

            // The stall timeout must anchor on the oldest entered,
            // unfinalized view in the term (view 8) rather than silently
            // disabling itself because view 6 has no deadline.
            assert_eq!(
                state.next_stall_timeout(),
                Some(entered + stall_timeout),
                "jumped-over views must not disable the stall timeout"
            );
        });
    }

    #[test]
    fn no_stall_deadline_when_unconfigured() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(33),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let entered = context.current();

            // Without a configured stall timeout no round arms a stall
            // deadline, and only the per-view timeouts drive next_timeout.
            assert_eq!(state.next_stall_timeout(), None);
            assert_eq!(
                state.next_timeout(),
                (
                    entered + Duration::from_secs(1),
                    TimeoutReason::LeaderTimeout
                )
            );
        });
    }

    #[test]
    fn expired_latch_keeps_reason_over_expired_anchor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(9),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Let the term's stall deadline expire, then latch an
            // event-driven timeout: the latched reason must not be relabeled
            // as StallTimeout by the older expired anchor.
            context.sleep(Duration::from_secs(5)).await;
            let view = state.current_view();
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            let (_, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::LeaderNullify);
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(12),
                view_retention: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Expiring a non-current view should do nothing.
            let deadline_v1 = state.next_timeout();
            state.trigger_timeout(View::zero(), TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(1));
            assert_eq!(state.next_timeout(), deadline_v1);
            assert!(
                !state.views.contains_key(&View::zero()),
                "old round should not be created when expire is ignored"
            );

            // Move to view 2 so view 1 becomes stale.
            let view_1 = View::new(1);
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(state.epoch(), view_1));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(2));

            let deadline_v2 = state.next_timeout();
            state.trigger_timeout(view_1, TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(state.next_timeout(), deadline_v2);
        });
    }

    #[test]
    fn inactivity_timeout_ignores_buffered_current_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let certification_timeout = Duration::from_secs(10);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: schemes[1].clone(),
                    elector: round_robin_with_term(
                        &schemes[1],
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(20),
                        ViewDelta::new(1),
                    ),
                    epoch: Epoch::new(15),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout,
                    timeout_retry: Duration::from_secs(30),
                    skip_budget: schemes[1].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            let parent = propose_and_notarize_view1(&mut state, 118);

            let finalization = build_finalization(&verifier, &schemes, &parent);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(state.current_view(), View::new(2));

            // A buffered, unverified proposal is enough to suppress the hint.
            let child = Proposal::new(
                Rnd::new(Epoch::new(15), View::new(2)),
                View::new(1),
                Sha256Digest::from([119u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child));

            let now = context.current();
            state.trigger_timeout(View::new(2), TimeoutReason::Inactivity);

            let (deadline, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::CertificationTimeout);
            assert_eq!(deadline, now + certification_timeout);

            // The proposal only disproves the inactivity hypothesis: the
            // leader's own nullify still latches an immediate timeout.
            state.trigger_timeout(View::new(2), TimeoutReason::LeaderNullify);
            let (deadline, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::LeaderNullify);
            assert_eq!(deadline, now);
        });
    }

    /// An equivocated proposal is not acceptable evidence for suppressing
    /// the inactivity hint.
    #[test]
    fn inactivity_timeout_latches_on_equivocated_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                15,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let parent = propose_and_notarize_view1(&mut state, 120);
            let finalization = build_finalization(&verifier, &schemes, &parent);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(state.current_view(), View::new(2));

            let child = |payload: u8| {
                Proposal::new(
                    Rnd::new(Epoch::new(15), View::new(2)),
                    View::new(1),
                    Sha256Digest::from([payload; 32]),
                )
            };
            assert!(state.set_proposal(View::new(2), child(121)));
            assert!(!state.set_proposal(View::new(2), child(122)));

            let now = context.current();
            state.trigger_timeout(View::new(2), TimeoutReason::Inactivity);
            let (deadline, reason) = state.next_timeout();
            assert_eq!(reason, TimeoutReason::Inactivity);
            assert_eq!(deadline, now);
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(13),
                view_retention: ViewDelta::new(3),
                leader_timeout,
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view_1 = state.current_view();
            assert_eq!(view_1, View::new(1));

            // Force the current view into timeout mode and schedule a retry.
            state.trigger_timeout(view_1, TimeoutReason::LeaderTimeout);
            assert!(
                state.next_timeout().0 <= context.current(),
                "current view should be expired after timeout is triggered"
            );
            let (was_retry, _) = state
                .construct_nullify(view_1, TimeoutReason::LeaderTimeout)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            let retry_deadline = state.next_timeout();
            assert_eq!(
                retry_deadline,
                (context.current() + retry, TimeoutReason::Retry),
                "timed-out view should schedule a retry"
            );

            // Advancing into the next view must install fresh deadlines instead of reusing
            // the expired/retrying state from the previous view.
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(state.epoch(), view_1));
            assert!(state.add_nullification(nullification));

            let view_2 = state.current_view();
            assert_eq!(view_2, View::new(2));
            let next_deadline = state.next_timeout();
            assert_eq!(
                next_deadline,
                (
                    context.current() + leader_timeout,
                    TimeoutReason::LeaderTimeout
                ),
                "next view should start with a fresh leader timeout"
            );
            assert_ne!(
                next_deadline, retry_deadline,
                "next view must not inherit the previous view retry deadline"
            );
        });
    }

    #[test]
    fn skip_budget_allows_repeated_leaders() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_state_with(
                &mut context,
                2,
                0,
                7,
                10,
                TermLength::ONE,
                ViewDelta::zero(),
                3,
            );
            let Fixture {
                schemes, verifier, ..
            } = fixture;
            let first_leader = state.leader_index(View::new(1));

            for view in 1..=3 {
                let view = View::new(view);
                assert_eq!(state.current_view(), view);
                let now = context.current();
                state.trigger_timeout(view, TimeoutReason::Inactivity);
                assert_eq!(state.next_timeout(), (now, TimeoutReason::Inactivity));
                assert!(
                    !state
                        .construct_nullify(view, TimeoutReason::Inactivity)
                        .expect("skip nullify")
                        .0
                );
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(state.epoch(), view));
                assert!(state.add_nullification(nullification));
            }

            assert_eq!(state.leader_index(View::new(3)), first_leader);

            let view = View::new(4);
            let now = context.current();
            state.trigger_timeout(view, TimeoutReason::Inactivity);
            assert_eq!(
                state.next_timeout(),
                (now + Duration::from_secs(1), TimeoutReason::LeaderTimeout)
            );
        });
    }

    #[test]
    fn skip_budget_counts_terms() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_state_with(
                &mut context,
                4,
                0,
                7,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::zero(),
                2,
            );
            let Fixture {
                schemes, verifier, ..
            } = fixture;
            for view in [View::new(1), View::new(6)] {
                assert_eq!(state.current_view(), view);
                let now = context.current();
                state.trigger_timeout(view, TimeoutReason::Inactivity);
                assert_eq!(state.next_timeout(), (now, TimeoutReason::Inactivity));
                assert!(
                    state
                        .construct_nullify(view, TimeoutReason::Inactivity)
                        .is_some()
                );
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(state.epoch(), view));
                assert!(state.add_nullification(nullification));
            }

            let view = View::new(11);
            let now = context.current();
            state.trigger_timeout(view, TimeoutReason::Inactivity);
            assert_eq!(
                state.next_timeout(),
                (now + Duration::from_secs(1), TimeoutReason::LeaderTimeout)
            );
        });
    }

    #[test]
    fn finalization_restores_pending_skip() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_state(&mut context, 4, 9, 10, 1, 1);
            let Fixture {
                schemes, verifier, ..
            } = fixture;
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([123u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            assert!(state.add_notarization(notarization).0);
            assert_eq!(state.certify_candidates().0, vec![proposal.clone()]);
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            let now = context.current();
            state.trigger_timeout(View::new(2), TimeoutReason::Inactivity);
            assert_eq!(
                state.next_timeout(),
                (now + Duration::from_secs(1), TimeoutReason::LeaderTimeout)
            );

            let finalization = build_finalization(&verifier, &schemes, &proposal);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(state.next_timeout(), (now, TimeoutReason::Inactivity));
        });
    }

    #[test]
    fn disabled_skip_defers_inactivity_to_leader_deadline() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state(&mut context, 4, 7, 10, 1, 0);
            let view = state.current_view();
            let now = context.current();

            state.trigger_timeout(view, TimeoutReason::Inactivity);
            assert_eq!(
                state.next_timeout(),
                (now + Duration::from_secs(1), TimeoutReason::LeaderTimeout)
            );
        });
    }

    #[test]
    fn disabled_skip_defers_leader_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state(&mut context, 4, 7, 10, 1, 0);
            let view = state.current_view();
            let now = context.current();
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), view),
                GENESIS_VIEW,
                Sha256Digest::from([124u8; 32]),
            );
            assert!(state.set_proposal(view, proposal));

            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            assert_eq!(
                state.next_timeout(),
                (
                    now + Duration::from_secs(2),
                    TimeoutReason::CertificationTimeout
                )
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(12),
                view_retention: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let leader = state.leader_index(view).unwrap();
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderNullify);

            // Fast-path trigger should not record metrics until we emit nullify.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            let expired_at = state.next_timeout();
            context.sleep(Duration::from_secs(1)).await;

            // Repeated timeout hints before emitting nullify should preserve the first timeout.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.next_timeout(),
                expired_at,
                "repeated timeout hints should not reset the expired deadline"
            );
            assert_eq!(state.timeouts.get_or_create(&label).get(), 0);

            // First emitted nullify should record the metric.
            let (was_retry, _) = state
                .construct_nullify(view, TimeoutReason::LeaderNullify)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            // Retries should not be counted as additional timed-out views.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            let (was_retry, _) = state
                .construct_nullify(view, TimeoutReason::Retry)
                .expect("retry timeout nullify should exist");
            assert!(was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            let retry_label = Timeout::new(leader_key, TimeoutReason::Retry);
            assert_eq!(state.timeouts.get_or_create(&retry_label).get(), 0);
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
                scheme: local_scheme.clone(),
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(4),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: local_scheme.participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let current = state.current_view();
            let next = current.next();

            // Non-current views are not eligible.
            assert!(
                state
                    .construct_nullify(next, TimeoutReason::LeaderTimeout)
                    .is_none()
            );

            // Observe a nullification for current view, which advances us to the next view.
            let current_round = Rnd::new(Epoch::new(4), current);
            let current_nullification = build_nullification(&verifier, &schemes, current_round);
            assert!(state.add_nullification(current_nullification));
            assert_eq!(state.current_view(), next);

            // Past views remain ineligible even if they have a nullification certificate.
            assert!(
                state
                    .construct_nullify(current, TimeoutReason::LeaderTimeout)
                    .is_none()
            );

            // Timeout path on current view: first attempt then retry.
            let (was_retry, _) = state
                .construct_nullify(next, TimeoutReason::LeaderTimeout)
                .expect("first timeout nullify for current view should be emitted");
            assert!(!was_retry);
            let (was_retry, _) = state
                .construct_nullify(next, TimeoutReason::Retry)
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(7),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
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
            let finalization = build_finalization(&verifier, &schemes, &proposal_a);
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
                scheme: local_scheme.clone(),
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(4),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: local_scheme.participants().len() as u64,
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
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);

            // The parent is still not certified.
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
    fn parent_payload_errors_without_nullification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1, 4);

            // Create parent proposal and certificate
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([2u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
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
    fn parent_payload_uses_term_skip_nullification_anchors() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([42u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            for v in [View::new(4), View::new(6)] {
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), v));
                assert!(state.add_nullification(nullification));
            }

            // View 11 is the start of term 3, so the intra-term skip check does not apply.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(11)),
                parent_view,
                Sha256Digest::from([7u8; 32]),
            );
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_payload_uses_term_skip_nullification_anchors_across_multiple_terms() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([42u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            // Anchor the rest of term 1 (view 4) and both fully-skipped terms
            // 2 (views 6-10) and 3 (views 11-15) with one nullification each.
            for v in [View::new(4), View::new(6), View::new(11)] {
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), v));
                assert!(state.add_nullification(nullification));
            }

            // View 16 is the start of term 4, two whole terms past the parent's.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(16)),
                parent_view,
                Sha256Digest::from([7u8; 32]),
            );
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_payload_accepts_certified_parent_covered_by_nullification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([42u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            // The parent view itself carries a nullification (covering the rest
            // of term 1) and term 2 is anchored at view 6.
            for v in [parent_view, View::new(6)] {
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), v));
                assert!(state.add_nullification(nullification));
            }

            // View 11 is the start of term 3; the certified parent remains
            // acceptable even though it is itself covered by a nullification.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(11)),
                parent_view,
                Sha256Digest::from([7u8; 32]),
            );
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_payload_reports_missing_term_anchor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            let parent_view = View::new(3);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([9u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            {
                let v = View::new(4);
                let nullification =
                    build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), v));
                assert!(state.add_nullification(nullification));
            }

            // View 11 is a term start so the intra-term skip check does not apply,
            // but the nullification for term 2 (view 6) is missing.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(11)),
                parent_view,
                Sha256Digest::from([10u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::MissingNullification {
                    proposal_view: View::new(11),
                    parent_view,
                    missing_view: View::new(6),
                })
            );
        });
    }

    #[test]
    fn optimistic_views_zero_disables_intra_term_lookahead() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(0),
                4,
            );

            let parent = propose_and_notarize_view1(&mut state, 93);

            let parent_notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(parent_notarization).0);

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([94u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            // With the lookahead disabled, no view is inside the issuance
            // window, so verification requests the uncertified parent's
            // notarization from the leader.
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve { view, kind: Kind::Notarization, .. } if view == View::new(1)
            ));

            let child_notarization = build_notarization(&verifier, &schemes, &child);
            assert!(state.add_notarization(child_notarization).0);
            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(1));

            assert!(state.certified(View::new(1), true).is_some());
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
        });
    }

    #[test]
    fn try_verify_requests_uncertified_cross_term_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Nullify term 1 to enter term 2 at view 6. One nullification
            // covers the rest of its term and sets the next term's leader.
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(9), View::new(3)));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(6));

            // A term-start proposal is never inside the issuance window, so
            // its uncertified parent is missing locally: the proposer must
            // have held the parent's certificate. Verification requests the
            // notarization from the leader.
            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(6)),
                View::new(2),
                Sha256Digest::from([44u8; 32]),
            );
            assert!(state.set_proposal(View::new(6), child.clone()));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve { proposal, view, kind: Kind::Notarization, .. }
                    if proposal == View::new(6) && view == View::new(2)
            ));

            // The round deduplicates the request while it is outstanding.
            assert!(matches!(state.try_verify(), Verify::Wait));

            // Certifying the fetched parent makes the proposal verifiable.
            let parent = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(2), true).is_some());
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("proposal should verify once the parent certifies");
            };
            assert_eq!(ctx.parent, (View::new(2), parent.payload));
            assert_eq!(proposal, child);
        });
    }

    #[test]
    fn optimistic_child_certification_waits_for_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent = propose_and_notarize_view1(&mut state, 101);

            let parent_notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(parent_notarization).0);

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([102u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(2)));

            let child_notarization = build_notarization(&verifier, &schemes, &child);
            assert!(state.add_notarization(child_notarization).0);

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert!(
                candidates
                    .iter()
                    .any(|proposal| proposal.round.view() == View::new(1))
            );

            assert!(state.certified(View::new(1), false).is_some());

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(9), View::new(1)));
            assert!(state.add_nullification(nullification));

            assert_eq!(
                state.find_parent(View::new(6)),
                Ok((GENESIS_VIEW, test_genesis()))
            );
            let next_term_proposal = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(6)),
                View::new(2),
                Sha256Digest::from([103u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&next_term_proposal),
                Err(ParentPayloadError::ParentNotCertified {
                    proposal_view: View::new(6),
                    parent_view: View::new(2),
                })
            );
            assert!(state.certify_candidates().0.is_empty());
        });
    }

    /// Regression: certification must widen a targeted verification fetch for
    /// the same missing parent so any peer can answer it.
    #[test]
    fn certification_fetch_widens_targeted_verification_request() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    participants,
                    schemes,
                    verifier,
                    ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(0),
                4,
            );

            certify_first_view(&mut state, &verifier, &schemes);

            // Receive proposal(3) without notarization(2). Verification first
            // requests the parent only from the stable leader.
            let p3 = fetch_proposal(3, 2, 103);
            state.set_leader(View::new(3), None);
            assert!(state.set_proposal(View::new(3), p3.clone()));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Notarization,
                    target,
                } if proposal == View::new(3)
                    && view == View::new(2)
                    && target == participants[2]
            ));

            // Notarization(3) triggers an untargeted request for the same
            // parent. This widens the in-flight resolver fetch.
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &p3))
                    .0
            );
            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert_eq!(fetches.len(), 1);
            assert_eq!(fetches[0].proposal, View::new(3));
            assert_eq!(fetches[0].view, View::new(2));

            // The blocked candidate is dormant, so another pass emits nothing.
            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert!(fetches.is_empty());

            // Delivering notarization(2) unblocks the chain. View 3 stays
            // blocked while view 2's certification is pending, without a
            // fetch: the notarization is already held.
            let p2 = fetch_proposal(2, 1, 102);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &p2))
                    .0
            );
            let (ready, fetches) = state.certify_candidates();
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].round.view(), View::new(2));
            assert!(fetches.is_empty());
            assert!(state.certified(View::new(2), true).is_some());

            let (ready, fetches) = state.certify_candidates();
            assert_eq!(ready.len(), 1);
            assert_eq!(ready[0].round.view(), View::new(3));
            assert!(fetches.is_empty());
        });
    }

    /// Regression: the fetch must fire even when the certificate gap is wider
    /// than the optimistic frontier. The fetch remains untargeted even when a
    /// same-term round records the stable leader.
    #[test]
    fn certify_candidates_fetches_across_wide_gap() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                20,
                TermLength::new(NZU32!(10)),
                ViewDelta::new(2),
                4,
            );

            // Certify view 1. The optimistic frontier assigns leaders only up
            // to view 3.
            certify_first_view(&mut state, &verifier, &schemes);

            // Receive notarization(6) without any of 2..=5. Views 5 and 6 sit
            // beyond the frontier, so neither round has a leader. The fetch
            // still fires and may be served by any peer.
            let p6 = fetch_proposal(6, 5, 106);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &p6))
                    .0
            );
            // Precondition: the candidate's and parent's rounds are leaderless.
            assert!(!state.leader_is_set(View::new(6)));
            assert!(!state.leader_is_set(View::new(5)));
            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert_eq!(fetches.len(), 1);
            assert_eq!(fetches[0].proposal, View::new(6));
            assert_eq!(fetches[0].view, View::new(5));
            // Confirm that a same-term round records the old leader.
            assert!(state.leader_index(View::new(2)).is_some());

            // Repair cascades one view at a time: delivering notarization(5)
            // exposes the next gap, again from a leaderless round.
            let p5 = fetch_proposal(5, 4, 105);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &p5))
                    .0
            );
            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert_eq!(fetches.len(), 1);
            assert_eq!(fetches[0].proposal, View::new(5));
            assert_eq!(fetches[0].view, View::new(4));
        });
    }

    /// Regression: a bare notarization for a term's final view can be the
    /// only artifact the voter holds from that term. It seeds a leader only
    /// for the next term's start, so no tracked round supplies the term's
    /// leader. The fetch must still fire.
    #[test]
    fn certify_candidates_fetches_term_end_without_leader() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Certify view 1 (term 1 spans views 1..=5).
            certify_first_view(&mut state, &verifier, &schemes);

            // Receive notarization(10), the final view of term 2, with no
            // other artifact from that term. No round in views 6..=10 has a
            // leader: the notarization seeds only view 11, term 3's start.
            let p10 = fetch_proposal(10, 9, 110);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &p10))
                    .0
            );
            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert_eq!(fetches.len(), 1);
            assert_eq!(fetches[0].proposal, View::new(10));
            assert_eq!(fetches[0].view, View::new(9));
        });
    }

    /// Certification exempts term-start candidates from the parent precheck
    /// (see [`State::certification_parent_ready`]). A term-start proposal
    /// dispatches even when its cross-term parent is uncertified and the
    /// skipped views' nullifications are not held.
    #[test]
    fn certify_candidates_exempts_term_start_from_parent_precheck() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Term 2 starts at view 6. Its parent (view 1) is not certified
            // and no nullification for views 2..=5 is tracked.
            let term_start = fetch_proposal(6, 1, 61);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &term_start))
                    .0
            );
            let (ready, fetches) = state.certify_candidates();
            assert_eq!(ready, vec![term_start]);
            assert!(fetches.is_empty());
        });
    }

    /// A certificate is adversarial input: a notarization whose proposal is
    /// structurally invalid must be dropped by certification, with no fetch
    /// and no requeue.
    #[test]
    fn certify_candidates_drops_malformed_candidates() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );
            certify_first_view(&mut state, &verifier, &schemes);

            // A parent at or above the proposal view.
            let bad_parent = fetch_proposal(2, 2, 60);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &bad_parent))
                    .0
            );
            // An intra-term proposal that skips views 2 and 3.
            let skip = fetch_proposal(4, 1, 61);
            assert!(
                state
                    .add_notarization(build_notarization(&verifier, &schemes, &skip))
                    .0
            );

            let (ready, fetches) = state.certify_candidates();
            assert!(ready.is_empty());
            assert!(fetches.is_empty());

            // Dropped, not requeued: a fetchless requeue would also return
            // empty outputs forever, so inspect the candidate set itself.
            assert!(state.certification_candidates.is_empty());
        });
    }

    #[test]
    fn optimistic_views_bounds_chain_length() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let first_payload = Sha256Digest::from([95u8; 32]);
            let first = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                first_payload,
            );
            state.create_round(View::new(1));
            assert!(state.proposed(first));

            let second = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([96u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), second.clone()));
            assert!(
                matches!(state.try_verify(), Verify::Wait),
                "future same-term verification should wait for local parent notarize"
            );
            assert!(state.construct_notarize(View::new(1)).is_some());

            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("future view should verify after local parent notarize");
            };
            assert_eq!(ctx.round.view(), View::new(2));
            assert_eq!(ctx.parent, (View::new(1), first_payload));
            assert_eq!(proposal, second);
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());

            let third = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(3)),
                View::new(2),
                Sha256Digest::from([97u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), third));
            // The second hop is outside the admission window, so the scan
            // skips it without requesting its ancestry.
            assert!(
                matches!(state.try_verify(), Verify::Wait),
                "depth=1 should block a second optimistic hop"
            );
        });
    }

    #[test]
    fn optimistic_successor_inherits_leader_without_none_election() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { verifier, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let skip_budget = verifier.participants().len() as u64;
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier,
                    elector: RequireCertificateElector {
                        term_length: TermLength::new(NZU32!(5)),
                        _phantom: std::marker::PhantomData,
                    },
                    epoch: Epoch::new(99),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget,
                },
            );
            state.set_genesis(test_genesis());

            let proposal = Proposal::new(
                Rnd::new(Epoch::new(99), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([9u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), proposal));
            assert!(
                state
                    .views
                    .get(&View::new(2))
                    .and_then(|round| round.leader())
                    .is_some()
            );
        });
    }

    #[test]
    fn catch_up_from_parent_finalization_allows_child_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([111u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &parent);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(state.current_view(), View::new(2));

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([112u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("child should verify");
            };
            assert_eq!(proposal, child);
            assert_eq!(ctx.parent, (View::new(1), parent.payload));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());
        });
    }

    #[test]
    fn catch_up_from_parent_certification_allows_child_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([113u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([114u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("child should verify");
            };
            assert_eq!(proposal, child);
            assert_eq!(ctx.parent, (View::new(1), parent.payload));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());
        });
    }

    #[test]
    fn forwardable_proposal_tracks_certificate_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 13, 10, 1, 4);

            let view = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(13), view),
                GENESIS_VIEW,
                Sha256Digest::from([116u8; 32]),
            );

            // Notarized: forwardable.
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            assert!(state.add_notarization(notarization).0);
            assert!(state.forwardable_proposal(view).is_some());

            // Our certification rejected it: not forwardable.
            assert!(state.certified(view, false).is_some());
            assert!(state.forwardable_proposal(view).is_none());

            // A subsequent nullification changes nothing.
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(13), view));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(2));
            assert!(state.forwardable_proposal(view).is_none());

            // A finalization overrides the local rejection.
            let finalization = build_finalization(&verifier, &schemes, &proposal);
            assert!(state.add_finalization(finalization).0);
            assert!(state.forwardable_proposal(view).is_some());
        });
    }

    #[test]
    fn pending_optimistic_child_verification_rejects_replaced_parent_notarization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent_a = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([117u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), parent_a.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(1)));
            assert!(state.construct_notarize(View::new(1)).is_some());

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([118u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("child should verify");
            };
            assert_eq!(proposal, child);
            assert_eq!(ctx.parent, (View::new(1), parent_a.payload));

            let parent_b = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([119u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_b);
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_some());
            assert_eq!(state.parent_payload(&child), Ok(parent_b.payload));
            assert!(!state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_none());
        });
    }

    /// A verification failure that arrives after the child's parent was
    /// replaced describes ancestry we no longer hold, so it must not latch.
    ///
    /// Latching would nullify the view over a verdict on the displaced parent,
    /// and the latch outlives the round's consumed verification request.
    #[test]
    fn failed_optimistic_child_verification_ignores_replaced_parent_verdict() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent_a = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([120u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), parent_a.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(1)));
            assert!(state.construct_notarize(View::new(1)).is_some());

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([121u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            let Verify::Ready(ctx, _) = state.try_verify() else {
                panic!("child should verify");
            };
            assert_eq!(ctx.parent, (View::new(1), parent_a.payload));

            // The parent view certifies a conflicting payload while the child's
            // verification is still in flight.
            let parent_b = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([122u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_b);
            assert!(state.add_notarization(notarization).0);
            assert_eq!(state.parent_payload(&child), Ok(parent_b.payload));

            // The automaton then rejects the child it verified against
            // parent_a. That verdict says nothing about parent_b.
            state.verification_failed(View::new(2), TimeoutReason::InvalidProposal);

            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));
            assert!(!matches!(
                state.next_timeout(),
                (_, TimeoutReason::InvalidProposal)
            ));
        });
    }

    #[test]
    fn verified_optimistic_child_notarize_rejects_replaced_parent_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let parent_a = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([120u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), parent_a.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(1)));
            assert!(state.construct_notarize(View::new(1)).is_some());

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([121u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("child should verify");
            };
            assert_eq!(proposal, child);
            assert_eq!(ctx.parent, (View::new(1), parent_a.payload));
            assert!(state.verified(View::new(2)));

            let parent_b = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([122u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &parent_b);
            let (added, equivocator) = state.add_finalization(finalization);
            assert!(added);
            assert!(equivocator.is_some());
            assert_eq!(state.parent_payload(&child), Ok(parent_b.payload));
            assert!(state.construct_notarize(View::new(2)).is_none());
        });
    }

    #[test]
    fn failed_certification_blocks_optimistic_child_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let parent = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([116u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), parent.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(1)));
            assert!(state.construct_notarize(View::new(1)).is_some());

            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([117u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), child.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(2)));

            // Local certification rejects the parent and we nullify it. The
            // optimistic child must no longer be signable.
            assert!(state.certified(View::new(1), false).is_some());
            assert!(
                state
                    .construct_nullify(View::new(1), TimeoutReason::FailedCertification)
                    .is_some()
            );
            assert!(
                state.construct_notarize(View::new(2)).is_none(),
                "failed-certified parent must not unlock optimistic child notarize"
            );
            // The notarized child must also remain ineligible for certification.
            let child_notarization = build_notarization(&verifier, &schemes, &child);
            assert!(state.add_notarization(child_notarization).0);
            assert!(state.certify_candidates().0.is_empty());

            // A finalization certificate for the parent overrides the local
            // rejection and restores it as usable ancestry.
            let finalization = build_finalization(&verifier, &schemes, &parent);
            assert!(state.add_finalization(finalization).0);
            assert!(state.construct_notarize(View::new(2)).is_some());
            assert_eq!(state.certify_candidates().0, vec![child]);
        });
    }

    #[test]
    fn replayed_failed_ancestor_blocks_direct_descendant_until_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Directly notarize two consecutive views in the same term.
            let ancestor = fetch_proposal(1, 0, 116);
            let descendant = fetch_proposal(2, 1, 117);
            for proposal in [&ancestor, &descendant] {
                let notarization = build_notarization(&verifier, &schemes, proposal);
                assert!(state.add_notarization(notarization).0);
            }

            // Restore a rejected certification for the ancestor. It must veto
            // the descendant's otherwise certificate-backed ancestry.
            state.replay(&Artifact::Certification(ancestor.round, false));
            assert!(
                state
                    .optimistic_ancestry_payload(descendant.view())
                    .is_none()
            );

            // A descendant finalization covers the rejection and makes that
            // certificate usable again.
            let finalization = build_finalization(&verifier, &schemes, &descendant);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(
                state
                    .optimistic_ancestry_payload(descendant.view())
                    .copied(),
                Some(descendant.payload)
            );
        });
    }

    #[test]
    fn failed_certification_blocks_locally_proposed_optimistic_child_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                2,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let parent = propose_and_notarize_view1(&mut state, 118);
            let child_context = state
                .try_propose()
                .expect("optimistic child proposal should start");
            assert_eq!(child_context.view(), View::new(2));
            assert_eq!(child_context.parent, (View::new(1), parent.payload));

            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(1), false).is_some());
            assert!(
                state
                    .construct_nullify(View::new(1), TimeoutReason::FailedCertification)
                    .is_some()
            );

            let child = Proposal::new(
                child_context.round,
                child_context.parent.0,
                Sha256Digest::from([119u8; 32]),
            );
            assert!(state.proposed(child));
            assert!(
                state.construct_notarize(View::new(2)).is_none(),
                "failed-certified parent must block a locally proposed optimistic child"
            );
        });
    }

    #[test]
    fn same_term_notarize_respects_admission_window() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state_with(
                &mut context,
                4,
                0,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            for view in [View::new(1), View::new(2), View::new(3)] {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(9), view),
                    view.previous().unwrap_or(GENESIS_VIEW),
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                assert!(state.set_proposal(view, proposal));
                assert!(state.verified(view));
                assert!(
                    state.construct_notarize(view).is_some(),
                    "view {view} is in the admission window from current view 1"
                );
            }

            let view = View::new(4);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(9), view),
                View::new(3),
                Sha256Digest::from([4u8; 32]),
            );
            assert!(state.set_proposal(view, proposal));
            assert!(state.verified(view));
            assert!(
                state.construct_notarize(view).is_none(),
                "view 4 is outside the admission window from current view 1"
            );
        });
    }

    #[test]
    fn certify_candidates_wait_for_parent_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let parent = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([98u8; 32]),
            );
            let parent_notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(parent_notarization).0);

            let child = Proposal::new(
                Rnd::new(Epoch::new(9), View::new(2)),
                View::new(1),
                Sha256Digest::from([99u8; 32]),
            );
            let child_notarization = build_notarization(&verifier, &schemes, &child);
            assert!(state.add_notarization(child_notarization).0);

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(1));

            assert!(state.certified(View::new(1), true).is_some());
            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(2));
        });
    }

    #[test]
    fn blocked_certification_candidates_wake_parent_first() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(10)),
                ViewDelta::new(3),
                4,
            );

            // Certify view 1 so only view 2 is initially ready.
            certify_first_view(&mut state, &verifier, &schemes);

            // Deliver the remaining chain in reverse, leaving each descendant
            // blocked on its immediate parent.
            let proposals = [
                fetch_proposal(2, 1, 102),
                fetch_proposal(3, 2, 103),
                fetch_proposal(4, 3, 104),
            ];
            for proposal in proposals.iter().rev() {
                let notarization = build_notarization(&verifier, &schemes, proposal);
                assert!(state.add_notarization(notarization).0);
            }

            // Each successful certification wakes only its immediate child.
            // More distant descendants remain dormant.
            for proposal in proposals {
                let (ready, fetches) = state.certify_candidates();
                assert_eq!(ready, vec![proposal.clone()]);
                assert!(fetches.is_empty());
                assert!(
                    state.certification_candidates.is_empty(),
                    "parent-blocked descendants must remain dormant"
                );
                assert!(state.certified(proposal.view(), true).is_some());
            }
        });
    }

    #[test]
    fn finalization_wakes_child_after_failed_parent_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                9,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            certify_first_view(&mut state, &verifier, &schemes);

            let parent = fetch_proposal(2, 1, 102);
            let child = fetch_proposal(3, 2, 103);
            for proposal in [&parent, &child] {
                let notarization = build_notarization(&verifier, &schemes, proposal);
                assert!(state.add_notarization(notarization).0);
            }

            let (ready, fetches) = state.certify_candidates();
            assert_eq!(ready, vec![parent.clone()]);
            assert!(fetches.is_empty());
            assert!(state.certification_candidates.is_empty());

            assert!(state.certified(parent.view(), false).is_some());
            assert!(state.certify_candidates().0.is_empty());

            let finalization = build_finalization(&verifier, &schemes, &parent);
            assert!(state.add_finalization(finalization).0);
            assert_eq!(state.certify_candidates().0, vec![child]);
        });
    }

    #[test]
    fn optimistic_frontier_slides_with_direct_notarization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                10,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            propose_and_notarize_view1(&mut state, 98);

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(10), View::new(2)),
                View::new(1),
                Sha256Digest::from([99u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2.clone()));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());

            assert!(state.views.contains_key(&View::new(3)));
            assert!(
                !state.views.contains_key(&View::new(4)),
                "issuance window should initially stop at view 3"
            );

            let notarization = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(state.add_notarization(notarization).0);

            assert!(
                state.views.contains_key(&View::new(4)),
                "direct notarization should slide optimistic frontier"
            );
        });
    }

    #[test]
    fn optimistic_frontier_walk_does_not_scan_rounds() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                10,
                10,
                TermLength::new(NZU32!(131)),
                ViewDelta::new(64),
                4,
            );

            // Build the densest proposal prefix admitted from view 1. A
            // follower can receive these leader proposals while a quorum
            // withholds the corresponding certificates from it.
            for view in 1..=65 {
                let view = View::new(view);
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(10), view),
                    view.previous().unwrap_or(GENESIS_VIEW),
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                assert!(state.set_proposal(view, proposal));
            }

            // Deliver only the certificate at the end of the prefix. This
            // single direct anchor opens the remainder of the stable-leader
            // term, so extending it must not rediscover that same anchor for
            // each successor.
            let proposal = state
                .views
                .get(&View::new(65))
                .and_then(|round| round.proposal())
                .cloned()
                .expect("proposal must be tracked");
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let probes = state.issuance_window_probes.get();
            assert!(state.add_notarization(notarization).0);

            // The anchor reaches every remaining in-term view and stops at the
            // next term start.
            for view in 66..=130 {
                assert!(
                    state.leader_index(View::new(view)).is_some(),
                    "view {view} must inherit the stable leader"
                );
            }
            assert!(state.leader_index(View::new(131)).is_none());

            // Frontier extension already knows the triggering direct anchor;
            // round scans would repeat work for every reached view.
            assert_eq!(state.issuance_window_probes.get(), probes);
        });
    }

    /// Regression: the frontier walk must start adjacent to the notarized
    /// view. Otherwise a far-future same-term round (created by an
    /// unbounded-future certificate) keeps the window the notarization just
    /// opened leaderless.
    #[test]
    fn optimistic_frontier_slides_despite_far_future_round() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                10,
                10,
                TermLength::new(NZU32!(20)),
                ViewDelta::new(2),
                4,
            );

            // A notarization for a far-future same-term view arrives first.
            let proposal_v10 = Proposal::new(
                Rnd::new(Epoch::new(10), View::new(10)),
                View::new(9),
                Sha256Digest::from([96u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal_v10);
            assert!(state.add_notarization(notarization).0);

            // A notarization for view 1 must still open its own window.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(10), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([97u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal_v1);
            assert!(state.add_notarization(notarization).0);

            for view in 2..=4u64 {
                assert!(
                    state.leader_index(View::new(view)).is_some(),
                    "view {view} must inherit the stable leader"
                );
            }
        });
    }

    #[test]
    fn indirect_notarization_still_requires_certification_for_finalize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                10,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let parent = propose_and_notarize_view1(&mut state, 101);

            let descendant = Proposal::new(
                Rnd::new(Epoch::new(10), View::new(2)),
                View::new(1),
                Sha256Digest::from([102u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), descendant.clone()));
            assert!(state.verified(View::new(2)));

            let notarization = build_notarization(&verifier, &schemes, &descendant);
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());
            assert_eq!(
                state.optimistic_ancestry_payload(View::new(1)).copied(),
                Some(Sha256Digest::from([101u8; 32]))
            );
            let round = state.views.get(&View::new(1)).expect("ancestor round");
            assert!(round.proposal().is_some());
            assert!(round.is_verified());

            // An indirect notarization is not enough for a finalize vote.
            assert!(state.construct_finalize(View::new(1)).is_none());

            // A direct notarization is still not enough: certification is the
            // remaining requirement.
            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.construct_finalize(View::new(1)).is_none());

            // Certification completes the requirement.
            assert!(state.certified(View::new(1), true).is_some());
            assert!(state.construct_finalize(View::new(1)).is_some());
        });
    }

    #[test]
    fn indirect_notarization_requires_verified_unequivocated_ancestors() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            propose_and_notarize_view1(&mut state, 111);

            let view2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([112u8; 32]),
            );
            state.create_round(View::new(2));
            assert!(state.proposed(view2));
            assert!(state.construct_notarize(View::new(2)).is_some());
            let conflicting_view2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([113u8; 32]),
            );
            assert!(!state.set_proposal(View::new(2), conflicting_view2));

            let view3 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(3)),
                View::new(2),
                Sha256Digest::from([114u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), view3.clone()));
            assert!(state.verified(View::new(3)));
            let notarization = build_notarization(&verifier, &schemes, &view3);
            assert!(state.add_notarization(notarization).0);

            assert!(state.optimistic_ancestry_payload(View::new(2)).is_none());
        });
    }

    #[test]
    fn optimistic_notarize_requires_parent_participation_within_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );
            assert!(state.enter_view(View::new(2)));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([118u8; 32]),
            );
            state.create_round(View::new(2));
            assert!(state.proposed(proposal_v2));
            assert!(state.construct_notarize(View::new(2)).is_none());

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([119u8; 32]),
            );
            state.create_round(View::new(1));
            assert!(state.proposed(proposal_v1));
            assert!(state.construct_notarize(View::new(1)).is_some());
            assert!(state.construct_notarize(View::new(2)).is_some());
        });
    }

    /// Regression: a parent notarization certificate observed from the network
    /// (without our own notarize vote) must satisfy the optimistic parent gate.
    /// The actor constructs votes once per event, so the gate must pass at the
    /// child's verified event or the vote is permanently lost.
    #[test]
    fn optimistic_notarize_accepts_directly_notarized_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Peers notarize view 1 without our participation.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([120u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes[1..], &proposal_v1);
            assert!(state.add_notarization(notarization).0);

            // The optimistic child of the notarized view is immediately votable.
            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([121u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());
        });
    }

    /// A directly-notarized parent whose certification we rejected must not
    /// anchor an optimistic notarize vote (mirrors payload resolution).
    #[test]
    fn optimistic_notarize_blocks_on_parent_failed_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([122u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes[1..], &proposal_v1);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(1), false).is_some());

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([123u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_none());
        });
    }

    /// A view whose only certificate is a finalization must anchor the
    /// issuance window, exactly as a notarized view does.
    #[test]
    fn finalization_anchors_optimistic_issuance_window() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            // View 1 is finalized without us ever seeing its notarization, so
            // it is the only possible anchor below the chain that follows.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([130u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal_v1);
            assert!(state.add_finalization(finalization).0);
            assert!(state.notarization(View::new(1)).is_none());

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([131u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());

            // View 3 is inside the window only because view 1 anchors it
            // (`3 <= 1 + 1 + optimistic_views`); an anchor at genesis would
            // put it out of reach.
            let proposal_v3 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(3)),
                View::new(2),
                Sha256Digest::from([132u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), proposal_v3));
            assert!(state.verified(View::new(3)));
            assert!(
                state.construct_notarize(View::new(3)).is_some(),
                "finalized view 1 should anchor the issuance window"
            );
        });
    }

    /// Pruned rounds must not remain issuance anchors. A stale round below the
    /// activity floor would widen the issuance window past its bound.
    #[test]
    fn prune_drops_stale_optimistic_anchors() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                1,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            for (view, payload) in [(1u64, 140u8), (2, 141)] {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(11), View::new(view)),
                    View::new(view - 1),
                    Sha256Digest::from([payload; 32]),
                );
                let notarization = build_notarization(&verifier, &schemes, &proposal);
                assert!(state.add_notarization(notarization).0);
            }

            // View 4's window spans views 1..4, so the notarization at view 2
            // anchors it.
            assert!(state.in_issuance_window(View::new(4)));

            let proposal_v4 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(4)),
                View::new(3),
                Sha256Digest::from([142u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal_v4);
            assert!(state.add_finalization(finalization).0);

            // Retention of 1 puts the activity floor at view 3.
            let removed = state.prune();
            assert_eq!(removed, vec![View::new(1), View::new(2)]);
            assert!(
                !state.in_issuance_window(View::new(4)),
                "pruned views must not anchor the issuance window"
            );
        });
    }

    /// An optimistic child may be notarized ahead of its parent's
    /// certification, but must not be finalized until the parent is explicitly
    /// certified.
    ///
    /// Marking the child certified while the parent is not cannot happen on the
    /// live path (`certification_parent_ready` gates it), so this drives
    /// [`State::certified`] directly to reproduce what journal replay restores.
    #[test]
    fn optimistic_finalize_blocks_on_uncertified_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                11,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // Peers notarize view 1; we never certify it.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([124u8; 32]),
            );
            let notarization_v1 = build_notarization(&verifier, &schemes[1..], &proposal_v1);
            assert!(state.add_notarization(notarization_v1).0);

            // The optimistic child is votable and reaches a notarization.
            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(11), View::new(2)),
                View::new(1),
                Sha256Digest::from([125u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2.clone()));
            assert!(state.verified(View::new(2)));
            assert!(state.construct_notarize(View::new(2)).is_some());
            let notarization_v2 = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(state.add_notarization(notarization_v2).0);

            // A certified child alone does not authorize a finalize vote.
            assert!(state.certified(View::new(2), true).is_some());
            assert!(
                state.construct_finalize(View::new(2)).is_none(),
                "finalize must wait for the parent's explicit certification"
            );

            // Certifying the parent releases the gate.
            assert!(state.certified(View::new(1), true).is_some());
            assert!(state.construct_finalize(View::new(2)).is_some());
        });
    }

    #[test]
    fn failed_certification_still_nullifies_current_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                13,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );

            let proposal = Proposal::new(
                Rnd::new(Epoch::new(13), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([115u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);

            assert!(state.add_notarization(notarization).0);
            assert_eq!(state.current_view(), View::new(1));

            assert!(state.certified(View::new(1), false).is_some());

            let (is_retry, nullify) = state
                .construct_nullify(View::new(1), TimeoutReason::FailedCertification)
                .expect("failed certification should still nullify the current view");
            assert!(!is_retry);
            assert_eq!(nullify.view(), View::new(1));
            let (is_retry, nullify) = state
                .construct_nullify(View::new(1), TimeoutReason::Retry)
                .expect("failed certification nullify should allow retry");
            assert!(is_retry);
            assert_eq!(nullify.view(), View::new(1));
        });
    }

    #[test]
    fn nullification_sets_entry_certificate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            let view = View::new(1);
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), view));
            assert!(state.add_nullification(nullification.clone()));
            assert_eq!(state.current_view(), View::new(6));
            let entry = state.get_best_certificate();
            assert!(
                matches!(
                    entry,
                    Some(Certificate::Nullification(ref cert)) if cert == &nullification
                ),
                "expected nullification entry certificate"
            );
        });
    }

    #[test]
    fn entry_certificate_prioritizes_finalization_then_nullification_then_notarization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 1, 4);

            let view = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([17u8; 32]),
            );

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            state.add_notarization(notarization.clone());
            assert!(state.certified(view, true).is_some());
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Notarization(ref n)) if n == &notarization
            ));

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), view));
            assert!(state.add_nullification(nullification.clone()));
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Nullification(ref n)) if n == &nullification
            ));

            let finalization = build_finalization(&verifier, &schemes, &proposal);
            let _ = state.add_finalization(finalization.clone());
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Finalization(ref f)) if f == &finalization
            ));
        });
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1, 4);

            // Add nullification certificate for view 1
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(1)));
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
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1, 4);

            // Add finalization
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal_a);
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
    fn parent_payload_rejects_intra_term_view_skip() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5, 4);

            // Certify view 1 so it can serve as a valid parent.
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            state.add_notarization(notarization);
            state.certified(parent_view, true);

            // Propose at view 3 with parent view 1. Both are within the same term
            // (term_length=5, term 1 = views 1-5), so view 3 is intra-term yet
            // skips view 2.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                parent_view,
                Sha256Digest::from([2u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::IntraTermProposalSkipsViews {
                    proposal_view: View::new(3),
                    parent_view,
                })
            );
        });
    }

    #[test]
    fn try_verify_fast_paths_intra_term_view_skip() {
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
                    elector: round_robin_with_term(
                        &verifier,
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(2),
                    ),
                    epoch,
                    view_retention: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    skip_budget: verifier.participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // Notarize view 2 so the leader is set for view 3.
            let notarization_proposal = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &notarization_proposal);
            state.add_notarization(notarization);
            assert!(state.leader_index(View::new(3)).is_some());

            // Inject a proposal at view 3 whose parent is view 1. Both are
            // in the same term (views 1-5), so this is an intra-term skip.
            let proposal = Proposal::new(
                Rnd::new(epoch, View::new(3)),
                View::new(1),
                Sha256Digest::from([2u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), proposal));

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Permanent ancestry error in a non-current view should not emit
            // a nullify vote for that non-current view.
            assert!(matches!(state.try_verify(), Verify::Wait));
            assert!(
                state
                    .construct_nullify(View::new(3), TimeoutReason::LeaderTimeout)
                    .is_none()
            );
            assert_eq!(state.next_timeout(), initial_deadline);
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
                    elector: round_robin(&verifier),
                    epoch,
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    skip_budget: verifier.participants().len() as u64,
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
            let finalization = build_finalization(&verifier, &schemes, &finalized_proposal);
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

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Permanent ancestry errors should immediately expire the timeout.
            assert!(!matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.next_timeout().0 <= context.current());
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
                    scheme: verifier.clone(),
                    elector: round_robin(&verifier),
                    epoch,
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    skip_budget: verifier.participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // Move into view 2 without certifying view 1 so the parent could still arrive later.
            assert!(state.enter_view(View::new(2)));

            // Inject a proposal whose parent is missing certification but is not permanently invalid.
            let proposal = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                View::new(1),
                Sha256Digest::from([7u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal));

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Missing parent certification should wait instead of forcing an immediate timeout.
            assert!(!matches!(state.try_verify(), Verify::Ready(..)));
            assert_eq!(state.next_timeout(), initial_deadline);
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
                    elector: round_robin(&schemes[0]),
                    epoch,
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[0].participants().len() as u64,
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
            assert!(!matches!(state.try_verify(), Verify::Ready(..)));

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);
        });
    }

    #[test]
    fn replayed_local_notarize_restores_optimistic_child_verification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(12);
            let elector = round_robin_with_term(
                &verifier,
                TermLength::new(NZU32!(5)),
                Duration::from_secs(4),
                ViewDelta::new(2),
            );
            // Use a non-leader so its local vote is the event that opens the
            // optimistic child.
            let leader_idx = usize::from(elector.elect(Rnd::new(epoch, View::new(1)), None));
            let local_idx = (leader_idx + 1) % schemes.len();

            let config = |scheme: ed25519::Scheme, elector| {
                let skip_budget = scheme.participants().len() as u64;
                Config {
                    scheme,
                    elector,
                    epoch,
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget,
                }
            };

            // Follow the live path through a local view-1 notarize vote and an
            // optimistic verification request for view 2.
            let mut live = State::new(
                context.child("live"),
                config(schemes[local_idx].clone(), elector.clone()),
            );
            live.set_genesis(test_genesis());

            let parent = Proposal::new(
                Rnd::new(epoch, View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([123u8; 32]),
            );
            assert!(live.set_proposal(View::new(1), parent));
            assert!(matches!(live.try_verify(), Verify::Ready(..)));
            assert!(live.verified(View::new(1)));
            let local_vote = live
                .construct_notarize(View::new(1))
                .expect("local notarize vote");

            let child = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                View::new(1),
                Sha256Digest::from([124u8; 32]),
            );
            assert!(live.set_proposal(View::new(2), child.clone()));
            assert!(matches!(live.try_verify(), Verify::Ready(..)));

            // Rebuild from the durable vote and redeliver the child proposal,
            // matching the inputs available after restart.
            let mut restarted = State::new(
                context.child("restarted"),
                config(schemes[local_idx].clone(), elector),
            );
            restarted.set_genesis(test_genesis());
            restarted.replay(&Artifact::Notarize(local_vote));
            assert!(restarted.set_proposal(View::new(2), child));

            // Replay must restore the ancestry gate that admitted the child on
            // the live path.
            assert!(
                matches!(restarted.try_verify(), Verify::Ready(..)),
                "replayed local notarize should preserve optimistic child verification"
            );
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
                    elector: round_robin(&schemes[0]),
                    epoch,
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[0].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());
            assert!(state.enter_view(view));
            state.set_leader(view, None);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());

            let candidates = state.certify_candidates().0;
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
                    elector: round_robin(&local_scheme),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: local_scheme.participants().len() as u64,
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
            let conflicting = build_notarization(&verifier, &other_schemes[..3], &proposal_b);
            state.add_notarization(conflicting.clone());
            state.replay(&Artifact::Notarization(conflicting.clone()));

            // Shouldn't finalize the certificate's proposal (proposal_b)
            assert!(state.construct_finalize(view).is_none());

            // Restart state and replay
            let mut restarted = State::new(
                context.child("state_restarted"),
                Config {
                    scheme: local_scheme.clone(),
                    elector: round_robin(&local_scheme),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: local_scheme.participants().len() as u64,
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

    /// Reproduces the restart equivocation trace at the state level: our
    /// replayed vote conflicts with the leader's re-forwarded proposal, then
    /// the network's finalization for the conflicting proposal arrives. The
    /// finalized proposal must drive parent lookups for the next view.
    #[test]
    fn restart_equivocation_parent_payload_tracks_finalized_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                verifier,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: schemes[1].clone(),
                    elector: round_robin(&verifier),
                    epoch,
                    view_retention: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[1].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // The initial view is led by the equivocating leader (participant 2).
            let view = View::new(1);
            assert_eq!(state.current_view(), view);
            assert_eq!(state.leader_index(view), Some(Participant::new(2)));

            // Restart: replay our journaled notarize for the leader's first proposal.
            let proposal_x = Proposal::new(
                Rnd::new(epoch, view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let local_vote = Notarize::sign(&schemes[1], proposal_x).unwrap();
            state.replay(&Artifact::Notarize(local_vote));

            // The rebuilt batcher re-forwards the leader's notarize, now
            // carrying the conflicting proposal.
            let proposal_y = Proposal::new(
                Rnd::new(epoch, view),
                GENESIS_VIEW,
                Sha256Digest::from([2u8; 32]),
            );
            assert!(!state.set_proposal(view, proposal_y.clone()));

            // The rest of the network (the leader and the other two honest
            // participants) finalized the conflicting proposal.
            let others = [schemes[0].clone(), schemes[2].clone(), schemes[3].clone()];
            let finalization = build_finalization(&verifier, &others, &proposal_y);
            let (added, equivocator) = state.add_finalization(finalization);
            assert!(added);
            assert_eq!(equivocator.unwrap(), participants[2]);

            // Verification of the next view's proposal must be offered the
            // finalized payload as the parent.
            let next = state.current_view();
            assert_eq!(next, View::new(2));
            let child = Proposal::new(Rnd::new(epoch, next), view, Sha256Digest::from([3u8; 32]));
            assert!(state.set_proposal(next, child.clone()));
            let Verify::Ready(context, proposal) = state.try_verify() else {
                panic!("verification context missing");
            };
            assert_eq!(proposal, child);
            assert_eq!(context.parent, (view, proposal_y.payload));
        });
    }

    #[test]
    fn replay_restores_indirect_notarization_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[1].clone();
            let ancestor = Proposal::new(
                Rnd::new(Epoch::new(12), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([121u8; 32]),
            );
            let descendant = Proposal::new(
                Rnd::new(Epoch::new(12), View::new(2)),
                View::new(1),
                Sha256Digest::from([122u8; 32]),
            );

            let mut state = State::new(
                context.child("initial"),
                Config {
                    scheme: local_scheme.clone(),
                    elector: round_robin_with_term(
                        &local_scheme,
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(2),
                    ),
                    epoch: Epoch::new(12),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: local_scheme.participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());
            state.create_round(View::new(1));
            assert!(state.proposed(ancestor));
            let local_vote = state
                .construct_notarize(View::new(1))
                .expect("local notarize vote");
            assert!(state.set_proposal(View::new(2), descendant.clone()));
            assert!(state.verified(View::new(2)));
            let notarization = build_notarization(&verifier, &schemes, &descendant);
            assert!(state.add_notarization(notarization.clone()).0);
            assert_eq!(
                state.optimistic_ancestry_payload(View::new(1)).copied(),
                Some(Sha256Digest::from([121u8; 32]))
            );

            let mut restarted = State::new(
                context.child("restarted"),
                Config {
                    scheme: local_scheme.clone(),
                    elector: round_robin_with_term(
                        &local_scheme,
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(2),
                    ),
                    epoch: Epoch::new(12),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: local_scheme.participants().len() as u64,
                },
            );
            restarted.set_genesis(test_genesis());
            assert!(restarted.set_proposal(View::new(2), descendant));
            assert!(restarted.verified(View::new(2)));
            restarted.add_notarization(notarization.clone());
            restarted.replay(&Artifact::Notarization(notarization));

            // The descendant certificate alone does not restore the ancestor:
            // optimistic ancestry needs our own replayed notarize vote.
            assert!(
                restarted
                    .optimistic_ancestry_payload(View::new(1))
                    .is_none()
            );

            restarted.replay(&Artifact::Notarize(local_vote));
            assert_eq!(
                restarted.optimistic_ancestry_payload(View::new(1)).copied(),
                Some(Sha256Digest::from([121u8; 32]))
            );
        });
    }

    #[test]
    fn trigger_timeout_latches_optimistic_future_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_state_with(
                &mut context,
                4,
                0,
                14,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(1),
                4,
            );
            let Fixture {
                schemes, verifier, ..
            } = fixture;

            let parent = propose_and_notarize_view1(&mut state, 116);

            let future = Proposal::new(
                Rnd::new(Epoch::new(14), View::new(2)),
                View::new(1),
                Sha256Digest::from([117u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), future));
            assert_eq!(state.current_view(), View::new(1));

            // A verification failure for the optimistic future view latches on
            // its round without disturbing the current view's schedule or
            // nullifying the future view early.
            let initial_deadline = state.next_timeout();
            let latched_at = context.current();
            state.trigger_timeout(View::new(2), TimeoutReason::InvalidProposal);
            assert!(
                state
                    .construct_nullify(View::new(2), TimeoutReason::InvalidProposal)
                    .is_none()
            );
            assert_eq!(state.next_timeout(), initial_deadline);

            // Once the view becomes current, the latch fires immediately: the
            // buffered invalid proposal suppresses the leader timeout and its
            // verification request was consumed, so without the latch the view
            // would stall until certification timeout.
            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(
                state.next_timeout(),
                (latched_at, TimeoutReason::InvalidProposal)
            );
            assert!(
                state
                    .construct_nullify(View::new(2), TimeoutReason::InvalidProposal)
                    .is_some()
            );
        });
    }

    /// A structurally invalid proposal for an optimistic future view must
    /// latch when we first look at it, not when the view becomes current.
    ///
    /// The buffered proposal suppresses the leader timeout and the round's
    /// verification request is consumed either way, so deferring the latch
    /// would stall the view until certification timeout.
    #[test]
    fn try_verify_latches_invalid_optimistic_future_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                1,
                15,
                10,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(2),
                4,
            );

            // The leader's view 1 proposal stamps the stable leader on view 2,
            // making it an optimistic future view we will look at.
            let parent = Proposal::new(
                Rnd::new(Epoch::new(15), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([150u8; 32]),
            );
            assert!(state.set_proposal(View::new(1), parent.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));

            // View 2 skips view 1, which no future certificate can repair.
            let invalid = Proposal::new(
                Rnd::new(Epoch::new(15), View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([151u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), invalid));
            assert_eq!(state.current_view(), View::new(1));

            let initial_deadline = state.next_timeout();
            let latched_at = context.current();
            assert!(matches!(state.try_verify(), Verify::Wait));

            // Latching a future view leaves the current view's schedule alone.
            assert_eq!(state.next_timeout(), initial_deadline);

            // Entering view 2 finds the latch already armed.
            let notarization = build_notarization(&verifier, &schemes, &parent);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(
                state.next_timeout(),
                (latched_at, TimeoutReason::InvalidProposal)
            );
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
                elector: round_robin(&verifier),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: verifier.participants().len() as u64,
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
                build_notarization(&verifier, &schemes, &proposal)
            };

            // Helper to create finalization for a view
            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                build_finalization(&verifier, &schemes, &proposal)
            };

            let mut pool = AbortablePool::<()>::default();

            // Add notarizations for views 3-8
            for i in 3..=8u64 {
                state.add_notarization(make_notarization(View::new(i)));
            }

            // All 6 views should be candidates
            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 6);

            // Set certify handles for views 3, 4, 5, 7 (NOT 6 or 8)
            for i in [3u64, 4, 5, 7] {
                let handle = pool.push(futures::future::pending());
                state.set_certify_handle(View::new(i), handle);
            }

            // Candidates empty (consumed by certify_candidates, handles block re-fetching)
            assert!(state.certify_candidates().0.is_empty());

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
            assert!(state.certify_candidates().0.is_empty());

            // Add view 9, should be returned as candidate
            state.add_notarization(make_notarization(View::new(9)));
            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(9));

            // Set handle for view 9, add view 10
            let handle9 = pool.push(futures::future::pending());
            state.set_certify_handle(View::new(9), handle9);
            state.add_notarization(make_notarization(View::new(10)));

            // View 10 returned (view 9 has handle)
            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), View::new(10));

            // Finalize view 9 - aborts view 9's handle
            state.add_finalization(make_finalization(View::new(9)));
            assert!(state.is_certify_aborted(View::new(9)));

            // Add view 11, should be returned
            state.add_notarization(make_notarization(View::new(11)));
            let candidates = state.certify_candidates().0;
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let make_notarization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                build_notarization(&verifier, &schemes, &proposal)
            };

            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                build_finalization(&verifier, &schemes, &proposal)
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
            assert!(
                state
                    .views
                    .get_mut(&stale_view)
                    .expect("stale round must exist")
                    .try_certify()
                    .is_some()
            );

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), live_view);
        });
    }

    #[test]
    fn nullification_keeps_notarization_as_certification_candidate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 10, 1, 4);

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), view));
            assert!(state.add_nullification(nullification));

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);
        });
    }

    #[test]
    fn nullification_does_not_abort_inflight_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 10, 1, 4);

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([24u8; 32]),
            );

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates().0;
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].round.view(), view);

            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(view, handle);

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), view));
            assert!(state.add_nullification(nullification));
            assert!(!state.is_certify_aborted(view));

            // Late certification completion is still accepted until the view is finalized.
            assert!(state.certified(view, true).is_some());
            assert!(state.explicit_ancestry_payload(view).is_some());
        });
    }

    #[test]
    fn conflicting_parent_headers_share_payload_but_certify_notarized_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            // The state signs its own view-3 nullify below, so it needs a
            // signing scheme rather than setup_state's verifier.
            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[1].clone(),
                    elector: round_robin(&verifier),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[1].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            // Certify view 1 so it remains an eligible parent.
            let certified_view = View::new(1);
            let certified_payload = Sha256Digest::from([31u8; 32]);
            let certified_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), certified_view),
                GENESIS_VIEW,
                certified_payload,
            );
            let certified_notarization =
                build_notarization(&verifier, &schemes, &certified_proposal);
            assert!(state.add_notarization(certified_notarization).0);
            assert!(state.certified(certified_view, true).is_some());

            // Start certification for view 2, then nullify it before completion.
            let nullified_view = View::new(2);
            let nullified_payload = Sha256Digest::from([32u8; 32]);
            let nullified_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), nullified_view),
                certified_view,
                nullified_payload,
            );
            let nullified_notarization =
                build_notarization(&verifier, &schemes, &nullified_proposal);
            assert!(state.add_notarization(nullified_notarization).0);
            assert_eq!(state.certify_candidates().0, vec![nullified_proposal]);
            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(nullified_view, handle);
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), nullified_view));
            assert!(state.add_nullification(nullification));

            // The view-3 leader signs a header that reuses the honest block's
            // payload but declares the older certified parent.
            let view = View::new(3);
            assert_eq!(state.current_view(), view);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));
            let payload = Sha256Digest::from([33u8; 32]);
            let bad_proposal =
                Proposal::new(Rnd::new(Epoch::new(1), view), certified_view, payload);
            let good_proposal =
                Proposal::new(Rnd::new(Epoch::new(1), view), nullified_view, payload);
            assert_ne!(bad_proposal, good_proposal);
            assert_eq!(bad_proposal.payload, good_proposal.payload);
            assert!(Notarize::sign(&schemes[0], bad_proposal.clone()).is_some());

            assert!(state.set_proposal(view, bad_proposal.clone()));
            let Verify::Ready(verify_context, verify_proposal) = state.try_verify() else {
                panic!("bad header should reach verification");
            };
            assert_eq!(verify_proposal, bad_proposal);
            assert_eq!(verify_context.parent, (certified_view, certified_payload));

            // The rejected header times out the view, so this validator
            // nullifies view 3 before the honest notarization arrives.
            state.trigger_timeout(view, TimeoutReason::InvalidProposal);
            let (retry, _) = state
                .construct_nullify(view, TimeoutReason::InvalidProposal)
                .expect("nullify");
            assert!(!retry);

            // The Byzantine leader and the other two honest validators form a
            // notarization for the header naming view 2, without this
            // validator's vote. A local nullify must not suppress the
            // certification dispatch.
            let good_votes: Vec<_> = [0usize, 2, 3]
                .into_iter()
                .map(|index| {
                    Notarize::sign(&schemes[index], good_proposal.clone()).expect("notarize")
                })
                .collect();
            let good_notarization = Notarization::from_notarizes(
                &verifier,
                non_empty![@good_votes.iter()],
                &Sequential,
            )
            .expect("notarization");
            let (added, equivocator) = state.add_notarization(good_notarization);
            assert!(added);
            assert!(equivocator.is_some());
            assert_eq!(state.certify_candidates().0, vec![good_proposal]);
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
                scheme: local_scheme.clone(),
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: local_scheme.participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(2);
            let child_view = parent_view.next();
            let payload = Sha256Digest::from([91u8; 32]);
            let proposal =
                Proposal::new(Rnd::new(Epoch::new(1), parent_view), GENESIS_VIEW, payload);

            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), parent_view));
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
                scheme: local_scheme.clone(),
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: local_scheme.participants().len() as u64,
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

            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), parent_view));
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
            assert!(!matches!(state.try_verify(), Verify::Ready(..)));

            // Late certification after nullification should unblock parent check for verification.
            assert!(state.certified(parent_view, true).is_some());
            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("verify context should exist");
            };
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    #[test]
    fn try_propose_requires_immediate_parent_within_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[2].clone(),
                    elector: round_robin_with_term(
                        &schemes[2],
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(0),
                    ),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[2].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            let parent_view = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([93u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(2)));
            state.replay(&Artifact::Nullification(nullification));

            assert!(state.enter_view(View::new(3)));
            state.set_leader(View::new(3), None);
            assert_eq!(state.leader_index(View::new(3)), Some(Participant::new(2)));
            assert!(state.try_propose().is_none());
        });
    }

    #[test]
    fn try_propose_allows_cross_term_parent_at_term_start() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[3].clone(),
                    elector: round_robin_with_term(
                        &schemes[3],
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(0),
                    ),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[3].participants().len() as u64,
                },
            );
            state.set_genesis(test_genesis());

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([94u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(4)));
            assert!(state.add_nullification(nullification));

            assert_eq!(state.current_view(), View::new(6));
            state.set_leader(View::new(6), None);
            assert_eq!(state.leader_index(View::new(6)), Some(Participant::new(3)));

            let proposal = state
                .try_propose()
                .expect("term-start proposal should use prior-term certified parent");
            assert_eq!(proposal.round.view(), View::new(6));
            assert_eq!(proposal.parent, (parent_view, parent_payload));
        });
    }

    /// One node's view of a split with a minimal quorum. The other three
    /// participants notarize views 3 and 4 optimistically while the
    /// certificate for view 2 never forms, so certification of the chain is
    /// blocked. A nullification for view 2 from the other half of the split
    /// skips the term, and we propose around the blocked chain. When view 2's
    /// notarization finally arrives, certification cascades parent-first, and
    /// a finalization for the chain tip clears the queue.
    #[test]
    fn late_parent_certificate_unblocks_notarized_chain_after_term_skip() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                3,
                1,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(3),
                4,
            );
            // Every certificate is minted by the other three participants: a
            // bare quorum that never includes our vote.
            let others = &schemes[..3];
            let epoch = Epoch::new(1);

            // Certify view 1 on genesis.
            let payload_v1 = Sha256Digest::from([1u8; 32]);
            let proposal_v1 =
                Proposal::new(Rnd::new(epoch, View::new(1)), GENESIS_VIEW, payload_v1);
            let notarization_v1 = build_notarization(&verifier, others, &proposal_v1);
            assert!(state.add_notarization(notarization_v1).0);
            assert!(state.certified(View::new(1), true).is_some());

            // Views 3 and 4 notarize optimistically; view 2's certificate
            // never forms, so certification of the whole chain is blocked.
            let payload_v2 = Sha256Digest::from([2u8; 32]);
            let proposal_v2 =
                Proposal::new(Rnd::new(epoch, View::new(2)), View::new(1), payload_v2);
            let proposal_v3 = Proposal::new(
                Rnd::new(epoch, View::new(3)),
                View::new(2),
                Sha256Digest::from([3u8; 32]),
            );
            let proposal_v4 = Proposal::new(
                Rnd::new(epoch, View::new(4)),
                View::new(3),
                Sha256Digest::from([4u8; 32]),
            );
            for proposal in [&proposal_v3, &proposal_v4] {
                let notarization = build_notarization(&verifier, others, proposal);
                assert!(state.add_notarization(notarization).0);
            }
            assert!(state.certify_candidates().0.is_empty());

            // The other half of the split nullified view 2. Its nullification
            // covers the rest of the term, and the term-start proposal builds
            // on certified view 1, around the blocked chain.
            let nullification =
                build_nullification(&verifier, others, Rnd::new(epoch, View::new(2)));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(6));
            assert_eq!(state.leader_index(View::new(6)), Some(Participant::new(3)));
            let proposal = state
                .try_propose()
                .expect("term-start proposal should skip the blocked chain");
            assert_eq!(proposal.parent, (View::new(1), payload_v1));

            // View 2's notarization finally arrives, and certification
            // cascades parent-first across the recovered chain.
            let notarization_v2 = build_notarization(&verifier, others, &proposal_v2);
            assert!(state.add_notarization(notarization_v2).0);
            for view in [View::new(2), View::new(3)] {
                let candidates = state.certify_candidates().0;
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].round.view(), view);
                assert!(state.certified(view, true).is_some());
            }

            // A finalization for the chain tip settles view 4 without waiting
            // for its pending certification.
            let finalization = build_finalization(&verifier, others, &proposal_v4);
            assert!(state.add_finalization(finalization).0);
            assert!(state.certify_candidates().0.is_empty());
            assert_eq!(state.current_view(), View::new(6));
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
                scheme: local_scheme.clone(),
                elector: round_robin(&local_scheme),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_secs(30),
                skip_budget: local_scheme.participants().len() as u64,
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
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
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
            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());
            assert!(!matches!(state.try_verify(), Verify::Ready(..)));
            assert_eq!(state.next_timeout(), initial_deadline);

            // Once the intermediate nullification arrives, the same proposal should become verifiable.
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), blocked_view));
            assert!(state.add_nullification(nullification));

            let Verify::Ready(ctx, proposal) = state.try_verify() else {
                panic!("verify context should exist");
            };
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    /// Builds a follower state at view 3 (RoundRobin with epoch 1 elects
    /// index 0, so signer index 1 follows) for ancestry-resolution tests.
    fn setup_follower_state(
        context: &mut deterministic::Context,
    ) -> (Fixture<ed25519::Scheme>, TestState) {
        let namespace = b"ns".to_vec();
        let fixture = ed25519::fixture(context, &namespace, 4);
        let local_scheme = fixture.schemes[1].clone();
        let cfg = Config {
            scheme: local_scheme.clone(),
            elector: round_robin(&local_scheme),
            epoch: Epoch::new(1),
            view_retention: ViewDelta::new(10),
            leader_timeout: Duration::from_secs(10),
            certification_timeout: Duration::from_secs(10),
            timeout_retry: Duration::from_secs(30),
            skip_budget: local_scheme.participants().len() as u64,
        };
        let mut state = State::new(context.child("state"), cfg);
        state.set_genesis(test_genesis());
        (fixture, state)
    }

    #[test]
    fn resolution_requests_first_missing_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let expected_leader = fixture.participants[0].clone();
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Certify view 2, entering view 3.
            let skipped_view = View::new(2);
            let skipped_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), skipped_view),
                GENESIS_VIEW,
                Sha256Digest::from([88u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &skipped_proposal);
            let (added, _) = state.add_notarization(notarization.clone());
            assert!(added);
            assert!(state.certified(skipped_view, true).is_some());
            let child_view = View::new(3);
            state.set_leader(child_view, None);
            assert_eq!(state.current_view(), child_view);

            // A proposal that skips the certified view requires its leader's
            // Nullification(2).
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                View::new(1),
                Sha256Digest::from([89u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Nullification,
                    target,
                }
                    if proposal == child_view
                        && view == skipped_view
                        && target == expected_leader
            ));

            // The leader's preferred notarization is already known and does
            // not provide the nullification this proposal needs. It must
            // neither permit a vote nor create a request loop in the same
            // round.
            let (added, _) = state.add_notarization(notarization);
            assert!(!added);
            assert!(matches!(state.try_verify(), Verify::Wait));
        });
    }

    #[test]
    fn resolution_requests_uncertified_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Track nullifications for views 1 and 2, entering view 3.
            let parent_view = View::new(1);
            let nullification_1 =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), parent_view));
            assert!(state.add_nullification(nullification_1.clone()));
            let nullification_2 =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(2)));
            assert!(state.add_nullification(nullification_2));
            let child_view = View::new(3);
            assert_eq!(state.current_view(), child_view);

            // The leader must hold a certificate for the parent it named.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([90u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Notarization,
                    ..
                }
                    if proposal == child_view
                        && view == parent_view
            ));

            // The leader's preferred covering nullification does not certify
            // the named parent, so it must neither permit a vote nor create a
            // same-round request loop.
            assert!(!state.add_nullification(nullification_1));
            assert!(matches!(state.try_verify(), Verify::Wait));
        });
    }

    #[test]
    fn resolution_silent_for_parent_below_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Finalize view 2, entering view 3.
            let finalized_view = View::new(2);
            let finalized_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), finalized_view),
                GENESIS_VIEW,
                Sha256Digest::from([91u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &finalized_proposal);
            let (added, _) = state.add_finalization(finalization);
            assert!(added);
            let child_view = View::new(3);
            assert_eq!(state.current_view(), child_view);

            // A proposal built below the finalization floor is invalid and
            // draws no request. An honest proposer reaches this state only
            // while holding a nullification that same-term vote safety rules
            // out alongside our finalization. There is no honest peer to
            // converge with.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                View::new(1),
                Sha256Digest::from([92u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(state.try_verify(), Verify::Wait));
        });
    }

    #[test]
    fn resolution_starts_at_first_gap_before_displaced_certificate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Certify view 3 from gossip without covering views 1 and 2. A
            // notarization needs no ancestry. Certification advances the view.
            // Then track a nullification for view 4 to reach view 5 as a
            // follower.
            let displaced_view = View::new(3);
            let displaced_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), displaced_view),
                View::new(1),
                Sha256Digest::from([95u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &displaced_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(displaced_view, true).is_some());
            let nullification_4 =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(4)));
            assert!(state.add_nullification(nullification_4));
            let child_view = View::new(5);
            assert_eq!(state.current_view(), child_view);

            // Repair starts at the first missing view, independently of the
            // displaced certificate above it.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                View::new(1),
                Sha256Digest::from([96u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Nullification,
                    ..
                }
                    if proposal == child_view
                        && view == View::new(2)
            ));
        });
    }

    #[test]
    fn resolution_rearms_in_next_round() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Certify view 2 and request its missing nullification at view 3.
            let skipped_view = View::new(2);
            let skipped_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), skipped_view),
                GENESIS_VIEW,
                Sha256Digest::from([97u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &skipped_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(skipped_view, true).is_some());
            state.set_leader(View::new(3), None);
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                View::new(1),
                Sha256Digest::from([98u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    view,
                    kind: Kind::Nullification,
                    ..
                } if view == skipped_view
            ));

            // Advance two views (we lead view 4, so a proposal there would
            // not be verified) and encounter the same gap again. The new
            // round must emit the request afresh.
            for view in 3..=4 {
                let nullification = build_nullification(
                    &verifier,
                    &schemes,
                    Rnd::new(Epoch::new(1), View::new(view)),
                );
                assert!(state.add_nullification(nullification));
            }
            let retry_view = View::new(5);
            assert_eq!(state.current_view(), retry_view);
            let retry_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), retry_view),
                View::new(1),
                Sha256Digest::from([99u8; 32]),
            );
            assert!(state.set_proposal(retry_view, retry_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Nullification,
                    ..
                }
                    if proposal == retry_view
                        && view == skipped_view
            ));
        });
    }

    #[test]
    fn resolution_does_not_wait_for_local_conflict() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Track a notarization for view 2 without certifying it.
            let skipped_view = View::new(2);
            let skipped_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), skipped_view),
                GENESIS_VIEW,
                Sha256Digest::from([100u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &skipped_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            let child_view = View::new(3);
            assert!(state.enter_view(child_view));
            state.set_leader(child_view, None);

            // The leader's proposal is enough evidence to request the missing
            // view. No conflicting local certificate is required.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                View::new(1),
                Sha256Digest::from([101u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Nullification,
                    ..
                }
                    if proposal == child_view
                        && view == skipped_view
            ));

            // Certification does not duplicate the still-active request.
            assert!(state.certified(skipped_view, true).is_some());
            assert!(matches!(state.try_verify(), Verify::Wait));
        });
    }

    #[test]
    fn resolution_requests_named_parent_with_term_cover() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            // Stable leaders use three-view terms. A nullification covers the
            // rest of its term. The covering certificate for a parent may sit
            // at an earlier view.
            let (fixture, mut state) = setup_state(&mut context, 4, 1, 10, 3, 4);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // A nullification at view 1 covers views 1..=3 and advances to
            // the next term start (view 4).
            let nullification_1 =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(1)));
            assert!(state.add_nullification(nullification_1));
            let child_view = View::new(4);
            assert_eq!(state.current_view(), child_view);

            // A proposal built on covered, uncertified view 2 asks its leader
            // for that named parent.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                View::new(2),
                Sha256Digest::from([102u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Notarization,
                    ..
                }
                    if proposal == child_view
                        && view == View::new(2)
            ));
        });
    }

    #[test]
    fn resolution_requests_absent_certificate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (fixture, mut state) = setup_follower_state(&mut context);
            let (schemes, verifier) = (fixture.schemes, fixture.verifier);

            // Certify view 1 and move into view 3 with nothing for view 2.
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([93u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &parent_proposal);
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());
            let child_view = View::new(3);
            assert!(state.enter_view(child_view));
            state.set_leader(child_view, None);

            // The proposal identifies the leader that must hold the missing
            // certificate even when we hold no conflicting evidence.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([94u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal));
            assert!(matches!(
                state.try_verify(),
                Verify::Resolve {
                    proposal,
                    view,
                    kind: Kind::Nullification,
                    ..
                }
                    if proposal == child_view
                        && view == View::new(2)
            ));
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
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
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
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(view));

            // Timeout path emits a first-attempt nullify.
            let (retry, _) = state
                .construct_nullify(view, TimeoutReason::LeaderTimeout)
                .expect("timeout nullify should exist");
            assert!(!retry);

            // Attempt to notarize after timeout
            assert!(state.construct_notarize(view).is_none());
        });
    }

    #[test]
    fn nullification_skips_to_next_term_start() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(5)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // We start in view 1 (first view of term [1,5]).
            assert_eq!(state.current_view(), View::new(1));

            // Nullify view 1: should skip to view 6 (start of next term [6,10]).
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(1)));
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(6),
                "nullification in term should skip to next term start"
            );
        });
    }

    #[test]
    fn nullification_at_term_end_skips_correctly() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Term [1,3]. Advance to view 3 via finalization of view 1 and 2.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal_v1);
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([11u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal_v2);
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(3));

            // Nullify view 3 (last view of term [1,3]). Should go to view 4 (start of [4,6]).
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(3)));
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(4),
                "nullification at term end should advance to next term start"
            );
        });
    }

    #[test]
    fn term_length_one_nullification_advances_by_one() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin(&schemes[0]),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            assert_eq!(state.current_view(), View::new(1));

            // With term_length=1, nullification should advance by exactly 1.
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), View::new(1)));
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(2),
                "term_length=1 should advance by exactly one view"
            );
        });
    }

    #[test]
    fn term_safety_blocks_finalize_after_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(5)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // View 1, first view of term [1,5].
            let view = state.current_view();
            assert_eq!(view, View::new(1));

            // Emit a timeout nullify vote for view 1.
            let (was_retry, _) = state
                .construct_nullify(view, TimeoutReason::LeaderTimeout)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            // View 1 notarizes and certifies (without finalizing), advancing
            // us to view 2 in the same term.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal_v1);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(view, true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            // View 2 is certified in the same term. Without an observed
            // finalization at or above the nullified view, the earlier local
            // nullify prevents a later finalize vote in the term.
            let view = View::new(2);
            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            assert!(state.set_proposal(view, proposal_v2.clone()));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(view));

            let notarization = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(view, true).is_some());

            assert!(
                state.construct_finalize(view).is_none(),
                "should not finalize a later view after nullifying in same term"
            );

            // The finalization for view 1 arrives late (e.g., selectively
            // withheld). Observing it unblocks the finalize vote for view 2.
            let finalization = build_finalization(&verifier, &schemes, &proposal_v1);
            state.add_finalization(finalization);
            assert!(
                state.construct_finalize(view).is_some(),
                "late-arriving finalization at the nullified view should unblock the finalize vote"
            );
        });
    }

    #[test]
    fn same_term_nullify_does_not_block_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(5)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view, TimeoutReason::LeaderTimeout)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            // View 1 notarizes and certifies (no finalization is observed, so
            // a hypothetical notarize gate would still be blocked), advancing
            // us to view 2 in the same term.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );
            let notarization = build_notarization(&verifier, &schemes, &proposal_v1);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(view, true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(View::new(2)));

            assert!(
                state.construct_notarize(View::new(2)).is_some(),
                "same-term nullify should not block later notarize votes"
            );
        });
    }

    #[test]
    fn recovered_parent_finalization_allows_same_term_child_finalize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                1,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(0),
                4,
            );
            assert!(state.enter_view(View::new(2)));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([44u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2.clone()));

            let notarization = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(View::new(2), true).is_some());

            assert!(state.construct_finalize(View::new(2)).is_none());

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([45u8; 32]),
            );
            let finalization_v1 = build_finalization(&verifier, &schemes, &proposal_v1);
            state.add_finalization(finalization_v1);

            assert!(state.construct_finalize(View::new(2)).is_some());
        });
    }

    #[test]
    fn certified_child_without_parent_anchor_cannot_finalize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state_with(
                &mut context,
                4,
                0,
                1,
                20,
                TermLength::new(NZU32!(5)),
                ViewDelta::new(0),
                4,
            );

            // Construct a defensive state the actor cannot persist: live
            // child certification is dispatched only after its parent anchor's
            // journal section has synced. The test bypasses that ordering to
            // prove the state-level finalize gate stays closed.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([50u8; 32]),
            );
            let notarization_v1 = build_notarization(&verifier, &schemes, &proposal_v1);
            assert!(state.add_notarization(notarization_v1).0);

            // Replay the child's certification directly, without the parent
            // precheck that guards the production dispatch path.
            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([51u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2.clone()));
            let notarization_v2 = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(state.add_notarization(notarization_v2).0);
            state.replay(&Artifact::Certification(
                Rnd::new(Epoch::new(1), View::new(2)),
                true,
            ));

            assert!(
                state.construct_finalize(View::new(2)).is_none(),
                "finalize must wait for the parent's explicit certification anchor"
            );

            // Supplying the missing parent anchor restores the valid state.
            assert!(state.certified(View::new(1), true).is_some());
            assert!(
                state.construct_finalize(View::new(2)).is_some(),
                "finalize should proceed once the parent is explicitly certified"
            );
        });
    }

    #[test]
    fn replay_restores_term_nullify_tracking_for_term_safety() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(5)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };

            // Helper that prepares a locally finalized parent at view 1 and a
            // certified child at view 2 within the same term.
            let build_finalizable_view_2 = |state: &mut State<_, _, _, _>| {
                let proposal_v1 = Proposal::new(
                    Rnd::new(Epoch::new(1), View::new(1)),
                    GENESIS_VIEW,
                    Sha256Digest::from([98u8; 32]),
                );
                assert!(state.set_proposal(View::new(1), proposal_v1.clone()));
                assert!(matches!(state.try_verify(), Verify::Ready(..)));
                assert!(state.verified(View::new(1)));
                let notarization_v1 = build_notarization(&verifier, &schemes, &proposal_v1);
                assert!(state.add_notarization(notarization_v1).0);
                assert!(state.certified(View::new(1), true).is_some());
                assert!(state.construct_finalize(View::new(1)).is_some());

                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), View::new(2)),
                    View::new(1),
                    Sha256Digest::from([99u8; 32]),
                );
                assert!(state.set_proposal(View::new(2), proposal.clone()));

                let notarization = build_notarization(&verifier, &schemes, &proposal);
                assert!(state.add_notarization(notarization).0);
                assert!(state.certified(View::new(2), true).is_some());
            };

            // Baseline: without replayed nullify, finalization is allowed at view 2.
            let mut baseline = State::new(context.child("baseline"), cfg);
            baseline.set_genesis(test_genesis());
            build_finalizable_view_2(&mut baseline);
            assert!(
                baseline.construct_finalize(View::new(2)).is_some(),
                "finalize should be allowed without prior nullify"
            );

            // Restarted state: replay local nullify at view 1, then restore the
            // same certified suffix via replay/local certification artifacts.
            let mut restarted = State::new(
                context.child("restarted"),
                Config {
                    scheme: schemes[0].clone(),
                    elector: round_robin_with_term(
                        &schemes[0],
                        TermLength::new(NZU32!(5)),
                        Duration::from_secs(4),
                        ViewDelta::new(0),
                    ),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[0].participants().len() as u64,
                },
            );
            restarted.set_genesis(test_genesis());
            let nullify =
                Nullify::sign::<Sha256Digest>(&schemes[0], Rnd::new(Epoch::new(1), View::new(1)))
                    .expect("nullify");
            restarted.replay(&Artifact::Nullify(nullify));

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([98u8; 32]),
            );
            let local_notarize_v1 =
                Notarize::sign(&schemes[0], proposal_v1.clone()).expect("local notarize");
            restarted.replay(&Artifact::Notarize(local_notarize_v1));
            let notarization_v1 = build_notarization(&verifier, &schemes, &proposal_v1);
            assert!(restarted.add_notarization(notarization_v1).0);
            assert!(restarted.certified(View::new(1), true).is_some());

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([99u8; 32]),
            );
            assert!(restarted.set_proposal(View::new(2), proposal_v2.clone()));
            let notarization_v2 = build_notarization(&verifier, &schemes, &proposal_v2);
            assert!(restarted.add_notarization(notarization_v2).0);
            assert!(restarted.certified(View::new(2), true).is_some());

            assert!(
                restarted.construct_finalize(View::new(2)).is_none(),
                "replayed nullify should restore term-safety lock after restart"
            );
        });
    }

    #[test]
    fn pruned_inert_nullify_does_not_block_finalize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(20)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let (was_retry, nullify) = state
                .construct_nullify(View::new(1), TimeoutReason::LeaderTimeout)
                .expect("timeout nullify should exist");
            assert!(!was_retry);
            let nullify_artifact = Artifact::Nullify(nullify);

            let finalized_view = View::new(10);
            let finalized_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), finalized_view),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &finalized_proposal);
            let finalization_artifact = Artifact::Finalization(finalization.clone());
            state.add_finalization(finalization.clone());
            assert_eq!(state.last_finalized(), finalized_view);
            assert_eq!(state.min_active(), View::new(8));

            let removed = state.prune();
            assert!(removed.contains(&View::new(1)));

            let certify_view = |state: &mut TestState| {
                let view = View::new(11);
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    finalized_view,
                    Sha256Digest::from([11u8; 32]),
                );
                assert!(state.set_proposal(view, proposal.clone()));
                assert!(matches!(state.try_verify(), Verify::Ready(..)));
                assert!(state.verified(view));

                let notarization = build_notarization(&verifier, &schemes, &proposal);
                assert!(state.add_notarization(notarization).0);
                assert!(state.certified(view, true).is_some());
                view
            };

            let view = certify_view(&mut state);

            // The finalization at view 10 covers the nullify at view 1, so the
            // finalize vote is unblocked (and pruning the nullified round must
            // not resurrect the block). Lock-relevant nullify votes are always
            // above last_finalized and thus above min_active, so pruning can
            // never remove an active lock.
            assert!(
                state.construct_finalize(view).is_some(),
                "inert same-term nullify must not block finalize after pruning"
            );

            let mut restarted = State::new(
                context.child("restarted"),
                Config {
                    scheme: schemes[0].clone(),
                    elector: round_robin_with_term(
                        &schemes[0],
                        TermLength::new(NZU32!(20)),
                        Duration::from_secs(4),
                        ViewDelta::new(0),
                    ),
                    epoch: Epoch::new(1),
                    view_retention: ViewDelta::new(2),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    skip_budget: schemes[0].participants().len() as u64,
                },
            );
            restarted.set_genesis(test_genesis());
            restarted.replay(&nullify_artifact);
            restarted.replay(&finalization_artifact);
            restarted.add_finalization(finalization);
            assert_eq!(restarted.last_finalized(), finalized_view);

            let view = certify_view(&mut restarted);
            assert!(
                restarted.construct_finalize(view).is_some(),
                "replayed inert nullify must remain inert after restart"
            );
        });
    }

    #[test]
    fn term_safety_allows_finalize_in_new_term_after_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Vote to nullify in term [1,3], activating the term safety lock.
            let view1 = View::new(1);
            let (was_retry, _) = state
                .construct_nullify(view1, TimeoutReason::LeaderTimeout)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            // Receive nullification certificate for view 1 and skip to next term start (view 4).
            let nullification =
                build_nullification(&verifier, &schemes, Rnd::new(Epoch::new(1), view1));
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(4));

            // Build, verify, notarize, and certify view 4 (term [4,6]).
            let view4 = View::new(4);
            let proposal_v4 = Proposal::new(
                Rnd::new(Epoch::new(1), view4),
                GENESIS_VIEW,
                Sha256Digest::from([55u8; 32]),
            );
            state.set_proposal(view4, proposal_v4.clone());
            assert!(matches!(state.try_verify(), Verify::Ready(..)));
            assert!(state.verified(view4));

            let notarization = build_notarization(&verifier, &schemes, &proposal_v4);
            state.add_notarization(notarization);
            assert!(state.certified(view4, true).is_some());

            // Finalization in a different term should not be blocked by the lock.
            assert!(
                state.construct_finalize(view4).is_some(),
                "finalize should be allowed in a new term after prior-term nullify"
            );
        });
    }

    #[test]
    fn same_leader_within_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: round_robin_with_term(
                    &schemes[0],
                    TermLength::new(NZU32!(3)),
                    Duration::from_secs(4),
                    ViewDelta::new(0),
                ),
                epoch: Epoch::new(1),
                view_retention: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                skip_budget: schemes[0].participants().len() as u64,
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // View 1 is in term [1,3]. Get its leader.
            let leader_v1 = state.leader_index(View::new(1)).unwrap();

            // Advance to view 2 via finalization.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal);
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let leader_v2 = state.leader_index(View::new(2)).unwrap();
            assert_eq!(
                leader_v1, leader_v2,
                "views within the same term should have the same leader"
            );

            // Advance to view 3.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([11u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal);
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(3));

            let leader_v3 = state.leader_index(View::new(3)).unwrap();
            assert_eq!(
                leader_v1, leader_v3,
                "last view in same term should have the same leader"
            );

            // Advance to view 4 (new term [4,6]).
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                View::new(2),
                Sha256Digest::from([12u8; 32]),
            );
            let finalization = build_finalization(&verifier, &schemes, &proposal);
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(4));

            // Leader of view 4 may differ since it's a new term (depends on election).
            // Just verify the leader is set.
            assert!(state.leader_index(View::new(4)).is_some());
        });
    }
}
