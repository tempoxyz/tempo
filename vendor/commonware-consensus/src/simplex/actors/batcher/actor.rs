use super::{Config, Mailbox, Message, Round};
use crate::{
    simplex::{
        actors::voter,
        config::ForwardingPolicy,
        interesting,
        metrics::{Inbound, Peer, TimeoutReason},
        scheme::Scheme,
        types::{Activity, Certificate, Proposal, Vote},
        Plan,
    },
    types::{Epoch, Participant, Round as Rnd, View, ViewDelta},
    Epochable, Relay, Reporter, Viewable,
};
use commonware_actor::mailbox;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::codec::WrappedReceiver, Blocker, Receiver, Recipients};
use commonware_parallel::Strategy;
use commonware_runtime::{
    spawn_cell,
    telemetry::{
        metrics::{
            histogram::{self, Buckets},
            Counter, CounterFamily, GaugeExt, GaugeFamily, Histogram, MetricsExt as _,
        },
        traces::TracedExt as _,
    },
    Clock, ContextCell, Handle, Metrics, Spawner,
};
use commonware_utils::ordered::Quorum;
use rand_core::CryptoRng;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, info_span, trace, Instrument as _, Span};

/// Tracks the current view, its leader, and whether the voter has
/// already been told to timeout this view.
struct Current {
    view: View,
    leader: Option<Participant>,
    timed_out: bool,
}

pub struct Actor<E, S, B, D, Re, Rl, T>
where
    E: Spawner + Metrics + Clock + CryptoRng,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay,
    T: Strategy,
{
    context: ContextCell<E>,

    scheme: Arc<S>,

    blocker: B,
    reporter: Re,
    relay: Rl,
    strategy: T,

    activity_timeout: ViewDelta,
    skip_timeout: ViewDelta,
    forwarding: ForwardingPolicy,
    epoch: Epoch,

    mailbox_receiver: mailbox::Receiver<Message<S, D>>,

    added: Counter,
    verified: Counter,
    inbound_messages: CounterFamily<Inbound>,
    latest_vote: GaugeFamily<Peer<S::PublicKey>>,
    latest_seen: Vec<View>,
    batch_size: Histogram,
    verify_latency: histogram::Timed,
    recover_latency: histogram::Timed,
}

impl<E, S, B, D, Re, Rl, T> Actor<E, S, B, D, Re, Rl, T>
where
    E: Spawner + Metrics + Clock + CryptoRng,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    Re: Reporter<Activity = Activity<S, D>>,
    Rl: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    T: Strategy,
{
    pub fn new(context: E, cfg: Config<S, B, Re, Rl, T>) -> (Self, Mailbox<S, D>) {
        let scheme = Arc::new(cfg.scheme);
        let participants = scheme.participants();
        let participant_count = participants.len();
        let added = context.counter("added", "number of messages added to the verifier");
        let verified = context.counter("verified", "number of messages verified");
        let inbound_messages = context.family("inbound_messages", "number of inbound messages");
        let latest_vote: GaugeFamily<Peer<S::PublicKey>> =
            context.family("latest_vote", "view of latest vote received per peer");
        for participant in participants.iter() {
            latest_vote.get_or_create_by(participant).set(0);
        }
        let batch_size = context.histogram(
            "batch_size",
            "number of messages in a signature verification batch",
            [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0],
        );
        let verify_latency = context.histogram(
            "verify_latency",
            "latency of signature verification",
            Buckets::CRYPTOGRAPHY,
        );
        let recover_latency = context.histogram(
            "recover_latency",
            "certificate recover latency",
            Buckets::CRYPTOGRAPHY,
        );
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),

                scheme,

                blocker: cfg.blocker,
                reporter: cfg.reporter,
                relay: cfg.relay,
                strategy: cfg.strategy,

                activity_timeout: cfg.activity_timeout,
                skip_timeout: cfg.skip_timeout,
                forwarding: cfg.forwarding,
                epoch: cfg.epoch,

                mailbox_receiver: receiver,

                added,
                verified,
                inbound_messages,
                latest_vote,
                latest_seen: vec![View::zero(); participant_count],
                batch_size,
                verify_latency: histogram::Timed::new(verify_latency),
                recover_latency: histogram::Timed::new(recover_latency),
            },
            Mailbox::new(sender),
        )
    }

    fn new_round(&self, view: View) -> Round<S, B, D, Re> {
        Round::new(
            Rnd::new(self.epoch, view),
            Arc::clone(&self.scheme),
            self.blocker.clone(),
            self.reporter.clone(),
        )
    }

    /// Records the latest view message received from a participant.
    ///
    /// This mechanism is not resistant to malicious validators (nor is
    /// it meant to be). If a peer sends us a certificate very far in the future,
    /// we will record that as their latest activity (and not attempt to skip them).
    fn record_activity(&mut self, sender: &S::PublicKey, view: View) {
        let Some(participant) = self.scheme.participants().index(sender) else {
            return;
        };
        let seen_view = &mut self.latest_seen[usize::from(participant)];
        if *seen_view < view {
            *seen_view = view;
        }
    }

    /// Returns true if the participant has sent a recent message.
    fn is_active(
        &self,
        work: &BTreeMap<View, Round<S, B, D, Re>>,
        view: View,
        participant: Participant,
    ) -> bool {
        // Until we have tracked `skip_timeout` views, everyone stays active so startup does not
        // immediately skip leaders whose `latest_seen` entry is still at the default view. This is
        // a work-entry heuristic: skipped or coalesced updates can make `work.len()` smaller than
        // the elapsed view span.
        if work.len() < self.skip_timeout.get() as usize {
            return true;
        }
        let seen_view = self.latest_seen[usize::from(participant)];
        view.get().saturating_sub(seen_view.get()) < self.skip_timeout.get()
    }

    /// Maps `missing` participants to targeted forward recipients, excluding self.
    fn forward_recipients(&self, missing: &[Participant]) -> Vec<S::PublicKey> {
        let me = self.scheme.me();
        missing
            .iter()
            .filter(|&&p| Some(p) != me)
            .filter_map(|&p| self.scheme.participants().key(p).cloned())
            .collect()
    }

    /// Selects forwarding targets for a certified proposal under the active policy.
    fn forward_targets(
        &self,
        round: &Round<S, B, D, Re>,
        proposal: &Proposal<D>,
        next_leader: Participant,
    ) -> Vec<Participant> {
        match self.forwarding {
            ForwardingPolicy::Disabled => Vec::new(),
            ForwardingPolicy::SilentVoters => round.missing_voters(proposal),
            ForwardingPolicy::SilentLeader => round
                .is_missing_voter(proposal, next_leader)
                .then_some(next_leader)
                .into_iter()
                .collect(),
        }
    }

    /// Forwards a proposal to the requested peers.
    fn forward_proposal(&mut self, proposal: Proposal<D>, missing: Vec<Participant>) {
        let peers = self.forward_recipients(&missing);
        if peers.is_empty() {
            return;
        }
        let _ = self.relay.broadcast(
            proposal.payload,
            Plan::Forward {
                round: proposal.round,
                recipients: Recipients::Some(peers),
            },
        );
    }

    /// Returns true if the leader has nullified the current view
    /// and we have not yet notified the voter.
    fn leader_nullified(current: &Current, work: &BTreeMap<View, Round<S, B, D, Re>>) -> bool {
        if current.timed_out {
            return false;
        }
        let Some(leader) = current.leader else {
            return false;
        };
        work.get(&current.view)
            .is_some_and(|round| round.has_nullify(leader))
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(voter, vote_receiver, certificate_receiver)
        )
    }

    pub async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        vote_receiver: impl Receiver<PublicKey = S::PublicKey>,
        certificate_receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let mut vote_receiver: WrappedReceiver<_, Vote<S, D>> =
            WrappedReceiver::new((), vote_receiver);
        let mut certificate_receiver: WrappedReceiver<_, Certificate<S, D>> =
            WrappedReceiver::new(self.scheme.certificate_codec_config(), certificate_receiver);

        // Initialize view data structures
        let mut current = Current {
            view: View::zero(),
            leader: None,
            timed_out: false,
        };
        let mut finalized = View::zero();
        let mut work: BTreeMap<View, Round<S, B, D, Re>> = BTreeMap::new();
        select_loop! {
            self.context,
            on_start => {
                // Track which view was modified (if any) for certificate construction
                let updated_view;
            },
            on_stopped => {
                debug!("context shutdown, stopping batcher");
            },
            Some(message) = self.mailbox_receiver.recv() else break => {
                let view = message.view();
                let operation = message.name();
                let epoch = self.epoch;
                let process_span = |parent: Span| {
                    info_span!(
                        parent: parent,
                        "simplex.batcher.process",
                        operation,
                        epoch = epoch.traced(),
                        view = view.traced()
                    )
                };
                match message {
                    Message::Update {
                        span,
                        current: new_current,
                        leader,
                        finalized: new_finalized,
                        forwardable_proposal,
                    } => {
                        let process = process_span(span.clone());
                        let _guard = process.entered();
                        let am_leader = self.scheme.me().is_some_and(|me| me == leader);
                        current = Current {
                            view: new_current,
                            leader: Some(leader),
                            timed_out: false,
                        };
                        finalized = new_finalized;

                        // Close the root span of any view the chain has now decided
                        for (_, round) in work.range_mut(..=finalized) {
                            round.close_span();
                        }

                        // Track the new current view, adopting the voter's view
                        // span so all of its work shares one trace
                        let round = work
                            .entry(current.view)
                            .or_insert_with(|| self.new_round(current.view));
                        round.set_span(span);
                        round.set_leader(leader);

                        // If the leader nullified this view or has not been active
                        // recently, tell the voter to reduce the leader timeout to now
                        #[allow(clippy::collapsible_else_if)]
                        let timeout_reason = if Self::leader_nullified(&current, &work) {
                            // Leader already buffered a nullify for this now-current view
                            // (allowed because we accept votes up to `current+1`)
                            Some(TimeoutReason::LeaderNullify)
                        } else {
                            if am_leader {
                                // If we are the leader, we should not timeout
                                None
                            } else {
                                // If we are not the leader and the leader isn't active, we should timeout
                                (!self.is_active(&work, current.view, leader))
                                    .then_some(TimeoutReason::Inactivity)
                            }
                        };
                        if let Some(timeout_reason) = timeout_reason {
                            current.timed_out = true;
                            voter.timeout(Rnd::new(self.epoch, current.view), timeout_reason);
                        }

                        // Forward the proposal, if enabled and we have something to forward
                        if let Some((proposal, round)) = forwardable_proposal
                            .filter(|_| self.forwarding.is_enabled())
                            .and_then(|proposal| {
                                work.get(&proposal.view()).map(|round| (proposal, round))
                            })
                        {
                            let participants = self.forward_targets(round, &proposal, leader);
                            self.forward_proposal(proposal, participants);
                        }

                        // Setting leader may enable batch verification
                        updated_view = current.view;
                    }
                    Message::Constructed(message) => {
                        // If the view isn't interesting, we can skip
                        if !interesting(self.activity_timeout, finalized, current.view, view, false)
                        {
                            continue;
                        }

                        // Add the message to the verifier
                        let round = work.entry(view).or_insert_with(|| self.new_round(view));
                        let process = process_span(round.span());
                        let _guard = process.entered();
                        round.add_constructed(message);
                        self.added.inc();
                        updated_view = view;
                    }
                }
            },
            // Handle certificates from the network
            Ok((sender, message)) = certificate_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "decoding error");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Certificate::Notarization(_) => Inbound::notarization(&sender),
                    Certificate::Nullification(_) => Inbound::nullification(&sender),
                    Certificate::Finalization(_) => Inbound::finalization(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch");
                    continue;
                }

                // Allow future certificates (they advance our view)
                let view = message.view();
                if !interesting(
                    self.activity_timeout,
                    finalized,
                    current.view,
                    view,
                    true, // allow future
                ) {
                    continue;
                }
                self.record_activity(&sender, view);

                // Skip certificates we already have for the view
                let kind = message.kind();
                let round = work.get(&view);
                let duplicate = round.is_some_and(|round| match &message {
                    Certificate::Notarization(_) => round.has_notarization(),
                    Certificate::Nullification(_) => round.has_nullification(),
                    Certificate::Finalization(_) => round.has_finalization(),
                });
                if duplicate {
                    trace!(%view, kind, "skipping duplicate certificate");
                    continue;
                }

                // Parent under the view's span if we already track the view (we avoid
                // creating per-view state for certificates that fail verification)
                let parent = round.map(|round| round.span()).unwrap_or_else(Span::none);
                let span = info_span!(
                    parent: parent,
                    "simplex.batcher.verify_certificate",
                    kind,
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                match message {
                    Certificate::Notarization(notarization) => {
                        // Verify the certificate
                        if !notarization.verify(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid notarization");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .mark_notarized();
                        voter.recovered(Certificate::Notarization(notarization));
                    }
                    Certificate::Nullification(nullification) => {
                        // Verify the certificate
                        if !nullification.verify::<_, D>(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid nullification");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .mark_nullified();
                        voter.recovered(Certificate::Nullification(nullification));
                    }
                    Certificate::Finalization(finalization) => {
                        // Verify the certificate
                        if !finalization.verify(
                            self.context.as_mut(),
                            self.scheme.as_ref(),
                            &self.strategy,
                        ) {
                            commonware_p2p::block!(self.blocker, sender, %view, "invalid finalization");
                            continue;
                        }

                        // Store and forward to voter
                        work.entry(view)
                            .or_insert_with(|| self.new_round(view))
                            .mark_finalized();
                        voter.recovered(Certificate::Finalization(finalization));
                    }
                }

                // Certificates are already forwarded to voter, no need for construction
                continue;
            },
            // Handle votes from the network
            Ok((sender, message)) = vote_receiver.recv() else break => {
                // If there is a decoding error, block
                let Ok(message) = message else {
                    commonware_p2p::block!(self.blocker, sender, "decoding error");
                    continue;
                };

                // Update metrics
                let label = match &message {
                    Vote::Notarize(_) => Inbound::notarize(&sender),
                    Vote::Nullify(_) => Inbound::nullify(&sender),
                    Vote::Finalize(_) => Inbound::finalize(&sender),
                };
                self.inbound_messages.get_or_create(&label).inc();

                // If the epoch is not the current epoch, block
                if message.epoch() != self.epoch {
                    commonware_p2p::block!(self.blocker, sender, "epoch mismatch");
                    continue;
                }

                // If the view isn't interesting, we can skip
                let view = message.view();
                if !interesting(self.activity_timeout, finalized, current.view, view, false) {
                    continue;
                }
                self.record_activity(&sender, view);

                // Add the vote to the verifier
                if work
                    .entry(view)
                    .or_insert_with(|| self.new_round(view))
                    .add_network(sender.clone(), message)
                {
                    self.added.inc();

                    // Update per-peer latest vote metric (only if higher than current)
                    let _ = self
                        .latest_vote
                        .get_or_create_by(&sender)
                        .try_set_max(view.get());

                    // If the current leader explicitly nullifies the current view, signal
                    // the voter so it can fast-path timeout without waiting for its local
                    // timer. We check after adding because duplicate votes are rejected.
                    if Self::leader_nullified(&current, &work) {
                        current.timed_out = true;
                        let round = Rnd::new(self.epoch, current.view);
                        let _guard = work
                            .get(&current.view)
                            .map(|round| round.span())
                            .unwrap_or_else(Span::none)
                            .entered();
                        voter.timeout(round, TimeoutReason::LeaderNullify);
                    }
                }
                updated_view = view;
            },
            on_end => {
                assert!(
                    updated_view != View::zero(),
                    "updated view must be greater than zero"
                );

                // Forward leader's proposal to voter (if we're not the leader and haven't already)
                if let Some(round) = work.get_mut(&current.view) {
                    if let Some(me) = self.scheme.me() {
                        if let Some(proposal) = round.forward_proposal(me) {
                            round.span().in_scope(|| voter.proposal(proposal));
                        }
                    }
                }

                // Skip verification and construction for views at or below finalized.
                //
                // We still use interesting() for filtering votes because we want to
                // notify the reporter of all votes within the activity timeout (even
                // if we don't need them in the voter).
                if updated_view <= finalized {
                    continue;
                }

                // Process the updated view (if any)
                let Some(round) = work.get_mut(&updated_view) else {
                    continue;
                };
                let span = round.span();
                async {
                    // Batch verify votes if ready
                    let timer = self.verify_latency.timer(self.context.as_ref());
                    let verified = if round.ready_notarizes() {
                        Some(round.verify_notarizes(self.context.as_mut(), &self.strategy).await)
                    } else if round.ready_nullifies() {
                        Some(round.verify_nullifies(self.context.as_mut(), &self.strategy).await)
                    } else if round.ready_finalizes() {
                        Some(round.verify_finalizes(self.context.as_mut(), &self.strategy).await)
                    } else {
                        None
                    };

                    // Process batch verification results
                    if let Some((batch, failed)) = verified {
                        timer.observe(self.context.as_ref());

                        // Process verified votes.
                        trace!(%updated_view, batch, "batch verified votes");
                        self.verified.inc_by(batch as u64);
                        self.batch_size.observe(batch as f64);

                        // Block invalid signers
                        for invalid in failed {
                            if let Some(signer) = self.scheme.participants().key(invalid) {
                                commonware_p2p::block!(
                                    self.blocker,
                                    signer.clone(),
                                    "invalid signature"
                                );
                            }
                        }
                    } else {
                        trace!(
                            current = %current.view,
                            %finalized,
                            "no verifier ready"
                        );
                    }

                    // Try to construct and forward certificates
                    if let Some(notarization) = self
                        .recover_latency
                        .time_some(
                            self.context.as_ref(),
                            round.try_construct_notarization(&self.strategy),
                        )
                        .await
                    {
                        debug!(%updated_view, "constructed notarization, forwarding to voter");

                        // Forward notarization to voter
                        voter.recovered(Certificate::Notarization(notarization));
                    }
                    if let Some(nullification) = self
                        .recover_latency
                        .time_some(
                            self.context.as_ref(),
                            round.try_construct_nullification(&self.strategy),
                        )
                        .await
                    {
                        debug!(%updated_view, "constructed nullification, forwarding to voter");
                        voter.recovered(Certificate::Nullification(nullification));
                    }
                    if let Some(finalization) = self
                        .recover_latency
                        .time_some(
                            self.context.as_ref(),
                            round.try_construct_finalization(&self.strategy),
                        )
                        .await
                    {
                        debug!(%updated_view, "constructed finalization, forwarding to voter");
                        voter.recovered(Certificate::Finalization(finalization));
                    }
                }
                .instrument(span)
                .await;

                // Drop any rounds that are no longer interesting
                while work.first_key_value().is_some_and(|(&view, _)| {
                    !interesting(self.activity_timeout, finalized, current.view, view, false)
                }) {
                    work.pop_first();
                }
            },
        }
    }
}
