use super::{
    Config, Mailbox,
    ingress::Message,
    state::{CertificateFetch, Config as StateConfig, State, Verify},
};
use crate::{
    CertifiableAutomaton, LATENCY, Relay, Reporter, Viewable,
    simplex::{
        Floor, Plan,
        actors::{Kind, batcher, resolver},
        elector::Elector,
        metrics::{self, Outbound, TimeoutReason},
        scheme::Scheme,
        types::{
            Activity, Artifact, Certificate, Context, Finalization, Finalize, Notarization,
            Notarize, Nullification, Nullify, Proposal, Vote,
        },
    },
    types::{Round as Rnd, View},
};
use commonware_actor::mailbox;
use commonware_codec::Read;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Recipients, Sender, utils::codec::WrappedSender};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, ReadOptions, Spawner, Storage,
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::{
        metrics::{CounterFamily, Histogram, MetricsExt as _},
        traces::TracedExt as _,
    },
};
use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
use commonware_utils::{
    channel::oneshot,
    futures::{AbortablePool, rebind},
};
use core::{future::Future, panic};
use rand_core::CryptoRng;
use std::{
    num::NonZeroUsize,
    pin::Pin,
    task::{self, Poll},
};
use tracing::{Instrument as _, Span, debug, info, info_span, trace, warn};

/// Tracks which certificate type was received from the resolver in the current iteration.
///
/// Used to prevent "boomerang" where we send a certificate back to the resolver
/// that we just received from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Resolved {
    #[default]
    None,
    Notarization,
    Nullification,
    Finalization,
}

/// Messages built and recorded during an event loop iteration, staged for
/// broadcast after the journal sync barrier (see [Actor::construct] and
/// [Actor::notify]).
#[allow(clippy::type_complexity)]
struct Staged<S: Scheme<D>, D: Digest> {
    nullify: Option<(Nullify<S>, Option<Certificate<S, D>>)>,
    certification: Option<(bool, Notarization<S, D>)>,
    notarize: Option<Notarize<S, D>>,
    notarization: Option<Notarization<S, D>>,
    nullification: Option<Nullification<S>>,
    finalize: Option<Finalize<S, D>>,
    finalization: Option<Finalization<S, D>>,
}

/// An outstanding request to the automaton.
struct Request<V: Viewable, R>(
    /// Attached context for the pending item. Must yield a view.
    V,
    /// Span tracking the request from issuance to processed response.
    Span,
    /// Oneshot receiver that the automaton is expected to respond over.
    oneshot::Receiver<R>,
);

impl<V: Viewable, R> Viewable for Request<V, R> {
    fn view(&self) -> View {
        self.0.view()
    }
}

/// Adapter that polls an [Option<Request<V, R>>] in place.
struct Waiter<'a, V: Viewable, R>(&'a mut Option<Request<V, R>>);

impl<'a, V: Viewable, R> Future for Waiter<'a, V, R> {
    type Output = (V, Span, Result<R, oneshot::error::RecvError>);

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let Waiter(slot) = self.get_mut();
        let res = match slot.as_mut() {
            Some(Request(_, _, receiver)) => match Pin::new(receiver).poll(cx) {
                Poll::Ready(res) => res,
                Poll::Pending => return Poll::Pending,
            },
            None => return Poll::Pending,
        };
        let Request(v, span, _) = slot.take().expect("request must exist");
        Poll::Ready((v, span, res))
    }
}

/// Actor responsible for driving participation in the consensus protocol.
pub struct Actor<
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Digest = D, Context = Context<D, S::PublicKey>>,
    R: Relay,
    F: Reporter<Activity = Activity<S, D>>,
> {
    context: ContextCell<E>,
    state: State<E, S, L, D>,
    blocker: B,
    automaton: A,
    relay: R,
    reporter: F,
    floor: Option<Floor<S, D>>,

    certificate_config: <S::Certificate as Read>::Cfg,
    partition: String,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    page_cache: CacheRef,
    journal: Option<Journal<E, Artifact<S, D>>>,
    dirty_section: Option<View>,

    mailbox_receiver: mailbox::Receiver<Message<S, D>>,

    outbound_messages: CounterFamily<Outbound>,
    notarization_latency: Histogram,
    finalization_latency: Histogram,
}

impl<
    E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme<D>,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: CertifiableAutomaton<Digest = D, Context = Context<D, S::PublicKey>>,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = Activity<S, D>>,
> Actor<E, S, L, B, D, A, R, F>
{
    pub fn new(context: E, cfg: Config<S, L, B, D, A, R, F>) -> (Self, Mailbox<S, D>) {
        // Initialize metrics
        let outbound_messages = context.family("outbound_messages", "number of outbound messages");
        let notarization_latency =
            context.histogram("notarization_latency", "notarization latency", LATENCY);
        let finalization_latency =
            context.histogram("finalization_latency", "finalization latency", LATENCY);

        // Initialize store
        let (mailbox_sender, mailbox_receiver) =
            mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        let mailbox = Mailbox::new(mailbox_sender);
        let certificate_config = cfg.scheme.certificate_codec_config();
        let state = State::new(
            context.child("state"),
            StateConfig {
                scheme: cfg.scheme,
                elector: cfg.elector,
                epoch: cfg.epoch,
                view_retention: cfg.view_retention,
                leader_timeout: cfg.leader_timeout,
                certification_timeout: cfg.certification_timeout,
                timeout_retry: cfg.timeout_retry,
                skip_budget: cfg.skip_budget,
            },
        );
        (
            Self {
                context: ContextCell::new(context),
                state,
                blocker: cfg.blocker,
                automaton: cfg.automaton,
                relay: cfg.relay,
                reporter: cfg.reporter,
                floor: Some(cfg.floor),

                certificate_config,
                partition: cfg.partition,
                replay_buffer: cfg.replay_buffer,
                write_buffer: cfg.write_buffer,
                page_cache: cfg.page_cache,
                journal: None,
                dirty_section: None,

                mailbox_receiver,

                outbound_messages,
                notarization_latency,
                finalization_latency,
            },
            mailbox,
        )
    }

    /// Returns the wall-clock seconds since we proposed in `view` (or entered
    /// it, when we led without a local proposal). None when we are not the
    /// view's leader or never started it (no meaningful sample).
    fn leader_elapsed(&self, view: View) -> Option<f64> {
        let elapsed = self.state.elapsed_since_start(view)?;
        let leader = self.state.leader_index(view)?;
        if !self.state.is_me(leader) {
            return None;
        }
        Some(elapsed.as_secs_f64())
    }

    /// Drops views and journal entries that are below the activity floor.
    async fn prune_views(mut self) -> Self {
        let removed = self.state.prune();
        if removed.is_empty() {
            return self;
        }
        for view in &removed {
            debug!(
                %view,
                last_finalized = %self.state.last_finalized(),
                "pruned view"
            );
        }
        let min_active = self.state.min_active();
        if self.journal.is_some() {
            let span = info_span!(
                "simplex.voter.journal.prune",
                epoch = self.state.epoch().traced(),
                min = min_active.traced()
            );
            rebind(&mut self.journal, |journal| {
                journal.prune(min_active.get()).instrument(span)
            })
            .await
            .expect("unable to prune journal");
        }
        self
    }

    /// Appends a verified message to the journal.
    ///
    /// The append is not immediately durable. All appends in an event loop
    /// iteration target the view being processed and are synced together by
    /// [Self::sync_journal].
    async fn append_journal(mut self, view: View, artifact: Artifact<S, D>) -> Self {
        if self.journal.is_some() {
            rebind(&mut self.journal, |journal| {
                journal.append(view.get(), &artifact)
            })
            .await
            .expect("unable to append to journal");
            match self.dirty_section {
                Some(dirty) => assert_eq!(
                    dirty, view,
                    "one voter iteration must append to a single journal section"
                ),
                None => self.dirty_section = Some(view),
            }
        }
        self
    }

    /// Syncs the journal section written by this iteration, if any.
    ///
    /// Called after construction and before publication so every appended artifact
    /// is durable by the end of the iteration. The next iteration cannot dispatch
    /// work made eligible here until this sync completes, so a durable child
    /// certification also implies its parent anchor is durable. A single sync
    /// coalesces all appends.
    async fn sync_journal(mut self) -> Self {
        let Some(view) = self.dirty_section else {
            return self;
        };
        let span = info_span!(
            "simplex.voter.journal.sync",
            epoch = self.state.epoch().traced(),
            view = view.traced()
        );
        rebind(&mut self.journal, |journal| {
            journal.sync(view.get()).instrument(span)
        })
        .await
        .expect("unable to sync journal");
        self.dirty_section = None;
        self
    }

    /// Publishes a durable local vote to the batcher and every peer.
    ///
    /// Callers must first sync pending journal appends. Otherwise a restart may
    /// forget the vote and sign a conflicting one, allowing conflicting certificates.
    fn publish_vote<T: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        sender: &mut WrappedSender<T, Vote<S, D>>,
        vote: Vote<S, D>,
    ) {
        // Every nullify retry refreshes volatile batcher state. The first retry after
        // replay may be the batcher's first copy of the vote.
        batcher.constructed(vote.clone());

        // Update outbound metrics
        let metric = match &vote {
            Vote::Notarize(_) => metrics::Outbound::notarize(),
            Vote::Nullify(_) => metrics::Outbound::nullify(),
            Vote::Finalize(_) => metrics::Outbound::finalize(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast vote
        sender.send(Recipients::All, vote, true);
    }

    /// Send a certificate to every peer.
    ///
    /// Callers must sync pending journal appends first (via [Self::sync_journal])
    /// so any state we advertise to the network survives a restart.
    fn broadcast_certificate<T: Sender>(
        &mut self,
        sender: &mut WrappedSender<T, Certificate<S, D>>,
        certificate: Certificate<S, D>,
    ) {
        // Update outbound metrics
        let metric = match &certificate {
            Certificate::Notarization(_) => metrics::Outbound::notarization(),
            Certificate::Nullification(_) => metrics::Outbound::nullification(),
            Certificate::Finalization(_) => metrics::Outbound::finalization(),
        };
        self.outbound_messages.get_or_create(metric).inc();

        // Broadcast certificate
        sender.send(Recipients::All, certificate, true);
    }

    /// Blocks an equivocator.
    fn block_equivocator(&mut self, equivocator: Option<S::PublicKey>) {
        let Some(equivocator) = equivocator else {
            return;
        };
        commonware_p2p::block!(self.blocker, equivocator, "blocking equivocator");
    }

    /// Attempt to propose a new block.
    #[allow(clippy::async_yields_async)]
    async fn try_propose(&mut self) -> Option<Request<Context<D, S::PublicKey>, D>> {
        // Check if we are ready to propose
        let context = self.state.try_propose()?;

        // Request proposal from application
        let span = info_span!(
            parent: self.state.view_span(context.view()),
            "simplex.voter.propose",
            epoch = context.round.epoch().traced(),
            view = context.view().traced()
        );
        let receiver = async {
            debug!(round = ?context.round, "requested proposal from automaton");
            self.automaton.propose(context.clone()).await
        }
        .instrument(span.clone())
        .await;
        Some(Request(context, span, receiver))
    }

    /// Attempt to verify a proposed block.
    #[allow(clippy::async_yields_async)]
    async fn try_verify(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
    ) -> Option<Request<Context<D, S::PublicKey>, bool>> {
        // Check if we are ready to verify
        let (context, proposal) = match self.state.try_verify() {
            Verify::Ready(context, proposal) => (context, proposal),
            Verify::Resolve {
                proposal,
                view,
                kind,
                target,
            } => {
                resolver.resolve(proposal, view, kind, Some(target));
                return None;
            }
            Verify::Wait => return None,
        };

        // Request verification
        let span = info_span!(
            parent: self.state.view_span(context.view()),
            "simplex.voter.verify",
            epoch = context.round.epoch().traced(),
            view = context.view().traced()
        );
        let receiver = async {
            debug!(?proposal, "requested proposal verification");
            self.automaton
                .verify(context.clone(), proposal.payload)
                .await
        }
        .instrument(span.clone())
        .await;
        Some(Request(context, span, receiver))
    }

    /// Drops pending application requests for exited views and dispatches
    /// eligible new ones.
    async fn reconcile_application_requests(
        &mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        pending_propose: &mut Option<Request<Context<D, S::PublicKey>, D>>,
        pending_verify: &mut Option<Request<Context<D, S::PublicKey>, bool>>,
    ) {
        // Keep requests for optimistic future views and clear requests for
        // exited views. Certification for an exited view can continue after
        // its verification receiver is dropped.
        let current_view = self.state.current_view();
        if pending_propose
            .as_ref()
            .is_some_and(|request| request.view() < current_view)
        {
            *pending_propose = None;
        }
        if pending_verify
            .as_ref()
            .is_some_and(|request| request.view() < current_view)
        {
            *pending_verify = None;
        }

        // State and Round prevent duplicate requests when both checkpoints
        // observe the same view.
        if pending_propose.is_none() {
            *pending_propose = self.try_propose().await;
        }
        if pending_verify.is_none() {
            *pending_verify = self.try_verify(resolver).await;
        }
    }

    /// Persists our nullify vote to the journal for crash recovery.
    async fn handle_nullify(self, nullify: Nullify<S>) -> Self {
        self.append_journal(nullify.view(), Artifact::Nullify(nullify))
            .await
    }

    /// Handle a timeout.
    ///
    /// Builds a nullify vote for the current view (as many times as required
    /// until we exit the view) and records it on the first attempt. Returns
    /// the vote for broadcast by [Self::notify], along with the best entry
    /// certificate for the current view (on retry) to help others enter it
    /// (see [State::get_best_certificate]).
    #[allow(clippy::type_complexity)]
    async fn timeout(
        mut self,
        reason: TimeoutReason,
    ) -> (Self, Option<(Nullify<S>, Option<Certificate<S, D>>)>) {
        // Construct a nullify vote for the current view
        let view = self.state.current_view();
        let Some((retry, nullify)) = self.state.construct_nullify(view, reason) else {
            return (self, None);
        };

        // Persist the nullify if it is a first attempt
        if !retry {
            self = self.handle_nullify(nullify.clone()).await;
            return (self, Some((nullify, None)));
        }

        // Include entry to help others enter the view (if on retry).
        //
        // We don't worry about recording this certificate because it must've already existed (and thus
        // we must've already broadcast and persisted it).
        let entry = self.state.get_best_certificate();
        (self, Some((nullify, entry)))
    }

    /// Tracks a verified nullification certificate if it is new.
    async fn handle_nullification(mut self, nullification: Nullification<S>) -> Self {
        let view = nullification.view();
        let artifact = Artifact::Nullification(nullification.clone());

        // Add verified nullification to journal
        if !self.state.add_nullification(nullification) {
            return self;
        }
        self.append_journal(view, artifact).await
    }

    /// Persists our notarize vote to the journal for crash recovery.
    async fn handle_notarize(self, notarize: Notarize<S, D>) -> Self {
        self.append_journal(notarize.view(), Artifact::Notarize(notarize))
            .await
    }

    /// Records a notarization certificate and blocks any equivocating leader.
    async fn handle_notarization(mut self, notarization: Notarization<S, D>) -> Self {
        let view = notarization.view();
        let artifact = Artifact::Notarization(notarization.clone());
        let (added, equivocator) = self.state.add_notarization(notarization);
        if added {
            self = self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator);
        self
    }

    /// Handles the certification of a proposal.
    ///
    /// If certification succeeds, the proposal can be used in future views. If it fails, we
    /// should nullify the view as fast as possible.
    async fn handle_certification(
        mut self,
        view: View,
        success: bool,
    ) -> (Self, Option<Notarization<S, D>>) {
        // Get the notarization before advancing state
        let Some(notarization) = self.state.certified(view, success) else {
            return (self, None);
        };

        // Record the certification result for recovery. It is synced before this
        // iteration's broadcast phase. If lost to a crash before then, certification
        // is re-requested on restart.
        let artifact = Artifact::Certification(Rnd::new(self.state.epoch(), view), success);
        self = self.append_journal(view, artifact).await;

        (self, Some(notarization))
    }

    /// Persists our finalize vote to the journal for crash recovery.
    async fn handle_finalize(self, finalize: Finalize<S, D>) -> Self {
        self.append_journal(finalize.view(), Artifact::Finalize(finalize))
            .await
    }

    /// Stores a finalization certificate and guards against leader equivocation.
    ///
    /// The finalization is appended to the journal without an immediate sync.
    /// If a crash loses a finalization that healed the same-term finalize
    /// gate, replay restores the blocked gate (which is safe) and it heals
    /// again as soon as peers redeliver any covering finalization.
    async fn handle_finalization(mut self, finalization: Finalization<S, D>) -> Self {
        let view = finalization.view();
        let artifact = Artifact::Finalization(finalization.clone());
        let (added, equivocator) = self.state.add_finalization(finalization);
        if added {
            self = self.append_journal(view, artifact).await;
        }
        self.block_equivocator(equivocator);
        self
    }

    /// Builds and records a notarize vote when this view is ready.
    async fn prepare_notarize(mut self, view: View) -> (Self, Option<Notarize<S, D>>) {
        // Construct a notarize vote
        let Some(notarize) = self.state.construct_notarize(view) else {
            return (self, None);
        };

        // Record the vote locally before sharing it.
        self = self.handle_notarize(notarize.clone()).await;
        (self, Some(notarize))
    }

    /// Builds and records a notarization certificate once we can assemble it locally.
    async fn prepare_notarization(
        mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        view: View,
        resolved: Resolved,
    ) -> (Self, Option<Notarization<S, D>>) {
        // Construct a notarization certificate
        let Some(notarization) = self.state.broadcast_notarization(view) else {
            return (self, None);
        };

        // Only the leader sees an unbiased latency sample, so record it now.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.notarization_latency.observe(elapsed);
        }

        // Tell the resolver this view is complete so it can stop requesting it.
        // For a certificate from the batcher, this update is enqueued before
        // the next loop iteration can emit any targeted ancestry repair it
        // exposes. The resolver's unrestricted backfill therefore cannot be
        // narrowed by that later target. Skip if the resolver just sent us
        // this certificate (avoid boomerang).
        if resolved != Resolved::Notarization {
            resolver.updated(Certificate::Notarization(notarization.clone()));
        }
        // Update our local round with the certificate.
        self = self.handle_notarization(notarization.clone()).await;
        (self, Some(notarization))
    }

    /// Builds and records a nullification certificate if the round provides a candidate.
    async fn prepare_nullification(
        mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        view: View,
        resolved: Resolved,
    ) -> (Self, Option<Nullification<S>>) {
        // Construct the nullification certificate.
        let Some(nullification) = self.state.broadcast_nullification(view) else {
            return (self, None);
        };

        // Notify resolver so dependent parents can progress.
        // Skip if the resolver just sent us this certificate (avoid boomerang).
        if resolved != Resolved::Nullification {
            resolver.updated(Certificate::Nullification(nullification.clone()));
        }
        // Track the certificate locally to avoid rebuilding it.
        self = self.handle_nullification(nullification.clone()).await;
        (self, Some(nullification))
    }

    /// Builds and records a finalize vote if the round provides a candidate.
    async fn prepare_finalize(mut self, view: View) -> (Self, Option<Finalize<S, D>>) {
        // Construct the finalize vote.
        let Some(finalize) = self.state.construct_finalize(view) else {
            return (self, None);
        };

        // Record the vote locally before sharing it.
        self = self.handle_finalize(finalize.clone()).await;
        (self, Some(finalize))
    }

    /// Builds and records a finalization certificate if the round provides a candidate.
    async fn prepare_finalization(
        mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        view: View,
        resolved: Resolved,
    ) -> (Self, Option<Finalization<S, D>>) {
        // Construct the finalization certificate.
        let Some(finalization) = self.state.broadcast_finalization(view) else {
            return (self, None);
        };

        // Only record latency if we are the current leader.
        if let Some(elapsed) = self.leader_elapsed(view) {
            self.finalization_latency.observe(elapsed);
        }

        // Tell the resolver this view is complete so it can stop requesting it.
        // Skip if the resolver just sent us this certificate (avoid boomerang).
        if resolved != Resolved::Finalization {
            resolver.updated(Certificate::Finalization(finalization.clone()));
        }
        // Advance the consensus core with the finalization proof.
        self = self.handle_finalization(finalization.clone()).await;
        (self, Some(finalization))
    }

    /// Processes the automaton's response to a proposal request.
    ///
    /// Returns the view to notify if the proposal was recorded.
    fn process_proposed(
        &mut self,
        context: Context<D, S::PublicKey>,
        proposed: Result<D, oneshot::error::RecvError>,
    ) -> Option<View> {
        // Try to use result
        let proposed = match proposed {
            Ok(proposed) => proposed,
            Err(err) => {
                debug!(?err, round = ?context.round, "failed to propose container");
                self.state
                    .trigger_timeout(context.view(), TimeoutReason::MissingProposal);
                return None;
            }
        };

        // If we have already moved past this view, drop the response as we
        // will not broadcast it. Proposals for the current or optimistic
        // future views are kept.
        if context.view() < self.state.current_view() {
            debug!(round = ?context.round, current = ?self.state.current_view(), "dropping requested proposal");
            return None;
        }

        // Construct proposal
        let proposal = Proposal::new(context.round, context.parent.0, proposed);
        if !self.state.proposed(proposal) {
            warn!(round = ?context.round, "dropped our proposal");
            return None;
        }
        let view = context.view();

        // Notify the application of the proposal. To lower view latency as
        // much as possible while preserving safety, this precedes the notarize
        // vote's journal sync: unlike votes (which can form a conflicting
        // certificate), extra payload bytes are harmless, and the worst a
        // crash can do is relay a different payload for the same round after
        // restart (see [Plan::Propose]).
        let _ = self.relay.broadcast(
            proposed,
            Plan::Propose {
                round: context.round,
            },
        );
        Some(view)
    }

    /// Processes the automaton's response to a verification request.
    ///
    /// Returns the view to notify.
    fn process_verified(
        &mut self,
        context: Context<D, S::PublicKey>,
        verified: Result<bool, oneshot::error::RecvError>,
    ) -> View {
        let view = context.view();
        match verified {
            Ok(true) => {
                // Mark verification complete
                self.state.verified(view);
            }
            Ok(false) => {
                warn!(round = ?context.round, "proposal failed verification");
                self.state
                    .verification_failed(view, TimeoutReason::InvalidProposal);
            }
            Err(err) => {
                debug!(?err, round = ?context.round, "failed to verify proposal");
                self.state
                    .verification_failed(view, TimeoutReason::IgnoredProposal);
            }
        };
        view
    }

    /// Processes the automaton's response to a certification request.
    ///
    /// Returns whether the round was still active (false if it was already
    /// pruned) and, if the result was recorded, the certification outcome to
    /// stage for [Self::notify].
    #[allow(clippy::type_complexity)]
    async fn process_certified(
        mut self,
        round: Rnd,
        certified: Result<bool, oneshot::error::RecvError>,
    ) -> (Self, bool, Option<(bool, Notarization<S, D>)>) {
        // Unlike propose/verify (where failing to act will lead to a timeout
        // and subsequent nullification), failing to certify can lead to a halt
        // because we'll never exit the view without a notarization + certification.
        //
        // We do not assume failure here because we recover on restart: a synced
        // certification result is replayed from the journal and a missing one
        // causes certification to be re-requested.
        let certified = match certified {
            Ok(certified) => certified,
            Err(err) => {
                debug!(?err, ?round, "failed to certify proposal");
                return (self, true, None);
            }
        };
        if !certified {
            warn!(?round, "proposal failed certification");
        }
        let notarization;
        (self, notarization) = self.handle_certification(round.view(), certified).await;
        let Some(notarization) = notarization else {
            return (self, false, None);
        };
        (self, true, Some((certified, notarization)))
    }

    /// Processes a message from the resolver or batcher.
    ///
    /// Returns the view to notify and whether the message was a certificate
    /// from the resolver.
    async fn process_message(mut self, msg: Message<S, D>) -> (Self, Option<(View, Resolved)>) {
        match msg {
            Message::Proposal { proposal, .. } => {
                let view = proposal.view();
                if !self.state.admits_vote(view) {
                    trace!(%view, "proposal outside viewport");
                    return (self, None);
                }
                trace!(%view, "received proposal");
                if !self.state.set_proposal(view, proposal) {
                    return (self, None);
                }
                (self, Some((view, Resolved::None)))
            }
            Message::Verified {
                certificate,
                from_resolver,
                ..
            } => {
                // Certificates can come from future views (they advance our view)
                let view = certificate.view();
                if !self.state.admits_certificate(view) {
                    trace!(%view, "certificate outside viewport");
                    return (self, None);
                }

                // Track resolved status to avoid sending back to resolver
                let mut resolved = Resolved::None;
                match certificate {
                    Certificate::Notarization(notarization) => {
                        trace!(%view, from_resolver, "received notarization");
                        self = self.handle_notarization(notarization).await;
                        if from_resolver {
                            resolved = Resolved::Notarization;
                        }
                    }
                    Certificate::Nullification(nullification) => {
                        trace!(%view, from_resolver, "received nullification");
                        self = self.handle_nullification(nullification).await;
                        if from_resolver {
                            resolved = Resolved::Nullification;
                        }
                    }
                    Certificate::Finalization(finalization) => {
                        trace!(%view, from_resolver, "received finalization");
                        self = self.handle_finalization(finalization).await;
                        if from_resolver {
                            resolved = Resolved::Finalization;
                        }
                    }
                }
                (self, Some((view, resolved)))
            }
            Message::Timeout { round, reason, .. } => {
                let view = round.view();
                debug!(%view, ?reason, "timing out view");
                self.state.trigger_timeout(view, reason);
                (self, Some((view, Resolved::None)))
            }
        }
    }

    /// Builds and records any votes or certificates that became available for `view`.
    ///
    /// Returned artifacts must be synced through [Self::sync_journal] before
    /// [Self::notify] publishes them.
    ///
    /// We don't need to iterate over all views to check for new actions because messages we receive
    /// only affect a single view. In particular, healing the same-term finalize gate does not
    /// proactively retry finalize votes for views certified while the gate was blocked: such a view
    /// only emits its vote if a later message touches it again (see the module documentation on
    /// same-term vote safety for the consequences when none arrives).
    async fn construct(
        mut self,
        resolver: &mut resolver::Mailbox<S, D>,
        view: View,
        resolved: Resolved,
    ) -> (Self, Staged<S, D>) {
        let (notarize, notarization, nullification, finalize, finalization);
        (self, notarize) = self.prepare_notarize(view).await;
        (self, notarization) = self.prepare_notarization(resolver, view, resolved).await;
        (self, nullification) = self.prepare_nullification(resolver, view, resolved).await;
        (self, finalize) = self.prepare_finalize(view).await;
        (self, finalization) = self.prepare_finalization(resolver, view, resolved).await;
        (
            self,
            Staged {
                nullify: None,
                certification: None,
                notarize,
                notarization,
                nullification,
                finalize,
                finalization,
            },
        )
    }

    /// Publishes the staged votes and certificates.
    ///
    /// Callers must first sync pending journal appends so locally constructed votes
    /// are durable before reaching the batcher, reporter, or network.
    fn notify<Sp: Sender, Sr: Sender>(
        &mut self,
        batcher: &mut batcher::Mailbox<S, D>,
        resolver: &mut resolver::Mailbox<S, D>,
        vote_sender: &mut WrappedSender<Sp, Vote<S, D>>,
        certificate_sender: &mut WrappedSender<Sr, Certificate<S, D>>,
        staged: Staged<S, D>,
    ) {
        assert!(
            self.dirty_section.is_none(),
            "journal must be synced before broadcast"
        );

        if let Some((certified, notarization)) = staged.certification {
            // Always forward certification outcomes to resolver. This can happen
            // after a nullification for the same view because certification is
            // asynchronous; finalization is the boundary that cancels in-flight
            // certification and suppresses late reporting.
            resolver.certified(notarization.view(), certified);
            if certified {
                self.reporter.report(Activity::Certification(notarization));
            }
        }

        if let Some((nullify, entry)) = staged.nullify {
            debug!(round=?nullify.round(), "broadcasting nullify");
            self.publish_vote(batcher, vote_sender, Vote::Nullify(nullify));

            // Broadcast entry to help others enter the view (if on retry).
            if let Some(entry) = entry {
                self.broadcast_certificate(certificate_sender, entry);
            }
        }
        if let Some(notarize) = staged.notarize {
            debug!(proposal=?notarize.proposal, "broadcasting notarize");
            self.publish_vote(batcher, vote_sender, Vote::Notarize(notarize));
        }
        if let Some(notarization) = staged.notarization {
            debug!(proposal=?notarization.proposal, "broadcasting notarization");
            self.broadcast_certificate(
                certificate_sender,
                Certificate::Notarization(notarization.clone()),
            );
            self.reporter.report(Activity::Notarization(notarization));
        }
        if let Some(nullification) = staged.nullification {
            debug!(round=?nullification.round(), "broadcasting nullification");
            self.broadcast_certificate(
                certificate_sender,
                Certificate::Nullification(nullification.clone()),
            );
            self.reporter.report(Activity::Nullification(nullification));
        }
        if let Some(finalize) = staged.finalize {
            debug!(proposal=?finalize.proposal, "broadcasting finalize");
            self.publish_vote(batcher, vote_sender, Vote::Finalize(finalize));
        }
        if let Some(finalization) = staged.finalization {
            debug!(proposal=?finalization.proposal, "broadcasting finalization");
            self.broadcast_certificate(
                certificate_sender,
                Certificate::Finalization(finalization.clone()),
            );
            self.reporter.report(Activity::Finalization(finalization));
        }
    }

    /// Spawns the actor event loop with the provided channels.
    pub fn start(
        mut self,
        batcher: batcher::Mailbox<S, D>,
        resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(batcher, resolver, vote_sender, certificate_sender)
        )
    }

    /// Core event loop that drives proposal, voting, networking, and recovery.
    async fn run(
        mut self,
        mut batcher: batcher::Mailbox<S, D>,
        mut resolver: resolver::Mailbox<S, D>,
        vote_sender: impl Sender<PublicKey = S::PublicKey>,
        certificate_sender: impl Sender<PublicKey = S::PublicKey>,
    ) {
        // Wrap channels
        let pool = self.context.network_buffer_pool();
        let mut vote_sender = WrappedSender::new(pool.clone(), vote_sender);
        let mut certificate_sender = WrappedSender::new(pool.clone(), certificate_sender);

        // Initialize journal
        let journal = Journal::<_, Artifact<S, D>>::init(
            self.context.child("journal"),
            JConfig {
                partition: self.partition.clone(),
                compression: None, // most of the data is not compressible
                codec_config: self.certificate_config.clone(),
                page_cache: self.page_cache.clone(),
                write_buffer: self.write_buffer,
            },
        )
        .await
        .expect("unable to open journal");

        // Add initial view from the configured floor. Replay skips all
        // artifacts at or below the floor's view (see the nullify-skip
        // rationale in the replay loop below).
        let floor = self.floor.take().expect("floor not initialized");
        let replay_floor = floor.view();

        // Anchor all startup work under a single root span. The floor
        // finalization and journal replay both run here before any view span
        // exists, so without this root their work would emit as orphan traces.
        let start = self.context.current();
        let epoch = self.state.epoch();
        let start_span = info_span!("simplex.voter.start", epoch = epoch.traced());

        // Apply the configured floor, forwarding and reporting any finalization.
        start_span.in_scope(|| {
            if let Some(finalization) = self.state.set_floor(floor) {
                let report = finalization.clone();
                resolver.updated(Certificate::Finalization(finalization));
                self.reporter.report(Activity::Finalization(report));
            }
        });

        // Rebuild from journal, nested under the startup span.
        // Replayed artifacts become in-memory state, so journal pages need not
        // remain in the OS page cache.
        let replayed;
        (self, replayed) = async {
            let mut replay = journal
                .replay(0, 0, self.replay_buffer, ReadOptions::DONT_CACHE)
                .await
                .expect("unable to replay journal");
            while let Some(artifact) = replay.next().await {
                // Dropping our own nullify votes at or below the floor is safe
                // for the same-term finalize gate: the floor finalization
                // covers any such vote (it lies between the vote and any later
                // same-term view), so the gate would treat it as healed anyway.
                // If the gate ever stops keying off last_finalized, this skip
                // must be revisited.
                let (_, _, _, artifact) = artifact.expect("unable to replay journal");
                if artifact.view() <= replay_floor {
                    continue;
                }

                self.state.replay(&artifact);
                match artifact {
                    Artifact::Notarize(notarize) => {
                        self = self.handle_notarize(notarize.clone()).await;
                        self.reporter.report(Activity::Notarize(notarize));
                    }
                    Artifact::Notarization(notarization) => {
                        self = self.handle_notarization(notarization.clone()).await;
                        resolver.updated(Certificate::Notarization(notarization.clone()));
                        self.reporter.report(Activity::Notarization(notarization));
                    }
                    Artifact::Certification(round, success) => {
                        let notarization;
                        (self, notarization) =
                            self.handle_certification(round.view(), success).await;
                        let Some(notarization) = notarization else {
                            continue;
                        };
                        resolver.certified(round.view(), success);
                        if success {
                            self.reporter.report(Activity::Certification(notarization));
                        }
                    }
                    Artifact::Nullify(nullify) => {
                        self = self.handle_nullify(nullify.clone()).await;
                        self.reporter.report(Activity::Nullify(nullify));
                    }
                    Artifact::Nullification(nullification) => {
                        self = self.handle_nullification(nullification.clone()).await;
                        resolver.updated(Certificate::Nullification(nullification.clone()));
                        self.reporter.report(Activity::Nullification(nullification));
                    }
                    Artifact::Finalize(finalize) => {
                        self = self.handle_finalize(finalize.clone()).await;
                        self.reporter.report(Activity::Finalize(finalize));
                    }
                    Artifact::Finalization(finalization) => {
                        self = self.handle_finalization(finalization.clone()).await;
                        resolver.updated(Certificate::Finalization(finalization.clone()));
                        self.reporter.report(Activity::Finalization(finalization));
                    }
                }

                // We deliberately avoid re-seeding the batcher with our
                // own votes (or the votes of other peers) on replay. We assume that
                // whatever view we were in during shutdown is no longer the latest
                // and we'll quickly jump ahead to a new view.
                //
                // If this is not the case (cluster-wide shutdown), we will recover
                // when timing out.
            }
            (self, replay.finish().expect("unable to replay journal"))
        }
        .instrument(info_span!(parent: &start_span, "simplex.voter.replay", epoch = epoch.traced()))
        .await;
        self.journal = Some(replayed);

        // Log current view after recovery
        let end = self.context.current();
        let elapsed = end.duration_since(start).unwrap_or_default();
        let observed_view = self.state.current_view();
        info!(
            %observed_view,
            ?elapsed,
            "consensus initialized"
        );

        // Initialize batcher with leader for current view
        let leader = self
            .state
            .leader_index(observed_view)
            .expect("leader not set");
        let (span, finalized) = self.state.batcher_context(observed_view);
        batcher.update(span, observed_view, leader, finalized, None);

        // Process messages
        let mut pending_propose: Option<Request<Context<D, S::PublicKey>, D>> = None;
        let mut pending_verify: Option<Request<Context<D, S::PublicKey>, bool>> = None;
        let mut certify_pool = AbortablePool::default();
        select_loop! {
            self.context,
            on_start => {
                // Reconcile application requests before building this iteration's
                // response waiters.
                self.reconcile_application_requests(
                    &mut resolver,
                    &mut pending_propose,
                    &mut pending_verify,
                ).await;

                // Attempt to certify any views that we have notarizations for.
                //
                // Even our own proposals are certified through the automaton: that
                // is the durability barrier that makes a block recoverable before
                // we cast a finalize vote for it. Because the prior iteration's
                // journal sync completed before this block runs, a child made
                // eligible by its parent cannot become durable first.
                let (candidates, fetches) = self.state.certify_candidates();
                for CertificateFetch { proposal, view } in fetches {
                    resolver.resolve(proposal, view, Kind::Notarization, None);
                }
                for proposal in candidates {
                    let round = proposal.round;
                    let view = round.view();
                    debug!(%view, "attempting certification");
                    let span = info_span!(
                        parent: self.state.view_span(view),
                        "simplex.voter.certify",
                        epoch = round.epoch().traced(),
                        view = view.traced()
                    );
                    #[allow(clippy::async_yields_async)]
                    let receiver = async { self.automaton.certify(round, proposal.payload).await }
                        .instrument(span.clone())
                        .await;
                    let handle = certify_pool.push(async move { (round, span, receiver.await) });
                    self.state.set_certify_handle(view, handle);
                }

                // Prune views below the activity floor. To lower view latency,
                // this runs after the automaton dispatches above so pruning
                // overlaps proposal building and verification instead of
                // delaying them.
                self = self.prune_views().await;

                // Prepare waiters
                let propose_wait = Waiter(&mut pending_propose);
                let verify_wait = Waiter(&mut pending_verify);
                let certify_wait = certify_pool.next_completed();

                // Wait for a timeout to fire or for a message to arrive
                let (deadline, reason) = self.state.next_timeout();
                let start = self.state.current_view();
                let mut resolved = Resolved::None;
                let mut nullify = None;
                let mut certification = None;
                let view;
            },
            on_stopped => {
                debug!("context shutdown, stopping voter");
            },
            _ = self.context.sleep_until(deadline) => {
                // Process the timeout (the constructed nullify is staged for the broadcast phase)
                let current_view = self.state.current_view();
                let span = info_span!(
                    parent: self.state.view_span(current_view),
                    "simplex.voter.timeout",
                    epoch = self.state.epoch().traced(),
                    view = current_view.traced(),
                    reason = reason.as_str()
                );
                (self, nullify) = self.timeout(reason).instrument(span).await;
                view = self.state.current_view();
            },
            (context, span, proposed) = propose_wait => {
                // Clear propose waiter
                pending_propose = None;

                // Process the automaton's response
                let Some(proposed_view) =
                    span.in_scope(|| self.process_proposed(context, proposed))
                else {
                    continue;
                };
                view = proposed_view;
            },
            (context, span, verified) = verify_wait => {
                // Clear verify waiter
                pending_verify = None;

                // Process the automaton's response
                view = span.in_scope(|| self.process_verified(context, verified));
            },
            // Aborted futures are expected when old views are pruned
            Ok((round, span, certified)) = certify_wait else continue => {
                // Handle response to our certification request.
                view = round.view();
                let (processed, certification_result);
                (self, processed, certification_result) = self
                    .process_certified(round, certified)
                    .instrument(span)
                    .await;
                if !processed {
                    continue;
                }
                certification = certification_result;
            },
            Some(msg) = self.mailbox_receiver.recv() else break => {
                // Handle messages from resolver and batcher
                let span = info_span!(
                    parent: msg.span(),
                    "simplex.voter.process",
                    operation = msg.name(),
                    epoch = self.state.epoch().traced(),
                    view = msg.view().traced()
                );
                let processed;
                (self, processed) = self.process_message(msg).instrument(span).await;
                let Some((processed_view, processed_resolved)) = processed else {
                    continue;
                };
                view = processed_view;
                resolved = processed_resolved;
            },
            on_end => {
                // Attempt to send any new view messages
                //
                // The batcher may drop votes we construct here if it has not yet been updated to the
                // message's view. This only happens when we skip ahead multiple views, which always
                // coincides with entering a new view (triggering a batcher update below before we send
                // any votes for the new current view). This has no impact on liveness, however, we may miss
                // building a finalization for an old view where we otherwise could have contributed.
                let span = info_span!(
                    parent: self.state.view_span(view),
                    "simplex.voter.notify",
                    epoch = self.state.epoch().traced(),
                    view = view.traced()
                );
                self = async {
                    // Build and record everything that became available for `view`.
                    let mut staged;
                    (self, staged) = self
                        .construct(&mut resolver, view, resolved)
                        .await;
                    staged.nullify = nullify;
                    staged.certification = certification;

                    // A constructed notarize advances the optimistic frontier and
                    // can make child requests eligible. Start those requests before
                    // journal sync and publication. The next iteration polls their
                    // responses.
                    self.reconcile_application_requests(
                        &mut resolver,
                        &mut pending_propose,
                        &mut pending_verify,
                    ).await;

                    // Sync everything appended this iteration (during message
                    // processing and construction) in a single coalesced sync.
                    // This runs even if there is nothing to broadcast (e.g. a
                    // certification result was recorded) so every artifact is
                    // durable by the end of the iteration that appended it.
                    self = self.sync_journal().await;

                    // Broadcast everything we built (and report it to the application).
                    self.notify(
                        &mut batcher,
                        &mut resolver,
                        &mut vote_sender,
                        &mut certificate_sender,
                        staged,
                    );
                    self
                }
                .instrument(span)
                .await;

                // Close the root span of any view the chain has now decided.
                // This runs after notify so the finalization broadcast and the
                // report into the application still nest under the view span.
                self.state.close_decided_spans();

                // Update the batcher if we have moved to a new view
                let current_view = self.state.current_view();
                if current_view > start {
                    let leader = self
                        .state
                        .leader_index(current_view)
                        .expect("leader not set");

                    // Forward only the previous view's proposal. After a
                    // multi-view jump, the network has moved past anything older.
                    let forwardable_proposal = current_view
                        .previous()
                        .and_then(|view| self.state.forwardable_proposal(view));

                    // If the leader nullified or is inactive, the batcher
                    // responds with a timeout that expires the view immediately
                    let (span, finalized) = self.state.batcher_context(current_view);
                    batcher.update(span, current_view, leader, finalized, forwardable_proposal);
                }
            },
        }

        // Sync and drop the journal
        self.journal
            .take()
            .expect("journal missing on voter exit")
            .sync_all()
            .await
            .expect("unable to sync journal");
    }
}
