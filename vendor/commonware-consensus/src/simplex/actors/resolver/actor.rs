use super::{
    super::{Ask, Kind, Until},
    Config,
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::{Effect, FetchReason},
};
use crate::{
    Epochable, Viewable,
    simplex::{
        actors::{resolver::state::State, voter},
        scheme::Scheme,
        types::Certificate,
    },
    types::{Epoch, View},
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Fetch, Outcome, Resolver, TargetedResolver, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    channel::fallible::OneshotExt, ordered::Quorum, sequence::U64, vec::NonEmptyVec,
};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    time::Duration,
};
use tracing::{debug, info_span};

/// Requests are made concurrently to multiple peers.
pub struct Actor<
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
> {
    context: ContextCell<E>,
    scheme: S,
    blocker: Option<B>,
    strategy: T,

    epoch: Epoch,
    mailbox_size: NonZeroUsize,
    fetch_timeout: Duration,

    /// Certificates known between the floor and the current view. Serves
    /// [HandlerMessage::Produce] requests and emits the [Effect]s the actor
    /// applies to the resolver (see [Self::apply_effects]).
    state: State<S, D>,

    /// Encoded nullifications retained while they cover an unfinalized view.
    /// This cache survives floor raises so asks below the floor remain servable.
    nullifications: BTreeMap<View, Bytes>,

    /// Encoded notarizations awaiting certification. They settle exact-parent
    /// fetches but are not served until certification succeeds.
    pending_notarizations: BTreeMap<View, Bytes>,

    /// Encoded certified notarizations retained until finalization. This cache
    /// survives floor raises so exact parents remain servable.
    certified_notarizations: BTreeMap<View, Bytes>,

    /// Views whose notarization is permanently uncertifiable, retained until
    /// finalization.
    ///
    /// [State] prunes these views at the floor, so these tombstones preserve the
    /// verdict for delayed exact-parent asks.
    uncertifiable_notarizations: BTreeSet<View>,

    mailbox_receiver: mailbox::Receiver<MailboxMessage<S, D>>,
}

impl<
    E: BufferPooler + Clock + CryptoRng + Metrics + Spawner,
    S: Scheme<D>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    T: Strategy,
> Actor<E, S, B, D, T>
{
    pub fn new(context: E, cfg: Config<S, B, T>) -> (Self, Mailbox<S, D>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), cfg.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                scheme: cfg.scheme,
                blocker: Some(cfg.blocker),
                strategy: cfg.strategy,

                epoch: cfg.epoch,
                mailbox_size: cfg.mailbox_size,
                fetch_timeout: cfg.fetch_timeout,

                state: State::new(cfg.term_length),
                nullifications: BTreeMap::new(),
                pending_notarizations: BTreeMap::new(),
                certified_notarizations: BTreeMap::new(),
                uncertifiable_notarizations: BTreeSet::new(),

                mailbox_receiver: receiver,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, sender, receiver))
    }

    async fn run(
        mut self,
        mut voter: voter::Mailbox<S, D>,
        sender: impl Sender<PublicKey = S::PublicKey>,
        receiver: impl Receiver<PublicKey = S::PublicKey>,
    ) {
        let participants = self.scheme.participants().clone();
        let me = self
            .scheme
            .me()
            .and_then(|index| participants.key(index))
            .cloned();

        let (handler_tx, mut handler_rx) =
            mailbox::new(self.context.as_ref().child("handler"), self.mailbox_size);
        let handler = Handler::new(handler_tx);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.child("resolver"),
            p2p::Config {
                peer_provider: StaticProvider::new(self.epoch.get(), participants),
                blocker: self.blocker.take().expect("blocker must be set"),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                me,
                timeout: self.fetch_timeout,
                fetch_retry_timeout: self.fetch_timeout,
                priority_requests: true,
                priority_responses: false,
            },
        );
        let mut resolver_task = resolver_engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut resolver_task => {
                break;
            },
            // It is possible that a voter proposes some block before the certificate(s) that back
            // it reach the resolver, allowing an external request to arrive in the meantime. We
            // accept this unlikely race, which requires the resolver to lag well behind the voter,
            // rather than block broadcast on an acknowledgment here.
            Some(message) = self.mailbox_receiver.recv() else break => {
                let span = info_span!(
                    parent: message.span(),
                    "simplex.resolver.process",
                    operation = message.name(),
                    epoch = self.epoch.traced(),
                    view = message.view().traced()
                );
                let _guard = span.entered();
                match message {
                    MailboxMessage::Certificate { certificate, .. } => {
                        self.updated(&mut resolver, certificate);
                    }
                    MailboxMessage::Certified { view, success, .. } => {
                        self.certified(&mut resolver, view, success);
                    }
                    MailboxMessage::Resolve {
                        proposal,
                        view,
                        kind,
                        target,
                        ..
                    } => {
                        self.resolve(&mut resolver, proposal, view, kind, target);
                    }
                }
            },
            Some(message) = handler_rx.recv() else break => {
                if message.response_closed() {
                    continue;
                }
                self.handle_resolver(message, &mut voter, &mut resolver);
            },
        }
    }

    /// Returns the highest finalized view, or zero if none is known.
    fn last_finalized(&self) -> View {
        self.state
            .finalization()
            .map_or(View::zero(), |certificate| certificate.view())
    }

    /// Records a certificate and applies its resolver lifecycle effects.
    fn updated<R: Resolver<Key = U64, Subscriber = Ask>>(
        &mut self,
        resolver: &mut R,
        certificate: Certificate<S, D>,
    ) {
        let term_length = self.state.term_length();
        let last_finalized = self.last_finalized();

        // Retain encoded certificates for as long as a peer can still ask for them.
        // [State] prunes at the floor, which rises sooner than finalization and
        // would hide this evidence from a peer still repairing the view.
        match &certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if view.term_end(term_length) > last_finalized {
                    self.nullifications.insert(view, certificate.encode());
                    let covered = view..=view.term_end(term_length);
                    Self::retire(resolver, move |view, ask| {
                        ask.kind == Kind::Nullification && covered.contains(&view)
                    });
                }
            }
            Certificate::Notarization(notarization) => {
                let view = notarization.view();
                if view > last_finalized && !self.uncertifiable_notarizations.contains(&view) {
                    if !self.certified_notarizations.contains_key(&view) {
                        self.pending_notarizations
                            .insert(view, certificate.encode());
                    }
                    Self::retire(resolver, move |asked, ask| {
                        ask.kind == Kind::Notarization && asked == view
                    });
                }
            }
            Certificate::Finalization(finalization) => {
                // Finalization is the global retirement boundary: a valid proposal
                // can no longer name ancestry at or below it, so nothing here can
                // still be asked for.
                let finalized = last_finalized.max(finalization.view());
                self.nullifications
                    .retain(|view, _| view.term_end(term_length) > finalized);
                self.pending_notarizations
                    .retain(|view, _| *view > finalized);
                self.certified_notarizations
                    .retain(|view, _| *view > finalized);
                self.uncertifiable_notarizations
                    .retain(|view| *view > finalized);
                Self::retire(resolver, move |view, _| view <= finalized);
            }
        }

        // Certificate state owns floor selection and background repair.
        let effects = self.state.handle(certificate);
        self.apply_effects(resolver, effects);
    }

    /// Handles a certification outcome from the voter.
    fn certified<R: Resolver<Key = U64, Subscriber = Ask>>(
        &mut self,
        resolver: &mut R,
        view: View,
        success: bool,
    ) {
        // Every verdict clears the pending payload. Only successful
        // notarizations above finalization become servable.
        let last_finalized = self.last_finalized();
        if let Some(notarization) = self.pending_notarizations.remove(&view)
            && success
            && view > last_finalized
        {
            self.certified_notarizations.insert(view, notarization);
        }

        // No copy of an uncertifiable notarization can certify anywhere, so it
        // is not an answer to an exact-parent request.
        if !success {
            self.certified_notarizations.remove(&view);
            if view > last_finalized {
                self.uncertifiable_notarizations.insert(view);
            }
            Self::retire(resolver, move |asked, ask| {
                ask.kind == Kind::Notarization && asked == view
            });
        }

        let effects = self.state.handle_certified(view, success);
        self.apply_effects(resolver, effects);
    }

    /// Applies the side effects requested by [super::state::State] to the resolver.
    fn apply_effects<R: Resolver<Key = U64, Subscriber = Ask>>(
        &mut self,
        resolver: &mut R,
        effects: Vec<Effect>,
    ) {
        for effect in effects {
            match effect {
                Effect::Fetch {
                    view,
                    cause,
                    reason,
                } => self.fetch(resolver, view, cause, reason),
                Effect::RetainAbove(floor) => {
                    // Resolver state does not repair below its floor, so a
                    // background ask there has nothing left to do. Only
                    // background asks retire here, because a proposal may name
                    // ancestry below the floor and only finalization rules that
                    // out.
                    Self::retire(resolver, move |view, ask| {
                        ask.until == Until::Floor && view <= floor
                    });
                }
            }
        }
    }

    /// Retires the asks that new evidence settles.
    ///
    /// `settled` reports whether the evidence answers an ask. [Resolver::retain]
    /// takes an owned predicate, so it cannot call [Self::settled]. Every
    /// retirement here names a span of views and a kind, which the caller captures
    /// by value instead.
    ///
    /// Settlement is monotonic: no later evidence unsettles an ask. A retirement
    /// therefore stays true however the resolver orders it against fetches, which
    /// it reorders under backpressure.
    fn retire<R: Resolver<Key = U64, Subscriber = Ask>>(
        resolver: &mut R,
        settled: impl Fn(View, Ask) -> bool + Send + 'static,
    ) {
        let _ = resolver.retain(move |key, ask| !settled(View::new(u64::from(key)), *ask));
    }

    /// Issues a background fetch for the nullification covering `view`.
    ///
    /// Both [FetchReason]s want the same certificate: [State] only reports
    /// a view whose covering nullification is missing, whether the gap was found
    /// by scanning below the current view or opened by a failed certification.
    fn fetch<R: Resolver<Key = U64, Subscriber = Ask>>(
        &self,
        resolver: &mut R,
        view: View,
        cause: View,
        reason: FetchReason,
    ) {
        let ask = Ask::backfill();

        // State only emits a background fetch for a gap that is unsettled at
        // issuance. Later evidence may settle and retire the queued fetch.
        assert!(!self.settled(view, ask.kind));
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = cause.traced(),
            view = view.traced(),
            reason = reason.as_str(),
            kind = ask.kind.as_str()
        );
        let _ = resolver.fetch(Fetch {
            key: U64::from(view),
            subscriber: ask,
            span,
        });
    }

    /// Fetches missing proposal ancestry. If `target` is provided, the resolver
    /// queries only that peer.
    fn resolve<R>(
        &self,
        resolver: &mut R,
        proposal: View,
        view: View,
        kind: Kind,
        target: Option<S::PublicKey>,
    ) where
        R: TargetedResolver<Key = U64, Subscriber = Ask, PublicKey = S::PublicKey>,
    {
        if view >= proposal || self.settled(view, kind) {
            return;
        }
        let ask = Ask::ancestry(kind);
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = proposal.traced(),
            view = view.traced(),
            reason = "proposal_ancestry",
            kind = ask.kind.as_str()
        );
        let fetch = Fetch {
            key: U64::from(view),
            subscriber: ask,
            span,
        };
        let _ = match target {
            Some(target) => resolver.fetch_targeted(fetch, NonEmptyVec::new(target)),
            None => resolver.fetch(fetch),
        };
    }

    /// Returns whether local evidence has settled an ask for `kind` at `view`.
    ///
    /// Settled means there is nothing left to fetch: either the evidence is in
    /// hand, or no response could ever serve the ask. This decides whether to
    /// open a fetch and whether a delivery completed one. [Self::retire] carries
    /// the same rule to the resolver, one piece of evidence at a time.
    ///
    /// A valid response does not imply this. The wire key names only a view, so a
    /// peer may answer a notarization request with a covering nullification: valid
    /// evidence the actor records, but not what was asked for.
    fn settled(&self, view: View, kind: Kind) -> bool {
        // Finalization rules out any further need for the view. This is also
        // what settles an ask answered by a finalization, since resolver state
        // retains the highest one independently of its construction floor.
        if view <= self.last_finalized() {
            return true;
        }
        match kind {
            Kind::Nullification => self.covering_nullification(view).is_some(),
            // Holding the notarization settles this, and so does a failed
            // verdict: certification judges the evidence itself, so no other
            // copy of it could pass either.
            Kind::Notarization => {
                self.pending_notarizations.contains_key(&view)
                    || self.certified_notarizations.contains_key(&view)
                    || self.uncertifiable_notarizations.contains(&view)
            }
        }
    }

    /// Returns whether every ask sharing the resolver key for `view` is settled.
    ///
    /// Ignoring a delivery retires the key, including subscribers that may not
    /// be present in the delivery, so demand for both kinds must be settled.
    fn key_settled(&self, view: View) -> bool {
        self.settled(view, Kind::Nullification) && self.settled(view, Kind::Notarization)
    }

    /// Returns the cached nullification covering `view`, if any.
    ///
    /// A nullification covers the rest of its term, so it may be keyed at an
    /// earlier view than the one being served.
    fn covering_nullification(&self, view: View) -> Option<&Bytes> {
        self.nullifications
            .range(view.covering_range(self.state.term_length()))
            .next_back()
            .map(|(_, nullification)| nullification)
    }

    /// Selects the best certificate to serve for `view`.
    ///
    /// The highest finalization settles every ask at or below it. Otherwise
    /// an exact certified notarization is preferred to a covering
    /// nullification, matching proposal construction. If neither is retained,
    /// the current floor is served. Pending notarizations and notarizations
    /// that fail certification are never served.
    fn produce_certificate(&self, view: View) -> Option<Bytes> {
        // Prefer the retained finalization because a higher notarization does
        // not settle an older ancestry request.
        if let Some(certificate @ Certificate::Finalization(_)) = self.state.get(view) {
            return Some(certificate.encode());
        }

        // Follow the proposal-parent hierarchy. An honest proposer builds on a
        // nullification only when it has no certified notarization to use.
        if let Some(notarization) = self.certified_notarizations.get(&view) {
            return Some(notarization.clone());
        }
        if let Some(nullification) = self.covering_nullification(view) {
            return Some(nullification.clone());
        }

        // Above retained finalization, the movable floor may still serve a
        // higher certified notarization.
        self.state.get(view).map(|certificate| certificate.encode())
    }

    /// Validates an incoming message, returning the parsed message if valid.
    ///
    /// Validity is judged against `view` alone, because that is all the request
    /// named. Any certificate an honest peer could serve for the view is accepted,
    /// including one that answers the other kind: rejecting it would fault a peer
    /// that answered the only question the wire key asked. Whether it
    /// settles the ask is a separate check (see [Self::settled]).
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // A nullification covers the rest of its term. A notarization or
        // finalization is servable from a peer's floor, which may sit above the
        // requested view.
        let servable = match &incoming {
            Certificate::Nullification(nullification) => {
                nullification.view().covers(view, self.state.term_length())
            }
            Certificate::Notarization(notarization) => notarization.view() >= view,
            Certificate::Finalization(finalization) => finalization.view() >= view,
        };
        if !servable {
            debug!(%view, received = %incoming.view(), "certificate below requested view");
            return None;
        }

        if incoming.epoch() != self.epoch {
            debug!(
                %view,
                epoch = %incoming.epoch(),
                expected = %self.epoch,
                "rejecting certificate from different epoch"
            );
            return None;
        }

        if !incoming.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
            debug!(%view, "certificate failed verification");
            return None;
        }

        debug!(%view, received = %incoming.view(), "received certificate for request");
        Some(incoming)
    }

    /// Handles a message from the [p2p::Engine].
    fn handle_resolver<R: Resolver<Key = U64, Subscriber = Ask>>(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut R,
    ) {
        match message {
            HandlerMessage::Deliver {
                span,
                view,
                data,
                asks,
                response,
            } => {
                let span = info_span!(
                    parent: span,
                    "simplex.resolver.deliver",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Ignoring is key-wide, so only skip validation after every
                // certificate kind that can share this view is settled.
                if self.key_settled(view) {
                    response.send_lossy(Outcome::Ignored);
                    return;
                }

                // Validate incoming message
                let validate = info_span!(
                    "simplex.resolver.validate",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let Some(parsed) = validate.in_scope(|| self.validate(view, data)) else {
                    response.send_lossy(Outcome::Invalid);
                    return;
                };

                // A failed notarization remains valid protocol evidence, but
                // replaying it cannot satisfy any outstanding repair ask.
                let obsolete = matches!(
                    &parsed,
                    Certificate::Notarization(notarization)
                        if self
                            .uncertifiable_notarizations
                            .contains(&notarization.view())
                );
                if !obsolete {
                    // Notify voter as soon as possible.
                    let resolved = info_span!(
                        "simplex.resolver.resolved",
                        epoch = self.epoch.traced(),
                        view = view.traced(),
                        certificate_view = parsed.view().traced()
                    );
                    resolved.in_scope(|| voter.resolved(parsed.clone()));

                    // Record the certificate, which settles whichever asks it
                    // answered and retires their fetches.
                    self.updated(resolver, parsed);
                }

                // The peer answered the view it was asked about, so it is never
                // faulted here. If an ask for this view is still open, the
                // response was valid but ambiguous, and the resolver retries
                // without penalizing the peer.
                let outcome = if asks.iter().all(|ask| self.settled(view, ask.kind)) {
                    Outcome::Complete
                } else {
                    Outcome::Ambiguous
                };
                response.send_lossy(outcome);
            }
            HandlerMessage::Produce { view, response } => {
                let span = info_span!(
                    "simplex.resolver.produce",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Produce message for view
                let Some(certificate) = self.produce_certificate(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_helpers::*, *};
    use crate::{
        simplex::{
            elector::{Config as _, Elector as _, RoundRobin, RoundRobinElector},
            scheme::ed25519,
            types::{Notarization, Notarize},
        },
        types::{Round, TermLength, ViewDelta},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        Sha256,
        certificate::{Scheme as _, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_async};
    use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Quota, Runner, Supervisor, deterministic};
    use commonware_utils::{
        NZU32, NZUsize, channel::oneshot, non_empty, non_empty_vec, probability, sync::Mutex,
    };
    use std::{collections::BTreeSet, sync::Arc};

    const NAMESPACE: &[u8] = b"resolver-actor";
    const EPOCH: Epoch = Epoch::new(9);
    const TERM_LENGTH: TermLength = TermLength::new(NZU32!(5));

    type TestScheme = ed25519::Scheme;
    type TestActor =
        Actor<deterministic::Context, TestScheme, NoopBlocker, Sha256Digest, Sequential>;

    #[derive(Clone, Default)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    /// Tracks the set of pending requests the way the resolver engine would.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        outstanding: Arc<Mutex<BTreeSet<(U64, Ask)>>>,
        targeted: Arc<Mutex<Vec<(U64, Ask, PublicKey)>>>,
    }

    impl RecordingResolver {
        fn outstanding(&self) -> Vec<u64> {
            self.outstanding
                .lock()
                .iter()
                .map(|(key, _)| u64::from(key))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        }

        fn targeted(&self) -> Vec<(u64, Ask, PublicKey)> {
            self.targeted
                .lock()
                .iter()
                .map(|(key, subscription, target)| (u64::from(key), *subscription, target.clone()))
                .collect()
        }

        fn subscriptions(&self, view: u64) -> Vec<Ask> {
            self.outstanding
                .lock()
                .iter()
                .filter_map(|(key, subscription)| (u64::from(key) == view).then_some(*subscription))
                .collect()
        }
    }

    impl Resolver for RecordingResolver {
        type Key = U64;
        type Subscriber = Ask;

        fn fetch<F>(&mut self, key: F) -> Feedback
        where
            F: Into<Fetch<U64, Ask>> + Send,
        {
            let fetch = key.into();
            self.outstanding
                .lock()
                .insert((fetch.key, fetch.subscriber));
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<U64, Ask>> + Send,
        {
            for key in keys {
                self.fetch(key);
            }
            Feedback::Ok
        }

        fn retain(&mut self, predicate: impl Fn(&U64, &Ask) -> bool + Send + 'static) -> Feedback {
            self.outstanding
                .lock()
                .retain(|(key, subscription)| predicate(key, subscription));
            Feedback::Ok
        }
    }

    impl TargetedResolver for RecordingResolver {
        type PublicKey = PublicKey;

        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<U64, Ask>> + Send,
            targets: NonEmptyVec<PublicKey>,
        ) -> Feedback {
            let fetch = fetch.into();
            self.targeted.lock().push((
                fetch.key.clone(),
                fetch.subscriber,
                targets.first().clone(),
            ));
            self.outstanding
                .lock()
                .insert((fetch.key, fetch.subscriber));
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(&mut self, fetches: Vec<(F, NonEmptyVec<PublicKey>)>) -> Feedback
        where
            F: Into<Fetch<U64, Ask>> + Send,
        {
            for (fetch, targets) in fetches {
                self.fetch_targeted(fetch, targets);
            }
            Feedback::Ok
        }
    }

    fn build_actor(
        context: deterministic::Context,
        scheme: TestScheme,
        term_length: TermLength,
    ) -> TestActor {
        let (actor, _) = Actor::new(
            context,
            Config {
                scheme,
                blocker: NoopBlocker,
                strategy: Sequential,
                epoch: EPOCH,
                mailbox_size: NZUsize!(8),
                fetch_timeout: Duration::from_secs(1),
                term_length,
            },
        );
        actor
    }

    fn assert_targeted_fetch_does_not_restrict_existing_backfill(target_index: usize) {
        let runtime = deterministic::Runner::timed(Duration::from_secs(10));
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let mut connections = Vec::new();
            for participant in &participants {
                connections.push(
                    oracle
                        .control(participant.clone())
                        .register(2, Quota::per_second(NZU32!(1_000)))
                        .await
                        .unwrap(),
                );
            }
            let mut connections = connections.into_iter();
            let requester_connection = connections.next().unwrap();
            let (_silent_sender, mut silent_receiver) = connections.next().unwrap();
            let responder_connection = connections.next().unwrap();
            let _unused_connection = connections.next().unwrap();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: probability!(1.0),
            };
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[1].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[1].clone(),
                    participants[0].clone(),
                    link.clone(),
                )
                .await
                .unwrap();

            let (requester_voter_sender, mut requester_voter_receiver) =
                mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let (requester, mut requester_mailbox) = TestActor::new(
                context.child("requester"),
                Config {
                    scheme: schemes[0].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _requester = requester.start(
                voter::Mailbox::new(requester_voter_sender),
                requester_connection.0,
                requester_connection.1,
            );

            let (responder_voter_sender, _responder_voter_receiver) =
                mailbox::new(context.child("responder_voter"), NZUsize!(8));
            let (responder, mut responder_mailbox) = TestActor::new(
                context.child("responder"),
                Config {
                    scheme: schemes[2].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _responder = responder.start(
                voter::Mailbox::new(responder_voter_sender),
                responder_connection.0,
                responder_connection.1,
            );

            let requested = View::new(1);
            let available = build_nullification(&schemes, &verifier, EPOCH, requested);
            responder_mailbox.updated(Certificate::Nullification(available.clone()));
            context.sleep(Duration::from_millis(10)).await;

            // Advancing to view 2 creates an unrestricted background ask for
            // view 1. The only connected peer is silent, so seeing
            // its request proves the background fetch is already in flight.
            requester_mailbox.updated(Certificate::Nullification(build_nullification(
                &schemes,
                &verifier,
                EPOCH,
                View::new(2),
            )));
            let (requester_key, _) = select! {
                request = silent_receiver.recv() => request.expect("silent peer channel closed"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("background request did not reach silent peer");
                },
            };
            assert_eq!(requester_key, participants[0]);

            // A later targeted ancestry request may name a remote peer or the
            // requester itself. It must attach its subscriber without
            // narrowing the in-flight unrestricted fetch.
            requester_mailbox.resolve(
                View::new(3),
                requested,
                Kind::Nullification,
                Some(participants[target_index].clone()),
            );
            context.sleep(Duration::from_millis(10)).await;

            // Remove the silent peer and expose a different responder. If
            // the targeted ask narrowed the fetch, recovery cannot finish.
            oracle
                .remove_link(participants[0].clone(), participants[1].clone())
                .await
                .unwrap();
            oracle
                .remove_link(participants[1].clone(), participants[0].clone())
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[2].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(participants[2].clone(), participants[0].clone(), link)
                .await
                .unwrap();

            let recovered = select! {
                message = requester_voter_receiver.recv() => message.expect("voter mailbox closed"),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("unrestricted fetch was narrowed by the targeted request");
                },
            };
            assert!(matches!(
                recovered,
                voter::Message::Verified {
                    certificate: Certificate::Nullification(nullification),
                    ..
                } if nullification == available
            ));
        });
    }

    #[test_async]
    async fn targeted_fetch_does_not_restrict_existing_backfill() {
        assert_targeted_fetch_does_not_restrict_existing_backfill(1);
    }

    #[test_async]
    async fn self_targeted_fetch_does_not_restrict_existing_backfill() {
        assert_targeted_fetch_does_not_restrict_existing_backfill(0);
    }

    /// Certification recovery fetches a missing mid-term parent from an
    /// available holder when the term leader is unavailable.
    #[test_async]
    async fn untargeted_parent_fetch_uses_available_holder() {
        let runtime = deterministic::Runner::timed(Duration::from_secs(10));
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let elector: RoundRobinElector<TestScheme> = RoundRobin::<Sha256>::default()
                .with_term(TERM_LENGTH, Duration::from_secs(1), ViewDelta::new(0))
                .build(schemes[0].participants());
            let leader = usize::from(elector.elect(Round::new(EPOCH, View::new(1)), None));
            assert_eq!(
                leader, 2,
                "fixture must leave the stable leader unavailable"
            );

            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let mut connections = Vec::new();
            for participant in &participants {
                connections.push(
                    oracle
                        .control(participant.clone())
                        .register(2, Quota::per_second(NZU32!(1_000)))
                        .await
                        .unwrap(),
                );
            }
            let mut connections = connections.into_iter();
            let requester_connection = connections.next().unwrap();
            let first_holder_connection = connections.next().unwrap();
            let _unavailable_leader_connection = connections.next().unwrap();
            let second_holder_connection = connections.next().unwrap();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: probability!(1.0),
            };
            for holder in [&participants[1], &participants[3]] {
                oracle
                    .add_link(participants[0].clone(), holder.clone(), link.clone())
                    .await
                    .unwrap();
                oracle
                    .add_link(holder.clone(), participants[0].clone(), link.clone())
                    .await
                    .unwrap();
            }

            let (requester_voter_sender, mut requester_voter_receiver) =
                mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let (requester, mut requester_mailbox) = TestActor::new(
                context.child("requester"),
                Config {
                    scheme: schemes[0].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TERM_LENGTH,
                },
            );
            let _requester = requester.start(
                voter::Mailbox::new(requester_voter_sender),
                requester_connection.0,
                requester_connection.1,
            );

            let parent = build_notarization(&schemes, &verifier, EPOCH, View::new(2));
            let mut holders = Vec::new();
            for (index, connection) in [(1, first_holder_connection), (3, second_holder_connection)]
            {
                let (voter_sender, voter_receiver) =
                    mailbox::new(context.child("holder_voter"), NZUsize!(8));
                let (holder, mut holder_mailbox) = TestActor::new(
                    context.child("holder"),
                    Config {
                        scheme: schemes[index].clone(),
                        blocker: NoopBlocker,
                        strategy: Sequential,
                        epoch: EPOCH,
                        mailbox_size: NZUsize!(8),
                        fetch_timeout: Duration::from_millis(200),
                        term_length: TERM_LENGTH,
                    },
                );
                let handle = holder.start(
                    voter::Mailbox::new(voter_sender),
                    connection.0,
                    connection.1,
                );
                holder_mailbox.updated(Certificate::Notarization(parent.clone()));
                holder_mailbox.certified(parent.view(), true);
                // Keep the holder and its mailboxes alive until the fetch completes.
                holders.push((handle, holder_mailbox, voter_receiver));
            }

            // Request the parent from any peer. The voter test covers the child
            // that triggers this request.
            context.sleep(Duration::from_millis(10)).await;
            requester_mailbox.resolve(View::new(3), View::new(2), Kind::Notarization, None);

            let recovered = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("missing parent was not fetched from an available validator");
                },
            };
            assert!(matches!(
                recovered,
                voter::Message::Verified {
                    certificate: Certificate::Notarization(fetched),
                    ..
                } if fetched == parent
            ));
        });
    }

    /// A valid notarization that does not settle the ask does not prevent a
    /// different peer from supplying the requested nullification.
    #[test_async]
    async fn ambiguous_notarization_does_not_block_nullification_fetch() {
        let runtime = deterministic::Runner::timed(Duration::from_secs(10));
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(participants.len()),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            let mut connections = Vec::new();
            for participant in &participants {
                connections.push(
                    oracle
                        .control(participant.clone())
                        .register(2, Quota::per_second(NZU32!(1_000)))
                        .await
                        .unwrap(),
                );
            }
            let mut connections = connections.into_iter();
            let requester_connection = connections.next().unwrap();
            let first_responder_connection = connections.next().unwrap();
            let nullification_holder_connection = connections.next().unwrap();
            let _unused_connection = connections.next().unwrap();

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: probability!(1.0),
            };
            oracle
                .add_link(
                    participants[0].clone(),
                    participants[1].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(
                    participants[1].clone(),
                    participants[0].clone(),
                    link.clone(),
                )
                .await
                .unwrap();

            let (requester_voter_sender, mut requester_voter_receiver) =
                mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let (requester, mut requester_mailbox) = TestActor::new(
                context.child("requester"),
                Config {
                    scheme: schemes[0].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _requester = requester.start(
                voter::Mailbox::new(requester_voter_sender),
                requester_connection.0,
                requester_connection.1,
            );

            let (first_voter_sender, _first_voter_receiver) =
                mailbox::new(context.child("first_voter"), NZUsize!(8));
            let (first_responder, mut first_responder_mailbox) = TestActor::new(
                context.child("first_responder"),
                Config {
                    scheme: schemes[1].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _first_responder = first_responder.start(
                voter::Mailbox::new(first_voter_sender),
                first_responder_connection.0,
                first_responder_connection.1,
            );

            let (holder_voter_sender, _holder_voter_receiver) =
                mailbox::new(context.child("holder_voter"), NZUsize!(8));
            let (nullification_holder, mut nullification_holder_mailbox) = TestActor::new(
                context.child("nullification_holder"),
                Config {
                    scheme: schemes[2].clone(),
                    blocker: NoopBlocker,
                    strategy: Sequential,
                    epoch: EPOCH,
                    mailbox_size: NZUsize!(8),
                    fetch_timeout: Duration::from_millis(200),
                    term_length: TermLength::ONE,
                },
            );
            let _nullification_holder = nullification_holder.start(
                voter::Mailbox::new(holder_voter_sender),
                nullification_holder_connection.0,
                nullification_holder_connection.1,
            );

            let requested = View::new(1);
            let notarized = requested.next();
            let notarization = build_notarization(&schemes, &verifier, EPOCH, notarized);
            first_responder_mailbox.updated(Certificate::Notarization(notarization.clone()));
            // Certifying the notarization makes it the responder's floor, so
            // the responder answers a lower-view request with it.
            first_responder_mailbox.certified(notarization.view(), true);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, requested);
            nullification_holder_mailbox.updated(Certificate::Nullification(nullification.clone()));
            context.sleep(Duration::from_millis(10)).await;

            // A later nullification exposes a gap and starts an unrestricted
            // background fetch. The only connected peer answers with a valid
            // notarization that does not settle the nullification ask.
            requester_mailbox.updated(Certificate::Nullification(build_nullification(
                &schemes, &verifier, EPOCH, notarized,
            )));
            let first = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("notarization was not fetched");
                },
            };
            assert!(matches!(
                first,
                voter::Message::Verified {
                    certificate: Certificate::Notarization(ref fetched),
                    ..
                } if fetched == &notarization
            ));

            oracle
                .add_link(
                    participants[0].clone(),
                    participants[2].clone(),
                    link.clone(),
                )
                .await
                .unwrap();
            oracle
                .add_link(participants[2].clone(), participants[0].clone(), link)
                .await
                .unwrap();
            oracle
                .remove_link(participants[0].clone(), participants[1].clone())
                .await
                .unwrap();
            oracle
                .remove_link(participants[1].clone(), participants[0].clone())
                .await
                .unwrap();
            context.sleep(Duration::from_millis(10)).await;

            // A targeted ancestry ask for the same view attaches another
            // subscriber. The ambiguous notarization answer released the
            // network slot, so another peer can supply the nullification
            // this proposal actually needs.
            requester_mailbox.resolve(
                View::new(3),
                requested,
                Kind::Nullification,
                Some(participants[2].clone()),
            );
            let recovered = select! {
                message = requester_voter_receiver.recv() => {
                    message.expect("voter mailbox closed")
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("ambiguous notarization answer blocked ancestry repair");
                },
            };
            assert!(matches!(
                recovered,
                voter::Message::Verified {
                    certificate: Certificate::Nullification(fetched),
                    ..
                } if fetched == nullification
            ));
        });
    }

    #[test_async]
    async fn updates_maintain_resolver_pending_set() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            // The first certificate emits requests at the term anchors.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(20));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![1, 6, 11, 16]);

            // A covering nullification retains out only its own term's requests
            // (here, the request at its own view): views below its start and
            // above its term end stay pending.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![1, 11, 16]);

            // A mid-term floor raise drops the requests below it and re-scans
            // the stranded term tail (view 5).
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(4));
            actor.updated(&mut resolver, Certificate::Finalization(finalization));
            assert_eq!(resolver.outstanding(), vec![5, 11, 16]);

            // A below-floor nullification covering the floor's term retains
            // out the request at its term end (view 5), not just the request
            // at its own view.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![11, 16]);

            // A floor raise drops the request at the floor view itself and
            // re-scans the stranded term tail (view 12).
            let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(11));
            actor.updated(&mut resolver, Certificate::Finalization(finalization));
            assert_eq!(resolver.outstanding(), vec![12, 16]);

            // A nullification at the floor covering the floor's term retains
            // out mid-term requests strictly inside its range.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(11));
            actor.updated(&mut resolver, Certificate::Nullification(nullification));
            assert_eq!(resolver.outstanding(), vec![16]);
        });
    }

    /// A resolve without a target must open an untargeted fetch, not be
    /// dropped.
    #[test_async]
    async fn resolve_without_target_falls_back_to_untargeted_fetch() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { verifier, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let actor = build_actor(context, verifier, TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let requested = View::new(9);

            actor.resolve(
                &mut resolver,
                View::new(10),
                requested,
                Kind::Notarization,
                None,
            );
            assert!(resolver.targeted().is_empty());
            assert_eq!(resolver.outstanding(), vec![9]);
            assert_eq!(
                resolver.subscriptions(9),
                vec![Ask::ancestry(Kind::Notarization)]
            );
        });
    }

    #[test_async]
    async fn targeted_fetches_drop_only_when_ask_is_satisfied() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let requested = View::new(3);

            actor.resolve(
                &mut resolver,
                View::new(10),
                requested,
                Kind::Nullification,
                Some(participants[0].clone()),
            );
            actor.resolve(
                &mut resolver,
                View::new(11),
                requested,
                Kind::Notarization,
                Some(participants[1].clone()),
            );
            resolver.fetch(Fetch {
                key: U64::from(requested),
                subscriber: Ask::backfill(),
                span: tracing::Span::none(),
            });
            assert_eq!(
                resolver.targeted(),
                vec![
                    (
                        3,
                        Ask::ancestry(Kind::Nullification),
                        participants[0].clone()
                    ),
                    (
                        3,
                        Ask::ancestry(Kind::Notarization),
                        participants[1].clone()
                    ),
                ]
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![
                    Ask::backfill(),
                    Ask::ancestry(Kind::Nullification),
                    Ask::ancestry(Kind::Notarization),
                ]
            );

            // A covering nullification completes both background repair and
            // the targeted nullification request. It must preserve the
            // targeted parent request. That opposite evidence is the reason
            // the parent certificate is still needed.
            actor.updated(
                &mut resolver,
                Certificate::Nullification(build_nullification(
                    &schemes, &verifier, EPOCH, requested,
                )),
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![Ask::ancestry(Kind::Notarization)]
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested,
                Kind::Nullification,
                Some(participants[2].clone()),
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                requested.next(),
                Kind::Nullification,
                Some(participants[2].clone()),
            );
            assert_eq!(resolver.targeted().len(), 2);

            // Exercise the mirror case at another key. Holding the exact
            // parent completes only the targeted parent request. It does not
            // provide the nullification needed to skip that view.
            let second_requested = requested.next_term_start(actor.state.term_length());
            actor.resolve(
                &mut resolver,
                View::new(12),
                second_requested,
                Kind::Nullification,
                Some(participants[2].clone()),
            );
            actor.resolve(
                &mut resolver,
                View::new(13),
                second_requested,
                Kind::Notarization,
                Some(participants[3].clone()),
            );
            resolver.fetch(Fetch {
                key: U64::from(second_requested),
                subscriber: Ask::backfill(),
                span: tracing::Span::none(),
            });
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(
                    &schemes,
                    &verifier,
                    EPOCH,
                    second_requested,
                )),
            );
            actor.certified(&mut resolver, second_requested, true);

            // The certified notarization is now the floor, which satisfies
            // background repair at that view. The targeted nullification ask
            // survives: a notarization is not a nullification covering it.
            assert_eq!(
                resolver.subscriptions(6),
                vec![Ask::ancestry(Kind::Nullification)]
            );
            actor.resolve(
                &mut resolver,
                View::new(14),
                second_requested,
                Kind::Notarization,
                Some(participants[0].clone()),
            );
            assert_eq!(resolver.targeted().len(), 4);

            // A numeric floor raise alone does not identify which ancestry
            // requirement it satisfies. Both remaining targeted requests
            // survive until matching evidence or finalization arrives.
            actor.apply_effects(&mut resolver, vec![Effect::RetainAbove(second_requested)]);
            assert_eq!(resolver.outstanding(), vec![3, 6]);

            // Finalization is the universal boundary. No valid proposal can
            // require ancestry at or below it. It removes every such key and
            // prevents a delayed mailbox request from recreating stale work.
            let finalized = second_requested;
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes, &verifier, EPOCH, finalized,
                )),
            );
            assert!(resolver.outstanding().is_empty());
            assert!(actor.nullifications.is_empty());
            assert!(actor.pending_notarizations.is_empty());
            assert!(actor.certified_notarizations.is_empty());
            assert!(actor.uncertifiable_notarizations.is_empty());
            actor.resolve(
                &mut resolver,
                finalized.next(),
                requested,
                Kind::Notarization,
                Some(participants[0].clone()),
            );
            assert!(resolver.outstanding().is_empty());
            assert_eq!(resolver.targeted().len(), 4);
        });
    }

    #[test_async]
    async fn exact_certified_notarization_is_preferred_over_covering_nullification_and_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut responder =
                build_actor(context.child("responder"), verifier.clone(), TERM_LENGTH);
            let mut responder_resolver = RecordingResolver::default();

            let requested = View::new(3);
            let nullification = Certificate::Nullification(build_nullification(
                &schemes, &verifier, EPOCH, requested,
            ));
            let expected_nullification = nullification.encode();
            responder.updated(&mut responder_resolver, nullification);
            let parent = build_notarization(&schemes, &verifier, EPOCH, requested);
            let expected_parent = Certificate::Notarization(parent.clone()).encode();
            responder.updated(&mut responder_resolver, Certificate::Notarization(parent));
            responder.certified(&mut responder_resolver, requested, true);
            let floor = View::new(4);
            let floor_notarization = build_notarization(&schemes, &verifier, EPOCH, floor);
            responder.updated(
                &mut responder_resolver,
                Certificate::Notarization(floor_notarization),
            );
            responder.certified(&mut responder_resolver, floor, true);

            assert_eq!(
                responder.covering_nullification(requested),
                Some(&expected_nullification)
            );
            assert_eq!(
                responder.certified_notarizations.get(&requested),
                Some(&expected_parent)
            );

            // The exact certified parent is preferred to both the covering
            // nullification and a nonmatching higher floor.
            assert_eq!(
                responder.produce_certificate(requested),
                Some(expected_parent)
            );
        });
    }

    #[test_async]
    async fn higher_certified_floor_does_not_hide_older_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut responder =
                build_actor(context.child("responder"), verifier.clone(), TERM_LENGTH);
            let mut responder_resolver = RecordingResolver::default();

            let requested = View::new(3);
            let finalization = Certificate::Finalization(build_finalization(
                &schemes, &verifier, EPOCH, requested,
            ));
            responder.updated(&mut responder_resolver, finalization);

            let floor = View::new(6);
            let notarization =
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor));
            responder.updated(&mut responder_resolver, notarization);
            responder.certified(&mut responder_resolver, floor, true);

            // The notarization is now the construction floor, but returning it
            // for view 3 would leave the targeted ask ambiguous. The retained
            // finalization settles that ask instead.
            let data = responder
                .produce_certificate(requested)
                .expect("responder should retain settling finalization");

            let (voter_tx, _voter_rx) = mailbox::new(context.child("requester_voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut requester = build_actor(context.child("requester"), verifier, TERM_LENGTH);
            let mut requester_resolver = RecordingResolver::default();
            let (response, receiver) = oneshot::channel();
            requester.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data,
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut requester_resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
        });
    }

    #[test_async]
    async fn notarization_is_served_only_after_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(3);
            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            let encoded = Certificate::Notarization(notarization.clone()).encode();

            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: encoded.clone(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
            assert!(actor.produce_certificate(view).is_none());

            actor.certified(&mut resolver, view, true);
            assert_eq!(actor.produce_certificate(view), Some(encoded));
        });
    }

    #[test_async]
    async fn late_verdict_after_finalization_promotes_nothing() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(5);

            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, view)),
            );
            assert!(actor.pending_notarizations.contains_key(&view));

            // A covering finalization prunes the payload awaiting its verdict.
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes,
                    &verifier,
                    EPOCH,
                    view.next(),
                )),
            );
            assert!(actor.pending_notarizations.is_empty());

            // The late verdict finds nothing to promote: a notarization at or
            // below finalization never becomes servable.
            actor.certified(&mut resolver, view, true);
            assert!(actor.certified_notarizations.is_empty());
        });
    }

    #[test_async]
    async fn nullification_satisfies_target_at_certified_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(
                context,
                verifier.clone(),
                TermLength::ONE,
            );
            let mut resolver = RecordingResolver::default();
            let view = View::new(3);

            // Certify the view first, then request its coexisting
            // nullification as ancestry for a proposal that skips it.
            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization),
            );
            actor.certified(&mut resolver, view, true);
            let floor = View::new(8);
            let certified_floor = build_notarization(&schemes, &verifier, EPOCH, floor);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(certified_floor.clone()),
            );
            actor.certified(&mut resolver, floor, true);
            actor.resolve(
                &mut resolver,
                View::new(10),
                view,
                Kind::Nullification,
                Some(participants[0].clone()),
            );
            assert_eq!(
                resolver.subscriptions(3),
                vec![Ask::ancestry(Kind::Nullification)]
            );

            // Certificate state still prefers the certified floor for
            // background bookkeeping, but locally observing the nullification
            // must retire the exact targeted ask it satisfies.
            actor.updated(
                &mut resolver,
                Certificate::Nullification(build_nullification(
                    &schemes, &verifier, EPOCH, view,
                )),
            );
            assert!(resolver.outstanding().is_empty());
            assert!(
                matches!(actor.state.get(view), Some(Certificate::Notarization(n)) if n == &certified_floor)
            );
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Kind::Nullification,
                Some(participants[1].clone()),
            );
            assert_eq!(resolver.targeted().len(), 1);
        });
    }

    #[test_async]
    async fn higher_certified_floor_does_not_suppress_exact_parent_fetch() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let floor = View::new(6);

            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            actor.resolve(
                &mut resolver,
                View::new(8),
                View::new(4),
                Kind::Notarization,
                Some(participants[0].clone()),
            );
            assert_eq!(
                resolver.targeted(),
                vec![(
                    4,
                    Ask::ancestry(Kind::Notarization),
                    participants[0].clone()
                )]
            );
        });
    }

    #[test_async]
    async fn certification_failure_retires_parent_target() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(5);

            actor.resolve(
                &mut resolver,
                View::new(10),
                view,
                Kind::Notarization,
                Some(participants[0].clone()),
            );
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, view)),
            );
            actor.certified(&mut resolver, view, false);

            // A false certification verdict is permanent. Parent repair is
            // retired, while ordinary repair asks for the nullification that
            // can now cover the failed view.
            assert_eq!(resolver.subscriptions(5), vec![Ask::backfill()]);
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Kind::Notarization,
                Some(participants[1].clone()),
            );
            assert_eq!(resolver.targeted().len(), 1);
        });
    }

    #[test_async]
    async fn parent_delivery_completes_on_possession_not_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(6);

            // The exact parent was asked for and arrived. Certification is an
            // application verdict on evidence already in hand, so the fetch has
            // nothing left to retrieve and must not stay open waiting for it.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(
                        build_notarization(&schemes, &verifier, EPOCH, view),
                    )
                    .encode(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
            assert!(actor.pending_notarizations.contains_key(&view));
            assert!(!actor.certified_notarizations.contains_key(&view));
        });
    }

    #[test_async]
    async fn failed_certification_retires_parent_ask_until_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes,
                verifier,
                participants,
                ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(6);

            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, view)),
            );
            actor.certified(&mut resolver, view, false);

            // The payload is no longer an answer, and the tombstone keeps a
            // delayed request from recreating the ask. A floor raise above the
            // view must not resurrect it (state prunes its own failed views).
            assert!(!actor.pending_notarizations.contains_key(&view));
            assert!(!actor.certified_notarizations.contains_key(&view));
            let floor = View::new(9);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            let targeted = resolver.targeted().len();
            actor.resolve(
                &mut resolver,
                View::new(11),
                view,
                Kind::Notarization,
                Some(participants[0].clone()),
            );
            assert_eq!(resolver.targeted().len(), targeted);
        });
    }

    #[test_async]
    async fn tombstoned_notarization_delivery_completes_without_recording() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, mut voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let view = View::new(6);

            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization.clone()),
            );
            actor.certified(&mut resolver, view, false);

            // Replaying the failed notarization is not new evidence: the voter
            // is not re-notified and the payload is not re-cached. The failed
            // verdict settles the ask, so the fetch still completes.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
            assert!(!actor.pending_notarizations.contains_key(&view));
            assert!(!actor.certified_notarizations.contains_key(&view));
            drop(voter);
            assert!(voter_rx.recv().await.is_none());

            // Finalization is the tombstone's retirement boundary.
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes,
                    &verifier,
                    EPOCH,
                    view.next(),
                )),
            );
            assert!(actor.uncertifiable_notarizations.is_empty());
        });
    }

    #[test_async]
    async fn valid_nullification_does_not_complete_parent_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            // The local requirement is intentionally absent from a delivery.
            // A covering nullification is a valid answer for the U64 key even
            // if the triggering proposal wanted a certified parent.
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(3));
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: View::new(4),
                    data: Certificate::<TestScheme, Sha256Digest>::Nullification(nullification)
                        .encode(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(receiver.await.unwrap(), Outcome::Ambiguous);
        });
    }

    #[test_async]
    async fn unrelated_higher_certified_notarization_does_not_complete_parent_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization.clone()),
            );
            actor.certified(&mut resolver, View::new(6), true);
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(notarization)
                        .encode(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Ambiguous);
        });
    }

    #[test_async]
    async fn already_certified_notarization_response_accepted() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let view = View::new(6);
            let notarization = build_notarization(&schemes, &verifier, EPOCH, view);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(notarization.clone()),
            );
            actor.certified(&mut resolver, view, true);

            // Build a second valid aggregate for the same proposal from a
            // different signer subset. Certification belongs to the proposal,
            // not to one encoding of its aggregate certificate.
            let votes: Vec<_> = schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, notarization.proposal.clone()).unwrap())
                .collect();
            let alternate =
                Notarization::from_notarizes(&verifier, non_empty![@&votes], &Sequential).unwrap();
            assert_ne!(notarization, alternate);

            // A targeted request can receive the leader's preferred
            // certificate even when the requester already certified it. The
            // duplicate will not produce a second certification callback, so
            // the resolver response must be completed immediately.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view,
                    data: Certificate::<TestScheme, Sha256Digest>::Notarization(alternate).encode(),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);

            // The duplicate is not re-cached as pending: no second verdict
            // would ever clear it.
            assert!(actor.pending_notarizations.is_empty());
        });
    }

    #[test_async]
    async fn finalization_completes_every_delivery_ask() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Certificate::<TestScheme, Sha256Digest>::Finalization(
                        build_finalization(&schemes, &verifier, EPOCH, View::new(6)),
                    )
                    .encode(),
                    asks: non_empty_vec![
                        Ask::backfill(),
                        Ask::ancestry(Kind::Nullification),
                        Ask::ancestry(Kind::Notarization),
                    ],
                    response,
                },
                &mut voter,
                &mut resolver,
            );
            assert_eq!(receiver.await.unwrap(), Outcome::Complete);
        });
    }

    #[test_async]
    async fn settled_key_ignores_delivery_without_validation() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, mut voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            actor.updated(
                &mut resolver,
                Certificate::Finalization(build_finalization(
                    &schemes,
                    &verifier,
                    EPOCH,
                    View::new(6),
                )),
            );
            assert!(actor.settled(requested, Kind::Nullification));
            assert!(actor.settled(requested, Kind::Notarization));

            // Garbage queued before local settlement is ignored without
            // decoding, verification, or peer penalty.
            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Bytes::from_static(b"unverifiable"),
                    asks: non_empty_vec![
                        Ask::backfill(),
                        Ask::ancestry(Kind::Nullification),
                        Ask::ancestry(Kind::Notarization),
                    ],
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(receiver.await.unwrap(), Outcome::Ignored);
            assert_eq!(actor.last_finalized(), View::new(6));
            assert!(matches!(
                actor.state.get(View::new(6)),
                Some(Certificate::Finalization(finalization))
                    if finalization.view() == View::new(6)
            ));
            drop(voter);
            assert!(voter_rx.recv().await.is_none());
        });
    }

    #[test_async]
    async fn nullification_only_settled_key_still_validates_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            actor.updated(
                &mut resolver,
                Certificate::Nullification(build_nullification(
                    &schemes, &verifier, EPOCH, requested,
                )),
            );
            assert!(actor.settled(requested, Kind::Nullification));
            assert!(!actor.settled(requested, Kind::Notarization));

            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Bytes::from_static(b"unverifiable"),
                    asks: non_empty_vec![Ask::ancestry(Kind::Nullification)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(receiver.await.unwrap(), Outcome::Invalid);
        });
    }

    #[test_async]
    async fn notarization_only_settled_key_still_validates_delivery() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let (voter_tx, _voter_rx) = mailbox::new(context.child("voter"), NZUsize!(8));
            let mut voter = voter::Mailbox::new(voter_tx);
            let mut actor = build_actor(context.child("actor"), verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();

            let requested = View::new(4);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(
                    &schemes, &verifier, EPOCH, requested,
                )),
            );
            assert!(!actor.settled(requested, Kind::Nullification));
            assert!(actor.settled(requested, Kind::Notarization));

            let (response, receiver) = oneshot::channel();
            actor.handle_resolver(
                HandlerMessage::Deliver {
                    span: tracing::Span::none(),
                    view: requested,
                    data: Bytes::from_static(b"unverifiable"),
                    asks: non_empty_vec![Ask::ancestry(Kind::Notarization)],
                    response,
                },
                &mut voter,
                &mut resolver,
            );

            assert_eq!(receiver.await.unwrap(), Outcome::Invalid);
        });
    }

    #[test_async]
    async fn validate_accepts_nullification_covering_requested_view_in_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
            assert!(View::new(6).same_term(View::new(10), TERM_LENGTH));
            let mut actor = build_actor(context, verifier, TERM_LENGTH);

            let validated = actor.validate(
                View::new(10),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification.clone())
                    .encode(),
            );

            assert!(matches!(
                validated,
                Some(Certificate::Nullification(parsed)) if parsed.view() == nullification.view()
            ));
        });
    }

    #[test_async]
    async fn validate_rejects_nullification_from_different_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(10));

            let validated = actor.validate(
                View::new(11),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification).encode(),
            );

            assert!(validated.is_none());
        });
    }

    #[test_async]
    async fn validate_rejects_nullification_above_requested_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(9));

            let validated = actor.validate(
                View::new(8),
                Certificate::<TestScheme, Sha256Digest>::Nullification(nullification).encode(),
            );

            assert!(validated.is_none());
        });
    }

    #[test_async]
    async fn failed_verdict_survives_higher_certified_floor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let mut resolver = RecordingResolver::default();
            let failed = View::new(7);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, failed)),
            );
            actor.certified(&mut resolver, failed, false);

            let floor = View::new(9);
            actor.updated(
                &mut resolver,
                Certificate::Notarization(build_notarization(&schemes, &verifier, EPOCH, floor)),
            );
            actor.certified(&mut resolver, floor, true);

            let notarization = build_notarization(&schemes, &verifier, EPOCH, failed);
            assert!(actor.uncertifiable_notarizations.contains(&failed));
            assert!(!actor.pending_notarizations.contains_key(&failed));
            assert!(!actor.certified_notarizations.contains_key(&failed));
            assert!(
                actor
                    .validate(failed, Certificate::Notarization(notarization).encode())
                    .is_some(),
                "failed certification does not make signed protocol evidence invalid",
            );
        });
    }

    #[test_async]
    async fn validate_rejects_finalization_from_different_epoch() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut actor = build_actor(context, verifier.clone(), TERM_LENGTH);
            let finalization =
                build_finalization(&schemes, &verifier, Epoch::new(10), View::new(7));

            let validated = actor.validate(
                View::new(7),
                Certificate::Finalization(finalization).encode(),
            );

            assert!(validated.is_none());
        });
    }
}
