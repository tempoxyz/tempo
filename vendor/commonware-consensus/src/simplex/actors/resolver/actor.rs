use super::{
    ingress::{Handler, HandlerMessage, Mailbox, MailboxMessage},
    state::{Effect, FetchReason},
    Config,
};
use crate::{
    simplex::{
        actors::{resolver::state::State, voter},
        scheme::Scheme,
        types::Certificate,
    },
    types::{Epoch, View},
    Epochable, Viewable,
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_p2p::{utils::StaticProvider, Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_resolver::{p2p, Fetch, Resolver as _};
use commonware_runtime::{
    spawn_cell, telemetry::traces::TracedExt as _, BufferPooler, Clock, ContextCell, Handle,
    Metrics, Spawner,
};
use commonware_utils::{channel::fallible::OneshotExt, ordered::Quorum, sequence::U64};
use rand_core::CryptoRng;
use std::{num::NonZeroUsize, time::Duration};
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

    state: State<S, D>,

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

                state: State::new(cfg.fetch_concurrent),

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
                initial: self.fetch_timeout / 2,
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
                        // Certificates from mailbox have no associated request view
                        let effects = self.state.handle(certificate, None);
                        self.apply_effects(&mut resolver, effects);
                    }
                    MailboxMessage::Certified { round, success, .. } => {
                        let effects = self.state.handle_certified(round.view(), success);
                        self.apply_effects(&mut resolver, effects);
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

    /// Applies the side effects requested by [super::state::State] to the resolver.
    fn apply_effects(
        &mut self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
        effects: Vec<Effect>,
    ) {
        for effect in effects {
            match effect {
                Effect::Fetch {
                    view,
                    cause,
                    reason,
                } => self.fetch(resolver, view, cause, reason),
                Effect::Remove(view) => {
                    let key = U64::from(view);
                    let _ = resolver.retain(move |candidate, _| *candidate != key);
                }
                Effect::RetainAbove(floor) => {
                    let floor = U64::from(floor);
                    let _ = resolver.retain(move |candidate, _| *candidate > floor);
                }
            }
        }
    }

    /// Issues a resolver fetch for `view`, attaching a span that records why the
    /// fetch was needed and which view's processing caused it.
    fn fetch(
        &self,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
        view: View,
        cause: View,
        reason: FetchReason,
    ) {
        let span = info_span!(
            "simplex.resolver.fetch",
            epoch = self.epoch.traced(),
            cause = cause.traced(),
            view = view.traced(),
            reason = reason.as_str()
        );
        let _ = resolver.fetch(Fetch {
            key: U64::from(view),
            subscriber: (),
            span,
        });
    }

    /// Validates an incoming message, returning the parsed message if valid.
    fn validate(&mut self, view: View, data: Bytes) -> Option<Certificate<S, D>> {
        // Decode message
        let incoming =
            Certificate::<S, D>::decode_cfg(data, &self.scheme.certificate_codec_config()).ok()?;

        // Validate message
        match incoming {
            Certificate::Notarization(notarization) => {
                let notarization_view = notarization.view();
                if notarization.view() < view {
                    debug!(%view, received = %notarization.view(), "notarization below view");
                    return None;
                }
                if notarization.epoch() != self.epoch {
                    debug!(
                        epoch = %notarization.epoch(),
                        expected = %self.epoch,
                        "rejecting notarization from different epoch"
                    );
                    return None;
                }
                if self.state.is_failed(notarization_view) {
                    debug!(
                        %notarization_view,
                        "rejecting notarization for view with failed certification"
                    );
                    return None;
                }
                if !notarization.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
                    debug!(%view, "notarization failed verification");
                    return None;
                }
                debug!(%view, received = %notarization_view, "received notarization for request");
                Some(Certificate::Notarization(notarization))
            }
            Certificate::Finalization(finalization) => {
                if finalization.view() < view {
                    debug!(%view, received = %finalization.view(), "finalization below view");
                    return None;
                }
                if finalization.epoch() != self.epoch {
                    debug!(
                        epoch = %finalization.epoch(),
                        expected = %self.epoch,
                        "rejecting finalization from different epoch"
                    );
                    return None;
                }
                if !finalization.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
                    debug!(%view, "finalization failed verification");
                    return None;
                }
                debug!(%view, received = %finalization.view(), "received finalization for request");
                Some(Certificate::Finalization(finalization))
            }
            Certificate::Nullification(nullification) => {
                if nullification.view() != view {
                    debug!(%view, received = %nullification.view(), "nullification view mismatch");
                    return None;
                }
                if nullification.epoch() != self.epoch {
                    debug!(
                        epoch = %nullification.epoch(),
                        expected = %self.epoch,
                        "rejecting nullification from different epoch"
                    );
                    return None;
                }
                if !nullification.verify::<_, D>(
                    self.context.as_mut(),
                    &self.scheme,
                    &self.strategy,
                ) {
                    debug!(%view, "nullification failed verification");
                    return None;
                }
                debug!(%view, received = %nullification.view(), "received nullification for request");
                Some(Certificate::Nullification(nullification))
            }
        }
    }

    /// Handles a message from the [p2p::Engine].
    fn handle_resolver(
        &mut self,
        message: HandlerMessage,
        voter: &mut voter::Mailbox<S, D>,
        resolver: &mut p2p::Mailbox<U64, S::PublicKey>,
    ) {
        match message {
            HandlerMessage::Deliver {
                span,
                view,
                data,
                response,
            } => {
                let span = info_span!(
                    parent: span,
                    "simplex.resolver.deliver",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Validate incoming message
                let validate = info_span!(
                    "simplex.resolver.validate",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let Some(parsed) = validate.in_scope(|| self.validate(view, data)) else {
                    // Resolver will block any peers that send invalid responses, so
                    // we don't need to do again here
                    response.send_lossy(false);
                    return;
                };
                response.send_lossy(true);

                // Notify voter as soon as possible
                let resolved = info_span!(
                    "simplex.resolver.resolved",
                    epoch = self.epoch.traced(),
                    view = view.traced(),
                    certificate_view = parsed.view().traced()
                );
                resolved.in_scope(|| voter.resolved(parsed.clone()));

                // Process message with the request view for tracking
                let effects = self.state.handle(parsed, Some(view));
                self.apply_effects(resolver, effects);
            }
            HandlerMessage::Produce { view, response } => {
                let span = info_span!(
                    "simplex.resolver.produce",
                    epoch = self.epoch.traced(),
                    view = view.traced()
                );
                let _guard = span.entered();

                // Produce message for view
                let Some(certificate) = self.state.get(view) else {
                    // If we drop the response channel, the resolver will automatically
                    // send an error response to the caller (so they don't need to wait
                    // the full timeout)
                    return;
                };
                response.send_lossy(certificate.encode());
            }
        }
    }
}
