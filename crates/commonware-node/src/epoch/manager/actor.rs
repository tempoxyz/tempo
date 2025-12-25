//! Actor implementing the epoch manager logic.
//!
//! This actor is responsible for:
//!
//! 1. entering and exiting epochs given messages it receives from the DKG
//!    manager.
//! 2. catching the node up by listening to votes for unknown epoch and
//!    requesting finalizations for the currently known boundary height.
//!
//! # Entering and exiting epochs
//!
//! When the actor receives an `Enter` message, it spins up a new simplex
//! consensus engine backing the epoch stored in the message. The message also
//! contains the public polynomial, share of the private key for this node,
//! and the participants in the next epoch - all determined by the DKG ceremony.
//! The engine receives a subchannel of the recovered, pending, and resolver
//! p2p channels, multiplexed by the epoch.
//!
//! When the actor receives an `Exit` message, it exists the engine backing the
//! epoch stored in it.
//!
//! # Catching up the node
//!
//! The actor makes use of the backup mechanism exposed by the subchannel
//! multiplexer API: assume the actor has a simplex engine running for epoch 0,
//! then this engine will have a subchannel registered on the multiplexer for
//! epoch 0.
//!
//! If the actor now receives a vote in epoch 5 over its pending mux backup
//! channel (since there are no subchannels registered with the muxer on
//! epochs 1 through 5), it will request the finalization certificate for the
//! boundary height of epoch 0 from the voter. This request is done over the
//! boundary certificates p2p network.
//!
//! Upon receipt of the request for epoch 0 over the boundary certificates p2p
//! network, the voter will send the finalization certificate to the *recovered*
//! p2p network, tagged by epoch 0.
//!
//! Finally, this certificate is received by the running simplex engine
//! (since remember, it's active for epoch 0), and subsequently forwarded to
//! the marshal actor, which finally is able to fetch all finalizations up to
//! the boundary height, which will eventually trigger the node to transition to
//! epoch 1.
//!
//! This process is repeated until the node catches up to the current network
//! epoch.
use std::{collections::BTreeMap, num::NonZeroUsize};

use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Reporters,
    simplex::{self, signing_scheme::bls12381_threshold::Scheme, types::Certificate},
    types::Epoch,
    utils,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::mux::{Builder as _, GlobalSender, MuxHandle, Muxer},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as _, Network, Spawner, Storage, spawn_cell,
};
use eyre::{WrapErr as _, ensure, eyre};
use futures::{StreamExt as _, channel::mpsc};
use governor::{RateLimiter, middleware::RateLimitingMiddleware};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand::{CryptoRng, Rng};
use tracing::{Level, Span, error, error_span, field::display, info, instrument, warn, warn_span};

use crate::{
    consensus::Digest,
    epoch::manager::ingress::{EpochTransition, Exit},
};

use super::ingress::Message;

const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB

pub(crate) struct Actor<TBlocker, TContext> {
    active_epochs: BTreeMap<Epoch, Handle<()>>,
    config: super::Config<TBlocker>,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    metrics: Metrics,
}

impl<TBlocker, TContext> Actor<TBlocker, TContext>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    // TODO(janis): are all of these bounds necessary?
    TContext: Spawner
        + commonware_runtime::Metrics
        + Rng
        + CryptoRng
        + Clock
        + governor::clock::Clock
        + Storage
        + Network,
{
    pub(super) fn new(
        config: super::Config<TBlocker>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<Message>,
    ) -> Self {
        let active_epochs = Gauge::default();
        let latest_epoch = Gauge::default();
        let latest_participants = Gauge::default();
        let how_often_signer = Counter::default();
        let how_often_verifier = Counter::default();

        context.register(
            "active_epochs",
            "the number of epochs currently managed by the epoch manager",
            active_epochs.clone(),
        );
        context.register(
            "latest_epoch",
            "the latest epoch managed by this epoch manager",
            latest_epoch.clone(),
        );
        context.register(
            "latest_participants",
            "the number of participants in the most recently started epoch",
            latest_participants.clone(),
        );
        context.register(
            "how_often_signer",
            "how often a node is a signer; a node is a signer if it has a share",
            how_often_signer.clone(),
        );
        context.register(
            "how_often_verifier",
            "how often a node is a verifier; a node is a verifier if it does not have a share",
            how_often_verifier.clone(),
        );

        Self {
            config,
            context: ContextCell::new(context),
            mailbox,
            metrics: Metrics {
                active_epochs,
                latest_epoch,
                latest_participants,
                how_often_signer,
                how_often_verifier,
            },
            active_epochs: BTreeMap::new(),
        }
    }

    pub(crate) fn start(
        mut self,
        votes: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        certificates: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        boundary_certificates: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(votes, certificates, resolver, boundary_certificates)
                .await
        )
    }

    async fn run(
        mut self,
        (vote_sender, vote_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        (certificate_sender, certificate_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        (resolver_sender, resolver_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        (mut boundary_certificate_sender, mut boundary_certificate_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let (mux, mut vote_mux, mut vote_backup) = Muxer::builder(
            self.context.with_label("vote_mux"),
            vote_sender,
            vote_receiver,
            self.config.mailbox_size,
        )
        .with_backup()
        .build();
        mux.start();

        let (mux, mut certificate_mux, mut certificate_global_sender) = Muxer::builder(
            self.context.with_label("certificate_mux"),
            certificate_sender,
            certificate_receiver,
            self.config.mailbox_size,
        )
        .with_global_sender()
        .build();
        mux.start();

        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.config.mailbox_size,
        );
        mux.start();

        // Create rate limiter for orchestrators
        let rate_limiter =
            RateLimiter::hashmap_with_clock(self.config.rate_limit, self.context.clone());

        loop {
            select!(
                message = vote_backup.next() => {
                    let Some((their_epoch, (from, _))) = message else {
                        error_span!("mux channel closed").in_scope(||
                            error!("vote p2p mux channel closed; exiting actor")
                        );
                        break;
                    };
                    let _: Result<_, _>  = self.handle_msg_for_unregistered_epoch(
                        &mut boundary_certificate_sender,
                        Epoch::new(their_epoch),
                        from,
                        &rate_limiter,
                    ).await;
                },

                message = boundary_certificate_receiver.recv() => {
                    let (from, payload) = match message {
                        Err(error) => {
                            error_span!("epoch channel closed").in_scope(||
                                error!(
                                    error = %eyre::Report::new(error),
                                    "epoch p2p channel closed; exiting actor",
                            ));
                        break;
                        }
                        Ok(msg) => msg,
                    };
                    let _: Result<_, _>  = self.handle_boundary_certificate_request(
                        from,
                        payload,
                        &mut certificate_global_sender)
                    .await;
                },

                msg = self.mailbox.next()=>  {
                    let Some(msg) = msg else {
                        warn_span!("mailboxes dropped").in_scope(||
                             warn!("all mailboxes dropped; exiting actor"
                        ));
                        break;
                    };
                    let cause = msg.cause;
                    match msg.activity {
                        super::ingress::Activity::Enter(enter) => {
                            let _: Result<_, _> = self
                                .enter(
                                    cause,
                                    enter,
                                    &mut vote_mux,
                                    &mut certificate_mux,
                                    &mut resolver_mux,
                                )
                                .await;
                        }
                        super::ingress::Activity::Exit(exit) => self.exit(cause, exit),
                    }
                },
            )
        }
    }

    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            %epoch,
            ?public,
            ?participants,
        ),
        err(level = Level::WARN)
    )]
    async fn enter(
        &mut self,
        cause: Span,
        EpochTransition {
            epoch,
            public,
            share,
            participants,
        }: EpochTransition,
        vote_mux: &mut MuxHandle<
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        >,
        certificates_mux: &mut MuxHandle<
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        >,
        resolver_mux: &mut MuxHandle<
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        >,
    ) -> eyre::Result<()> {
        ensure!(
            !self.active_epochs.contains_key(&epoch),
            "an engine for the entered epoch is already running; ignoring",
        );

        let n_participants = participants.len();
        // Register the new signing scheme with the scheme provider.
        let scheme = if let Some(share) = share {
            info!("we have a share for this epoch, participating as a signer",);
            Scheme::new(participants, &public, share)
        } else {
            info!("we don't have a share for this epoch, participating as a verifier",);
            Scheme::verifier(participants, &public)
        };
        assert!(
            self.config.scheme_provider.register(epoch, scheme.clone()),
            "a scheme must never be registered twice",
        );

        let is_signer = matches!(scheme, Scheme::Signer { .. });

        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
                blocker: self.config.blocker.clone(),
                automaton: self.config.application.clone(),
                relay: self.config.application.clone(),
                reporter: Reporters::from((
                    self.config.subblocks.clone(),
                    self.config.marshal.clone(),
                )),
                partition: format!(
                    "{partition_prefix}_consensus_epoch_{epoch}",
                    partition_prefix = self.config.partition_prefix
                ),
                mailbox_size: self.config.mailbox_size,
                epoch,
                namespace: crate::config::NAMESPACE.to_vec(),

                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                buffer_pool: self.config.buffer_pool.clone(),

                leader_timeout: self.config.time_to_propose,
                notarization_timeout: self.config.time_to_collect_notarizations,
                nullify_retry: self.config.time_to_retry_nullify_broadcast,
                fetch_timeout: self.config.time_for_peer_response,
                activity_timeout: self.config.views_to_track,
                skip_timeout: self.config.views_until_leader_skip,

                fetch_concurrent: crate::config::NUMBER_CONCURRENT_FETCHES,
                fetch_rate_per_peer: crate::config::RESOLVER_LIMIT,
            },
        );

        let vote = vote_mux.register(epoch.get()).await.unwrap();
        let certificate = certificates_mux.register(epoch.get()).await.unwrap();
        let resolver = resolver_mux.register(epoch.get()).await.unwrap();

        assert!(
            self.active_epochs
                .insert(epoch, engine.start(vote, certificate, resolver))
                .is_none(),
            "there must be no other active engine running: this was ensured at \
            the beginning of this method",
        );

        info!("started consensus engine backing the epoch");

        self.metrics.latest_participants.set(n_participants as i64);
        self.metrics.active_epochs.inc();
        self.metrics.latest_epoch.set(epoch.get() as i64);
        self.metrics.how_often_signer.inc_by(is_signer as u64);
        self.metrics.how_often_verifier.inc_by(!is_signer as u64);

        Ok(())
    }

    #[instrument(parent = &cause, skip_all, fields(epoch))]
    fn exit(&mut self, cause: Span, Exit { epoch }: Exit) {
        if let Some(engine) = self.active_epochs.remove(&epoch) {
            engine.abort();
            info!("stopped engine backing epoch");
        } else {
            warn!(
                "attempted to exit unknown epoch, but epoch was not backed by \
                an active engine",
            );
        }

        if !self.config.scheme_provider.delete(&epoch) {
            warn!(
                "attempted to delete scheme for epoch, but epoch had no scheme \
                registered"
            );
        }
    }

    /// Handles messages for epochs received on un-registered sub-channels.
    ///
    /// If `their_epoch` is known (equal to our current epoch or in the past),
    /// no action is taken.
    ///
    /// If `their_epoch` is in the future, then the finalization certificate for
    /// our latest epoch is requested from the sender.
    ///
    /// This makes use of commonware's backup channels: when starting a new
    /// engine, we register a new subchannel with the muxer and tagged with that
    /// epoch. Upon receiving a message on an un-registered epoch, the
    /// commonware p2p muxer will send the message to the backup channel, tagged
    /// with the unknown epoch.
    #[instrument(skip_all, fields(msg.epoch = %their_epoch, msg.from = %from), err(level = Level::INFO))]
    async fn handle_msg_for_unregistered_epoch<S, C, MW>(
        &mut self,
        boundary_certificate_sender: &mut impl Sender<PublicKey = PublicKey>,
        their_epoch: Epoch,
        from: PublicKey,
        rate_limiter: &RateLimiter<PublicKey, S, C, MW>,
    ) -> eyre::Result<()>
    where
        S: governor::state::keyed::KeyedStateStore<PublicKey>,
        C: governor::clock::Clock,
        MW: RateLimitingMiddleware<C::Instant>,
    {
        let Some(our_epoch) = self.active_epochs.keys().last().copied() else {
            return Err(eyre!(
                "received message over unregistered epoch channel, but we are \
                not running simplex engines backing any epochs",
            ));
        };
        ensure!(
            their_epoch > our_epoch,
            "request epoch `{their_epoch}` is in our past, no action is necessary",
        );

        ensure!(
            rate_limiter.check_key(&from).is_ok(),
            "sender `{from}` is rate limited",
        );

        let boundary_height = utils::last_block_in_epoch(self.config.epoch_length, our_epoch);
        ensure!(
            self.config
                .marshal
                .get_finalization(boundary_height)
                .await
                .is_none(),
            "finalization certificate for epoch `{our_epoch}` at boundary \
            height `{boundary_height}` is already known; no action necessary",
        );

        boundary_certificate_sender
            .send(Recipients::One(from), our_epoch.encode().freeze(), true)
            .await
            .wrap_err("failed request for finalization certificate of our epoch")?;

        info!("requested finalization certificate for our epoch");

        Ok(())
    }

    #[instrument(skip_all, fields(
        msg.from = %from,
        msg.payload_len = bytes.len(),
        msg.decoded_epoch = tracing::field::Empty,
    ), err(level = Level::WARN))]
    async fn handle_boundary_certificate_request(
        &mut self,
        from: PublicKey,
        bytes: Bytes,
        recovered_global_sender: &mut GlobalSender<impl Sender<PublicKey = PublicKey>>,
    ) -> eyre::Result<()> {
        let requested_epoch = Epoch::decode(bytes.as_ref())
            .wrap_err("failed decoding epoch channel payload as epoch")?;
        tracing::Span::current().record("msg.decoded_epoch", display(requested_epoch));
        let boundary_height = utils::last_block_in_epoch(self.config.epoch_length, requested_epoch);
        let cert = self
            .config
            .marshal
            .get_finalization(boundary_height)
            .await
            .ok_or_else(|| {
                eyre!(
                    "do not have finalization for requested epoch \
                    `{requested_epoch}`, boundary height `{boundary_height}` \
                    available locally; cannot serve request"
                )
            })?;
        let message = Certificate::<Scheme<PublicKey, MinSig>, Digest>::Finalization(cert);
        recovered_global_sender
            .send(
                requested_epoch.get(),
                Recipients::One(from),
                message.encode().freeze(),
                false,
            )
            .await
            .wrap_err(
                "failed forwarding finalization certificate to requester via `recovered` channel",
            )?;
        Ok(())
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
    latest_participants: Gauge,
    how_often_signer: Counter,
    how_often_verifier: Counter,
}
