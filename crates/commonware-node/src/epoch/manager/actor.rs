use std::{collections::BTreeMap, num::NonZeroUsize};

use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::{self, signing_scheme::bls12381_threshold::Scheme, types::Voter},
    types::Epoch,
};
use commonware_cryptography::{
    Signer as _, bls12381::primitives::variant::MinSig, ed25519::PublicKey,
};
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
use prometheus_client::metrics::gauge::Gauge;
use rand::{CryptoRng, Rng};
use tracing::{Level, Span, info, instrument, warn, warn_span};

use crate::{
    consensus::Digest,
    epoch::{
        self,
        manager::ingress::{Enter, Exit},
    },
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

        Self {
            config,
            context: ContextCell::new(context),
            mailbox,
            metrics: Metrics {
                active_epochs,
                latest_epoch,
                latest_participants,
            },
            active_epochs: BTreeMap::new(),
        }
    }

    pub(crate) fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(pending, recovered, resolver).await)
    }

    async fn run(
        mut self,
        (pending_sender, pending_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        (recovered_sender, recovered_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        (resolver_sender, resolver_receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let (mux, mut pending_mux, mut pending_backup) = Muxer::builder(
            self.context.with_label("pending_mux"),
            pending_sender,
            pending_receiver,
            self.config.mailbox_size,
        )
        .with_backup()
        .build();
        mux.start();

        let (mux, mut recovered_mux, mut recovered_global_sender) = Muxer::builder(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
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

        loop {
            select!(
                message = pending_backup.next() => {
                    let Some((epoch, (from, _))) = message else {
                        warn_span!("mux channel closed").in_scope(||
                            warn!("pending p2p mux channel closed; exiting actor"
                        ));
                        break;
                    };
                    let _: Result<_, _>  = self.handle_msg_for_unknown_epoch(
                        &mut recovered_global_sender,
                        epoch,
                        from,
                    ).await;
                },

                msg = self.mailbox.next()=>  {
                    let Some(msg) = msg else {
                        warn_span!("mailboxes dropped").in_scope(|| warn!("all mailboxes dropped; exiting actor"));
                        break;
                    };
                    let cause = msg.cause;
                    match msg.activity {
                        super::ingress::Activity::Enter(enter) => {
                            let _: Result<_, _> = self
                                .enter(
                                    cause,
                                    enter,
                                    &mut pending_mux,
                                    &mut recovered_mux,
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
        follows_from = [cause],
        skip_all,
        fields(
            %epoch,
            ?public,
            ?share,
            ?participants,
        ),
        err(level = Level::WARN)
    )]
    async fn enter(
        &mut self,
        cause: Span,
        Enter {
            epoch,
            public,
            share,
            participants,
        }: Enter,
        pending_mux: &mut MuxHandle<
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        >,
        recovered_mux: &mut MuxHandle<
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

        // Register the new signing scheme with the scheme provider.
        let scheme = if let Some(share) = share {
            Scheme::new(participants.as_ref(), &public, share)
        } else {
            Scheme::verifier(participants.as_ref(), &public)
        };
        assert!(self.config.scheme_provider.register(epoch, scheme.clone()));

        self.metrics
            .latest_participants
            .set(participants.len() as i64);
        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                me: self.config.me.public_key(),
                participants,
                scheme,
                blocker: self.config.blocker.clone(),
                automaton: self.config.application.clone(),
                relay: self.config.application.clone(),
                reporter: self.config.marshal.clone(),
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

                max_fetch_count: crate::config::NUMBER_MAX_FETCHES,
                fetch_concurrent: crate::config::NUMBER_CONCURRENT_FETCHES,
                fetch_rate_per_peer: crate::config::RESOLVER_LIMIT,
            },
        );

        let pending_sc = pending_mux.register(epoch).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch).await.unwrap();

        assert!(
            self.active_epochs
                .insert(epoch, engine.start(pending_sc, recovered_sc, resolver_sc))
                .is_none(),
            "there must be no other active engine running: this was ensured at \
            the beginning of this method",
        );

        info!("started consensus engine backing the epoch");

        self.metrics.active_epochs.inc();
        self.metrics.latest_epoch.set(epoch as i64);

        Ok(())
    }

    #[instrument(follows_from = [cause], skip_all, fields(epoch))]
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
    /// This makes use of commonware's backup channels: when starting a new
    /// engine, we register a new subchannel with the muxer and tagged with that
    /// epoch. Upon receiving a message on an un-registered epoch, the
    /// commonware p2p muxer will send the message to the backup channel, tagged
    /// with unknown epoch.
    #[instrument(skip_all, fields(msg.epoch = epoch, msg.from = %from), err(level = Level::WARN))]
    async fn handle_msg_for_unknown_epoch(
        &mut self,
        recovered_global_sender: &mut GlobalSender<impl Sender<PublicKey = PublicKey>>,
        epoch: Epoch,
        from: PublicKey,
    ) -> eyre::Result<()> {
        let Some(latest_epoch) = self.active_epochs.keys().last().copied() else {
            return Err(eyre!(
                "received message over unregistered epoch channel, but we have no active epochs at all"
            ));
        };
        ensure!(
            epoch < latest_epoch,
            "sender seems to be ahead of us; our latest running epoch: {latest_epoch}",
        );

        let boundary_height = epoch::last_height(epoch, self.config.epoch_length);
        let Some(finalization) = self.config.marshal.get_finalization(boundary_height).await else {
            return Err(eyre!(
                "boundary height `{boundary_height}` of epoch is not locally known; peer needs to ask a nother node"
            ));
        };

        info!(
            boundary_height,
            "found certificate for boundary height `{boundary_height}`, forwarding to peer"
        );

        // Forward the finalization to the sender. This operation is best-effort.
        let message = Voter::<Scheme<MinSig>, Digest>::Finalization(finalization);
        let res = recovered_global_sender
            .send(
                epoch,
                Recipients::One(from),
                message.encode().freeze(),
                true,
            )
            .await
            .wrap_err("failed handing finalization certificate to p2p network")?;
        ensure!(
            !res.is_empty(),
            "failed forwarding finalization certificate to peer",
        );
        Ok(())
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
    latest_participants: Gauge,
}
