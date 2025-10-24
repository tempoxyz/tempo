use std::{collections::BTreeMap, num::NonZeroUsize};

use commonware_consensus::{
    simplex::{self, signing_scheme::bls12381_threshold::Scheme},
    types::Epoch,
};
use commonware_cryptography::{Signer as _, ed25519::PublicKey};
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{MuxHandle, Muxer},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as _, Network, Spawner, Storage, spawn_cell,
};
use eyre::ensure;
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::gauge::Gauge;
use rand::{CryptoRng, Rng};
use tracing::{Level, Span, info, instrument, warn};

use crate::epoch::manager::ingress::{Enter, Exit};

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

        Self {
            config,
            context: ContextCell::new(context),
            mailbox,
            metrics: Metrics {
                active_epochs,
                latest_epoch,
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
        let (mux, mut pending_mux) = Muxer::new(
            self.context.with_label("pending_mux"),
            pending_sender,
            pending_receiver,
            self.config.mailbox_size,
        );
        mux.start();
        let (mux, mut recovered_mux) = Muxer::new(
            self.context.with_label("recovered_mux"),
            recovered_sender,
            recovered_receiver,
            self.config.mailbox_size,
        );
        mux.start();
        let (mux, mut resolver_mux) = Muxer::new(
            self.context.with_label("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.config.mailbox_size,
        );
        mux.start();

        while let Some(msg) = self.mailbox.next().await {
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
        // engine.start(pending_sc, recovered_sc, resolver_sc).await;

        info!("started consensus engine backing the epoch");

        self.metrics.active_epochs.inc();
        self.metrics.latest_epoch.set(epoch as i64);

        Ok(())
    }

    #[instrument(follows_from = [cause], skip_all, fields(epoch))]
    fn exit(&mut self, cause: Span, Exit { epoch }: Exit) {
        if let Some(engine) = self.active_epochs.remove(&epoch) {
            engine.abort()
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
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
}
