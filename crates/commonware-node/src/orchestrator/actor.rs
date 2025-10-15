use std::{collections::BTreeMap, num::NonZeroUsize};

use commonware_consensus::{Automaton as _, threshold_simplex, types::Epoch};
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{MuxHandle, Muxer},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as _, Network, Spawner, Storage, spawn_cell,
};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::FixedBytes;
use eyre::{bail, ensure};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::gauge::Gauge;
use rand::{CryptoRng, Rng};
use tempo_commonware_node_cryptography::{Digest, PublicKey};
use tracing::{Level, Span, info, instrument};

use crate::orchestrator::ingress::Activity;

use super::ingress::Message;

const METADATA_KEY: FixedBytes<12> = FixedBytes::new([
    b'O', b'R', b'C', b'H', b'E', b'S', b'T', b'R', b'A', b'T', b'O', b'R',
]);

const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB

pub(crate) struct Actor<TBlocker, TContext> {
    config: super::Config<TBlocker>,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    metrics: Metrics,
    epoch_to_engine: BTreeMap<u64, Handle<()>>,
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
            "the number of epochs currently managed by the orchestrator",
            active_epochs.clone(),
        );
        context.register(
            "latest_epoch",
            "the latest epoch managed by this orchestrator",
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
            epoch_to_engine: BTreeMap::new(),
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

        let mut metadata = Metadata::init(
            self.context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", self.config.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize orchestrator metadata");

        // Enter the initial epoch
        let (epoch, seed) = match metadata.get(&METADATA_KEY).cloned() {
            Some(val) => val,
            None => {
                let epoch = 0;
                let seed = self.config.application.genesis(epoch).await;
                (epoch, seed)
            }
        };

        let _ = self
            .begin_epoch(
                None,
                epoch,
                seed,
                &mut metadata,
                &mut pending_mux,
                &mut recovered_mux,
                &mut resolver_mux,
            )
            .await;

        // Wait for instructions to transition epochs.
        while let Some(msg) = self.mailbox.next().await {
            let cause = msg.cause;
            match msg.command {
                Activity::EpochBoundaryReached(epoch_boundary_reached) => {
                    let _: Result<_, _> = self
                        .begin_epoch(
                            Some(cause),
                            epoch_boundary_reached.epoch.saturating_add(1),
                            epoch_boundary_reached.seed,
                            &mut metadata,
                            &mut pending_mux,
                            &mut recovered_mux,
                            &mut resolver_mux,
                        )
                        .await;
                }
                Activity::EpochEntered(epoch_entered) => {
                    let _: Result<_, _> = self.sunset_epoch(cause, epoch_entered.epoch).await;
                }
            }
        }
    }

    /// Enters an epoch by sunsetting engines that came before.
    #[instrument(
        follows_from = [cause],
        skip_all,
        fields(epoch),
        err(level = Level::WARN),
    )]
    async fn sunset_epoch(&mut self, cause: Span, epoch: Epoch) -> eyre::Result<()> {
        let Some(last) = self.epoch_to_engine.last_key_value().map(|(last, _)| *last) else {
            bail!(
                "received a signal that epoch `{epoch}` was entered, but there was no engine at all running"
            );
        };

        ensure!(
            epoch == last,
            "epoch entered is `{epoch}`, but highest epoch running is `{last}`; ignoring signal",
        );

        let first = self
            .epoch_to_engine
            .first_key_value()
            .map(|(first, _)| *first)
            .expect("if there is a last entry, there must be a first entry in the map");

        for epoch in first..last {
            if let Some(engine) = self.epoch_to_engine.remove(&epoch) {
                // TODO(janis): this is very not-graceful. Is it ok to just nuke
                // the engine or do we need a cancellation token or some other
                // mechanism to take down the engine gracefully?
                info!(epoch, "closing consensus engine for epoch");
                engine.abort();
                self.metrics.active_epochs.dec();
            }
        }
        Ok(())
    }

    /// Begins a new epoch by spawning a consensus engine.
    #[expect(
        clippy::too_many_arguments,
        reason = "can make this into a struct at the cost of simplicity"
    )]
    #[expect(for_loops_over_fallibles, reason = "inside expanded proc macro code")]
    #[instrument(
        follows_from = cause,
        skip_all,
        fields(
            %incoming_epoch,
            %seed,
        ),
        err(level = Level::WARN),
    )]
    async fn begin_epoch(
        &mut self,
        cause: Option<Span>,
        incoming_epoch: Epoch,
        seed: Digest,
        metadata: &mut Metadata<ContextCell<TContext>, FixedBytes<12>, (Epoch, Digest)>,
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
        if let Some((epoch, _)) = self.epoch_to_engine.last_key_value() {
            ensure!(
                &incoming_epoch > epoch,
                "highest epoch running is `{epoch}`; either incoming epoch \
                `{incoming_epoch}` was already begun or is too old"
            );
        }

        let _ = metadata
            .put_sync(METADATA_KEY, (incoming_epoch, seed))
            .await;

        let engine = threshold_simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            threshold_simplex::Config {
                crypto: self.config.signer.clone(),
                blocker: self.config.blocker.clone(),
                automaton: self.config.application.clone(),
                relay: self.config.application.clone(),
                reporter: self.config.marshal.clone(),
                supervisor: self.config.supervisor.clone(),
                partition: format!(
                    "{partition_prefix}_consensus_epoch_{incoming_epoch}",
                    partition_prefix = self.config.partition_prefix
                ),
                mailbox_size: self.config.mailbox_size,
                epoch: incoming_epoch,
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

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(incoming_epoch as u32).await.unwrap();
        let recovered_sc = recovered_mux.register(incoming_epoch as u32).await.unwrap();
        let resolver_sc = resolver_mux.register(incoming_epoch as u32).await.unwrap();

        assert!(
            self.epoch_to_engine
                .insert(
                    incoming_epoch,
                    engine.start(pending_sc, recovered_sc, resolver_sc),
                )
                .is_none(),
            "epoch `{incoming_epoch} must not already be backed by a consensus engine",
        );

        self.metrics.active_epochs.inc();
        self.metrics.latest_epoch.set(incoming_epoch as i64);

        Ok(())
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
}
