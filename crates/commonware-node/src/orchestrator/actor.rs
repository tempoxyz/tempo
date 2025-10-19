use std::num::NonZeroUsize;

use commonware_consensus::{threshold_simplex, types::Epoch};
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{MuxHandle, Muxer},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as _, Network, Spawner, Storage, spawn_cell,
};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U32;
use eyre::{WrapErr as _, bail};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::gauge::Gauge;
use rand::{CryptoRng, Rng};
use tempo_commonware_node_cryptography::PublicKey;
use tracing::{Level, Span, info, instrument, warn};

use crate::orchestrator::ingress::Activity;

use super::ingress::Message;

const ACTIVE_EPOCH_KEY: u32 = 0;
const PREVIOUS_EPOCH_KEY: u32 = 1;

const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB

pub(crate) struct Actor<TBlocker, TContext> {
    config: super::Config<TBlocker>,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    metrics: Metrics,
    active_epoch: Option<(u64, Handle<()>)>,
    previous_epoch: Option<(u64, Handle<()>)>,
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
            active_epoch: None,
            previous_epoch: None,
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
                partition: format!("{}_metadata", self.config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize orchestrator metadata");

        let previous = metadata.get(&U32::from(PREVIOUS_EPOCH_KEY)).copied();
        let active = metadata
            .get(&U32::from(ACTIVE_EPOCH_KEY))
            .copied()
            .inspect(|epoch| info!(epoch, "recovered rising epoch from disk"))
            .unwrap_or_else(|| {
                info!("no rising epoch found on disk; starting from 0");
                0
            });

        if let Some(previous) = previous {
            info!(previous, "recovered previous epoch from disk");
            assert!(
                previous < active,
                "invariant violated: active epoch `{active}` must be greater \
                than previous epoch `{previous}`",
            );
            let _ = self
                .begin_epoch::<false>(
                    None,
                    previous,
                    &mut metadata,
                    &mut pending_mux,
                    &mut recovered_mux,
                    &mut resolver_mux,
                )
                .await;
        }
        let _ = self
            .begin_epoch::<true>(
                None,
                active,
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
                        .begin_epoch::<true>(
                            Some(cause),
                            epoch_boundary_reached.epoch.saturating_add(1),
                            &mut metadata,
                            &mut pending_mux,
                            &mut recovered_mux,
                            &mut resolver_mux,
                        )
                        .await;
                }
                Activity::EpochEntered(epoch_entered) => {
                    let _: Result<_, _> = self
                        .end_previous_epoch(cause, epoch_entered.epoch, &mut metadata)
                        .await;
                }
            }
        }
    }

    /// Stops the previous epoch.
    #[instrument(
        follows_from = [cause],
        skip_all,
        fields(epoch),
        err(level = Level::WARN),
    )]
    async fn end_previous_epoch(
        &mut self,
        cause: Span,
        epoch: Epoch,
        metadata: &mut Metadata<ContextCell<TContext>, U32, Epoch>,
    ) -> eyre::Result<()> {
        let Some((running, engine)) = self.previous_epoch.take() else {
            bail!(
                "attempted to stop the engine backing the epoch before the \
                new epoch `{epoch}`, but no engine was running; that does not \
                affect the currently running epoch but should not happen"
            );
        };
        engine.abort();

        if let Some(stored) = metadata.remove(&PREVIOUS_EPOCH_KEY.into())
            && running != stored
        {
            warn!(
                stored,
                running,
                "the outgoing epoch stored on disk did not match the one \
                running; still deleting it from disk and stopping the engine, \
                but but this should not happen",
            );
        }
        metadata
            .sync()
            .await
            .wrap_err("failed deleting information on previous epoch from disk")
    }

    /// Begins a new epoch by spawning a consensus engine backing it.
    ///
    /// Also starts the process of sunsetting the previously active epoch.
    ///
    /// # Note on the const generic
    ///
    /// The method is also used to spin up the previous epoch on startup. This
    /// epoch must not however overwrite the active epoch written to disk.
    /// Therefore we make use of const generic: if `IS_ACTIVE`, then the
    /// active epoch is written to disk.
    ///
    /// Due to monomorphization we end up with 2 different methods: one for
    /// startup, and one for normal operation.
    #[expect(for_loops_over_fallibles, reason = "inside expanded proc macro code")]
    #[instrument(
        follows_from = cause,
        skip_all,
        fields(%epoch, is_starting_active_epoch = IS_ACTIVE),
        err(level = Level::WARN),
    )]
    async fn begin_epoch<const IS_ACTIVE: bool>(
        &mut self,
        cause: Option<Span>,
        epoch: Epoch,
        metadata: &mut Metadata<ContextCell<TContext>, U32, Epoch>,
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
        if let Some((current, engine)) = self.active_epoch.take() {
            if epoch <= current {
                self.active_epoch = Some((current, engine));
                bail!(
                    "current epoch is `{current}`, but epoch to be started is \
                    `{epoch}`; this means it's either already started or too old; \
                    ignoring the request",
                );
            }

            if let Some(old) = self.previous_epoch.replace((current, engine)) {
                warn!(
                    current_epoch = current,
                    straggling_epoch = old.0,
                    "sunsetting current epoch but an even older epoch was not \
                    yet completely wound down; stopping it down now but this \
                    should not happen",
                );
                old.1.abort();
            }
            metadata.put(PREVIOUS_EPOCH_KEY.into(), current);
        }

        if IS_ACTIVE {
            metadata.put(ACTIVE_EPOCH_KEY.into(), epoch);
        }
        let _ = metadata.sync().await;

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

        // Create epoch-specific subchannels
        let pending_sc = pending_mux.register(epoch as u32).await.unwrap();
        let recovered_sc = recovered_mux.register(epoch as u32).await.unwrap();
        let resolver_sc = resolver_mux.register(epoch as u32).await.unwrap();

        assert!(
            self.active_epoch
                .replace((epoch, engine.start(pending_sc, recovered_sc, resolver_sc),))
                .is_none(),
            "there must be no engine running at this point because it was shifted to sunsetting at the beginning of this method",
        );

        self.metrics.active_epochs.inc();
        self.metrics.latest_epoch.set(epoch as i64);

        Ok(())
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
}
