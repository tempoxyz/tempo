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
//! The engine receives a subchannel of the vote, certificate, and resolver
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
//! If the actor now receives a vote in epoch 5 over its vote mux backup
//! channel (since there are no subchannels registered with the muxer on
//! epochs 1 through 5), it hints to the marshal actor that a finalization
//! certificate for the node's *current* epoch's boundary height must exist.
//!
//! Marshal fetches and verifies that certificate, then delivers the missing
//! blocks in order. Once the DKG manager processes the boundary block, it
//! persists the next epoch's state and instructs this actor to enter it.
//! Only that instruction installs the next epoch's scheme and allows hints
//! for its boundary. This repeats until the node catches up to the network.
use std::{collections::BTreeMap, num::NonZeroUsize};

use alloy_consensus::BlockHeader as _;
use commonware_consensus::{
    simplex::{self, config::Floor, elector, scheme::bls12381_threshold::vrf::Scheme},
    types::{Epoch, EpochDelta, Epocher as _, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{Builder as _, MuxHandle, Muxer},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Network, Spawner, Storage, spawn_cell,
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
};
use commonware_utils::{NZUsize, vec::NonEmptyVec};
use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{StreamExt as _, channel::mpsc};
use rand_core::{CryptoRng, Rng};
use reth_ethereum::chainspec::EthChainSpec;
use reth_provider::HeaderProvider as _;
use tempo_chainspec::TempoHardforks as _;
use tempo_primitives::TempoHeader;
use tracing::{Level, Span, debug, error, error_span, info, instrument, warn, warn_span};

use crate::{
    consensus::Digest,
    epoch::manager::ingress::{EpochTransition, Exit},
};

use super::ingress::{Content, Message};

const REPLAY_BUFFER: NonZeroUsize = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024); // 1MB

pub(crate) struct Actor<TContext, TBlocker> {
    active_epochs: BTreeMap<Epoch, Handle<()>>,
    config: super::Config<TBlocker>,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<Message>,
    metrics: Metrics,
}

impl<TContext, TBlocker> Actor<TContext, TBlocker>
where
    TBlocker: Blocker<PublicKey = PublicKey>,
    // TODO(janis): are all of these bounds necessary?
    TContext: BufferPooler
        + Spawner
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
        let active_epochs = context.gauge(
            "active_epochs",
            "the number of epochs currently managed by the epoch manager",
        );
        let latest_epoch = context.gauge(
            "latest_epoch",
            "the latest epoch managed by this epoch manager",
        );
        let latest_participants = context.gauge(
            "latest_participants",
            "the number of participants in the most recently started epoch",
        );
        let how_often_signer = context.counter(
            "how_often_signer",
            "how often a node is a signer; a node is a signer if it has a share",
        );
        let how_often_verifier = context.counter(
            "how_often_verifier",
            "how often a node is a verifier; a node is a verifier if it does not have a share",
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
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(votes, certificates, resolver))
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
    ) {
        let (mux, mut vote_mux, mut vote_backup) = Muxer::builder(
            self.context.child("vote_mux"),
            vote_sender,
            vote_receiver,
            self.config.mailbox_size.into(),
        )
        .with_backup()
        .build();
        mux.start();

        let (mux, mut certificate_mux) = Muxer::builder(
            self.context.child("certificate_mux"),
            certificate_sender,
            certificate_receiver,
            self.config.mailbox_size.into(),
        )
        .build();
        mux.start();

        let (mux, mut resolver_mux) = Muxer::new(
            self.context.child("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.config.mailbox_size.into(),
        );
        mux.start();

        loop {
            select!(
                message = vote_backup.recv() => {
                    let Some((their_epoch, (from, _))) = message else {
                        error_span!("mux channel closed").in_scope(||
                            error!("vote p2p mux channel closed; exiting actor")
                        );
                        break;
                    };
                    self.handle_msg_for_unregistered_epoch(
                        Epoch::new(their_epoch),
                        from,
                    ).await;
                },

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        warn_span!("mailboxes dropped").in_scope(||
                             warn!("all mailboxes dropped; exiting actor"
                        ));
                        break;
                    };
                    let cause = msg.cause;
                    match msg.content {
                        Content::Enter(enter) => {
                            if self
                                .enter(
                                    cause,
                                    enter,
                                    &mut vote_mux,
                                    &mut certificate_mux,
                                    &mut resolver_mux,
                                )
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Content::Exit(exit) => self.exit(cause, exit),
                    }
                },
            )
        }
    }

    /// Read a finalized header, falling back to EL headers if the block body is unavailable.
    async fn get_header(&mut self, height: Height) -> eyre::Result<TempoHeader> {
        if let Some(block) = self.config.marshal.get_block(height).await {
            return Ok(block.header().clone());
        }

        self.config
            .execution_node
            .provider
            .header_by_number(height.get())
            .wrap_err_with(|| format!("failed reading finalized header at height `{height}`"))?
            .ok_or_eyre(format!("missing finalized header at height `{height}`"))
    }

    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            %epoch,
            network_identity = %public.public(),
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
        if let Some(latest) = self.active_epochs.last_key_value().map(|(k, _)| *k) {
            ensure!(
                epoch > latest,
                "requested to start an epoch `{epoch}` older than the latest \
                running, `{latest}`; refusing",
            );
        }

        let n_participants = participants.len();

        // Register the new signing scheme with the scheme provider.
        let is_signer = matches!(share, Some(..));
        let scheme = if let Some(share) = share {
            info!("we have a share for this epoch, participating as a signer",);
            Scheme::signer(crate::config::NAMESPACE, participants, public, share)
                .expect("our private share must match our slice of the public key")
        } else {
            info!("we don't have a share for this epoch, participating as a verifier",);
            Scheme::verifier(crate::config::NAMESPACE, participants, public)
        };

        self.config.scheme_provider.register(epoch, scheme.clone());

        let (floor, boundary_timestamp) = match epoch.previous().map(|prev| {
            self.config
                .epoch_strategy
                .last(prev)
                .expect("epoch strategy valid for all epochs and heights")
        }) {
            Some(boundary_height) => {
                let (_, digest) = self
                    .config
                    .marshal
                    .get_info(boundary_height)
                    .await
                    .ok_or_else(|| {
                        eyre!(
                            "cannot start a consensus for epoch `{epoch}`, \
                            because we do not have information on the \
                            finalized block of its boundary height \
                            `{boundary_height}`"
                        )
                    })?;

                let header = self.get_header(boundary_height).await?;
                (Floor::Genesis(digest), header.timestamp())
            }
            None => {
                let chain_spec = self.config.execution_node.chain_spec();
                (
                    Floor::Genesis(Digest(chain_spec.genesis_hash())),
                    chain_spec.genesis_header().timestamp(),
                )
            }
        };

        // Each epoch constructs one elector. Use its preceding finalized boundary so nodes
        // choose the same version even when entering or restarting at different times.
        #[expect(deprecated, reason = "retain the pre-T12 leader schedule")]
        let elector = if self
            .config
            .execution_node
            .chain_spec()
            .tempo_hardfork_at(boundary_timestamp)
            .is_t12()
        {
            elector::RandomVersion::V1
        } else {
            elector::RandomVersion::V0
        };

        let engine_ctx = self.context.child("simplex").with_attribute("epoch", epoch);
        let engine = simplex::Engine::new(
            engine_ctx,
            simplex::Config {
                epoch,
                floor,
                scheme,
                elector: elector::Random::<commonware_cryptography::Sha256>::new(elector),
                strategy: Sequential,

                reporter: self.config.marshal.clone(),
                partition: format!(
                    "{partition_prefix}_consensus_epoch_{epoch}",
                    partition_prefix = self.config.partition_prefix
                ),

                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,

                blocker: self.config.blocker.clone(),
                automaton: self.config.application.clone(),
                relay: self.config.application.clone(),
                page_cache: self.config.page_cache.clone(),
                leader_timeout: self.config.time_to_propose,
                certification_timeout: self.config.time_to_collect_notarizations,
                timeout_retry: self.config.time_to_retry_nullify_broadcast,
                fetch_timeout: self.config.time_for_peer_response,
                view_retention: self.config.views_to_track,
                skip: simplex::config::SkipPolicy::Enabled {
                    timeout: self.config.inactive_time_before_leader_skip,
                    budget: simplex::config::SkipBudget::Participants,
                },

                mailbox_size: self.config.mailbox_size,
                forward: commonware_consensus::simplex::config::ForwardPolicy::Disabled,
                track_historical_votes: true,
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

        let _ = self.metrics.latest_epoch.metric().try_set(epoch.get());
        self.metrics.active_epochs.metric().inc();

        self.metrics
            .latest_participants
            .metric()
            .set(n_participants as i64);
        self.metrics
            .how_often_signer
            .metric()
            .inc_by(u64::from(is_signer));
        self.metrics
            .how_often_verifier
            .metric()
            .inc_by(u64::from(!is_signer));

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

        // XXX: Keep the last 2 epochs around: the marshal actor might get
        // finalization certificates from straggling nodes that have not yet
        // transitioned and are still (re-)propsing the boundary block of the
        // outgoing epoch with new certificate.
        //
        // If we delete the scheme too eagerly here, then i) we won't be able
        // to verify the certificate, ii) consider their message invalid, and
        // finally iii) block them because this is treated as Byzantine
        // behavior.
        if let Some(to_delete) = epoch.checked_sub(EpochDelta::new(2))
            && !self.config.scheme_provider.delete(&to_delete)
        {
            debug!(
                to_exit = %epoch,
                %to_delete,
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
    /// If `their_epoch` is in the future, then a hint is sent to the marshal
    /// actor that a boundary certificate could be fetched.
    #[instrument(
        skip_all,
        fields(msg.epoch = %their_epoch, msg.from = %from),
    )]
    async fn handle_msg_for_unregistered_epoch(&mut self, their_epoch: Epoch, from: PublicKey) {
        let Some(reference_epoch) = self.active_epochs.keys().last().copied() else {
            debug!("received message for unregistered epoch before DKG entered an epoch");
            return;
        };

        if reference_epoch >= their_epoch {
            return;
        }

        let boundary_height = self
            .config
            .epoch_strategy
            .last(reference_epoch)
            .expect("our epoch strategy should cover all epochs");

        tracing::debug!(
            %reference_epoch,
            %boundary_height,
            "hinting to sync system that a finalization certificate might be \
            available for our reference epoch",
        );

        self.config
            .marshal
            .hint_finalized(boundary_height, NonEmptyVec::new(from));
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
    latest_participants: Gauge,
    how_often_signer: Counter,
    how_often_verifier: Counter,
}
