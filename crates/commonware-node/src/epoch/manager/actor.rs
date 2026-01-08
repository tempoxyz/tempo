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

use alloy_consensus::BlockHeader as _;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Reporters,
    marshal::Update,
    simplex::{self, elector, scheme::bls12381_threshold::Scheme},
    types::{Epoch, Epocher as _, Height},
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Sender,
    utils::mux::{Builder as _, MuxHandle, Muxer},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as _, Network, Spawner, Storage, spawn_cell,
};
use commonware_utils::{Acknowledgement as _, vec::NonEmptyVec};
use eyre::{ensure, eyre};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand::{CryptoRng, Rng};
use tracing::{Level, Span, debug, error, error_span, info, instrument, warn, warn_span};

use crate::{
    consensus::Digest,
    epoch::manager::ingress::{EpochTransition, Exit},
};

use super::ingress::{Content, Message};

const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB

pub(crate) struct Actor<TBlocker, TContext> {
    active_epochs: BTreeMap<Epoch, Handle<()>>,
    config: super::Config<TBlocker>,
    context: ContextCell<TContext>,
    confirmed_latest_network_epoch: Option<Epoch>,
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
            confirmed_latest_network_epoch: None,
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
        spawn_cell!(self.context, self.run(votes, certificates, resolver).await)
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
            self.context.with_label("vote_mux"),
            vote_sender,
            vote_receiver,
            self.config.mailbox_size,
        )
        .with_backup()
        .build();
        mux.start();

        let (mux, mut certificate_mux) = Muxer::builder(
            self.context.with_label("certificate_mux"),
            certificate_sender,
            certificate_receiver,
            self.config.mailbox_size,
        )
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
                message = vote_backup.next() => {
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
                        Content::Exit(exit) => self.exit(cause, exit),
                        Content::Update(update) => {
                            match *update {
                                Update::Tip(height, digest) => {
                                    let _ = self.handle_finalized_tip(height, digest).await;
                                }
                                Update::Block(_block, ack) => {
                                    ack.acknowledge();
                                }
                            }
                        }
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
            Scheme::signer(
                crate::config::NAMESPACE,
                participants,
                public,
                share,
                Sequential,
            )
            .expect("our private share must match our slice of the public key")
        } else {
            info!("we don't have a share for this epoch, participating as a verifier",);
            Scheme::verifier(crate::config::NAMESPACE, participants, public, Sequential)
        };
        self.config.scheme_provider.register(epoch, scheme.clone());

        let engine = simplex::Engine::new(
            self.context.with_label("consensus_engine"),
            simplex::Config {
                scheme,
                elector: elector::Random,
                blocker: self.config.blocker.clone(),
                automaton: self.config.application.clone(),
                relay: self.config.application.clone(),
                reporter: Reporters::from((
                    self.config.subblocks.clone(),
                    Reporters::from((self.config.marshal.clone(), self.config.feed.clone())),
                )),
                partition: format!(
                    "{partition_prefix}_consensus_epoch_{epoch}",
                    partition_prefix = self.config.partition_prefix
                ),
                mailbox_size: self.config.mailbox_size,
                epoch,

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

        let latest = self.confirmed_latest_network_epoch.get_or_insert(epoch);
        *latest = (*latest).max(epoch);

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

    #[instrument(
        skip_all,
        fields(%height, epoch = tracing::field::Empty),
        err,
    )]
    async fn handle_finalized_tip(&mut self, height: Height, digest: Digest) -> eyre::Result<()> {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(height)
            .expect("epoch strategy is valid for all epochs and heights");
        Span::current().record("epoch", tracing::field::display(epoch_info.epoch()));

        {
            let network_epoch = self
                .confirmed_latest_network_epoch
                .get_or_insert(epoch_info.epoch());
            *network_epoch = (*network_epoch).max(epoch_info.epoch());
        }

        // If the tip contains a boundary block, then:
        //
        // 1. request the block from the marshal actor;
        // 2. read the DKG outcome from the block header;
        // 3. register the DKG scheme on the scheme provider;
        // 4. set the confirmed network height to the value in the on-chain
        // DKG outcome.
        //
        // This soft enters the new epoch without spinning up a new simplex
        // engine, and allows the epoch manager to forward more finalization
        // hints to the marshal actor.
        if epoch_info.last() == height {
            info!(
                "the finalized tip is a boundary block; requesting the \
                block to set the scheme for its epoch"
            );
            let block = self
                .config
                .marshal
                .subscribe(None, digest)
                .await
                .await
                .map_err(|_| eyre!("marshal never returned the block"))?;
            let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
                &mut block.header().extra_data().as_ref(),
            )
            .expect("boundary blocks must contain DKG outcomes");
            self.config.scheme_provider.register(
                onchain_outcome.epoch,
                Scheme::verifier(
                    crate::config::NAMESPACE,
                    onchain_outcome.players().clone(),
                    onchain_outcome.sharing().clone(),
                    Sequential,
                ),
            );
            self.confirmed_latest_network_epoch
                .replace(onchain_outcome.epoch);
            debug!(
                next_epoch = %onchain_outcome.epoch,
                "read DKG outcome from boundary and registered scheme",
            );
        }
        Ok(())
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
        let reference_epoch = match (
            self.active_epochs.keys().last().copied(),
            self.confirmed_latest_network_epoch,
        ) {
            (Some(our), None) => our,
            (Some(our), Some(confirmed_finalized)) => our.max(confirmed_finalized),
            (None, Some(confirmed_finalized)) => confirmed_finalized,
            (None, None) => {
                debug!(
                    "received message for unregistered epoch, but we are \
                    neither running a consensus engine backing an epoch, nor \
                    do we know what the latest finalized epoch is; there is \
                    nothing to do",
                );
                return;
            }
        };

        if reference_epoch >= their_epoch {
            debug!(
                %reference_epoch,
                "message is for current or past epoch; no action necessary",
            );
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
            .hint_finalized(boundary_height, NonEmptyVec::new(from))
            .await;
    }
}

struct Metrics {
    active_epochs: Gauge,
    latest_epoch: Gauge,
    latest_participants: Gauge,
    how_often_signer: Counter,
    how_often_verifier: Counter,
}
