use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use commonware_codec::{
    Encode as _, EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_consensus::{Block as _, Reporter, types::Epoch, utils};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_p2p::{
    Receiver, Sender,
    utils::{mux, mux::MuxHandle},
};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics as _, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{
    Acknowledgement, quorum,
    sequence::FixedBytes,
    set::{Ordered, OrderedAssociated},
    union,
};

use eyre::{OptionExt as _, eyre};
use futures::{StreamExt as _, channel::mpsc};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_node::TempoFullNode;
use tracing::{Span, error, info, instrument, warn};

use crate::{
    consensus::block::Block,
    db::{MetadataDatabase, ReadWriteTransaction},
    dkg::{
        ceremony::{self, Ceremony, OUTCOME_NAMESPACE},
        manager::{
            DecodedValidator,
            ingress::{Finalize, GetIntermediateDealing, GetOutcome},
            validators::{self, ValidatorState},
        },
    },
    epoch,
};

pub mod post_allegretto;
pub mod pre_allegretto;

pub(crate) struct Actor<TContext, TPeerManager>
where
    TContext: Clock + commonware_runtime::Metrics + Storage,
    TPeerManager: commonware_p2p::Manager,
{
    /// The actor configuration passed in when constructing the actor.
    config: super::Config<TPeerManager>,

    /// The runtime context passed in when constructing the actor.
    context: ContextCell<TContext>,

    /// The channel over which the actor will receive messages.
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    /// The unified database for all DKG-related state.
    db: MetadataDatabase<ContextCell<TContext>>,

    /// Handles to the metrics objects that the actor will update during its
    /// runtime.
    metrics: Metrics,
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        > + Sync,
{
    pub(super) async fn new(
        config: super::Config<TPeerManager>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let context = ContextCell::new(context);

        // Initialize the unified metadata database
        let metadata: Metadata<ContextCell<TContext>, FixedBytes<32>, Bytes> = Metadata::init(
            context.with_label("database"),
            metadata::Config {
                partition: format!("{}_database", config.partition_prefix),
                codec_config: RangeCfg::from(0..=usize::MAX),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let db = MetadataDatabase::new(metadata);

        // Run migration from old metadata stores if needed
        {
            let mut tx = db.read_write();
            super::migrate::maybe_migrate_to_db(&context, &config.partition_prefix, &mut tx)
                .await?;
            tx.set_node_version(env!("CARGO_PKG_VERSION").to_string());
            tx.commit().await?;
        }

        let syncing_players = Gauge::default();

        let peers = Gauge::default();

        let pre_allegretto_ceremonies = Counter::default();
        let post_allegretto_ceremonies = Counter::default();
        let failed_allegretto_transitions = Counter::default();

        context.register(
            "syncing_players",
            "how many syncing players were registered; these will become players in the next ceremony",
            syncing_players.clone(),
        );

        context.register(
            "peers",
            "how many peers are registered overall for the latest epoch",
            peers.clone(),
        );

        context.register(
            "pre_allegretto_ceremonies",
            "how many ceremonies the node ran pre-allegretto",
            pre_allegretto_ceremonies.clone(),
        );
        context.register(
            "post_allegretto_ceremonies",
            "how many ceremonies the node ran post-allegretto",
            post_allegretto_ceremonies.clone(),
        );

        context.register(
            "failed_allegretto_transitions",
            "how many transitions from pre- to post-allegretto failed",
            failed_allegretto_transitions.clone(),
        );

        let ceremony = ceremony::Metrics::register(&context);

        let metrics = Metrics {
            peers,
            syncing_players,
            pre_allegretto_ceremonies,
            post_allegretto_ceremonies,
            failed_allegretto_transitions,
            ceremony,
        };

        Ok(Self {
            config,
            context,
            mailbox,
            db,
            metrics,
        })
    }

    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let mut tx = self.db.read_write();

        // Emits an error event on return.
        if self.post_allegretto_init(&mut tx).await.is_err() {
            return;
        }
        // Emits an error event on return.
        if self.pre_allegretto_init(&mut tx).await.is_err() {
            return;
        }

        self.register_previous_epoch_state(&mut tx).await;
        self.register_current_epoch_state(&mut tx).await;

        let (mux, mut ceremony_mux) = mux::Muxer::new(
            self.context.with_label("ceremony_mux"),
            sender,
            receiver,
            self.config.mailbox_size,
        );
        mux.start();

        let mut ceremony = Some(
            self.start_ceremony_for_current_epoch_state(&mut tx, &mut ceremony_mux)
                .await,
        );

        tx.commit().await.expect("must be able to commit init tx");

        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
                super::Command::Finalize(finalize) => {
                    self.handle_finalized(cause, finalize, &mut ceremony, &mut ceremony_mux)
                        .await;
                }
                super::Command::GetIntermediateDealing(get_ceremony_deal) => {
                    let _: Result<_, _> = self
                        .handle_get_intermediate_dealing(
                            cause,
                            get_ceremony_deal,
                            ceremony.as_mut(),
                        )
                        .await;
                }
                super::Command::GetOutcome(get_ceremony_outcome) => {
                    let _: Result<_, _> =
                        self.handle_get_outcome(cause, get_ceremony_outcome).await;
                }

                // Verifies some DKG dealing based on the current state the DKG manager
                // is in. This is a request when verifying proposals. It relies on the
                // fact that a new epoch (and hence a different hardfork regime) will
                // only be entered once the finalized height of the current epoch was seen.
                //
                // Furthermore, extra data headers are only checked for intermediate
                // dealings up but excluding the last height of an epoch.
                //
                // In other words: no dealing will ever have to be verified if it is
                // for another epoch than the currently latest one.
                super::Command::VerifyDealing(verify_dealing) => {
                    let mut tx = self.db.read_write();
                    let outcome = if tx.has_post_allegretto_state().await {
                        verify_dealing
                            .dealing
                            .verify(&union(&self.config.namespace, OUTCOME_NAMESPACE))
                    } else if tx.has_pre_allegretto_state().await {
                        verify_dealing.dealing.verify_pre_allegretto(&union(
                            &self.config.namespace,
                            OUTCOME_NAMESPACE,
                        ))
                    } else {
                        error!("could not determine if we are running pre- or post allegretto;");
                        continue;
                    };
                    let _ = verify_dealing.response.send(outcome);
                }
            }
        }
    }

    pub(crate) fn start(
        mut self,
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(dkg_channel).await)
    }

    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            request.epoch = epoch,
            ceremony.epoch = ceremony.as_ref().map(|c| c.epoch()),
        ),
        err,
    )]
    async fn handle_get_intermediate_dealing<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetIntermediateDealing { epoch, response }: GetIntermediateDealing,
        ceremony: Option<&mut Ceremony<TReceiver, TSender>>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let ceremony =
            ceremony.ok_or_eyre("no ceremony running, can't serve intermediate dealings")?;
        let mut outcome = None;

        'get_outcome: {
            if ceremony.epoch() != epoch {
                warn!(
                    ceremony.epoch = %ceremony.epoch(),
                    "deal outcome for ceremony of different epoch requested",
                );
                break 'get_outcome;
            }
            outcome = ceremony.deal_outcome().cloned();
        }

        response
            .send(outcome)
            .map_err(|_| eyre!("failed returning outcome because requester went away"))
    }

    #[instrument(
        parent = &cause,
        skip_all,
        err,
    )]
    async fn handle_get_outcome(
        &mut self,
        cause: Span,
        GetOutcome { response }: GetOutcome,
    ) -> eyre::Result<()> {
        let mut tx = self.db.read_write();

        let outcome = tx.get_public_outcome().await?.ok_or_else(|| {
            eyre!(
                "no DKG outcome was found in state, even though it must exist \
                - derived from the epoch state from either the pre- or \
                post-allegretto logic"
            )
        })?;

        response
            .send(outcome)
            .map_err(|_| eyre!("failed returning outcome because requester went away"))
    }

    /// Handles a finalized block.
    ///
    /// Some block heights are special cased:
    ///
    /// + first height of an epoch: notify the epoch manager that the previous
    ///   epoch can be shut down.
    /// + pre-to-last height of an epoch: finalize the ceremony and generate the
    ///   the state for the next ceremony.
    /// + last height of an epoch:
    ///     1. notify the epoch manager that a new epoch can be entered;
    ///     2. start a new ceremony by reading the validator config smart
    ///        contract
    ///
    /// The processing of all other blocks depends on which part of the epoch
    /// they fall in:
    ///
    /// + first half: if we are a dealer, distribute the generated DKG shares
    ///   to the players and collect their acks. If we are a player, receive
    ///   DKG shares and respond with an ack.
    /// + exact middle of an epoch: if we are a dealer, generate the dealing
    ///   (the intermediate outcome) of the ceremony.
    /// + second half of an epoch: if we are a dealer, send it to the application
    ///   if a request comes in (the application is supposed to add this to the
    ///   block it is proposing). Always attempt to read dealings from the blocks
    ///   and track them (if a dealer or player both).
    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            block.derived_epoch = utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            ceremony.epoch = maybe_ceremony.as_ref().map(|c| c.epoch()),
        ),
    )]
    async fn handle_finalized<TReceiver, TSender>(
        &mut self,
        cause: Span,
        Finalize {
            block,
            acknowledgment,
        }: Finalize,
        maybe_ceremony: &mut Option<Ceremony<TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let mut tx = self.db.read_write();

        if self.is_running_post_allegretto(&block, &mut tx).await {
            self.handle_finalized_post_allegretto(
                cause,
                *block,
                maybe_ceremony,
                ceremony_mux,
                &mut tx,
            )
            .await;
        } else {
            self.handle_finalized_pre_allegretto(
                cause,
                *block,
                maybe_ceremony,
                ceremony_mux,
                &mut tx,
            )
            .await;
        }

        tx.commit()
            .await
            .expect("must be able to commit finalize tx");
        acknowledgment.acknowledge();
    }

    /// Starts a new ceremony for the epoch state tracked by the actor.
    #[instrument(skip_all, fields(me = %self.config.me.public_key(), current_epoch = tracing::field::Empty))]
    async fn start_ceremony_for_current_epoch_state<TReceiver, TSender>(
        &mut self,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        Span::current().record("current_epoch", self.current_epoch_state(tx).await.epoch());
        if tx.has_post_allegretto_state().await {
            self.start_post_allegretto_ceremony(tx, mux).await
        } else {
            self.start_pre_allegretto_ceremony(tx, mux).await
        }
    }

    /// Registers the new epoch by reporting to the epoch manager that it should
    /// be entered and registering its peers on the peers manager.
    #[instrument(skip_all, fields(epoch = tracing::field::Empty))]
    async fn register_current_epoch_state(
        &mut self,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    ) {
        let epoch_state = self.current_epoch_state(tx).await;
        Span::current().record("epoch", epoch_state.epoch());

        if let Some(previous_epoch) = epoch_state.epoch().checked_sub(1)
            && let boundary_height =
                utils::last_block_in_epoch(self.config.epoch_length, previous_epoch)
            && let None = self.config.marshal.get_info(boundary_height).await
        {
            info!(
                boundary_height,
                previous_epoch,
                "don't have the finalized boundary block of the previous epoch; \
                this usually happens if the node restarted right after processing \
                the the pre-to-last block; not starting a consensus engine backing \
                the current epoch because the boundary block is its \"genesis\""
            );
            return;
        }

        let new_validator_state = match &epoch_state {
            EpochState::PreModerato(epoch_state) => tx
                .get_validators(epoch_state.epoch().saturating_sub(1))
                .await
                .expect("must be able to read validators")
                .expect(
                    "there must always be a validator state for the previous \
                    epoch state written for pre-allegretto logic; this is \
                    ensured at startup",
                ),
            EpochState::PostModerato(epoch_state) => epoch_state.validator_state.clone(),
        };

        tx.set_validators(epoch_state.epoch(), new_validator_state.clone());

        self.config
            .epoch_manager
            .report(
                epoch::Enter {
                    epoch: epoch_state.epoch(),
                    public: epoch_state.public_polynomial().clone(),
                    share: epoch_state.private_share().clone(),
                    participants: epoch_state.participants().clone(),
                }
                .into(),
            )
            .await;
        info!(
            epoch = epoch_state.epoch(),
            participants = ?epoch_state.participants(),
            public = alloy_primitives::hex::encode(epoch_state.public_polynomial().encode()),
            "reported epoch state to epoch manager",
        );
        self.register_validators(epoch_state.epoch(), new_validator_state)
            .await;
    }

    /// Reports that the previous epoch should be entered.
    ///
    /// This method is called on startup to ensure that a consensus engine for
    /// the previous epoch i-1 is started in case the node went down before the
    /// new epoch i was firmly locked in.
    ///
    /// This method also registers the validators for epochs i-1 and i-2.
    ///
    /// # Panics
    ///
    /// Panics if no current epoch state exists on disk.
    #[instrument(skip_all, fields(previous_epoch = tracing::field::Empty))]
    async fn register_previous_epoch_state(
        &mut self,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    ) {
        if let Some(epoch_state) = self.previous_epoch_state(tx).await {
            Span::current().record("previous_epoch", epoch_state.epoch());
            self.config
                .epoch_manager
                .report(
                    epoch::Enter {
                        epoch: epoch_state.epoch(),
                        public: epoch_state.public_polynomial().clone(),
                        share: epoch_state.private_share().clone(),
                        participants: epoch_state.participants().clone(),
                    }
                    .into(),
                )
                .await;
            info!(
                epoch = epoch_state.epoch(),
                participants = ?epoch_state.participants(),
                public = alloy_primitives::hex::encode(epoch_state.public_polynomial().encode()),
                "reported epoch state to epoch manager",
            );
        }

        let current_epoch = self.current_epoch_state(tx).await.epoch();

        if let Some(epoch) = current_epoch.checked_sub(2)
            && let Ok(Some(validator_state)) = tx.get_validators(epoch).await
        {
            self.register_validators(epoch, validator_state).await;
        }
        if let Some(epoch) = current_epoch.checked_sub(1)
            && let Ok(Some(validator_state)) = tx.get_validators(epoch).await
        {
            self.register_validators(epoch, validator_state).await;
        }
    }

    /// Registers peers derived from `validator_state` for `epoch` on the peer manager.
    #[instrument(skip_all, fields(epoch))]
    async fn register_validators(&mut self, epoch: Epoch, validator_state: ValidatorState) {
        let peers_to_register = validator_state.resolve_addresses_and_merge_peers();
        self.metrics.peers.set(peers_to_register.len() as i64);
        self.config
            .peer_manager
            .update(epoch, peers_to_register.clone())
            .await;

        info!(
            peers_registered = ?peers_to_register,
            "registered p2p peers by merging dealers, players, syncing players",
        );
    }

    /// Returns if the DKG manager is running a post-allegretto ceremony.
    ///
    /// The DKG manager is running a post-allegretto ceremony if block.timestamp
    /// is after the allegretto timestamp, and if the post-allegretto epoch state
    /// is set.
    ///
    /// This is to account for ceremonies that are started pre-allegretto, and
    /// are running past the hardfork timestamp: we need to run the ceremony to
    /// its conclusion and then start a new post-allegretto ceremony at the epoch
    /// boundary.
    async fn is_running_post_allegretto(
        &self,
        block: &Block,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    ) -> bool {
        self.config
            .execution_node
            .chain_spec()
            .is_allegretto_active_at_timestamp(block.timestamp())
            && tx.has_post_allegretto_state().await
    }

    /// Returns the previous epoch state.
    ///
    /// Always prefers the post allegretto state, if it exists.
    async fn previous_epoch_state(
        &self,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    ) -> Option<EpochState> {
        if let Ok(Some(epoch_state)) = tx.get_previous_epoch::<post_allegretto::EpochState>().await
        {
            Some(EpochState::PostModerato(epoch_state))
        } else if let Ok(Some(epoch_state)) =
            tx.get_previous_epoch::<pre_allegretto::EpochState>().await
        {
            Some(EpochState::PreModerato(epoch_state))
        } else {
            None
        }
    }

    /// Returns the current epoch state.
    ///
    /// Always prefers the post allegretto state, if it exists.
    ///
    /// # Panics
    ///
    /// Panics if no epoch state exists, neither for the pre- nor post-allegretto
    /// regime. There must always be an epoch state.
    async fn current_epoch_state(
        &self,
        tx: &mut ReadWriteTransaction<ContextCell<TContext>>,
    ) -> EpochState {
        if let Ok(Some(epoch_state)) = tx.get_epoch::<post_allegretto::EpochState>().await {
            EpochState::PostModerato(epoch_state)
        } else if let Ok(Some(epoch_state)) = tx.get_epoch::<pre_allegretto::EpochState>().await {
            EpochState::PreModerato(epoch_state)
        } else {
            panic!("either pre- or post-allegretto current-epoch-state should exist")
        }
    }
}

#[derive(Clone, Debug)]
enum EpochState {
    PreModerato(pre_allegretto::EpochState),
    PostModerato(post_allegretto::EpochState),
}

impl EpochState {
    fn epoch(&self) -> Epoch {
        match self {
            Self::PreModerato(epoch_state) => epoch_state.epoch(),
            Self::PostModerato(epoch_state) => epoch_state.epoch(),
        }
    }

    fn participants(&self) -> &Ordered<PublicKey> {
        match self {
            Self::PreModerato(epoch_state) => epoch_state.participants(),
            Self::PostModerato(epoch_state) => epoch_state.participants(),
        }
    }

    fn public_polynomial(&self) -> &Public<MinSig> {
        match self {
            Self::PreModerato(epoch_state) => epoch_state.public_polynomial(),
            Self::PostModerato(epoch_state) => epoch_state.public_polynomial(),
        }
    }

    fn private_share(&self) -> &Option<Share> {
        match self {
            Self::PreModerato(epoch_state) => epoch_state.private_share(),
            Self::PostModerato(epoch_state) => epoch_state.private_share(),
        }
    }
}

#[derive(Clone)]
struct Metrics {
    peers: Gauge,
    pre_allegretto_ceremonies: Counter,
    post_allegretto_ceremonies: Counter,
    failed_allegretto_transitions: Counter,
    syncing_players: Gauge,
    ceremony: ceremony::Metrics,
}

/// Attempts to read the validator config from the smart contract until it becomes available.
async fn read_validator_config_with_retry<C: commonware_runtime::Clock>(
    context: &C,
    node: &TempoFullNode,
    epoch: Epoch,
    epoch_length: u64,
) -> OrderedAssociated<PublicKey, DecodedValidator> {
    let mut attempts = 1;
    let retry_after = Duration::from_secs(1);
    loop {
        if let Ok(validators) =
            validators::read_from_contract(attempts, node, epoch, epoch_length).await
        {
            break validators;
        }
        tracing::warn_span!("read_validator_config_with_retry").in_scope(|| {
            warn!(
                attempts,
                retry_after = %tempo_telemetry_util::display_duration(retry_after),
                "reading validator config from contract failed; will retry",
            );
        });
        attempts += 1;
        context.sleep(retry_after).await;
    }
}

#[derive(Clone, Debug)]
pub struct DkgOutcome {
    /// Whether this outcome is due to a successful or a failed DKG ceremony.
    pub dkg_successful: bool,

    /// The epoch that this DKG outcome is for (not during which it was running!).
    pub epoch: Epoch,

    /// The participants in the next epoch as determined by the DKG.
    pub participants: Ordered<PublicKey>,

    /// The public polynomial in the next epoch as determined by the DKG.
    pub public: Public<MinSig>,

    /// The share of this node in the next epoch as determined by the DKG.
    pub share: Option<Share>,
}

impl Write for DkgOutcome {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_successful.write(buf);
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for DkgOutcome {
    fn encode_size(&self) -> usize {
        self.dkg_successful.encode_size()
            + UInt(self.epoch).encode_size()
            + self.participants.encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
    }
}

impl Read for DkgOutcome {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let dkg_successful = bool::read(buf)?;
        let epoch = UInt::read(buf)?.into();
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        let share = Option::<Share>::read_cfg(buf, &())?;
        Ok(Self {
            dkg_successful,
            epoch,
            participants,
            public,
            share,
        })
    }
}
