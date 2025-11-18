use std::{net::SocketAddr, sync::Arc, time::Duration};

use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
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
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    quorum,
    sequence::U64,
    set::{Ordered, OrderedAssociated},
};

use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{StreamExt as _, channel::mpsc, lock::Mutex};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use reth_chainspec::EthChainSpec as _;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tempo_node::TempoFullNode;
use tracing::{Span, info, instrument, warn};

use crate::{
    dkg::{
        CeremonyState,
        ceremony::{self, Ceremony},
        manager::{
            DecodedValidator,
            ingress::{Finalize, GetIntermediateDealing, GetOutcome},
            validators,
        },
    },
    epoch::{self, is_first_block_in_epoch},
};

const EPOCH_KEY: u64 = 0;

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

    /// Persisted information on the currently running ceremmony and its
    /// predecessor (epochs i and i-1). This ceremony metadata is updated on
    /// the last height of en epoch (the height on which the ceremony for the
    /// next epoch will be started).
    ceremony_metadata: Arc<Mutex<Metadata<ContextCell<TContext>, U64, CeremonyState>>>,

    /// Persisted information on the current epoch (participants, this node's
    /// share of the private polynomial, the public polynomial). As the ceremony
    /// is finalized one node before the boundary block, the resulting epoch
    /// information is also updated then. (remember, for a given epoch length E,
    /// the first height of epoch i is i×E, and so the boundary block of
    /// epoch (i-1) is b = i×E-1 and its predecessor b-1.
    //
    // FIXME(janis): this means that if the node goes down right after it
    // updated the state on b-1 but before it saw the boundary block b, on a
    // restart the old epoch will never be entered again!
    epoch_metadata: Metadata<ContextCell<TContext>, U64, EpochState>,

    /// Information on the peers registered on the p2p peer mamnager for a given
    /// epoch i and its precursors i-1 and i-2. Peer information is persisted
    /// on the last height of an epoch.
    // FIXME(janis): we are not actually deleting the information ever.
    validators_metadata: Metadata<ContextCell<TContext>, U64, validators::Tracked>,

    /// The epoch state of the current epoch. Populated from `epoch_metadata` on
    /// initialization and updated on every completed ceremony (one before the
    /// last height of an epoch).
    epoch_state: EpochState,

    /// Tracks all current and potential future validators as read from the
    /// smart contract. This object is populated from `validators_metadata`.
    /// on init and updated on
    validator_state: validators::Tracked,

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
        >,
{
    pub(super) async fn init(
        config: super::Config<TPeerManager>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let context = ContextCell::new(context);

        let ceremony_metadata = Metadata::init(
            context.with_label("ceremony_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_ceremony", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let epoch_metadata = Metadata::init(
            context.with_label("epoch_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let validators_metadata = Metadata::init(
            context.with_label("validators__metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_validators", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let ceremony_failures = Counter::default();
        let ceremony_successes = Counter::default();

        let ceremony_dealers = Gauge::default();
        let ceremony_players = Gauge::default();

        let syncing_players = Gauge::default();

        let how_often_dealer = Counter::default();
        let how_often_player = Counter::default();

        let peers = Gauge::default();

        context.register(
            "ceremony_failures",
            "the number of failed ceremonies a node participated in",
            ceremony_failures.clone(),
        );
        context.register(
            "ceremony_successes",
            "the number of successful ceremonies a node participated in",
            ceremony_successes.clone(),
        );
        context.register(
            "ceremony_dealers",
            "the number of dealers in the currently running ceremony",
            ceremony_dealers.clone(),
        );
        context.register(
            "ceremony_players",
            "the number of players in the currently running ceremony",
            ceremony_players.clone(),
        );

        context.register(
            "syncing_players",
            "how many syncing players were registered; these will become players in the next ceremony",
            syncing_players.clone(),
        );

        context.register(
            "how_often_dealer",
            "number of the times as node was active as a dealer",
            how_often_dealer.clone(),
        );
        context.register(
            "how_often_player",
            "number of the times as node was active as a player",
            how_often_player.clone(),
        );

        context.register(
            "peers",
            "how many peers are registered overall for the latest epoch",
            peers.clone(),
        );

        let metrics = Metrics {
            how_often_dealer,
            how_often_player,
            ceremony_failures,
            ceremony_successes,
            ceremony_dealers,
            ceremony_players,
            peers,
            syncing_players,
        };

        let (epoch_state, validator_state) = if let Some::<EpochState>(epoch_state) =
            epoch_metadata.get(&EPOCH_KEY.into()).cloned()
        {
            let validator_state = validators_metadata
                .get(&epoch_state.epoch.into())
                .cloned()
                .ok_or_else(|| {
                    eyre!(
                        "found epoch state for epoch `{}` on dsk, but no matching validator state",
                        epoch_state.epoch
                    )
                })?;
            (epoch_state, validator_state)
        } else {
            let spec = config.execution_node.chain_spec();
            let outcome =
                PublicOutcome::decode(spec.genesis().extra_data.as_ref()).wrap_err_with(|| {
                    format!(
                        "failed decoding the genesis.extra_data field as an \
                        initial DKG outcome; this field must be set and it \
                        must be decodable; bytes = {}",
                        spec.genesis().extra_data.len(),
                    )
                })?;

            ensure!(
                outcome.epoch == 0,
                "at genesis, the epoch must be zero, but genesis reported `{}`",
                outcome.epoch
            );
            let initial =
                validators::read_from_contract(0, &config.execution_node, 0, config.epoch_length)
                    .await
                    .wrap_err("validator config could not be read from contract for genesis")?;
            let validator_state = validators::Tracked::new(initial);

            // ensure, just on genesis, that the peerset we'd get out of the
            // on-chain contract would result in what we see in the initial
            // outcome.
            let peers_as_per_contract = validator_state.resolve_addresses_and_merge();
            ensure!(
                peers_as_per_contract.keys() == &outcome.participants,
                "the DKG participants stored in the genesis extraData header \
                don't match the peers determined from the onchain contract of \
                the genesis block; \
                extraData.participants = `{:?}; \
                contract.peers = `{:?}",
                outcome.participants,
                peers_as_per_contract.keys(),
            );

            let epoch_state = EpochState {
                dkg_successful: true,
                epoch: 0,
                participants: outcome.participants,
                public: outcome.public,
                share: config.initial_share.clone(),
            };

            (epoch_state, validator_state)
        };

        Ok(Self {
            config,
            context,
            mailbox,
            ceremony_metadata: Arc::new(Mutex::new(ceremony_metadata)),
            epoch_metadata,
            epoch_state,
            validators_metadata,
            validator_state,
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
        let (mux, mut ceremony_mux) = mux::Muxer::new(
            self.context.with_label("ceremony_mux"),
            sender,
            receiver,
            self.config.mailbox_size,
        );
        mux.start();

        self.config
            .epoch_manager
            .report(
                epoch::Enter {
                    epoch: self.epoch_state.epoch,
                    public: self.epoch_state.public.clone(),
                    share: self.epoch_state.share.clone(),
                    participants: self.epoch_state.participants.clone(),
                }
                .into(),
            )
            .await;

        let mut ceremony = Some(self.start_ceremony(&mut ceremony_mux).await);
        self.register_peers().await;

        while let Some(message) = self.mailbox.next().await {
            let cause = message.cause;
            match message.command {
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
                super::Command::Finalize(finalize) => {
                    self.handle_finalized(cause, finalize, &mut ceremony, &mut ceremony_mux)
                        .await;
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
        ceremony: Option<&mut Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
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
        let outcome = PublicOutcome {
            epoch: self.epoch_state.epoch,
            public: self.epoch_state.public.clone(),
            participants: self.epoch_state.participants.clone(),
        };
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
            response: _response,
        }: Finalize,
        maybe_ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        // Special case --- boundary block: report that a new epoch should be
        // entered, start a new ceremony.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ... for epochs 0, 1, 2.
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.report_new_epoch().await;

            let syncing_players = read_validator_config_with_retry(
                &self.context,
                &self.config.execution_node,
                self.epoch_state.epoch,
                self.config.epoch_length,
            )
            .await;

            if self.epoch_state.dkg_successful {
                self.validator_state.push_on_success(syncing_players);
            } else {
                self.validator_state.push_on_failure(syncing_players);
            }
            self.register_peers().await;
            maybe_ceremony.replace(self.start_ceremony(ceremony_mux).await);
            // Early return: start driving the ceremony on the first height of
            // the next epoch.
            return;
        }

        // Special case first height: exit the old epoch, start a new ceremony.
        //
        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if is_first_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.report_epoch_entered().await;
        }

        let mut ceremony = maybe_ceremony.take().expect(
            "past this point a ceremony must always be defined; the only \
                time a ceremony is not permitted to exist is exactly on the \
                boundary; did the code after ensure that the ceremony is \
                returned to its Option?",
        );

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares().await;
                let _ = ceremony.process_messages().await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages().await;
                let _ = ceremony.construct_intermediate_outcome().await;
            }
            epoch::RelativePosition::SecondHalf => {
                let _ = ceremony.process_dealings_in_block(&block).await;
            }
        }

        // XXX: Need to finalize on the pre-to-last height of the epoch so that
        // the information becomes available on the last height and can be
        // stored on chain.
        let is_one_before_boundary =
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height() + 1).is_none();
        if is_one_before_boundary {
            assert!(
                maybe_ceremony.replace(ceremony).is_none(),
                "putting back the ceremony we just took out",
            );
            return;
        }

        info!("on pre-to-last height of epoch; finalizing ceremony");

        let next_epoch = ceremony.epoch() + 1;

        let (ceremony_outcome, dkg_successful) = match ceremony.finalize() {
            Ok(outcome) => {
                self.metrics.ceremony_successes.inc();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                (outcome, true)
            }
            Err(outcome) => {
                self.metrics.ceremony_failures.inc();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                (outcome, false)
            }
        };
        let (public, share) = ceremony_outcome.role.into_key_pair();

        self.epoch_state = EpochState {
            dkg_successful,
            epoch: next_epoch,
            participants: ceremony_outcome.participants,
            public,
            share,
        };
        self.epoch_metadata
            .put_sync(EPOCH_KEY.into(), self.epoch_state.clone())
            .await
            .expect("must always be able to write epoch state to disk");

        // Prune older ceremony.
        if let Some(epoch) = self.epoch_state.epoch.checked_sub(2) {
            let mut ceremony_metadata = self.ceremony_metadata.lock().await;
            ceremony_metadata.remove(&epoch.into());
            ceremony_metadata.sync().await.expect("metadata must sync");
        }
    }

    /// Registers the known peers on the p2p peer manager for the current epoch.
    ///
    /// The peers are derived from the tracked validators and the epoch they are
    /// registered for from the tracked epoch state.
    ///
    /// This function also persists the validators on disk.
    async fn register_peers(&mut self) {
        let peers_to_register = self.validator_state.resolve_addresses_and_merge();
        self.metrics.peers.set(peers_to_register.len() as i64);

        self.validators_metadata
            .put_sync(self.epoch_state.epoch.into(), self.validator_state.clone())
            .await
            .expect("must always be able to store validators peers on disk");
        self.config
            .peer_manager
            .update(self.epoch_state.epoch, peers_to_register.clone())
            .await;

        info!(
            epoch = self.epoch_state.epoch,
            peers_registered = ?peers_to_register,
            "registered p2p peers by merging dealers, players, syncing players",
        );
    }

    /// Starts a new ceremony for the epoch state tracked by the actor.
    #[instrument(
        skip_all,
        fields(
            me = %self.config.me.public_key(),
            epoch = self.epoch_state.epoch,
        )
    )]
    async fn start_ceremony<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<ContextCell<TContext>, TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: self.epoch_state.public.clone(),
            share: self.epoch_state.share.clone(),
            epoch: self.epoch_state.epoch,
            dealers: self.validator_state.dealer_pubkeys(),
            players: self.validator_state.player_pubkeys(),
        };
        let ceremony = ceremony::Ceremony::init(
            &mut self.context,
            mux,
            self.ceremony_metadata.clone(),
            config,
        )
        .await
        .expect("must always be able to initialize ceremony");

        info!(
            n_dealers = ceremony.dealers().len(),
            dealers = ?ceremony.dealers(),
            n_players = ceremony.players().len(),
            players = ?ceremony.players(),
            as_player = ceremony.is_player(),
            as_dealer = ceremony.is_dealer(),
            n_syncing_players = self.validator_state.syncing_players().len(),
            syncing_players = ?self.validator_state.syncing_players(),
            "started a ceremony",
        );

        self.metrics
            .ceremony_dealers
            .set(ceremony.dealers().len() as i64);
        self.metrics
            .ceremony_players
            .set(ceremony.players().len() as i64);
        self.metrics
            .syncing_players
            .set(self.validator_state.syncing_players().len() as i64);
        self.metrics
            .how_often_dealer
            .inc_by(ceremony.is_dealer() as u64);
        self.metrics
            .how_often_player
            .inc_by(ceremony.is_player() as u64);

        ceremony
    }

    /// Reports that a new epoch can be entered.
    ///
    /// This should trigger the epoch manager to start a new consensus engine
    /// backing the epoch stored by the DKG manager.
    #[instrument(skip_all)]
    async fn report_new_epoch(&mut self) {
        self.config
            .epoch_manager
            .report(
                epoch::Enter {
                    epoch: self.epoch_state.epoch,
                    public: self.epoch_state.public.clone(),
                    share: self.epoch_state.share.clone(),
                    participants: self.epoch_state.participants.clone(),
                }
                .into(),
            )
            .await;
        info!(
            epoch = self.epoch_state.epoch,
            participants = ?self.epoch_state.participants,
            public = alloy_primitives::hex::encode(self.epoch_state.public.encode()),
            "reported new epoch to epoch manager and registered peers",
        );
    }

    async fn report_epoch_entered(&mut self) {
        if let Some(previous_epoch) = self.epoch_state.epoch.checked_sub(1) {
            self.config
                .epoch_manager
                .report(
                    epoch::Exit {
                        epoch: previous_epoch,
                    }
                    .into(),
                )
                .await;
        }
    }
}

#[derive(Clone)]
struct Metrics {
    how_often_dealer: Counter,
    how_often_player: Counter,
    ceremony_failures: Counter,
    ceremony_successes: Counter,
    ceremony_dealers: Gauge,
    ceremony_players: Gauge,
    peers: Gauge,
    syncing_players: Gauge,
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

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
struct EpochState {
    dkg_successful: bool,
    epoch: Epoch,
    participants: Ordered<PublicKey>,
    public: Public<MinSig>,
    share: Option<Share>,
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dkg_successful.write(buf);
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        self.dkg_successful.encode_size()
            + UInt(self.epoch).encode_size()
            + self.participants.encode_size()
            + self.public.encode_size()
            + self.share.encode_size()
    }
}

impl Read for EpochState {
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
