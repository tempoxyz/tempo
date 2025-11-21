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
    Acknowledgement as _, quorum,
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
            validators::{self, ValidatorState},
        },
    },
    epoch,
    epoch::is_first_block_in_epoch,
};

const CURRENT_EPOCH_KEY: u64 = 0;
const PREVIOUS_EPOCH_KEY: u64 = 1;

const DKG_OUTCOME_KEY: u64 = 0;

mod postmoderato;

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

    /// Persisted information on the current epoch. This includes the DKG outcome
    /// of the ceremony that lead to the current epoch, as well as the validators
    /// that make up this epoch. The validators include the dealers (these are
    /// the actual participants/signers of the epoch), the players (these should
    /// become signers on conclusion of the next ceremony), and the syncing
    /// players (these have time to catch up and will become players once
    /// the next ceremony is done).
    epoch_metadata: Metadata<ContextCell<TContext>, U64, postmoderato::EpochState>,

    /// The persisted DKG outcome. This is the result of latest DKG ceremony,
    /// constructed one height before the boundary height b (on b-1).
    dkg_outcome_metadata: Metadata<ContextCell<TContext>, U64, DkgOutcome>,

    /// Information on the peers registered on the p2p peer mamnager for a given
    /// epoch i and its precursors i-1 and i-2. Peer information is persisted
    /// on the last height of an epoch.
    ///
    /// Note that validators are also persisted in the epoch metadata and are
    /// the main source of truth. The validators are also tracked here so that
    /// they can be resgistered as peers for older epoch states that are no longer
    /// tracked.
    validators_metadata: Metadata<ContextCell<TContext>, U64, ValidatorState>,

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

        let mut epoch_metadata = Metadata::init(
            context.with_label("epoch_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_current_epoch", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let dkg_outcome_metadata = Metadata::init(
            context.with_label("dkg_outcome_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_next_dkg_outcome", config.partition_prefix),
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

        // If no epoch state is stored on disk, this must be fresh node starting
        // at genesis.
        if epoch_metadata.get(&CURRENT_EPOCH_KEY.into()).is_none() {
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
            let validator_state = ValidatorState::new(initial);

            // ensure, just on genesis, that the peerset we'd get out of the
            // on-chain contract would result in what we see in the initial
            // outcome.
            let peers_as_per_contract = validator_state.resolve_addresses_and_merge_peers();
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

            epoch_metadata
                .put_sync(
                    CURRENT_EPOCH_KEY.into(),
                    postmoderato::EpochState {
                        dkg_outcome: DkgOutcome {
                            dkg_successful: true,
                            epoch: 0,
                            participants: outcome.participants,
                            public: outcome.public,
                            share: config.initial_share.clone(),
                        },
                        validator_state,
                    },
                )
                .await
                .expect("persisting epoch state must always work");
        };

        Ok(Self {
            config,
            context,
            mailbox,
            ceremony_metadata: Arc::new(Mutex::new(ceremony_metadata)),
            dkg_outcome_metadata,
            epoch_metadata,
            validators_metadata,
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

        self.report_previous_epoch_state_and_validators().await;
        self.register_current_epoch_state().await;
        let mut ceremony = Some(
            self.start_ceremony_for_current_epoch_state(&mut ceremony_mux)
                .await,
        );

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
        let Some(dkg_outcome) = self
            .dkg_outcome_metadata
            .get(&DKG_OUTCOME_KEY.into())
            .cloned()
        else {
            return Ok(());
        };
        let outcome = PublicOutcome {
            epoch: dkg_outcome.epoch,
            public: dkg_outcome.public,
            participants: dkg_outcome.participants,
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
            acknowledgment,
        }: Finalize,
        maybe_ceremony: &mut Option<Ceremony<ContextCell<TContext>, TReceiver, TSender>>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let block_epoch = utils::epoch(self.config.epoch_length, block.height());
        // Replay protection: if the node shuts down right after the last block
        // of the outgoing epoch was processed, but before the first block of
        // the incoming epoch was processed, then we do not want to update the
        // epoch state again.
        if block_epoch != self.current_epoch_state().epoch() {
            info!(
                block_epoch,
                actor_epoch = self.current_epoch_state().epoch(),
                "block was for an epoch other than what the actor is currently tracking; ignoring",
            );
        }

        // Special case --- boundary block: report that a new epoch should be
        // entered, start a new ceremony.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ... for epochs 0, 1, 2.
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.update_and_register_current_epoch_state().await;

            maybe_ceremony.replace(
                self.start_ceremony_for_current_epoch_state(ceremony_mux)
                    .await,
            );
            // Early return: start driving the ceremony on the first height of
            // the next epoch.
            acknowledgment.acknowledge();
            return;
        }

        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if is_first_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.enter_current_epoch_and_register_peers().await;

            // Similar for the validators: we only need to track the current
            // and last two epochs.
            if let Some(epoch) = self.current_epoch_state().epoch().checked_sub(3) {
                self.validators_metadata.remove(&epoch.into());
                self.validators_metadata
                    .sync()
                    .await
                    .expect("metadata must always be writable");
            }
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
            utils::is_last_block_in_epoch(self.config.epoch_length, block.height() + 1).is_some();
        if !is_one_before_boundary {
            assert!(
                maybe_ceremony.replace(ceremony).is_none(),
                "putting back the ceremony we just took out",
            );
            acknowledgment.acknowledge();
            return;
        }

        info!("on pre-to-last height of epoch; finalizing ceremony");

        let current_epoch = ceremony.epoch();

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

        self.dkg_outcome_metadata
            .put_sync(
                DKG_OUTCOME_KEY.into(),
                DkgOutcome {
                    dkg_successful,
                    epoch: current_epoch + 1,
                    participants: ceremony_outcome.participants,
                    public,
                    share,
                },
            )
            .await
            .expect("must always be able to persist the DKG outcome");

        // Prune older ceremony.
        if let Some(epoch) = current_epoch.checked_sub(1) {
            let mut ceremony_metadata = self.ceremony_metadata.lock().await;
            ceremony_metadata.remove(&epoch.into());
            ceremony_metadata.sync().await.expect("metadata must sync");
        }

        acknowledgment.acknowledge();
    }

    /// Starts a new ceremony for the epoch state tracked by the actor.
    #[instrument(
        skip_all,
        fields(
            me = %self.config.me.public_key(),
            current_epoch = self.current_epoch_state().epoch(),
        )
    )]
    async fn start_ceremony_for_current_epoch_state<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<ContextCell<TContext>, TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state = self.current_epoch_state().clone();
        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public_polynomial().clone(),
            share: epoch_state.private_share().clone(),
            epoch: epoch_state.epoch(),
            dealers: epoch_state.dealer_pubkeys(),
            players: epoch_state.player_pubkeys(),
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
            n_syncing_players = epoch_state.validator_state.syncing_players().len(),
            syncing_players = ?epoch_state.validator_state.syncing_players(),
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
            .set(epoch_state.validator_state.syncing_players().len() as i64);
        self.metrics
            .how_often_dealer
            .inc_by(ceremony.is_dealer() as u64);
        self.metrics
            .how_often_player
            .inc_by(ceremony.is_player() as u64);

        ceremony
    }

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

    /// Registers the new epoch by reporting to the epoch manager that it should
    /// be entered and registering its peers on the peers manager.
    #[instrument(skip_all, fields(epoch = self.current_epoch_state().epoch()))]
    async fn register_current_epoch_state(&mut self) {
        let epoch_state = self.current_epoch_state().clone();

        self.validators_metadata
            .put_sync(
                epoch_state.epoch().into(),
                epoch_state.validator_state.clone(),
            )
            .await
            .expect("must always be able to persist validator metadata");

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
        self.register_validators(epoch_state.epoch(), epoch_state.validator_state)
            .await;
    }

    /// Reports that the previous epoch should be entered.
    ///
    /// This method is called on startup to ensure that a consensus engine for
    /// the previous epoch i-1 is started in case the node went down before the
    /// new epoch i was firmly locked in.
    ///
    /// This method also registers the validators for the epochs i-1 and i-2.
    #[instrument(skip_all, fields(previous_epoch = self.previous_epoch_state().map(|s| s.epoch())))]
    async fn report_previous_epoch_state_and_validators(&mut self) {
        if let Some(epoch_state) = self.previous_epoch_state().cloned() {
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

        if let Some(epoch) = self.current_epoch_state().epoch().checked_sub(2)
            && let Some(validator_state) = self.validators_metadata.get(&epoch.into()).cloned()
        {
            self.register_validators(epoch, validator_state).await;
        }
        if let Some(epoch) = self.current_epoch_state().epoch().checked_sub(1)
            && let Some(validator_state) = self.validators_metadata.get(&epoch.into()).cloned()
        {
            self.register_validators(epoch, validator_state).await;
        }
    }

    /// Reports that a new epoch was entered, that the previous epoch can be ended.
    async fn enter_current_epoch_and_register_peers(&mut self) {
        let old_epoch_state = self
            .epoch_metadata
            .remove(&PREVIOUS_EPOCH_KEY.into())
            .expect("there must always be a current epoch state");
        self.config
            .epoch_manager
            .report(
                epoch::Exit {
                    epoch: old_epoch_state.epoch(),
                }
                .into(),
            )
            .await;
        self.epoch_metadata
            .sync()
            .await
            .expect("must always be able to persist state");

        if let Some(epoch) = old_epoch_state.epoch().checked_sub(2) {
            self.validators_metadata.remove(&epoch.into());
            self.validators_metadata
                .sync()
                .await
                .expect("must always be able to persist data");
        }
    }

    #[instrument(skip_all)]
    async fn update_and_register_current_epoch_state(&mut self) {
        let old_epoch_state = self
            .epoch_metadata
            .remove(&CURRENT_EPOCH_KEY.into())
            .expect("there must always exist an epoch state");

        // Remove it?
        let dkg_outcome = self
            .dkg_outcome_metadata
            .get(&DKG_OUTCOME_KEY.into())
            .cloned()
            .expect(
                "when updating the current epoch state, there must be a DKG \
                outcome of some ceremomny",
            );

        assert_eq!(
            old_epoch_state.epoch() + 1,
            dkg_outcome.epoch,
            "sanity check: old outcome must be new outcome - 1"
        );

        let syncing_players = read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            dkg_outcome.epoch,
            self.config.epoch_length,
        )
        .await;

        let mut new_validator_state = old_epoch_state.validator_state.clone();
        if dkg_outcome.dkg_successful {
            new_validator_state.push_on_success(syncing_players);
        } else {
            new_validator_state.push_on_failure(syncing_players);
        }

        self.epoch_metadata.put(
            CURRENT_EPOCH_KEY.into(),
            postmoderato::EpochState {
                dkg_outcome,
                validator_state: new_validator_state.clone(),
            },
        );
        self.epoch_metadata
            .put(PREVIOUS_EPOCH_KEY.into(), old_epoch_state);

        self.epoch_metadata
            .sync()
            .await
            .expect("must always be able to persists epoch state");

        self.register_current_epoch_state().await;
    }

    fn current_epoch_state(&self) -> &postmoderato::EpochState {
        self.epoch_metadata
            .get(&CURRENT_EPOCH_KEY.into())
            .expect("current epoch state must be set at all times")
    }

    fn previous_epoch_state(&self) -> Option<&postmoderato::EpochState> {
        self.epoch_metadata.get(&PREVIOUS_EPOCH_KEY.into())
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

#[derive(Clone, Debug)]
struct DkgOutcome {
    /// Whether this outcome is due to a successful or a failed DKG ceremony.
    dkg_successful: bool,

    /// The epoch that this DKG outcome is for (not during which it was running!).
    epoch: Epoch,

    /// The participants in the next epoch as determined by the DKG.
    participants: Ordered<PublicKey>,

    /// The public polynomial in the next epoch as determined by the DKG.
    public: Public<MinSig>,

    /// The share of this node in the next epoch as determined by the DKG.
    share: Option<Share>,
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
