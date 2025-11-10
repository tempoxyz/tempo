use std::{
    collections::{BTreeMap, HashMap},
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};

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

use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
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
        manager::ingress::{Finalize, GetIntermediateDealing, GetOutcome},
    },
    epoch,
};

const EPOCH_KEY: u64 = 0;

pub(crate) struct Actor<TContext, TPeerManager>
where
    TContext: Clock + commonware_runtime::Metrics + Storage,
    TPeerManager: commonware_p2p::Manager,
{
    config: super::Config<TPeerManager>,
    context: ContextCell<TContext>,
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    ceremony_metadata: Arc<Mutex<Metadata<ContextCell<TContext>, U64, CeremonyState>>>,
    epoch_metadata: Metadata<ContextCell<TContext>, U64, EpochState>,
    p2p_metadata: Metadata<ContextCell<TContext>, U64, P2pState>,

    epoch_state: EpochState,
    p2p_states: P2pStates,

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

        let p2p_metadata = Metadata::init(
            context.with_label("p2p_metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_p2p_state", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let ceremony_failures = Counter::default();
        let ceremony_successes = Counter::default();

        let ceremony_dealers = Gauge::default();
        let ceremony_players = Gauge::default();

        let how_often_dealer = Counter::default();
        let how_often_player = Counter::default();

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
            "how_often_dealer",
            "number of the times as node was active as a dealer",
            how_often_dealer.clone(),
        );
        context.register(
            "how_often_player",
            "number of the times as node was active as a player",
            how_often_player.clone(),
        );

        let metrics = Metrics {
            how_often_dealer,
            how_often_player,
            ceremony_failures,
            ceremony_successes,
            ceremony_dealers,
            ceremony_players,
        };

        let epoch_state = if let Some::<EpochState>(epoch_state) =
            epoch_metadata.get(&EPOCH_KEY.into()).cloned()
        {
            epoch_state
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

            EpochState {
                epoch: 0,
                participants: outcome.participants,
                public: outcome.public,
                share: config.initial_share.clone(),
            }
        };

        let mut p2p_states = P2pStates::new();
        for epoch in epoch_state.epoch.saturating_sub(2)..=epoch_state.epoch {
            if let Some::<P2pState>(p2p_state) = p2p_metadata.get(&epoch.into()).cloned() {
                p2p_states.add(epoch, p2p_state);
            }
        }

        Ok(Self {
            config,
            context,
            mailbox,
            ceremony_metadata: Arc::new(Mutex::new(ceremony_metadata)),
            epoch_metadata,
            p2p_metadata,
            epoch_state,
            metrics,
            p2p_states,
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

        let mut ceremony = Some(self.start_new_ceremony(&mut ceremony_mux).await);
        let merged_peer_set = self.p2p_states.construct_merged_peerset();

        self.config
            .peer_manager
            .update(
                self.p2p_states.highest_epoch().expect(
                    "once a new ceremony was started, there must be a \
                            highest epoch in the p2p states",
                ),
                merged_peer_set.clone(),
            )
            .await;

        info!(
            epoch = self.p2p_states.highest_epoch(),
            ?merged_peer_set,
            "updated latest peer set by merging validator of the last 3 epochs"
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
                    self.handle_finalize(cause, finalize, &mut ceremony, &mut ceremony_mux)
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
        parent = cause,
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
        parent = cause,
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
        parent = cause,
        skip_all,
        fields(
            block.derived_epoch = utils::epoch(self.config.epoch_length, block.height()),
            block.height = block.height(),
            ceremony.epoch = maybe_ceremony.as_ref().map(|c| c.epoch()),
        ),
    )]
    async fn handle_finalize<TReceiver, TSender>(
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
        // Special case boundary height: only start a new epoch and return.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ...
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.report_new_epoch().await;

            // Early return here. We want to start processing the ceremony on
            // the first height of the next epoch.
            return;
        }

        // Special case first height: exit the old epoch, start a new ceremony.
        //
        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if block.height().is_multiple_of(self.config.epoch_length) {
            self.report_epoch_entered().await;

            maybe_ceremony.replace(self.start_new_ceremony(ceremony_mux).await);
            let merged_peer_set = self.p2p_states.construct_merged_peerset();
            self.config
                .peer_manager
                .update(
                    self.p2p_states.highest_epoch().expect(
                        "once a new ceremony was started, there must be a \
                            highest epoch in the p2p states",
                    ),
                    merged_peer_set.clone(),
                )
                .await;
            info!(
                epoch = self.p2p_states.highest_epoch(),
                ?merged_peer_set,
                "updated latest peer set by merging validator of the last 3 epochs"
            );
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

        let ceremony_outcome = match ceremony.finalize() {
            Ok(outcome) => {
                self.metrics.ceremony_successes.inc();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                outcome
            }
            Err(outcome) => {
                self.metrics.ceremony_failures.inc();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                outcome
            }
        };
        let (public, share) = ceremony_outcome.role.into_key_pair();

        self.epoch_state = EpochState {
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

    /// Starts a new ceremony.
    ///
    /// This method is intended to be called on the first block an epoch.
    ///
    /// 1. The validator config is read from the boundary block of the previous
    ///    epoch. This is to ensure that the boundary block is firmly available
    ///    in the execution layer.
    /// 2. The peer set is updated given the new validators.
    /// 3. A new DKG ceremony is launched with the new validators as its players.
    #[instrument(
        skip_all,
        fields(
            me = %self.config.me.public_key(),
            epoch = self.epoch_state.epoch,
        )
    )]
    async fn start_new_ceremony<TReceiver, TSender>(
        &mut self,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<ContextCell<TContext>, TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        // XXX(!!!): This is critical: start_new_epoch *MUST* be called on the
        // first block, and the validator config *MUST* be read on the
        // *BOUNDARY* of the previous epoch. This ensures that the block is
        // firmly committed on the execution layer.
        let boundary = self.epoch_state.epoch.checked_sub(1).map_or(0, |previous| {
            utils::last_block_in_epoch(self.config.epoch_length, previous)
        });

        let new_p2p_state =
            match read_validator_config_from_contract(self.config.execution_node.clone(), boundary)
                .await
            {
                Ok(p2p_state) => p2p_state,
                Err(error) => {
                    warn!(
                        %error,
                        "unable to read validator config from contract; taking the \
                        last validator config and starting a new ceremony with that \
                        instead"
                    );
                    self.p2p_states.highest().cloned().expect(
                        "there must be one set of validators; if there is not and \
                    reading it from the contract failed we can't go on",
                    )
                }
            };

        self.p2p_metadata
            .put_sync(self.epoch_state.epoch.into(), new_p2p_state.clone())
            .await
            .expect("must always be able to write p2p state to disk");
        if let Some((old_epoch, _)) = self
            .p2p_states
            .add(self.epoch_state.epoch, new_p2p_state.clone())
        {
            self.p2p_metadata.remove(&old_epoch.into());
            self.p2p_metadata.sync().await.expect("metadata must sync");
        }

        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: self.epoch_state.public.clone(),
            share: self.epoch_state.share.clone(),
            epoch: self.epoch_state.epoch,
            dealers: self.epoch_state.participants.clone(),
            players: new_p2p_state.peers.iter().cloned().collect(),
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
            "started a ceremony",
        );

        self.metrics
            .ceremony_dealers
            .set(ceremony.dealers().len() as i64);
        self.metrics
            .ceremony_players
            .set(ceremony.players().len() as i64);
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
            public = const_hex::encode(self.epoch_state.public.encode()),
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
}

/// Reads the validator config `at_height` from a smart contract.
#[instrument(skip_all, fields(at_height), err)]
async fn read_validator_config_from_contract(
    node: TempoFullNode,
    at_height: u64,
) -> eyre::Result<P2pState> {
    use alloy_evm::EvmInternals;
    use reth_chainspec::EthChainSpec as _;
    use reth_ethereum::evm::revm::{
        State, context::ContextTr as _, database::StateProviderDatabase,
    };
    use reth_node_builder::{Block as _, ConfigureEvm as _};
    use reth_provider::{BlockReader as _, StateProviderFactory as _};
    use tempo_precompiles::{
        VALIDATOR_CONFIG_ADDRESS,
        storage::evm::EvmPrecompileStorageProvider,
        validator_config::{IValidatorConfig, ValidatorConfig},
    };

    let block = node
        .provider
        .block_by_number(at_height)
        .map_err(Into::<eyre::Report>::into)
        .and_then(|maybe| maybe.ok_or_eyre("execution layer returned empty block"))
        .wrap_err_with(|| format!("failed reading block at height `{at_height}`"))?;

    let db = State::builder()
        .with_database(StateProviderDatabase::new(
            node.provider
                .state_by_block_id(at_height.into())
                .wrap_err_with(|| {
                    format!("failed to get state from node provider for height `{at_height}`")
                })?,
        ))
        .build();

    // XXX: Ensure that evm and internals go out of scope before the await point
    // below.
    let contract_validators = {
        let mut evm = node
            .evm_config
            .evm_for_block(db, block.header())
            .wrap_err("failed instantiating evm for genesis block")?;

        let block = evm.block.clone();
        let internals = EvmInternals::new(evm.journal_mut(), &block);
        let mut precompile_storage =
            EvmPrecompileStorageProvider::new_max_gas(internals, node.chain_spec().chain_id());

        let mut validator_config =
            ValidatorConfig::new(VALIDATOR_CONFIG_ADDRESS, &mut precompile_storage);
        validator_config
            .get_validators(IValidatorConfig::getValidatorsCall {})
            .wrap_err("failed to query contract for validator config")?
    };

    let addresses = decode_contract_validators(contract_validators)
        .await
        .wrap_err("failed to decode validators read from contract")?;

    let peers = addresses
        .into_iter()
        .map(|(key, addrs)| (key, addrs.inbound))
        .collect();

    Ok(P2pState { peers })
}

struct Addresses {
    inbound: SocketAddr,
    _outbound: SocketAddr,
}

use tempo_precompiles::validator_config::IValidatorConfig;
async fn decode_contract_validators(
    contract_vals: Vec<IValidatorConfig::Validator>,
) -> eyre::Result<HashMap<PublicKey, Addresses>> {
    let mut parsed_vals = HashMap::new();
    for val in contract_vals.into_iter().filter(|val| val.active) {
        let peer = PublicKey::decode(val.publicKey.as_ref()).wrap_err_with(|| {
            format!(
                "failed decoding pubkey of validator at index `{}`",
                val.index
            )
        })?;
        let inbound_address = val.inboundAddress;
        let outbound_address = val.outboundAddress;

        // TODO(janis): doing all of these in a loop and sequentially is bad.
        let mut all_inbound = inbound_address
            .to_socket_addrs()
            .wrap_err_with(|| {
                format!(
                    "failed converting contract inboundAddress of contract \
                    `{inbound_address}` of peer `{peer}` to socket address by \
                    parsing it or resolving the hostname"
                )
            })?
            .collect::<Vec<_>>();

        let Some(inbound) = all_inbound.pop() else {
            return Err(eyre!(
                "peer `{peer}` with inboundAddress `{inbound_address}` \
                resolved to zero addresses"
            ));
        };

        let mut all_outbound = outbound_address
            .to_socket_addrs()
            .wrap_err_with(|| {
                format!(
                    "failed converting contract outboundAddress \
                    `{outbound_address}` of peer `{peer}` to socket address \
                    by parsing it or resolving the hostname"
                )
            })?
            .collect::<Vec<_>>();

        let Some(outbound) = all_outbound.pop() else {
            return Err(eyre!(
                "peer `{peer}` with outboundAddress `{outbound_address}` \
                resolved to zero addresses"
            ));
        };

        info!(
            peer = %peer,
            outbound_address,
            potential_addresses = ?all_outbound,
            inbound_address,
            potential_addresses = ?all_inbound,
            "resolved inbound and outbound addresses to socket addresses; \
            always taking the last one in case there are more than one"
        );

        if parsed_vals
            .insert(
                peer.clone(),
                Addresses {
                    inbound,
                    _outbound: outbound,
                },
            )
            .is_some()
        {
            bail!("pub key `{peer}` was duplicate; this is not permitted");
        }
    }
    Ok(parsed_vals)
}

/// The state with all participants, public and private key share for an epoch.
#[derive(Clone)]
struct EpochState {
    epoch: u64,
    participants: Ordered<PublicKey>,
    public: Public<MinSig>,
    share: Option<Share>,
}

impl Write for EpochState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        UInt(self.epoch).write(buf);
        self.participants.write(buf);
        self.public.write(buf);
        self.share.write(buf);
    }
}

impl EncodeSize for EpochState {
    fn encode_size(&self) -> usize {
        UInt(self.epoch).encode_size()
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
        let epoch = UInt::read(buf)?.into();
        let participants = Ordered::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?;
        let public =
            Public::<MinSig>::read_cfg(buf, &(quorum(participants.len() as u32) as usize))?;
        let share = Option::<Share>::read_cfg(buf, &())?;
        Ok(Self {
            epoch,
            participants,
            public,
            share,
        })
    }
}

struct P2pStates {
    inner: BTreeMap<Epoch, P2pState>,
}

impl P2pStates {
    fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    fn add(&mut self, epoch: Epoch, new: P2pState) -> Option<(Epoch, P2pState)> {
        use std::collections::btree_map::Entry;
        match self.inner.entry(epoch) {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(new);
            }
            Entry::Occupied(mut slot) => {
                if slot.get() != &new {
                    warn!(
                        epoch,
                        old = ?slot.get(),
                        ?new,
                        "overwriting peer set at the same epoch"
                    );
                    slot.insert(new);
                }
            }
        }
        let old_epoch = epoch.checked_sub(3)?;
        self.inner.remove(&old_epoch).map(|p2p| (old_epoch, p2p))
    }

    fn highest(&self) -> Option<&P2pState> {
        self.inner.last_key_value().map(|(_, p2p)| p2p)
    }

    fn highest_epoch(&self) -> Option<Epoch> {
        self.inner.last_key_value().map(|(epoch, _)| *epoch)
    }

    /// Merges the peers in the current, parent, and grandparent p2p states.
    fn construct_merged_peerset(&self) -> OrderedAssociated<PublicKey, SocketAddr> {
        self.inner
            .values()
            .flat_map(|p2p| p2p.peers.iter_pairs())
            .map(|(key, addr)| (key.clone(), *addr))
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
struct P2pState {
    peers: OrderedAssociated<PublicKey, SocketAddr>,
}

impl Write for P2pState {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.peers.write(buf);
    }
}

impl EncodeSize for P2pState {
    fn encode_size(&self) -> usize {
        self.peers.encode_size()
    }
}

impl Read for P2pState {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let peers = OrderedAssociated::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), (), ()))?;
        Ok(Self { peers })
    }
}
