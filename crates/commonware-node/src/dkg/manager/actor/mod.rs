use std::{collections::BTreeMap, net::SocketAddr, num::NonZeroU32, task::Poll, time::Duration};

use alloy_consensus::BlockHeader as _;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{Encode as _, EncodeSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block as _,
    marshal::{self, Update},
    simplex::scheme::bls12381_threshold::Scheme,
    types::{Epoch, EpochPhase, Epocher as _, FixedEpocher},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::{self, DealerLog, DealerPrivMsg, DealerPubMsg, PlayerAck, SignedDealerLog, observe},
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
    transcript::Summary,
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{
    Address, Receiver, Recipients, Sender,
    utils::mux::{self, MuxHandle},
};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics as _, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, NZU32, ordered};

use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::{
    FutureExt as _, Stream, StreamExt as _, channel::mpsc, select_biased, stream::FusedStream,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use reth_provider::{BlockNumReader, HeaderProvider};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::TempoFullNode;
use tracing::{Span, debug, error, info, info_span, instrument, warn, warn_span};

use crate::{
    consensus::{Digest, block::Block},
    dkg::manager::{
        Command,
        ingress::{GetDkgOutcome, VerifyDealerLog},
        validators::{self, DecodedValidator},
    },
};

mod state;
use state::State;

/// Wire message type for DKG protocol communication.
pub(crate) enum Message {
    /// A dealer message containing public and private components for a player.
    Dealer(DealerPubMsg<MinSig>, DealerPrivMsg),
    /// A player acknowledgment sent back to a dealer.
    Ack(PlayerAck<PublicKey>),
}

impl Write for Message {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Dealer(pub_msg, priv_msg) => {
                0u8.write(writer);
                pub_msg.write(writer);
                priv_msg.write(writer);
            }
            Self::Ack(ack) => {
                1u8.write(writer);
                ack.write(writer);
            }
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealer(pub_msg, priv_msg) => pub_msg.encode_size() + priv_msg.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
        }
    }
}

impl Read for Message {
    type Cfg = NonZeroU32;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(reader)?;
        match tag {
            0 => {
                let pub_msg = DealerPubMsg::read_cfg(reader, cfg)?;
                let priv_msg = DealerPrivMsg::read(reader)?;
                Ok(Self::Dealer(pub_msg, priv_msg))
            }
            1 => {
                let ack = PlayerAck::read(reader)?;
                Ok(Self::Ack(ack))
            }
            other => Err(commonware_codec::Error::InvalidEnum(other)),
        }
    }
}

pub(crate) struct Actor<TContext, TPeerManager>
where
    TContext: Clock + commonware_runtime::Metrics + commonware_runtime::Storage,
    TPeerManager: commonware_p2p::Manager,
{
    /// The actor configuration passed in when constructing the actor.
    config: super::Config<TPeerManager>,

    /// The runtime context passed in when constructing the actor.
    context: ContextCell<TContext>,

    /// The channel over which the actor will receive messages.
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    /// Handles to the metrics objects that the actor will update during its
    /// runtime.
    metrics: Metrics,
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext:
        Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + commonware_runtime::Storage,
    TPeerManager: commonware_p2p::Manager<PublicKey = PublicKey, Peers = ordered::Map<PublicKey, Address>>
        + Sync,
{
    pub(super) async fn new(
        config: super::Config<TPeerManager>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let context = ContextCell::new(context);

        let metrics = Metrics::init(&context);

        Ok(Self {
            config,
            context,
            mailbox,
            metrics,
        })
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

    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let Ok(mut storage) = state::builder()
            .partition_prefix(&self.config.partition_prefix)
            .initial_state({
                let mut context = self.context.clone();
                let execution_node = self.config.execution_node.clone();
                let initial_share = self.config.initial_share.clone();
                let epoch_strategy = self.config.epoch_strategy.clone();
                let mut marshal = self.config.marshal.clone();
                async move {
                    read_initial_state_and_set_floor(
                        &mut context,
                        &execution_node,
                        initial_share.clone(),
                        &epoch_strategy,
                        &mut marshal,
                    )
                    .await
                }
            })
            .init(self.context.with_label("state"))
            .await
        else {
            // NOTE: Builder::init emits en error event.
            return;
        };

        let (mux, mut dkg_mux) = mux::Muxer::new(
            self.context.with_label("dkg_mux"),
            sender,
            receiver,
            self.config.mailbox_size,
        );
        mux.start();

        let reason = loop {
            match self.run_dkg_loop(&mut storage, &mut dkg_mux).await {
                Ok(new_state) => {
                    let (new_state, prune_previous) = match new_state {
                        NewState::FromSkip(new_state) => {
                            let prune_previous = new_state.epoch.previous();
                            (new_state, prune_previous)
                        }
                        NewState::Normal(new_state) => (new_state, None),
                    };
                    if let Err(error) = storage
                        .append_state(new_state)
                        .await
                        .wrap_err("failed appending state to journal")
                    {
                        break error;
                    }
                    // If the new state was obtained by skipping a round, all
                    // previous epochs historical and will not observe any
                    // activity. Usually an old epoch is exited on observing the
                    // first finalized height of the new epoch. This is done to
                    // help straggling nodes observe finalizations of the
                    // boundary height. But since the network has already
                    // advanced past the new epoch, there is no need for that.
                    if let Some(prune_previous) = prune_previous {
                        let _ = self.config.epoch_manager.exit(prune_previous);
                        let _ = storage.prune(prune_previous.next()).await;
                    }
                }
                Err(error) => break error,
            }
        };

        tracing::warn_span!("dkg_actor").in_scope(|| {
            warn!(
                %reason,
                "actor exited",
            );
        });
    }

    async fn run_dkg_loop<TStorageContext, TSender, TReceiver>(
        &mut self,
        storage: &mut state::Storage<TStorageContext>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> eyre::Result<NewState>
    where
        TStorageContext: commonware_runtime::Metrics + commonware_runtime::Storage,
        TSender: Sender<PublicKey = PublicKey>,
        TReceiver: Receiver<PublicKey = PublicKey>,
    {
        let state = storage.current();

        if storage
            .get_latest_finalized_block_for_epoch(&state.epoch)
            .is_none()
            && let Some(previous) = storage.previous().await
        {
            // On restarts:
            // If there is no finalized block for this epoch, then we must not
            // have observed the first one. Therefore we need to start a
            // consensus engine to ensure we register peers, schemes, etc.
            self.enter_epoch(&previous)
                .wrap_err("could not instruct epoch manager to enter the previous epoch")?;
        }

        self.metrics.reset();

        self.metrics.dealers.set(state.dealers.len() as i64);
        self.metrics.players.set(state.players.len() as i64);
        self.metrics.syncing_players.set(state.syncers.len() as i64);

        if let Some(previous) = state.epoch.previous() {
            // NOTE: State::prune emits an error event.
            storage.prune(previous).await.wrap_err_with(|| {
                format!("unable to prune storage before up until epoch `{previous}`",)
            })?;
        }

        let all_peers = state.construct_merged_peer_set();
        self.metrics.peers.set(all_peers.len() as i64);
        self.config
            .peer_manager
            .update(state.epoch.get(), all_peers)
            .await;

        self.enter_epoch(&state)
            .wrap_err("could not instruct epoch manager to enter a new epoch")?;

        // TODO: emit an event with round info
        let round = state::Round::from_state(&state, &self.config.namespace);

        let mut dealer_state = storage
            .create_dealer_for_round(
                self.config.me.clone(),
                round.clone(),
                state.share.clone(),
                state.seed,
            )
            .wrap_err("unable to instantiate dealer state")?;

        if dealer_state.is_some() {
            self.metrics.how_often_dealer.inc();
        }

        let mut player_state = storage
            .create_player_for_round(self.config.me.clone(), &round)
            .wrap_err("unable to instantiate player state")?;

        if player_state.is_some() {
            self.metrics.how_often_player.inc();
        }

        // Register a channel for this round
        let (mut round_sender, mut round_receiver) =
            mux.register(state.epoch.get()).await.wrap_err_with(|| {
                format!(
                    "unable to create subchannel for this DKG ceremony of epoch `{}`",
                    state.epoch
                )
            })?;

        let mut ancestry_stream = AncestorStream::new();

        info_span!("run_dkg_loop").in_scope(|| {
            info!(
                me = %self.config.me.public_key(),
                epoch = %round.epoch(),
                dealers = ?state.dealers,
                players = ?state.players,
                syncers = ?state.syncers,
                as_dealer = dealer_state.is_some(),
                as_player= player_state.is_some(),
                "entering a new DKG ceremony",
            )
        });

        let mut skip_to_boundary = false;
        loop {
            let mut shutdown = self.context.stopped().fuse();
            select_biased!(

                _ = &mut shutdown => {
                    break Err(eyre!("shutdown triggered"));
                }

                network_msg = round_receiver.recv().fuse() => {
                    match network_msg {
                        Ok((sender, message)) => {
                            // Produces an error event.
                            let _ = self.handle_network_msg(
                                &round,
                                &mut round_sender,
                                storage,
                                dealer_state.as_mut(),
                                player_state.as_mut(),
                                sender,
                                message,
                            ).await;
                        }
                        Err(err) => {
                            break Err(err).wrap_err("network p2p subchannel closed")
                        }
                    }
                }

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        break Err(eyre!("all instances of the DKG actor's mailbox are dropped"));
                    };

                    match msg.command {
                        Command::Update(update) => {
                            match *update {
                                Update::Tip(height, _) => {
                                    if !skip_to_boundary {
                                        skip_to_boundary |= self.should_skip_round(
                                            &round,
                                            height,
                                        ).await;
                                        if skip_to_boundary {
                                            self.metrics.rounds_skipped.inc();
                                        }
                                    }
                                }
                                Update::Block(block, ack) if skip_to_boundary => {
                                    let maybe_new_state = match self.handle_finalized_boundary(
                                        msg.cause,
                                        &round,
                                        block,
                                    ).await {
                                        Ok(maybe_state) => maybe_state,
                                        Err(err) => break Err(err).wrap_err("failed handling finalized block"),
                                    };
                                    ack.acknowledge();
                                    if let Some(new_state) = maybe_new_state {
                                        break Ok(new_state);
                                    }
                                }

                                Update::Block(block, ack) => {
                                    let maybe_new_state = match self.handle_finalized_block(
                                        msg.cause,
                                        &state,
                                        &round,
                                        &mut round_sender,
                                        storage,
                                        &mut dealer_state,
                                        &mut player_state,
                                        block,
                                    ).await {
                                        Ok(maybe_state) => maybe_state,
                                        Err(err) => break Err(err).wrap_err("failed handling finalized block"),
                                    };
                                    ack.acknowledge();
                                    if let Some(new_state) = maybe_new_state {
                                        break Ok(new_state);
                                    }
                                }
                            }
                        }

                        Command::GetDealerLog(get_dealer_log) => {
                            warn_span!("get_dealer_log").in_scope(|| {
                                let log = if get_dealer_log.epoch != round.epoch() {
                                    warn!(
                                        request.epoch = %get_dealer_log.epoch,
                                        round.epoch = %round.epoch(),
                                        "application requested dealer log for \
                                        an epoch other than we are currently \
                                        running",
                                    );
                                    None
                                } else {
                                    dealer_state
                                        .as_ref()
                                        .and_then(|dealer_state| dealer_state.finalized())
                                };
                                let _ = get_dealer_log
                                .response
                                .send(log);
                            });
                        }

                        Command::GetDkgOutcome(request) => {
                            if let Some(target) = ancestry_stream.tip()
                            && target == request.digest
                            {
                                ancestry_stream.update_receiver((msg.cause, request));
                                continue;
                            }
                            if let Some((hole, request)) = self
                                .handle_get_dkg_outcome(
                                    &msg.cause,
                                    storage,
                                    &player_state,
                                    &round,
                                    &state,
                                    request,
                                )
                                .await
                            {
                                let stream = match self.config.marshal.ancestry((None, hole)).await {
                                    Some(stream) => stream,
                                    None => break Err(eyre!("marshal mailbox is closed")),
                                };
                                ancestry_stream.set(
                                    (msg.cause, request),
                                    stream,
                                );
                            }
                        }
                        Command::VerifyDealerLog(verify) => {
                            self.handle_verify_dealer_log(
                                &state,
                                &round,
                                verify,
                            );
                        }
                    }
                }

                notarized_block = ancestry_stream.next() => {
                    if let Some(block) = notarized_block {
                        storage.cache_notarized_block(&round, block);
                        let (cause, request) = ancestry_stream
                            .take_request()
                            .expect("if the stream is yielding blocks, there must be a receiver");
                        if let Some((hole, request)) = self
                            .handle_get_dkg_outcome(&cause, storage, &player_state, &round, &state, request)
                            .await
                        {
                            let stream = match self.config.marshal.ancestry((None, hole)).await {
                                Some(stream) => stream,
                                None => break Err(eyre!("marshal mailbox is closed")),
                            };
                            ancestry_stream.set(
                                (cause, request),
                                stream,
                            );
                        }
                    }
                }

            )
        }
    }

    fn handle_verify_dealer_log(
        &self,
        state: &state::State,
        round: &state::Round,
        VerifyDealerLog {
            epoch,
            bytes,
            response,
        }: VerifyDealerLog,
    ) {
        if state.epoch != epoch {
            let _ = response.send(Err(eyre!(
                "requested dealer log for epoch `{epoch}`, but current round \
                is for epoch `{}`",
                state.epoch
            )));
            return;
        }
        let res = SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
            &mut &bytes[..],
            &NZU32!(state.players.len() as u32),
        )
        .wrap_err("failed reading dealer log from header")
        .and_then(|log| {
            log.check(round.info())
                .map(|(dealer, _)| dealer)
                .ok_or_eyre("not a dealer in the current round")
        })
        .inspect(|_| {
            self.metrics.dealings_read.inc();
        })
        .inspect_err(|_| {
            self.metrics.bad_dealings.inc();
        });
        let _ = response.send(res);
    }

    /// Determines if it makes sense to continue with the current DKG ceremony.
    ///
    /// If `finalized_tip` indicates that the *next* epoch was already finalized,
    /// then there is no point in continuing with the current DKG round.
    ///
    /// We know that an epoch was finalized by either observing the boundary
    /// block for said epoch, or by observing an even newer epoch.
    #[instrument(
        skip_all,
        fields(
            round.epoch = %round.epoch(),
            finalized.tip = finalized_tip,
            finalized.epoch = tracing::field::Empty,
        ),
    )]
    async fn should_skip_round(&mut self, round: &state::Round, finalized_tip: u64) -> bool {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(finalized_tip)
            .expect("epoch strategy is valid for all heights");
        Span::current().record(
            "finalized.epoch",
            tracing::field::display(epoch_info.epoch()),
        );

        let should_skip_round = epoch_info.epoch() > round.epoch().next()
            || (epoch_info.epoch() == round.epoch().next() && epoch_info.last() == finalized_tip);

        if should_skip_round {
            let boundary_height = self
                .config
                .epoch_strategy
                .last(round.epoch())
                .expect("epoch strategy is valid for all epochs");
            info!(
                boundary_height,
                "confirmed that the network is at least 2 epochs aheads of us; \
                setting synchronization floor to boundary height of our DKG's \
                epoch and reporting that the rest of the DKG round should be \
                skipped",
            );

            // NOTE: `set_floor(height)` implies that the next block sent by
            // marshal will be height + 1.
            self.config.marshal.set_floor(boundary_height - 1).await;
        }
        should_skip_round
    }

    /// Handles a finalized block.
    ///
    /// Returns a new [`State`] after finalizing the boundary block of the epoch.
    ///
    /// Some block heights are special cased:
    ///
    /// + first height of an epoch: notify the epoch manager that the previous
    ///   epoch can be shut down.
    /// + last height of an epoch:
    ///     1. notify the epoch manager that a new epoch can be entered;
    ///     2. prepare for the state of the next iteration by finalizing the current
    ///        DKG round and reading the next players (players in the DKG round after
    ///        the immediately next one) from the smart contract.
    ///
    /// The processing of all other blocks depends on which part of the epoch
    /// they fall in:
    ///
    /// + first half: if we are a dealer, distribute the generated DKG shares
    ///   to the players and collect their acks. If we are a player, receive
    ///   DKG shares and respond with an ack.
    /// + exact middle of an epoch: if we are a dealer, generate the dealer log
    ///   of the DKG ceremony.
    /// + second half of the epoch: read dealer logs from blocks.
    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            dkg.epoch = %round.epoch(),
            block.height = block.height(),
            block.extra_data.bytes = block.header().extra_data().len(),
        ),
        err,
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "easiest way to express this for now"
    )]
    // TODO(janis): replace this by a struct?
    async fn handle_finalized_block<TStorageContext, TSender>(
        &mut self,
        cause: Span,
        state: &state::State,
        round: &state::Round,
        round_channel: &mut TSender,
        storage: &mut state::Storage<TStorageContext>,
        dealer_state: &mut Option<state::Dealer>,
        player_state: &mut Option<state::Player>,
        block: Block,
    ) -> eyre::Result<Option<NewState>>
    where
        TStorageContext: commonware_runtime::Metrics + commonware_runtime::Storage,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(block.height())
            .expect("epoch strategy is covering all block heights");

        ensure!(
            epoch_info.epoch() == round.epoch(),
            "block was not for this epoch; must observe all blocks epoch by \
            epoch; cannot deal with observing blocks out-of-order"
        );

        if block.height() == epoch_info.first()
            && let Some(previous) = round.epoch().previous()
        {
            self.config
                .epoch_manager
                .exit(previous)
                .wrap_err("failed to instruct epoch manager to exit the previous epoch")?;
        }

        match epoch_info.phase() {
            EpochPhase::Early => {
                if let Some(dealer_state) = dealer_state {
                    self.distribute_shares(
                        storage,
                        round.epoch(),
                        dealer_state,
                        player_state,
                        round_channel,
                    )
                    .await;
                }
            }
            EpochPhase::Midpoint | EpochPhase::Late => {
                if let Some(dealer_state) = dealer_state {
                    dealer_state.finalize();
                }
            }
        }

        if block.height() != epoch_info.last() {
            if !block.header().extra_data().is_empty() {
                'handle_log: {
                    let (dealer, log) =
                        match read_dealer_log(block.header().extra_data().as_ref(), round) {
                            Err(reason) => {
                                warn!(
                                    %reason,
                                    "failed to read dealer log from block \
                                    extraData header field");
                                break 'handle_log;
                            }
                            Ok((dealer, log)) => (dealer, log),
                        };
                    storage
                        .append_dealer_log(round.epoch(), dealer.clone(), log)
                        .await
                        .wrap_err("failed to append log to journal")?;
                    if self.config.me.public_key() == dealer
                        && let Some(dealer_state) = dealer_state
                    {
                        info!(
                            "found own dealing in finalized block; deleting it \
                            from state to not write it again"
                        );
                        dealer_state.take_finalized();
                    }
                }
            }

            storage
                .append_finalized_block(round.epoch(), block)
                .await
                .wrap_err("failed to append finalized block to journal")?;

            return Ok(None);
        }

        info!("reached last block of epoch; reading DKG outcome from header");

        let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
            &mut block.header().extra_data().as_ref(),
        )
        .expect("the last block of an epoch must contain the DKG outcome");

        info!("reading validator from contract");

        let all_validators = read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            round.epoch(),
            &self.config.epoch_strategy,
            &self.metrics.attempts_to_read_validator_contract,
        )
        .await;

        let (local_output, mut share) = if let Some((outcome, share)) =
            storage.get_dkg_outcome(&state.epoch, &block.parent_digest())
        {
            debug!("using cached DKG outcome");
            (outcome.clone(), share.clone())
        } else {
            let logs = storage
                .logs_for_epoch(round.epoch())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>();

            if let Some(player_state) = player_state.take() {
                info!("we were a player in the ceremony; finalizing share");
                // NOTE: this method will panic if the player lost state. There
                // is a strong assumption that if the player ACKed shares (so
                // that they are not revealed), that it must have the shares
                // available. Upon restart, the shares must be replayed against
                // the player state.
                match player_state.finalize(logs, 1) {
                    Ok((new_output, new_share)) => {
                        info!("local DKG ceremony was a success");
                        (new_output, Some(new_share))
                    }
                    Err(error) => {
                        warn!(
                            error = %eyre::Report::new(error),
                            "local DKG ceremony was a failure",
                        );
                        (state.output.clone(), state.share.clone())
                    }
                }
            } else {
                match observe(round.info().clone(), logs, 1) {
                    Ok(output) => {
                        info!("local DKG ceremony was a success");
                        (output, None)
                    }
                    Err(error) => {
                        warn!(
                            error = %eyre::Report::new(error),
                            "local DKG ceremony was a failure",
                        );
                        (state.output.clone(), state.share.clone())
                    }
                }
            }
        };

        if local_output != onchain_outcome.output {
            let am_player = onchain_outcome
                .next_players
                .position(&self.config.me.public_key())
                .is_some();
            warn!(
                am_player,
                "the output of the local DKG ceremony does not match what is \
                on chain; something is terribly wrong; will try and participate \
                in the next round (if a player), but if we are misbehaving and \
                other nodes are blocking us it might be time to delete this node \
                and spin up a new identity",
            );
            share.take();
        }

        // Because we use cached data we, need to check for DKG success here:
        // if the on-chain output is the input output (the output of the previous
        // state), then we know the DKG failed.
        if onchain_outcome.output == state.output {
            self.metrics.failures.inc();
        } else {
            self.metrics.successes.inc();
        }

        Ok(Some(NewState::Normal(state::State {
            epoch: onchain_outcome.epoch,
            seed: Summary::random(&mut self.context),
            output: onchain_outcome.output.clone(),
            share,
            dealers: pubkeys_to_addrs(onchain_outcome.players().clone(), &all_validators),
            players: pubkeys_to_addrs(onchain_outcome.next_players, &all_validators),
            syncers: ordered::Map::from_iter_dedup(
                all_validators
                    .iter_pairs()
                    .filter(|(_, v)| v.active)
                    .map(|(k, v)| (k.clone(), v.inbound)),
            ),
            is_full_dkg: onchain_outcome.is_next_full_dkg,
        })))
    }

    /// Looks for and handles a finalized boundary block.
    ///
    /// Called if the DKG round if asked to skip ahead to the boundary block.
    /// Does not consider any state for the current DKG round; just reads the
    /// DKG outcome from the header and returns it.
    #[instrument(
        parent = &cause,
        skip_all,
        fields(
            dkg.epoch = %round.epoch(),
            block.height = block.height(),
            block.extra_data.bytes = block.header().extra_data().len(),
        ),
        err,
    )]
    async fn handle_finalized_boundary(
        &mut self,
        cause: Span,
        round: &state::Round,
        block: Block,
    ) -> eyre::Result<Option<NewState>> {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(block.height())
            .expect("epoch strategy is covering all block heights");

        ensure!(
            epoch_info.epoch() == round.epoch(),
            "block was not for this epoch; must observe all blocks epoch by \
            epoch; cannot deal with observing blocks out-of-order"
        );

        if block.height() != epoch_info.last() {
            return Ok(None);
        }

        info!("found boundary block; reading DKG outcome from header");

        let onchain_outcome = tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(
            &mut block.header().extra_data().as_ref(),
        )
        .expect("the last block of an epoch must contain the DKG outcome");

        info!("reading validators from contract");

        let all_validators = read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            round.epoch(),
            &self.config.epoch_strategy,
            &self.metrics.attempts_to_read_validator_contract,
        )
        .await;

        Ok(Some(NewState::FromSkip(state::State {
            epoch: onchain_outcome.epoch,
            seed: Summary::random(&mut self.context),
            output: onchain_outcome.output.clone(),
            share: None,
            dealers: pubkeys_to_addrs(onchain_outcome.players().clone(), &all_validators),
            players: pubkeys_to_addrs(onchain_outcome.next_players, &all_validators),
            syncers: ordered::Map::from_iter_dedup(
                all_validators
                    .iter_pairs()
                    .filter(|(_, v)| v.active)
                    .map(|(k, v)| (k.clone(), v.inbound)),
            ),
            is_full_dkg: onchain_outcome.is_next_full_dkg,
        })))
    }

    #[instrument(skip_all, fields(me = %self.config.me.public_key(), %epoch))]
    async fn distribute_shares<TStorageContext, TSender>(
        &self,
        storage: &mut state::Storage<TStorageContext>,
        epoch: Epoch,
        dealer_state: &mut state::Dealer,
        player_state: &mut Option<state::Player>,
        round_channel: &mut TSender,
    ) where
        TStorageContext: commonware_runtime::Metrics + commonware_runtime::Storage,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let me = self.config.me.public_key();
        for (player, pub_msg, priv_msg) in dealer_state.shares_to_distribute().collect::<Vec<_>>() {
            if player == me {
                if let Some(player_state) = player_state
                    && let Ok(ack) = player_state
                        .receive_dealing(storage, epoch, me.clone(), pub_msg, priv_msg)
                        .await
                        .inspect(|_| {
                            self.metrics.shares_distributed.inc();
                            self.metrics.shares_received.inc();
                        })
                        .inspect_err(|error| warn!(%error, "failed to store our own dealing"))
                    && let Ok(()) = dealer_state
                        .receive_ack(storage, epoch, me.clone(), ack)
                        .await
                        .inspect_err(|error| warn!(%error, "failed to store our own ACK"))
                {
                    self.metrics.acks_received.inc();
                    self.metrics.acks_sent.inc();
                    info!("stored our own ACK and share");
                }
            } else {
                // Send to remote player
                let payload = Message::Dealer(pub_msg, priv_msg).encode().freeze();
                match round_channel
                    .send(Recipients::One(player.clone()), payload, true)
                    .await
                {
                    Ok(success) => {
                        if success.is_empty() {
                            // TODO(janis): figure out what it means if the response
                            // is empty. Does it just mean the other party failed
                            // to respond?
                            info!(%player, "failed to send share");
                        } else {
                            self.metrics.shares_distributed.inc();
                            info!(%player, "share sent");
                        }
                    }
                    Err(error) => {
                        warn!(%player, %error, "error sending share");
                    }
                }
            }
        }
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %round.epoch(),
            %from,
            bytes = message.len()),
        err)]
    #[expect(
        clippy::too_many_arguments,
        reason = "easiest way to express this for now"
    )]
    // TODO(janis): replace this by a struct?
    async fn handle_network_msg<TStorageContext>(
        &self,
        round: &state::Round,
        round_channel: &mut impl Sender<PublicKey = PublicKey>,
        storage: &mut state::Storage<TStorageContext>,
        dealer_state: Option<&mut state::Dealer>,
        player_state: Option<&mut state::Player>,
        from: PublicKey,
        mut message: Bytes,
    ) -> eyre::Result<()>
    where
        TStorageContext: commonware_runtime::Metrics + commonware_runtime::Storage,
    {
        let msg = Message::read_cfg(&mut message, &NZU32!(round.players().len() as u32))
            .wrap_err("failed reading p2p message")?;

        match msg {
            Message::Dealer(pub_msg, priv_msg) => {
                if let Some(player_state) = player_state {
                    info!("received message from a dealer");
                    self.metrics.shares_received.inc();
                    let ack = player_state
                        .receive_dealing(storage, round.epoch(), from.clone(), pub_msg, priv_msg)
                        .await
                        .wrap_err("failed storing dealing")?;

                    if let Err(error) = round_channel
                        .send(
                            Recipients::One(from.clone()),
                            Message::Ack(ack).encode().freeze(),
                            true,
                        )
                        .await
                    {
                        // FIXME(janis): the GATs in the Sender (and LimitedSender)
                        // lead to `borrowed data escapes outside of method` errors.
                        // `wrap_err` with early return does not work, and neither
                        // does `Report::new` nor `&error as &dyn std::error::Error`.
                        warn!(
                            reason = ?error,
                            "failed returning ACK to dealer",
                        );
                        bail!("failed returning ACK to dealer");
                    }
                    info!("returned ACK to dealer");
                    self.metrics.acks_sent.inc();
                } else {
                    info!("received a dealer message, but we are not a player");
                }
            }
            Message::Ack(ack) => {
                if let Some(dealer_state) = dealer_state {
                    info!("received an ACK");
                    self.metrics.acks_received.inc();
                    dealer_state
                        .receive_ack(storage, round.epoch(), from, ack)
                        .await
                        .wrap_err("failed storing ACK")?;
                } else {
                    info!("received an ACK, but we are not a dealer");
                }
            }
        }
        Ok(())
    }

    /// Attempts to serve a `GetDkgOutcome` request by finalizing the DKG outcome.
    ///
    /// A DKG outcome can be finalized in one of the following cases:
    ///
    /// 1. if the DKG actor has observed as many dealer logs as there are dealers.
    /// 2. if all blocks in an epoch were observed (finalized + notarized leading
    /// up to `request.digest`).
    ///
    /// If the DKG was finalized this way, this method will return `None`.
    /// Otherwise will return `Some((digest, request))` if the block identified
    /// by `digest` was missing and needs to be fetched first to ensure all
    /// blocks in an epoch were observed.
    #[instrument(
        parent = cause,
        skip_all,
        fields(
            as_player = player_state.is_some(),
            our.epoch = %round.epoch(),
        ),
    )]
    async fn handle_get_dkg_outcome<TStorageContext>(
        &mut self,
        cause: &Span,
        storage: &mut state::Storage<TStorageContext>,
        player_state: &Option<state::Player>,
        round: &state::Round,
        state: &State,
        request: GetDkgOutcome,
    ) -> Option<(Digest, GetDkgOutcome)>
    where
        TStorageContext: commonware_runtime::Metrics + commonware_runtime::Storage,
    {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(request.height)
            .expect("our strategy covers all epochs");
        if round.epoch() != epoch_info.epoch() {
            warn!(
                request.epoch = %epoch_info.epoch(),
                "request is not for our epoch"
            );
            return None;
        }

        let output = if let Some((output, _)) = storage
            .get_dkg_outcome(&state.epoch, &request.digest)
            .cloned()
        {
            output
        } else {
            let mut logs = storage
                .logs_for_epoch(round.epoch())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>();

            'ensure_enough_logs: {
                if logs.len() == round.dealers().len() {
                    info!("collected as many logs as there are dealers; concluding DKG");
                    break 'ensure_enough_logs;
                }

                info!(
                    "did not have all dealer logs yet; will try to extend with \
                    logs read from notarized blocks and concluding DKG that way",
                );
                let (mut height, mut digest) = (request.height, request.digest);
                while height >= epoch_info.first()
                    && Some(height)
                        >= storage
                            .get_latest_finalized_block_for_epoch(&round.epoch())
                            .map(|(_, info)| info.height)
                {
                    if let Some(block) =
                        storage.get_notarized_reduced_block(&round.epoch(), &digest)
                    {
                        logs.extend(block.log.clone());
                        height = block.height;
                        digest = block.parent;
                    } else {
                        return Some((digest, request));
                    }
                }
            }

            // Create a player-state ad hoc: the DKG player object is not
            // cloneable, and finalizing consumes it.
            let player_state = player_state.is_some().then(||
                storage
                        .create_player_for_round(self.config.me.clone(), round)
                        .expect("created a player instance before, must be able to create it again")
                        .expect("did not return a player instance even though we created it for this round already")
            );

            let (output, share) = if let Some(player_state) = player_state {
                match player_state.finalize(logs, 1) {
                    Ok((new_output, share)) => {
                        info!("DKG ceremony was a success");
                        (new_output, Some(share))
                    }
                    Err(error) => {
                        warn!(
                            error = %eyre::Report::new(error),
                            "DKG ceremony was a failure",
                        );
                        (state.output.clone(), state.share.clone())
                    }
                }
            } else {
                match observe(round.info().clone(), logs, 1) {
                    Ok(output) => {
                        info!("DKG ceremony was a success");
                        (output, None)
                    }
                    Err(error) => {
                        warn!(
                            error = %eyre::Report::new(error),
                            "DKG ceremony was a failure",
                        );
                        (state.output.clone(), state.share.clone())
                    }
                }
            };

            storage.cache_dkg_outcome(state.epoch, request.digest, output.clone(), share);
            output
        };

        // Check if next ceremony should be full.
        // Read from pre-last block of the epoch, but never ahead of the current request.
        let next_epoch = state.epoch.next();
        let is_next_full_dkg = validators::read_next_full_dkg_ceremony(
            &self.config.execution_node,
            epoch_info.last().saturating_sub(1).min(request.height),
        )
        .is_ok_and(|epoch| epoch == next_epoch.get());
        if is_next_full_dkg {
            info!(%next_epoch, "next DKG ceremony will be full");
        }

        if request
            .response
            .send(OnchainDkgOutcome {
                epoch: next_epoch,
                output,
                next_players: state.syncers.keys().clone(),
                is_next_full_dkg,
            })
            .is_err()
        {
            warn!("requester went away before speculative DKG outcome could be sent");
        };

        None
    }

    fn enter_epoch(&mut self, state: &state::State) -> eyre::Result<()> {
        self.config
            .epoch_manager
            .enter(
                state.epoch,
                state.output.public().clone(),
                state.share.clone(),
                state.dealers.keys().clone(),
            )
            .wrap_err("could not instruct epoch manager to enter epoch")
    }
}

enum NewState {
    FromSkip(state::State),
    Normal(state::State),
}

#[instrument(skip_all, err)]
async fn read_initial_state_and_set_floor<TContext>(
    context: &mut TContext,
    node: &TempoFullNode,
    share: Option<Share>,
    epoch_strategy: &FixedEpocher,
    marshal: &mut crate::alias::marshal::Mailbox,
) -> eyre::Result<State>
where
    TContext: CryptoRngCore,
{
    let newest_height = node
        .provider
        .best_block_number()
        .wrap_err("failed reading newest block number from database")?;

    let epoch_info = epoch_strategy
        .containing(newest_height)
        .expect("epoch strategy is for all heights");

    let last_boundary = if epoch_info.last() == newest_height {
        newest_height
    } else {
        epoch_info.epoch().previous().map_or(0, |previous| {
            epoch_strategy
                .last(previous)
                .expect("epoch strategy is for all epochs")
        })
    };
    info!(
        newest_height,
        last_boundary,
        "execution layer reported newest available block, reading on-chain \
        DKG outcome from last boundary height, and validator state from newest \
        block"
    );
    let header = node
        .provider
        .header_by_number(last_boundary)
        .map_or_else(
            |e| Err(eyre::Report::new(e)),
            |header| header.ok_or_eyre("execution layer reported it had no header"),
        )
        .wrap_err_with(|| {
            format!("failed to read header for last boundary block number `{last_boundary}`")
        })?;

    // XXX: Reads the contract from the latest available block (newest_height),
    // not from the boundary. The reason is that we cannot be sure that the
    // boundary block is available. But we know that the on-chain state is
    // immutable - validators never change their identity and never update their
    // IP addresses (the latter would actually probably be fine; what matters is
    // that identities don't change).
    let onchain_outcome =
        tempo_dkg_onchain_artifacts::OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
            .wrap_err("the boundary header did not contain the on-chain DKG outcome")?;

    let all_validators = validators::read_from_contract_at_block(0, node, newest_height)
        .await
        .wrap_err_with(|| {
            format!("failed reading validator config from block height `{newest_height}`")
        })?;

    let share = 'verify_initial_share: {
        let Some(share) = share else {
            break 'verify_initial_share None;
        };
        let Ok(partial) = onchain_outcome.sharing().partial_public(share.index) else {
            warn!(
                "the index of the provided share exceeds the polynomial of the \
                on-chain DKG outcome; ignoring the share"
            );
            break 'verify_initial_share None;
        };
        if share.public::<MinSig>() != partial {
            warn!(
                "the provided share does not match the polynomial of the \
                on-chain DKG outcome; ignoring the share"
            );
            break 'verify_initial_share None;
        }
        Some(share)
    };

    info!(newest_height, "setting sync floor");
    marshal.set_floor(newest_height).await;

    Ok(State {
        epoch: onchain_outcome.epoch,
        seed: Summary::random(context),
        output: onchain_outcome.output.clone(),
        share,
        dealers: pubkeys_to_addrs(onchain_outcome.players().clone(), &all_validators),
        players: pubkeys_to_addrs(onchain_outcome.next_players, &all_validators),
        syncers: ordered::Map::from_iter_dedup(
            all_validators
                .iter_pairs()
                .filter(|(_, v)| v.active)
                .map(|(k, v)| (k.clone(), v.inbound)),
        ),
        is_full_dkg: false,
    })
}

#[derive(Clone)]
struct Metrics {
    peers: Gauge,

    shares_distributed: Gauge,
    shares_received: Gauge,
    acks_received: Gauge,
    acks_sent: Gauge,
    dealings_read: Gauge,
    bad_dealings: Gauge,

    failures: Counter,
    successes: Counter,

    dealers: Gauge,
    players: Gauge,
    syncing_players: Gauge,

    how_often_dealer: Counter,
    how_often_player: Counter,

    rounds_skipped: Counter,
    attempts_to_read_validator_contract: Counter,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let syncing_players = Gauge::default();
        context.register(
            "syncing_players",
            "how many syncing players were registered; these will become players in the next ceremony",
            syncing_players.clone(),
        );

        let peers = Gauge::default();
        context.register(
            "peers",
            "how many peers are registered overall for the latest epoch",
            peers.clone(),
        );

        let failures = Counter::default();
        context.register(
            "ceremony_failures",
            "the number of failed ceremonies a node participated in",
            failures.clone(),
        );

        let successes = Counter::default();
        context.register(
            "ceremony_successes",
            "the number of successful ceremonies a node participated in",
            successes.clone(),
        );

        let dealers = Gauge::default();
        context.register(
            "ceremony_dealers",
            "the number of dealers in the currently running ceremony",
            dealers.clone(),
        );
        let players = Gauge::default();
        context.register(
            "ceremony_players",
            "the number of players in the currently running ceremony",
            players.clone(),
        );

        let how_often_dealer = Counter::default();
        context.register(
            "how_often_dealer",
            "number of the times as node was active as a dealer",
            how_often_dealer.clone(),
        );
        let how_often_player = Counter::default();
        context.register(
            "how_often_player",
            "number of the times as node was active as a player",
            how_often_player.clone(),
        );

        let shares_distributed = Gauge::default();
        context.register(
            "ceremony_shares_distributed",
            "the number of shares distributed by this node as a dealer in the current ceremony",
            shares_distributed.clone(),
        );

        let shares_received = Gauge::default();
        context.register(
            "ceremony_shares_received",
            "the number of shares received by this node as a playr in the current ceremony",
            shares_received.clone(),
        );

        let acks_received = Gauge::default();
        context.register(
            "ceremony_acks_received",
            "the number of acknowledgments received by this node as a dealer in the current ceremony",
            acks_received.clone(),
        );

        let acks_sent = Gauge::default();
        context.register(
            "ceremony_acks_sent",
            "the number of acknowledgments sent by this node as a player in the current ceremony",
            acks_sent.clone(),
        );

        let dealings_read = Gauge::default();
        context.register(
            "ceremony_dealings_read",
            "the number of dealings read from the blockchain in the current ceremony",
            dealings_read.clone(),
        );

        let bad_dealings = Gauge::default();
        context.register(
            "ceremony_bad_dealings",
            "the number of blocks where decoding and verifying dealings failed in the current ceremony",
            bad_dealings.clone(),
        );

        let rounds_skipped = Counter::default();
        context.register(
            "rounds_skipped",
            "how many DKG rounds were skipped because the node fell too far behind and tried to catch up",
            rounds_skipped.clone(),
        );

        let attempts_to_read_validator_contract = Counter::default();
        context.register(
            "attempts_to_read_validator_contract",
            "the total number of attempts it took to read the validators from the smart contract",
            attempts_to_read_validator_contract.clone(),
        );

        Self {
            peers,
            syncing_players,
            shares_distributed,
            shares_received,
            acks_received,
            acks_sent,
            dealings_read,
            bad_dealings,
            dealers,
            players,
            how_often_dealer,
            how_often_player,
            failures,
            successes,
            rounds_skipped,
            attempts_to_read_validator_contract,
        }
    }

    fn reset(&self) {
        self.shares_distributed.set(0);
        self.shares_received.set(0);
        self.acks_received.set(0);
        self.acks_sent.set(0);
        self.dealings_read.set(0);
        self.bad_dealings.set(0);
    }
}

/// Attempts to read the validator config from the smart contract until it becomes available.
async fn read_validator_config_with_retry<C: commonware_runtime::Clock>(
    context: &C,
    node: &TempoFullNode,
    epoch: Epoch,
    epoch_strategy: &FixedEpocher,
    metric: &Counter,
) -> ordered::Map<PublicKey, DecodedValidator> {
    let mut attempts = 0;
    let retry_after = Duration::from_secs(1);

    let last = epoch_strategy
        .last(epoch)
        .expect("epoch strategy is valid for all epochs");
    loop {
        metric.inc();
        attempts += 1;
        if let Ok(validators) = validators::read_from_contract_at_block(attempts, node, last).await
        {
            break validators;
        }
        tracing::warn_span!("read_validator_config_with_retry").in_scope(|| {
            if attempts < 10 {
                warn!(
                    attempts,
                    retry_after = %tempo_telemetry_util::display_duration(retry_after),
                    "reading validator config from contract failed; will retry",
                );
            } else {
                error!(
                    attempts,
                    retry_after = %tempo_telemetry_util::display_duration(retry_after),
                    "reading validator config from contract failed; will retry",
                );
            }
        });
        context.sleep(retry_after).await;
    }
}

fn pubkeys_to_addrs(
    keys: ordered::Set<PublicKey>,
    validators: &ordered::Map<PublicKey, DecodedValidator>,
) -> ordered::Map<PublicKey, SocketAddr> {
    ordered::Map::from_iter_dedup(keys.into_iter().map(|key| {
        (
            key.clone(),
            validators
                .get_value(&key)
                .expect(
                    "all DKG participants must have an entry in the \
                        unfiltered, contract validator set; if one does not, \
                        then it was wrongly included in the ceremony or the \
                        contract was bad",
                )
                .outbound,
        )
    }))
}

/// A wrapper around [`marshal::ingress::mailbox::AncestorStream`] wrapped in
/// an option to make it easier to work with select macros.
///
/// Invariants: if the inner stream is set, then the matching original request
/// is also set.
struct AncestorStream {
    pending_request: Option<(Span, GetDkgOutcome)>,
    inner: Option<marshal::ingress::mailbox::AncestorStream<Scheme<PublicKey, MinSig>, Block>>,
}

impl AncestorStream {
    fn new() -> Self {
        Self {
            pending_request: None,
            inner: None,
        }
    }

    fn take_request(&mut self) -> Option<(Span, GetDkgOutcome)> {
        self.inner.take();
        self.pending_request.take()
    }

    fn set(
        &mut self,
        pending_request: (Span, GetDkgOutcome),
        stream: marshal::ingress::mailbox::AncestorStream<Scheme<PublicKey, MinSig>, Block>,
    ) {
        self.pending_request.replace(pending_request);
        self.inner.replace(stream);
    }

    fn tip(&self) -> Option<Digest> {
        self.pending_request.as_ref().map(|(_, req)| req.digest)
    }

    fn update_receiver(&mut self, pending_request: (Span, GetDkgOutcome)) {
        self.pending_request.replace(pending_request);
    }
}

impl Stream for AncestorStream {
    type Item = Block;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let item = {
            let this = match self.inner.as_mut() {
                Some(inner) => inner,
                None => return Poll::Ready(None),
            };
            this.poll_next_unpin(cx)
        };
        match futures::ready!(item) {
            None => {
                self.inner.take();
                Poll::Ready(None)
            }
            Some(block) => Poll::Ready(Some(block)),
        }
    }
}

impl FusedStream for AncestorStream {
    fn is_terminated(&self) -> bool {
        self.inner.is_none()
    }
}

fn read_dealer_log(
    mut bytes: &[u8],
    round: &state::Round,
) -> eyre::Result<(PublicKey, DealerLog<MinSig, PublicKey>)> {
    let signed_log = dkg::SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
        &mut bytes,
        &NZU32!(round.players().len() as u32),
    )
    .wrap_err("could not decode as signed dealer log")?;

    let (dealer, log) = signed_log
        .check(round.info())
        .ok_or_eyre("failed checking signed log against current round")?;
    Ok((dealer, log))
}
