use std::{cmp::Ordering, collections::BTreeMap, num::NonZeroU32, sync::Arc, task::Poll};

use alloy_consensus::{BlockHeader as _, Sealable};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode as _, EncodeSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    Heightable as _,
    marshal::{Update, core::DigestFallback},
    types::{Epoch, EpochPhase, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::{
            self as dkg, DealerLog, DealerPrivMsg, DealerPubMsg, Logs, PlayerAck, SignedDealerLog,
            observe,
        },
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::{Batch, PrivateKey, PublicKey},
    transcript::Summary,
};
use commonware_math::algebra::Random as _;
use commonware_p2p::{
    Receiver, Recipients, Sender,
    utils::mux::{self, MuxHandle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, IoBuf, Spawner, Storage, spawn_cell,
    telemetry::metrics::{
        Counter, Gauge, MetricsExt as _,
        histogram::{Buckets, Timed},
    },
};
use commonware_utils::{Acknowledgement, N3f1, NZU32, acknowledgement::Exact};

use eyre::{OptionExt as _, Report, WrapErr as _, bail, ensure, eyre};
use futures::{
    FutureExt as _, Stream, StreamExt as _,
    channel::mpsc,
    future::{Ready, ready},
    stream::{FusedStream, FuturesOrdered},
};
use rand_core::CryptoRng;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::TempoHeader;
use tokio::select;
use tracing::{Level, Span, debug, info, info_span, instrument, warn};

use crate::consensus::{Digest, block::Block};

mod state;
#[cfg(test)]
mod tests;
use state::{Dealer, Player, Round, ShareState, State};

use super::{
    Command, EpochManager, ExecutionLayer, Marshal,
    ingress::{GetDkgOutcome, VerifyDealerLog},
};

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

pub(crate) struct Actor<
    TContext,
    TExecutionLayer = Arc<tempo_node::TempoFullNode>,
    TMarshal = crate::alias::marshal::Mailbox,
    TEpochManager = crate::epoch::manager::Mailbox,
> where
    TContext: BufferPooler + Clock + commonware_runtime::Metrics + Storage,
{
    /// The actor configuration passed in when constructing the actor.
    config: super::Config<TExecutionLayer, TMarshal, TEpochManager>,

    /// The runtime context passed in when constructing the actor.
    context: ContextCell<TContext>,

    /// The channel over which the actor will receive messages.
    mailbox: mpsc::UnboundedReceiver<super::Message>,

    /// Handles to the metrics objects that the actor will update during its
    /// runtime.
    metrics: Metrics,

    /// Queue of finalized blocks if marshal is configured to send out multiple
    /// blocks at a time.
    pending_finalized_blocks: FuturesOrdered<Ready<(Span, Block, Exact)>>,
}

impl<TContext, TExecutionLayer, TMarshal, TEpochManager>
    Actor<TContext, TExecutionLayer, TMarshal, TEpochManager>
where
    TContext: BufferPooler + Clock + CryptoRng + commonware_runtime::Metrics + Spawner + Storage,
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
    TEpochManager: EpochManager,
{
    pub(super) async fn new(
        config: super::Config<TExecutionLayer, TMarshal, TEpochManager>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let context = ContextCell::new(context);
        let metrics = Metrics::init(context.as_present());

        Ok(Self {
            config,
            context,
            mailbox,
            metrics,
            pending_finalized_blocks: FuturesOrdered::new(),
        })
    }

    pub(crate) fn start(
        mut self,
        dkg_channel: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(dkg_channel))
    }

    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        // NOTE: The instrumented fns emits on error events

        let Ok(opened) = state::builder()
            .partition_prefix(&self.config.partition_prefix)
            .init_unverified(self.context.child("state"))
            .await
        else {
            return;
        };

        let Ok(mut storage) = self.heal(opened).await else {
            return;
        };

        if self
            .prepopulate_to_last_finalized_height(&mut storage)
            .await
            .is_err()
        {
            return;
        }

        let (mux, mut dkg_mux) = mux::Muxer::new(
            self.context.child("dkg_mux"),
            sender,
            receiver,
            self.config.mailbox_size.into(),
        );

        mux.start();

        let reason = loop {
            if let Err(error) = self.run_dkg_loop(&mut storage, &mut dkg_mux).await {
                break error;
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
    ) -> eyre::Result<()>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
        TSender: Sender<PublicKey = PublicKey>,
        TReceiver: Receiver<PublicKey = PublicKey>,
    {
        let state = storage.current();

        self.metrics.reset();
        self.metrics
            .dealers
            .metric()
            .set(state.dealers().len() as i64);
        self.metrics
            .players
            .metric()
            .set(state.players().len() as i64);

        if let Some(previous) = state.epoch.previous() {
            // NOTE: State::prune emits an error event.
            storage.prune(previous).await.wrap_err_with(|| {
                format!("unable to prune storage before up until epoch `{previous}`",)
            })?;
        }

        self.enter_epoch(&state)
            .wrap_err("could not instruct epoch manager to enter a new epoch")?;

        // TODO: emit an event with round info
        let round = Round::from_state(&state, &self.config.namespace);

        let mut dealer_state = storage
            .create_dealer_for_round(
                self.config.me.clone(),
                round.clone(),
                state.share.clone(),
                state.seed,
            )
            .wrap_err("unable to instantiate dealer state")?;

        if dealer_state.is_some() {
            self.metrics.how_often_dealer.metric().inc();
        }

        let mut player_state = storage
            .create_player_for_round(self.config.me.clone(), &round)
            .wrap_err("unable to instantiate player state")?;

        if player_state.is_some() {
            self.metrics.how_often_player.metric().inc();
        }

        // Register a channel for this round
        let (mut round_sender, mut round_receiver) =
            mux.register(state.epoch.get()).await.wrap_err_with(|| {
                format!(
                    "unable to create subchannel for this DKG ceremony of epoch `{}`",
                    state.epoch
                )
            })?;

        let ancestry_ctx = Arc::new(self.context.child("ancestry_stream"));
        let mut ancestry_stream = AncestorStream::<TMarshal::Ancestry>::new();

        info_span!("start_dkg", epoch = %state.epoch).in_scope(|| {
            info!(
                me = %self.config.me.public_key(),
                dealers = ?state.dealers(),
                players = ?state.players(),
                as_dealer = dealer_state.is_some(),
                as_player = player_state.is_some(),
                "entering a new DKG ceremony",
            )
        });

        loop {
            let mut shutdown = self.context.stopped().fuse();
            select!(
                biased;

                _ = &mut shutdown => {
                    break Err(eyre!("shutdown triggered"));
                }

                Some((cause, block, ack)) = self.pending_finalized_blocks.next() => {
                    let should_break = match self
                        .handle_finalized_header(
                            cause,
                            &state,
                            &round,
                            &mut round_sender,
                            storage,
                            &mut dealer_state,
                            &mut player_state,
                            block.header().clone(),
                        )
                        .await
                        .wrap_err("failed handling finalized block")?
                    {
                        Some(new_state) => {
                            info_span!("run_dkg_loop", epoch = %state.epoch).in_scope(|| {
                                info!(
                                    "constructed a new epoch state; persisting new state \
                                    and exiting current epoch",
                                )
                            });

                            if let Err(err) = storage
                                .set_state(new_state)
                                .await
                                .wrap_err("failed appending new state to journal")
                            {
                                break Err(err);
                            }
                            // Emits an error event.
                            let _ = self.exit_epoch(&state);

                            true
                        }
                        None => false,
                    };
                    ack.acknowledge();
                    if should_break {
                        break Ok(());
                    }
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
                                Update::Tip(_, _, _) => {}
                                Update::Block(block, ack) => {
                                    info_span!("finalized_block").in_scope(|| info!(
                                        height = %block.height(),
                                        digest = %block.digest(),
                                        "received finalized block",
                                    ));
                                    self.pending_finalized_blocks.push_back(ready((
                                        msg.cause, (*block).clone(), ack,
                                    )));
                                }
                            }
                        }

                        Command::GetDealerLog(get_dealer_log) => {
                            info_span!("get_dealer_log").in_scope(|| {
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
                            if let Ok(Some((hole, request))) = self
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
                                let stream = match self
                                    .config
                                    .marshal
                                    .ancestry(
                                        ancestry_ctx.clone(),
                                        (DigestFallback::Wait, hole),
                                        self.metrics.ancestor_fetch_duration.clone(),
                                    )
                                    .await
                                {
                                    Some(stream) => stream,
                                    None => break Err(eyre!("marshal mailbox is closed")),
                                };
                                ancestry_stream.set((msg.cause, request), stream);
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

                Some(notarized_block) = ancestry_stream.next() => {
                    storage.cache_notarized_block(&round, notarized_block);
                    let (cause, request) = ancestry_stream
                        .take_request()
                        .expect("if the stream is yielding blocks, there must be a receiver");
                    if let Ok(Some((hole, request))) = self
                        .handle_get_dkg_outcome(&cause, storage, &player_state, &round, &state, request)
                        .await
                    {
                        let stream = match self
                            .config
                            .marshal
                            .ancestry(
                                ancestry_ctx.clone(),
                                (DigestFallback::Wait, hole),
                                self.metrics.ancestor_fetch_duration.clone(),
                            )
                            .await
                        {
                            Some(stream) => stream,
                            None => break Err(eyre!("marshal mailbox is closed")),
                        };
                        ancestry_stream.set((cause, request), stream);
                    }
                }
            )
        }
    }

    /// Turns freshly opened storage into storage that is guaranteed to hold a
    /// state matching the finalized floor:
    ///
    /// 1. The persisted state is up-to-date: it is used as-is.
    /// 2. The persisted state is stale: the state is re-initialized from the
    ///    chain, reusing the stale share if it still matches the on-chain
    ///    outcome, or recovering it from revealed dealings otherwise.
    /// 3. No state is persisted: like 2., but without a stale share to fall
    ///    back on.
    #[instrument(skip_all, err)]
    async fn heal<TStorageContext>(
        &mut self,
        storage: state::Unverified<TStorageContext>,
    ) -> eyre::Result<state::Storage<TStorageContext>>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
    {
        let mut share_candidate = ShareState::unset_plaintext();
        if let Some(state) = storage.state() {
            let epoch_info = self
                .config
                .epoch_strategy
                .containing(self.config.last_finalized_height.next())
                .expect("epoch strategy is covering all heights");
            let round = Round::from_state(state, &self.config.namespace);
            if round.epoch() < epoch_info.epoch() {
                warn!(
                    "latest DKG state is for `{}`, but the next block will be \
                    for epoch `{}`. Resetting DKG initial state",
                    round.epoch(),
                    epoch_info.epoch(),
                );
                share_candidate = state.share.clone();
            } else {
                let state = state.clone();
                return storage
                    .init_verified(state)
                    .await
                    .wrap_err("failed writing initial state back to storage");
            }
        };
        let initial_state = self
            .establish_initial_state(share_candidate)
            .await
            .wrap_err("failed constructing initial state")?;

        storage
            .init_verified(initial_state)
            .await
            .wrap_err("failed setting initial state")
    }

    #[instrument(skip_all, err)]
    async fn prepopulate_to_last_finalized_height<TStorageContext>(
        &self,
        storage: &mut state::Storage<TStorageContext>,
    ) -> eyre::Result<()>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
    {
        let state = storage.current();
        let round = Round::from_state(&state, &self.config.namespace);
        let target_height = self.config.last_finalized_height;
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(target_height.next())
            .expect("epoch strategy is covering all heights");

        // The DKG actor may have persisted the new epoch before the finalized floor caught up
        // during shutdown. Do not replay prior-epoch headers against the newer DKG round.
        if round.epoch() > epoch_info.epoch() {
            return Ok(());
        }

        let mut height = storage
            .get_latest_finalized_block_for_epoch(&round.epoch())
            .map_or(epoch_info.first(), |(height, _)| height.next());

        if height <= target_height {
            info!(
                epoch = %round.epoch(),
                %height,
                %target_height,
                "prepopulating DKG state from finalized headers"
            );
        }

        while height <= target_height {
            let header = get_header(
                &self.config.execution_node,
                &self.config.marshal,
                height,
            ).await
            .wrap_err_with(|| format!(
                "neither consensus nor execution layer had a header for block at height `{height}`"
            ))?;

            self.record_finalized_header(storage, &round, header, None)
                .await
                .wrap_err("failed backfilling header to storage")?;
            height = height.next();
        }
        Ok(())
    }

    async fn record_finalized_header<TStorageContext>(
        &self,
        storage: &mut state::Storage<TStorageContext>,
        round: &Round,
        header: TempoHeader,
        dealer_state: Option<&mut Dealer>,
    ) -> eyre::Result<()>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
    {
        let height = Height::new(header.number());
        if !header.extra_data().is_empty() {
            'handle_log: {
                let (dealer, log) = match read_dealer_log(header.extra_data().as_ref(), round) {
                    Err(reason) => {
                        warn!(
                            %reason,
                            %height,
                            "failed to read dealer log from block extraData header field"
                        );
                        break 'handle_log;
                    }
                    Ok((dealer, log)) => (dealer, log),
                };
                storage
                    .append_dealer_log(round.epoch(), dealer.clone(), log)
                    .await
                    .wrap_err("failed to append dealer log from finalized header")?;
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
            .append_finalized_header(round.epoch(), header)
            .await
            .wrap_err("failed to append finalized header")
    }

    fn handle_verify_dealer_log(
        &self,
        state: &State,
        round: &Round,
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
            &NZU32!(round.players().len() as u32),
        )
        .wrap_err("failed reading dealer log from header")
        .and_then(|log| {
            log.check(round.info())
                .map(|(dealer, _)| dealer)
                .ok_or_eyre("dealer log signature is invalid")
        })
        .inspect(|_| {
            self.metrics.dealings_read.metric().inc();
        })
        .inspect_err(|_| {
            self.metrics.bad_dealings.metric().inc();
        });
        let _ = response.send(res);
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
            block.digest = %Digest::new(header.hash_slow()),
            block.height = %Height::new(header.number()),
            block.extra_data.bytes = header.extra_data().len(),
        ),
        err,
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "easiest way to express this for now"
    )]
    // TODO(janis): replace this by a struct?
    async fn handle_finalized_header<TStorageContext, TSender>(
        &mut self,
        cause: Span,
        state: &State,
        round: &Round,
        round_channel: &mut TSender,
        storage: &mut state::Storage<TStorageContext>,
        dealer_state: &mut Option<Dealer>,
        player_state: &mut Option<Player>,
        header: TempoHeader,
    ) -> eyre::Result<Option<State>>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let height = Height::new(header.number());
        let parent_digest = Digest(header.parent_hash());
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(height)
            .expect("epoch strategy is covering all block heights");

        match round.epoch().cmp(&epoch_info.epoch()) {
            Ordering::Less => {
                bail!(
                    "block is for a future epoch `{}`, but the current DKG \
                    loop is for epoch `{}`; this should never happen because \
                    the DKG actor drives which epochs are entered",
                    epoch_info.epoch(),
                    round.epoch(),
                );
            }
            Ordering::Greater => {
                warn!(
                    "ignoring block for prior epoch; older blocks are replayed \
                    against the DKG loop when a node was shut down right \
                    after a boundary block completed an epoch, but before \
                    it was fully processed by other actors"
                );
                return Ok(None);
            }
            Ordering::Equal => {
                // Normal, expected behavior.
            }
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

        if height != epoch_info.last() {
            self.record_finalized_header(storage, round, header, dealer_state.as_mut())
                .await
                .wrap_err("failed to record finalized header")?;

            return Ok(None);
        }

        info!("reached last block of epoch; reading DKG outcome from header");

        let onchain_outcome = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
            .expect("the last block of an epoch must contain the DKG outcome");

        info!("reading validator from contract");

        let (local_output, mut share) = if let Some((outcome, share)) =
            storage.get_dkg_outcome(&state.epoch, &parent_digest)
        {
            debug!("using cached DKG outcome");
            (outcome.clone(), share.clone())
        } else {
            let mut logs = Logs::<MinSig, PublicKey, N3f1>::new(round.info().clone());
            for (k, v) in storage.logs_for_epoch(round.epoch()) {
                logs.record(k.clone(), v.clone());
            }

            let ctx_mut = self.context.as_present_mut();
            let player_outcome = if let Some(player) = player_state.take() {
                info!("we were a player in the ceremony; finalizing share");
                match player.finalize(ctx_mut, logs.clone(), &Sequential) {
                    Ok((new_output, new_share)) => {
                        info!("local DKG ceremony was a success");
                        Some((new_output, ShareState::Plaintext(Some(new_share))))
                    }
                    Err(reason @ dkg::Error::MissingPlayerDealing) => {
                        warn!(
                            reason = %Report::new(reason),
                            "missing critical DKG state to reconstruct a share in this epoch; has \
                            consensus state been deleted or a node with the same identity started \
                            without consensus state? Finalizing the current round as an observer \
                            and will not have a share in the next epoch"
                        );
                        None
                    }
                    Err(error) => {
                        warn!(
                            error = %Report::new(error),
                            "local DKG ceremony was a failure",
                        );
                        Some((state.output.clone(), state.share.clone()))
                    }
                }
            } else {
                None
            };

            if let Some(outcome) = player_outcome {
                outcome
            } else {
                match observe::<_, _, N3f1, Batch>(ctx_mut, logs, &Sequential) {
                    Ok(output) => {
                        info!("local DKG ceremony was a success");
                        (output, ShareState::Plaintext(None))
                    }
                    Err(error) => {
                        warn!(
                            error = %Report::new(error),
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
            share = ShareState::Plaintext(None);
        }

        // Because we use cached data, we need to check for DKG success here:
        // if the on-chain output is the same as the input into the loop (which
        // is just state.output), then we know the DKG failed.
        if onchain_outcome.output == state.output {
            self.metrics.failures.metric().inc();
        } else {
            self.metrics.successes.metric().inc();
        }

        Ok(Some(State {
            epoch: onchain_outcome.epoch,
            seed: Summary::random(self.context.as_present_mut()),
            output: onchain_outcome.output.clone(),
            share,
            players: onchain_outcome.next_players,
            is_full_dkg: onchain_outcome.is_next_full_dkg,
        }))
    }

    #[instrument(skip_all, fields(me = %self.config.me.public_key(), %epoch))]
    async fn distribute_shares<TStorageContext, TSender>(
        &self,
        storage: &mut state::Storage<TStorageContext>,
        epoch: Epoch,
        dealer_state: &mut Dealer,
        player_state: &mut Option<Player>,
        round_channel: &mut TSender,
    ) where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
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
                            self.metrics.shares_distributed.metric().inc();
                            self.metrics.shares_received.metric().inc();
                        })
                        .inspect_err(|error| warn!(%error, "failed to store our own dealing"))
                    && let Ok(()) = dealer_state
                        .receive_ack(storage, epoch, me.clone(), ack)
                        .await
                        .inspect_err(|error| warn!(%error, "failed to store our own ACK"))
                {
                    self.metrics.acks_received.metric().inc();
                    self.metrics.acks_sent.metric().inc();
                    info!("stored our own ACK and share");
                }
            } else {
                // Send to remote player
                let payload = Message::Dealer(pub_msg, priv_msg).encode();
                let success = round_channel.send(Recipients::One(player.clone()), payload, true);
                if !success.is_empty() {
                    self.metrics.shares_distributed.metric().inc();
                    info!(%player, "share sent");
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
        round: &Round,
        round_channel: &mut impl Sender<PublicKey = PublicKey>,
        storage: &mut state::Storage<TStorageContext>,
        dealer_state: Option<&mut Dealer>,
        player_state: Option<&mut Player>,
        from: PublicKey,
        mut message: IoBuf,
    ) -> eyre::Result<()>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
    {
        let msg = Message::read_cfg(&mut message, &NZU32!(round.players().len() as u32))
            .wrap_err("failed reading p2p message")?;

        match msg {
            Message::Dealer(pub_msg, priv_msg) => {
                if let Some(player_state) = player_state {
                    info!("received message from a dealer");
                    self.metrics.shares_received.metric().inc();
                    let ack = player_state
                        .receive_dealing(storage, round.epoch(), from.clone(), pub_msg, priv_msg)
                        .await
                        .wrap_err("failed storing dealing")?;

                    let sent = round_channel.send(
                        Recipients::One(from.clone()),
                        Message::Ack(ack).encode(),
                        true,
                    );

                    // Follows the doc on the return value of of Sender::send.
                    ensure!(
                        !sent.is_empty(),
                        "failed returning ACK to dealer because it was rate \
                        limited, the connection was closed, or the message \
                        otherwise rejected",
                    );

                    info!("returned ACK to dealer");
                    self.metrics.acks_sent.metric().inc();
                } else {
                    info!("received a dealer message, but we are not a player");
                }
            }
            Message::Ack(ack) => {
                if let Some(dealer_state) = dealer_state {
                    info!("received an ACK");
                    self.metrics.acks_received.metric().inc();
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
            for_block = %request.digest,
        ),
        err(level = Level::WARN),
    )]
    async fn handle_get_dkg_outcome<TStorageContext>(
        &mut self,
        cause: &Span,
        storage: &mut state::Storage<TStorageContext>,
        player_state: &Option<Player>,
        round: &Round,
        state: &State,
        request: GetDkgOutcome,
    ) -> eyre::Result<Option<(Digest, GetDkgOutcome)>>
    where
        TStorageContext: BufferPooler + commonware_runtime::Metrics + Clock + Storage,
    {
        let epoch_info = self
            .config
            .epoch_strategy
            .containing(request.height)
            .expect("our strategy covers all epochs");

        ensure!(
            round.epoch() == epoch_info.epoch(),
            "request is for epoch `{}`, not our epoch",
            epoch_info.epoch(),
        );

        let output = if let Some((output, _)) = storage
            .get_dkg_outcome(&state.epoch, &request.digest)
            .cloned()
        {
            output
        } else {
            let mut finalized_logs = storage
                .logs_for_epoch(round.epoch())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>();

            'ensure_enough_logs: {
                if finalized_logs.len() == round.dealers().len() {
                    info!("collected as many logs as there are dealers; concluding DKG");
                    break 'ensure_enough_logs;
                }

                info!(
                    "did not have all dealer logs yet; will try to extend with \
                    logs read from notarized blocks and concluding DKG that way",
                );
                let mut notarized_logs = BTreeMap::new();
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
                        if let Some((dealer, log)) = block.log.clone()
                            && !finalized_logs.contains_key(&dealer)
                        {
                            // The ancestry walk is newest-to-oldest, so older logs replace
                            // newer ancestry duplicates while finalized logs stay authoritative.
                            notarized_logs.insert(dealer, log);
                        }
                        height = if let Some(height) = block.height.previous() {
                            height
                        } else {
                            break;
                        };
                        digest = block.parent;
                    } else {
                        debug!(
                            missing = %digest,
                            "cannot yet finalize the DKG because a block is missing"
                        );
                        return Ok(Some((digest, request)));
                    }
                }
                for (dealer, log) in notarized_logs {
                    finalized_logs.entry(dealer).or_insert(log);
                }
            }

            let mut logs = Logs::<MinSig, PublicKey, N3f1>::new(round.info().clone());
            debug!(how_many = finalized_logs.len(), "recording longs");
            for (k, v) in finalized_logs {
                debug!(?k, ?v, "recording log");
                logs.record(k, v);
            }

            // Create a player-state ad hoc: the DKG player object is not
            // cloneable, and finalizing consumes it.
            let player_state = player_state.is_some().then(||
                storage
                        .create_player_for_round(self.config.me.clone(), round)
                        .expect("created a player instance before, must be able to create it again")
                        .expect("did not return a player instance even though we created it for this round already")
            );

            let (output, share) = {
                let player_outcome = if let Some(player) = player_state {
                    info!("we were a player in the ceremony; finalizing share");
                    match player.finalize(&mut *self.context, logs.clone(), &Sequential) {
                        Ok((new_output, new_share)) => {
                            info!("local DKG ceremony was a success");
                            Some((new_output, ShareState::Plaintext(Some(new_share))))
                        }
                        Err(reason @ dkg::Error::MissingPlayerDealing) => {
                            warn!(
                                reason = %Report::new(reason),
                                "missing critical DKG state to reconstruct a share in this epoch; has \
                                consensus state been deleted or a node with the same identity started \
                                without consensus state? Finalizing the current round as an observer \
                                and will not have a share in the next epoch"
                            );
                            None
                        }
                        Err(error) => {
                            warn!(
                                error = %Report::new(error),
                                "local DKG ceremony was a failure",
                            );
                            Some((state.output.clone(), state.share.clone()))
                        }
                    }
                } else {
                    None
                };

                if let Some(outcome) = player_outcome {
                    outcome
                } else {
                    match observe::<_, _, N3f1, Batch>(&mut *self.context, logs, &Sequential) {
                        Ok(output) => {
                            info!("local DKG ceremony was a success");
                            (output, ShareState::Plaintext(None))
                        }
                        Err(error) => {
                            warn!(
                                error = %Report::new(error),
                                "local DKG ceremony was a failure",
                            );
                            (state.output.clone(), state.share.clone())
                        }
                    }
                }
            };

            storage.cache_dkg_outcome(state.epoch, request.digest, output.clone(), share);
            output
        };

        // Check if next ceremony should be full.
        let next_epoch = state.epoch.next();
        let will_be_re_dkg = self
            .config
            .execution_node
            .next_full_dkg_epoch(request.digest)
            // in theory it should never fail, but if it does, just stick to reshare.
            .is_ok_and(|epoch| epoch == next_epoch.get());
        info!(
            will_be_re_dkg,
            %next_epoch,
            "determined if the next epoch will be a reshare or full re-dkg process",
        );

        let next_players = self
            .config
            .execution_node
            .next_players(request.digest)
            .wrap_err("could not determine who the next players are supposed to be")?;

        request
            .response
            .send(OnchainDkgOutcome {
                epoch: next_epoch,
                output,
                next_players,
                is_next_full_dkg: will_be_re_dkg,
            })
            .map_err(|_| {
                eyre!("requester went away before speculative DKG outcome could be sent")
            })?;

        Ok(None)
    }

    #[instrument(skip_all, fields(epoch = %state.epoch), err(level = Level::WARN))]
    fn enter_epoch(&mut self, state: &State) -> eyre::Result<()> {
        self.config
            .epoch_manager
            .enter(
                state.epoch,
                state.output.public().clone(),
                state.share.clone().into_inner(),
                state.dealers().clone(),
            )
            .wrap_err("could not instruct epoch manager to enter epoch")
    }

    #[instrument(skip_all, fields(epoch = %state.epoch), err(level = Level::WARN))]
    fn exit_epoch(&mut self, state: &State) -> eyre::Result<()> {
        self.config
            .epoch_manager
            .exit(state.epoch)
            .wrap_err("could not instruct epoch manager to enter epoch")
    }

    /// Constructs a fresh state from the on-chain DKG outcome at the last
    /// finalized boundary.
    ///
    /// The share is sourced, in order of preference, from the configured
    /// initial share, from `share_candidate` (salvaged from a stale persisted
    /// state), or by recovering it from publicly revealed dealings. The first
    /// two are only used if they match the polynomial of the on-chain
    /// outcome.
    #[instrument(skip_all, err)]
    async fn establish_initial_state(
        &mut self,
        share_candidate: ShareState,
    ) -> eyre::Result<State> {
        let latest_boundary = latest_boundary_at_or_before(
            &self.config.epoch_strategy,
            self.config.last_finalized_height,
        );
        info!(
            %latest_boundary,
            last_finalized = %self.config.last_finalized_height,
            "marshal reported finalized floor at startup, reading on-chain DKG \
            outcome from last boundary height"
        );

        let onchain_outcome = read_outcome_from_boundary(
            &self.config.execution_node,
            &self.config.marshal,
            latest_boundary,
        )
        .await?;

        // The configured initial share takes precedence over the candidate
        // salvaged from a stale state. Either is only usable if it matches
        // the polynomial of the on-chain DKG outcome.
        let mut share = None;
        for candidate in [
            self.config.initial_share.clone(),
            share_candidate.into_inner(),
        ] {
            let Some(candidate) = candidate else {
                continue;
            };
            let Ok(partial) = onchain_outcome.sharing().partial_public(candidate.index) else {
                warn!(
                    "the index of the provided share exceeds the polynomial of the \
                    on-chain DKG outcome; ignoring the share"
                );
                continue;
            };
            if candidate.public::<MinSig>() != partial {
                warn!(
                    "the provided share does not match the polynomial of the \
                    on-chain DKG outcome; ignoring the share"
                );
                continue;
            }
            share = Some(candidate);
            break;
        }

        let mut state = State {
            epoch: onchain_outcome.epoch,
            seed: Summary::random(&mut self.context),
            output: onchain_outcome.output.clone(),
            share: state::ShareState::Plaintext(share),
            players: onchain_outcome.next_players,
            is_full_dkg: onchain_outcome.is_next_full_dkg,
        };

        if let state::ShareState::Plaintext(None) = &state.share
            && let Ok(Some(share)) = self.maybe_recover_revealed_share(&state).await
        {
            info!(epoch = %state.epoch, "recovered share from public dealings");
            state.share = state::ShareState::Plaintext(Some(share));
        }

        Ok(state)
    }

    /// Attempts to reconstruct our current threshold share from dealer logs finalized during the
    /// previous epoch.
    #[instrument(skip_all, fields(epoch = %state.epoch), err)]
    async fn maybe_recover_revealed_share(&mut self, state: &State) -> eyre::Result<Option<Share>> {
        let public_key = self.config.me.public_key();
        if state.output.players().position(&public_key).is_none()
        // TODO: currently unreliable; use once fixed
        // || state.output.revealed().position(&public_key).is_none()
        {
            return Ok(None);
        }

        let Some(ceremony_epoch) = state.epoch.previous() else {
            return Ok(None);
        };

        let ceremony_boundary = ceremony_epoch.previous().map_or(Height::zero(), |epoch| {
            self.config
                .epoch_strategy
                .last(epoch)
                .expect("epoch strategy is valid for all epochs")
        });

        let ceremony_outcome = read_outcome_from_boundary(
            &self.config.execution_node,
            &self.config.marshal,
            ceremony_boundary,
        )
        .await
        .wrap_err("failed reading outcome for ceremony boundary")?;

        ensure!(
            ceremony_outcome.epoch == ceremony_epoch,
            "boundary outcome is for epoch `{}`, expected ceremony epoch `{ceremony_epoch}`",
            ceremony_outcome.epoch,
        );

        // A failed ceremony carries its input output forward. In that case, the current share was
        // produced by an older ceremony, not by the dealer logs from the immediately previous epoch.
        // Do not attempt an unbounded search through earlier epochs here.
        if ceremony_outcome.output == state.output {
            return Ok(None);
        }

        let ceremony_state = State {
            epoch: ceremony_outcome.epoch,
            seed: state.seed,
            output: ceremony_outcome.output,
            share: state::ShareState::Plaintext(None),
            players: ceremony_outcome.next_players,
            is_full_dkg: ceremony_outcome.is_next_full_dkg,
        };

        let round = Round::from_state(&ceremony_state, &self.config.namespace);
        ensure!(
            round.players().position(&public_key).is_some(),
            "our identity is in the current output but was not a player in ceremony epoch \
        `{ceremony_epoch}`"
        );

        let selected_dealers = state.output.dealers();
        let first = self
            .config
            .epoch_strategy
            .first(ceremony_epoch)
            .ok_or_eyre("ceremony epoch has no first height")?;
        let last = self
            .config
            .epoch_strategy
            .last(ceremony_epoch)
            .ok_or_eyre("ceremony epoch has no last height")?;

        // Honest dealers do not finalize logs before the midpoint, but block validation does not
        // enforce that timing, so scan the entire ceremony epoch.
        let mut height = first;
        let mut dealer_logs = BTreeMap::new();
        while height < last && dealer_logs.len() < selected_dealers.len() {
            let header = get_header(&self.config.execution_node, &self.config.marshal, height)
                .await
                .wrap_err("failed reading finalized header")?;

            if !header.extra_data().is_empty()
                && let Ok((dealer, log)) = read_dealer_log(header.extra_data().as_ref(), &round)
                && selected_dealers.position(&dealer).is_some()
            {
                dealer_logs.entry(dealer).or_insert(log);
            }

            height = height.next();
        }

        ensure!(
            dealer_logs.len() == selected_dealers.len(),
            "found only {} of {} selected dealer logs in finalized headers for ceremony epoch `{ceremony_epoch}`",
            dealer_logs.len(),
            selected_dealers.len(),
        );

        let mut logs = Logs::<MinSig, PublicKey, N3f1>::new(round.info().clone());
        for (dealer, log) in dealer_logs {
            logs.record(dealer, log);
        }

        let player = state::Player::new(
            dkg::Player::new(round.info().clone(), self.config.me.clone())
                .wrap_err("failed creating player to recover revealed share")?,
        );

        let (recovered_output, share) = match player.finalize(&mut self.context, logs, &Sequential)
        {
            Ok(recovered) => recovered,
            Err(dkg::Error::MissingPlayerDealing) => return Ok(None),
            Err(error) => {
                return Err(eyre::Report::new(error))
                    .wrap_err("failed finalizing revealed share from dealer logs");
            }
        };

        ensure!(
            recovered_output == state.output,
            "recovered output does not match the on-chain output"
        );

        Ok(Some(share))
    }
}

fn latest_boundary_at_or_before(epoch_strategy: &FixedEpocher, height: Height) -> Height {
    let epoch_info = epoch_strategy
        .containing(height)
        .expect("epoch strategy is for all heights");

    if epoch_info.last() == height {
        height
    } else {
        epoch_info
            .epoch()
            .previous()
            .map_or_else(Height::zero, |previous| {
                epoch_strategy
                    .last(previous)
                    .expect("epoch strategy is for all epochs")
            })
    }
}

#[cfg(test)]
#[test]
fn latest_boundary_at_or_before_height() {
    let epoch_strategy = FixedEpocher::new(std::num::NonZeroU64::new(10).unwrap());

    for (height, expected) in [(4, 0), (9, 9), (12, 9)] {
        assert_eq!(
            latest_boundary_at_or_before(&epoch_strategy, Height::new(height)),
            Height::new(expected),
            "unexpected boundary for height {height}"
        );
    }
}

async fn read_outcome_from_boundary<TExecutionLayer, TMarshal>(
    node: &TExecutionLayer,
    marshal: &TMarshal,
    boundary: Height,
) -> eyre::Result<OnchainDkgOutcome>
where
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
{
    let header = get_header(node, marshal, boundary)
        .await
        .wrap_err_with(|| {
            format!("failed to read latest boundary header at height `{boundary}`")
        })?;

    OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
        .wrap_err("the boundary block did not contain the on-chain DKG outcome")
}

#[instrument(skip_all, fields(%height))]
async fn get_header<TExecutionLayer, TMarshal>(
    node: &TExecutionLayer,
    marshal: &TMarshal,
    height: Height,
) -> eyre::Result<TempoHeader>
where
    TExecutionLayer: ExecutionLayer,
    TMarshal: Marshal,
{
    match node.finalized_header(height) {
        Ok(Some(header)) => return Ok(header),
        Ok(None) => {
            debug!(%height, "execution layer did not have a finalized header for DKG state");
        }
        Err(error) => {
            warn!(
                %error,
                %height,
                "failed to read finalized header from execution layer for DKG state"
            );
        }
    }

    if let Some(block) = marshal.get_block(height).await {
        return Ok(block.header().clone());
    }

    bail!("could not find header for finalized block at `{height}`");
}

#[derive(Clone)]
struct Metrics {
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

    how_often_dealer: Counter,
    how_often_player: Counter,

    ancestor_fetch_duration: Timed,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let failures = context.counter(
            "ceremony_failures",
            "the number of failed ceremonies a node participated in",
        );

        let successes = context.counter(
            "ceremony_successes",
            "the number of successful ceremonies a node participated in",
        );

        let dealers = context.gauge(
            "ceremony_dealers",
            "the number of dealers in the currently running ceremony",
        );
        let players = context.gauge(
            "ceremony_players",
            "the number of players in the currently running ceremony",
        );

        let how_often_dealer = context.counter(
            "how_often_dealer",
            "number of the times as node was active as a dealer",
        );
        let how_often_player = context.counter(
            "how_often_player",
            "number of the times as node was active as a player",
        );

        let shares_distributed = context.gauge(
            "ceremony_shares_distributed",
            "the number of shares distributed by this node as a dealer in the current ceremony",
        );

        let shares_received = context.gauge(
            "ceremony_shares_received",
            "the number of shares received by this node as a player in the current ceremony",
        );

        let acks_received = context.gauge(
            "ceremony_acks_received",
            "the number of acknowledgments received by this node as a dealer in the current ceremony",
        );

        let acks_sent = context.gauge(
            "ceremony_acks_sent",
            "the number of acknowledgments sent by this node as a player in the current ceremony",
        );

        let dealings_read = context.gauge(
            "ceremony_dealings_read",
            "the number of dealings read from the blockchain in the current ceremony",
        );

        let bad_dealings = context.gauge(
            "ceremony_bad_dealings",
            "the number of blocks where decoding and verifying dealings failed in the current ceremony",
        );

        let ancestor_fetch_duration = Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the DKG ancestry stream, in seconds",
            Buckets::LOCAL,
        ));

        Self {
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
            ancestor_fetch_duration,
        }
    }

    fn reset(&self) {
        self.shares_distributed.metric().set(0);
        self.shares_received.metric().set(0);
        self.acks_received.metric().set(0);
        self.acks_sent.metric().set(0);
        self.dealings_read.metric().set(0);
        self.bad_dealings.metric().set(0);
    }
}

/// A wrapper around an ancestry stream held in an option to make it easier to
/// use with select macros.
///
/// Invariant: the inner stream and its matching original request are set and
/// cleared together.
struct AncestorStream<T> {
    pending_request: Option<(Span, GetDkgOutcome)>,
    inner: Option<T>,
}

impl<T> AncestorStream<T>
where
    T: Stream<Item = Arc<Block>> + Unpin,
{
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

    fn set(&mut self, pending_request: (Span, GetDkgOutcome), stream: T) {
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

impl<T> Stream for AncestorStream<T>
where
    T: Stream<Item = Arc<Block>> + Unpin,
{
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
                self.pending_request.take();
                Poll::Ready(None)
            }
            Some(block) => Poll::Ready(Some((*block).clone())),
        }
    }
}

impl<T> FusedStream for AncestorStream<T>
where
    T: Stream<Item = Arc<Block>> + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.inner.is_none()
    }
}

fn read_dealer_log(
    mut bytes: &[u8],
    round: &Round,
) -> eyre::Result<(PublicKey, DealerLog<MinSig, PublicKey>)> {
    let signed_log = SignedDealerLog::<MinSig, PrivateKey>::read_cfg(
        &mut bytes,
        &NZU32!(round.players().len() as u32),
    )
    .wrap_err("could not decode as signed dealer log")?;

    let (dealer, log) = signed_log
        .check(round.info())
        .ok_or_eyre("failed checking signed log against current round")?;
    Ok((dealer, log))
}
