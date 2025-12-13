use std::{collections::HashMap, net::SocketAddr, sync::Arc, task::ready, time::Duration};

use commonware_codec::{
    Encode as _, EncodeSize, RangeCfg, Read, ReadExt as _, Write, varint::UInt,
};
use commonware_consensus::{
    Block as _, Reporter as _,
    marshal::Update,
    types::{Epoch, Round},
    utils,
};
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{group::Share, poly::Public, variant::MinSig},
    ed25519::PublicKey,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Sender,
    utils::{mux, mux::MuxHandle},
};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics as _, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    quorum,
    sequence::U64,
    set::{Ordered, OrderedAssociated},
    union,
};

use eyre::{Context as _, eyre};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{mpsc, oneshot},
    future::BoxFuture,
    lock::Mutex,
    stream::FuturesUnordered,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use tempo_chainspec::hardfork::TempoHardforks as _;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tempo_node::TempoFullNode;
use tracing::{Span, debug, error, info, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    dkg::{
        ceremony::{self, Ceremony, HasHoles, OUTCOME_NAMESPACE},
        manager::{
            DecodedValidator,
            ingress::{GetIntermediateDealing, GetOutcome},
            validators::{self, ValidatorState},
        },
    },
    epoch,
    utils::OptionFuture,
};

mod post_allegretto;
mod pre_allegretto;

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

    /// Persisted information on the currently running ceremony and its
    /// predecessor (epochs i and i-1). This ceremony metadata is updated on
    /// the last height of en epoch (the height on which the ceremony for the
    /// next epoch will be started).
    ceremony_metadata: Arc<Mutex<Metadata<ContextCell<TContext>, U64, ceremony::State>>>,

    /// Persisted information on the current epoch for DKG ceremonies that were
    /// started after the allegretto hardfork.
    post_allegretto_metadatas: post_allegretto::Metadatas<ContextCell<TContext>>,

    /// Persisted information on the current epoch for DKG ceremonies that were
    /// started before the allegretto hardfork.
    pre_allegretto_metadatas: pre_allegretto::Metadatas<ContextCell<TContext>>,

    /// Information on the peers registered on the p2p peer manager for a given
    /// epoch i and its precursors i-1 and i-2. Peer information is persisted
    /// on the last height of an epoch.
    ///
    /// Note that validators are also persisted in the epoch metadata and are
    /// the main source of truth. The validators are also tracked here so that
    /// they can be registered as peers for older epoch states that are no longer
    /// tracked.
    validators_metadata: Metadata<ContextCell<TContext>, U64, ValidatorState>,

    /// Handles to the metrics objects that the actor will update during its
    /// runtime.
    metrics: Metrics,

    /// The latest finalized tip the actor is aware of.
    finalized_tip: Option<(u64, Digest)>,

    gaps: Vec<u64>,
    pending_gap: OptionFuture<PendingFinalizedGap>,
    pending_finalized_block: Option<(Span, Block, Exact)>,

    pending_dkg_outcome_requests: HashMap<Digest, Vec<oneshot::Sender<PublicOutcome>>>,

    notarized_fetch_abort_handles: HashMap<Digest, oneshot::Sender<()>>,
    notarized_fetch_to_requests: HashMap<Digest, Vec<Digest>>,
    notarized_stream: FuturesUnordered<FetchNotarizedBlock>,
}

fn fetch_notarized_block(
    mut marshal: crate::alias::marshal::Mailbox,
    digest: Digest,
    round: Option<Round>,
) -> (oneshot::Sender<()>, FetchNotarizedBlock) {
    let (tx, mut rx) = oneshot::channel();
    (
        tx,
        FetchNotarizedBlock {
            digest,
            req: async move {
                select!(
                    _ = &mut rx => {
                        Err(eyre!("aborted or dropped"))
                    },

                    block = async move { marshal.subscribe(round, digest).await.await } => {
                        block.wrap_err("subscription was dropped before a block was received")
                    },
                )
            }
            .boxed(),
        },
    )
}

struct FetchNotarizedBlock {
    digest: Digest,
    req: BoxFuture<'static, eyre::Result<Block>>,
}

impl Future for FetchNotarizedBlock {
    type Output = (Digest, eyre::Result<Block>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let res = ready!(self.req.poll_unpin(cx));
        std::task::Poll::Ready((self.digest, res))
    }
}

struct PendingFinalizedGap {
    req: BoxFuture<'static, Option<Block>>,
}

impl Future for PendingFinalizedGap {
    type Output = Option<Block>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.req.poll_unpin(cx)
    }
}

impl<TContext, TPeerManager> Actor<TContext, TPeerManager>
where
    TContext: Clock + CryptoRngCore + commonware_runtime::Metrics + Spawner + Storage,
    TPeerManager: commonware_p2p::Manager<
            PublicKey = PublicKey,
            Peers = OrderedAssociated<PublicKey, SocketAddr>,
        >,
{
    pub(super) async fn new(
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

        let post_allegretto_metadatas =
            post_allegretto::Metadatas::init(&context, &config.partition_prefix).await;

        let pre_allegretto_metadatas =
            pre_allegretto::Metadatas::init(&context, &config.partition_prefix).await;

        let validators_metadata = Metadata::init(
            context.with_label("validators__metadata"),
            commonware_storage::metadata::Config {
                partition: format!("{}_validators", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

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
            ceremony_metadata: Arc::new(Mutex::new(ceremony_metadata)),
            post_allegretto_metadatas,
            pre_allegretto_metadatas,
            validators_metadata,
            metrics,
            finalized_tip: None,
            gaps: vec![],
            pending_gap: None.into(),
            pending_finalized_block: None,

            pending_dkg_outcome_requests: HashMap::new(),
            notarized_fetch_to_requests: HashMap::new(),
            notarized_fetch_abort_handles: HashMap::new(),
            notarized_stream: FuturesUnordered::new(),
        })
    }

    async fn run(
        mut self,
        (sender, receiver): (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        // Emits an error event on return.
        if self.post_allegretto_init().await.is_err() {
            return;
        }
        // Emits an error event on return.
        if self.pre_allegretto_init().await.is_err() {
            return;
        }

        self.register_previous_epoch_state().await;
        self.register_current_epoch_state().await;

        let (mux, mut ceremony_mux) = mux::Muxer::new(
            self.context.with_label("ceremony_mux"),
            sender,
            receiver,
            self.config.mailbox_size,
        );
        mux.start();

        let mut ceremony = self
            .start_ceremony_for_current_epoch_state(&mut ceremony_mux)
            .await;

        'events: loop {
            if self.pending_gap.is_none() {
                if let Some(gap) = self.gaps.pop() {
                    self.pending_gap.replace(PendingFinalizedGap {
                        req: {
                            let mut marshal = self.config.marshal.clone();
                            async move { marshal.get_block(gap).await }
                        }
                        .boxed(),
                    });
                } else if let Some((cause, block, ack)) = self.pending_finalized_block.take() {
                    debug!(
                        height = block.height(),
                        "gaps filled; processing deferred finalized block now",
                    );
                    self.handle_finalized_block(
                        cause,
                        block,
                        ack,
                        &mut ceremony,
                        &mut ceremony_mux,
                    )
                    .await;
                }
            }

            // NOTE: Can't use a commonware select! here: the double-fusing of
            // the notarized block stream causes it to hot-loop.
            futures::select_biased!(

            finalized_block = &mut self.pending_gap => {
                let PendingFinalizedGap { .. } = self
                    .pending_gap
                    .take()
                    .expect("must be present if resolved");

                // NOTE: marshal not having the finalized block even though it
                // tried forwarding a later block is exceedingly strange.
                //
                // Stop? Restart?
                if let Some(block) = finalized_block {
                    ceremony.add_finalized_block(block).await;
                }
            },

            notarized_block = self.notarized_stream.next() => {
                match notarized_block {
                    Some((digest, res)) => {
                        self.handle_notarized_block(digest, res, &mut ceremony);
                    }
                    // Fused streams resolve once on exhaustion but will be
                    // disabled in the next iteration of the loop - unless a new
                    // future is pushed into them.
                    None => {
                        debug!("all notarized subscriptions completed");
                    }
                }
            },

            message = self.mailbox.next() => {
                let Some(message) = message else {
                    break 'events;
                };
                let cause = message.cause;
                match message.command {
                    super::Command::Finalized(update) => match *update {
                        Update::Tip(height, digest) => self.finalized_tip = Some((height, digest)),
                        Update::Block(block, ack) => {
                            self.handle_finalized_block(
                                cause,
                                block,
                                ack,
                                &mut ceremony,
                                &mut ceremony_mux,
                            )
                            .await;
                        }
                    },

                    super::Command::GetIntermediateDealing(get_ceremony_deal) => {
                        let _: Result<_, _> = self
                            .handle_get_intermediate_dealing(
                                cause,
                                get_ceremony_deal,
                                &mut ceremony,
                            )
                            .await;
                    }
                    super::Command::GetOutcome(get_ceremony_outcome) => {
                        let _: Result<_, _> =
                            self.handle_get_outcome(
                                cause,
                                &mut ceremony,
                                get_ceremony_outcome,
                            ).await;
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
                        let outcome = if self
                            .post_allegretto_metadatas
                            .current_epoch_state()
                            .is_some()
                        {
                            verify_dealing
                                .dealing
                                .verify(&union(&self.config.namespace, OUTCOME_NAMESPACE))
                        } else if self
                            .pre_allegretto_metadatas
                            .current_epoch_state()
                            .is_some()
                        {
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

            );
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
            ceremony.epoch = %ceremony.epoch(),
        ),
        err,
    )]
    async fn handle_get_intermediate_dealing<TReceiver, TSender>(
        &mut self,
        cause: Span,
        GetIntermediateDealing { epoch, response }: GetIntermediateDealing,
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
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
    async fn handle_get_outcome<TReceiver, TSender>(
        &mut self,
        cause: Span,
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
        GetOutcome {
            parent,
            round,
            response,
        }: GetOutcome,
    ) -> eyre::Result<()>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        eyre::ensure!(
            round.epoch() == ceremony.epoch(),
            "currently active ceremony is for epoch `{}`, but DKG outcome was \
            requested for epoch `{}`",
            ceremony.epoch(),
            round.epoch(),
        );

        match ceremony.finalize(parent.1) {
            Ok(Ok(outcome) | Err(outcome)) => response
                .send(outcome.to_public_outcome())
                .map_err(|_| eyre!("failed returning outcome because requester went away")),
            Err(ceremony::HasHoles { notarized_hole }) => {
                info!(
                    "could not yet serve DKG outcome because holes were found; \
                    fetching holes and queueing response once they are plugged"
                );
                let round =
                    (notarized_hole == parent.1).then_some(Round::new(round.epoch(), parent.0));
                if !self
                    .notarized_fetch_abort_handles
                    .contains_key(&notarized_hole)
                {
                    let (abort, fut) =
                        fetch_notarized_block(self.config.marshal.clone(), notarized_hole, round);
                    self.notarized_stream.push(fut);
                    self.notarized_fetch_abort_handles
                        .insert(notarized_hole, abort);
                }
                self.notarized_fetch_to_requests
                    .entry(notarized_hole)
                    .or_default()
                    .push(parent.1);
                self.pending_dkg_outcome_requests
                    .entry(parent.1)
                    .or_default()
                    .push(response);

                Ok(())
            }
        }
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
            ceremony.epoch = ceremony.epoch(),
        ),
    )]
    async fn handle_finalized_block<TReceiver, TSender>(
        &mut self,
        cause: Span,
        block: Block,
        acknowledgement: Exact,
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        self.find_gaps_in_ceremony(block.height(), ceremony);
        if !self.gaps.is_empty() {
            debug!(
                n_gaps = self.gaps.len(),
                "found finalized block gaps in ceremony; deferring \
                processing of block and filling gaps first",
            );
            assert!(
                self.pending_finalized_block
                    .replace((cause, block, acknowledgement))
                    .is_none(),
                "new finalized blocks must never be processed if a \
                deferred one exists",
            );
            return;
        }

        if self.is_running_post_allegretto(&block) {
            self.handle_finalized_post_allegretto(cause, block, ceremony, ceremony_mux)
                .await;
        } else {
            self.handle_finalized_pre_allegretto(cause, block, ceremony, ceremony_mux)
                .await;
        }
        acknowledgement.acknowledge();
    }

    /// Handles a notarization by registering it in the currently running ceremony.
    // TODO: this would be a candidate to establish follows-from relations
    #[instrument(
        skip_all,
        // fields(
        //     notarization.epoch = notarization.epoch(),
        //     notarization.digest = %notarization.proposal.payload,
        //     ceremony.epoch = ceremony.epoch(),
        // ),
    )]
    fn handle_notarized_block<TReceiver, TSender>(
        &mut self,
        digest: Digest,
        res: eyre::Result<Block>,
        ceremony: &mut Ceremony<ContextCell<TContext>, TReceiver, TSender>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        self.notarized_fetch_abort_handles.remove(&digest);
        let original_requests = self
            .notarized_fetch_to_requests
            .remove(&digest)
            .unwrap_or_default();
        let Ok(block) = res else {
            // Plugging the hole failed. Drop all related requests.
            for req in original_requests {
                self.pending_dkg_outcome_requests.remove(&req);
            }
            return;
        };

        ceremony.add_notarized_block(block);

        for pending_digest in original_requests {
            if let Some(pending_requests) =
                self.pending_dkg_outcome_requests.remove(&pending_digest)
            {
                match ceremony.finalize(pending_digest) {
                    Ok(Ok(private) | Err(private)) => {
                        let public = private.to_public_outcome();
                        for response in pending_requests {
                            let _ = response.send(public.clone());
                        }
                    }
                    // TODO: merge fetching here and in `handle_get_outcome`
                    Err(HasHoles { notarized_hole }) => {
                        info!(
                            %notarized_hole,
                            "could not yet serve DKG outcome because holes \
                            were found; fetching holes and queueing response \
                            once they are plugged"
                        );
                        if !self
                            .notarized_fetch_abort_handles
                            .contains_key(&notarized_hole)
                        {
                            let (abort, fut) = fetch_notarized_block(
                                self.config.marshal.clone(),
                                notarized_hole,
                                None,
                            );
                            self.notarized_stream.push(fut);
                            self.notarized_fetch_abort_handles
                                .insert(notarized_hole, abort);
                        }
                        self.notarized_fetch_to_requests
                            .entry(notarized_hole)
                            .or_default()
                            .push(pending_digest);
                        self.pending_dkg_outcome_requests
                            .insert(pending_digest, pending_requests);
                    }
                }
            }
        }
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
        if self.post_allegretto_metadatas.exists() {
            self.start_post_allegretto_ceremony(mux).await
        } else {
            self.start_pre_allegretto_ceremony(mux).await
        }
    }

    /// Registers the new epoch by reporting to the epoch manager that it should
    /// be entered and registering its peers on the peers manager.
    #[instrument(skip_all, fields(epoch = self.current_epoch_state().epoch()))]
    async fn register_current_epoch_state(&mut self) {
        let epoch_state = self.current_epoch_state();

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
            EpochState::PreModerato(epoch_state) => self
                .validators_metadata
                .get(&epoch_state.epoch().saturating_sub(1).into())
                .cloned()
                .expect(
                    "there must always be a validator state for the previous \
                    epoch state written for pre-allegretto logic; this is \
                    ensured at startup",
                ),
            EpochState::PostModerato(epoch_state) => epoch_state.validator_state.clone(),
        };

        self.validators_metadata
            .put_sync(epoch_state.epoch().into(), new_validator_state.clone())
            .await
            .expect("must always be able to sync state");

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
    #[instrument(
        skip_all,
        fields(previous_epoch = self.previous_epoch_state().map(|s| s.epoch())))]
    async fn register_previous_epoch_state(&mut self) {
        if let Some(epoch_state) = self.previous_epoch_state() {
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
    fn is_running_post_allegretto(&self, block: &Block) -> bool {
        self.config
            .execution_node
            .chain_spec()
            .is_allegretto_active_at_timestamp(block.timestamp())
            && self.post_allegretto_metadatas.exists()
    }

    /// Returns the previous epoch state.
    ///
    /// Always prefers the post allegretto state, if it exists.
    fn previous_epoch_state(&self) -> Option<EpochState> {
        if let Some(epoch_state) = self
            .post_allegretto_metadatas
            .previous_epoch_state()
            .cloned()
        {
            Some(EpochState::PostModerato(epoch_state))
        } else {
            self.pre_allegretto_metadatas
                .previous_epoch_state()
                .cloned()
                .map(EpochState::PreModerato)
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
    fn current_epoch_state(&self) -> EpochState {
        if let Some(epoch_state) = self
            .post_allegretto_metadatas
            .current_epoch_state()
            .cloned()
        {
            EpochState::PostModerato(epoch_state)
        } else if let Some(epoch_state) =
            self.pre_allegretto_metadatas.current_epoch_state().cloned()
        {
            EpochState::PreModerato(epoch_state)
        } else {
            panic!("either pre- or post-allegretto current-epoch-state should exist")
        }
    }

    fn find_gaps_in_ceremony<TReceiver, TSender>(
        &mut self,
        height: u64,
        ceremony: &Ceremony<ContextCell<TContext>, TReceiver, TSender>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        self.gaps = ceremony.find_gaps_up_to_height(height);
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
