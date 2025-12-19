use std::{collections::HashMap, net::SocketAddr, task::ready, time::Duration};

use alloy_consensus::BlockHeader as _;
use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _, RangeCfg};
use commonware_consensus::{
    Block as _, Reporter as _,
    marshal::Update,
    simplex::signing_scheme::bls12381_threshold::Scheme,
    types::{Epoch, Round},
    utils,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_p2p::{
    Receiver, Sender,
    utils::{mux, mux::MuxHandle},
};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics as _, Spawner, Storage, spawn_cell};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{
    Acknowledgement, acknowledgement::Exact, sequence::U64, set::OrderedAssociated, union,
};

use eyre::{OptionExt as _, WrapErr as _, ensure, eyre};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{mpsc, oneshot},
    future::BoxFuture,
    stream::FuturesUnordered,
};
use prometheus_client::metrics::gauge::Gauge;
use rand_core::CryptoRngCore;
use reth_ethereum::chainspec::EthChainSpec as _;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tempo_node::TempoFullNode;
use tracing::{Span, debug, info, instrument, warn};

use crate::{
    consensus::{Digest, block::Block},
    db::MetadataDatabase,
    dkg::{
        ceremony::{self, Ceremony, HasHoles, OUTCOME_NAMESPACE, PrivateOutcome},
        manager::{
            ingress::{GetIntermediateDealing, GetOutcome},
            read_write_transaction::DkgReadWriteTransaction,
            validators::{self, DecodedValidator, ValidatorState},
        },
    },
    epoch::{self, is_first_block_in_epoch},
    utils::OptionFuture,
};

mod state;

use state::DkgOutcome;
pub(super) use state::State;

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
        > + Sync,
{
    pub(super) async fn new(
        config: super::Config<TPeerManager>,
        context: TContext,
        mailbox: mpsc::UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let context = ContextCell::new(context);

        // Initialize the unified metadata database
        let metadata: Metadata<ContextCell<TContext>, U64, Bytes> = Metadata::init(
            context.with_label("database"),
            metadata::Config {
                partition: format!("{}_database", config.partition_prefix),
                codec_config: RangeCfg::from(0..=usize::MAX),
            },
        )
        .await
        .expect("must be able to initialize metadata on disk to function");

        let db = MetadataDatabase::new(metadata);

        {
            // TODO: set this when opening the database/metadata for the first time?
            let mut tx = DkgReadWriteTransaction::new(db.read_write());
            tx.set_node_version(env!("CARGO_PKG_VERSION").to_string());
            tx.commit()
                .await
                .wrap_err("failed to commit init transaction")?;
        }

        let syncing_players = Gauge::default();

        let peers = Gauge::default();

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

        let ceremony = ceremony::Metrics::register(&context);

        let metrics = Metrics {
            peers,
            syncing_players,
            ceremony,
        };

        Ok(Self {
            config,
            context,
            mailbox,
            db,
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
        let mut tx = DkgReadWriteTransaction::new(self.db.read_write());

        // Emits an error event on return.
        if self.initialize_epoch_state(&mut tx).await.is_err() {
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

        let mut ceremony = self.start_new_ceremony(&mut tx, &mut ceremony_mux).await;

        tx.commit()
            .await
            .expect("must be able to commit initial DB transaction");

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
                    let mut tx = DkgReadWriteTransaction::new(self.db.read_write());
                    ceremony.add_finalized_block(&mut tx, block).await;
                    tx.commit().await.expect("committing state must work");
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
                        let _ = verify_dealing.response.send(verify_dealing
                            .dealing
                            .verify(
                                &union(&self.config.namespace, OUTCOME_NAMESPACE)
                        ));
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

    #[instrument(skip_all, err)]
    pub(super) async fn initialize_epoch_state(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) -> eyre::Result<()> {
        let spec = self.config.execution_node.chain_spec();
        if !tx.has_actor_state().await {
            info!(
                "no epoch state found on disk - reading validators and public \
                polynomial from genesis block",
            );

            let initial_dkg_outcome = PublicOutcome::decode(spec.genesis().extra_data.as_ref())
                .wrap_err_with(|| {
                    format!(
                        "failed decoding the genesis.extra_data field as an \
                        initial DKG outcome; this field must be set and it \
                        must be decodable; bytes = {}",
                        spec.genesis().extra_data.len(),
                    )
                })?;

            ensure!(
                initial_dkg_outcome.epoch == 0,
                "at genesis, the epoch must be zero, but genesis reported `{}`",
                initial_dkg_outcome.epoch
            );

            let our_share = self.config.initial_share.clone();
            if let Some(our_share) = our_share.clone() {
                // XXX: explicitly check the signing key matches the public
                // polynomial. If it does not, commonware silently demotes the
                // node to a verifier.
                //
                // FIXME: replace this once commonware provides logic to not
                // degrade the node silently.
                let signer_or_verifier = Scheme::<_, MinSig>::new(
                    initial_dkg_outcome.participants.clone(),
                    &initial_dkg_outcome.public,
                    our_share,
                );
                ensure!(
                    matches!(signer_or_verifier, Scheme::Signer { .. },),
                    "incorrect signing share provided: the node would not be a \
                    signer in the ceremony"
                );
            }

            let initial_validators = validators::read_from_contract(
                0,
                &self.config.execution_node,
                0,
                self.config.epoch_length,
            )
            .await
            .wrap_err("validator config could not be read from genesis block validator config smart contract")?;

            // ensure that the peer set written into the smart contract matches
            // the participants as determined by the initial DKG outcome.
            let initial_validator_state = ValidatorState::new(initial_validators);
            let peers_as_per_contract = initial_validator_state.resolve_addresses_and_merge_peers();
            ensure!(
                peers_as_per_contract.keys() == &initial_dkg_outcome.participants,
                "the DKG participants stored in the genesis extraData header \
                don't match the peers determined from the onchain contract of \
                the genesis block; \
                extraData.participants = `{:?}; \
                contract.peers = `{:?}",
                initial_dkg_outcome.participants,
                peers_as_per_contract.keys(),
            );

            info!(
                initial_public_polynomial = ?initial_dkg_outcome.public,
                initial_validators = ?peers_as_per_contract,
                "using public polynomial and validators read from contract",
            );

            tx.set_actor_state(State {
                dkg_outcome: DkgOutcome {
                    dkg_successful: true,
                    epoch: 0,
                    participants: initial_dkg_outcome.participants,
                    public: initial_dkg_outcome.public,
                    share: self.config.initial_share.clone(),
                },
                validator_state: initial_validator_state,
            });
        }

        if self.config.delete_signing_share {
            let mut epoch_state = self.current_epoch_state(tx).await;
            warn!("delete-signing-share set; deleting signing share");
            epoch_state.dkg_outcome.share.take();
            tx.set_actor_state(epoch_state);
        }

        Ok(())
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
        ceremony: &mut Ceremony<TReceiver, TSender>,
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
        ceremony: &mut Ceremony<TReceiver, TSender>,
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
        ceremony: &mut Ceremony<TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let gaps = ceremony.find_gaps_up_to_height(block.height());
        if !gaps.is_empty() {
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
            self.gaps = gaps;
            return;
        }

        let mut tx = DkgReadWriteTransaction::new(self.db.read_write());

        // Skip if the block was already processed. Can happen if the node was
        // shutdown after committing the changes but before the marshal actor
        // processed the ack.
        if let Ok(Some(last_processed_height)) = tx.get_last_processed_height().await
            && block.height() == last_processed_height
        {
            info!(last_processed_height, "skipping already-processed block");
        } else {
            self.process_finalized_block(block.clone(), ceremony, ceremony_mux, &mut tx)
                .await;
        }
        let block_height = block.height();
        ceremony.add_finalized_block(&mut tx, block).await;
        tx.set_last_processed_height(block_height);
        tx.commit()
            .await
            .expect("must be able to commit finalize tx");
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
        ceremony: &mut Ceremony<TReceiver, TSender>,
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

    async fn process_finalized_block<TReceiver, TSender>(
        &mut self,
        block: Block,
        ceremony: &mut Ceremony<TReceiver, TSender>,
        ceremony_mux: &mut MuxHandle<TSender, TReceiver>,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let block_epoch = utils::epoch(self.config.epoch_length, block.height());

        let current_epoch_state = self.current_epoch_state(tx).await;

        // Replay protection: if the node shuts down right after the last block
        // of the outgoing epoch was processed, but before the first block of
        // the incoming epoch was processed, then we do not want to update the
        // epoch state again.
        //
        // This relies on the fact that the actor updates its tracked epoch
        // state on the last block of the epoch.
        if block_epoch != current_epoch_state.epoch() {
            info!(
                block_epoch,
                actor_epoch = current_epoch_state.epoch(),
                "block was for an epoch other than what the actor is currently tracking; ignoring",
            );
            return;
        }

        // Special case --- boundary block: finalize the ceremony based on the
        // parent block.
        //
        // Recall, for some epoch length E, the boundary heights are
        // 1E-1, 2E-1, 3E-1, ... for epochs 0, 1, 2.
        //
        // So for E = 100, the boundary heights would be 99, 199, 299, ...
        if utils::is_last_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            info!("reached end of epoch - reporting new epoch and starting ceremony");
            let block_outcome = PublicOutcome::decode(block.header().extra_data().as_ref()).expect(
                "the last block of an epoch must always contain the outcome of the DKG ceremony",
            );

            // Finalizations happen in strictly sequential order. This means we
            // are guaranteed to have observed the parent.
            let our_outcome = ceremony.finalize(block.parent_digest()).expect(
                "finalizing the ceremony on the boundary using the block's \
                    parent must work - we have observed all finalized blocks up \
                    until here, so we must have observed its parent, too",
            );

            self.update_and_register_current_epoch_state(tx, our_outcome, block_outcome)
                .await;

            *ceremony = self.start_new_ceremony(tx, ceremony_mux).await;

            // Early return: start driving the ceremony on the first height of
            // the next epoch.
            return;
        }

        // Recall, for an epoch length E the first heights are 0E, 1E, 2E, ...
        //
        // So for E = 100, the first heights are 0, 100, 200, ...
        if is_first_block_in_epoch(self.config.epoch_length, block.height()).is_some() {
            self.enter_current_epoch_and_remove_old_state(tx).await;

            // Similar for the validators: we only need to track the current
            // and last two epochs.
            if let Some(epoch) = current_epoch_state.epoch().checked_sub(3) {
                tx.remove_validators(epoch);
            }
        }

        match epoch::relative_position(block.height(), self.config.epoch_length) {
            epoch::RelativePosition::FirstHalf => {
                let _ = ceremony.distribute_shares(tx).await;
                let _ = ceremony.process_messages(tx).await;
            }
            epoch::RelativePosition::Middle => {
                let _ = ceremony.process_messages(tx).await;
                let _ = ceremony.construct_intermediate_outcome(tx).await;
            }
            epoch::RelativePosition::SecondHalf => {
                // Nothing special happens in the second half of the epoch.
                // Should we use these extra blocks to process more messages?
            }
        }
    }

    #[instrument(skip_all)]
    async fn update_and_register_current_epoch_state(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        our_dkg_outcome: Result<PrivateOutcome, PrivateOutcome>,
        canonical_dkg_outcome: PublicOutcome,
    ) {
        let old_epoch_state: State = self.current_epoch_state(tx).await;

        let new_epoch = our_dkg_outcome
            .as_ref()
            .map_or_else(|e| e.epoch, |o| o.epoch);

        assert_eq!(
            old_epoch_state.epoch() + 1,
            new_epoch,
            "sanity check: old outcome must be new outcome - 1"
        );

        let mut dkg_outcome = match our_dkg_outcome {
            Ok(outcome) => {
                self.metrics.ceremony.one_more_success();
                info!(
                    "ceremony was successful; using the new participants, polynomial and secret key"
                );
                let (public, share) = outcome.role.into_key_pair();
                DkgOutcome {
                    dkg_successful: true,
                    epoch: new_epoch,
                    participants: outcome.participants,
                    public,
                    share,
                }
            }
            Err(outcome) => {
                self.metrics.ceremony.one_more_failure();
                warn!(
                    "ceremony was a failure; using the old participants, polynomial and secret key"
                );
                let (public, share) = outcome.role.into_key_pair();
                DkgOutcome {
                    dkg_successful: false,
                    epoch: new_epoch,
                    participants: outcome.participants,
                    public,
                    share,
                }
            }
        };

        let dkg_mismatch = canonical_dkg_outcome.public != dkg_outcome.public;
        if dkg_mismatch {
            warn!(
                "the DKG outcome committed to chain does not match our own; \
                will take the on-chain outcome instead and delete our share"
            );
            // At this point we cannot know if the public outcome was successful
            // or not so we don't change the our_dkg_outcome.dkg_successful.
            //
            // FIXME(janis): it is critical that the next set of validators and
            // players get pushed into the DKG outcome so that the we get
            // global agreement on these values.
            dkg_outcome.public = canonical_dkg_outcome.public;
            dkg_outcome.participants = canonical_dkg_outcome.participants;
            // TODO: look into revealed shares to see if we can heal
            dkg_outcome.share.take();
        }

        let syncing_players = read_validator_config_with_retry(
            &self.context,
            &self.config.execution_node,
            new_epoch,
            self.config.epoch_length,
        )
        .await;
        let mut new_validator_state = old_epoch_state.validator_state.clone();
        match (dkg_outcome.dkg_successful, dkg_mismatch) {
            // No DKG mismatches
            (true, false) => {
                new_validator_state.push_on_success(syncing_players);
            }
            (false, false) => {
                new_validator_state.push_on_failure(syncing_players);
            }

            // DKG mismatches
            (false, true) => {
                new_validator_state.push_on_success(syncing_players);
            }

            // TODO(janis): publish the IP addresses and pubkeys to chain. Then
            // we can recover from this.
            (true, true) => {
                unreachable!(
                    "a local DKG success with an on-chain mismatch means that \
                    the node successfully read all necessary dealings from \
                    chain while a quorum of validators came to a different \
                    conclusion based off the same data; this is not something \
                    to recover from"
                );
            }
        }

        let new_epoch_state = State {
            dkg_outcome,
            validator_state: new_validator_state.clone(),
        };

        tx.set_previous_actor_state(old_epoch_state);
        tx.set_actor_state(new_epoch_state.clone());
        self.register_current_epoch_state(tx).await;
    }

    /// Reports that a new epoch was fully entered, that the previous epoch can be ended.
    async fn enter_current_epoch_and_remove_old_state(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
    ) {
        let epoch_to_shutdown =
            if let Ok(Some(old_epoch_state)) = tx.get_previous_actor_state().await {
                tx.remove_previous_actor_state();
                Some(old_epoch_state.epoch())
            } else {
                None
            };

        if let Some(epoch) = epoch_to_shutdown {
            self.config
                .epoch_manager
                .report(epoch::Exit { epoch }.into())
                .await;
        }

        if let Some(epoch) = epoch_to_shutdown.and_then(|epoch| epoch.checked_sub(2)) {
            tx.remove_validators(epoch);
        }
    }

    /// Starts a new ceremony for the epoch state tracked by the actor.
    #[instrument(skip_all, fields(epoch = tracing::field::Empty))]
    async fn start_new_ceremony<TReceiver, TSender>(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
        mux: &mut MuxHandle<TSender, TReceiver>,
    ) -> Ceremony<TReceiver, TSender>
    where
        TReceiver: Receiver<PublicKey = PublicKey>,
        TSender: Sender<PublicKey = PublicKey>,
    {
        let epoch_state: State = self.current_epoch_state(tx).await;
        Span::current().record("epoch", epoch_state.epoch());

        let config = ceremony::Config {
            namespace: self.config.namespace.clone(),
            me: self.config.me.clone(),
            public: epoch_state.public_polynomial().clone(),
            share: epoch_state.private_share().clone(),
            epoch: epoch_state.epoch(),
            epoch_length: self.config.epoch_length,
            dealers: epoch_state.dealer_pubkeys(),
            players: epoch_state.player_pubkeys(),
        };
        let ceremony = ceremony::Ceremony::init(
            &mut self.context,
            mux,
            tx,
            config,
            self.metrics.ceremony.clone(),
        )
        .await
        .expect("must always be able to initialize ceremony");

        info!(
            us = %self.config.me,
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
            .syncing_players
            .set(epoch_state.validator_state.syncing_players().len() as i64);

        if let Some(old_epoch) = epoch_state.epoch().checked_sub(2) {
            tx.remove_ceremony(old_epoch);
        }

        ceremony
    }

    /// Registers the new epoch by reporting to the epoch manager that it should
    /// be entered and registering its peers on the peers manager.
    #[instrument(skip_all, fields(epoch = tracing::field::Empty))]
    async fn register_current_epoch_state(
        &mut self,
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
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

        let new_validator_state = epoch_state.validator_state.clone();

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
        tx: &mut DkgReadWriteTransaction<ContextCell<TContext>>,
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

    /// Returns the previous epoch state.
    async fn previous_epoch_state(
        &mut self,
        tx: &DkgReadWriteTransaction<ContextCell<TContext>>,
    ) -> Option<State> {
        tx.get_previous_actor_state().await.ok().flatten()
    }

    /// Returns the current epoch state.
    ///
    /// # Panics
    ///
    /// Panics if no epoch state exists in the database.
    async fn current_epoch_state(
        &mut self,
        tx: &DkgReadWriteTransaction<ContextCell<TContext>>,
    ) -> State {
        tx.get_actor_state()
            .await
            .and_then(|maybe| maybe.ok_or_eyre("epoch state did not exist"))
            .wrap_err("failed to read epoch state")
            .expect("there must always exist an epoch state and it must be readable")
    }
}

#[derive(Clone)]
struct Metrics {
    peers: Gauge,
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
