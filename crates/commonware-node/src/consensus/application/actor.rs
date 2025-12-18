//! The actor running the application event loop.
//!
//! # On the usage of the commonware-pacer
//!
//! The actor will contain `Pacer::pace` calls for all interactions
//! with the execution layer. This is a no-op in production because the
//! commonware tokio runtime ignores these. However, these are critical in
//! e2e tests using the commonware deterministic runtime: since the execution
//! layer is still running on the tokio runtime, these calls signal the
//! deterministic runtime to spend real life time to wait for the execution
//! layer calls to complete.

use std::{sync::Arc, time::Duration};

use alloy_consensus::BlockHeader;
use alloy_primitives::{B256, Bytes};
use alloy_rpc_types_engine::PayloadId;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Block as _,
    marshal::SchemeProvider as _,
    types::{Epoch, Round, View},
    utils,
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_macros::select;
use commonware_runtime::{
    ContextCell, FutureExt as _, Handle, Metrics, Pacer, Spawner, Storage, spawn_cell,
};

use commonware_utils::SystemTimeExt;
use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
use futures::{
    StreamExt as _, TryFutureExt as _,
    channel::{mpsc, oneshot},
    future::{Either, always_ready, ready, try_join},
};
use rand::{CryptoRng, Rng};
use reth_node_builder::ConsensusEngineHandle;
use reth_primitives_traits::SealedBlock;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};

use reth_provider::BlockReader as _;
use tokio::sync::RwLock;
use tracing::{Level, debug, error, error_span, info, instrument, warn};

use tempo_payload_types::TempoPayloadBuilderAttributes;

use super::{
    Mailbox, executor,
    executor::ExecutorMailbox,
    ingress::{Broadcast, Finalized, Genesis, Message, Propose, Verify},
};
use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    subblocks,
};

pub(in crate::consensus) struct Actor<TContext, TState = Uninit> {
    context: ContextCell<TContext>,
    mailbox: mpsc::Receiver<Message>,

    inner: Inner<TState>,
}

impl<TContext, TState> Actor<TContext, TState> {
    pub(super) fn mailbox(&self) -> &Mailbox {
        &self.inner.my_mailbox
    }
}

impl<TContext> Actor<TContext, Uninit>
where
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    pub(super) async fn init(config: super::Config<TContext>) -> eyre::Result<Self> {
        let (tx, rx) = mpsc::channel(config.mailbox_size);
        let my_mailbox = Mailbox::from_sender(tx);

        let block = config
            .execution_node
            .provider
            .block_by_number(0)
            .map_err(Into::<eyre::Report>::into)
            .and_then(|maybe| maybe.ok_or_eyre("block reader returned empty genesis block"))
            .wrap_err("failed reading genesis block from execution node")?;

        Ok(Self {
            context: ContextCell::new(config.context),
            mailbox: rx,

            inner: Inner {
                fee_recipient: config.fee_recipient,
                epoch_length: config.epoch_length,
                new_payload_wait_time: config.new_payload_wait_time,

                my_mailbox,
                marshal: config.marshal,

                genesis_block: Arc::new(Block::from_execution_block(SealedBlock::seal_slow(block))),

                execution_node: config.execution_node,
                subblocks: config.subblocks,

                scheme_provider: config.scheme_provider,

                state: Uninit(()),
            },
        })
    }

    /// Runs the actor until it is externally stopped.
    async fn run_until_stopped(self, dkg_manager: crate::dkg::manager::Mailbox) {
        let Self {
            context,
            mailbox,
            inner,
        } = self;
        // TODO(janis): should be placed under a shutdown signal so we don't
        // just stall on startup.
        let Ok(initialized) = inner.into_initialized(context.clone(), dkg_manager).await else {
            // XXX: relies on into_initialized generating an error event before exit.
            return;
        };

        Actor {
            context,
            mailbox,
            inner: initialized,
        }
        .run_until_stopped()
        .await
    }

    pub(in crate::consensus) fn start(
        mut self,
        dkg_manager: crate::dkg::manager::Mailbox,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run_until_stopped(dkg_manager).await)
    }
}

impl<TContext> Actor<TContext, Init>
where
    TContext: Pacer + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    async fn run_until_stopped(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            if let Err(error) = self.handle_message(msg) {
                error_span!("handle message").in_scope(|| {
                    error!(
                        %error,
                        "critical error occurred while handling message; exiting"
                    )
                });
                break;
            }
        }
    }

    fn handle_message(&mut self, msg: Message) -> eyre::Result<()> {
        match msg {
            Message::Broadcast(broadcast) => {
                self.context.with_label("broadcast").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_broadcast(broadcast)
                });
            }
            Message::Finalized(finalized) => {
                // XXX: being able to finalize is the only stop condition.
                // There is no point continuing if this doesn't work.
                self.inner
                    .handle_finalized(*finalized)
                    .wrap_err("failed finalizing block")?;
            }
            Message::Genesis(genesis) => {
                self.context.with_label("genesis").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_genesis(genesis)
                });
            }
            Message::Propose(propose) => {
                self.context.with_label("propose").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_propose(propose, context)
                });
            }
            Message::Verify(verify) => {
                self.context.with_label("verify").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_verify(*verify, context)
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Inner<TState> {
    fee_recipient: alloy_primitives::Address,
    epoch_length: u64,
    new_payload_wait_time: Duration,

    my_mailbox: Mailbox,

    marshal: crate::alias::marshal::Mailbox,

    genesis_block: Arc<Block>,
    execution_node: TempoFullNode,
    subblocks: subblocks::Mailbox,
    scheme_provider: SchemeProvider,

    state: TState,
}

impl Inner<Init> {
    #[instrument(
        skip_all,
        fields(%broadcast.payload),
        err(level = Level::ERROR),
    )]
    async fn handle_broadcast(mut self, broadcast: Broadcast) -> eyre::Result<()> {
        let Some(latest_proposed) = self.state.latest_proposed_block.read().await.clone() else {
            return Err(eyre!("there was no latest block to broadcast"));
        };
        ensure!(
            broadcast.payload == latest_proposed.digest(),
            "broadcast of payload `{}` was requested, but digest of latest proposed block is `{}`",
            broadcast.payload,
            latest_proposed.digest(),
        );

        self.marshal.broadcast(latest_proposed).await;
        Ok(())
    }

    #[instrument(skip_all)]
    /// Pushes a `finalized` request to the back of the finalization queue.
    fn handle_finalized(&self, finalized: Finalized) -> eyre::Result<()> {
        self.state.executor_mailbox.forward_finalized(finalized)
    }

    #[instrument(
        skip_all,
        fields(
            epoch = %genesis.epoch,
        ),
        ret(Display),
        err(level = Level::ERROR)
    )]
    async fn handle_genesis(mut self, genesis: Genesis) -> eyre::Result<Digest> {
        #[expect(
            clippy::option_if_let_else,
            reason = "if-let-else would put the 0-case at the bottom"
        )]
        let source = match genesis.epoch.previous() {
            // epoch 0 has no previous epoch
            None => self.genesis_block.digest(),
            Some(previous_epoch) => {
                // The last block of the *previous* epoch provides the "genesis"
                // of the *current* epoch. Only epoch 0 is special cased above.
                let height = utils::last_block_in_epoch(self.epoch_length, previous_epoch);

                let Some((_, digest)) = self.marshal.get_info(height).await else {
                    // XXX: the None case here should not be hit:
                    // 1. an epoch transition is triggered by the application
                    // finalizing the last block of the outgoing epoch.
                    // 2. the finalized block is received from the marshal actor,
                    // so we know it must be available and indexed
                    // by the marshaller.
                    // 3. this means this call should always succeed.
                    //
                    // TODO(janis): should we panic instead?
                    bail!(
                        "no information on the source block at height `{height}` \
                    exists yet; this is a problem and will likely cause the \
                    consensus engine to not start"
                    );
                };
                digest
            }
        };
        genesis.response.send(source).map_err(|_| {
            eyre!("failed returning parent digest for epoch: return channel was already closed")
        })?;
        Ok(source)
    }

    /// Handles a [`Propose`] request.
    #[instrument(
        skip_all,
        fields(
            epoch = %request.round.epoch(),
            view = %request.round.view(),
            parent.view = %request.parent.0,
            parent.digest = %request.parent.1,
        ),
        err(level = Level::WARN),
    )]
    async fn handle_propose<TContext: Pacer>(
        self,
        request: Propose,
        context: TContext,
    ) -> eyre::Result<()> {
        let Propose {
            parent: (parent_view, parent_digest),
            mut response,
            round,
        } = request;

        let proposal = select!(
            () = response.cancellation() => {
                Err(eyre!(
                    "proposal return channel was closed by consensus \
                    engine before block could be proposed; aborting"
                ))
           },

            res = self.clone().propose(
                context.clone(),
                parent_view,
                parent_digest,
                round
            ) => {
                res.wrap_err("failed creating a proposal")
            }
        )?;

        let proposal_digest = proposal.digest();
        let proposal_height = proposal.height();

        info!(
            proposal.digest = %proposal_digest,
            proposal.height = %proposal_height,
            "constructed proposal",
        );

        response.send(proposal_digest).map_err(|_| {
            eyre!(
                "failed returning proposal to consensus engine: response \
                channel was already closed"
            )
        })?;

        // If re-proposing, then don't store the parent for broadcasting and
        // don't touch the execution layer.
        if proposal_digest == parent_digest {
            return Ok(());
        }

        {
            let mut lock = self.state.latest_proposed_block.write().await;
            *lock = Some(proposal.clone());
        }

        // Make sure reth sees the new payload so that in the next round we can
        // verify blocks on top of it.
        let is_good = verify_block(
            context,
            round.epoch(),
            self.epoch_length,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &proposal,
            parent_digest,
            &self.scheme_provider,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?;

        if !is_good {
            eyre::bail!("validation reported that that just-proposed block is invalid");
        }

        Ok(())
    }

    /// Verifies a [`Verify`] request.
    ///
    /// this method only renders a decision on the `verify.response`
    /// channel if it was able to come to a boolean decision. If it was
    /// unable to refute or prove the validity of the block it will
    /// return an error and drop the response channel.
    ///
    /// Conditions for which no decision could be made are usually:
    /// no block could be read from the syncer or communication with the
    /// execution layer failed.
    #[instrument(
        skip_all,
        fields(
            epoch = %verify.round.epoch(),
            view = %verify.round.view(),
            digest = %verify.payload,
            parent.view = %verify.parent.0,
            parent.digest = %verify.parent.1,
            proposer = %verify.proposer,
        ),
    )]
    async fn handle_verify<TContext: Pacer>(mut self, verify: Verify, context: TContext) {
        let Verify {
            parent,
            payload,
            proposer,
            mut response,
            round,
        } = verify;
        let result = select!(
            () = response.cancellation() => {
                Err(eyre!(
                    "verification return channel was closed by consensus \
                    engine before block could be validated; aborting"
                ))
            },

            res = self.clone().verify(context, parent, payload, proposer, round) => {
                res.wrap_err("block verification failed")
            }
        );

        // Respond with the verification result ASAP. Also generates
        // the event reporting the result of the verification.
        let _ = report_verification_result(response, &result);

        // 2. make the forkchoice state available && cache the block
        if let Ok((block, true)) = result {
            // Only make the verified block canonical when not doing a
            // re-propose at the end of an epoch.
            if parent.1 != payload
                && let Err(error) = self
                    .state
                    .executor_mailbox
                    .canonicalize_head(block.height(), block.digest())
            {
                tracing::warn!(
                    %error,
                    "failed making the verified proposal the head of the canonical chain",
                );
            }
            self.marshal.verified(round, block).await;
        }
    }

    async fn propose<TContext: Pacer>(
        mut self,
        context: TContext,
        parent_view: View,
        parent_digest: Digest,
        round: Round,
    ) -> eyre::Result<Block> {
        let genesis_block = self.genesis_block.clone();
        let parent_request = if parent_digest == genesis_block.digest() {
            Either::Left(always_ready(|| Ok((*genesis_block).clone())))
        } else {
            Either::Right(
                self.marshal
                    .subscribe(Some(Round::new(round.epoch(), parent_view)), parent_digest)
                    .await,
            )
        };
        let parent = parent_request
            .await
            .map_err(|_| eyre!(
                "failed getting parent block from syncer; syncer dropped channel before request was fulfilled"
            ))?;

        debug!(height = parent.height(), "retrieved parent block",);

        // XXX: Re-propose the parent if the parent is the last height of the
        // epoch. parent.height+1 should be proposed as the first block of the
        // next epoch.
        if utils::is_last_block_in_epoch(self.epoch_length, parent.height())
            .is_some_and(|e| e == round.epoch())
        {
            info!("parent is last height of epoch; re-proposing parent");
            return Ok(parent);
        }

        // Send the proposal parent to reth to cover edge cases when we were not asked to verify it directly.
        if !verify_block(
            context.clone(),
            utils::epoch(self.epoch_length, parent.height()),
            self.epoch_length,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &parent,
            // It is safe to not verify the parent of the parent because this block is already notarized.
            parent.parent_digest(),
            &self.scheme_provider,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?
        {
            eyre::bail!("the proposal parent block is not valid");
        }

        ready(
            self.state
                .executor_mailbox
                .canonicalize_head(parent.height(), parent.digest()),
        )
        .and_then(|ack| ack.map_err(eyre::Report::new))
        .await
        .wrap_err("failed updating canonical head to parent")?;

        // Query DKG manager for ceremony data before building payload
        // This data will be passed to the payload builder via attributes
        let extra_data = if utils::is_last_block_in_epoch(self.epoch_length, parent.height() + 1)
            .is_some_and(|e| e == round.epoch())
        {
            // At epoch boundary: include public ceremony outcome
            let outcome = self
                .state
                .dkg_manager
                .get_public_ceremony_outcome((parent_view, parent_digest), round)
                .await
                .wrap_err("failed getting public dkg ceremony outcome")?;
            ensure!(
                round.epoch().next() == outcome.epoch,
                "outcome is for epoch `{}`, but we are trying to include the \
                outcome for epoch `{}`",
                outcome.epoch,
                round.epoch().next(),
            );
            info!(
                %outcome.epoch,
                "received DKG outcome; will include in payload builder attributes",
            );
            outcome.encode().freeze().into()
        } else {
            // Regular block: try to include intermediate dealing
            match self
                .state
                .dkg_manager
                .get_intermediate_dealing(round.epoch())
                .await
            {
                Err(error) => {
                    warn!(
                        %error,
                        "failed getting ceremony deal for current epoch because DKG manager went away",
                    );
                    Bytes::default()
                }
                Ok(None) => Bytes::default(),
                Ok(Some(deal_outcome)) => {
                    info!(
                        "found ceremony deal outcome; will include in payload builder attributes"
                    );
                    deal_outcome.encode().freeze().into()
                }
            }
        };

        let attrs = TempoPayloadBuilderAttributes::new(
            // XXX: derives the payload ID from the parent so that
            // overlong payload builds will eventually succeed on the
            // next iteration: if all other nodes take equally as long,
            // the consensus engine will kill the proposal task (see
            // also `response.cancellation` below). Then eventually
            // consensus will circle back to an earlier node, which then
            // has the chance of picking up the old payload.
            payload_id_from_block_hash(&parent.block_hash()),
            parent.block_hash(),
            self.fee_recipient,
            context.current().epoch_millis(),
            extra_data,
            move || {
                self.subblocks
                    .get_subblocks(parent.block_hash())
                    .unwrap_or_default()
            },
        );

        let interrupt_handle = attrs.interrupt_handle().clone();

        let payload_id = self
            .execution_node
            .payload_builder_handle
            .send_new_payload(attrs)
            .pace(&context, Duration::from_millis(20))
            .await
            .map_err(|_| eyre!("channel was closed before a response was returned"))
            .and_then(|ret| ret.wrap_err("execution layer rejected request"))
            .wrap_err("failed requesting new payload from the execution layer")?;

        debug!(
            timeout_ms = self.new_payload_wait_time.as_millis(),
            "sleeping for payload builder timeout"
        );
        context.sleep(self.new_payload_wait_time).await;

        interrupt_handle.interrupt();

        let payload = self
            .execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, reth_node_builder::PayloadKind::WaitForPending)
            .pace(&context, Duration::from_millis(20))
            .await
            // XXX: this returns Option<Result<_, _>>; drilling into
            // resolve_kind this really seems to resolve to None if no
            // payload_id was found.
            .ok_or_eyre("no payload found under provided id")
            .and_then(|rsp| rsp.map_err(Into::<eyre::Report>::into))
            .wrap_err_with(|| format!("failed getting payload for payload ID `{payload_id}`"))?;

        Ok(Block::from_execution_block(payload.block().clone()))
    }

    async fn verify<TContext: Pacer>(
        mut self,
        context: TContext,
        (parent_view, parent_digest): (View, Digest),
        payload: Digest,
        proposer: PublicKey,
        round: Round,
    ) -> eyre::Result<(Block, bool)> {
        let genesis_block = self.genesis_block.clone();
        let parent_request = if parent_digest == genesis_block.digest() {
            Either::Left(always_ready(|| Ok((*genesis_block).clone())))
        } else {
            Either::Right(
                self.marshal
                    .subscribe(Some(Round::new(round.epoch(), parent_view)), parent_digest)
                    .await
                    .map_err(|_| eyre!("syncer dropped channel before the parent block was sent")),
            )
        };
        let block_request = self
            .marshal
            .subscribe(None, payload)
            .await
            .map_err(|_| eyre!("syncer dropped channel before the block-to-verified was sent"));

        let (block, parent) = try_join(block_request, parent_request)
            .await
            .wrap_err("failed getting required blocks from syncer")?;

        // Can only repropose at the end of an epoch.
        //
        // NOTE: fetching block and parent twice (in the case block == parent)
        // seems wasteful, but both run concurrently, should finish almost
        // immediately, and happen very rarely. It's better to optimize for the
        // general case.
        if payload == parent_digest {
            if utils::is_last_block_in_epoch(self.epoch_length, block.height())
                .is_some_and(|e| e == round.epoch())
            {
                return Ok((block, true));
            } else {
                return Ok((block, false));
            }
        }

        if let Err(reason) = verify_header_extra_data(
            &block,
            (parent_view, parent_digest),
            round,
            &self.state.dkg_manager,
            self.epoch_length,
            &proposer,
        )
        .await
        {
            warn!(
                %reason,
                "header extra data could not be verified; failing block",
            );
            return Ok((block, false));
        }

        if let Err(error) = self
            .state
            .executor_mailbox
            .canonicalize_head(parent.height(), parent.digest())
        {
            tracing::warn!(
                %error,
                parent.height = parent.height(),
                parent.digest = %parent.digest(),
                "failed updating canonical head to parent",
            );
        }

        let is_good = verify_block(
            context,
            round.epoch(),
            self.epoch_length,
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &block,
            parent_digest,
            &self.scheme_provider,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?;

        Ok((block, is_good))
    }
}

impl Inner<Uninit> {
    /// Returns a fully initialized actor using runtime information.
    ///
    /// This includes:
    ///
    /// 1. reading the last finalized digest from the consensus marshaller.
    /// 2. starting the canonical chain engine and storing its handle.
    #[instrument(skip_all, err)]
    async fn into_initialized<TContext: Metrics + Spawner + Pacer>(
        self,
        context: TContext,
        dkg_manager: crate::dkg::manager::Mailbox,
    ) -> eyre::Result<Inner<Init>> {
        let executor = executor::Builder {
            execution_node: self.execution_node.clone(),
            genesis_block: self.genesis_block.clone(),
            marshal: self.marshal.clone(),
        }
        .build(context.with_label("executor"));

        let executor_mailbox = executor.mailbox().clone();
        let executor_handle = executor.start();

        let initialized = Inner {
            fee_recipient: self.fee_recipient,
            epoch_length: self.epoch_length,
            new_payload_wait_time: self.new_payload_wait_time,
            my_mailbox: self.my_mailbox,
            marshal: self.marshal,
            genesis_block: self.genesis_block,
            execution_node: self.execution_node,
            state: Init {
                latest_proposed_block: Arc::new(RwLock::new(None)),
                dkg_manager,
                executor_mailbox,
                _executor_handle: AbortOnDrop(executor_handle).into(),
            },
            subblocks: self.subblocks,
            scheme_provider: self.scheme_provider,
        };

        Ok(initialized)
    }
}

/// Marker type to signal that the actor is not fully initialized.
#[derive(Clone, Debug)]
pub(in crate::consensus) struct Uninit(());

/// Carries the runtime initialized state of the application.
#[derive(Clone, Debug)]
struct Init {
    latest_proposed_block: Arc<RwLock<Option<Block>>>,
    dkg_manager: crate::dkg::manager::Mailbox,
    /// The communication channel to the [`executor::Executor`] task.
    executor_mailbox: ExecutorMailbox,
    /// The handle to the spawned executor task.
    ///
    /// If the last instance of this is dropped (the application task is aborted),
    /// this ensures that the task is aborted as well.
    _executor_handle: Arc<AbortOnDrop>,
}

/// Verifies `block` given its `parent` against the execution layer.
///
/// Returns whether the block is valid or not. Returns an error if validation
/// was not possible, for example if communication with the execution layer
/// failed.
///
/// Reason the reason for why a block was not valid is communicated as a
/// tracing event.
#[instrument(
    skip_all,
    fields(
        epoch,
        epoch_length,
        block.parent_digest = %block.parent_digest(),
        block.digest = %block.digest(),
        block.height = block.height(),
        block.timestamp = block.timestamp(),
        parent.digest = %parent_digest,
    )
)]
async fn verify_block<TContext: Pacer>(
    context: TContext,
    epoch: Epoch,
    epoch_length: u64,
    engine: ConsensusEngineHandle<TempoPayloadTypes>,
    block: &Block,
    parent_digest: Digest,
    scheme_provider: &SchemeProvider,
) -> eyre::Result<bool> {
    use alloy_rpc_types_engine::PayloadStatusEnum;

    if utils::epoch(epoch_length, block.height()) != epoch {
        info!("block does not belong to this epoch");
        return Ok(false);
    }
    if block.parent_hash() != *parent_digest {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(false);
    }
    let scheme = scheme_provider
        .scheme(epoch)
        .ok_or_eyre("cannot determine participants in the current epoch")?;
    let block = block.clone().into_inner();
    let execution_data = TempoExecutionData {
        block: Arc::new(block),
        validator_set: Some(
            scheme
                .participants()
                .into_iter()
                .map(|p| B256::from_slice(p))
                .collect(),
        ),
    };
    let payload_status = engine
        .new_payload(execution_data)
        .pace(&context, Duration::from_millis(50))
        .await
        .wrap_err("failed sending `new payload` message to execution layer to validate block")?;
    match payload_status.status {
        PayloadStatusEnum::Valid | PayloadStatusEnum::Accepted => Ok(true),
        PayloadStatusEnum::Invalid { validation_error } => {
            info!(
                validation_error,
                "execution layer returned that the block was invalid"
            );
            Ok(false)
        }
        PayloadStatusEnum::Syncing => {
            // FIXME: is this error message correct?
            bail!(
                "failed validating block because payload is still syncing, \
                this means the parent block was available to the consensus
                layer but not the execution layer"
            )
        }
    }
}

#[instrument(skip_all, err(Display))]
async fn verify_header_extra_data(
    block: &Block,
    parent: (View, Digest),
    round: Round,
    dkg_manager: &crate::dkg::manager::Mailbox,
    epoch_length: u64,
    proposer: &PublicKey,
) -> eyre::Result<()> {
    if utils::is_last_block_in_epoch(epoch_length, block.height()).is_some() {
        info!(
            "on last block of epoch; verifying that the boundary block \
            contains the correct DKG outcome",
        );
        let our_outcome = dkg_manager
            .get_public_ceremony_outcome(parent, round)
            .await
            .wrap_err(
                "failed getting public dkg ceremony outcome; cannot verify end \
                of epoch block",
            )?;
        let block_outcome = PublicOutcome::decode(block.header().extra_data().as_ref()).wrap_err(
            "failed decoding extra data header as DKG ceremony \
                outcome; cannot verify end of epoch block",
        )?;
        if our_outcome != block_outcome {
            // Emit the log here so that it's structured. The error would be annoying to read.
            warn!(
                our.epoch = %our_outcome.epoch,
                our.participants = ?our_outcome.participants,
                our.public = ?our_outcome.public,
                block.epoch = %block_outcome.epoch,
                block.participants = ?block_outcome.participants,
                block.public = ?block_outcome.public,
                "our public dkg ceremony outcome does not match what's stored \
                in the block",
            );
            return Err(eyre!(
                "our public dkg ceremony outcome does not match what's \
                stored in the block header extra_data field; they must \
                match so that the end-of-block is valid",
            ));
        }
    } else if !block.header().extra_data().is_empty()
        && let Ok(dealing) = block.try_read_ceremony_deal_outcome()
    {
        info!("block header extra_data header contained intermediate DKG dealing; verifying it");
        ensure!(
            dealing.dealer() == proposer,
            "proposer `{proposer}` is not the dealer `{}` recorded in the \
            intermediate DKG dealing",
            dealing.dealer(),
        );

        ensure!(
            dkg_manager
                .verify_intermediate_dealings(dealing)
                .await
                .wrap_err("failed request to verify DKG dealing")?,
            "signature of intermediate DKG outcome could not be verified",
        );
    }

    Ok(())
}

/// Constructs a [`PayloadId`] from the first 8 bytes of `block_hash`.
fn payload_id_from_block_hash(block_hash: &B256) -> PayloadId {
    PayloadId::new(
        <[u8; 8]>::try_from(&block_hash[0..8])
            .expect("a 32 byte array always has more than 8 bytes"),
    )
}

/// Reports the verification result as a tracing event and consensus response.
///
/// This means either sending true/false if a decision could be rendered, or
/// dropping the channel, if not.
#[instrument(skip_all, err)]
fn report_verification_result(
    response: oneshot::Sender<bool>,
    verification_result: &eyre::Result<(Block, bool)>,
) -> eyre::Result<()> {
    match &verification_result {
        Ok((_, is_good)) => {
            info!(
                proposal_valid = is_good,
                "returning proposal verification result to consensus",
            );
            response.send(*is_good).map_err(|_| {
                eyre!(
                    "attempted to send return verification result, but \
                        receiver already dropped the channel"
                )
            })?;
        }
        Err(error) => {
            info!(
                %error,
                "could not decide proposal, dropping response channel",
            );
        }
    }
    Ok(())
}

/// Ensures the task associated with the [`Handle`] is aborted [`Handle::abort`] when this instance is dropped.
struct AbortOnDrop(Handle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl std::fmt::Debug for AbortOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AbortOnDrop").finish_non_exhaustive()
    }
}
