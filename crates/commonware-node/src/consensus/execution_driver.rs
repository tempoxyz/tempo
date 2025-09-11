//! Drives the execution engine by forwarding consensus messages.

use std::{sync::Arc, time::SystemTime};

use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionData, ForkchoiceState};
use commonware_consensus::{Automaton, Block as _, Relay, Reporter, marshal};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};

use commonware_utils::SystemTimeExt;
use eyre::{OptionExt, WrapErr as _, bail, ensure, eyre};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    FutureExt as _, SinkExt as _, StreamExt as _, TryFutureExt,
    future::{BoxFuture, Either, try_join},
};
use rand::{CryptoRng, Rng};
use reth::payload::PayloadBuilderHandle;
use reth_ethereum_engine_primitives::EthBuiltPayload;
use reth_node_builder::{ConsensusEngineHandle, PayloadTypes};
use reth_node_ethereum::EthEngineTypes;
use reth_primitives_traits::SealedBlock;
use tempo_node::TempoFullNode;

use reth_provider::BlockReader as _;
use sequential_futures_queue::SequentialFuturesQueue;
use tokio::sync::RwLock;
use tracing::{Level, info, instrument};

use tempo_commonware_node_cryptography::{BlsScheme, Digest};

use super::{View, block::Block};

pub struct Builder<TContext> {
    /// The execution context of the commonwarexyz application (tokio runtime, etc).
    pub context: TContext,

    /// Used as PayloadAttributes.suggested_fee_recipient
    pub fee_recipient: alloy_primitives::Address,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    /// The syncer for subscribing to blocks distributed via the consensus
    /// p2p network.
    pub syncer_mailbox: marshal::Mailbox<BlsScheme, Block<reth_ethereum_primitives::Block>>,

    /// A handle to the execution node to verify and create new payloads.
    pub execution_node: TempoFullNode,
}

impl<TContext> Builder<TContext>
where
    TContext: Clock + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    pub(super) fn try_init(self) -> eyre::Result<ExecutionDriver<TContext>> {
        let (tx, rx) = mpsc::channel(self.mailbox_size);
        let my_mailbox = Mailbox::from_sender(tx);

        let block = self
            .execution_node
            .provider
            .block_by_number(0)
            .map_err(Into::<eyre::Report>::into)
            .and_then(|maybe| maybe.ok_or_eyre("block reader returned empty genesis block"))
            .wrap_err("failed reading genesis block from execution node")?;
        Ok(ExecutionDriver {
            context: self.context,

            fee_recipient: self.fee_recipient,

            from_consensus: rx,
            my_mailbox,
            syncer_mailbox: self.syncer_mailbox,

            genesis_block: Arc::new(Block::from_execution_block(SealedBlock::seal_slow(block))),

            latest_proposed_block: Arc::new(RwLock::new(None)),

            execution_node: self.execution_node,

            finalization_queue: SequentialFuturesQueue::new(),
        })
    }
}

pub struct ExecutionDriver<TContext> {
    context: TContext,

    fee_recipient: alloy_primitives::Address,

    from_consensus: mpsc::Receiver<Message<reth_ethereum_primitives::Block>>,
    my_mailbox: Mailbox<reth_ethereum_primitives::Block>,

    syncer_mailbox: marshal::Mailbox<BlsScheme, Block<reth_ethereum_primitives::Block>>,

    genesis_block: Arc<Block<reth_ethereum_primitives::Block>>,
    latest_proposed_block: Arc<RwLock<Option<Block<reth_ethereum_primitives::Block>>>>,

    execution_node: TempoFullNode,

    /// A queue of finalizations, performed sequentially.
    ///
    /// Sequential finalization is critical so that an older forkchoice update
    /// does not override a newer.
    finalization_queue: SequentialFuturesQueue<BoxFuture<'static, eyre::Result<()>>>,
}

impl<TContext> ExecutionDriver<TContext>
where
    TContext: Clock + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    pub(super) fn mailbox(&self) -> &Mailbox<reth_ethereum_primitives::Block> {
        &self.my_mailbox
    }

    async fn run(mut self) {
        loop {
            tokio::select!(
                // NOTE: biased because we prefer running finalizations above all else.
                biased;

                Some(_res) = self.finalization_queue.next() => {
                    // TODO: decide what to do if finalizations fail.
                    // Finalizations failing is pretty bad. Probably warrants
                    // nuking the node since we can't go on.
                    //
                    // NOTE(return value): expected to be reported in the span
                    // of the future.
                }

                Some(msg) = self.from_consensus.next() => {
                    self.handle_message(msg);
                }

                else => break,
            )
        }
    }

    pub(super) fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    fn handle_message(&mut self, msg: Message<reth_ethereum_primitives::Block>) {
        match msg {
            Message::Broadcast(broadcast) => self.handle_broadcast(broadcast),
            Message::Finalized(finalized) => self.handle_finalized(*finalized),
            Message::Genesis(genesis) => _ = self.handle_genesis(genesis),
            Message::Propose(propose) => self.handle_propose(propose),
            Message::Verify(verify) => self.handle_verify(verify),
        }
    }

    fn handle_broadcast(&mut self, broadcast: Broadcast) {
        self.context.with_label("broadcast").spawn({
            let latest_proposed_block = self.latest_proposed_block.clone();
            let syncer = self.syncer_mailbox.clone();
            move |_| handle_broadcast(broadcast, latest_proposed_block, syncer)
        });

        #[instrument(
            skip_all,
            fields(%broadcast.payload),
            err(level = Level::ERROR))]
        async fn handle_broadcast(
            broadcast: Broadcast,
            latest_proposed: Arc<RwLock<Option<Block<reth_ethereum_primitives::Block>>>>,
            mut syncer: marshal::Mailbox<BlsScheme, Block<reth_ethereum_primitives::Block>>,
        ) -> eyre::Result<()> {
            let Some(latest_proposed) = latest_proposed.read().await.clone() else {
                return Err(eyre!("there was no latest block to broadcast"));
            };
            ensure!(
                broadcast.payload == latest_proposed.digest(),
                "broadcast of payload `{}` was requested, but digest of latest proposed block is `{}`",
                broadcast.payload,
                latest_proposed.digest(),
            );

            syncer.broadcast(latest_proposed).await;
            Ok(())
        }
    }

    /// Pushes a `finalized` request to the back of the finalization queue.
    fn handle_finalized(&mut self, finalized: Finalized<reth_ethereum_primitives::Block>) {
        self.finalization_queue
            .push(self.finalize(finalized).boxed());
    }

    #[instrument(
        skip_all,
        ret(Display),
        err(level = Level::WARN)
    )]
    fn handle_genesis(&mut self, genesis: Genesis) -> eyre::Result<Digest> {
        let genesis_digest = self.genesis_block.digest();
        genesis.response.send(genesis_digest).map_err(|_| {
            eyre!("failed returning genesis block digest: return channel was already closed")
        })?;
        Ok(genesis_digest)
    }

    fn handle_propose(&mut self, propose: Propose) {
        self.context.with_label("propose").spawn({
            let run_propose = self.propose(propose);
            move |context| async move {
                let _ = run_propose.given_timestamp(context.current()).await;
            }
        });
    }

    fn handle_verify(&self, verify: Verify) {
        self.context.with_label("verify").spawn({
            let fut = self.verify(verify);
            move |_| async {
                let _ = fut.await;
            }
        });
    }

    /// Returns a [`RunPropose`] to run a proposal at a given system timestamp.
    // XXX: I wish this could have been implemented a bit more elegantly and
    // without the extra RunPropose indirection, but the requirement of feeding
    // in the context/system time when spawning makes this necessary.
    fn propose(
        &self,
        propose: Propose,
    ) -> RunPropose<reth_ethereum_primitives::Block, EthEngineTypes> {
        RunPropose {
            request: propose,
            engine: self
                .execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            fee_recipient: self.fee_recipient,
            genesis_block: self.genesis_block.clone(),
            latest_proposed_block: self.latest_proposed_block.clone(),
            payload_builder: self.execution_node.payload_builder_handle.clone(),
            syncer_mailbox: self.syncer_mailbox.clone(),
        }
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
            view = verify.view,
            digest = %verify.payload,
            parent.view = verify.parent.0,
            parent.digest = %verify.parent.1,
        ),
        err
    )]
    fn verify(&self, verify: Verify) -> impl Future<Output = eyre::Result<()>> + 'static {
        let engine = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .clone();
        let genesis_block = self.genesis_block.clone();
        let mut syncer_mailbox = self.syncer_mailbox.clone();

        // XXX: this async block MUST remain the last expression. This code
        // makes use of how tracing evaluates function bodies to determine
        // where to attach instrumentation.
        //
        // It checks the last expression in function. If this turns out to be
        // an async block (which here it is) it wraps that very last async
        // block but not the statements preceding it.
        //
        // 1: tracing_attributes::expand::AsyncInfo::from_fn,
        // https://github.com/tokio-rs/tracing/blob/f71cebe41e4c12735b1d19ca804428d4ff7d905d/tracing-attributes/src/expand.rs#L572
        async move {
            let Verify {
                view,
                parent,
                payload,
                mut response,
            } = verify;

            let verification_fut = async {
                let parent_request = if parent.1 == genesis_block.digest() {
                    Either::Left(futures_util::future::always_ready({
                        move || Ok((*genesis_block).clone())
                    }))
                } else {
                    Either::Right(
                        syncer_mailbox
                            .subscribe(Some(parent.0), parent.1)
                            .await
                            .map_err(|_| {
                                eyre!("syncer dropped channel before the parent block was sent")
                            }),
                    )
                };
                let block_request = syncer_mailbox.subscribe(None, payload).await.map_err(|_| {
                    eyre!("syncer dropped channel before the block-to-verified was sent")
                });

                let (block, parent) = try_join(block_request, parent_request)
                    .await
                    .wrap_err("failed getting required blocks from syncer")?;

                let is_good = verify_block(engine, &block, &parent)
                    .await
                    .wrap_err("failed verifying block against execution layer")?;
                Ok::<_, eyre::Report>((block, is_good))
            };

            let (block, is_good) = tokio::select!(
                biased;

                () = response.cancellation() => {
                    Err(eyre!(
                        "verification return channel was closed by consensus \
                        engine before block could be validated; aborting"
                    ))
                }

                res = verification_fut => {
                    res.wrap_err("block verification failed")
                }
            )?;

            // XXX: storing the verified block is moved outside the
            // previous select! statement such that valid blocks are
            // always cached.
            if is_good {
                syncer_mailbox.verified(view, block).await;
            }

            response.send(is_good).map_err(|_| {
                eyre!(
                    "attempted to send return verification result, but \
                        receiver already dropped the channel"
                )
            })?;

            Ok::<(), eyre::Report>(())
        }
    }

    #[instrument(
        skip_all,
        fields(finalized_block.digest = %finalized.block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    fn finalize(
        &self,
        finalized: Finalized<reth_ethereum_primitives::Block>,
    ) -> impl Future<Output = eyre::Result<()>> + 'static {
        let engine = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .clone();
        // XXX: This async block *must* be the last expression in this
        // function so that `instrument` wraps the async block and not
        // statements before it.
        async move {
            let Finalized { block } = finalized;

            let (block, hash) = block.clone().into_inner().split();
            let payload_status = engine
                .new_payload(ExecutionData::from_block_unchecked(hash, &block))
                .await
                .wrap_err(
                    "failed sending new-payload request to execution \
                    engine to query payload status of finalized block",
                )?;

            // TODO: just die if this fails? This condition really should not
            // happen because all finalized blocks up to this point are fed in
            // through the syncer.
            // If this happens regardless some invariant was violated and we
            // have no way to recover.
            ensure!(
                payload_status.is_valid(),
                "payload status of block-to-be-finalized not valid: \
                `{payload_status}`"
            );

            let fcu_response = engine
                .fork_choice_updated(
                    ForkchoiceState {
                        head_block_hash: hash,
                        safe_block_hash: hash,
                        finalized_block_hash: hash,
                    },
                    None,
                    reth_node_builder::EngineApiMessageVersion::V3,
                )
                .await
                .wrap_err(
                    "failed running engine_forkchoiceUpdated to set the \
                    finalized block hash",
                )?;

            ensure!(
                fcu_response.is_valid(),
                "payload status of forkchoice update response valid: `{}`",
                fcu_response.payload_status,
            );

            Ok(())
        }
    }
}

/// Holds all objects to run a proposal via [`Self::given_timestamp`].
struct RunPropose<TBlock, TPayload>
where
    TBlock: reth_primitives_traits::Block + 'static,
    TPayload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    request: Propose,
    engine: ConsensusEngineHandle<TPayload>,
    fee_recipient: alloy_primitives::Address,
    genesis_block: Arc<Block<TBlock>>,
    latest_proposed_block: Arc<RwLock<Option<Block<TBlock>>>>,
    payload_builder: PayloadBuilderHandle<TPayload>,
    syncer_mailbox: marshal::Mailbox<BlsScheme, Block<TBlock>>,
}

// impl<TBlock, TPayload> RunPropose<TBlock, TPayload>
impl<TPayload> RunPropose<reth_ethereum_primitives::Block, TPayload>
where
    TPayload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    #[instrument(
        name = "propose",
        skip_all,
        fields(
            view = self.request.view,
            parent.view = self.request.parent.0,
            parent.digest = %self.request.parent.1,
        ),
        err(level = Level::WARN),
    )]
    async fn given_timestamp(self, timestamp: SystemTime) -> eyre::Result<()> {
        let Self {
            request,
            engine,
            fee_recipient,
            genesis_block,
            latest_proposed_block,
            payload_builder,
            mut syncer_mailbox,
        } = self;
        let Propose {
            // TODO: is there any extra use for this outside of emitting events?
            view: _view,
            parent,
            mut response,
        } = request;

        let proposal_fut = async move {
            let parent_request = if parent.1 == genesis_block.digest() {
                Either::Left(futures_util::future::always_ready({
                    move || Ok((*genesis_block).clone())
                }))
            } else {
                Either::Right(syncer_mailbox.subscribe(Some(parent.0), parent.1).await)
            };
            let parent = parent_request
                        .await
                        .map_err(|_| eyre!(
                            "failed getting parent block from syncer; syncer dropped channel before request was fulfilled"
                        ))?;

            // XXX: ensures the timestamp is strictly monotonically increasing.
            // This is a requirement to pass eth/reth checks.
            //
            // TODO: revisit this to use `SystemTimeExt::epoch_millis` again
            // once it is/if it becomes possible to use milliseconds in
            // reth. This is to ensure a consistent view of timestamps in
            // reth vs the consensus engine.
            let mut timestamp = timestamp.epoch().as_secs();
            if timestamp <= parent.timestamp() {
                timestamp = parent.timestamp().saturating_add(1);
            }
            let payload_attrs = alloy_rpc_types_engine::PayloadAttributes {
                timestamp,
                // XXX(tempo-malachite): for PoS compatibility
                prev_randao: B256::ZERO,
                suggested_fee_recipient: fee_recipient,
                // XXX(tempo-malachite): empty withdrawals post-shanghai
                withdrawals: Some(vec![]),
                // TODO: tempo-malachite does this (why?); but maybe we can
                // use the consensus block' digest for this? alternatively somehow
                // tie this to the threshold simplex view / round / height?;
                parent_beacon_block_root: Some(B256::ZERO),
            };
            let parent_block_hash = parent.block_hash();

            // XXX: sets head = safe = finalized = parent because our finalization
            // steps does the same.
            //
            // TODO: revisit this if we ever relax HEAD pointing a
            // not-yet-finalized head.
            let forkchoice_state = ForkchoiceState {
                head_block_hash: parent_block_hash,
                safe_block_hash: parent_block_hash,
                finalized_block_hash: parent_block_hash,
            };

            let forkchoice_updated = engine
                .fork_choice_updated(
                    forkchoice_state,
                    Some(payload_attrs),
                    reth_node_builder::EngineApiMessageVersion::V3,
                )
                .await
                .wrap_err("failed sending fork_choice_updated to execution node")?;

            let payload_id = forkchoice_updated.payload_id.ok_or_eyre(
                "execution node did not return a payload ID - \
                            `fork_choice_update.payload_id` was empty; \
                            cannot continue without it",
            )?;

            // XXX: resolves to a payload with at least one transactions included.
            //
            // FIXME: Figure out if WaitForPending really is ok. Using
            // WaitForPending instead of Earliest could mean that this future hangs
            // for too long and consensus just moves past this node.
            //
            // Summit does not suffer from this difficulty because they don't have that
            // granular control over the node. Instead, they hardcoded a sleep of 50ms
            // before fetching the payload. Hard sleep is always iffy, but maybe that
            // is a viable alternative to force normal processing to stay within
            // proposal timings?
            let payload = payload_builder
                .resolve_kind(payload_id, reth_node_builder::PayloadKind::WaitForPending)
                .await
                // XXX: this returns Option<Result<_, _>>; drilling into
                // resolve_kind this really seems to resolve to None if no
                // payload_id was found.
                .ok_or_eyre("no payload found under provided id")
                .and_then(|rsp| rsp.map_err(Into::<eyre::Report>::into))
                .wrap_err_with(|| {
                    format!("failed getting payload for payload ID `{payload_id}`")
                })?;
            Ok::<_, eyre::Report>(payload)
        };

        let proposal = tokio::select!(
            biased;

            () = response.cancellation() => {
                Err(eyre!(
                    "proposal return channel was closed by consensus \
                    engine before block could be proposed; aborting"
                ))
            }

            res = proposal_fut => {
                res.wrap_err("failed creating a proposal")
            }
        )?;

        let consensus_block = Block::from_execution_block(proposal.block().clone());
        let proposed_block_digest = consensus_block.digest();
        response.send(proposed_block_digest).map_err(|_| {
            eyre!("failed sending block as proposal: response channel was already closed")
        })?;

        {
            let mut lock = latest_proposed_block.write().await;
            *lock = Some(consensus_block);
        }

        Ok::<(), eyre::Report>(())
    }
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
        block.parent_digest = %block.parent_digest(),
        block.digest = %block.digest(),
        block.height = block.height(),
        block.timestamp = block.timestamp(),
        parent.digest = %parent.digest(),
        parent.height = parent.height(),
        parent.timestamp = parent.timestamp(),
    )
)]
async fn verify_block<TPayload>(
    engine: ConsensusEngineHandle<TPayload>,
    block: &Block<reth_ethereum_primitives::Block>,
    parent: &Block<reth_ethereum_primitives::Block>,
) -> eyre::Result<bool>
where
    TPayload: PayloadTypes<
            PayloadAttributes = alloy_rpc_types_engine::PayloadAttributes,
            ExecutionData = ExecutionData,
            BuiltPayload = EthBuiltPayload,
        >,
{
    use alloy_rpc_types_engine::PayloadStatusEnum;
    if block.parent_digest() != parent.digest() {
        info!(
            "parent digest stored in block must match the digest of the parent \
            argument but doesn't"
        );
        return Ok(false);
    }
    if block.height() != parent.height().saturating_add(1) {
        info!("block's height must be +1 that of the parent but isn't");
        return Ok(false);
    }
    if block.timestamp() <= parent.timestamp() {
        info!("block's timestamp must exceed parent's timestamp but doesn't");
        return Ok(false);
    }

    let (block, hash) = block.clone().into_inner().split();
    let payload_status = engine
        .new_payload(ExecutionData::from_block_unchecked(hash, &block))
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

impl<TBlock> Automaton for Mailbox<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    type Context = super::Context;

    type Digest = Digest;

    async fn genesis(&mut self) -> Self::Digest {
        let (tx, rx) = oneshot::channel();
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        self.to_execution_driver
            .send(Genesis { response: tx }.into())
            .await
            .expect("application is present and ready to receive genesis");
        rx.await
            .expect("application returns the digest of the genesis")
    }

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        //
        // XXX: comment taken from alto - what does this mean? is this relevant to us?
        // > If we linked payloads to their parent, we would verify
        // > the parent included in the payload matches the provided `Context`.
        let (tx, rx) = oneshot::channel();
        self.to_execution_driver
            .send(
                Propose {
                    view: context.view,
                    parent: context.parent,
                    response: tx,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive proposals");
        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        //
        // XXX: comment taken from alto - what does this mean? is this relevant to us?
        // > If we linked payloads to their parent, we would verify
        // > the parent included in the payload matches the provided `Context`.
        let (tx, rx) = oneshot::channel();
        self.to_execution_driver
            .send(
                Verify {
                    view: context.view,
                    parent: context.parent,
                    payload,
                    response: tx,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive verify requests");
        rx
    }
}

impl<TBlock> Relay for Mailbox<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Broadcast { payload: digest }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}

impl<TBlock> Reporter for Mailbox<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    type Activity = Block<TBlock>;

    async fn report(&mut self, block: Self::Activity) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Finalized { block }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}

#[derive(Clone)]
pub struct Mailbox<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    to_execution_driver: mpsc::Sender<Message<TBlock>>,
}

impl<TBlock> Mailbox<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from_sender(to_execution_driver: mpsc::Sender<Message<TBlock>>) -> Self {
        Self {
            to_execution_driver,
        }
    }
}

/// Messages forwarded from consensus to execution driver.
// TODO: add trace spans into all of these messages.
enum Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    Broadcast(Broadcast),
    Finalized(Box<Finalized<TBlock>>),
    Genesis(Genesis),
    Propose(Propose),
    Verify(Verify),
}

struct Genesis {
    response: oneshot::Sender<Digest>,
}

impl<TBlock> From<Genesis> for Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from(value: Genesis) -> Self {
        Self::Genesis(value)
    }
}

struct Propose {
    view: View,
    parent: (View, Digest),
    response: oneshot::Sender<Digest>,
}

impl<TBlock> From<Propose> for Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from(value: Propose) -> Self {
        Self::Propose(value)
    }
}

struct Broadcast {
    payload: Digest,
}

impl<TBlock> From<Broadcast> for Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from(value: Broadcast) -> Self {
        Self::Broadcast(value)
    }
}

struct Verify {
    view: View,
    parent: (View, Digest),
    payload: Digest,
    response: oneshot::Sender<bool>,
}

impl<TBlock> From<Verify> for Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from(value: Verify) -> Self {
        Self::Verify(value)
    }
}

struct Finalized<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    block: Block<TBlock>,
}

impl<TBlock> From<Finalized<TBlock>> for Message<TBlock>
where
    TBlock: reth_primitives_traits::Block + 'static,
{
    fn from(value: Finalized<TBlock>) -> Self {
        Self::Finalized(value.into())
    }
}
