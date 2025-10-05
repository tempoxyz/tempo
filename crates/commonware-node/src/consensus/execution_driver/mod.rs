//! Drives the execution engine by forwarding consensus messages.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_types_engine::PayloadId;
use commonware_consensus::{
    Automaton, Block as _, Epochable, Relay, Reporter,
    marshal::{self, ingress::mailbox::Identifier},
    threshold_simplex::types::Context,
    types::{Epoch, Round, View},
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};

use commonware_utils::SystemTimeExt;
use eyre::{OptionExt, WrapErr as _, bail, ensure, eyre};
use futures_channel::{mpsc, oneshot};
use futures_util::{
    SinkExt as _, StreamExt as _, TryFutureExt,
    future::{Either, try_join},
};
use rand::{CryptoRng, Rng};
use reth::{
    payload::{EthBuiltPayload, EthPayloadBuilderAttributes},
    rpc::types::Withdrawals,
};
use reth_node_builder::ConsensusEngineHandle;
use reth_primitives_traits::SealedBlock;
use tempo_node::{TempoExecutionData, TempoFullNode, TempoPayloadTypes};

use reth_provider::{BlockNumReader as _, BlockReader as _};
use tempo_primitives::TempoPrimitives;
use tokio::sync::RwLock;
use tracing::{Level, info, instrument};

use tempo_commonware_node_cryptography::{BlsScheme, Digest};
use tempo_payload_types::TempoPayloadBuilderAttributes;

mod executor;

use crate::consensus::execution_driver::executor::ExecutorMailbox;

use super::block::Block;

pub(super) struct ExecutionDriverBuilder<TContext> {
    /// The execution context of the commonwarexyz application (tokio runtime, etc).
    pub(super) context: TContext,

    /// Used as PayloadAttributes.suggested_fee_recipient
    pub(super) fee_recipient: alloy_primitives::Address,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub(super) mailbox_size: usize,

    /// The syncer for subscribing to blocks distributed via the consensus
    /// p2p network.
    pub(super) syncer: marshal::Mailbox<BlsScheme, Block>,

    /// A handle to the execution node to verify and create new payloads.
    pub(super) execution_node: TempoFullNode,

    /// The minimum amount of time to wait before resolving a new payload from the builder
    pub(super) new_payload_wait_time: Duration,
}

impl<TContext> ExecutionDriverBuilder<TContext>
where
    TContext: Clock + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    /// Builds the uninitialized execution driver.
    pub(super) fn build(self) -> eyre::Result<ExecutionDriver<TContext, Uninit>> {
        let (tx, rx) = mpsc::channel(self.mailbox_size);
        let my_mailbox = ExecutionDriverMailbox::from_sender(tx);

        let block = self
            .execution_node
            .provider
            .block_by_number(0)
            .map_err(Into::<eyre::Report>::into)
            .and_then(|maybe| maybe.ok_or_eyre("block reader returned empty genesis block"))
            .wrap_err("failed reading genesis block from execution node")?;

        Ok(ExecutionDriver {
            context: self.context,
            mailbox: rx,

            inner: Inner {
                fee_recipient: self.fee_recipient,
                new_payload_wait_time: self.new_payload_wait_time,

                my_mailbox,
                syncer: self.syncer,

                genesis_block: Arc::new(Block::from_execution_block(SealedBlock::seal_slow(block))),

                execution_node: self.execution_node,

                state: Uninit(()),
            },
        })
    }
}

pub(super) struct ExecutionDriver<TContext, TState = Uninit> {
    context: TContext,
    mailbox: mpsc::Receiver<Message>,

    inner: Inner<TState>,
}

impl<TContext, TState> ExecutionDriver<TContext, TState> {
    pub(super) fn mailbox(&self) -> &ExecutionDriverMailbox {
        &self.inner.my_mailbox
    }
}

impl<TContext> ExecutionDriver<TContext, Uninit>
where
    TContext: Clock + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    /// Runs the execution driver until it is externally stopped.
    async fn run_until_stopped(self) {
        let Self {
            context,
            mailbox,
            inner,
        } = self;
        // TODO(janis): should be placed under a shutdown signal so we don't
        // just stall on startup.
        let Ok(initialized) = inner.into_initialized(context.clone()).await else {
            // XXX: relies on into_initialized generating an error event before exit.
            return;
        };

        ExecutionDriver {
            context,
            mailbox,
            inner: initialized,
        }
        .run_until_stopped()
        .await
    }

    pub(super) fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run_until_stopped())
    }
}

impl<TContext> ExecutionDriver<TContext, Init>
where
    TContext: Clock + governor::clock::Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
{
    /// Runs the initialized execution driver.
    async fn run_until_stopped(mut self) {
        loop {
            tokio::select!(
                // NOTE: biased because we prefer running finalizations above
                // all else.
                // TODO(janis): listen to a shutdown message here so that having
                // biased and this note here make sense.
                biased;

                Some(msg) = self.mailbox.next() => {
                    if let Err(error) =  self.handle_message(msg) {
                        tracing::error_span!("handle message").in_scope(|| tracing::error!(
                            %error,
                            "critical error occurred while handling message; exiting"
                        ));
                        break;
                    }
                }

                else => break,
            )
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
            Message::Genesis(genesis) => _ = self.inner.handle_genesis(genesis),
            Message::Propose(propose) => {
                self.context.with_label("propose").spawn({
                    let inner = self.inner.clone();
                    move |context| inner.handle_propose(propose, context)
                });
            }
            Message::Verify(verify) => {
                self.context.with_label("verify").spawn({
                    let inner = self.inner.clone();
                    move |_| inner.handle_verify(verify)
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Inner<TState> {
    fee_recipient: alloy_primitives::Address,
    new_payload_wait_time: Duration,

    my_mailbox: ExecutionDriverMailbox,

    syncer: marshal::Mailbox<BlsScheme, Block>,

    genesis_block: Arc<Block>,
    execution_node: TempoFullNode,

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

        self.syncer.broadcast(latest_proposed).await;
        Ok(())
    }

    /// Pushes a `finalized` request to the back of the finalization queue.
    fn handle_finalized(&self, finalized: Finalized) -> eyre::Result<()> {
        self.state.executor_mailbox.forward_finalized(finalized)
    }

    #[instrument(
        skip_all,
        fields(
            epoch = genesis.epoch,
        ),
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

    /// Handles a [`Propose`] request.
    #[instrument(
        skip_all,
        fields(
            epoch = request.round.epoch(),
            view = request.round.view(),
            parent.view = request.parent.0,
            parent.digest = %request.parent.1,
        ),
        err(level = Level::WARN),
    )]
    async fn handle_propose<TContext>(self, request: Propose, context: TContext) -> eyre::Result<()>
    where
        TContext: Clock,
    {
        let Propose {
            parent,
            mut response,
            round,
        } = request;
        let proposal = tokio::select!(
            biased;

            () = response.cancellation() => {
                Err(eyre!(
                    "proposal return channel was closed by consensus \
                    engine before block could be proposed; aborting"
                ))
           }

            res = self.clone().propose(context, parent, round) => {
                res.wrap_err("failed creating a proposal")
            }
        )?;

        let consensus_block = Block::from_execution_block(proposal.block().clone());
        let proposed_block_digest = consensus_block.digest();
        response.send(proposed_block_digest).map_err(|_| {
            eyre!(
                "failed returning proposal to consensus engine: response channel was already closed"
            )
        })?;

        {
            let mut lock = self.state.latest_proposed_block.write().await;
            *lock = Some(consensus_block);
        }

        if let Err(error) = self
            .state
            .executor_mailbox
            .canonicalize(None, proposed_block_digest)
        {
            tracing::warn!(
                %error,
                %proposed_block_digest,
                "failed making the proposal the head of the canonical chain",
            );
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
            epoch = verify.round.epoch(),
            view = verify.round.view(),
            digest = %verify.payload,
            parent.view = verify.parent.0,
            parent.digest = %verify.parent.1,
        ),
    )]
    async fn handle_verify(mut self, verify: Verify) {
        let Verify {
            parent,
            payload,
            mut response,
            round,
        } = verify;
        let result = tokio::select!(
            biased;

            () = response.cancellation() => {
                Err(eyre!(
                    "verification return channel was closed by consensus \
                    engine before block could be validated; aborting"
                ))
            }

            res = self.clone().verify(parent, payload, round) => {
                res.wrap_err("block verification failed")
            }
        );

        // 1. respond with the verification result ASAP. Also generates
        // the event reporting the result of the verification.
        let _ = report_verification_result(response, &result);

        // 2. make the forkchoice state available && cache the block
        if let Ok((block, true)) = result {
            if let Err(error) = self.state.executor_mailbox.canonicalize(None, payload) {
                tracing::warn!(
                    %error,
                    "failed making the verified proposal the head of the canonical chain",
                );
            }
            self.syncer.verified(round, block).await;
        }
    }

    async fn propose<TContext>(
        mut self,
        context: TContext,
        parent: (View, Digest),
        round: Round,
    ) -> eyre::Result<EthBuiltPayload<TempoPrimitives>>
    where
        TContext: Clock,
    {
        if let Err(error) = self
            .state
            .executor_mailbox
            .canonicalize(Some(Round::new(round.epoch(), parent.0)), parent.1)
        {
            tracing::warn!(
                %error,
                "failed making the proposal's parent the head of the canonical chain",
            );
        }
        let genesis_block = self.genesis_block.clone();
        let parent_request = if parent.1 == genesis_block.digest() {
            Either::Left(futures_util::future::always_ready({
                move || Ok((*genesis_block).clone())
            }))
        } else {
            Either::Right(
                self.syncer
                    .subscribe(Some(Round::new(round.epoch(), parent.0)), parent.1)
                    .await,
            )
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
        let mut timestamp = context.current().epoch().as_secs();
        if timestamp <= parent.timestamp() {
            timestamp = parent.timestamp().saturating_add(1);
        }

        let attrs = TempoPayloadBuilderAttributes::new(EthPayloadBuilderAttributes {
            // XXX: derives the payload ID from the parent so that
            // overlong payload builds will eventually succeed on the
            // next iteration: if all other nodes take equally as long,
            // the consensus engine will kill the proposal task (see
            // also `response.cancellation` below). Then eventually
            // consensus will circle back to an earlier node, which then
            // has the chance of picking up the old payload.
            id: payload_id_from_block_hash(&parent.block_hash()),
            parent: parent.block_hash(),
            timestamp,
            suggested_fee_recipient: self.fee_recipient,
            // XXX(tempo): for PoS compatibility
            prev_randao: B256::ZERO,
            // XXX(tempo): empty withdrawals post-shanghai
            withdrawals: Withdrawals::default(),
            // TODO: tempo-malachite did this (why?); but maybe we can
            // use the consensus block' digest for this? alternatively somehow
            // tie this to the threshold simplex view / round / height?;
            parent_beacon_block_root: Some(B256::ZERO),
        });

        let interrupt_handle = attrs.interrupt_handle().clone();

        let payload_id = self
            .execution_node
            .payload_builder_handle
            .send_new_payload(attrs)
            .await
            .map_err(|_| eyre!("channel was closed before a response was returned"))
            .and_then(|ret| ret.wrap_err("execution layer rejected request"))
            .wrap_err("failed requesting new payload from the execution layer")?;

        tracing::debug!(
            timeout_ms = self.new_payload_wait_time.as_millis(),
            "sleeping for payload builder timeout"
        );
        context.sleep(self.new_payload_wait_time).await;

        interrupt_handle.interrupt();

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
        let payload = self
            .execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, reth_node_builder::PayloadKind::WaitForPending)
            .await
            // XXX: this returns Option<Result<_, _>>; drilling into
            // resolve_kind this really seems to resolve to None if no
            // payload_id was found.
            .ok_or_eyre("no payload found under provided id")
            .and_then(|rsp| rsp.map_err(Into::<eyre::Report>::into))
            .wrap_err_with(|| format!("failed getting payload for payload ID `{payload_id}`"))?;

        Ok(payload)
    }

    async fn verify(
        mut self,
        parent: (View, Digest),
        payload: Digest,
        round: Round,
    ) -> eyre::Result<(Block, bool)> {
        if let Err(error) = self
            .state
            .executor_mailbox
            .canonicalize(Some(Round::new(round.epoch(), parent.0)), parent.1)
        {
            tracing::warn!(
                %error,
                "failed setting the proposal's parent as the head of the canonical chain",
            );
        }

        let genesis_block = self.genesis_block.clone();
        let parent_request = if parent.1 == genesis_block.digest() {
            Either::Left(futures_util::future::always_ready({
                move || Ok((*genesis_block).clone())
            }))
        } else {
            Either::Right(
                self.syncer
                    .subscribe(Some(Round::new(round.epoch(), parent.0)), parent.1)
                    .await
                    .map_err(|_| eyre!("syncer dropped channel before the parent block was sent")),
            )
        };
        let block_request = self
            .syncer
            .subscribe(None, payload)
            .await
            .map_err(|_| eyre!("syncer dropped channel before the block-to-verified was sent"));

        let (block, parent) = try_join(block_request, parent_request)
            .await
            .wrap_err("failed getting required blocks from syncer")?;

        let is_good = verify_block(
            self.execution_node
                .add_ons_handle
                .beacon_engine_handle
                .clone(),
            &block,
            &parent,
        )
        .await
        .wrap_err("failed verifying block against execution layer")?;

        Ok((block, is_good))
    }
}

impl Inner<Uninit> {
    /// Returns a fully initialized execution driver using runtime information.
    ///
    /// This includes:
    ///
    /// 1. reading the last finalized digest from the consensus marshaller.
    /// 2. starting the canonical chain engine and storing its handle.
    #[instrument(skip_all, err)]
    async fn into_initialized<TContext>(mut self, context: TContext) -> eyre::Result<Inner<Init>>
    where
        TContext: Metrics + Spawner,
    {
        // TODO(janis): does this have the potential to stall indefinitely?
        // If so, we should have some kind of heartbeat to inform telemetry.
        let (finalized_consensus_height, finalized_consensus_digest) = self
            .syncer
            .get_info(Identifier::Latest)
            .await
            .unwrap_or_else(|| {
                info!(
                    "marshal actor returned nothing for the latest block; \
                    cannot distinguish between the actor failing or us still \
                    being at genesis; using height 0 and genesis digest; \
                    consider looking at logs"
                );
                (0, self.genesis_block.digest())
            });

        let latest_execution_block_number =
            self.execution_node.provider.last_block_number().wrap_err(
                "failed getting last block number from execution layer; cannot \
                continue without it",
            )?;

        info!(
            finalized_consensus_height,
            %finalized_consensus_digest,
            latest_execution_block_number,
            "consensus and execution layers reported their latest local state; \
            setting forkchoice-state and catching up execution layer, if \
            necessary",
        );

        let executor = executor::Builder {
            execution_node: self.execution_node.clone(),
            genesis_block: self.genesis_block.clone(),
            latest_finalized_digest: finalized_consensus_digest,
            marshal: self.syncer.clone(),
        }
        .build();

        let initialized = Inner {
            fee_recipient: self.fee_recipient,
            new_payload_wait_time: self.new_payload_wait_time,
            my_mailbox: self.my_mailbox,
            syncer: self.syncer,
            genesis_block: self.genesis_block,
            execution_node: self.execution_node,
            state: Init {
                latest_proposed_block: Arc::new(RwLock::new(None)),
                executor_mailbox: executor.mailbox().clone(),
            },
        };

        context
            .with_label("executor")
            .spawn(move |_| executor.run());

        Ok(initialized)
    }
}

/// Marker type to signal that the execution driver is not fully initialized.
#[derive(Clone, Debug)]
pub(super) struct Uninit(());

/// Carries the runtime initialized state of the execution driver.
#[derive(Clone, Debug)]
struct Init {
    latest_proposed_block: Arc<RwLock<Option<Block>>>,
    executor_mailbox: ExecutorMailbox,
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
async fn verify_block(
    engine: ConsensusEngineHandle<TempoPayloadTypes>,
    block: &Block,
    parent: &Block,
) -> eyre::Result<bool> {
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

    let block = block.clone().into_inner();
    let payload_status = engine
        .new_payload(TempoExecutionData(block))
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

impl Automaton for ExecutionDriverMailbox {
    type Context = Context<Self::Digest>;

    type Digest = Digest;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (tx, rx) = oneshot::channel();
        // TODO: panicking here really is not good. there's actually no requirement on `Self::Context` nor `Self::Digest` to fulfill
        // any invariants, so we could just turn them into `Result<Context, Error>` and be happy.
        self.to_execution_driver
            .send(
                Genesis {
                    epoch,
                    response: tx,
                }
                .into(),
            )
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
                    parent: context.parent,
                    response: tx,
                    round: context.round,
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
                    parent: context.parent,
                    payload,
                    round: context.round,
                    response: tx,
                }
                .into(),
            )
            .await
            .expect("application is present and ready to receive verify requests");
        rx
    }
}

impl Relay for ExecutionDriverMailbox {
    type Digest = Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Broadcast { payload: digest }.into())
            .await
            .expect("application is present and ready to receive broadcasts");
    }
}

impl Reporter for ExecutionDriverMailbox {
    type Activity = Block;

    async fn report(&mut self, block: Self::Activity) {
        let (response, rx) = oneshot::channel();
        // TODO: panicking here is really not necessary. Just log at the ERROR or WARN levels instead?
        self.to_execution_driver
            .send(Finalized { block, response }.into())
            .await
            .expect("application is present and ready to receive broadcasts");

        // XXX: This is used as an acknowledgement that the application
        // finalized the block:
        // Response on this channel -> future returns -> marshaller gets an ack
        //
        // TODO(janis): report if this channel gets dropped?
        let _ = rx.await;
    }
}

#[derive(Clone)]
pub(super) struct ExecutionDriverMailbox {
    to_execution_driver: mpsc::Sender<Message>,
}

impl ExecutionDriverMailbox {
    fn from_sender(to_execution_driver: mpsc::Sender<Message>) -> Self {
        Self {
            to_execution_driver,
        }
    }
}

/// Messages forwarded from consensus to execution driver.
// TODO: add trace spans into all of these messages.
enum Message {
    Broadcast(Broadcast),
    Finalized(Box<Finalized>),
    Genesis(Genesis),
    Propose(Propose),
    Verify(Verify),
}

struct Genesis {
    epoch: Epoch,
    response: oneshot::Sender<Digest>,
}

impl From<Genesis> for Message {
    fn from(value: Genesis) -> Self {
        Self::Genesis(value)
    }
}

struct Propose {
    parent: (View, Digest),
    response: oneshot::Sender<Digest>,
    round: Round,
}

impl From<Propose> for Message {
    fn from(value: Propose) -> Self {
        Self::Propose(value)
    }
}

struct Broadcast {
    payload: Digest,
}

impl From<Broadcast> for Message {
    fn from(value: Broadcast) -> Self {
        Self::Broadcast(value)
    }
}

struct Verify {
    parent: (View, Digest),
    payload: Digest,
    response: oneshot::Sender<bool>,
    round: Round,
}

impl From<Verify> for Message {
    fn from(value: Verify) -> Self {
        Self::Verify(value)
    }
}

#[derive(Debug)]
struct Finalized {
    block: Block,
    response: oneshot::Sender<()>,
}

impl From<Finalized> for Message {
    fn from(value: Finalized) -> Self {
        Self::Finalized(value.into())
    }
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
