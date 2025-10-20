//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.
//!
//! If the agent detects that the execution layer is missing blocks it attempts
//! to backfill them from the consensus layer.

use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatus};
use commonware_consensus::{Block as _, marshal, types::Round};
use commonware_macros::select;
use commonware_runtime::{ContextCell, FutureExt, Handle, Metrics, Pacer, Spawner, spawn_cell};
use eyre::{WrapErr as _, ensure};
use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
};
use reth_provider::BlockNumReader as _;
use tempo_commonware_node_cryptography::{BlsScheme, Digest};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, Span, info, instrument, warn};

use crate::consensus::block::Block;

pub(super) struct Builder {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    pub(super) execution_node: TempoFullNode,

    /// The genesis block of the network. This is critically important when
    /// backfilling: since marshal does not know about genesis, subscribing to
    /// it with a round and the genesis digest will cause it to never resolve.
    pub(super) genesis_block: Arc<Block>,

    /// The last digest that the consensus layer has finalized. The agent
    /// will send this as the first finalized head to the execution layer.
    pub(super) latest_finalized_digest: Digest,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    pub(super) marshal: marshal::Mailbox<BlsScheme, Block>,
}

impl Builder {
    /// Constructs the [`Executor`].
    pub(super) fn build<TContext>(self, context: TContext) -> Executor<TContext>
    where
        TContext: Spawner,
    {
        let Self {
            execution_node,
            genesis_block,
            latest_finalized_digest,
            marshal,
        } = self;

        let (to_me, from_execution_driver) = mpsc::unbounded();

        let my_mailbox = ExecutorMailbox { inner: to_me };

        // XXX: canonicalizing the latest finalized digest && starting a backfill
        // ensures that a) executor sends head = safe = finalized = latest_finalized
        // as its first operation, and b) that it immediately triggers a backfill
        // from the last finalized block to the latest execution layer block.
        my_mailbox
            .canonicalize(None, latest_finalized_digest)
            .expect("our mailbox must work right after construction");

        my_mailbox
            .backfill(None, latest_finalized_digest)
            .expect("our mailbox must work right after construction");

        Executor {
            context: ContextCell::new(context),
            execution_node,
            genesis_block,
            mailbox: from_execution_driver,
            latest_finalized_digest,
            marshal,
            my_mailbox,
        }
    }
}

pub(super) struct Executor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TempoFullNode,

    /// The genesis block of the network. This is critically important when
    /// backfilling: since marshal does not know about genesis, subscribing to
    /// it with a round and the genesis digest will cause it to never resolve.
    genesis_block: Arc<Block>,

    /// The channel over which the agent will receive new commands from the
    /// execution driver.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: marshal::Mailbox<BlsScheme, Block>,

    /// The latest finalized digest of the block that the agent has sent to the
    /// execution layer. When advancing the canonical chain by sending a
    /// forkchoice update, it will set
    /// finalized_block_hash = latest_finalized_digest.
    latest_finalized_digest: Digest,

    /// The mailbox passed to other parts of the system to forward messages to
    /// the agent.
    my_mailbox: ExecutorMailbox,
}

impl<TContext> Executor<TContext>
where
    TContext: Metrics + Pacer + Spawner,
{
    pub(super) fn mailbox(&self) -> &ExecutorMailbox {
        &self.my_mailbox
    }

    pub(super) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        loop {
            select! {
                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break; };
                    // XXX: updating forkchoice and finalizing blocks must
                    // happen sequentially, so blocking the event loop on await
                    // is desired.
                    //
                    // Backfills will be spawned as tasks and will also send
                    // resolved the blocks to this queue.
                    self.handle_message(msg).await;
                },
            }
        }
    }

    async fn handle_message(&mut self, message: Message) {
        let cause = message.cause;
        match message.command {
            Command::Backfill { round, digest } => self.backfill(cause, round, digest),
            Command::Canonicalize { round, digest } => {
                let _ = self.canonicalize(cause, round, digest).await;
            }
            Command::ForwardBlock { block, response } => {
                let _ = self.forward_block(*block, response, cause).await;
            }
        }
    }

    /// Backfills a block identified by `digest` by reading it from the
    /// consensus layer.
    ///
    /// Must only be called if `digest` belongs to a notarized block. If `digest`
    /// does not identify a notarized block the triggered backfill will never
    /// complete. `round` is used for blocks which are not yet available in the
    /// consensus layer to help the marshal agent request it from the consensus
    /// p2p network.
    ///
    /// Note that this function is not async. Backfills are run in an async
    /// queue and are allowed to finish anytime.
    ///
    /// # How backfills are triggered
    ///
    /// Backfills are done by requesting a block identified by `digest` and
    /// `round` from the consensus `marshal` agent. Backfills are started in
    /// two ways:
    ///
    /// 1. In the executor's constructor [`Builder::build`] with arguments
    /// `round = None`, `digest = latest_finalized_digest`.
    /// `latest_finalized_digest` is expected to be read from the `marshal`
    /// agent, and as such the corresponding block and all its ancestors must
    /// exist in the marshaler.
    /// 2. As part of [`Executor::canonicalize`]. After sending a
    /// fork-choice-update for `digest`, if the execution level responds with
    /// `syncing` (meaning it does not yet have the block available), a backfill
    /// is started if and only if `round` was set. The reasoning is that
    /// `canonicalize` is called on the parent block of a consensus proposal or
    /// verification. For both, the parent is guaranteed to be notarized (by
    /// the simplex protocol), and hence its round known. For this reason, it is
    /// guaranteed that the marshal agent will request (and eventually receive)
    /// the block from the network. If a wrong `round` was supplied the block
    /// subscription to the marshal would stall indefinitely.
    ///
    /// # Walking the chain of ancestors
    ///
    /// An initial backfill will trigger an avalanche of backfills walking the
    /// chain of block ancestors until an ancestor's height is found to be at or
    /// below the latest height available to the execution layer. Each new
    /// backfill is a message to the actor with `round` unset (because `round`
    /// can not be discerned from the block itself). But since all of these
    /// ancestor blocks are finalized (indirectly or directly since they are
    /// ancestors of a notarized block), it is also guaranteed that the marshal
    /// agent will eventually supply the block.
    #[instrument(
        skip_all,
        parent = &cause,
        fields(
            epoch = round.as_ref().map(Round::epoch),
            view = round.as_ref().map(Round::view),
            %digest,
        ),
    )]
    fn backfill(&mut self, cause: Span, round: Option<Round>, digest: Digest) {
        self.context.with_label("backfill").spawn({
            let fut = backfill_from_consensus(
                Span::current(),
                digest,
                self.execution_node.clone(),
                self.my_mailbox.clone(),
                self.genesis_block.clone(),
                self.marshal.clone(),
                round,
            );
            move |_| fut
        });
    }

    /// Canonicalizes `digest` by setting it as the head of the execution layer.
    ///
    /// This function sends a forkchoice-update to the execution layer, setting
    /// `head_block_hash = digest` and
    /// `finalized_block_hash = self.latest_finalized_digest`.
    ///
    /// If `digest` is not found in the execution layer, the agent attempts to
    /// backfill it and its ancestors from the consensus layer.
    #[instrument(
        skip_all,
        follows_from = [cause],
        fields(
            epoch = round.as_ref().map(Round::epoch),
            view = round.as_ref().map(Round::view),
            %digest,
        ),
        ret,
        err(Display),
    )]
    async fn canonicalize(
        &self,
        cause: Span,
        round: Option<Round>,
        digest: Digest,
    ) -> eyre::Result<PayloadStatus> {
        let finalized_block_hash = self.latest_finalized_digest.0;
        let forkchoice_state = ForkchoiceState {
            head_block_hash: digest.0,
            safe_block_hash: finalized_block_hash,
            finalized_block_hash,
        };
        info!(
            head_block_hash = %forkchoice_state.head_block_hash,
            finalized_block_hash = %forkchoice_state.finalized_block_hash,
            "sending forkchoice-update",
        );
        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                forkchoice_state,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .pace(&self.context, Duration::from_millis(20))
            .await
            .wrap_err("failed requesting execution layer to update forkchoice state")?;

        if fcu_response.is_invalid() {
            return Err(eyre::Report::msg(fcu_response.payload_status)
                .wrap_err("execution layer responded with error for forkchoice-update"));
        }

        // XXX: taking `round` being set as a trigger to check the ancestry. The
        // reasoning is such: if `round` is provided, this means that
        // canonicalize was called with explicit information about a parent
        // being available at a given view. This means that parent must have
        // been notarized and will eventually be (indirectly) finalized.
        //
        // If on the other hand `digest` was requested to be canonicalized
        // without round information, then it is not (yet) notarized.
        if round.is_some() && fcu_response.is_syncing() {
            info!("execution layer reported digest to be syncing; attempting backfill");
            self.my_mailbox
                .backfill(round, digest)
                .expect("mailbox must be open because this was called from inside the actor");
        }

        Ok(fcu_response.payload_status)
    }

    /// Finalizes `block` by sending it to the execution layer.
    ///
    /// If `response` is set, `block` is considered to at the tip of the
    /// finalized chain. The agent will also confirm the finalization  by
    /// responding on that channel and set the digest as the latest finalized
    /// head.
    ///
    /// The agent will also cache `digest` as the latest finalized digest.
    /// The agent does not update the forkchoice state of the execution layer
    /// here but upon serving a `Command::Canonicalize` request.
    ///
    /// If `response` is not set the agent assumes that `block` is an older
    /// block backfilled from the consensus layer.
    ///
    /// # Invariants
    ///
    /// It is critical that a newer finalized block is always send after an
    /// older finalized block. This is standard behavior of the commonmware
    /// marshal agent.
    #[instrument(
        skip_all,
        follows_from = [cause],
        fields(
            block.digest = %block.digest(),
            is_backfill = response.is_none(),
        ),
        err(level = Level::WARN),
        ret,
    )]
    async fn forward_block(
        &mut self,
        block: Block,
        response: Option<oneshot::Sender<()>>,
        cause: Span,
    ) -> eyre::Result<()> {
        let digest = block.digest();
        let block = block.into_inner();
        let payload_status = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData(block))
            .pace(&self.context, Duration::from_millis(20))
            .await
            .wrap_err(
                "failed sending new-payload request to execution engine to \
                query payload status of finalized block",
            )?;

        ensure!(
            payload_status.is_valid() || payload_status.is_syncing(),
            "this is a problem: payload status of block-to-be-finalized was \
            neither valid nor syncing: `{payload_status}`"
        );

        if let Some(response) = response {
            self.latest_finalized_digest = digest;

            // TODO(janis): this acknowledges to the marshaller that the finalized
            // block was successfully delivered to the state machine, but we don't
            // actually set the finalized head. That will only happen once the next
            // update request is sent. We can postpone sending a response here and
            // instead store the channel internally, sending an ack once the
            // canonical (including finalized) is actually updated.
            if let Err(()) = response.send(()) {
                warn!("tried acknowledging finalization but channel was already closed");
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExecutorMailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl ExecutorMailbox {
    /// Requests the agent to backfill a block identified by its `digest`.
    ///
    /// If `round` is set the agent will use this to subscribe to a block from
    /// the commonware marshal agent.
    fn backfill(&self, round: Option<Round>, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Backfill { round, digest },
            })
            .wrap_err("failed sending backfill request to finalizer, this means it exited")
    }

    /// Requests the agent to update the canonical chain to `digest`.
    ///
    /// Of `round` is set, the agent will also attempt to backfill the ancestors
    /// of `digest`.
    pub(super) fn canonicalize(&self, round: Option<Round>, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Canonicalize { round, digest },
            })
            .wrap_err("failed sending canonicalize request to agent, this means it exited")
    }

    /// Request the agent to forward a finalized block to the execution layer.
    pub(super) fn forward_block(&self, block: Block) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::ForwardBlock {
                    block: Box::new(block),
                    response: None,
                },
            })
            .wrap_err("failed sending finalization request to agent, this means it exited")
    }

    /// Requests the agent to forward a `finalized` block to the execution layer.
    pub(super) fn forward_finalized(&self, finalized: super::Finalized) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::ForwardBlock {
                    block: Box::new(finalized.block),
                    response: Some(finalized.response),
                },
            })
            .wrap_err("failed sending finalization request to agent, this means it exited")
    }
}

#[derive(Debug)]
struct Message {
    cause: Span,
    command: Command,
}

#[derive(Debug)]
enum Command {
    /// Requests the agent to backfill a block identified by its `digest`.
    ///
    /// If `round` is set the agent will use this to subscribe to a block from
    /// the commonware marshal agent.
    Backfill {
        round: Option<Round>,
        digest: Digest,
    },
    /// Requests the agent to canonicalize `digest`.
    ///
    /// This variant is used by the `ExecutorMailbox::canonicalize` method.
    /// If `round` information is set the agent will attempt to backfill
    /// `digest` and ancestors to the execution layer.
    Canonicalize {
        round: Option<Round>,
        digest: Digest,
    },
    /// Requests the agent to forward a block to the execution layer.
    ///
    /// This variant is used for both ExecutorMailbox::forward_block and
    /// ExecutorBlock::forward_finalized.
    ///
    /// The response channel is expected to be set if a finalized block is
    /// sent, i.e. a block tip of the finalized chain. This is the case when a
    /// finalized block is received from the commonware marshaller, which
    /// expects an acknowledgmenet of finalization.
    ForwardBlock {
        block: Box<Block>,
        response: Option<oneshot::Sender<()>>,
    },
}

/// Reads a block from consensus and forwards it to the execution layer.
///
/// Triggers a new backfill if its parent's height is below the latest
/// block number available in the execution layer.
#[instrument(
    skip_all,
    follows_from = [cause],
    fields(
        epoch = round.as_ref().map(Round::epoch),
        view = round.as_ref().map(Round::view),
        %digest,
    ),
    err(level = Level::WARN),
)]
async fn backfill_from_consensus(
    cause: Span,
    digest: Digest,
    execution_node: TempoFullNode,
    executor_mailbox: ExecutorMailbox,
    genesis_block: Arc<Block>,
    mut marshal: marshal::Mailbox<BlsScheme, Block>,
    round: Option<Round>,
) -> eyre::Result<()> {
    if digest == genesis_block.digest() {
        info!("genesis digest supplied; stopping backfill");
        return Ok(());
    }

    let block = marshal
        .subscribe(round, digest)
        .await
        .await
        .wrap_err("consensus layer did not have block")?;

    let height = block.height();
    let parent = block.parent();

    // XXX: last_block_number returns that block number that is guaranteed
    // to exist in the execution layer's database.
    let last_execution_height = execution_node
        .provider
        .last_block_number()
        .wrap_err("failed querying execution layer for its last block number")?;

    executor_mailbox
        .forward_block(block)
        .wrap_err("executor mailbox was already closed")?;

    if height.saturating_sub(1) > last_execution_height {
        info!(
            last_execution_height,
            "reached the last block number of the execution layer; aborting backfill"
        );
        executor_mailbox
            .backfill(None, parent)
            .wrap_err("executor mailbox was already closed")?;
    }
    Ok(())
}
