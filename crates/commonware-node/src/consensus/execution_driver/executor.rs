//! Drives the actual execution by sending finalized blocks and forkchoice updates.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::sync::Arc;

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatus};
use commonware_consensus::{Block as _, marshal, types::Round};
use eyre::{WrapErr as _, ensure};
use futures_channel::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot,
};
use futures_util::StreamExt as _;
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
    pub(super) fn build(self) -> Executor {
        let Self {
            execution_node,
            genesis_block,
            latest_finalized_digest,
            marshal,
        } = self;

        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();

        let my_mailbox = ExecutorMailbox { inner: to_me };

        // XXX: canonicalizing the latest finalizad digest && starting a backfill
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
            execution_node,
            genesis_block,
            mailbox: from_execution_driver,
            latest_finalized_digest,
            marshal,
            my_mailbox,
        }
    }
}

pub(super) struct Executor {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TempoFullNode,

    /// The genesis block of the network. This is critically important when
    /// backfilling: since marshal does not know about genesis, subscribing to
    /// it with a round and the genesis digest will cause it to never resolve.
    genesis_block: Arc<Block>,

    /// The channel over which the agent will receive new commands from the
    /// execution driver.
    mailbox: UnboundedReceiver<Message>,

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

impl Executor {
    pub(super) fn mailbox(&self) -> &ExecutorMailbox {
        &self.my_mailbox
    }

    pub(super) async fn run(mut self) {
        while let Some(msg) = self.mailbox.next().await {
            // XXX: finalizations must happen strictly sequentially, so blocking
            // the event loop is desired.
            // TODO: also listen to shutdown signals from the runtime here.
            self.handle_message(msg).await;
        }
    }

    async fn handle_message(&mut self, message: Message) {
        let cause = message.cause;
        match message.command {
            Command::Backfill { round, digest } => {
                let _ = self.backfill(cause, round, digest).await;
            }
            Command::Canonicalize { round, digest } => {
                let _ = self.canonicalize(cause, round, digest).await;
            }
            Command::ForwardBlock { block, response } => {
                let _ = self.forward_block(*block, response, cause).await;
            }
        }
    }

    #[instrument(
        skip_all,
        follows_from = [cause],
        fields(
            epoch = round.as_ref().map(Round::epoch),
            view = round.as_ref().map(Round::view),
            %digest,
        ),
        ret,
        err,
    )]
    async fn canonicalize(
        &self,
        cause: Span,
        round: Option<Round>,
        digest: Digest,
    ) -> eyre::Result<PayloadStatus> {
        info!("canonicalizing");
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
            self.my_mailbox
                .backfill(round, digest)
                .expect("mailbox must be open because this was called from inside the actor");
        }

        Ok(fcu_response.payload_status)
    }

    /// Attempts to backfill a block by reading its `digest` from the consensus layer.
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
    async fn backfill(
        &mut self,
        cause: Span,
        round: Option<Round>,
        digest: Digest,
    ) -> eyre::Result<()> {
        if digest == self.genesis_block.digest() {
            info!("genesis digest supplied; stopping backfill");
            return Ok(());
        }

        let block = self
            .marshal
            .subscribe(round, digest)
            .await
            .await
            .wrap_err("consensus layer did not have block")?;

        let height = block.height();
        let parent = block.parent();

        // XXX: last_block_number returns that block number that is guaranteed
        // to exist in the execution layer's database.
        let last_execution_height = self
            .execution_node
            .provider
            .last_block_number()
            .wrap_err("failed querying execution layer for its last block number")?;

        self.my_mailbox
            .forward_block(block)
            .expect("mailbox must be open because this was called from inside the actor");

        if height.saturating_sub(1) > last_execution_height {
            info!(
                last_execution_height,
                "reached the last block number of the execution layer; aborting backfill"
            );
            self.my_mailbox
                .backfill(None, parent)
                .expect("mailbox must be open because this was called from inside the actor");
        }
        Ok(())
    }

    /// Finalizes `block` by sending it to the execution layer.
    ///
    /// If `response` is set, a successful finalization will be acknowledged
    /// on that channel. `response` is also taken as the indicator for when
    /// `block` is at the tip of the finalized chain. If is set, then the
    /// block's digest will be taken as the latest finalized block. If it is
    /// not set, then the block is assumed to be an older backfilled one.
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
    inner: UnboundedSender<Message>,
}

impl ExecutorMailbox {
    fn backfill(&self, round: Option<Round>, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Backfill { round, digest },
            })
            .wrap_err("failed sending backfill request to finalizer, this means it exited")
    }

    /// Instructs the agent to update the canonical chain to `digest`.
    pub(super) fn canonicalize(&self, round: Option<Round>, digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Canonicalize { round, digest },
            })
            .wrap_err("failed sending canonicalize request to agent, this means it exited")
    }

    /// Instructs the agent to forward a finalized block to the execution layer.
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

    /// Instructs the agent to forward a finalized block to the execution layer.
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
    Backfill {
        round: Option<Round>,
        digest: Digest,
    },
    Canonicalize {
        round: Option<Round>,
        digest: Digest,
    },
    /// Commands the canonical chain engine to forward a finalized block to
    /// the execution layer.
    ///
    /// The response channel is set if the finalized block is new (i.e. at the
    /// tip of the finalized chain).
    ForwardBlock {
        block: Box<Block>,
        response: Option<oneshot::Sender<()>>,
    },
}
