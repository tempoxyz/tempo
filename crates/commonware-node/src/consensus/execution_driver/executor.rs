//! Drives the actual execution by sending finalized blocks and forkchoice updates.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use alloy_rpc_types_engine::{ForkchoiceState, PayloadStatus};
use eyre::{WrapErr as _, ensure};
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures_util::StreamExt as _;
use tempo_commonware_node_cryptography::Digest;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, instrument, warn};

pub(super) struct Builder {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    pub(super) execution_node: TempoFullNode,

    /// The last digest that the consensus layer has finalized. The agent
    /// will send this as the first finalized head to the execution layer.
    pub(super) latest_finalized_digest: Digest,
}

impl Builder {
    /// Constructs the [`Executor`].
    pub(super) fn build(self) -> Executor {
        let Self {
            execution_node,
            latest_finalized_digest,
        } = self;

        let (to_me, from_execution_driver) = futures_channel::mpsc::unbounded();

        let my_mailbox = ExecutorMailbox { inner: to_me };

        // XXX: this ensures that the initial forkchoice-state with
        // head = safe = finalized = latest_finalized is the first thing that
        // the agent sends to the execution layer.
        my_mailbox
            .canonicalize(latest_finalized_digest)
            .expect("our mailbox must work right after construction");

        Executor {
            execution_node,
            mailbox: from_execution_driver,
            latest_finalized_digest,
            my_mailbox,
        }
    }
}

pub(super) struct Executor {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TempoFullNode,

    /// The channel over which the agent will receive new commands from the
    /// execution driver.
    mailbox: UnboundedReceiver<Message>,

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
            Command::Finalize(finalized) => {
                let _ = self.finalize(*finalized, cause).await;
            }
            Command::Update(digest) => {
                let _ = self.update(digest, cause).await;
            }
        }
    }

    #[instrument(
        skip_all,
        follows_from = [cause],
        fields(finalized_block.digest = %finalized.block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    async fn finalize(
        &mut self,
        finalized: super::Finalized,
        cause: tracing::Span,
    ) -> eyre::Result<()> {
        let super::Finalized { block, response } = finalized;

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

        Ok(())
    }

    #[instrument(skip_all, fields(%digest), follows_from = [cause], ret, err)]
    async fn update(&self, digest: Digest, cause: tracing::Span) -> eyre::Result<PayloadStatus> {
        let finalized_block_hash = self.latest_finalized_digest.0;
        let forkchoice_state = ForkchoiceState {
            head_block_hash: digest.0,
            safe_block_hash: finalized_block_hash,
            finalized_block_hash,
        };
        tracing::info!(
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
            Err(eyre::Report::msg(fcu_response.payload_status)
                .wrap_err("execution layer responded with error for forkchoice-update"))
        } else {
            Ok(fcu_response.payload_status)
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExecutorMailbox {
    inner: UnboundedSender<Message>,
}

impl ExecutorMailbox {
    /// Instructs the agent to forward a finalized block to the execution layer.
    pub(super) fn forward_finalized(&self, finalized: super::Finalized) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: tracing::Span::current(),
                command: Command::Finalize(finalized.into()),
            })
            .wrap_err("failed sending finalization request to agent, this means it exited")
    }

    /// Instructs the agent to update the canonical chain to `head_digest`.
    pub(super) fn canonicalize(&self, head_digest: Digest) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: tracing::Span::current(),
                command: Command::Update(head_digest),
            })
            .wrap_err("failed sending update request to agent, this means it exited")
    }
}

#[derive(Debug)]
struct Message {
    cause: tracing::Span,
    command: Command,
}

#[derive(Debug)]
enum Command {
    Finalize(Box<super::Finalized>),
    Update(Digest),
}
