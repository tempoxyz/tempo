//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.
//!
//! If the agent detects that the execution layer is missing blocks it attempts
//! to backfill them from the consensus layer.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{Block as _, marshal::Update};

use commonware_macros::select;
use commonware_runtime::{ContextCell, FutureExt, Handle, Metrics, Pacer, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure, eyre};
use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
};
use reth_provider::BlockNumReader as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{Level, Span, debug, info, instrument, warn};

use crate::consensus::{Digest, block::Block};

pub(super) struct Builder {
    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    pub(super) execution_node: TempoFullNode,

    /// The genesis block of the network. Used to populate fields on
    /// the send the initial forkchoice state.
    pub(super) genesis_block: Arc<Block>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    pub(super) marshal: crate::alias::marshal::Mailbox,
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
            marshal,
        } = self;

        let (to_me, from_app) = mpsc::unbounded();

        let my_mailbox = ExecutorMailbox { inner: to_me };

        let genesis_hash = genesis_block.block_hash();
        Executor {
            context: ContextCell::new(context),
            execution_node,
            mailbox: from_app,
            marshal,
            my_mailbox,
            last_canonicalized: LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: genesis_hash,
                    safe_block_hash: genesis_hash,
                    finalized_block_hash: genesis_hash,
                },
                head_height: 0,
                finalized_height: 0,
            },
        }
    }
}

/// Tracks the last forkchoice state that the executor sent to the execution layer.
///
/// Also tracks the corresponding heights corresponding to
/// `forkchoice_state.head_block_hash` and
/// `forkchoice_state.finalized_block_hash`, respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LastCanonicalized {
    forkchoice: ForkchoiceState,
    head_height: u64,
    finalized_height: u64,
}

impl LastCanonicalized {
    /// Updates the finalized height and finalized block hash to `height` and `hash`.
    ///
    /// `height` must be ahead of the latest canonicalized finalized height. If
    /// it is not, then this is a no-op.
    ///
    /// Similarly, if `height` is ahead or the same as the latest canonicalized
    /// head height, it also updates the head height.
    ///
    /// This is to ensure that the finalized block hash is never ahead of the
    /// head hash.
    fn update_finalized(self, height: u64, hash: B256) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.finalized_height = height;
            this.forkchoice.safe_block_hash = hash;
            this.forkchoice.finalized_block_hash = hash;
        }
        if height >= this.head_height {
            this.head_height = height;
            this.forkchoice.head_block_hash = hash;
        }
        this
    }

    /// Updates the head height and head block hash to `height` and `hash`.
    ///
    /// If `height > self.finalized_height`, this method will return a new
    /// canonical state with `self.head_height = height` and
    /// `self.forkchoice.head = hash`.
    ///
    /// If `height <= self.finalized_height`, then this method will return
    /// `self` unchanged.
    fn update_head(self, height: u64, hash: B256) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.head_height = height;
            this.forkchoice.head_block_hash = hash;
        }
        this
    }
}

pub(super) struct Executor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TempoFullNode,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: crate::alias::marshal::Mailbox,

    /// The mailbox passed to other parts of the system to forward messages to
    /// the agent.
    my_mailbox: ExecutorMailbox,

    last_canonicalized: LastCanonicalized,
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
            Command::CanonicalizeHead { height, digest, tx } => {
                let _ = self
                    .canonicalize(cause, HeadOrFinalized::Head, height, digest, tx)
                    .await;
            }
            Command::Finalize(finalized) => {
                let _ = self.finalize(cause, *finalized).await;
            }
        }
    }

    /// Canonicalizes `digest` by sending a forkchoice update to the execution layer.
    #[instrument(
        skip_all,
        follows_from = [cause],
        fields(
            head.height = height,
            head.digest = %digest,
            %head_or_finalized,
        ),
        err,
    )]
    async fn canonicalize(
        &mut self,
        cause: Span,
        head_or_finalized: HeadOrFinalized,
        height: u64,
        digest: Digest,
        ack: oneshot::Sender<()>,
    ) -> eyre::Result<()> {
        let new_canonicalized = match head_or_finalized {
            HeadOrFinalized::Head => self.last_canonicalized.update_head(height, digest.0),
            HeadOrFinalized::Finalized => {
                self.last_canonicalized.update_finalized(height, digest.0)
            }
        };

        if new_canonicalized == self.last_canonicalized {
            info!("would not change forkchoice state; not sending it to the execution layer");
            let _ = ack.send(());
            return Ok(());
        }

        info!(
            head_block_hash = %new_canonicalized.forkchoice.head_block_hash,
            head_block_height = new_canonicalized.head_height,
            finalized_block_hash = %new_canonicalized.forkchoice.finalized_block_hash,
            finalized_block_height = new_canonicalized.finalized_height,
            "sending forkchoice-update",
        );
        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                new_canonicalized.forkchoice,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .pace(&self.context, Duration::from_millis(20))
            .await
            .wrap_err("failed requesting execution layer to update forkchoice state")?;

        debug!(
            payload_status = %fcu_response.payload_status,
            "execution layer reported FCU status",
        );

        if fcu_response.is_invalid() {
            return Err(Report::msg(fcu_response.payload_status)
                .wrap_err("execution layer responded with error for forkchoice-update"));
        }

        let _ = ack.send(());
        self.last_canonicalized = new_canonicalized;

        Ok(())
    }

    #[instrument(parent = &cause, skip_all)]
    /// Handles finalization events.
    async fn finalize(&mut self, cause: Span, finalized: super::ingress::Finalized) {
        match finalized.inner {
            Update::Tip(height, digest) => {
                let _: Result<_, _> = self
                    .canonicalize(
                        Span::current(),
                        HeadOrFinalized::Finalized,
                        height,
                        digest,
                        oneshot::channel().0,
                    )
                    .await;
            }
            Update::Block(block, acknowledgment) => {
                let _: Result<_, _> = self
                    .forward_finalized(Span::current(), block, acknowledgment)
                    .await;
            }
        }
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
        parent = &cause,
        fields(
            block.digest = %block.digest(),
            block.height = block.height(),
        ),
        err(level = Level::WARN),
        ret,
    )]
    async fn forward_finalized(
        &mut self,
        cause: Span,
        block: Block,
        acknowledgment: Exact,
    ) -> eyre::Result<()> {
        if let Err(error) = self
            .canonicalize(
                Span::current(),
                HeadOrFinalized::Finalized,
                block.height(),
                block.digest(),
                oneshot::channel().0,
            )
            .await
        {
            warn!(
                %error,
                "failed canonicalizing finalized block; will still attempt \
                forwarding it to the execution layer",
            );
        }

        if let Ok(execution_height) = self
            .execution_node
            .provider
            .last_block_number()
            .map_err(Report::new)
            .inspect_err(|error| {
                warn!(
                    %error,
                    "failed getting last finalized block from execution layer, will \
                    finalize forward block to execution layer without extra checks, \
                    but it might fail"
                )
            })
            && execution_height + 1 < block.height()
        {
            info!(
                execution.finalized_height = execution_height,
                "hole detected; consensus attempts to finalize block with gaps \
                on the execution layer; filling them in first",
            );
            let _ = self.fill_holes(execution_height + 1, block.height()).await;
        }

        let block = block.into_inner();
        let payload_status = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData {
                block,
                // can be omitted for finalized blocks
                validator_set: None,
            })
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

        acknowledgment.acknowledge();

        Ok(())
    }

    /// Reads all blocks heights `from..to` and forwards them to the execution layer.
    #[instrument(
        skip_all,
        fields(from, to),
        err(level = Level::WARN),
    )]
    async fn fill_holes(&mut self, from: u64, to: u64) -> eyre::Result<()> {
        ensure!(from <= to, "backfill range is negative");

        for height in from..to {
            let block = self.marshal.get_block(height).await.ok_or_else(|| {
                eyre!(
                    "marshal actor does not know about block `{height}`, but \
                    this function expects that it has all blocks in the provided \
                    range",
                )
            })?;

            let digest = block.digest();

            let payload_status = self
                .execution_node
                .add_ons_handle
                .beacon_engine_handle
                .new_payload(TempoExecutionData {
                    block: block.into_inner(),
                    // can be omitted for finalized blocks
                    validator_set: None,
                })
                .pace(&self.context, Duration::from_millis(20))
                .await
                .wrap_err(
                    "failed sending new-payload request to execution engine to \
                    query payload status of finalized block",
                )?;

            ensure!(
                payload_status.is_valid() || payload_status.is_syncing(),
                "this is a problem: payload status of block `{digest}` we are \
                trying to backfill is neither valid nor syncing: \
                `{payload_status}`"
            );
        }
        Ok(())
    }
}

/// Marker to indicate whether the head hash or finalized hash should be updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeadOrFinalized {
    Head,
    Finalized,
}

impl std::fmt::Display for HeadOrFinalized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::Head => "head",
            Self::Finalized => "finalized",
        };
        f.write_str(msg)
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExecutorMailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl ExecutorMailbox {
    /// Requests the agent to update the head of the canonical chain to `digest`.
    pub(super) fn canonicalize_head(
        &self,
        height: u64,
        digest: Digest,
    ) -> eyre::Result<oneshot::Receiver<()>> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::CanonicalizeHead { height, digest, tx },
            })
            .wrap_err("failed sending canonicalize request to agent, this means it exited")?;

        Ok(rx)
    }

    /// Requests the agent to forward a `finalized` block to the execution layer.
    pub(super) fn forward_finalized(
        &self,
        finalized: super::ingress::Finalized,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Finalize(finalized.into()),
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
    /// Requests the agent to set the head of the canonical chain to `digest`.
    CanonicalizeHead {
        height: u64,
        digest: Digest,
        tx: oneshot::Sender<()>,
    },
    /// Requests the agent to forward a finalization event to the execution layer.
    Finalize(Box<super::ingress::Finalized>),
}
