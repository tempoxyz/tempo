//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.
//!
//! If the agent detects that the execution layer is missing blocks it attempts
//! to backfill them from the consensus layer.

use std::{sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{Block as _, marshal::ingress::mailbox::Identifier};

use commonware_macros::select;
use commonware_runtime::{ContextCell, FutureExt, Handle, Metrics, Pacer, Spawner, spawn_cell};
use eyre::{WrapErr as _, bail, ensure, eyre};
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

    /// The genesis block of the network. This is critically important when
    /// backfilling: since marshal does not know about genesis, subscribing to
    /// it with a round and the genesis digest will cause it to never resolve.
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

        Executor {
            context: ContextCell::new(context),
            execution_node,
            genesis_block,
            mailbox: from_app,
            marshal,
            my_mailbox,
            last_canonicalized: None,
        }
    }
}

#[derive(Debug, Clone)]
struct LastCanonicalized {
    forkchoice: ForkchoiceState,
    head_height: u64,
    finalized_height: u64,
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
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: crate::alias::marshal::Mailbox,

    /// The mailbox passed to other parts of the system to forward messages to
    /// the agent.
    my_mailbox: ExecutorMailbox,

    last_canonicalized: Option<LastCanonicalized>,
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
        // XXX: `run_pre_event_loop_init` is emitting an error event on failure.
        if self.run_pre_event_loop_init().await.is_err() {
            return;
        };

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

    #[instrument(skip_all, err)]
    async fn run_pre_event_loop_init(&mut self) -> eyre::Result<()> {
        let (finalized_consensus_height, finalized_consensus_digest) = self
            .marshal
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

        self.canonicalize(
            Span::current(),
            (finalized_consensus_height, finalized_consensus_digest),
            (finalized_consensus_height, finalized_consensus_digest),
        )
        .await
        .wrap_err("failed setting initial canonical state; can't go on like this")?;

        let latest_execution_block_number =
            self.execution_node.provider.last_block_number().wrap_err(
                "failed getting last block number from execution layer; cannot \
                continue without it",
            )?;

        if latest_execution_block_number == finalized_consensus_height {
            info!(
                finalized_consensus_height,
                %finalized_consensus_digest,
                "consensus and execution layers are at the same height; can \
                enter event loop now",
            );
        } else if finalized_consensus_height > latest_execution_block_number {
            info!(
                latest_execution_block_number,
                finalized_consensus_height,
                %finalized_consensus_digest,
                "consensus and execution layers reported different heights; \
                catching up the execution layer",
            );
            self.backfill(
                latest_execution_block_number.saturating_add(1),
                latest_execution_block_number,
            )
            .await
            .wrap_err(
                "backfilling from consensus layer to execution layer \
                failed; cannot recover from that",
            )?;
        } else {
            bail!(
                "execution layer is ahead of consensus layer; cannot deal \
                with that; \
                execution_height: `{latest_execution_block_number}`, \
                consensus_height: `{finalized_consensus_height}`"
            );
        }
        Ok(())
    }

    async fn handle_message(&mut self, message: Message) {
        let cause = message.cause;
        match message.command {
            Command::Canonicalize { head, finalized } => {
                let _ = self.canonicalize(cause, head, finalized).await;
            }
            Command::ForwardFinalized { block, response } => {
                let _ = self.forward_finalized(*block, response, cause).await;
            }
        }
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
            head.height = head.0,
            head.digest = %head.1,
            finalized.height = finalized.0,
            finalized.digest = %finalized.1,
        ),
        err,
    )]
    async fn canonicalize(
        &mut self,
        cause: Span,
        head: (u64, Digest),
        finalized: (u64, Digest),
    ) -> eyre::Result<()> {
        assert!(
            head.0 >= finalized.0,
            "invariant violated: finalized head must never exceed tip",
        );

        // Compare with the last send forkchoice state: if either head or
        // finalized are newer, don't update the other.
        let last_canonicalized = match &self.last_canonicalized {
            None => LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: head.1.0,
                    safe_block_hash: finalized.1.0,
                    finalized_block_hash: finalized.1.0,
                },
                head_height: head.0,
                finalized_height: finalized.0,
            },
            Some(last_canonicalized) => {
                // Only take the new finalized hash if the head is higher.
                // Reason: the finalized hash must not change.
                let (finalized_height, finalized_block_hash) =
                    if finalized.0 > last_canonicalized.finalized_height {
                        (finalized.0, finalized.1.0)
                    } else {
                        (
                            last_canonicalized.finalized_height,
                            last_canonicalized.forkchoice.finalized_block_hash,
                        )
                    };

                // Take the head hash if the height is higher or the same.
                // Reason: the head hash is allowed to change.
                let (head_height, head_block_hash) = if head.0 >= last_canonicalized.head_height {
                    (head.0, head.1.0)
                } else {
                    (
                        last_canonicalized.head_height,
                        last_canonicalized.forkchoice.head_block_hash,
                    )
                };

                LastCanonicalized {
                    forkchoice: ForkchoiceState {
                        head_block_hash,
                        safe_block_hash: finalized_block_hash,
                        finalized_block_hash,
                    },
                    head_height,
                    finalized_height,
                }
            }
        };

        info!(
            head_block_hash = %last_canonicalized.forkchoice.head_block_hash,
            head_block_height = last_canonicalized.head_height,
            finalized_block_hash = %last_canonicalized.forkchoice.finalized_block_hash,
            finalized_block_height = last_canonicalized.finalized_height,
            "sending forkchoice-update",
        );
        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                last_canonicalized.forkchoice,
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
            return Err(eyre::Report::msg(fcu_response.payload_status)
                .wrap_err("execution layer responded with error for forkchoice-update"));
        }

        self.last_canonicalized.replace(last_canonicalized);

        Ok(())
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
        fields(block.digest = %block.digest()),
        err(level = Level::WARN),
        ret,
    )]
    async fn forward_finalized(
        &mut self,
        block: Block,
        response: oneshot::Sender<()>,
        cause: Span,
    ) -> eyre::Result<()> {
        let LastCanonicalized {
            forkchoice,
            head_height,
            finalized_height,
        } = self
            .last_canonicalized
            .clone()
            .expect("must always be set in the event loop handlers");

        // If we get a finalized block ahead of the last finalized hash sent to
        // the executionl layer, canonicalize the finalized hash.
        //
        // If the finalized block is also ahead of the head hash, then also
        // update that.
        if block.height() > finalized_height {
            let finalized = (block.height(), block.digest());
            let head = if finalized.0 > head_height {
                finalized
            } else {
                (head_height, Digest(forkchoice.head_block_hash))
            };
            self.canonicalize(Span::current(), head, finalized)
                .await
                .wrap_err("failed canonicalizing finalized block")?;
        }

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

        if let Err(()) = response.send(()) {
            warn!("tried acknowledging finalization but channel was already closed");
        }

        Ok(())
    }

    /// Reads all blocks heights `from..=to` and forwards them to the execution layer.
    #[instrument(
        skip_all,
        fields(from, to),
        err(level = Level::WARN),
    )]
    async fn backfill(&mut self, from: u64, to: u64) -> eyre::Result<()> {
        ensure!(from <= to, "backfill range is negative");

        for height in from..=to {
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
                .new_payload(TempoExecutionData(block.into_inner()))
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

#[derive(Clone, Debug)]
pub(super) struct ExecutorMailbox {
    inner: mpsc::UnboundedSender<Message>,
}

impl ExecutorMailbox {
    /// Requests the agent to update the canonical chain to `digest`.
    ///
    /// Of `round` is set, the agent will also attempt to backfill the ancestors
    /// of `digest`.
    pub(super) fn canonicalize(
        &self,
        head: (u64, Digest),
        finalized: (u64, Digest),
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::Canonicalize { head, finalized },
            })
            .wrap_err("failed sending canonicalize request to agent, this means it exited")
    }

    /// Requests the agent to forward a `finalized` block to the execution layer.
    pub(super) fn forward_finalized(
        &self,
        finalized: super::ingress::Finalized,
    ) -> eyre::Result<()> {
        self.inner
            .unbounded_send(Message {
                cause: Span::current(),
                command: Command::ForwardFinalized {
                    block: Box::new(finalized.block),
                    response: finalized.response,
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
    /// Requests the agent to canonicalize `digest`.
    ///
    /// This variant is used by the `ExecutorMailbox::canonicalize` method.
    /// If `round` information is set the agent will attempt to backfill
    /// `digest` and ancestors to the execution layer.
    Canonicalize {
        head: (u64, Digest),
        finalized: (u64, Digest),
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
    ForwardFinalized {
        block: Box<Block>,
        response: oneshot::Sender<()>,
    },
}
