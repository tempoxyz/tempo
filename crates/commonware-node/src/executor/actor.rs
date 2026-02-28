//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::{collections::BTreeMap, pin::Pin, sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
use commonware_consensus::{Heightable as _, marshal::Update, types::Height};

use commonware_runtime::{
    Clock, ContextCell, FutureExt, Handle, Metrics, Pacer, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{OptionExt as _, Report, WrapErr as _, ensure};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    select_biased,
};
use reth_provider::{BlockHashReader, BlockNumReader as _};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tracing::{
    Level, Span, debug, error, error_span, info, info_span, instrument, warn, warn_span,
};

use super::{
    Config,
    ingress::{CanonicalizeHead, Command, Message, SubscribeFinalized},
};
use crate::consensus::{Digest, block::Block};

/// Tracks the last forkchoice state that the executor sent to the execution layer.
///
/// Also tracks the corresponding heights corresponding to
/// `forkchoice_state.head_block_hash` and
/// `forkchoice_state.finalized_block_hash`, respectively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LastCanonicalized {
    forkchoice: ForkchoiceState,
    head_height: Height,
    finalized_height: Height,
}

impl LastCanonicalized {
    /// Updates the finalized height and finalized block hash to `height` and `digest`.
    ///
    /// `height` must be ahead of the latest canonicalized finalized height. If
    /// it is not, then this is a no-op.
    ///
    /// Similarly, if `height` is ahead or the same as the latest canonicalized
    /// head height, it also updates the head height.
    ///
    /// This is to ensure that the finalized block hash is never ahead of the
    /// head hash.
    fn update_finalized(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.finalized_height = height;
            this.forkchoice.safe_block_hash = digest.0;
            this.forkchoice.finalized_block_hash = digest.0;
        }
        if height >= this.head_height {
            this.head_height = height;
            this.forkchoice.head_block_hash = digest.0;
        }
        this
    }

    /// Updates the head height and head block hash to `height` and `digest`.
    ///
    /// If `height > self.finalized_height`, this method will return a new
    /// canonical state with `self.head_height = height` and
    /// `self.forkchoice.head = hash`.
    ///
    /// If `height <= self.finalized_height`, then this method will return
    /// `self` unchanged.
    fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height {
            this.head_height = height;
            this.forkchoice.head_block_hash = digest.0;
        }
        this
    }
}

pub(crate) struct Actor<TContext> {
    context: ContextCell<TContext>,

    /// A handle to the execution node layer. Used to forward finalized blocks
    /// and to update the canonical chain by sending forkchoice updates.
    execution_node: TempoFullNode,

    last_consensus_finalized_height: Height,
    last_execution_finalized_height: Height,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: crate::alias::marshal::Mailbox,

    last_canonicalized: LastCanonicalized,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    fcu_heartbeat_interval: Duration,

    /// The timer for the next FCU heartbeat. Reset whenever an FCU is sent.
    fcu_heartbeat_timer: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,

    /// A list of subscriptions waiting for the executor to finalize a block
    /// at a given height.
    pending_finalized_subscriptions: BTreeMap<Height, Vec<oneshot::Sender<()>>>,
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + Metrics + Pacer + Spawner,
{
    pub(super) fn init(
        context: TContext,
        config: super::Config,
        mailbox: UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let Config {
            execution_node,
            last_finalized_height,
            marshal,
            fcu_heartbeat_interval,
        } = config;
        let last_execution_finalized_height = execution_node
            .provider
            .last_block_number()
            .wrap_err("unable to read latest block number from execution layer")?;
        let last_finalized_block_hash = execution_node
            .provider
            .block_hash(last_execution_finalized_height)
            .map_or_else(
                |e| Err(Report::new(e)),
                |hash| hash.ok_or_eyre("execution layer does not have the block hash"),
            )
            .wrap_err("failed to read the last finalized block hash")?;
        let fcu_heartbeat_timer = Box::pin(context.sleep(fcu_heartbeat_interval));
        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            last_consensus_finalized_height: last_finalized_height,
            last_execution_finalized_height: Height::new(last_execution_finalized_height),
            mailbox,
            marshal,
            last_canonicalized: LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: last_finalized_block_hash,
                    safe_block_hash: last_finalized_block_hash,
                    finalized_block_hash: last_finalized_block_hash,
                },
                head_height: Height::zero(),
                finalized_height: Height::zero(),
            },
            fcu_heartbeat_interval,
            fcu_heartbeat_timer,
            pending_finalized_subscriptions: BTreeMap::new(),
        })
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        info_span!("start").in_scope(|| {
            info!(
                last_finalized_consensus_height = %self.last_consensus_finalized_height,
                last_finalized_execution_height = %self.last_execution_finalized_height,
                "consensus and execution layers reported last finalized heights; \
                backfilling blocks from consensus to execution if necessary",
            );
        });

        let mut backfill_on_start = {
            let marshal = self.marshal.clone();
            std::pin::pin!(
                futures::stream::iter(
                    self.last_execution_finalized_height.get() + 1
                        ..=self.last_consensus_finalized_height.get(),
                )
                .then(move |height| {
                    let mut marshal = marshal.clone();
                    async move { (height, marshal.get_block(Height::new(height)).await) }
                })
                .fuse()
            )
        };

        loop {
            select_biased! {
                backfill = backfill_on_start.next() => {
                    match backfill {
                        Some((height, Some(block))) => {
                            let (ack, _wait) = Exact::handle();
                            let span = info_span!("backfill_on_start", height);
                            let _ = self.forward_finalized(
                                span,
                                block,
                                ack,
                            ).await;
                        }
                        Some((height, None)) => {
                            warn_span!("backfill_on_start", height)
                            .in_scope(|| warn!(
                                "marshal actor did not have block even though \
                                it must have finalized it previously",
                            ));
                        }
                        None => {
                            info_span!("backfill_on_start")
                            .in_scope(|| info!(
                                "no more blocks to backfill from consensus to \
                                execution layer")
                            );
                        }
                    }
                },

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break; };
                    // XXX: updating forkchoice and finalizing blocks must
                    // happen sequentially, so blocking the event loop on await
                    // is desired.
                    //
                    // Backfills will be spawned as tasks and will also send
                    // resolved the blocks to this queue.
                    if let Err(error) = self.handle_message(msg).await {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor encountered fatal fork choice update error; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
                    }
                },

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    self.send_forkchoice_update_heartbeat().await;
                    self.reset_fcu_heartbeat_timer();
                },
            }
        }
    }

    fn reset_fcu_heartbeat_timer(&mut self) {
        self.fcu_heartbeat_timer = Box::pin(self.context.sleep(self.fcu_heartbeat_interval));
    }

    #[instrument(skip_all)]
    async fn send_forkchoice_update_heartbeat(&mut self) {
        info!(
            head_block_hash = %self.last_canonicalized.forkchoice.head_block_hash,
            head_block_height = %self.last_canonicalized.head_height,
            finalized_block_hash = %self.last_canonicalized.forkchoice.finalized_block_hash,
            finalized_block_height = %self.last_canonicalized.finalized_height,
            "sending FCU",
        );

        let fcu_response = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                self.last_canonicalized.forkchoice,
                None,
                reth_node_builder::EngineApiMessageVersion::V3,
            )
            .pace(&self.context, Duration::from_millis(20))
            .await;

        match fcu_response {
            Ok(response) if response.is_invalid() => {
                warn!(
                    payload_status = %response.payload_status,
                    "execution layer reported FCU status",
                );
            }
            Ok(response) => {
                info!(
                    payload_status = %response.payload_status,
                    "execution layer reported FCU status",
                );
            }
            Err(error) => {
                warn!(
                    error = %Report::new(error),
                    "failed sending FCU to execution layer",
                );
            }
        }
    }

    async fn handle_message(&mut self, message: Message) -> eyre::Result<()> {
        let cause = message.cause;
        match message.command {
            Command::CanonicalizeHead(CanonicalizeHead {
                height,
                digest,
                ack,
            }) => {
                // Errors are logged inside canonicalize; head canonicalization failures
                // are non-fatal and will be retried on the next block.
                let _ = self
                    .canonicalize(cause, HeadOrFinalized::Head, height, digest, ack)
                    .await;
            }
            Command::Finalize(finalized) => {
                self.finalize(cause, *finalized)
                    .await
                    .wrap_err("failed handling finalization")?;
            }
            Command::SubscribeFinalized(SubscribeFinalized { height, response }) => {
                if self.last_canonicalized.finalized_height >= height {
                    let _ = response.send(());
                } else {
                    self.pending_finalized_subscriptions
                        .entry(height)
                        .or_default()
                        .push(response);
                }
            }
        }
        Ok(())
    }

    /// Canonicalizes `digest` by sending a forkchoice update to the execution layer.
    #[instrument(
        skip_all,
        parent = &cause,
        fields(
            head.height = %height,
            head.digest = %digest,
            %head_or_finalized,
        ),
        err,
    )]
    async fn canonicalize(
        &mut self,
        cause: Span,
        head_or_finalized: HeadOrFinalized,
        height: Height,
        digest: Digest,
        ack: oneshot::Sender<()>,
    ) -> eyre::Result<()> {
        let new_canonicalized = match head_or_finalized {
            HeadOrFinalized::Head => self.last_canonicalized.update_head(height, digest),
            HeadOrFinalized::Finalized => self.last_canonicalized.update_finalized(height, digest),
        };

        if new_canonicalized == self.last_canonicalized {
            info!("would not change forkchoice state; not sending it to the execution layer");
            let _ = ack.send(());
            return Ok(());
        }

        info!(
            head_block_hash = %new_canonicalized.forkchoice.head_block_hash,
            head_block_height = %new_canonicalized.head_height,
            finalized_block_hash = %new_canonicalized.forkchoice.finalized_block_hash,
            finalized_block_height = %new_canonicalized.finalized_height,
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
        self.reset_fcu_heartbeat_timer();

        Ok(())
    }

    #[instrument(parent = &cause, skip_all)]
    /// Handles finalization events.
    async fn finalize(&mut self, cause: Span, finalized: Update<Block>) -> eyre::Result<()> {
        match finalized {
            Update::Tip(_, height, digest) => {
                self.canonicalize(
                    Span::current(),
                    HeadOrFinalized::Finalized,
                    height,
                    digest,
                    oneshot::channel().0,
                )
                .await
                .wrap_err("failed canonicalizing finalization tip")?;
            }
            Update::Block(block, acknowledgment) => {
                self.forward_finalized(Span::current(), block, acknowledgment)
                    .await
                    .wrap_err("failed forwarding finalized block to execution layer")?;
            }
        }
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
        parent = &cause,
        fields(
            block.digest = %block.digest(),
            block.height = %block.height(),
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
        let height = block.height();
        self.canonicalize(
            Span::current(),
            HeadOrFinalized::Finalized,
            block.height(),
            block.digest(),
            oneshot::channel().0,
        )
        .await
        .wrap_err("failed canonicalizing finalized block")?;

        let block = block.into_inner();
        let payload_status = self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData {
                block: Arc::new(block),
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

        self.pending_finalized_subscriptions.retain(|&key, value| {
            let retain = key > height;
            if !retain {
                value.drain(..).for_each(|tx| {
                    let _ = tx.send(());
                });
            }
            retain
        });

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
