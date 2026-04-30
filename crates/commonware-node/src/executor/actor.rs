//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::{ops::RangeInclusive, pin::Pin, sync::Arc, time::Duration};

use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_consensus::{Heightable as _, marshal::Update, types::Height};

use commonware_runtime::{
    Clock, ContextCell, FutureExt, Handle, Metrics, Pacer, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::{BoxFuture, Ready, ready},
    stream::FuturesOrdered,
};
use reth_ethereum::{chainspec::EthChainSpec, rpc::eth::primitives::BlockNumHash};
use reth_provider::BlockNumReader as _;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::TempoPayloadAttributes;
use tokio::select;
use tracing::{
    Level, Span, debug, error, error_span, info, info_span, instrument, warn, warn_span,
};

use super::{
    Config,
    ingress::{CanonicalizeHead, Command, Message},
};
use crate::{
    consensus::{Digest, block::Block},
    executor::ingress::CanonicalizeAndBuild,
    utils::OptionFuture,
};

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
    /// If `height > self.finalized_height` or `digest` is the same as the finalized block hash,
    /// this method will return a new canonical state with `self.head_height = height` and
    /// `self.forkchoice.head = hash`.
    ///
    /// If `height <= self.finalized_height`, then this method will return
    /// `self` unchanged.
    fn update_head(self, height: Height, digest: Digest) -> Self {
        let mut this = self;
        if height > this.finalized_height || digest.0 == this.forkchoice.finalized_block_hash {
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

    /// Gap between the last finalized block on the consensus and execution
    /// layers. Needs to be handled on startup because the execution layer does
    /// not reliably flush all blocks.
    finalized_heights_to_backfill: RangeInclusive<u64>,

    /// Backfills that are currently in-flight and are awaiting resolution.
    pending_backfill: OptionFuture<BoxFuture<'static, (u64, Option<Block>)>>,

    /// Blocks received from the marshal actor that are awaiting execution and
    /// acknowledgement. FuturesOrdered because it is nicer to use as a stream
    /// in a select-loop.
    pending_finalizations: FuturesOrdered<Ready<(Span, Block, Exact)>>,

    latest_observed_finalized_tip: Option<(Height, Digest)>,
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

        let canonical_state = execution_node.provider.canonical_in_memory_state();
        let finalized_num_hash = canonical_state
            .get_finalized_num_hash()
            .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));
        let head_num_hash: BlockNumHash = canonical_state.chain_info().into();

        let fcu_heartbeat_timer = Box::pin(context.sleep(fcu_heartbeat_interval));
        let finalized_heights_to_backfill =
            (last_execution_finalized_height + 1)..=last_finalized_height.get();
        let last_execution_finalized_height = Height::new(last_execution_finalized_height);
        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            last_consensus_finalized_height: last_finalized_height,
            last_execution_finalized_height,
            mailbox,
            marshal,
            last_canonicalized: LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: head_num_hash.hash,
                    safe_block_hash: finalized_num_hash.hash,
                    finalized_block_hash: finalized_num_hash.hash,
                },
                head_height: Height::new(head_num_hash.number),
                finalized_height: Height::new(finalized_num_hash.number),
            },
            fcu_heartbeat_interval,
            fcu_heartbeat_timer,

            finalized_heights_to_backfill,
            pending_backfill: OptionFuture::none(),
            pending_finalizations: FuturesOrdered::new(),

            latest_observed_finalized_tip: None,
        })
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
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

        loop {
            if self.pending_backfill.is_none()
                && let Some(height) = self.finalized_heights_to_backfill.next()
            {
                self.pending_backfill.replace({
                    let marshal = self.marshal.clone();
                    async move { (height, marshal.get_block(Height::new(height)).await) }.boxed()
                });
            }

            let finalized_tip_has_moved =
                self.latest_observed_finalized_tip
                    .is_some_and(|(height, digest)| {
                        self.last_canonicalized
                            != self.last_canonicalized.update_finalized(height, digest)
                    });

            select! {
                biased;

                // Complete all backfills first.
                block = &mut self.pending_backfill => {
                    match block {
                        (height, Some(block)) => {
                            let (ack, _wait) = Exact::handle();
                            let span = info_span!("backfill_on_start", %height);
                            let _ = self.forward_finalized(
                                span,
                                block,
                                ack,
                            ).await;
                        }
                        (height, None) => {
                            warn_span!("backfill_on_start", %height)
                            .in_scope(|| warn!(
                                "marshal actor did not have block even though \
                                it must have finalized it previously",
                            ));
                        }
                    }
                }

                // Then forward all finalizations.
                Some((cause, block, ack)) = self.pending_finalizations.next()
                , if self.pending_backfill.is_none()
                => {
                    // Error is emitted on function return.
                    if let Err(error) = self.forward_finalized(cause, block, ack).await
                    {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor encountered fatal fork choice update error; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
                    }
                }

                // Update the finalized tip if it has moved.
                Some((height, digest)) = ready(self.latest_observed_finalized_tip)
                , if finalized_tip_has_moved
                && self.pending_backfill.is_none()
                => {
                    let (response, _rx) = oneshot::channel();
                    self.canonicalize(
                        Span::current(),
                        HeadOrFinalized::Finalized,
                        height,
                        digest,
                        JustCanonicalizeOrAlsoBuild::JustCanonicalize { response },
                    )
                    .await;
                }

                // Serve requests lasts.
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
            .fork_choice_updated(self.last_canonicalized.forkchoice, None)
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
        let is_backfilling =
            self.pending_backfill.is_some() || !self.finalized_heights_to_backfill.is_empty();
        match message.command {
            Command::CanonicalizeHead(..) | Command::CanonicalizeAndBuild(..) if is_backfilling => {
                info_span!("handle_message")
                    .in_scope(|| info!("request to canonicalize dropped while backfilling"));
            }
            Command::CanonicalizeHead(CanonicalizeHead {
                height,
                digest,
                response,
            }) => {
                self.canonicalize(
                    cause,
                    HeadOrFinalized::Head,
                    height,
                    digest,
                    JustCanonicalizeOrAlsoBuild::JustCanonicalize { response },
                )
                .await;
            }
            Command::CanonicalizeAndBuild(CanonicalizeAndBuild {
                height,
                digest,
                attributes,
                response,
            }) => {
                self.canonicalize(
                    cause,
                    HeadOrFinalized::Head,
                    height,
                    digest,
                    JustCanonicalizeOrAlsoBuild::AlsoBuild {
                        response,
                        attributes: Box::new(*attributes),
                    },
                )
                .await;
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(_, height, digest) => {
                    self.latest_observed_finalized_tip.replace((height, digest));
                }
                Update::Block(block, acknowledgement) => {
                    self.pending_finalizations
                        .push_back(ready((cause, block, acknowledgement)));
                }
            },
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
    )]
    async fn canonicalize(
        &mut self,
        cause: Span,
        head_or_finalized: HeadOrFinalized,
        height: Height,
        digest: Digest,
        maybe_build: JustCanonicalizeOrAlsoBuild,
    ) {
        let new_canonicalized = match head_or_finalized {
            HeadOrFinalized::Head => self.last_canonicalized.update_head(height, digest),
            HeadOrFinalized::Finalized => self.last_canonicalized.update_finalized(height, digest),
        };

        if new_canonicalized == self.last_canonicalized
            && let JustCanonicalizeOrAlsoBuild::JustCanonicalize { response } = maybe_build
        {
            info!("would not change forkchoice state; not sending it to the execution layer");
            let _ = response.send(Ok(()));
            return;
        }

        info!(
            head_block_hash = %new_canonicalized.forkchoice.head_block_hash,
            head_block_height = %new_canonicalized.head_height,
            finalized_block_hash = %new_canonicalized.forkchoice.finalized_block_hash,
            finalized_block_height = %new_canonicalized.finalized_height,
            "sending forkchoice-update",
        );
        let fcu_response = match self
            .execution_node
            .add_ons_handle
            .beacon_engine_handle
            .fork_choice_updated(
                new_canonicalized.forkchoice,
                maybe_build.attributes().cloned(),
            )
            .pace(&self.context, Duration::from_millis(20))
            .await
            .wrap_err("failed requesting execution layer to update forkchoice state")
        {
            Err(error) => {
                maybe_build.send_error(error);
                return;
            }
            Ok(response) => response,
        };

        debug!(
            payload_status = %fcu_response.payload_status,
            "execution layer reported FCU status",
        );

        if fcu_response.is_invalid() {
            maybe_build.send_error(
                Report::msg(fcu_response.payload_status)
                    .wrap_err("execution layer responded with error for forkchoice-update"),
            );
            return;
        }

        match maybe_build {
            JustCanonicalizeOrAlsoBuild::JustCanonicalize { response } => {
                let _ = response.send(Ok(()));
            }
            JustCanonicalizeOrAlsoBuild::AlsoBuild { response, .. } => {
                if let Some(payload_id) = fcu_response.payload_id {
                    let _ = response.send(Ok(payload_id));
                }
            }
        }
        self.last_canonicalized = new_canonicalized;
        self.reset_fcu_heartbeat_timer();
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
        let (response, rx) = oneshot::channel();
        self.canonicalize(
            Span::current(),
            HeadOrFinalized::Finalized,
            block.height(),
            block.digest(),
            JustCanonicalizeOrAlsoBuild::JustCanonicalize { response },
        )
        .await;
        rx.await
            .wrap_err("executor dropped channel")
            .and_then(|res| res)?;

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

        Ok(())
    }
}

/// Controls canonicalization: if attributes are sent, the FCU also builds a payload.
enum JustCanonicalizeOrAlsoBuild {
    JustCanonicalize {
        response: oneshot::Sender<eyre::Result<()>>,
    },
    AlsoBuild {
        response: oneshot::Sender<eyre::Result<PayloadId>>,
        attributes: Box<TempoPayloadAttributes>,
    },
}

impl JustCanonicalizeOrAlsoBuild {
    fn attributes(&self) -> Option<&TempoPayloadAttributes> {
        match self {
            Self::JustCanonicalize { .. } => None,
            Self::AlsoBuild { attributes, .. } => Some(attributes),
        }
    }
    fn send_error(self, error: eyre::Report) {
        match self {
            Self::JustCanonicalize { response } => {
                let _ = response.send(Err(error));
            }
            Self::AlsoBuild { response, .. } => {
                let _ = response.send(Err(error));
            }
        }
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
