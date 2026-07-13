//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::{collections::VecDeque, sync::Arc, time::Duration};

use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_consensus::{Heightable as _, marshal::Update, types::Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    Clock, ContextCell, FutureExt, Handle, Metrics as RuntimeMetrics, Pacer, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, bail, ensure};
use futures::{
    FutureExt as _, StreamExt as _,
    channel::{
        mpsc::{self, UnboundedReceiver},
        oneshot,
    },
    future::BoxFuture,
    stream::FuturesUnordered,
};
use prometheus_client::metrics::counter::Counter;
use reth_ethereum::{chainspec::EthChainSpec, rpc::eth::primitives::BlockNumHash};
use reth_node_builder::PayloadKind;
use reth_provider::{BlockHashReader as _, BlockIdReader as _, BlockReader as _, BlockSource};
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{Level, Span, debug, error, error_span, info, info_span, instrument, warn};

use super::{
    Config,
    ingress::{CanonicalizeAndBuild, CanonicalizeHead, Command, Message},
};
use crate::{
    consensus::{Digest, block::Block},
    utils::OptionFuture,
};

/// Tracks the latest forkchoice state accepted by the execution layer.
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
    execution_node: Arc<TempoFullNode>,

    /// Highest finalized height the executor should backfill to on startup so
    /// that CL and EL have a consistent view.
    finalized_floor: Height,

    /// The channel over which the agent will receive new commands from the
    /// application actor.
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// The mailbox of the marshal actor. Used to backfill blocks.
    marshal: crate::alias::marshal::Mailbox,

    /// The latest state that the executor canonicalized. On startup, contains
    /// the latest execution layer state.
    last_canonicalized: LastCanonicalized,

    /// The interval at which to send a forkchoice update heartbeat to the
    /// execution layer.
    fcu_heartbeat_interval: Duration,

    /// The timer for the next FCU heartbeat.
    ///
    /// Armed only when no execution request is active or queued.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// Execution-layer requests waiting for the active execution task to finish.
    execution_queue: VecDeque<ExecutionRequest>,
    /// The single execution-layer request currently being driven in the background.
    execution_task: OptionFuture<BoxFuture<'static, ExecutionTaskResult>>,

    /// Payload build jobs currently being driven to completion.
    ///
    /// Each job resolves a payload from the execution layer's payload builder
    /// and delivers it to the subscriber that requested the build. If the
    /// subscriber dropped its receiver in the meantime, the built payload is
    /// discarded.
    payload_jobs: FuturesUnordered<BoxFuture<'static, ()>>,

    latest_observed_finalized_tip: (Height, Digest),

    /// The node's ed25519 public key if the node is participating in
    /// consensus. Not set if not, for example for followers.
    public_key: Option<PublicKey>,

    metrics: Metrics,
}

#[derive(Clone)]
struct Metrics {
    /// Number of finalized blocks whose proposer matches this node's public key.
    finalized_blocks_proposed_by_self: Counter,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: RuntimeMetrics,
    {
        let finalized_blocks_proposed_by_self = Counter::default();
        context.register(
            "finalized_blocks_proposed_by_self",
            "number of finalized blocks whose proposer matches this node's public key",
            finalized_blocks_proposed_by_self.clone(),
        );
        Self {
            finalized_blocks_proposed_by_self,
        }
    }
}

impl<TContext> Actor<TContext>
where
    TContext: Clock + RuntimeMetrics + Pacer + Spawner,
{
    pub(super) fn init(
        context: TContext,
        config: super::Config,
        mailbox: UnboundedReceiver<super::ingress::Message>,
    ) -> eyre::Result<Self> {
        let Config {
            execution_node,
            finalized_floor,
            finalized_tip,
            marshal,
            fcu_heartbeat_interval,
            public_key,
        } = config;
        let metrics = Metrics::init(&context);

        let canonical_state = execution_node.provider.canonical_in_memory_state();

        let head_num_hash: BlockNumHash = canonical_state.chain_info().into();
        let execution_finalized_num_hash = canonical_state
            .get_finalized_num_hash()
            .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));

        Ok(Self {
            context: ContextCell::new(context),
            execution_node,
            finalized_floor,
            mailbox,
            marshal,
            last_canonicalized: LastCanonicalized {
                forkchoice: ForkchoiceState {
                    head_block_hash: head_num_hash.hash,
                    safe_block_hash: execution_finalized_num_hash.hash,
                    finalized_block_hash: execution_finalized_num_hash.hash,
                },
                head_height: Height::new(head_num_hash.number),
                finalized_height: Height::new(execution_finalized_num_hash.number),
            },
            fcu_heartbeat_interval,
            fcu_heartbeat_timer: OptionFuture::none(),
            execution_queue: VecDeque::new(),
            execution_task: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            latest_observed_finalized_tip: finalized_tip,

            public_key,
            metrics,
        })
    }

    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        if let Err(error) = self.backfill_to_finalized_floor().await {
            error_span!("shutdown").in_scope(|| {
                error!(
                    %error,
                    "executor failed startup backfill",
                )
            });
            return;
        }

        info_span!("start").in_scope(|| {
            info!(
                finalized_height = %self.last_canonicalized.finalized_height,
                finalized_digest = %self.last_canonicalized.forkchoice.finalized_block_hash,
                head_height = %self.last_canonicalized.head_height,
                head_digest = %self.last_canonicalized.forkchoice.head_block_hash,
                "entering executor loop",
            );
        });

        loop {
            self.start_next_execution_task();
            self.update_fcu_heartbeat_timer();

            select! {
                biased;

                task_result = &mut self.execution_task => {
                    match task_result {
                        ExecutionTaskResult::Completed { canonicalized, payload_job } => {
                            if let Some(canonicalized) = canonicalized {
                                // There is only one execution task running at
                                // a time, and `last_canonicalized` is only
                                // mutated here to keep a consistent view.
                                self.last_canonicalized = canonicalized;
                            }
                            if let Some(job) = payload_job {
                                self.payload_jobs.push(
                                    run_payload_job(
                                        self.context.clone(),
                                        self.execution_node.clone(),
                                        job,
                                    )
                                    .boxed(),
                                );
                            }
                        }
                        ExecutionTaskResult::Fatal { error } => {
                            error_span!("shutdown").in_scope(|| error!(
                                %error,
                                "executor encountered fatal execution-layer update error; \
                                shutting down to prevent consensus-execution divergence"
                            ));
                            break;
                        }
                    }
                }

                Some(()) = self.payload_jobs.next() => {}

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else { break; };
                    if let Err(error) = self.handle_message(msg) {
                        error_span!("shutdown").in_scope(|| error!(
                            %error,
                            "executor failed handling message; \
                            shutting down to prevent consensus-execution divergence"
                        ));
                        break;
                    }
                },

                _ = (&mut self.fcu_heartbeat_timer).fuse() => {
                    self.send_forkchoice_update_heartbeat();
                },
            }
        }
    }

    async fn backfill_to_finalized_floor(&mut self) -> eyre::Result<()> {
        let start = self.last_canonicalized.finalized_height.get() + 1;
        let end = self.finalized_floor.get();
        let heights = start..=end;
        if !heights.is_empty() {
            info!(
                start = *heights.start(),
                end = *heights.end(),
                "backfilling finalized blocks before entering executor loop"
            );
        }
        for height in heights {
            let span = info_span!("backfill_on_start", %height);
            let block = get_block(
                self.marshal.clone(),
                self.execution_node.clone(),
                Height::new(height),
            )
            .await
            .wrap_err_with(|| format!("failed backfilling block for height `{height}`"))?;

            let (ack, _wait) = Exact::handle();
            let request = FinalizedBlockRequest {
                cause: span,
                block,
                acknowledgment: ack,
            };

            if let Some(canonicalized) = forward_finalized(
                &self.context,
                self.execution_node.clone(),
                self.public_key.clone(),
                self.metrics.clone(),
                self.last_canonicalized,
                request,
            )
            .await
            .wrap_err_with(|| {
                format!(
                    "failed forwarding backfilled finalized block at height `{height}` \
                    to execution layer"
                )
            })? {
                self.last_canonicalized = canonicalized;
            }
        }

        Ok(())
    }

    fn arm_fcu_heartbeat_timer(&mut self) {
        if !self.fcu_heartbeat_timer.is_none() {
            return;
        }
        self.fcu_heartbeat_timer
            .replace(self.context.sleep(self.fcu_heartbeat_interval).boxed());
    }

    fn disarm_fcu_heartbeat_timer(&mut self) {
        self.fcu_heartbeat_timer = OptionFuture::none();
    }

    fn update_fcu_heartbeat_timer(&mut self) {
        if self.execution_task.is_none() && self.execution_queue.is_empty() {
            self.arm_fcu_heartbeat_timer();
        } else {
            self.disarm_fcu_heartbeat_timer();
        }
    }

    #[instrument(skip_all)]
    fn send_forkchoice_update_heartbeat(&mut self) {
        self.enqueue_execution_request(ExecutionRequest::Heartbeat {
            cause: Span::current(),
        });
    }

    fn handle_message(&mut self, message: Message) -> eyre::Result<()> {
        let cause = message.cause;
        match message.command {
            Command::CanonicalizeHead(CanonicalizeHead {
                height,
                digest,
                response,
            }) => {
                self.enqueue_execution_request(ExecutionRequest::Canonicalize(Box::new(
                    Canonicalize {
                        cause,
                        head_or_finalized: HeadOrFinalized::Head,
                        height,
                        digest,
                        response: Some(response),
                        build_attributes: None,
                    },
                )));
            }
            Command::CanonicalizeAndBuild(CanonicalizeAndBuild {
                height,
                digest,
                attributes,
                response,
            }) => {
                self.enqueue_execution_request(ExecutionRequest::Canonicalize(Box::new(
                    Canonicalize {
                        cause,
                        head_or_finalized: HeadOrFinalized::Head,
                        height,
                        digest,
                        response: None,
                        build_attributes: Some((*attributes, response)),
                    },
                )));
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(_, height, digest) => {
                    self.latest_observed_finalized_tip = (height, digest);
                }
                Update::Block(block, acknowledgement) => {
                    self.enqueue_execution_request(ExecutionRequest::FinalizeBlock(Box::new(
                        FinalizedBlockRequest {
                            cause,
                            block,
                            acknowledgment: acknowledgement,
                        },
                    )));
                }
            },
        }
        Ok(())
    }

    fn enqueue_execution_request(&mut self, request: ExecutionRequest) {
        if matches!(&request, ExecutionRequest::Heartbeat { .. })
            && (!self.execution_queue.is_empty() || !self.execution_task.is_none())
        {
            return;
        }

        self.execution_queue.push_back(request);
    }

    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        // If nothing is currently scheduled and a newer finalized tip was
        // observed, push it into the queue so that it will be picked up next.
        if self.execution_queue.is_empty() {
            let (height, digest) = self.latest_observed_finalized_tip;
            let new_canonicalized = self.last_canonicalized.update_finalized(height, digest);
            if new_canonicalized != self.last_canonicalized {
                self.execution_queue
                    .push_back(ExecutionRequest::Canonicalize(Box::new(Canonicalize {
                        cause: Span::current(),
                        head_or_finalized: HeadOrFinalized::Finalized,
                        height,
                        digest,
                        response: None,
                        build_attributes: None,
                    })));
            }
        }

        if self.execution_queue.is_empty() {
            return;
        }
        let request = self.execution_queue.pop_front().expect("front exists");

        let task = execute_request(
            self.context.clone(),
            self.execution_node.clone(),
            self.public_key.clone(),
            self.metrics.clone(),
            self.last_canonicalized,
            request,
        );
        self.execution_task.replace(task.boxed());
    }
}

#[instrument(skip_all, fields(height), err)]
async fn get_block(
    marshal: crate::alias::marshal::Mailbox,
    execution_node: Arc<TempoFullNode>,
    height: Height,
) -> eyre::Result<Block> {
    if let Some(block) = marshal.get_block(height).await {
        return Ok(block);
    }

    warn!(
        "marshal did not have backfill block; looking up its finalized digest \
        to look for it in the execution layer"
    );
    let Some((_, digest)) = marshal.get_info(height).await else {
        bail!("marshal actor did not have finalization info at height");
    };

    info!(
        %digest,
        "found finalized digest for block height; checking execution layer",
    );
    let Some(block) = execution_node
        .provider
        .find_sealed_or_recovered_block(digest.0, BlockSource::Any)
        .wrap_err_with(|| {
            format!("failed querying execution layer for backfill block `{digest}`")
        })?
    else {
        warn!(%digest, "execution layer did not have missing backfill block");
        bail!(
            "marshal actor did not have block at height `{height}` and \
            execution layer did not have block `{digest}`"
        );
    };

    Ok(Block::from_execution_block_unchecked(block, None))
}

enum ExecutionRequest {
    Heartbeat { cause: Span },
    Canonicalize(Box<Canonicalize>),
    FinalizeBlock(Box<FinalizedBlockRequest>),
}

struct FinalizedBlockRequest {
    cause: Span,
    block: Block,
    acknowledgment: Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ForkchoiceUpdateKind {
    Heartbeat,
    Canonicalize { head_or_finalized: HeadOrFinalized },
}

enum ExecutionTaskResult {
    Completed {
        canonicalized: Option<LastCanonicalized>,
        /// A payload build that the forkchoice update kicked off on the
        /// execution layer and that still needs to be driven to completion.
        payload_job: Option<StartPayloadJob>,
    },
    Fatal {
        error: Report,
    },
}

struct Canonicalize {
    cause: Span,
    head_or_finalized: HeadOrFinalized,
    height: Height,
    digest: Digest,
    /// Acknowledges to the requester that the execution layer accepted the
    /// forkchoice update.
    response: Option<oneshot::Sender<()>>,
    /// Payload attributes to register a build job with the forkchoice
    /// update, paired with the subscriber awaiting the built payload.
    build_attributes: Option<(TempoPayloadAttributes, oneshot::Sender<TempoBuiltPayload>)>,
}

/// A payload build registered on the execution layer whose result still needs
/// to be delivered to the subscriber that requested it.
struct StartPayloadJob {
    cause: Span,
    payload_id: PayloadId,
    response: oneshot::Sender<TempoBuiltPayload>,
}

async fn execute_request<TContext>(
    context: ContextCell<TContext>,
    execution_node: Arc<TempoFullNode>,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    canonicalized: LastCanonicalized,
    request: ExecutionRequest,
) -> ExecutionTaskResult
where
    TContext: Pacer,
{
    match request {
        ExecutionRequest::Heartbeat { cause } => {
            if let Err(error) = submit_forkchoice_update(
                &execution_node,
                &context,
                cause,
                canonicalized,
                None,
                ForkchoiceUpdateKind::Heartbeat,
            )
            .await
            {
                warn!(%error, "queued forkchoice update failed");
            }
            ExecutionTaskResult::Completed {
                canonicalized: None,
                payload_job: None,
            }
        }
        ExecutionRequest::Canonicalize(request) => {
            let (canonicalized, payload_job) =
                run_canonicalize_task(&context, execution_node, canonicalized, *request).await;
            ExecutionTaskResult::Completed {
                canonicalized,
                payload_job,
            }
        }
        ExecutionRequest::FinalizeBlock(request) => {
            match forward_finalized(
                &context,
                execution_node,
                public_key,
                metrics,
                canonicalized,
                *request,
            )
            .await
            {
                Ok(canonicalized) => ExecutionTaskResult::Completed {
                    canonicalized,
                    payload_job: None,
                },
                Err(error) => ExecutionTaskResult::Fatal { error },
            }
        }
    }
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        %height,
        %digest,
        head_or_finalized = %head_or_finalized,
    ),
)]
async fn run_canonicalize_task<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    Canonicalize {
        cause,
        head_or_finalized,
        height,
        digest,
        response,
        mut build_attributes,
    }: Canonicalize,
) -> (Option<LastCanonicalized>, Option<StartPayloadJob>) {
    let new_canonicalized = match head_or_finalized {
        HeadOrFinalized::Head => canonicalized.update_head(height, digest),
        HeadOrFinalized::Finalized => canonicalized.update_finalized(height, digest),
    };

    if build_attributes
        .as_ref()
        .is_some_and(|(_, response)| response.is_canceled())
    {
        info!("dropping payload build request: the subscriber went away while it was queued");
        build_attributes.take();
    }

    // Only build on top of the most recent head. If the requested parent
    // could not be made the head (because a block above it was already
    // finalized), the build is stale, and submitting its attributes anyway
    // would register a build on top of the wrong block. Taking the
    // attributes drops the response channel, which signals the failure to
    // the subscriber.
    if build_attributes.is_some() && new_canonicalized.forkchoice.head_block_hash != digest.0 {
        info!("dropping payload build request: its parent cannot be made the head");
        build_attributes.take();
    }

    let (attributes, payload_response) = build_attributes.unzip();

    // The forkchoice update is submitted even if it would not change the
    // forkchoice state: the execution layer treats it as a no-op (the FCU
    // heartbeat relies on this).
    match submit_forkchoice_update(
        &execution_node,
        context,
        cause.clone(),
        new_canonicalized,
        attributes,
        ForkchoiceUpdateKind::Canonicalize { head_or_finalized },
    )
    .await
    {
        Ok(payload_id) => {
            if let Some(response) = response {
                let _ = response.send(());
            }
            let payload_job = match (payload_response, payload_id) {
                (Some(response), Some(payload_id)) => Some(StartPayloadJob {
                    cause,
                    payload_id,
                    response,
                }),
                (Some(_dropped_to_signal_failure), None) => {
                    warn!("execution layer did not return a payload id for the build request");
                    None
                }
                (None, _) => None,
            };
            (Some(new_canonicalized), payload_job)
        }
        Err(error) => {
            // Dropping the response channels signals the failure to the
            // subscribers; the cause is only logged here.
            warn!(%error, "forkchoice update failed");
            (None, None)
        }
    }
}

/// Drives a payload build on the execution layer to completion.
///
/// Resolves the payload registered under `payload_id` from the execution
/// layer's payload builder and delivers it on `response`. If the subscriber
/// goes away before the payload is resolved (for example because the
/// consensus engine cancelled the proposal request that triggered the
/// build), the in-flight resolve future is dropped, which deregisters the
/// build job from the payload builder and aborts the build.
#[instrument(
    skip_all,
    parent = &cause,
    fields(%payload_id),
)]
async fn run_payload_job<TContext: Pacer>(
    context: TContext,
    execution_node: Arc<TempoFullNode>,
    StartPayloadJob {
        cause,
        payload_id,
        mut response,
    }: StartPayloadJob,
) {
    let payload = select! {
        payload = execution_node
            .payload_builder_handle
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .pace(&context, Duration::from_millis(20))
        => payload,

        // Drops the in-flight payload-resolution, killing payload build.
        () = response.cancellation() => {
            info!("payload subscriber went away before the payload was resolved; killing the payload build");
            return;
        }
    };

    // In the failure branches, dropping the response channel signals the
    // failure to the subscriber; the cause is only logged here.
    match payload {
        Some(Ok(payload)) => {
            if response.send(payload).is_err() {
                info!(
                    "payload subscriber went away before the payload could be delivered; discarding it"
                );
            }
        }
        Some(Err(error)) => {
            warn!(
                error = %eyre::Report::new(error),
                "payload build job failed",
            );
        }
        None => {
            warn!("no payload build job found under the payload ID");
        }
    }
}

#[instrument(
    skip_all,
    parent = &cause,
    fields(
        head_block_hash = %canonicalized.forkchoice.head_block_hash,
        head_block_height = %canonicalized.head_height,
        finalized_block_hash = %canonicalized.forkchoice.finalized_block_hash,
        finalized_block_height = %canonicalized.finalized_height,
        ?kind,
    ),
)]
async fn submit_forkchoice_update<TContext: Pacer>(
    execution_node: &TempoFullNode,
    context: &TContext,
    cause: Span,
    canonicalized: LastCanonicalized,
    attrs: Option<TempoPayloadAttributes>,
    kind: ForkchoiceUpdateKind,
) -> eyre::Result<Option<PayloadId>> {
    let fcu_response = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(canonicalized.forkchoice, attrs)
        .pace(context, Duration::from_millis(20))
        .await
        .wrap_err("failed requesting execution layer to update forkchoice state")?;

    if kind == ForkchoiceUpdateKind::Heartbeat {
        if fcu_response.is_invalid() {
            warn!(
                payload_status = %fcu_response.payload_status,
                "execution layer reported FCU status",
            );
        } else {
            info!(
                payload_status = %fcu_response.payload_status,
                "execution layer reported FCU status",
            );
        }
    } else {
        debug!(
            payload_status = %fcu_response.payload_status,
            "execution layer reported FCU status",
        );
    }

    if fcu_response.is_invalid() {
        return Err(Report::msg(fcu_response.payload_status)
            .wrap_err("execution layer responded with error for forkchoice-update"));
    }

    Ok(fcu_response.payload_id)
}

#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
    err(level = Level::WARN),
    ret,
)]
async fn forward_finalized<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    public_key: Option<PublicKey>,
    metrics: Metrics,
    canonicalized: LastCanonicalized,
    request: FinalizedBlockRequest,
) -> eyre::Result<Option<LastCanonicalized>> {
    let FinalizedBlockRequest {
        cause,
        block,
        acknowledgment,
    } = request;

    // The finalized watermark reported by the execution layer is taken as
    // gospel: a finalized block at or below the watermark is never forwarded
    // (for example when consensus replays finalized blocks after restoring
    // from a snapshot whose anchor is behind the execution state), because
    // the new-payload + forkchoice-update combination would move the
    // execution layer's forkchoice backwards and trigger a reorg. Instead,
    // such a block must already be part of the execution layer's canonical
    // chain, in which case it is acknowledged and dropped.
    //
    // The watermark must be read from the provider rather than from the
    // tracked `canonicalized` state: forkchoice updates for finalized tips
    // are accepted even when the execution layer reports SYNCING, so the
    // tracked state can run ahead of what the execution layer has actually
    // persisted while it is still pipeline-syncing toward the finalized tip.
    //
    // TODO: replace this by checking the last canonicalized height once all
    // sync is forced through marshal and pipeline syncing is disabled.
    let execution_finalized = execution_node
        .provider
        .finalized_block_num_hash()
        .wrap_err("failed reading finalized block num hash from execution layer")?
        .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));

    if block.height().get() <= execution_finalized.number {
        let canonical_hash = execution_node
            .provider
            .block_hash(block.height().get())
            .wrap_err_with(|| {
                format!(
                    "failed reading canonical execution block hash at finalized \
                    block height `{}`",
                    block.height(),
                )
            })?;
        ensure!(
            canonical_hash == Some(block.digest().0),
            "finalized block with digest `{}` at height `{}` is at or below the \
            execution layer's finalized block `{}` at height `{}`, but does not \
            match the execution layer's canonical chain (canonical hash: `{:?}`)",
            block.digest(),
            block.height(),
            execution_finalized.hash,
            execution_finalized.number,
            canonical_hash,
        );
        info!(
            execution_finalized_height = execution_finalized.number,
            execution_finalized_hash = %execution_finalized.hash,
            "finalized block is already part of the execution layer's canonical \
            chain; acknowledging without forwarding",
        );
        acknowledgment.acknowledge();
        return Ok(None);
    }

    // Rebase the tracked forkchoice state onto the watermark the execution
    // layer reported before extending it with the new block, so that the
    // forkchoice update below always finalizes the block.
    let new_canonicalized = LastCanonicalized {
        forkchoice: ForkchoiceState {
            safe_block_hash: execution_finalized.hash,
            finalized_block_hash: execution_finalized.hash,
            ..canonicalized.forkchoice
        },
        head_height: canonicalized.head_height,
        finalized_height: Height::new(execution_finalized.number),
    }
    .update_finalized(block.height(), block.digest());

    let (block, block_access_list) = block.into_parts();
    let consensus_context = block.header().consensus_context;
    let payload_status = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(TempoExecutionData {
            block,
            block_access_list,
            // can be omitted for finalized blocks
            validator_set: None,
        })
        .pace(context, Duration::from_millis(20))
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

    submit_forkchoice_update(
        &execution_node,
        context,
        cause.clone(),
        new_canonicalized,
        None,
        ForkchoiceUpdateKind::Canonicalize {
            head_or_finalized: HeadOrFinalized::Finalized,
        },
    )
    .await?;

    if let Some(public_key) = public_key.as_ref()
        && consensus_context
            .is_some_and(|context| &PublicKey::from(context.proposer.get()) == public_key)
    {
        metrics.finalized_blocks_proposed_by_self.inc();
    }

    acknowledgment.acknowledge();

    Ok(Some(new_canonicalized))
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
