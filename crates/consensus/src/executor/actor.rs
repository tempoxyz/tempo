//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::{collections::VecDeque, ops::RangeInclusive, sync::Arc, time::Duration};

use alloy_rpc_types_engine::{ForkchoiceState, PayloadId};
use commonware_consensus::{Heightable as _, marshal::Update, types::Height};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    Clock, ContextCell, FutureExt, Handle, Metrics as RuntimeMetrics, Pacer, Spawner, spawn_cell,
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use eyre::{Report, WrapErr as _, ensure};
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
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{
    Level, Span, debug, error, error_span, info, info_span, instrument, warn, warn_span,
};

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

    /// The timer for the next FCU heartbeat.
    ///
    /// Armed only when no execution request is active or queued.
    fcu_heartbeat_timer: OptionFuture<BoxFuture<'static, ()>>,

    /// Gap between the last finalized block on the consensus and execution
    /// layers. Needs to be handled on startup because the execution layer does
    /// not reliably flush all blocks.
    finalized_heights_to_backfill: RangeInclusive<u64>,

    /// Backfills that are currently in-flight and are awaiting resolution.
    pending_backfill: OptionFuture<BoxFuture<'static, (u64, Option<Block>)>>,

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

    latest_observed_finalized_tip: Option<(Height, Digest)>,

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
            last_finalized_height,
            marshal,
            fcu_heartbeat_interval,
            public_key,
        } = config;
        let metrics = Metrics::init(&context);
        let canonical_state = execution_node.provider.canonical_in_memory_state();
        let finalized_num_hash = canonical_state
            .get_finalized_num_hash()
            .unwrap_or_else(|| BlockNumHash::new(0, execution_node.chain_spec().genesis_hash()));
        let head_num_hash: BlockNumHash = canonical_state.chain_info().into();

        let fcu_heartbeat_timer = OptionFuture::some(context.sleep(fcu_heartbeat_interval).boxed());
        let last_execution_finalized_height = Height::new(finalized_num_hash.number);
        let finalized_heights_to_backfill =
            (last_execution_finalized_height.get() + 1)..=last_finalized_height.get();
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
            execution_queue: VecDeque::new(),
            execution_task: OptionFuture::none(),
            payload_jobs: FuturesUnordered::new(),

            latest_observed_finalized_tip: None,

            public_key,
            metrics,
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

                block = &mut self.pending_backfill => {
                    match block {
                        (height, Some(block)) => {
                            let (ack, _wait) = Exact::handle();
                            let span = info_span!("backfill_on_start", %height);
                            self.enqueue_execution_request(ExecutionRequest::FinalizeBlock(
                                Box::new(FinalizedBlockRequest {
                                    cause: span,
                                    block,
                                    acknowledgment: ack,
                                    is_backfill: true,
                                }),
                            ));
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
        if !self.is_backfilling()
            && self.execution_task.is_none()
            && self.execution_queue.is_empty()
        {
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
        let is_backfilling = self.is_backfilling();
        match message.command {
            Command::CanonicalizeHead(CanonicalizeHead {
                height,
                digest,
                response,
            }) => {
                if is_backfilling {
                    info_span!("handle_message")
                        .in_scope(|| info!("request to canonicalize deferred while backfilling"));
                }
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
                if is_backfilling {
                    info_span!("handle_message").in_scope(|| {
                        info!("request to canonicalize and build deferred while backfilling")
                    });
                }
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
                    self.latest_observed_finalized_tip.replace((height, digest));
                }
                Update::Block(block, acknowledgement) => {
                    self.enqueue_execution_request(ExecutionRequest::FinalizeBlock(Box::new(
                        FinalizedBlockRequest {
                            cause,
                            block,
                            acknowledgment: acknowledgement,
                            is_backfill: false,
                        },
                    )));
                }
            },
        }
        Ok(())
    }

    fn enqueue_execution_request(&mut self, request: ExecutionRequest) {
        if matches!(&request, ExecutionRequest::Heartbeat { .. })
            && (!self.execution_queue.is_empty()
                || !self.execution_task.is_none()
                || self.is_backfilling())
        {
            return;
        }

        if request.is_backfill() {
            let insert_at = self
                .execution_queue
                .iter()
                .position(|request| !request.is_backfill())
                .unwrap_or(self.execution_queue.len());
            self.execution_queue.insert(insert_at, request);
        } else {
            self.execution_queue.push_back(request);
        }
    }

    fn start_next_execution_task(&mut self) {
        if !self.execution_task.is_none() {
            return;
        }

        // If nothing is currently scheduled and a newer finalized tip was
        // observed, push it into the queue so that it will be picked up next.
        if self.execution_queue.is_empty()
            && !self.is_backfilling()
            && let Some((height, digest)) = self.latest_observed_finalized_tip
            && let new_canonicalized = self.last_canonicalized.update_finalized(height, digest)
            && new_canonicalized != self.last_canonicalized
        {
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

        let Some(request) = self.execution_queue.front() else {
            return;
        };
        if self.is_backfilling() && !request.is_backfill() {
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

    fn is_backfilling(&self) -> bool {
        self.pending_backfill.is_some() || !self.finalized_heights_to_backfill.is_empty()
    }
}

enum ExecutionRequest {
    Heartbeat { cause: Span },
    Canonicalize(Box<Canonicalize>),
    FinalizeBlock(Box<FinalizedBlockRequest>),
}

impl ExecutionRequest {
    fn is_backfill(&self) -> bool {
        let Self::FinalizeBlock(req) = self else {
            return false;
        };
        req.is_backfill
    }
}

struct FinalizedBlockRequest {
    cause: Span,
    block: Block,
    acknowledgment: Exact,
    is_backfill: bool,
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
            let fatal_on_error = !request.is_backfill;
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
                Err(error) if fatal_on_error => ExecutionTaskResult::Fatal { error },
                Err(error) => {
                    warn!(%error, "failed forwarding backfilled finalized block to execution layer");
                    ExecutionTaskResult::Completed {
                        canonicalized: None,
                        payload_job: None,
                    }
                }
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
        is_backfill: _,
    } = request;

    let new_canonicalized = canonicalized.update_finalized(block.height(), block.digest());
    let forkchoice = (new_canonicalized != canonicalized).then_some(new_canonicalized);

    if let Some(canonicalized) = forkchoice {
        submit_forkchoice_update(
            &execution_node,
            context,
            cause.clone(),
            canonicalized,
            None,
            ForkchoiceUpdateKind::Canonicalize {
                head_or_finalized: HeadOrFinalized::Finalized,
            },
        )
        .await?;
    }

    let (block, block_access_list) = block.into_parts();
    let consensus_context = block.header().consensus_context;
    let payload_status = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .new_payload(TempoExecutionData {
            block: block.into(),
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

    if let Some(public_key) = public_key.as_ref()
        && consensus_context
            .is_some_and(|context| &PublicKey::from(context.proposer.get()) == public_key)
    {
        metrics.finalized_blocks_proposed_by_self.inc();
    }

    acknowledgment.acknowledge();

    Ok(forkchoice)
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
