//! Drives the actual execution forwarding blocks and setting forkchoice state.
//!
//! This agent forwards finalized blocks from the consensus layer to the
//! execution layer and tracks the digest of the latest finalized block.
//! It also advances the canonical chain by sending forkchoice-updates.

use std::{collections::VecDeque, ops::RangeInclusive, sync::Arc, time::Duration};

use alloy_rpc_types_engine::ForkchoiceState;
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
};
use prometheus_client::metrics::counter::Counter;
use reth_ethereum::{chainspec::EthChainSpec, rpc::eth::primitives::BlockNumHash};
use reth_primitives_traits::{BlockBody as _, SealedHeader};
use reth_transaction_pool::TransactionPool;
use tempo_node::{TempoExecutionData, TempoFullNode};
use tempo_payload_builder::{TempoPayloadBuilder, TempoPayloadBuilderConfig};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tokio::select;
use tracing::{Span, debug, error, error_span, info, info_span, instrument, warn, warn_span};

use super::{
    Config,
    ingress::{BuildOptimistic, CanonicalizeHead, Command, Message},
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
                        ExecutionTaskResult::Completed { canonicalized } => {
                            if let Some(canonicalized) = canonicalized {
                                // There is only one execution task running at
                                // a time, and `last_canonicalized` is only
                                // mutated here to keep a consistent view.
                                self.last_canonicalized = canonicalized;
                            }
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
                        height,
                        digest,
                        response: Some(response),
                    },
                )));
            }
            Command::BuildOptimistic(BuildOptimistic {
                parent,
                attributes,
                response,
            }) => {
                if is_backfilling {
                    info_span!("handle_message")
                        .in_scope(|| info!("optimistic build request deferred while backfilling"));
                }
                self.enqueue_execution_request(ExecutionRequest::BuildOptimistic(Box::new(
                    BuildOptimisticRequest {
                        cause,
                        parent,
                        attributes: *attributes,
                        response,
                    },
                )));
            }
            Command::Finalize(finalized) => match *finalized {
                Update::Tip(_, _, _) => {}
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
    BuildOptimistic(Box<BuildOptimisticRequest>),
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
    Canonicalize,
}

enum ExecutionTaskResult {
    Completed {
        canonicalized: Option<LastCanonicalized>,
    },
}

struct Canonicalize {
    cause: Span,
    height: Height,
    digest: Digest,
    /// Acknowledges to the requester that the execution layer accepted the
    /// forkchoice update.
    response: Option<oneshot::Sender<()>>,
}

struct BuildOptimisticRequest {
    cause: Span,
    parent: Block,
    attributes: TempoPayloadAttributes,
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
                ForkchoiceUpdateKind::Heartbeat,
            )
            .await
            {
                warn!(%error, "queued forkchoice update failed");
            }
            ExecutionTaskResult::Completed {
                canonicalized: None,
            }
        }
        ExecutionRequest::Canonicalize(request) => {
            let canonicalized =
                run_canonicalize_task(&context, execution_node, canonicalized, *request).await;
            ExecutionTaskResult::Completed { canonicalized }
        }
        ExecutionRequest::BuildOptimistic(request) => {
            run_optimistic_build_task(execution_node, *request).await;
            ExecutionTaskResult::Completed {
                canonicalized: None,
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
                Ok(canonicalized) => ExecutionTaskResult::Completed { canonicalized },
                Err(error) => {
                    warn!(%error, "failed forwarding backfilled finalized block to execution layer");
                    ExecutionTaskResult::Completed {
                        canonicalized: None,
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
    ),
)]
async fn run_canonicalize_task<TContext: Pacer>(
    context: &TContext,
    execution_node: Arc<TempoFullNode>,
    canonicalized: LastCanonicalized,
    Canonicalize {
        cause,
        height,
        digest,
        response,
    }: Canonicalize,
) -> Option<LastCanonicalized> {
    let new_canonicalized = canonicalized.update_head(height, digest);

    // The forkchoice update is submitted even if it would not change the
    // forkchoice state: the execution layer treats it as a no-op (the FCU
    // heartbeat relies on this).
    match submit_forkchoice_update(
        &execution_node,
        context,
        cause.clone(),
        new_canonicalized,
        ForkchoiceUpdateKind::Canonicalize,
    )
    .await
    {
        Ok(()) => {
            if let Some(response) = response {
                let _ = response.send(());
            }
            Some(new_canonicalized)
        }
        Err(error) => {
            // Dropping the response channels signals the failure to the
            // subscribers; the cause is only logged here.
            warn!(%error, "forkchoice update failed");
            None
        }
    }
}

/// Builds a payload from a consensus parent that may not yet be canonicalized
/// in the execution layer.
#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        parent_height = %request.parent.height(),
        parent_digest = %request.parent.digest(),
    ),
)]
async fn run_optimistic_build_task(
    execution_node: Arc<TempoFullNode>,
    request: BuildOptimisticRequest,
) {
    let BuildOptimisticRequest {
        cause: _,
        parent,
        attributes,
        response,
    } = request;

    if response.is_canceled() {
        info!(
            "dropping optimistic payload build request: the subscriber went away while it was queued"
        );
        return;
    }

    let parent_header = Arc::new(SealedHeader::new(
        parent.block().header().clone(),
        parent.block_hash(),
    ));
    let pool = execution_node.pool.clone();
    let parent_transaction_hashes = parent
        .block()
        .body()
        .transaction_hashes_iter()
        .copied()
        .collect::<Vec<_>>();
    if !parent_transaction_hashes.is_empty() {
        let removed = pool.prune_transactions(parent_transaction_hashes);
        debug!(
            parent_transactions_pruned = removed.len(),
            "pruned consensus parent transactions before optimistic build",
        );
    }
    let provider = execution_node.provider.clone();
    let task_executor = execution_node.task_executor.clone();
    let builder_executor = task_executor.clone();
    let evm_config = execution_node.evm_config.clone();

    let build = task_executor.spawn_blocking(move || {
        let builder = TempoPayloadBuilder::new(
            pool,
            provider,
            builder_executor,
            evm_config,
            TempoPayloadBuilderConfig::default(),
        );
        builder.build_optimistic_payload(parent_header, attributes)
    });

    match build.await {
        Ok(Ok(payload)) => {
            if response.send(payload).is_err() {
                info!(
                    "payload subscriber went away before the optimistic payload could be delivered; discarding it"
                );
            }
        }
        Ok(Err(error)) => {
            warn!(
                error = %eyre::Report::new(error),
                "optimistic payload build failed",
            );
        }
        Err(error) => {
            warn!(
                %error,
                "optimistic payload build task failed",
            );
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
    kind: ForkchoiceUpdateKind,
) -> eyre::Result<()> {
    let fcu_response = execution_node
        .add_ons_handle
        .beacon_engine_handle
        .fork_choice_updated(canonicalized.forkchoice, None)
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

    Ok(())
}

#[instrument(
    skip_all,
    parent = &request.cause,
    fields(
        block.digest = %request.block.digest(),
        block.height = %request.block.height(),
    ),
    err(level = tracing::Level::WARN),
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
        is_backfill,
    } = request;

    let consensus_context = block.header().consensus_context;
    let canonicalized = if is_backfill {
        let payload_status = execution_node
            .add_ons_handle
            .beacon_engine_handle
            .new_payload(TempoExecutionData {
                block: block.execution_block().clone(),
                block_access_list: block.block_access_list().cloned(),
                validator_set: None,
            })
            .pace(context, Duration::from_millis(20))
            .await
            .wrap_err(
                "failed sending backfilled block to execution engine with new-payload request",
            )?;

        ensure!(
            payload_status.is_valid() || payload_status.is_syncing(),
            "backfilled block payload status was neither valid nor syncing: `{payload_status}`"
        );

        let canonicalized = canonicalized.update_head(block.height(), block.digest());
        submit_forkchoice_update(
            &execution_node,
            context,
            cause,
            canonicalized,
            ForkchoiceUpdateKind::Canonicalize,
        )
        .await?;

        Some(canonicalized)
    } else {
        None
    };

    if let Some(public_key) = public_key.as_ref()
        && consensus_context
            .is_some_and(|context| &PublicKey::from(context.proposer.get()) == public_key)
    {
        metrics.finalized_blocks_proposed_by_self.inc();
    }

    acknowledgment.acknowledge();

    Ok(canonicalized)
}
