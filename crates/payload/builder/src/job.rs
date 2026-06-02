use alloy_primitives::B256;
use reth_basic_payload_builder::{
    BuildArguments, BuildOutcome, HeaderForPayload, MissingPayloadBehaviour, PayloadBuilder,
    PayloadConfig,
};
use reth_engine_tree::tree::SavedCache;
use reth_payload_builder::PayloadBuilderError;
use reth_payload_builder::{
    BuildNewPayload, KeepPayloadJobAlive, PayloadId, PayloadJob, PayloadJobGenerator,
};
use reth_payload_primitives::{BuiltPayload, PayloadAttributes, PayloadKind};
use reth_revm::{cached::CachedReads, cancelled::CancelOnDrop};
use reth_storage_api::{BlockReaderIdExt, StateProviderFactory};
use reth_tasks::Runtime;
use reth_trie_parallel::state_root_task::StateRootHandle;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_payload_types::{TempoBuiltPayload, TempoPayloadAttributes};
use tempo_primitives::TempoHeader;
use tokio::{
    sync::{Semaphore, oneshot},
    time::{Interval, Sleep},
};
use tracing::{debug, trace, warn};

const PAYLOAD_BUILDER_THREAD_NAME: &str = "payload-builder";

/// Payload job generator used by Tempo consensus builds.
///
/// This mirrors Reth's basic payload job lifecycle, but accepts a
/// `SpeculativePayloadParent` in the attributes so BAL builds can supply the
/// parent header directly before that parent is canonical/provider-visible.
#[derive(Debug)]
pub struct TempoPayloadJobGenerator<Client, Builder> {
    client: Client,
    executor: Runtime,
    interval: Duration,
    deadline: Duration,
    payload_task_limiter: Arc<Semaphore>,
    builder: Builder,
}

impl<Client, Builder> TempoPayloadJobGenerator<Client, Builder> {
    /// Creates a new Tempo payload job generator.
    pub fn new(
        client: Client,
        executor: Runtime,
        interval: Duration,
        deadline: Duration,
        max_payload_tasks: usize,
        builder: Builder,
    ) -> Self {
        assert!(
            max_payload_tasks > 0,
            "max_payload_tasks must be greater than 0"
        );
        Self {
            client,
            executor,
            interval,
            deadline,
            payload_task_limiter: Arc::new(Semaphore::new(max_payload_tasks)),
            builder,
        }
    }

    fn max_job_duration(&self, unix_timestamp: u64) -> Duration {
        let duration_until_timestamp = duration_until(unix_timestamp).min(self.deadline * 3);
        self.deadline + duration_until_timestamp
    }

    fn job_deadline(&self, unix_timestamp: u64) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.max_job_duration(unix_timestamp)
    }
}

impl<Client, Builder> PayloadJobGenerator for TempoPayloadJobGenerator<Client, Builder>
where
    Client: StateProviderFactory + BlockReaderIdExt<Header = TempoHeader> + Clone + Unpin + 'static,
    Builder: PayloadBuilder<Attributes = TempoPayloadAttributes, BuiltPayload = TempoBuiltPayload>
        + Unpin
        + 'static,
{
    type Job = TempoPayloadJob<Builder>;

    fn new_payload_job(
        &self,
        input: BuildNewPayload<TempoPayloadAttributes>,
        id: PayloadId,
    ) -> Result<Self::Job, PayloadBuilderError> {
        let parent_header = if let Some(speculative_parent) = input.attributes.speculative_parent()
        {
            if speculative_parent.parent_hash() != input.parent_hash {
                return Err(PayloadBuilderError::MissingParentHeader(input.parent_hash));
            }
            speculative_parent.parent_header()
        } else if input.parent_hash.is_zero() {
            Arc::new(
                self.client
                    .latest_header()
                    .map_err(PayloadBuilderError::from)?
                    .ok_or_else(|| PayloadBuilderError::MissingParentHeader(B256::ZERO))?,
            )
        } else {
            Arc::new(
                self.client
                    .sealed_header_by_hash(input.parent_hash)
                    .map_err(PayloadBuilderError::from)?
                    .ok_or_else(|| PayloadBuilderError::MissingParentHeader(input.parent_hash))?,
            )
        };

        let config = PayloadConfig::new(parent_header, input.attributes, id);
        let deadline = Box::pin(tokio::time::sleep_until(
            self.job_deadline(config.attributes.timestamp()),
        ));

        let mut job = TempoPayloadJob {
            config,
            executor: self.executor.clone(),
            deadline,
            interval: tokio::time::interval(self.interval),
            best_payload: PayloadState::Missing,
            pending_block: None,
            cached_reads: CachedReads::default(),
            execution_cache: input.cache,
            trie_handle: input.trie_handle,
            payload_task_limiter: self.payload_task_limiter.clone(),
            builder: self.builder.clone(),
        };
        job.spawn_build_job();
        Ok(job)
    }
}

/// Payload job used by [`TempoPayloadJobGenerator`].
#[derive(Debug)]
pub struct TempoPayloadJob<Builder>
where
    Builder: PayloadBuilder,
{
    config: PayloadConfig<Builder::Attributes, HeaderForPayload<Builder::BuiltPayload>>,
    executor: Runtime,
    deadline: Pin<Box<Sleep>>,
    interval: Interval,
    best_payload: PayloadState<Builder::BuiltPayload>,
    pending_block: Option<PendingPayload<Builder::BuiltPayload>>,
    cached_reads: CachedReads,
    execution_cache: Option<SavedCache>,
    trie_handle: Option<StateRootHandle>,
    payload_task_limiter: Arc<Semaphore>,
    builder: Builder,
}

impl<Builder> TempoPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    fn spawn_build_job(&mut self) {
        trace!(target: "payload_builder", id = %self.config.payload_id(), "spawn new payload build task");
        let (tx, rx) = oneshot::channel();
        let cancel = CancelOnDrop::default();
        let task_cancel = cancel.clone();
        let payload_config = self.config.clone();
        let best_payload = self.best_payload.payload().cloned();
        let cached_reads = std::mem::take(&mut self.cached_reads);
        let execution_cache = self.execution_cache.clone();
        let trie_handle = self.trie_handle.take();
        let builder = self.builder.clone();
        let executor = self.executor.clone();
        let limiter = self.payload_task_limiter.clone();

        self.executor.spawn_task(async move {
            let permit = limiter
                .acquire_owned()
                .await
                .expect("payload task semaphore closed");
            executor.spawn_blocking_named_or_tokio(PAYLOAD_BUILDER_THREAD_NAME, move || {
                let _permit = permit;
                let args = BuildArguments {
                    cached_reads,
                    execution_cache,
                    trie_handle,
                    config: payload_config,
                    cancel,
                    best_payload,
                };
                let result = builder.try_build(args);
                let _ = tx.send(result);
            });
        });

        self.pending_block = Some(PendingPayload {
            _cancel: task_cancel,
            payload: rx,
        });
    }
}

impl<Builder> Future for TempoPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type Output = Result<(), PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.deadline.as_mut().poll(cx).is_ready() {
            trace!(target: "payload_builder", "payload building deadline reached");
            return Poll::Ready(Ok(()));
        }

        loop {
            if let Some(mut fut) = this.pending_block.take() {
                match Pin::new(&mut fut).poll(cx) {
                    Poll::Ready(Ok(outcome)) => match outcome {
                        BuildOutcome::Better {
                            payload,
                            cached_reads,
                        } => {
                            this.cached_reads = cached_reads;
                            debug!(target: "payload_builder", value = %payload.fees(), "built better payload");
                            this.best_payload = PayloadState::Best(payload);
                        }
                        BuildOutcome::Freeze(payload) => {
                            debug!(target: "payload_builder", "payload frozen, no further building will occur");
                            this.best_payload = PayloadState::Frozen(payload);
                        }
                        BuildOutcome::Aborted { fees, cached_reads } => {
                            this.cached_reads = cached_reads;
                            trace!(target: "payload_builder", worse_fees = %fees, "skipped payload build of worse block");
                        }
                        BuildOutcome::Cancelled => {
                            debug!(target: "payload_builder", "payload build cancelled");
                            return Poll::Ready(Ok(()));
                        }
                    },
                    Poll::Ready(Err(error)) => {
                        debug!(target: "payload_builder", %error, "payload build attempt failed");
                    }
                    Poll::Pending => {
                        this.pending_block = Some(fut);
                        return Poll::Pending;
                    }
                }
            }

            if this.best_payload.is_frozen() {
                return Poll::Pending;
            }

            std::task::ready!(this.interval.poll_tick(cx));
            this.spawn_build_job();
        }
    }
}

impl<Builder> PayloadJob for TempoPayloadJob<Builder>
where
    Builder: PayloadBuilder + Unpin + 'static,
    Builder::Attributes: Unpin + Clone,
    Builder::BuiltPayload: Unpin + Clone,
{
    type PayloadAttributes = Builder::Attributes;
    type ResolvePayloadFuture = ResolveBestPayload<Self::BuiltPayload>;
    type BuiltPayload = Builder::BuiltPayload;

    fn best_payload(&self) -> Result<Self::BuiltPayload, PayloadBuilderError> {
        if let Some(payload) = self.best_payload.payload() {
            Ok(payload.clone())
        } else {
            self.builder.build_empty_payload(self.config.clone())
        }
    }

    fn payload_attributes(&self) -> Result<Self::PayloadAttributes, PayloadBuilderError> {
        Ok(self.config.attributes.clone())
    }

    fn payload_timestamp(&self) -> Result<u64, PayloadBuilderError> {
        Ok(self.config.attributes.timestamp())
    }

    fn resolve_kind(
        &mut self,
        kind: PayloadKind,
    ) -> (Self::ResolvePayloadFuture, KeepPayloadJobAlive) {
        let best_payload = self.best_payload.payload().cloned();
        if best_payload.is_none() && self.pending_block.is_none() {
            self.spawn_build_job();
        }

        let maybe_better = self.pending_block.take();
        let mut empty_payload = None;

        if best_payload.is_none() {
            debug!(target: "payload_builder", id=%self.config.payload_id(), "no best payload yet to resolve");
            let args = BuildArguments {
                cached_reads: std::mem::take(&mut self.cached_reads),
                execution_cache: self.execution_cache.clone(),
                trie_handle: None,
                config: self.config.clone(),
                cancel: CancelOnDrop::default(),
                best_payload: None,
            };

            match self.builder.on_missing_payload(args) {
                MissingPayloadBehaviour::AwaitInProgress => {
                    debug!(target: "payload_builder", id=%self.config.payload_id(), "awaiting in progress payload build job");
                }
                MissingPayloadBehaviour::RaceEmptyPayload => {
                    let (tx, rx) = oneshot::channel();
                    let config = self.config.clone();
                    let builder = self.builder.clone();
                    self.executor.spawn_blocking_named_or_tokio(
                        PAYLOAD_BUILDER_THREAD_NAME,
                        move || {
                            let res = builder.build_empty_payload(config);
                            let _ = tx.send(res);
                        },
                    );
                    empty_payload = Some(rx);
                }
                MissingPayloadBehaviour::RacePayload(job) => {
                    let (tx, rx) = oneshot::channel();
                    self.executor.spawn_blocking_named_or_tokio(
                        PAYLOAD_BUILDER_THREAD_NAME,
                        move || {
                            let _ = tx.send(job());
                        },
                    );
                    empty_payload = Some(rx);
                }
            };
        }

        (
            ResolveBestPayload {
                best_payload,
                maybe_better,
                empty_payload: empty_payload.filter(|_| kind != PayloadKind::WaitForPending),
            },
            KeepPayloadJobAlive::No,
        )
    }
}

#[derive(Debug, Clone)]
enum PayloadState<P> {
    Missing,
    Best(P),
    Frozen(P),
}

impl<P> PayloadState<P> {
    const fn is_frozen(&self) -> bool {
        matches!(self, Self::Frozen(_))
    }

    const fn payload(&self) -> Option<&P> {
        match self {
            Self::Missing => None,
            Self::Best(payload) | Self::Frozen(payload) => Some(payload),
        }
    }
}

/// Future that resolves the best payload available for a job.
#[derive(Debug)]
pub struct ResolveBestPayload<Payload> {
    best_payload: Option<Payload>,
    maybe_better: Option<PendingPayload<Payload>>,
    empty_payload: Option<oneshot::Receiver<Result<Payload, PayloadBuilderError>>>,
}

impl<Payload> ResolveBestPayload<Payload> {
    const fn is_empty(&self) -> bool {
        self.best_payload.is_none() && self.maybe_better.is_none() && self.empty_payload.is_none()
    }
}

impl<Payload> Future for ResolveBestPayload<Payload>
where
    Payload: Unpin,
{
    type Output = Result<Payload, PayloadBuilderError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(fut) = Pin::new(&mut this.maybe_better).as_pin_mut()
            && let Poll::Ready(res) = fut.poll(cx)
        {
            this.maybe_better = None;
            if let Ok(Some(payload)) = res.map(|out| out.into_payload()).inspect_err(
                |err| warn!(target: "payload_builder", %err, "failed to resolve pending payload"),
            ) {
                debug!(target: "payload_builder", "resolving better payload");
                return Poll::Ready(Ok(payload));
            }
        }

        if let Some(best) = this.best_payload.take() {
            debug!(target: "payload_builder", "resolving best payload");
            return Poll::Ready(Ok(best));
        }

        if let Some(fut) = Pin::new(&mut this.empty_payload).as_pin_mut()
            && let Poll::Ready(res) = fut.poll(cx)
        {
            this.empty_payload = None;
            return match res {
                Ok(res) => Poll::Ready(res),
                Err(err) => Poll::Ready(Err(err.into())),
            };
        }

        if this.is_empty() {
            return Poll::Ready(Err(PayloadBuilderError::MissingPayload));
        }

        Poll::Pending
    }
}

#[derive(Debug)]
struct PendingPayload<P> {
    _cancel: CancelOnDrop,
    payload: oneshot::Receiver<Result<BuildOutcome<P>, PayloadBuilderError>>,
}

impl<P> Future for PendingPayload<P> {
    type Output = Result<BuildOutcome<P>, PayloadBuilderError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let res = std::task::ready!(Pin::new(&mut self.payload).poll(cx));
        Poll::Ready(res.map_err(Into::into).and_then(|res| res))
    }
}

fn duration_until(unix_timestamp_secs: u64) -> Duration {
    let unix_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Duration::from_secs(unix_timestamp_secs).saturating_sub(unix_now)
}
