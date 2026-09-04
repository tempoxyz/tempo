use super::{
    acks::{PendingAck, PendingAcks},
    cache,
    delivery::PendingVerification,
    durability::{DispatchGate, Durable as _},
    floor::Floor,
    mailbox::{CommitmentFallback, Mailbox, Message},
    stream::Stream,
    subscriptions::{Key as SubscriptionKey, KeyFor as SubscriptionKeyFor, Subscriptions},
    variant::NoBuffer,
    Buffer, Variant,
};
use crate::{
    marshal::{
        resolver::handler::{self, Annotation, Key, Request},
        store::{Blocks, Certificates},
        Config, Identifier as BlockID, Start, Update,
    },
    simplex::{
        scheme::Scheme,
        types::{verify_certificates, Finalization, Notarization, Subject},
    },
    types::{Epoch, Epocher, Height, Round, ViewDelta},
    Block, Epochable, Heightable, Reporter,
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::{
    certificate::{Provider, Verifier},
    Digestible,
};
use commonware_macros::{boxed, select_loop};
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Resolver, TargetedResolver};
use commonware_runtime::{
    spawn_cell,
    telemetry::{
        metrics::{Gauge, GaugeExt, MetricsExt as _},
        traces::TracedExt as _,
    },
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Pool},
    Acknowledgement, BoxedError,
};
use futures::{
    future::{join, join_all},
    try_join,
};
use rand_core::CryptoRng;
use std::{collections::BTreeMap, future::Future, num::NonZeroUsize, sync::Arc};
use tracing::{debug, info_span, warn, Instrument as _, Span};

// Resolver request keys are expressed in the variant commitment type, which
// may differ from the block digest for coded variants.
type ResolverRequestFor<V> = Key<<V as Variant>::Commitment>;

// A resolver delivery plus the peer-validity response channel. Local
// annotations on the delivery decide how accepted data is used.
struct ResolverDelivery<V: Variant> {
    delivery: Delivery<ResolverRequestFor<V>, Annotation>,
    value: Bytes,
    response: oneshot::Sender<bool>,
}

/// Completion marker for entries in the actor's durability sync pool.
enum PooledSync {
    /// A sync that requires no action on completion.
    Observed,
    /// A finalized-archive sync batch became durable. Carries the sequence
    /// assigned by [`Actor::start_finalized_sync`] so the completion arm can
    /// release every batch the sync covers (see [`DispatchGate::release`]).
    Finalized(u64),
}

/// The [Actor] is responsible for receiving uncertified blocks from the broadcast mechanism,
/// receiving notarizations and finalizations from consensus, and reconstructing a total order
/// of blocks.
///
/// The actor is designed to be used in a view-based model. Each view corresponds to a
/// potential block in the chain. The actor will only finalize a block if it has a
/// corresponding finalization.
///
/// The actor also provides a backfill mechanism for missing blocks. If the actor receives a
/// finalization for a block that is ahead of its current view, it will request the missing blocks
/// from its peers. This ensures that the actor can catch up to the rest of the network if it falls
/// behind.
pub struct Actor<E, V, P, FC, FB, ES, T, A = Exact>
where
    E: BufferPooler + CryptoRng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    P: Provider<Scope = Epoch, Scheme: Scheme<V::Commitment>>,
    FC: Certificates<
        BlockDigest = <V::Block as Digestible>::Digest,
        Commitment = V::Commitment,
        Scheme = P::Scheme,
    >,
    FB: Blocks<Block = V::StoredBlock>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    // ---------- Context ----------
    context: ContextCell<E>,

    // ---------- Message Passing ----------
    // Mailbox
    mailbox: mailbox::Receiver<Message<P::Scheme, V>>,

    // ---------- Configuration ----------
    // Provider for epoch-specific signing schemes
    provider: P,
    // Epoch configuration
    epocher: ES,
    // Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: ViewDelta,
    // Maximum number of blocks to repair at once
    max_repair: NonZeroUsize,
    // Codec configuration for block type
    block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // ---------- State ----------
    // Current processed floor and any pending floor update
    floor: Floor<P::Scheme, V::Commitment>,
    // Application delivery cursor
    stream: Stream<E>,
    // Pending application acknowledgements
    pending_acks: PendingAcks<V, A>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: Subscriptions<V>,
    // Defers application dispatch of finalized-archive writes until a sync
    // covering them completes
    dispatch_gate: DispatchGate,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, V, P::Scheme>,
    // Finalizations stored by height
    finalizations_by_height: FC,
    // Finalized blocks stored by height
    finalized_blocks: FB,

    // ---------- Metrics ----------
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,
}

impl<E, V, P, FC, FB, ES, T, A> Actor<E, V, P, FC, FB, ES, T, A>
where
    E: BufferPooler + CryptoRng + Spawner + Metrics + Clock + Storage,
    V: Variant,
    P: Provider<Scope = Epoch, Scheme: Scheme<V::Commitment>>,
    FC: Certificates<
        BlockDigest = <V::Block as Digestible>::Digest,
        Commitment = V::Commitment,
        Scheme = P::Scheme,
    >,
    FB: Blocks<Block = V::StoredBlock>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    /// Create a new application actor.
    #[boxed]
    pub async fn init(
        context: E,
        finalizations_by_height: FC,
        mut finalized_blocks: FB,
        config: Config<P, ES, T, V::ApplicationBlock, V::Block, V::Commitment>,
    ) -> (Self, Mailbox<P::Scheme, V>, Option<Height>) {
        // Initialize cache
        let prunable_config = cache::Config {
            partition_prefix: format!("{}-cache", config.partition_prefix),
            prunable_items_per_section: config.prunable_items_per_section,
            replay_buffer: config.replay_buffer,
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            key_page_cache: config.page_cache.clone(),
        };
        let cache = cache::Manager::init(
            context.child("cache"),
            prunable_config,
            config.block_codec_config.clone(),
        )
        .await;

        // The application metadata name is retained for legacy support.
        let application_metadata_partition =
            format!("{}-application-metadata", config.partition_prefix);
        let stream = Stream::new(context.child("stream"), &application_metadata_partition).await;
        let last_processed_height = stream.processed_height();

        // Genesis is a local anchor. A floor finalization is verified and
        // resolved after `run` receives the resolver and buffer.
        let pending_floor_anchor = match config.start {
            Start::Genesis(anchor) => {
                assert_eq!(
                    anchor.height(),
                    Height::zero(),
                    "genesis anchor must be at height zero"
                );
                Self::ensure_genesis_anchor(&mut finalized_blocks, anchor, last_processed_height)
                    .await;
                None
            }
            Start::Floor(finalization) => Some(finalization),
        };
        let last_processed_round =
            Self::latest_processed_round(&finalizations_by_height, last_processed_height).await;

        // Create metrics
        let finalized_height = context.gauge("finalized_height", "Finalized height of application");
        let processed_height = context.gauge("processed_height", "Processed height of application");
        if let Some(last_processed_height) = last_processed_height {
            let _ = processed_height.try_set(last_processed_height.get());
        }
        let floor = pending_floor_anchor.map_or_else(
            || Floor::resolved(last_processed_height, last_processed_round),
            |finalization| {
                Floor::awaiting_anchor(last_processed_height, last_processed_round, finalization)
            },
        );

        // Initialize mailbox
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                provider: config.provider,
                epocher: config.epocher,
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                block_codec_config: config.block_codec_config,
                strategy: config.strategy,
                floor,
                stream,
                pending_acks: PendingAcks::new(config.max_pending_acks.get()),
                tip: Height::zero(),
                block_subscriptions: Subscriptions::new(),
                dispatch_gate: DispatchGate::default(),
                cache,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
            },
            Mailbox::new(sender),
            last_processed_height,
        )
    }

    async fn ensure_genesis_anchor(
        finalized_blocks: &mut FB,
        anchor: V::Block,
        last_processed_height: Option<Height>,
    ) {
        let anchor_height = anchor.height();
        let anchor_commitment = V::commitment(&anchor);
        match finalized_blocks
            .get(ArchiveID::Index(anchor_height.get()))
            .await
        {
            Ok(Some(stored)) => {
                let stored: V::Block = stored.into();
                assert_eq!(
                    stored.height(),
                    anchor_height,
                    "stored genesis block height mismatch"
                );
                assert!(
                    V::commitment(&stored) == anchor_commitment,
                    "stored genesis block does not match configured anchor"
                );
            }
            Ok(None) => {
                if let Some(existing) =
                    last_processed_height.filter(|height| anchor_height < *height)
                {
                    warn!(
                        height = %anchor_height,
                        %existing,
                        "ignoring stale anchor"
                    );
                    return;
                }

                finalized_blocks
                    .put(anchor.into())
                    .await
                    .expect("failed to store startup anchor");
                finalized_blocks
                    .sync()
                    .await
                    .expect("failed to sync startup anchor");
                debug!(height = %anchor_height, "stored genesis block");
            }
            Err(err) => panic!("failed to check startup anchor: {err}"),
        }
    }

    /// Start the actor.
    pub fn start<R, Buf>(
        mut self,
        application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: Buf,
        resolver: (handler::Receiver<V::Commitment>, R),
    ) -> Handle<()>
    where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver))
    }

    /// Start the actor without a broadcast buffer.
    pub fn start_unbuffered<R>(
        self,
        application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: (handler::Receiver<V::Commitment>, R),
    ) -> Handle<()>
    where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
    {
        self.start(
            application,
            NoBuffer::<<P::Scheme as Verifier>::PublicKey>::new(),
            resolver,
        )
    }

    /// Run the application actor.
    async fn run<R, Buf>(
        mut self,
        mut application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        mut buffer: Buf,
        (mut resolver_rx, mut resolver): (handler::Receiver<V::Commitment>, R),
    ) where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<Result<Arc<V::Block>, SubscriptionKeyFor<V>>>::default();

        // Observe durable syncs that no consensus caller awaits (the
        // notarization and finalization paths). A flush failure inside
        // `start_sync` is reported only through the returned handle, so every
        // handle must be observed to apply the fatal policy. This pool does
        // so without blocking the actor on a sync.
        let mut syncs = Pool::<PooledSync>::default();

        // Anchor all startup work under a single root span. Tip recovery, floor
        // installation, gap repair, and the initial dispatch all run before any
        // mailbox message arrives, so without this root their work would emit as
        // orphan traces.
        async {
            // Get tip and send to application
            let tip = self.get_latest().await;
            if let Some((height, digest, round)) = tip {
                application.report(Update::Tip(round, height, digest));
                self.tip = height;
                let _ = self.finalized_height.try_set(height.get());
            }

            // Load persisted cache epochs so find_block can discover blocks
            // written before the last shutdown.
            self.cache.load_persisted_epochs().await;

            // A configured floor follows the same path as `SetFloor`: verify it,
            // then apply a local anchor or fetch the anchor block.
            if let Some(finalization) = self.floor.take_pending_anchor() {
                self.install_floor(
                    finalization,
                    false,
                    &mut resolver,
                    &mut buffer,
                    &mut application,
                )
                .await;
            }

            // Attempt to repair any gaps in the finalized blocks archive, if there are any.
            if self
                .try_repair_gaps(&mut buffer, &mut resolver, &mut application)
                .await
            {
                self.sync_finalized().await;
            }

            // Attempt to dispatch the next finalized block to the application, if it is ready.
            self.try_dispatch_blocks(&mut application).await;
        }
        .instrument(info_span!("marshal.actor.start"))
        .await;

        select_loop! {
            self.context,
            on_start => {
                // Remove any dropped subscribers. If all subscribers dropped, abort the waiter.
                self.block_subscriptions.retain_open();
            },
            on_stopped => {
                debug!("context shutdown, stopping marshal");
            },
            // Drive durability syncs: a real sync failure panics inside the
            // pooled future (the fatal policy), aborting the actor. A completed
            // finalized-archive sync additionally releases the dispatch barrier
            // for the batches it covers and resumes application dispatch.
            sync = syncs.next_completed() => {
                if let PooledSync::Finalized(seq) = sync {
                    self.dispatch_gate.release(seq);
                    self.try_dispatch_blocks(&mut application).await;
                }
            },
            // Handle waiter completions first
            Ok(completion) = waiters.next_completed() else continue => match completion {
                Ok(block) => {
                    self.ingest(block, &mut buffer, &mut application, &mut resolver)
                        .await;
                }
                Err(key) => {
                    match key {
                        SubscriptionKey::Digest(digest) => {
                            debug!(
                                ?digest,
                                "buffer subscription closed, canceling local subscribers"
                            );
                        }
                        SubscriptionKey::Commitment(commitment) => {
                            debug!(
                                ?commitment,
                                "buffer subscription closed, canceling local subscribers"
                            );
                        }
                    }
                    self.block_subscriptions.remove(&key);
                }
            },
            // Handle application acknowledgements (drain all ready acks, sync once)
            result = self.pending_acks.current() => {
                if let Err((height, e)) = self
                    .handle_ack(result, &mut application, &mut buffer, &mut resolver)
                    .await
                {
                    debug!(
                        ?e,
                        %height,
                        "application acknowledgement dropped, stopping marshal"
                    );
                    return;
                }
            },
            // Handle consensus inputs before backfill or resolver traffic
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                let span = info_span!(
                    parent: message.span(),
                    "marshal.actor.process",
                    operation = message.name(),
                );
                self.handle_mailbox_message(
                    message,
                    &mut resolver,
                    &mut waiters,
                    &mut syncs,
                    &mut buffer,
                    &mut application,
                )
                .instrument(span)
                .await;
            },
            // Handle resolver messages last (batched up to max_repair, sync once)
            Some(message) = resolver_rx.recv() else {
                debug!("handler closed, shutting down");
                return;
            } => {
                self.handle_resolver_message(
                    message,
                    &mut resolver_rx,
                    &mut resolver,
                    &mut syncs,
                    &mut buffer,
                    &mut application,
                )
                .await;
            },
        }
    }

    /// Handles one ready application acknowledgement and drains any queued acks
    /// that are already complete.
    async fn handle_ack<Buf, R>(
        &mut self,
        result: <A::Waiter as Future>::Output,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: &mut Buf,
        resolver: &mut R,
    ) -> Result<(), (Height, A::Error)>
    where
        Buf: Buffer<V>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        // Start with the ack that woke this `select_loop!` arm.
        let mut pending = Some(self.pending_acks.complete_current(result));
        let last_acked_commitment = loop {
            let (height, commitment, result) = pending.take().expect("pending ack must exist");
            match result {
                Ok(()) => {
                    // Apply in-memory progress updates for this acknowledged
                    // block. The metadata sync below makes drained updates durable.
                    self.update_processed_height(height, resolver);
                    self.update_processed_round(height, resolver).await;
                }
                Err(e) => return Err((height, e)),
            }

            // Opportunistically drain any additional already-ready acks so we
            // can persist one metadata sync for the whole batch below.
            match self.pending_acks.pop_ready() {
                Some(next) => pending = Some(next),
                None => break commitment,
            }
        };

        // Persist buffered progress updates once after draining all ready acks.
        self.stream
            .sync()
            .await
            .expect("failed to sync application progress");

        // Anything below the last acknowledged commitment is safe for the
        // buffer to prune.
        buffer.finalized(last_acked_commitment);

        // Refill the application dispatch pipeline.
        self.try_dispatch_blocks(application).await;

        Ok(())
    }

    /// Handles a single mailbox message from local consensus/application callers.
    async fn handle_mailbox_message<Buf, R>(
        &mut self,
        message: Message<P::Scheme, V>,
        resolver: &mut R,
        waiters: &mut AbortablePool<Result<Arc<V::Block>, SubscriptionKeyFor<V>>>,
        syncs: &mut Pool<PooledSync>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
    {
        if message.response_closed() {
            return;
        }

        match message {
            Message::GetInfo {
                identifier,
                response,
                ..
            } => {
                let info = match identifier {
                    // TODO: Instead of pulling out the entire block, determine the
                    // height directly from the archive by mapping the digest to
                    // the index, which is the same as the height.
                    BlockID::Digest(digest) => self
                        .finalized_blocks
                        .get(ArchiveID::Key(&digest))
                        .await
                        .ok()
                        .flatten()
                        .map(|b| (b.height(), digest)),
                    BlockID::Height(height) => self.get_info_by_height(height).await,
                    BlockID::Latest => self.get_latest().await.map(|(h, d, _)| (h, d)),
                };
                response.send_lossy(info);
            }
            Message::GetVerified {
                round, response, ..
            } => {
                let block = self.cache.get_verified(round).await.map(Into::into);
                response.send_lossy(block);
            }
            Message::Forward {
                round,
                commitment,
                recipients,
                ..
            } => {
                if matches!(&recipients, Recipients::Some(peers) if peers.is_empty()) {
                    return;
                }
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block not found for forwarding");
                    return;
                };
                buffer.send(round, block, recipients);
            }
            Message::Proposed {
                round,
                block,
                recipients,
                ack,
                ..
            } => {
                // To lower view latency as much as possible while preserving
                // safety, we broadcast the block before persisting it
                // (durability is not required until certify). A leader that
                // crashes here may broadcast a conflicting block for the same
                // round after restart. This is tolerated: extra block bytes
                // cannot form a conflicting certificate (unlike votes), block
                // storage tolerates multiple candidates per round (see
                // [Mailbox::get_verified]), and the propose paths skip or
                // reuse a recovered block on restart.
                buffer.send(round, Arc::clone(&block), recipients);
                self.persist_verified(round, block, ack, buffer, application, resolver)
                    .await;
            }
            Message::Verified {
                round, block, ack, ..
            } => {
                self.persist_verified(round, block, ack, buffer, application, resolver)
                    .await;
            }
            Message::Certified {
                round, block, ack, ..
            } => {
                self.ingest(Arc::clone(&block), buffer, application, resolver)
                    .await;
                let digest = block.digest();

                // A block the verified archive already holds needs no second copy:
                // the verified archive's covering sync handle vouches for it. At
                // most one notarization exists per round, so the notarized slot can
                // never belong to a different payload: a duplicate put is a no-op
                // whose handle still covers the original write. If the round has
                // already been pruned by tip advancement, both writes are no-ops
                // because the round is below the retention floor.
                let block_sync = if self.cache.has_verified(round, &digest).await {
                    debug!(?round, "certified block covered by verified write");
                    self.cache.start_sync_verified(round).await
                } else {
                    self.cache
                        .put_notarized(round, digest, Arc::unwrap_or_clone(block).into())
                        .await
                };

                // Hold the certify barrier until the round's notarization
                // certificate (when one was accepted before this message) is
                // durable alongside the block.
                let notarization_sync = self.cache.start_sync_notarizations(round).await;
                let handle = Handle::from_future(async move {
                    let (notarization, block) = join(notarization_sync, block_sync).await;
                    notarization.and(block)
                });
                ack.send_lossy(handle);
            }
            Message::Notarization { notarization, .. } => {
                let round = notarization.round();
                let commitment = notarization.proposal.payload;
                let digest = V::commitment_to_inner(commitment);

                // Persist the notarization; the certify barrier folds in its
                // durability via `start_sync_notarizations`. The archive keeps a
                // single notarization per round, so a re-delivery is a no-op whose
                // handle still covers the original write. No consensus caller
                // awaits this handle, so the pool observes it (applying the fatal
                // policy) without blocking the actor.
                let handle = self
                    .cache
                    .put_notarization(round, digest, notarization)
                    .await;
                syncs.push(async move {
                    handle.durable(round, "notarization").await;
                    PooledSync::Observed
                });

                // A notarization alone is not enough to fetch missing proposal
                // data. If the block is not locally available, remember the
                // certificate and wait for a later finalization/repair path.
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    self.ingest(Arc::clone(&block), buffer, application, resolver)
                        .await;
                    if self.cache.has_verified(round, &digest).await {
                        debug!(?round, "notarized block covered by verified write");
                    } else {
                        let handle = self
                            .cache
                            .put_notarized(round, digest, Arc::unwrap_or_clone(block).into())
                            .await;
                        syncs.push(async move {
                            handle.durable(round, "notarized").await;
                            PooledSync::Observed
                        });
                    }
                } else {
                    debug!(?round, "notarized block unavailable locally");
                }
            }
            Message::Finalization { finalization, .. } => {
                let round = finalization.round();
                let commitment = finalization.proposal.payload;
                let digest = V::commitment_to_inner(commitment);

                // Cache finalization by round.
                self.cache
                    .put_finalization(round, digest, finalization.clone())
                    .await;

                // Search for the finalized block locally, otherwise fetch it remotely.
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    // The anchor path stores the floor block and finalization,
                    // advances floors, prunes below them, and resumes dispatch.
                    if self
                        .ingest(Arc::clone(&block), buffer, application, resolver)
                        .await
                    {
                        return;
                    }

                    let height = block.height();
                    self.update_processed_round_floor(height, round, resolver)
                        .await;
                    if self
                        .store_finalization(
                            height,
                            digest,
                            Arc::unwrap_or_clone(block),
                            Some(finalization),
                            application,
                        )
                        .await
                    {
                        // If a floor anchor is pending, repair and dispatch are
                        // no-ops until the anchor block is stored.
                        self.try_repair_gaps(buffer, resolver, application).await;
                        self.start_finalized_sync(round, syncs).await;
                        debug!(?round, %height, "finalized block stored");
                    }
                } else {
                    // The finalization carries a round and commitment, but not a
                    // height. Keep the request round-bound until the block is decoded.
                    debug!(?round, ?commitment, "finalized block missing");
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_round(commitment, round),
                        )
                        .ignore();
                }
            }
            Message::GetBlock {
                identifier,
                response,
                ..
            } => match identifier {
                BlockID::Digest(digest) => {
                    let result = self
                        .find_block_by_digest(buffer, digest)
                        .await
                        .map(Arc::unwrap_or_clone);
                    response.send_lossy(result);
                }
                BlockID::Height(height) => {
                    let result = self.get_finalized_block(height).await;
                    response.send_lossy(result);
                }
                BlockID::Latest => {
                    let block = match self.get_latest().await {
                        Some((_, digest, _)) => self.find_block_by_digest(buffer, digest).await,
                        None => None,
                    }
                    .map(Arc::unwrap_or_clone);
                    response.send_lossy(block);
                }
            },
            Message::GetFinalization {
                height, response, ..
            } => {
                let finalization = self.get_finalization_by_height(height).await;
                response.send_lossy(finalization);
            }
            Message::GetProcessedHeight { response, .. } => {
                response.send_lossy(self.stream.processed_height());
            }
            Message::HintFinalized {
                height, targets, ..
            } => {
                // Skip if finalization is already available locally.
                if self.has_finalization_by_height(height).await {
                    return;
                }

                self.floor
                    .fetch_targeted_if_permitted(resolver, Request::finalized(height), targets)
                    .ignore();
            }
            Message::SubscribeByDigest {
                span,
                digest,
                fallback,
                response,
            } => {
                self.handle_subscribe(
                    span,
                    fallback.into(),
                    SubscriptionKey::Digest(digest),
                    response,
                    resolver,
                    waiters,
                    buffer,
                )
                .await;
            }
            Message::SubscribeByCommitment {
                span,
                commitment,
                fallback,
                response,
            } => {
                self.handle_subscribe(
                    span,
                    fallback,
                    SubscriptionKey::Commitment(commitment),
                    response,
                    resolver,
                    waiters,
                    buffer,
                )
                .await;
            }
            Message::HintNotarized {
                round, commitment, ..
            } => {
                if self
                    .find_block_by_commitment(buffer, commitment)
                    .await
                    .is_none()
                {
                    self.floor
                        .fetch_if_permitted(resolver, Request::notarized(round))
                        .ignore();
                }
            }
            Message::SetFloor { finalization, .. } => {
                self.install_floor(finalization, true, resolver, buffer, application)
                    .await;
            }
            Message::Prune { height, .. } => {
                // Only allow pruning at or below the current floor.
                if height > self.floor.processed_height() {
                    warn!(%height, floor = %self.floor.processed_height(), "prune height above floor, ignoring");
                    return;
                }

                self.prune_finalized_archives(height)
                    .await
                    .expect("failed to prune finalized archives");

                // Intentionally keep existing block subscriptions alive. Canceling
                // waiters can have catastrophic consequences because actors do not
                // retry subscriptions on failed channels.
            }
        }
    }

    /// Handles a batch of resolver messages, starting one pooled
    /// finalized-archive sync if any accepted delivery buffered a write.
    async fn handle_resolver_message<Buf, R>(
        &mut self,
        message: handler::Message<V::Commitment>,
        resolver_rx: &mut handler::Receiver<V::Commitment>,
        resolver: &mut R,
        syncs: &mut Pool<PooledSync>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        let mut handled = false;
        let mut produces = Vec::new();
        let mut delivers = Vec::new();

        // Drain up to max_repair resolver messages. Block deliveries are handled
        // immediately, certificate-bearing deliveries are batched for verification,
        // and produce responses wait until repair has had a chance to fill gaps.
        for msg in std::iter::once(message)
            .chain(std::iter::from_fn(|| resolver_rx.try_recv().ok()))
            .take(self.max_repair.get())
        {
            if msg.response_closed() {
                continue;
            }
            handled = true;

            match msg {
                handler::Message::Produce { key, response } => {
                    produces.push((key, response));
                }
                handler::Message::Deliver {
                    delivery,
                    value,
                    response,
                } => {
                    let span = info_span!(
                        parent: &delivery.subscribers.first().1,
                        "marshal.resolver.deliver",
                        key = %delivery.key
                    );
                    for (_, subscriber_span) in delivery.subscribers.iter().skip(1) {
                        span.follows_from(subscriber_span.id());
                    }
                    self.handle_deliver(
                        ResolverDelivery {
                            delivery,
                            value,
                            response,
                        },
                        &mut delivers,
                        buffer,
                        application,
                        resolver,
                    )
                    .instrument(span)
                    .await;
                }
            }
        }
        if !handled {
            return;
        }

        // Batch verify and process all certificate-bearing deliveries.
        self.verify_delivered(delivers, buffer, application, resolver)
            .await;

        // Attempt to fill gaps before handling produce requests so we can serve
        // data received earlier in the same batch.
        self.try_repair_gaps(buffer, resolver, application).await;

        // Start a pooled sync so any writes buffered by this batch become
        // durable without blocking the mailbox. Dispatch of the written
        // heights resumes when the sync completes. A batch has no single
        // round, so the label is the node's processed round when it started.
        self.start_finalized_sync(self.floor.processed_round(), syncs)
            .await;

        // Handle produce requests in parallel.
        join_all(
            produces
                .into_iter()
                .filter(|(_, response)| !response.is_closed())
                .map(|(key, response)| self.handle_produce(key, response, buffer)),
        )
        .await;
    }

    /// Handle a produce request from a remote peer.
    #[tracing::instrument(name = "marshal.resolver.produce", level = "debug", skip_all, fields(key = %key))]
    async fn handle_produce<Buf: Buffer<V>>(
        &self,
        key: ResolverRequestFor<V>,
        response: oneshot::Sender<Bytes>,
        buffer: &Buf,
    ) {
        match key {
            Key::Block(commitment) => {
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy(block.encode());
            }
            Key::Finalized { height } => {
                let Some(finalization) = self.get_finalization_by_height(height).await else {
                    debug!(%height, "finalization missing on request");
                    return;
                };
                let Some(block) = self.get_finalized_block(height).await else {
                    debug!(%height, "finalized block missing on request");
                    return;
                };
                response.send_lossy((finalization, V::into_inner(block)).encode());
            }
            Key::Notarized { round } => {
                let Some(notarization) = self.cache.get_notarization(round).await else {
                    debug!(?round, "notarization missing on request");
                    return;
                };
                let commitment = notarization.proposal.payload;
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy((notarization, block).encode());
            }
        }
    }

    /// Handle a local subscription request for a block.
    #[allow(clippy::too_many_arguments)]
    async fn handle_subscribe<Buf: Buffer<V>>(
        &mut self,
        span: Span,
        fallback: CommitmentFallback,
        key: SubscriptionKeyFor<V>,
        response: oneshot::Sender<Arc<V::Block>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        waiters: &mut AbortablePool<Result<Arc<V::Block>, SubscriptionKeyFor<V>>>,
        buffer: &mut Buf,
    ) {
        let digest = match key {
            SubscriptionKey::Digest(digest) => digest,
            SubscriptionKey::Commitment(commitment) => V::commitment_to_inner(commitment),
        };

        let block = match key {
            SubscriptionKey::Digest(digest) => self.find_block_by_digest(buffer, digest).await,
            SubscriptionKey::Commitment(commitment) => {
                self.find_block_by_commitment(buffer, commitment).await
            }
        };
        if let Some(block) = block {
            response.send_lossy(block);
            return;
        }

        // We don't have the block locally. Local-only waits reach this point
        // without a round or height, so they only register a subscriber below.
        //
        // Round-based fetching is for notarized proposal lookups whose height is
        // not known before the request. Height-based fetching is only for callers
        // that already have a validated pruning height.
        match fallback {
            CommitmentFallback::FetchByRound { round } => {
                // Fetch the notarized proposal for this round. The response
                // must include a certificate so the commitment is tied to the
                // certified round context. The decoded block is heightable, but
                // that height is not known soon enough to key, coalesce, or prune
                // the in-flight resolver request.
                if self
                    .floor
                    .fetch_if_permitted(resolver, Request::notarized(round))
                    .denied()
                {
                    return;
                }
                debug!(?round, ?digest, "requested block missing");
            }
            CommitmentFallback::FetchByCommitment { height } => {
                let commitment = match key {
                    SubscriptionKey::Commitment(commitment) => commitment,
                    SubscriptionKey::Digest(_) => {
                        unreachable!("digest subscriptions cannot request commitment fallback")
                    }
                };

                // This path is only for accepted ancestry or finalized repair,
                // never for a candidate block's immediate parent.
                if self
                    .floor
                    .fetch_if_permitted(resolver, Request::certified_block(commitment, height))
                    .denied()
                {
                    return;
                }
                debug!(%height, ?commitment, ?digest, "requested certified ancestry block missing");
            }
            CommitmentFallback::Wait => {}
        }

        let round = match fallback {
            CommitmentFallback::FetchByRound { round } => Some(round),
            CommitmentFallback::Wait | CommitmentFallback::FetchByCommitment { .. } => None,
        };

        // Register subscriber.
        match key {
            SubscriptionKey::Digest(digest) => {
                debug!(?round, ?digest, "registering subscriber");
            }
            SubscriptionKey::Commitment(commitment) => {
                debug!(?round, ?commitment, ?digest, "registering subscriber");
            }
        }
        self.block_subscriptions
            .insert(span, key, response, waiters, buffer);
    }

    /// Verifies and installs a floor, fetching the anchor block if needed.
    async fn install_floor<Buf, R>(
        &mut self,
        finalization: Finalization<P::Scheme, V::Commitment>,
        skip_if_superseded: bool,
        resolver: &mut R,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        let round = finalization.round();
        if round <= self.floor.processed_round() {
            warn!(
                ?round,
                floor = ?self.floor.processed_round(),
                "floor not updated, below existing round floor"
            );
            return;
        }

        let Some(scoped) = self.provider.scoped(finalization.epoch()) else {
            panic!("floor finalization epoch unavailable");
        };
        assert!(
            finalization.verify(self.context.as_mut(), &scoped, &self.strategy),
            "floor finalization must verify"
        );

        let commitment = finalization.proposal.payload;
        let digest = V::commitment_to_inner(commitment);
        self.cache
            .put_finalization(round, digest, finalization.clone())
            .await;

        // A pending anchor at the same or a newer floor already blocks
        // progress. Keep waiting for it instead of replacing it.
        if skip_if_superseded && self.floor.has_pending_anchor_at_or_after(round) {
            return;
        }

        if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
            self.floor.await_anchor(finalization);
            assert!(self.ingest(block, buffer, application, resolver).await);
            return;
        }

        // The pending floor owns the next application sync point. Drop any
        // in-flight acks before they can advance the processed height past it.
        self.pending_acks.clear();

        debug!(?round, ?commitment, "starting fetch for floor block");
        self.floor.await_anchor(finalization);
        self.floor
            .fetch_if_permitted(
                resolver,
                Request::finalized_block_by_round(commitment, round),
            )
            .ignore();
    }

    /// Ingests `block` and persists it as a verify-stage candidate for `round`,
    /// delivering the write's durable-sync handle through `ack`.
    ///
    /// If the round has already been pruned by tip advancement, `put_verified`
    /// is a no-op because the round is below the retention floor (and no longer
    /// is required by consensus to make progress). A duplicate delivery is also
    /// a no-op, with the handle still covering the original write's durability.
    async fn persist_verified<Buf: Buffer<V>>(
        &mut self,
        round: Round,
        block: Arc<V::Block>,
        ack: oneshot::Sender<Handle<()>>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        self.ingest(Arc::clone(&block), buffer, application, resolver)
            .await;
        let digest = block.digest();
        let handle = self
            .cache
            .put_verified(round, digest, Arc::unwrap_or_clone(block).into())
            .await;
        ack.send_lossy(handle);
    }

    /// Notifies subscribers of a validated block and applies it to any
    /// pending floor transition.
    ///
    /// Subscribers are notified before the block is persisted. This is not
    /// observable while running because mailbox requests are only served
    /// after the current `select_loop!` arm completes. After an unclean
    /// shutdown, however, a subscriber may hold a block that marshal never
    /// durably stored. Subscriptions make no durability promise. Durable
    /// height-ordered delivery is provided by application dispatch, which
    /// only sends blocks once the finalized archives are durable (see
    /// [`Self::try_dispatch_blocks`]).
    ///
    /// Returns true if the block was consumed as the floor anchor.
    async fn ingest<Buf: Buffer<V>>(
        &mut self,
        block: Arc<V::Block>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) -> bool {
        self.block_subscriptions.notify(Arc::clone(&block));

        if !self.floor.matches_pending_anchor(V::commitment(&block)) {
            return false;
        }

        self.apply_pending_floor(block, buffer, application, resolver)
            .await;
        true
    }

    /// Applies the pending floor transition using its matching anchor block.
    ///
    /// # Panics
    ///
    /// Panics if no pending floor anchor is installed.
    async fn apply_pending_floor<Buf: Buffer<V>>(
        &mut self,
        block: Arc<V::Block>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        // Floor anchors can bypass the local proposal-verification path. Check
        // the parent relationship before using a non-genesis anchor for walkback.
        let height = block.height();
        if height > Height::zero() {
            let parent_commitment = V::parent_commitment(&block);
            assert!(
                block.parent() == V::commitment_to_inner(parent_commitment),
                "floor block parent commitment mismatch"
            );
        }

        // This anchor cannot move the application sync point, but its
        // finalization round can still prune round-bound resolver work.
        // Keep pending acks intact because processed_height is unchanged.
        if height <= self.floor.processed_height() {
            warn!(
                %height,
                existing = %self.floor.processed_height(),
                "floor not updated, at or below existing"
            );
            let finalization = self
                .floor
                .take_pending_anchor()
                .expect("pending floor anchor missing");
            self.update_processed_round_floor(height, finalization.round(), resolver)
                .await;
            if self.try_repair_gaps(buffer, resolver, application).await {
                self.sync_finalized().await;
            }
            self.try_dispatch_blocks(application).await;
            return;
        }

        let digest = block.digest();
        let finalization = self
            .floor
            .take_pending_anchor()
            .expect("pending floor anchor missing");
        let round = finalization.round();
        try_join!(
            async {
                self.finalized_blocks
                    .put(Arc::unwrap_or_clone(block).into())
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .put(height, digest, finalization)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )
        .expect("failed to store floor anchor");
        self.sync_finalized().await;

        if height > self.tip {
            application.report(Update::Tip(round, height, digest));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // The anchor is durable, but the application still needs to process it.
        // Record the previous height so dispatch resumes at the anchor itself.
        let dispatch_floor = height
            .previous()
            .expect("floor anchor above processed height must have predecessor");
        self.update_processed_height(dispatch_floor, resolver);
        self.update_processed_round_floor(dispatch_floor, round, resolver)
            .await;
        self.stream
            .sync()
            .await
            .expect("failed to sync floor metadata");

        // Drop all pending acknowledgement waiters so any in-flight application
        // acks for blocks below the new floor cannot rewrite the processed floor.
        self.pending_acks.clear();

        // The floor is durable, so cache/finalized data below it can be pruned.
        self.prune_after_floor(height)
            .await
            .expect("failed to prune data below floor");

        // Intentionally keep existing block subscriptions alive. Canceling
        // waiters can have catastrophic consequences (nodes can get stuck in
        // different views) as actors do not retry subscriptions on failed channels.
        if self.try_repair_gaps(buffer, resolver, application).await {
            self.sync_finalized().await;
        }
        self.try_dispatch_blocks(application).await;
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    async fn handle_deliver<Buf: Buffer<V>>(
        &mut self,
        message: ResolverDelivery<V>,
        delivers: &mut Vec<PendingVerification<P::Scheme, V>>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        let ResolverDelivery {
            delivery,
            mut value,
            response,
        } = message;
        let Delivery {
            key, subscribers, ..
        } = delivery;
        match key {
            Key::Block(commitment) => {
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value.as_ref(), &block_cfg) else {
                    response.send_lossy(false);
                    return;
                };
                if V::commitment(&block) != commitment {
                    response.send_lossy(false);
                    return;
                }

                // This block may match the pending floor request. Whether it
                // installs or is rejected as the floor anchor, do not also
                // process it as an ordinary block delivery.
                let block = Arc::new(block);
                if self
                    .ingest(Arc::clone(&block), buffer, application, resolver)
                    .await
                {
                    response.send_lossy(true);
                    return;
                }

                // The peer-visible request only says "give me this block".
                // Local annotations explain why the block was requested and
                // therefore where, if anywhere, it should be stored.
                let height = block.height();
                let digest = block.digest();
                let annotations = subscribers
                    .map_into(|(annotation, _)| annotation)
                    .into_vec();

                // Round-bound proposal-parent fetches are `Key::Notarized`
                // deliveries and are handled below. In this block-keyed path,
                // `Finalized` means the block belongs in the finalized chain.
                let finalization = self.cache.get_finalization_for(digest).await;
                if let Some(finalization) = &finalization {
                    self.update_processed_round_floor(height, finalization.round(), resolver)
                        .await;
                }
                if finalization.is_some()
                    || annotations
                        .iter()
                        .any(|annotation| matches!(annotation, Annotation::Finalized(_)))
                {
                    self.store_finalization(
                        height,
                        digest,
                        Arc::unwrap_or_clone(block),
                        finalization,
                        application,
                    )
                    .await;
                } else if annotations
                    .iter()
                    .any(|annotation| matches!(annotation, Annotation::Certified { .. }))
                    && height > self.floor.processed_height()
                {
                    if let Some(bounds) = self.epocher.containing(height) {
                        self.cache
                            .put_certified(
                                bounds.epoch(),
                                height,
                                digest,
                                Arc::unwrap_or_clone(block).into(),
                            )
                            .await;
                    }
                }
                debug!(?digest, %height, "received block");
                response.send_lossy(true);
            }
            Key::Finalized { height } => {
                let Some((epoch, certificate_codec_config)) =
                    self.certificate_codec_config_for_height(height)
                else {
                    debug!(
                        %height,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return;
                };

                let Ok(finalization) =
                    Finalization::read_cfg(&mut value, &certificate_codec_config)
                else {
                    response.send_lossy(false);
                    return;
                };

                // We decoded the certificate with the codec config for the height's epoch, so the
                // finalization must claim that same epoch. A mismatch means the bytes were bounded
                // against the wrong participant set, so reject before verification.
                if finalization.epoch() != epoch {
                    response.send_lossy(false);
                    return;
                }

                // Decode the block carried with the finalization. Below, it is checked against
                // the requested height and the finalization payload.
                let Ok(block) =
                    V::ApplicationBlock::decode_cfg(&mut value, &self.block_codec_config)
                else {
                    response.send_lossy(false);
                    return;
                };

                // In contrast to the `Block` and `Notarization` deliveries, the finalization delivery
                // is guaranteed to be certified (assuming the certificate verifies). Because of this,
                // we can skip broader payload checks and just check that the application block matches
                // the commitment in the finalization proposal.
                //
                // TODO(https://github.com/commonwarexyz/monorepo/issues/3938): Apply this pattern
                // conditionally to `Request::Block` and `Request::Notarized`, if the requester knows
                // the requested block is certified.
                let commitment = finalization.proposal.payload;
                if block.height() != height || block.digest() != V::commitment_to_inner(commitment)
                {
                    response.send_lossy(false);
                    return;
                }
                delivers.push(PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                });
            }
            Key::Notarized { round } => {
                let Some(scheme) = self.provider.scheme(round.epoch()) else {
                    debug!(
                        ?round,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return;
                };
                let certificate_codec_config = scheme.certificate_codec_config();
                let Ok(notarization) =
                    Notarization::read_cfg(&mut value, &certificate_codec_config)
                else {
                    response.send_lossy(false);
                    return;
                };

                // The resolver key binds this response to `round`; a certificate for any other
                // round is a bad response even if it decodes correctly.
                if notarization.round() != round {
                    response.send_lossy(false);
                    return;
                }

                // Use the notarization payload to derive the block decode config. Below, the
                // decoded block is checked against the same payload.
                let commitment = notarization.proposal.payload;
                if !V::check_payload(scheme.as_ref(), commitment) {
                    response.send_lossy(false);
                    return;
                }
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value, &block_cfg) else {
                    response.send_lossy(false);
                    return;
                };

                if V::commitment(&block) != notarization.proposal.payload {
                    response.send_lossy(false);
                    return;
                }
                delivers.push(PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                });
            }
        }
    }

    /// Batch verify pending certificates and process valid items.
    #[tracing::instrument(name = "marshal.actor.verify_delivered", level = "info", skip_all, fields(count = delivers.len().traced()))]
    async fn verify_delivered<Buf: Buffer<V>>(
        &mut self,
        mut delivers: Vec<PendingVerification<P::Scheme, V>>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        delivers.retain(|item| !item.response_closed());
        if delivers.is_empty() {
            return;
        }

        // Extract (subject, certificate) pairs for batch verification.
        let certs: Vec<_> = delivers
            .iter()
            .map(|item| match item {
                PendingVerification::Finalized { finalization, .. } => (
                    Subject::Finalize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                ),
                PendingVerification::Notarized { notarization, .. } => (
                    Subject::Notarize {
                        proposal: &notarization.proposal,
                    },
                    &notarization.certificate,
                ),
            })
            .collect();

        // Group indices by epoch.
        let mut by_epoch: BTreeMap<Epoch, Vec<usize>> = BTreeMap::new();
        for (i, item) in delivers.iter().enumerate() {
            let epoch = match item {
                PendingVerification::Notarized { notarization, .. } => notarization.epoch(),
                PendingVerification::Finalized { finalization, .. } => finalization.epoch(),
            };
            by_epoch.entry(epoch).or_default().push(i);
        }

        // Batch verify each epoch group.
        let mut verified = vec![false; delivers.len()];
        for (epoch, indices) in &by_epoch {
            let Some(scoped) = self.provider.scoped(*epoch) else {
                continue;
            };
            let group: Vec<_> = indices.iter().map(|&i| certs[i]).collect();
            let results =
                verify_certificates(self.context.as_mut(), &scoped, &group, &self.strategy);
            for (j, &idx) in indices.iter().enumerate() {
                verified[idx] = results[j];
            }
        }

        // Process each verified item, rejecting unverified ones.
        for (index, item) in delivers.drain(..).enumerate() {
            if !verified[index] {
                match item {
                    PendingVerification::Finalized { response, .. }
                    | PendingVerification::Notarized { response, .. } => {
                        response.send_lossy(false);
                    }
                }
                continue;
            }
            match item {
                PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                } => {
                    // Valid finalization received.
                    response.send_lossy(true);
                    let block = Arc::new(V::from_application_block(
                        block,
                        finalization.proposal.payload,
                    ));
                    let round = finalization.round();
                    let height = block.height();
                    let digest = block.digest();
                    debug!(?round, %height, "received finalization");

                    // The floor-anchor path fully handles this finalization
                    // and moves the lower bound past it.
                    if self
                        .ingest(Arc::clone(&block), buffer, application, resolver)
                        .await
                    {
                        continue;
                    }

                    self.update_processed_round_floor(height, round, resolver)
                        .await;

                    self.store_finalization(
                        height,
                        digest,
                        Arc::unwrap_or_clone(block),
                        Some(finalization),
                        application,
                    )
                    .await;
                }
                PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                } => {
                    // Valid notarization received.
                    response.send_lossy(true);
                    let round = notarization.round();
                    let commitment = notarization.proposal.payload;
                    let digest = V::commitment_to_inner(commitment);
                    debug!(?round, ?digest, "received notarization");

                    // Cache the notarization and block, blocking until both are
                    // durable (or the runtime is shutting down) so the repair
                    // bookkeeping below never runs ahead of storage.
                    let height = block.height();
                    let block = Arc::new(block);
                    let block_sync = self
                        .cache
                        .put_notarized(round, digest, block.as_ref().clone().into())
                        .await;
                    let notarization_sync = self
                        .cache
                        .put_notarization(round, digest, notarization)
                        .await;
                    join(
                        block_sync.durable(round, "notarized"),
                        notarization_sync.durable(round, "notarization"),
                    )
                    .await;

                    // A notarized delivery can carry the pending floor block
                    // after the finalization is cached.
                    if self
                        .ingest(Arc::clone(&block), buffer, application, resolver)
                        .await
                    {
                        continue;
                    }

                    // If there exists a finalization certificate for this block, we
                    // should finalize it. This could finalize the block faster when
                    // a notarization then a finalization are received via consensus
                    // and we resolve the notarization request before the block request.
                    if let Some(finalization) = self.cache.get_finalization_for(digest).await {
                        self.update_processed_round_floor(height, finalization.round(), resolver)
                            .await;

                        // SAFETY: `digest` identifies a unique `commitment`, so this
                        // cached finalization payload must match `V::commitment(&block)`.
                        self.store_finalization(
                            height,
                            digest,
                            Arc::unwrap_or_clone(block),
                            Some(finalization),
                            application,
                        )
                        .await;
                    }
                }
            }
        }
    }

    /// Returns the certificate codec config for `epoch`.
    fn certificate_codec_config(
        &self,
        epoch: Epoch,
    ) -> Option<<<P::Scheme as Verifier>::Certificate as Read>::Cfg> {
        self.provider
            .scoped(epoch)
            .map(|scoped| scoped.certificate_codec_config())
    }

    /// Returns the epoch containing `height` and its certificate codec config.
    fn certificate_codec_config_for_height(
        &self,
        height: Height,
    ) -> Option<(Epoch, <<P::Scheme as Verifier>::Certificate as Read>::Cfg)> {
        let epoch = self.epocher.containing(height)?.epoch();
        self.certificate_codec_config(epoch)
            .map(|config| (epoch, config))
    }

    // -------------------- Application Dispatch --------------------

    /// Attempt to dispatch the next finalized block to the application if ready.
    ///
    /// Dispatch finalized blocks to the application until the pipeline is full
    /// or no more blocks are available.
    ///
    /// This does NOT advance the processed floor height or sync metadata. It only
    /// sends blocks to the application and enqueues pending acks. Metadata is
    /// updated later, in a subsequent `select_loop!` iteration, when the ack
    /// handler updates the processed height.
    ///
    /// Blocks are dispatched only once durable. Every buffered
    /// finalized-archive write freezes dispatch at or above its height until
    /// a sync covering it completes (see [`DispatchGate`]). Dispatch is
    /// re-attempted by the pool-completion arm for pooled syncs and by the
    /// caller itself after a blocking sync. Callers that buffer writes must
    /// still call [`Self::sync_finalized`] or [`Self::start_finalized_sync`]
    /// before yielding to the `select_loop!` so the freeze is released.
    ///
    /// Acks are processed in FIFO order so the processed floor height always
    /// advances sequentially.
    ///
    /// # Crash safety
    ///
    /// Because `select_loop!` arms run to completion, archive data is always
    /// durable before the ack handler advances the processed floor height:
    ///
    /// ```text
    /// Iteration N (caller):
    ///   store_finalization   ->  Archive::put (buffered)
    ///   sync_finalized       ->  archive durable
    ///   try_dispatch_blocks  ->  sends durable blocks to app, enqueues pending acks
    ///
    /// Iteration M (ack handler, M > N):
    ///   ack handler       ->  update_processed_height  ->  metadata buffered
    ///   stream.sync       ->  metadata durable
    /// ```
    async fn try_dispatch_blocks(
        &mut self,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) {
        // Dispatch resumes after the floor anchor is durably stored.
        if self.floor.blocks_progress() {
            return;
        }

        // Durability barrier: buffered writes are readable from the archives
        // before they are durable. Never dispatch at or above the lowest
        // write not yet covered by a completed sync.
        let barrier = self.dispatch_gate.barrier();
        while self.pending_acks.has_capacity() {
            let next_height = self
                .pending_acks
                .next_dispatch_height(self.stream.next_height());
            if barrier.is_some_and(|lowest| next_height >= lowest) {
                return;
            }
            let Some(block) = self.get_finalized_block(next_height).await else {
                return;
            };
            assert_eq!(
                block.height(),
                next_height,
                "finalized block height mismatch"
            );

            let (height, commitment) = (block.height(), V::commitment(&block));
            let (ack, ack_waiter) = A::handle();
            application.report(Update::Block(V::owned_into_inner_shared(block), ack));
            self.pending_acks.enqueue(PendingAck {
                height,
                commitment,
                receiver: ack_waiter,
            });
        }
    }

    // -------------------- Prunable Storage --------------------

    /// Sync both finalization archives to durable storage, blocking the actor
    /// until they are durable.
    ///
    /// Must be called within the same `select_loop!` arm as any preceding
    /// [`Self::store_finalization`] / [`Self::try_repair_gaps`] writes, before yielding back
    /// to the loop. This is the durability barrier for application delivery:
    /// [`Self::try_dispatch_blocks`] must run only after this sync completes.
    /// It also ensures archives are durable before the ack handler advances
    /// the processed floor height. See [`Self::try_dispatch_blocks`] for details.
    ///
    /// Blocking the actor stalls every mailbox caller behind the sync.
    /// Prefer [`Self::start_finalized_sync`] unless work later in the same
    /// arm requires the writes to already be durable.
    #[tracing::instrument(name = "marshal.actor.sync_finalized", level = "info", skip_all)]
    async fn sync_finalized(&mut self) {
        if let Err(e) = try_join!(
            async {
                self.finalized_blocks.sync().await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .sync()
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
        ) {
            panic!("failed to sync finalization archives: {e}");
        }

        // Everything accepted before this sync is now durable, so nothing
        // remains to gate dispatch.
        self.dispatch_gate.clear();
    }

    /// Start a non-blocking sync of both finalization archives on the
    /// durability pool. A no-op if nothing was written since the last sync
    /// (blocking or pooled) started.
    ///
    /// The pooled entry resolves to [`PooledSync::Finalized`] once every write
    /// accepted before this call is durable. The sync adopts every deferred
    /// write (see [`DispatchGate::adopt`]), and until the pool-completion arm
    /// observes the completion, [`Self::try_dispatch_blocks`] will not
    /// dispatch at or above the lowest height a pending batch wrote. This
    /// preserves the durability barrier described there without blocking the
    /// mailbox on a sync like [`Self::sync_finalized`].
    ///
    /// Like [`Self::sync_finalized`], this must be called within the same
    /// `select_loop!` arm as the writes it covers, before yielding back to the
    /// loop. `round` only labels the sync in diagnostics.
    #[tracing::instrument(name = "marshal.actor.start_finalized_sync", level = "info", skip_all)]
    async fn start_finalized_sync(&mut self, round: Round, syncs: &mut Pool<PooledSync>) {
        // If no write needs syncing, every accepted write is already covered
        // by a blocking or in-flight sync.
        let Some(seq) = self.dispatch_gate.adopt() else {
            return;
        };

        let (blocks, finalizations) = match try_join!(
            async {
                let handle = self.finalized_blocks.start_sync().await.map_err(Box::new)?;
                Ok::<_, BoxedError>(handle)
            },
            async {
                let handle = self
                    .finalizations_by_height
                    .start_sync()
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(handle)
            },
        ) {
            Ok(handles) => handles,
            Err(e) => panic!("failed to start finalization archive sync: {e}"),
        };
        syncs.push(async move {
            let (blocks, finalizations) = join(
                blocks.durable(round, "finalized blocks"),
                finalizations.durable(round, "finalizations"),
            )
            .await;
            if blocks && finalizations {
                PooledSync::Finalized(seq)
            } else {
                // Runtime shutdown before the sync completed: nothing may be
                // released for dispatch.
                PooledSync::Observed
            }
        });
    }

    // -------------------- Immutable Storage --------------------

    /// Get a finalized block from the immutable archive.
    async fn get_finalized_block(&self, height: Height) -> Option<V::Block> {
        match self
            .finalized_blocks
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(stored) => stored.map(|stored| stored.into()),
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: Height,
    ) -> Option<Finalization<P::Scheme, V::Commitment>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Check whether a finalization exists in the archive at `height` without
    /// fetching it.
    async fn has_finalization_by_height(&self, height: Height) -> bool {
        match self.finalizations_by_height.has(height).await {
            Ok(has) => has,
            Err(e) => panic!("failed to check finalization: {e}"),
        }
    }

    /// Get finalized block information from either the finalization archive or
    /// the finalized-block archive.
    async fn get_info_by_height(
        &self,
        height: Height,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        if let Some(finalization) = self.get_finalization_by_height(height).await {
            return Some((
                height,
                V::commitment_to_inner(finalization.proposal.payload),
            ));
        }

        self.get_finalized_block(height)
            .await
            .map(|block| (block.height(), block.digest()))
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// After persisting the block, the caller must sync finalized archives
    /// before dispatching the next contiguous block to the application. The
    /// buffered archive writes from this method are not a sufficient durability
    /// guarantee for downstream application state transitions on their own.
    ///
    /// Writes are buffered and not synced. The caller must call
    /// [sync_finalized](Self::sync_finalized) (blocking) or
    /// [start_finalized_sync](Self::start_finalized_sync) (pooled) before
    /// yielding to the `select_loop!` so that archive data is durable before
    /// the ack handler advances the processed floor height. See
    /// [`Self::try_dispatch_blocks`] for the crash safety invariant.
    async fn store_finalization(
        &mut self,
        height: Height,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
        finalization: Option<Finalization<P::Scheme, V::Commitment>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) -> bool {
        // Blocks below the last processed height are not useful to us, so we ignore them (this
        // has the nice byproduct of ensuring we don't call a backing store with a block below the
        // pruning boundary)
        if height <= self.floor.processed_height() {
            debug!(
                %height,
                floor = %self.floor.processed_height(),
                ?digest,
                "dropping finalization at or below processed height floor"
            );
            return false;
        }

        // Convert block to storage format
        let stored: V::StoredBlock = block.into();
        let round = finalization.as_ref().map(|f| f.round());

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            async {
                self.finalized_blocks.put(stored).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put(height, digest, finalization)
                        .await
                        .map_err(Box::new)?;
                }
                Ok::<_, BoxedError>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        // The write above is buffered and readable before it is durable, so
        // hold dispatch at or above it until a sync covers it.
        self.dispatch_gate.defer(height);

        // Update metrics and application
        if let Some(round) = round.filter(|_| height > self.tip) {
            application.report(Update::Tip(round, height, digest));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        true
    }

    /// Get the latest finalized block information (height and digest tuple).
    ///
    /// Blocks are only finalized directly with a finalization or indirectly via a descendant
    /// block's finalization. Thus, the highest known finalized block must itself have a direct
    /// finalization.
    ///
    /// We return the height and digest using the highest known finalization that we know the
    /// block height for. While it's possible that we have a later finalization, if we do not have
    /// the full block for that finalization, we do not know its height and therefore it would not
    /// yet be found in the `finalizations_by_height` archive. While not checked explicitly, we
    /// should have the associated block (in the `finalized_blocks` archive) for the information
    /// returned.
    async fn get_latest(&mut self) -> Option<(Height, <V::Block as Digestible>::Digest, Round)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((
            height,
            V::commitment_to_inner(finalization.proposal.payload),
            finalization.round(),
        ))
    }

    // -------------------- Mixed Storage --------------------

    /// Looks for a block in cache and finalized storage by digest.
    async fn find_block_in_storage(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<V::Block> {
        // Check verified / notarized blocks via cache manager.
        if let Some(block) = self.cache.find_block_matching(digest, |_| true).await {
            return Some(block.into());
        }
        // Check finalized blocks.
        match self.finalized_blocks.get(ArchiveID::Key(&digest)).await {
            Ok(stored) => stored.map(|stored| stored.into()),
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Looks for a block in cache and finalized storage by full consensus commitment.
    async fn find_block_in_storage_by_commitment(
        &self,
        commitment: V::Commitment,
    ) -> Option<V::Block> {
        let digest = V::commitment_to_inner(commitment);
        if let Some(block) = self
            .cache
            .find_block_matching(digest, |stored| V::stored_commitment(stored) == commitment)
            .await
        {
            return Some(block.into());
        }

        match self.finalized_blocks.get(ArchiveID::Key(&digest)).await {
            Ok(Some(stored)) => {
                (V::stored_commitment(&stored) == commitment).then(|| stored.into())
            }
            Ok(None) => None,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Looks for a block anywhere in local storage using only the digest.
    ///
    /// This is used when we only have a digest (during gap repair following
    /// parent links).
    async fn find_block_by_digest<Buf: Buffer<V>>(
        &self,
        buffer: &Buf,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<Arc<V::Block>> {
        if let Some(block) = buffer.find_by_digest(digest).await {
            return Some(block);
        }
        self.find_block_in_storage(digest).await.map(Arc::new)
    }

    /// Looks for a block anywhere in local storage using the full commitment.
    ///
    /// This is used when we have a full commitment (from notarizations/finalizations).
    /// Having the full commitment may enable additional retrieval mechanisms.
    async fn find_block_by_commitment<Buf: Buffer<V>>(
        &self,
        buffer: &Buf,
        commitment: V::Commitment,
    ) -> Option<Arc<V::Block>> {
        if let Some(block) = buffer.find_by_commitment(commitment).await {
            return Some(block);
        }
        self.find_block_in_storage_by_commitment(commitment)
            .await
            .map(Arc::new)
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive. The total
    /// number of missing heights that can be repaired at once is bounded by `self.max_repair`,
    /// though multiple gaps may be spanned.
    ///
    /// This also handles the "trailing" case where finalizations exist beyond
    /// the last stored block (the block data was lost before a crash). The
    /// trailing block is anchored first so that backward gap repair can fill
    /// inward from it.
    ///
    /// Writes are buffered. Returns `true` if this call wrote repaired blocks and
    /// needs a subsequent [`sync_finalized`](Self::sync_finalized).
    #[tracing::instrument(name = "marshal.actor.try_repair_gaps", level = "info", skip_all)]
    async fn try_repair_gaps<Buf: Buffer<V>>(
        &mut self,
        buffer: &mut Buf,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) -> bool {
        // Gap repair needs a known processed floor. A floor transition may
        // jump the lower bound once its anchor block arrives.
        if self.floor.blocks_progress() {
            return false;
        }

        let mut wrote = false;
        let start = self.floor.processed_height().next();

        // If finalizations extend beyond the last stored block, anchor the
        // trailing block so the gap repair loop below can walk backward from it.
        if let Some(last_finalized) = self.finalizations_by_height.last_index() {
            let have_block = self
                .finalized_blocks
                .last_index()
                .is_some_and(|last| last >= last_finalized);
            if last_finalized > self.floor.processed_height() && !have_block {
                // Get the finalization for the last finalized block.
                let finalization = self
                    .get_finalization_by_height(last_finalized)
                    .await
                    .expect("finalization missing");
                let commitment = finalization.proposal.payload;
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    // If found, persist the block.
                    let digest = block.digest();
                    wrote |= self
                        .store_finalization(
                            last_finalized,
                            digest,
                            Arc::unwrap_or_clone(block),
                            Some(finalization),
                            application,
                        )
                        .await;
                } else {
                    // Request the missing block.
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_height(commitment, last_finalized),
                        )
                        .ignore();
                }
            }
        }

        // Fill internal gaps by walking backward from each gap's end block.
        'cache_repair: loop {
            let (gap_start, Some(gap_end)) = self.finalized_blocks.next_gap(start) else {
                // No gaps detected
                return wrote;
            };

            // Attempt to repair the gap backwards from the end of the gap, using
            // blocks from our local storage. The walkback only needs each
            // block's height and parent linkage.
            let Some(cursor) = self.get_finalized_block(gap_end).await else {
                panic!("gapped block missing that should exist: {gap_end}");
            };
            let (mut height, mut parent_digest, mut parent_commitment) = (
                cursor.height(),
                cursor.parent(),
                V::parent_commitment(&cursor),
            );

            // Compute the lower bound of the recursive repair. `gap_start` is `Some`
            // if `start` is not in a gap. We add one to it to ensure we don't
            // re-persist it to the database in the repair loop below.
            let gap_start = gap_start.map(Height::next).unwrap_or(start);

            // Iterate backwards, repairing blocks as we go.
            while height > gap_start {
                if let Some(block) = self
                    .find_block_by_commitment(buffer, parent_commitment)
                    .await
                {
                    let finalization = self.cache.get_finalization_for(parent_digest).await;
                    let next = (block.height(), block.parent(), V::parent_commitment(&block));
                    wrote |= self
                        .store_finalization(
                            next.0,
                            parent_digest,
                            Arc::unwrap_or_clone(block),
                            finalization,
                            application,
                        )
                        .await;
                    debug!(height = %next.0, "repaired block");
                    (height, parent_digest, parent_commitment) = next;
                } else {
                    // Request the next missing commitment.
                    //
                    // SAFETY: Finalized blocks are archived only after the
                    // parent relationship needed for walkback has been
                    // validated by marshal.
                    let parent_height = height
                        .previous()
                        .expect("cursor above gap start has a parent");
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_height(parent_commitment, parent_height),
                        )
                        .ignore();
                    break 'cache_repair;
                }
            }
        }

        // Request any finalizations for missing items in the archive, up to
        // the `max_repair` quota. This may help shrink the size of the gap
        // closest to the application's processed height if finalizations
        // for the requests' heights exist. If not, we rely on the recursive
        // digest fetches above.
        let missing_items = self
            .finalized_blocks
            .missing_items(start, self.max_repair.get());
        let requests: Vec<_> = missing_items.into_iter().map(Request::finalized).collect();
        if !requests.is_empty() {
            self.floor
                .fetch_all_if_permitted(resolver, requests)
                .ignore();
        }
        wrote
    }

    /// Buffers a processed height update in memory and metrics. Does NOT sync
    /// to durable storage. Sync metadata after buffered updates to make them durable.
    fn update_processed_height(
        &mut self,
        height: Height,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        self.stream.acknowledge(height);
        self.floor.set_processed_height(height);
        let _ = self
            .processed_height
            .try_set(self.floor.processed_height().get());

        // Prune any existing requests below the new floor.
        resolver.retain(handler::above_height_floor::<V::Commitment>(height));
    }

    /// Returns the latest known finalization round at or below the processed height.
    async fn latest_processed_round(finalizations_by_height: &FC, height: Option<Height>) -> Round {
        let Some(height) = height else {
            return Round::zero();
        };
        let Some(finalization_height) = finalizations_by_height
            .ranges_from(Height::zero())
            .filter_map(|(start, end)| (start <= height).then_some(end.min(height)))
            .max()
        else {
            return Round::zero();
        };

        match finalizations_by_height
            .get(ArchiveID::Index(finalization_height.get()))
            .await
        {
            Ok(Some(finalization)) => finalization.round(),
            Ok(None) => panic!("processed finalization missing from stored range"),
            Err(err) => panic!("failed to get processed finalization: {err}"),
        }
    }

    /// Buffers a processed round update in memory and prunes round-bound requests.
    async fn update_processed_round(
        &mut self,
        height: Height,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        let Some(finalization) = self.get_finalization_by_height(height).await else {
            return;
        };
        self.update_processed_round_floor(height, finalization.round(), resolver)
            .await;
    }

    /// Buffers a processed round floor update in memory and prunes round-bound requests.
    async fn update_processed_round_floor(
        &mut self,
        height: Height,
        round: Round,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        if height > self.floor.processed_height() || round <= self.floor.processed_round() {
            return;
        }

        let previous = self.floor.processed_round();
        self.floor.set_processed_round(round);

        // Retain view-indexed cache data for a window behind the previously
        // processed finalized block.
        let prune_round = Round::new(
            previous.epoch(),
            previous.view().saturating_sub(self.view_retention_timeout),
        );
        self.cache.prune_by_view(prune_round).await;

        // Prune round-bound requests at or below the processed round.
        resolver.retain(handler::above_round_floor::<V::Commitment>(
            self.floor.processed_round(),
        ));
    }

    /// Prunes finalized blocks and certificates below the given height.
    async fn prune_finalized_archives(&mut self, height: Height) -> Result<(), BoxedError> {
        // Prune the finalized block and finalization certificate archives in parallel.
        try_join!(
            async {
                self.finalized_blocks
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }

    /// Prunes finalized archives and height-indexed certified cache data below the durable floor.
    async fn prune_after_floor(&mut self, height: Height) -> Result<(), BoxedError> {
        let cache = &mut self.cache;
        let finalized_blocks = &mut self.finalized_blocks;
        let finalizations_by_height = &mut self.finalizations_by_height;
        try_join!(
            async {
                cache.prune_by_height(height).await;
                Ok::<_, BoxedError>(())
            },
            async {
                finalized_blocks.prune(height).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }
}
