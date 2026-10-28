//! Wrapper for consensus applications that handles epochs and block dissemination.
//!
//! # Overview
//!
//! [`Deferred`] is an adapter that wraps any [`Application`] implementation to handle
//! epoch transitions automatically. It intercepts consensus operations (propose, verify) and
//! ensures blocks are only produced within valid epoch boundaries.
//!
//! # Epoch Boundaries
//!
//! When the parent is the last block in an epoch (as determined by the [`Epocher`]), this wrapper
//! re-proposes that boundary block instead of building a new block. This avoids producing blocks
//! that would be pruned by the epoch transition.
//!
//! # Deferred Verification
//!
//! Before casting a notarize vote, [`Deferred`] waits for the block to become available and
//! then verifies that the block's embedded context matches the consensus context. However, it does not
//! wait for the application to finish verifying the block contents before voting. This enables verification
//! to run while we wait for a quorum of votes to form a certificate (hiding verification latency behind network
//! latency). Once a certificate is formed, we wait on the verification result in [`CertifiableAutomaton::certify`]
//! before voting to finalize (ensuring no invalid blocks are admitted to the canonical chain).
//!
//! # Usage
//!
//! Wrap your [`Application`] implementation with [`Deferred::new`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let application = Deferred::new(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     epocher,
//! );
//! ```
//!
//! # Implementation Notes
//!
//! - Genesis blocks are handled specially: epoch 0 returns the application's genesis block,
//!   while subsequent epochs use the last block of the previous epoch as genesis
//! - Blocks are automatically verified to be within the current epoch
//!
//! # Notarization and Data Availability
//!
//! In rare crash cases, it is possible for a notarization certificate to exist without a block being
//! available to the honest parties. [`CertifiableAutomaton::certify`] may then remain pending while
//! it waits for the block. Simplex may time out and nullify the view without resolving that request.
//!
//! For this reason, it should not be expected that every notarized payload will be certifiable due
//! to the lack of an available block. However, if even one honest and online party has the block,
//! they will attempt to forward it to others via marshal's resolver.
//!
//! ```text
//!                                      ┌───────────────────────────────────────────────────┐
//!                                      ▼                                                   │
//! ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
//! │          B1         │◀──│          B2         │◀──│          B3         │XXX│          B4         │
//! └─────────────────────┘   └─────────────────────┘   └──────────┬──────────┘   └─────────────────────┘
//!                                                                │
//!                                                         Pending Certify
//! ```
//!
//! # Future Work
//!
//! - To further reduce view latency, a participant could optimistically vote for a block prior to
//!   observing its availability during [`Automaton::verify`]. However, this would require updating
//!   other components (like [`crate::marshal`]) to handle backfill where notarization does not imply
//!   a block is fetchable (without modification, a malicious leader that withholds blocks during propose
//!   could get an honest node to exhaust their network rate limit fetching things that don't exist rather
//!   than blocks they need AND can fetch).

use crate::{
    Application, Automaton, CertifiableAutomaton, CertifiableBlock, Epochable, Relay, Reporter,
    marshal::{
        Update,
        application::{
            gates::{self, GateOutcome, Gates},
            validation::{Stage, is_inferred_reproposal_at_certify},
        },
        core::{CommitmentFallback, DigestFallback, Mailbox},
        standard::{
            Standard, relay,
            validation::{
                Decision, ParentCheck, await_and_validate_parent, precheck_epoch_and_reproposal,
                run_app_verify,
            },
        },
    },
    simplex::{Plan, types::Context},
    types::{Epocher, Round},
};
use commonware_actor::Feedback;
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::{
        metrics::{
            MetricsExt as _,
            histogram::{Buckets, Timed},
        },
        traces::TracedExt as _,
    },
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::TracedAsyncMutex,
};
use rand_core::Rng;
use std::sync::Arc;
use tracing::{Instrument as _, debug, info, info_span};

/// An [`Application`] adapter that handles epoch transitions and validates block ancestry.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries and validate
/// block ancestry. It prevents blocks from being produced outside their valid epoch,
/// handles the special case of re-proposing boundary blocks at epoch boundaries,
/// and ensures all blocks have valid parent linkage and contiguous heights.
///
/// # Ancestry Validation
///
/// Applications wrapped by [`Deferred`] can rely on the following ancestry checks being
/// performed automatically during verification:
/// - Parent digest matches the consensus context's expected parent
/// - Block height is exactly one greater than the parent's height
///
/// Verifying only the immediate parent is sufficient since the parent was either notarized by
/// consensus, whose honest voters verified its context, or verified locally before this
/// participant voted for it (optimistic validation). Either way the entire ancestry chain back
/// to genesis is transitively validated.
///
/// Applications do not need to re-implement these checks in their own verification logic.
///
/// # Context Recovery
///
/// With deferred verification, validators wait for data availability (DA) and verify the context
/// before voting. If a validator crashes after voting but before certification, they lose their in-memory
/// certification gate task. When recovering, validators extract context from a [`CertifiableBlock`].
///
/// _This embedded context is trustworthy because the notarizing quorum (which contains at least f+1 honest
/// validators) verified that the block's context matched the consensus context before voting._
pub struct Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: CertifiableBlock,
    ES: Epocher,
{
    context: Arc<TracedAsyncMutex<E>>,
    application: A,
    marshal: Mailbox<S, Standard<B>>,
    epocher: ES,
    gates: Gates<<B as Digestible>::Digest, B>,

    build_duration: Timed,
    proposal_parent_fetch_duration: Timed,
    ancestor_fetch_duration: Timed,
    // TEMP probe: parent fetch wait for proposals whose parent was not local.
    proposal_parent_miss_duration: Timed,
}

impl<E, S, A, B, ES> Clone for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: CertifiableBlock,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            application: self.application.clone(),
            marshal: self.marshal.clone(),
            epocher: self.epocher.clone(),
            gates: self.gates.clone(),
            build_duration: self.build_duration.clone(),
            proposal_parent_fetch_duration: self.proposal_parent_fetch_duration.clone(),
            ancestor_fetch_duration: self.ancestor_fetch_duration.clone(),
            proposal_parent_miss_duration: self.proposal_parent_miss_duration.clone(),
        }
    }
}

impl<E, S, A, B, ES> Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    /// Creates a new [`Deferred`] wrapper.
    pub fn new(context: E, application: A, marshal: Mailbox<S, Standard<B>>, epocher: ES) -> Self {
        let build_histogram = context.histogram(
            "build_duration",
            "Histogram of time taken for the application to build a new block, in seconds",
            Buckets::LOCAL,
        );
        let build_duration = Timed::new(build_histogram);
        let parent_fetch_histogram = context.histogram(
            "parent_fetch_duration",
            "Histogram of time taken to fetch a parent block in propose, in seconds",
            Buckets::LOCAL,
        );
        let proposal_parent_fetch_duration = Timed::new(parent_fetch_histogram);
        let ancestor_fetch_histogram = context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        );
        let ancestor_fetch_duration = Timed::new(ancestor_fetch_histogram);
        let proposal_parent_miss_histogram = context.histogram(
            "parent_miss_duration",
            "TEMP probe: time to fetch a propose parent that was not available locally, in seconds",
            Buckets::LOCAL,
        );
        let proposal_parent_miss_duration = Timed::new(proposal_parent_miss_histogram);

        Self {
            context: Arc::new(TracedAsyncMutex::new("marshal.context", context)),
            application,
            marshal,
            epocher,
            gates: Gates::new(),

            build_duration,
            proposal_parent_fetch_duration,
            ancestor_fetch_duration,
            proposal_parent_miss_duration,
        }
    }

    /// Verifies a proposed block's application-level validity.
    ///
    /// This method validates that:
    /// 1. The block's parent digest matches the expected parent
    /// 2. The block's height is exactly one greater than the parent's height
    /// 3. The underlying application's verification logic passes
    ///
    /// The `parent_request` must be a subscription to the parent named by `context.parent`,
    /// started by the caller so the parent fetch can overlap work that precedes this call.
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Valid blocks are reported to the marshal as verified.
    #[inline]
    async fn deferred_verify(
        &mut self,
        context: <Self as Automaton>::Context,
        block: Arc<B>,
        parent_request: oneshot::Receiver<Arc<B>>,
        stage: Stage,
    ) -> oneshot::Receiver<GateOutcome> {
        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let (mut tx, rx) = oneshot::channel();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();
        let runtime_context = self
            .context
            .lock()
            .await
            .child("deferred_verify")
            .with_attribute("round", context.round);
        let span = info_span!(
            "marshal.deferred.verify.deferred",
            round = %context.round
        );
        runtime_context.spawn(move |runtime_context| {
            async move {
                let round = context.round;

                // Start the candidate store immediately: it depends on neither the
                // parent fetch (which may hit the network) nor the verdict below.
                // Storing before validation is intentional: these caches provide
                // candidate availability/recovery, not a validity decision. This
                // task gates the finalize vote by resolving true only after both
                // app verification succeeds and the store is durable.
                let store = stage.store(&marshal, round, Arc::clone(&block));
                let verify = async {
                    // Validate the parent we already started fetching.
                    let parent = match await_and_validate_parent(
                        context.parent.1,
                        block.as_ref(),
                        parent_request,
                        &mut tx,
                    )
                    .await
                    {
                        Some(ParentCheck::Valid(parent)) => parent,
                        Some(ParentCheck::Invalid) => return Some(false),
                        None => return None,
                    };
                    run_app_verify(
                        runtime_context,
                        context,
                        Arc::clone(&block),
                        parent,
                        &mut application,
                        &marshal,
                        &mut tx,
                        ancestor_fetch_duration,
                    )
                    .await
                };
                let (verdict, durable) = futures::join!(verify, store);

                // Publish only when the block is both valid and durable. App-invalid
                // candidates may already be in the cache from the concurrent store above,
                // so the gate verdict is the authority for consensus progress.
                if let Some(application_valid) = gates::resolve(verdict, durable) {
                    tx.send_lossy(GateOutcome::Ready(application_valid));
                }
            }
            .instrument(span)
        });

        rx
    }

    async fn certify_from_embedded_context(
        &mut self,
        round: Round,
        digest: B::Digest,
    ) -> oneshot::Receiver<bool> {
        // No in-progress task means we never verified this proposal locally. We can use the
        // block's embedded context to help complete finalization when Byzantine validators
        // withhold their finalize votes. If a Byzantine proposer embedded a malicious context,
        // the f+1 honest validators from the notarizing quorum will verify against the proper
        // context and reject the mismatch, preventing a 2f+1 finalization quorum.
        //
        // We must fetch here rather than only wait for local broadcast delivery. A Byzantine
        // leader can send a proposal to just f+1 honest validators, collect enough honest
        // notarize votes to form a notarization, and leave the remaining honest validators
        // without the block. Those validators need the notarized round to recover the block
        // and certify; otherwise they can remain stuck if the Byzantine validators stop
        // participating in the next view.
        //
        // Subscribe to the block and verify using its embedded context once available.
        debug!(
            ?round,
            ?digest,
            "subscribing to block for certification using embedded context"
        );
        let block_rx = self
            .marshal
            .subscribe_by_digest(digest, DigestFallback::FetchByRound { round });
        let mut marshaled = self.clone();
        let epocher = self.epocher.clone();
        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("certify")
            .with_attribute("round", round);
        context.spawn(move |_| {
            async move {
                let block = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping certification"
                        );
                        return;
                    },
                    result = block_rx => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?digest,
                                reason = "failed to fetch block for certification",
                                "skipping certification"
                            );
                            return;
                        }
                    },
                };

                // Re-proposal detection for certify path: we don't have the consensus context,
                // only the block's embedded context from original proposal. Infer re-proposal from:
                // 1. Block is at epoch boundary (only boundary blocks can be re-proposed)
                // 2. Certification round's view > embedded context's view (re-proposals retain their
                //    original embedded context, so a later view indicates the block was re-proposed)
                // 3. Same epoch (re-proposals don't cross epoch boundaries)
                let embedded_context = block.context();
                let is_reproposal = is_inferred_reproposal_at_certify(
                    &epocher,
                    block.height(),
                    embedded_context.round,
                    round,
                );
                if is_reproposal {
                    // Certifier holds a notarization for this block, so route
                    // the write to the notarized cache. `certified` is
                    // idempotent, so crash-recovery double-invocation is safe.
                    if !marshaled.marshal.certified(round, block).await {
                        return;
                    }
                    tx.send_lossy(true);
                    return;
                }

                // Start the parent fetch for the deferred verification below,
                // which expects a caller-started subscription. Certify does not
                // carry the consensus context, so the parent round comes from
                // the block's embedded context. That context is trustworthy
                // because the digest is notarized and the notarizing quorum's
                // f+1 honest validators verified it against the consensus
                // context before voting.
                let (parent_view, parent_commitment) = embedded_context.parent;
                let parent_request = marshaled.marshal.subscribe_by_commitment(
                    parent_commitment,
                    CommitmentFallback::FetchByRound {
                        round: Round::new(embedded_context.epoch(), parent_view),
                    },
                );

                let verify_rx = marshaled
                    .deferred_verify(embedded_context, block, parent_request, Stage::Certified)
                    .await;
                gates::forward(tx, verify_rx, |result| match result {
                    GateOutcome::Ready(result) => Some(result),
                    GateOutcome::Recover => None,
                })
                .await;
            }
            .instrument(info_span!(
                "marshal.deferred.certify.embedded",
                round = %round,
                digest = %digest
            ))
        });
        rx
    }

    #[allow(clippy::async_yields_async)]
    async fn certify_from_existing_task(
        &mut self,
        round: Round,
        digest: B::Digest,
        task: oneshot::Receiver<GateOutcome>,
    ) -> oneshot::Receiver<bool> {
        // `verify()` waits only on local broadcast delivery, so nudge a
        // round-bound notarized fetch that can unblock the existing waiter
        // if local broadcast never arrives. For the standard variant, the
        // digest is also the variant commitment.
        self.marshal.hint_notarized(round, digest);

        // A completed gate either carries an applicable local verdict or requests
        // recovery. After an unclean restart the in-memory task is gone, which also
        // recovers via the embedded-context fetch path.
        let mut marshaled = self.clone();
        let (tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("certify_existing")
            .with_attribute("round", round);
        context.spawn(move |_| {
            gates::drive(tx, task, round, digest, move || async move {
                marshaled.certify_from_embedded_context(round, digest).await
            })
            .instrument(info_span!(
                "marshal.deferred.certify.existing",
                round = %round,
                digest = %digest
            ))
        });
        rx
    }
}

impl<E, S, A, B, ES> Automaton for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    type Digest = B::Digest;
    type Context = Context<Self::Digest, S::PublicKey>;

    /// Proposes a new block or re-proposes the epoch boundary block.
    ///
    /// This method builds a new block from the underlying application unless the parent block
    /// is the last block in the current epoch. When at an epoch boundary, it re-proposes the
    /// boundary block to avoid creating blocks that would be invalidated by the epoch transition.
    ///
    /// The proposal operation is spawned in a background task and returns a receiver that will
    /// contain the proposed block's digest when ready. The block is staged before the digest is
    /// delivered and handed to marshal when consensus requests the relay broadcast, which
    /// persists it after the send. The resulting sync handle is awaited only at certification so
    /// it overlaps consensus voting. The digest does not imply durability on
    /// its own; [`CertifiableAutomaton::certify`] awaits the registered certification gate before
    /// the finalize vote.
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.deferred.propose", level = "info", skip_all, fields(round = %consensus_context.round))]
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let gates = self.gates.clone();

        // Metrics
        let build_duration = self.build_duration.clone();
        let proposal_parent_fetch_duration = self.proposal_parent_fetch_duration.clone();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();
        let proposal_parent_miss_duration = self.proposal_parent_miss_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("propose")
            .with_attribute("round", consensus_context.round);
        let span = info_span!(
            "marshal.deferred.propose.task",
            round = %consensus_context.round
        );
        context.spawn(move |runtime_context| {
            async move {
                // On leader recovery, marshal may already hold a verified block
                // for this round (persisted by a pre-crash propose that reached
                // its relay broadcast while the notarize vote never reached the
                // journal).
                //
                // The pre-crash digest may already have been broadcast, so
                // building a fresh block would equivocate. The stored block is
                // the only proposal we can broadcast for this round.
                //
                // The recovered block is safe to reuse only if its embedded
                // context matches the context simplex just recovered, or if it
                // is the parent re-proposed at the epoch boundary: that stores the
                // parent under its original context, whose round is the parent's own.
                // Otherwise the cached block was built against a different
                // parent and cannot be broadcast under the current header, so
                // drop the receiver and let the voter nullify the view via
                // timeout.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if let Some(block) = marshal.get_verified(consensus_context.round).await {
                    let block_context = block.context();
                    let digest = block.digest();
                    let reproposal =
                        digest == consensus_context.parent.1 && block.height() == last_in_epoch;
                    if !reproposal && block_context != consensus_context {
                        debug!(
                            round = ?consensus_context.round,
                            ?consensus_context,
                            ?block_context,
                            "skipping proposal: cached verified block context no longer matches"
                        );
                        return;
                    }
                    // Stage the recovered block so the relay broadcast re-sends
                    // it through the same handshake as a fresh proposal. The
                    // relay-time persist deduplicates against the pre-crash
                    // write, with the handle covering the original.
                    debug!(
                        round = ?consensus_context.round,
                        ?digest,
                        reproposal,
                        "reusing verified block from marshal on leader recovery"
                    );
                    gates
                        .stage(
                            consensus_context.round,
                            digest,
                            Arc::new(block),
                            tx,
                            "recovered block",
                        )
                        .await;
                    return;
                }

                // The parent for any consensus context is in the same epoch: the
                // boundary block of the previous epoch is the genesis block of the
                // current epoch.
                //
                // Proposal context carries the certified parent view/commitment but
                // not the parent height. The parent may be certified above the
                // finalized tip, so this must stay round-bound until the block is
                // returned.
                let (parent_view, parent_commitment) = consensus_context.parent;
                let (parent_request, mut parent_local) = marshal.subscribe_by_commitment_probed(
                    parent_commitment,
                    CommitmentFallback::FetchByRound {
                        round: Round::new(consensus_context.epoch(), parent_view),
                    },
                );

                // TEMP probe: parent_local resolves once marshal has handled the
                // subscription and says whether the parent was already local.
                let probe_start = runtime_context.current();
                let probe_round = consensus_context.round;
                let probe_elapsed_us = |ctx: &E| {
                    ctx.current()
                        .duration_since(probe_start)
                        .unwrap_or_default()
                        .as_micros() as u64
                };
                let parent_timer = proposal_parent_fetch_duration.timer(&runtime_context);
                let miss_timer = proposal_parent_miss_duration.timer(&runtime_context);
                let parent = select! {
                    _ = tx.closed() => {
                        let local = parent_local.try_recv().ok();
                        info!(
                            target: "parent_probe",
                            round = %probe_round,
                            parent_view = parent_view.get(),
                            ?local,
                            elapsed_us = probe_elapsed_us(&runtime_context),
                            outcome = "dropped",
                            "parent probe"
                        );
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
                            let local = parent_local.try_recv().ok();
                            info!(
                                target: "parent_probe",
                                round = %probe_round,
                                parent_view = parent_view.get(),
                                ?local,
                                elapsed_us = probe_elapsed_us(&runtime_context),
                                outcome = "failed",
                                "parent probe"
                            );
                            debug!(
                                ?parent_commitment,
                                reason = "failed to fetch parent block",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };
                parent_timer.observe(&runtime_context);
                // Marshal sends the local flag right after handling the subscription.
                let local = parent_local.await.ok();
                if local == Some(false) {
                    miss_timer.observe(&runtime_context);
                }
                info!(
                    target: "parent_probe",
                    round = %probe_round,
                    parent_view = parent_view.get(),
                    parent_height = parent.height().get(),
                    ?local,
                    elapsed_us = probe_elapsed_us(&runtime_context),
                    outcome = "ok",
                    "parent probe"
                );

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                if parent.height() == last_in_epoch {
                    let digest = parent.digest();
                    gates
                        .stage(
                            consensus_context.round,
                            digest,
                            parent,
                            tx,
                            "re-proposed boundary block",
                        )
                        .await;
                    return;
                }

                let ancestor_stream = marshal.ancestor_stream(
                    Arc::new(runtime_context.child("ancestor_stream")),
                    [parent],
                    ancestor_fetch_duration,
                );
                let build_request = application
                    .propose(
                        (
                            runtime_context.child("app_propose"),
                            consensus_context.clone(),
                        ),
                        ancestor_stream,
                        (),
                    )
                    .instrument(info_span!(
                        "marshal.deferred.application.propose",
                        round = %consensus_context.round,
                        parent_view = parent_view.traced(),
                        parent = %parent_commitment
                    ));

                let build_timer = build_duration.timer(&runtime_context);
                let built_block = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = build_request => match result {
                        Some(block) => block,
                        None => {
                            debug!(
                                ?parent_commitment,
                                reason = "block building failed",
                                "skipping proposal"
                            );
                            return;
                        }
                    },
                };
                build_timer.observe(&runtime_context);

                let digest = built_block.digest();
                gates
                    .stage(
                        consensus_context.round,
                        digest,
                        Arc::new(built_block),
                        tx,
                        "proposed block",
                    )
                    .await;
            }
            .instrument(span)
        });
        rx
    }

    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.deferred.verify", level = "info", skip_all, fields(round = %context.round, digest = %digest))]
    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let marshal = self.marshal.clone();
        let mut marshaled = self.clone();
        let round = context.round;

        // Verification needs the full block but waits only for local delivery. Certification starts
        // recovery only when the block is not buffered. If a buffered block is evicted before
        // verification registers its wait, verification is left with neither the block nor an
        // active fetch. Register the wait before publishing the gate so it receives the buffered
        // block or is waiting when recovery delivers it.
        let block_request = marshal.subscribe_by_digest(digest, DigestFallback::Wait);
        let (task_tx, task_rx) = oneshot::channel();
        self.gates.insert(round, digest, task_rx);

        let (mut tx, rx) = oneshot::channel();
        let runtime_context = self
            .context
            .lock()
            .await
            .child("optimistic_verify")
            .with_attribute("round", round);
        runtime_context.spawn(move |_| {
            async move {
                // Start the parent fetch immediately: its commitment and certified
                // round are known from the consensus context, so it can proceed in
                // parallel with broadcast delivery of the candidate block.
                // Reproposals (digest == context.parent.1) skip parent validation
                // entirely, so they must not fetch: the "parent" is the candidate
                // itself, and candidate acquisition is deliberately local-only.
                let parent_request = (digest != context.parent.1).then(|| {
                    let (parent_view, parent_commitment) = context.parent;
                    marshal.subscribe_by_commitment(
                        parent_commitment,
                        CommitmentFallback::FetchByRound {
                            round: Round::new(context.epoch(), parent_view),
                        },
                    )
                });

                // Stop waiting for the block if consensus drops the verification request.
                let block = select! {
                    _ = tx.closed() => {
                        debug!(
                            reason = "consensus dropped receiver",
                            "skipping optimistic verification"
                        );
                        return;
                    },
                    result = block_request => match result {
                        Ok(block) => block,
                        Err(_) => {
                            debug!(
                                ?digest,
                                reason = "failed to fetch block for optimistic verification",
                                "skipping optimistic verification"
                            );
                            return;
                        }
                    },
                };

                // Shared pre-checks enforce:
                // - Block epoch membership.
                // - Re-proposal detection via `digest == context.parent.1`.
                //
                // Re-proposals return early and skip normal parent/height checks
                // because consensus settles their validity when certifying the view
                // that first carried the block, and parent-child checks would fail by
                // construction when parent == block.
                let Some(decision) = precheck_epoch_and_reproposal(
                    &marshaled.epocher,
                    &marshal,
                    &context,
                    digest,
                    block,
                )
                .await
                else {
                    return;
                };
                let block = match decision {
                    Decision::Complete(valid) => {
                        // `Complete` means either immediate rejection or successful
                        // re-proposal handling with no further ancestry validation.
                        //
                        // A rejection is safe to publish as a gate verdict because the
                        // precheck depends only on the block's height and the gate key's
                        // epoch, never on the declared parent. A conflicting header for
                        // the same `(round, digest)` cannot produce an honest
                        // notarization: reading the digest as a re-proposal requires it
                        // to be the recorded payload of an earlier view, so its embedded
                        // context fails the mismatch check under any normal header.
                        task_tx.send_lossy(GateOutcome::Ready(valid));
                        tx.send_lossy(valid);
                        return;
                    }
                    Decision::Continue(block) => block,
                };

                // `Continue` implies a non-reproposal, so the parent subscription
                // was started above.
                let parent_request =
                    parent_request.expect("non-reproposal has a parent subscription");

                // Before casting a notarize vote, ensure the block's embedded context matches
                // the consensus context.
                //
                // This is a critical step - the notarize quorum is guaranteed to have at least
                // f+1 honest validators who will verify against this context, preventing a Byzantine
                // proposer from embedding a malicious context. The other f honest validators who did
                // not vote will later use the block-embedded context to help finalize if Byzantine
                // validators withhold their finalize votes.
                if block.context() != context {
                    debug!(
                        ?context,
                        block_context = ?block.context(),
                        "block-embedded context does not match consensus context during optimistic verification"
                    );
                    task_tx.send_lossy(GateOutcome::Recover);
                    tx.send_lossy(false);
                    return;
                }

                // Optimistic verify returns immediately; the deferred_verify task
                // runs in the background and forwards its final verdict to
                // `task_tx` so `certify` observes the same result via the
                // synchronously-registered `task_rx`.
                //
                // Once the optimistic verdict is delivered, the certification
                // gate owns the deferred work. Nullification keeps that gate
                // alive, while finalization drops it.
                let deferred_rx = marshaled
                    .deferred_verify(context, block, parent_request, Stage::Verified)
                    .await;
                tx.send_lossy(true);
                gates::forward(task_tx, deferred_rx, Some).await;
            }
            .instrument(info_span!(
                "marshal.deferred.verify.optimistic",
                round = %round,
                digest = %digest
            ))
        });
        rx
    }
}

impl<E, S, A, B, ES> CertifiableAutomaton for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<
            E,
            Block = B,
            SigningScheme = S,
            Context = Context<B::Digest, S::PublicKey>,
            Input = (),
        >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.deferred.certify", level = "info", skip_all, fields(round = %round, digest = %digest))]
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        self.gates.flush_unrelayed(&self.marshal, round, digest);

        // Attempt to retrieve the existing certification gate task for this round/digest.
        let task = self.gates.take(round, digest);
        if let Some(task) = task {
            return self.certify_from_existing_task(round, digest, task).await;
        }

        self.certify_from_embedded_context(round, digest).await
    }
}

impl<E, S, A, B, ES> Relay for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    type Digest = B::Digest;
    type PublicKey = S::PublicKey;
    type Plan = Plan<S::PublicKey>;

    fn broadcast(&mut self, commitment: Self::Digest, plan: Plan<S::PublicKey>) -> Feedback {
        relay::broadcast(&self.gates, &self.marshal, commitment, plan)
    }
}

impl<E, S, A, B, ES> Reporter for Deferred<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old certification gate tasks.
    fn report(&mut self, update: Self::Activity) -> Feedback {
        // Clean up certification gate tasks for rounds <= the finalized round.
        if let Update::Tip(round, _, _) = &update {
            self.gates.retain_after(round);
        }
        self.application.report(update)
    }
}

#[cfg(test)]
mod tests {
    use super::Deferred;
    use crate::{
        Automaton, CertifiableAutomaton, Relay,
        marshal::mocks::{
            harness::{
                B, BLOCKS_PER_EPOCH, Ctx, NAMESPACE, NUM_VALIDATORS, S, StandardHarness,
                TestHarness, V, default_leader, make_raw_block, setup_network_with_participants,
            },
            verifying::{GatedVerifyingApp, MockVerifyingApp},
        },
        simplex::{Plan, scheme::bls12381_threshold::vrf as bls12381_threshold_vrf},
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View},
    };
    use commonware_broadcast::Broadcaster;
    use commonware_cryptography::{
        Digestible, Hasher as _,
        certificate::{ConstantProvider, mocks::Fixture},
        sha256::Sha256,
    };
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{Clock, Runner, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, channel::fallible::OneshotExt};
    use std::time::Duration;

    #[test_traced("INFO")]
    fn test_certify_lower_view_after_higher_view() {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            assert!(
                marshal
                    .verified(Round::new(Epoch::new(0), View::new(1)), parent.clone())
                    .await
            );

            // Block A at view 5 (height 2)
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_a = B::new::<Sha256>(context_a.clone(), parent_digest, Height::new(2), 200);
            let commitment_a = StandardHarness::commitment(&block_a);
            assert!(marshal.verified(round_a, block_a.clone()).await);

            // Block B at view 10 (height 2, different block same height)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = Ctx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let block_b = B::new::<Sha256>(context_b.clone(), parent_digest, Height::new(2), 300);
            let commitment_b = StandardHarness::commitment(&block_b);
            assert!(marshal.verified(round_b, block_b.clone()).await);

            context.sleep(Duration::from_millis(10)).await;

            // Step 1: Verify block A at view 5
            let _ = marshaled.verify(context_a, commitment_a).await.await;

            // Step 2: Verify block B at view 10
            let _ = marshaled.verify(context_b, commitment_b).await.await;

            // Step 3: Certify block B at view 10 FIRST
            let certify_b = marshaled.certify(round_b, commitment_b).await;
            assert!(
                certify_b.await.unwrap(),
                "Block B certification should succeed"
            );

            // Step 4: Certify block A at view 5 - should succeed
            let certify_a = marshaled.certify(round_a, commitment_a).await;

            select! {
                result = certify_a => {
                    assert!(result.unwrap(), "Block A certification should succeed");
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("Block A certification timed out");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_unsupported_epoch() {
        #[derive(Clone)]
        struct LimitedEpocher {
            inner: FixedEpocher,
            max_epoch: u64,
        }

        impl Epocher for LimitedEpocher {
            fn containing(&self, height: Height) -> Option<crate::types::EpochInfo> {
                let bounds = self.inner.containing(height)?;
                if bounds.epoch().get() > self.max_epoch {
                    None
                } else {
                    Some(bounds)
                }
            }

            fn first(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.first(epoch)
                }
            }

            fn last(&self, epoch: Epoch) -> Option<Height> {
                if epoch.get() > self.max_epoch {
                    None
                } else {
                    self.inner.last(epoch)
                }
            }
        }

        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                limited_epocher,
            );

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent =
                B::new::<Sha256>(parent_ctx.clone(), genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();

            assert!(
                marshal
                    .clone()
                    .verified(Round::new(Epoch::zero(), View::new(19)), parent.clone())
                    .await
            );

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = Ctx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_digest),
            };
            let block = B::new::<Sha256>(
                unsupported_context.clone(),
                parent_digest,
                Height::new(20),
                2000,
            );
            let block_commitment = StandardHarness::commitment(&block);

            assert!(
                marshal
                    .clone()
                    .verified(unsupported_round, block.clone())
                    .await
            );

            context.sleep(Duration::from_millis(10)).await;

            // Call verify and wait for the result (verify returns optimistic result,
            // but also spawns deferred verification)
            let verify_result = marshaled
                .verify(unsupported_context, block_commitment)
                .await;

            // Wait for optimistic verify to complete so the certification gate task is registered
            let optimistic_result = verify_result.await;

            // The optimistic verify should return false because the block is in an unsupported epoch
            assert!(
                !optimistic_result.unwrap(),
                "Optimistic verify should reject block in unsupported epoch"
            );
        })
    }

    /// Test that marshaled rejects blocks when consensus context doesn't match block's embedded context.
    ///
    /// This tests that when verify() is called with a context that doesn't match what's embedded
    /// in the block, the verification should fail. A Byzantine proposer could broadcast a block
    /// with one embedded context but consensus could call verify() with a different context.
    #[test_traced("WARN")]
    fn test_marshaled_rejects_mismatched_context() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();

            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = Ctx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_commitment = StandardHarness::commitment(&parent);

            assert!(
                marshal
                    .clone()
                    .verified(Round::new(Epoch::zero(), View::new(1)), parent.clone())
                    .await
            );

            // Build a block with context A (embedded in the block).
            let round_a = Round::new(Epoch::zero(), View::new(2));
            let context_a = Ctx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = B::new::<Sha256>(context_a, parent.digest(), Height::new(2), 200);
            let commitment_a = StandardHarness::commitment(&block_a);
            assert!(marshal.verified(round_a, block_a).await);

            context.sleep(Duration::from_millis(10)).await;

            // Verify using a different consensus context B (hash mismatch).
            let round_b = Round::new(Epoch::zero(), View::new(3));
            let context_b = Ctx {
                round: round_b,
                leader: participants[1].clone(),
                parent: (View::new(1), parent_commitment),
            };

            let verify_rx = marshaled.verify(context_b, commitment_a).await;
            select! {
                result = verify_rx => {
                    assert!(
                        !result.unwrap(),
                        "mismatched context hash should be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should reject mismatched context hash promptly");
                },
            }
        })
    }

    /// Dropping the optimistic verify receiver before the block is available can close the
    /// synchronously-registered certification gate task. `certify` must recover through the
    /// embedded-context path instead of returning the closed task to consensus.
    #[test_traced("WARN")]
    fn test_deferred_certify_recovers_after_verify_receiver_drop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let round = Round::new(Epoch::zero(), View::new(1));
            let block_context = Ctx {
                round,
                leader: me,
                parent: (View::zero(), genesis.digest()),
            };
            let block =
                B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);
            let digest = block.digest();

            let verify_rx = marshaled.verify(block_context, digest).await;
            drop(verify_rx);

            // Give the optimistic task a chance to observe the dropped receiver while its
            // block subscription is still pending.
            context.sleep(Duration::from_millis(10)).await;

            assert!(marshal.verified(round, block).await);
            let certify_rx = marshaled.certify(round, digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify should recover after verify receiver drop"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should recover promptly after verify drop");
                },
            }
        });
    }

    /// The store request runs concurrently with `app.verify`, not after it: while
    /// gated application verification is still blocked, the block has already
    /// reached marshal and is locally queryable even though the sync handle may
    /// still be pending. Releasing verification then lets certification await
    /// the registered certification gate. Separate restart tests cover durable
    /// recovery after certification.
    #[test_traced("WARN")]
    fn test_deferred_store_overlaps_app_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();

            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let buffer = setup.extra;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let (mock_app, verify_started, release_verify): (GatedVerifyingApp<B, S>, _, _) =
                GatedVerifyingApp::new();
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Seed parent and child via the buffer (in-memory only) so
            // `deferred_verify` can fetch them without going through the
            // persisted marshal path.
            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(child_ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();

            assert!(
                buffer
                    .broadcast(commonware_p2p::Recipients::Some(vec![]), parent)
                    .accepted(),
                "buffer broadcast for parent should be accepted"
            );
            assert!(
                buffer
                    .broadcast(commonware_p2p::Recipients::Some(vec![]), child)
                    .accepted(),
                "buffer broadcast for child should be accepted"
            );

            // Kick off the optimistic verify, which spawns `deferred_verify`. Its gated
            // `app.verify` blocks until we release it.
            let optimistic_rx = marshaled.verify(child_ctx, child_digest).await;
            assert!(
                optimistic_rx
                    .await
                    .expect("optimistic verify should resolve"),
                "optimistic verify should accept the available block"
            );

            // Application verification is now blocked. The store request runs concurrently
            // with it, so the block is locally queryable even though verification has not
            // returned and the sync handle may still be pending.
            verify_started
                .await
                .expect("verify should reach the gated application");
            assert!(
                marshal.get_block(&child_digest).await.is_some(),
                "the store request runs concurrently with app.verify, so the block is locally queryable while verification is still gated"
            );

            // Releasing verification lets certification succeed (valid and durable).
            release_verify.send_lossy(());
            let certify_rx = marshaled.certify(child_round, child_digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify should succeed once verification passes"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve after verification is released");
                },
            }
        });
    }

    /// Regression: when marshal holds a verified block for a round from a
    /// pre-crash propose, a restarted leader's `propose` must return that
    /// block's digest instead of asking the application to build afresh.
    /// The recovered proposal must also be staged for the relay, so the
    /// broadcast re-sends it and certification resolves through the
    /// deduplicated re-persist. The inline variant skips the view instead
    /// (see `inline::tests::test_propose_skips_when_verified_block_exists_on_restart`).
    #[test_traced("WARN")]
    fn test_propose_reuses_verified_block_on_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };
            let block_a = B::new::<Sha256>(ctx.clone(), genesis.digest(), Height::new(1), 100);
            let digest_a = block_a.digest();
            assert!(marshal.verified(round, block_a.clone()).await);

            // The app cannot build (`propose` returns None) and its
            // verification never completes, so the assertions below hold
            // only if the stored block is reused as-is and certification
            // resolves through the durability gate registered by the
            // recovery staging.
            let (mock_app, verify_started, _release_verify): (GatedVerifyingApp<B, S>, _, _) =
                GatedVerifyingApp::new();
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = marshaled.propose(ctx).await;
            let digest = digest_rx.await.expect("propose must return a digest");
            assert_eq!(
                digest, digest_a,
                "propose must reuse the block marshal already persisted for this round"
            );

            // The relay broadcast must find the recovered proposal staged and
            // re-persist it (a dedup no-op whose handle covers the pre-crash
            // write), resolving the certification gate registered by the
            // recovery path.
            let _ = marshaled.broadcast(digest, Plan::Propose { round });
            let certify_rx = marshaled.certify(round, digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "recovered proposal must certify through the relay handshake"
                    );
                },
                _ = verify_started => {
                    panic!("certifying a recovered proposal must not run app verification");
                },
            }
        });
    }

    /// Regression: a boundary re-proposal stores the parent block itself at
    /// the re-proposal round, under the parent's original embedded context.
    /// A leader that crashes after that relay broadcast must recognize the
    /// cached parent as the re-proposal on restart and propose it again,
    /// rather than skipping the round because its embedded context names an
    /// older round.
    #[test_traced("WARN")]
    fn test_propose_reuses_reproposed_boundary_block_on_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);

            // Seed the boundary block at the re-proposal round, where the
            // pre-crash relay broadcast of the re-proposal persisted it.
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
            let boundary_block = B::new::<Sha256>(
                Ctx {
                    round: boundary_round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                boundary_height,
                1900,
            );
            let boundary_digest = boundary_block.digest();
            let round = Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
            assert!(marshal.verified(round, boundary_block).await);

            let ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_digest),
            };

            // The app cannot build and its verification never completes, so
            // the assertions below hold only if the cached parent is
            // re-proposed as-is.
            let (mock_app, verify_started, _release_verify): (GatedVerifyingApp<B, S>, _, _) =
                GatedVerifyingApp::new();
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = marshaled.propose(ctx).await;
            let digest = digest_rx.await.expect("propose must return a digest");
            assert_eq!(
                digest, boundary_digest,
                "propose must re-propose the boundary block marshal already persisted for this round"
            );

            let _ = marshaled.broadcast(digest, Plan::Propose { round });
            let certify_rx = marshaled.certify(round, digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "re-proposed boundary block must certify through the relay handshake"
                    );
                },
                _ = verify_started => {
                    panic!("certifying a re-proposed boundary block must not run app verification");
                },
            }
        });
    }

    /// Regression: if a pre-crash leader persisted a verified block for a
    /// round but the simplex `Notarize` never reached the journal, replay
    /// can recover a `consensus_context` whose parent differs from the one
    /// the cached block was built against (e.g. a late certification of an
    /// older view changes the parent selected by `State::find_parent`).
    /// In that case the restarted leader must not broadcast the stale
    /// cached block; it must drop the receiver so the voter nullifies the
    /// view via `MissingProposal`.
    #[test_traced("WARN")]
    fn test_propose_skips_when_verified_block_context_changed() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);

            // Stash a stale block built against genesis as its parent at round V=2.
            let round = Round::new(Epoch::zero(), View::new(2));
            let stale_ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };
            let stale_block = B::new::<Sha256>(stale_ctx, genesis.digest(), Height::new(1), 100);
            assert!(marshal.verified(round, stale_block).await);

            // Simulate a replay where parent selection now points to a
            // different parent view than the cached block was built for.
            let new_parent_digest = Sha256::hash(&[b"late-certified-parent"]);
            let new_ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::new(1), new_parent_digest),
            };

            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = marshaled.propose(new_ctx).await;
            assert!(
                digest_rx.await.is_err(),
                "propose must drop the receiver when the cached block's context no longer matches"
            );
        });
    }

    /// Regression: in deferred mode `propose` registers a certification gate that
    /// `certify` awaits. After the leader certifies its own proposal, the block must be
    /// durably recoverable across an unclean restart. This is the >= f+1 guarantee
    /// for the leader's own block.
    #[test_traced("WARN")]
    fn test_deferred_propose_then_certify_persists_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;

            let me = participants[0].clone();
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);

            // Seed the parent at its round so `propose` can fetch it locally.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = Ctx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(marshal.verified(parent_round, parent).await);

            // The leader builds the child via `app.propose`.
            let round = Round::new(Epoch::zero(), View::new(2));
            let ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();
            let mock_app: MockVerifyingApp<B, S> =
                MockVerifyingApp::new().with_propose_result(child);
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest = marshaled
                .propose(ctx)
                .await
                .await
                .expect("propose must return a digest");
            assert_eq!(
                digest, child_digest,
                "propose must return the built block's digest"
            );

            // The leader certifies its own proposal; this awaits the deferred propose sync handle.
            assert!(
                marshaled
                    .certify(round, child_digest)
                    .await
                    .await
                    .expect("certify result missing"),
                "certify must succeed for the leader's own proposal"
            );

            // After certify, the block must be durable across an unclean restart.
            actor_handle.abort();
            drop(marshaled);
            drop(marshal);

            let setup2 = StandardHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            assert!(
                marshal2.get_block(&child_digest).await.is_some(),
                "certify resolved true for the leader's own proposal so the block must be durable"
            );
        });
    }

    /// Shared scenario for the proposal-parent equivocation tests.
    ///
    /// The local validator certified the view-1 block but only nullified view 2,
    /// while the rest of the network notarized and certified the view-2 block.
    /// The view-3 leader builds on the view-2 block and broadcasts it, so the
    /// block is buffered locally but was never verified here. The equivocating
    /// context names the certified view-1 block as parent, which this
    /// validator's parent selection accepts (view 1 certified, view 2 nullified).
    struct EquivocationFixture {
        marshaled: Deferred<deterministic::Context, S, MockVerifyingApp<B, S>, B, FixedEpocher>,
        round: Round,
        digest: <B as Digestible>::Digest,
        embedded_ctx: Ctx,
        equivocating_ctx: Ctx,
        _extra: <StandardHarness as TestHarness>::ValidatorExtra,
    }

    async fn equivocation_fixture(
        context: &mut deterministic::Context,
        app: MockVerifyingApp<B, S>,
    ) -> EquivocationFixture {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;

        let me = participants[0].clone();
        let setup = StandardHarness::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let marshal = setup.mailbox;
        let buffer = setup.extra;

        let genesis = make_raw_block(Sha256::hash(&[b""]), Height::zero(), 0);
        let leader = participants[1].clone();

        // The view-1 block: the parent this validator last certified.
        let certified_round = Round::new(Epoch::zero(), View::new(1));
        let certified_ctx = Ctx {
            round: certified_round,
            leader: default_leader(),
            parent: (View::zero(), genesis.digest()),
        };
        let certified = B::new::<Sha256>(certified_ctx, genesis.digest(), Height::new(1), 100);
        let certified_digest = certified.digest();
        assert!(marshal.verified(certified_round, certified).await);

        // The view-2 block: notarized by the network but only nullified here,
        // so this validator never certified it.
        let notarized_round = Round::new(Epoch::zero(), View::new(2));
        let notarized_ctx = Ctx {
            round: notarized_round,
            leader: leader.clone(),
            parent: (View::new(1), certified_digest),
        };
        let notarized = B::new::<Sha256>(notarized_ctx, certified_digest, Height::new(2), 200);
        let notarized_digest = notarized.digest();
        assert!(marshal.verified(notarized_round, notarized).await);

        // The view-3 block builds on the view-2 block. The leader's broadcast
        // delivered it into the local buffer without a local verification.
        let round = Round::new(Epoch::zero(), View::new(3));
        let embedded_ctx = Ctx {
            round,
            leader: leader.clone(),
            parent: (View::new(2), notarized_digest),
        };
        let block = B::new::<Sha256>(embedded_ctx.clone(), notarized_digest, Height::new(3), 300);
        let digest = block.digest();
        assert!(
            buffer
                .broadcast(commonware_p2p::Recipients::Some(vec![]), block)
                .accepted(),
            "buffer broadcast for the candidate should be accepted"
        );

        let equivocating_ctx = Ctx {
            round,
            leader,
            parent: (View::new(1), certified_digest),
        };

        let marshaled = Deferred::new(
            context.child("deferred"),
            app,
            marshal,
            FixedEpocher::new(BLOCKS_PER_EPOCH),
        );
        context.sleep(Duration::from_millis(10)).await;

        EquivocationFixture {
            marshaled,
            round,
            digest,
            embedded_ctx,
            equivocating_ctx,
            _extra: buffer,
        }
    }

    /// A leader can equivocate at the proposal layer: sign one proposal for a
    /// digest declaring the notarized view-2 parent (sent to the validators
    /// that certified view 2) and another declaring the certified view-1
    /// parent (sent to a validator that only nullified view 2). Both pass
    /// their recipients' parent selection and carry the same digest because
    /// they name the same block.
    ///
    /// Refusing to notarize the mismatched proposal is correct. That refusal
    /// must not outlive the proposal: once the honest notarization for
    /// `(round, digest)` arrives, certification must judge the block against
    /// its embedded context (defended by the notarizing quorum) and succeed.
    /// Adopting the verdict computed under the equivocating context wedges
    /// this validator in the view: the other honest validators have certified
    /// and advanced, leaving too few validators to form either a nullification
    /// or a finalization after the Byzantine validator stops participating.
    #[test_traced("WARN")]
    fn test_certify_not_poisoned_by_equivocating_parent_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut fixture = equivocation_fixture(&mut context, MockVerifyingApp::new()).await;

            let verify_rx = fixture
                .marshaled
                .verify(fixture.equivocating_ctx.clone(), fixture.digest)
                .await;
            assert!(
                !verify_rx.await.expect("verify result missing"),
                "the equivocating proposal must not be notarized"
            );

            let certify_rx = fixture
                .marshaled
                .certify(fixture.round, fixture.digest)
                .await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify of the notarized digest must not adopt the verdict computed under the equivocating context"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve promptly");
                },
            }
        });
    }

    /// Control for the equivocation tests: a live application rejection under
    /// the matching context is a real verdict. Certification must keep
    /// honoring it, because deferred voting means a notarization can exist
    /// for an application-invalid block.
    #[test_traced("WARN")]
    fn test_certify_honors_application_rejection() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut fixture =
                equivocation_fixture(&mut context, MockVerifyingApp::with_verify_result(false))
                    .await;

            let verify_rx = fixture
                .marshaled
                .verify(fixture.embedded_ctx.clone(), fixture.digest)
                .await;
            assert!(
                verify_rx.await.expect("verify result missing"),
                "optimistic verify accepts an available block with a matching context"
            );

            let certify_rx = fixture
                .marshaled
                .certify(fixture.round, fixture.digest)
                .await;
            select! {
                result = certify_rx => {
                    assert!(
                        !result.expect("certify result missing"),
                        "certify must propagate the application rejection"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve promptly");
                },
            }
        });
    }

    /// Without a registered gate (never verified locally, or the gate was lost
    /// to a restart), certification runs the application against the block's
    /// embedded context. A live rejection there must reach consensus too.
    #[test_traced("WARN")]
    fn test_certify_without_prior_verify_honors_application_rejection() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let mut fixture =
                equivocation_fixture(&mut context, MockVerifyingApp::with_verify_result(false))
                    .await;

            // No prior verify, so no gate exists and certify falls through to
            // the embedded-context path.
            let certify_rx = fixture
                .marshaled
                .certify(fixture.round, fixture.digest)
                .await;
            select! {
                result = certify_rx => {
                    assert!(
                        !result.expect("certify result missing"),
                        "certify must propagate the application rejection"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should resolve promptly");
                },
            }
        });
    }
}
