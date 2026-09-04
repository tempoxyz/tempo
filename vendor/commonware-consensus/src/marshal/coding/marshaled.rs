//! Wrapper for consensus applications that handles epochs, erasure coding, and block dissemination.
//!
//! # Overview
//!
//! [`Marshaled`] is an adapter that wraps any [`Application`] implementation to handle
//! epoch transitions and erasure coded broadcast automatically. It intercepts consensus
//! operations (propose, verify, certify) and ensures blocks are only produced within valid epoch boundaries.
//!
//! # Epoch Boundaries
//!
//! An epoch is a fixed number of blocks (the `epoch_length`). When the last block in an epoch
//! is reached, this wrapper prevents new blocks from being built & proposed until the next epoch begins.
//! Instead, it re-proposes the boundary block to avoid producing blocks that would be pruned
//! by the epoch transition.
//!
//! # Erasure Coding
//!
//! This wrapper integrates with a variant of marshal that supports erasure coded broadcast. When a leader
//! proposes a new block, it is automatically erasure encoded and its shards are broadcasted to active
//! participants. When verifying a proposed block (the precondition for notarization), the wrapper
//! ensures the commitment's context digest matches the consensus context and waits for validation of
//! the shard assigned to this participant by the proposer. If that shard is valid, the assigned shard is
//! relayed to all other participants to aid in block reconstruction.
//!
//! A participant may still reconstruct the full block from gossiped shards before its designated
//! leader-delivered shard arrives. That is sufficient for later certification and repair flows, but it
//! is not treated as notarization readiness: a participant only helps form a notarization once it has
//! validated the shard it is supposed to echo.
//!
//! During certification (the phase between notarization and finalization), the wrapper subscribes to
//! block reconstruction and validates epoch boundaries, parent commitment, height contiguity, and
//! that the block's embedded context matches the consensus context before allowing the block to be
//! certified. If certification fails, the voter can still emit a nullify vote to advance the view.
//!
//! # Usage
//!
//! Wrap your [`Application`] implementation with [`Marshaled::new`] and provide it to your
//! consensus engine for the [`Automaton`] and [`Relay`]. The wrapper handles all epoch logic transparently.
//!
//! ```rust,ignore
//! let cfg = MarshaledConfig {
//!     application: my_application,
//!     marshal: marshal_mailbox,
//!     shards: shard_mailbox,
//!     scheme_provider,
//!     epocher,
//!     strategy,
//! };
//! let application = Marshaled::new(context, cfg);
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
//! available to the honest parties (e.g., if the whole network crashed before receiving `f+1` shards
//! and the proposer went permanently offline). In this case, `certify` will be unable to fetch the
//! block before timeout and result in a nullification.
//!
//! For this reason, it should not be expected that every notarized payload will be certifiable due
//! to the lack of an available block. However, if even one honest and online party has the block,
//! they will attempt to forward it to others via marshal's resolver. This case is already present
//! in the event of a block that was proposed with invalid codec; Marshal will not be able to reconstruct
//! the block, and therefore won't serve it.
//!
//! ```text
//!                                      ┌───────────────────────────────────────────────────┐
//!                                      ▼                                                   │
//! ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
//! │          B1         │◀──│          B2         │◀──│          B3         │XXX│          B4         │
//! └─────────────────────┘   └─────────────────────┘   └──────────┬──────────┘   └─────────────────────┘
//!                                                                │
//!                                                          Failed Certify
//! ```

use crate::{
    marshal::{
        application::{
            gates::{self, Gates},
            validation::{is_inferred_reproposal_at_certify, is_valid_reproposal_at_verify, Stage},
        },
        coding::{
            shards,
            types::{coding_config_for_participants, hash_context, CodedBlock},
            validation::{validate_block, validate_proposal, ProposalError},
            Coding,
        },
        core, Update,
    },
    simplex::{scheme::Scheme, types::Context, Plan},
    types::{coding::Commitment, Epoch, Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, CertifiableBlock, Epochable, Heightable,
    Relay, Reporter,
};
use commonware_actor::Feedback;
use commonware_coding::Scheme as CodingScheme;
use commonware_cryptography::{
    certificate::{Provider, Scheme as _, Verifier},
    Committable, Digestible, Hasher,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_runtime::{
    telemetry::{
        metrics::{
            histogram::{Buckets, Timed},
            MetricsExt as _,
        },
        traces::TracedExt as _,
    },
    Clock, Metrics, Spawner, Storage,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::TracedAsyncMutex,
};
use rand_core::Rng;
use std::sync::Arc;
use tracing::{debug, info_span, warn, Instrument as _};

/// Configuration for initializing [`Marshaled`].
#[allow(clippy::type_complexity)]
pub struct MarshaledConfig<A, B, C, H, Z, S, ES>
where
    B: CertifiableBlock<Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    /// The underlying application to wrap.
    pub application: A,
    /// Mailbox for communicating with the marshal engine.
    pub marshal: core::Mailbox<Z::Scheme, Coding<B, C, H, <Z::Scheme as Verifier>::PublicKey>>,
    /// Mailbox for communicating with the shards engine.
    pub shards: shards::Mailbox<B, C, H, <Z::Scheme as Verifier>::PublicKey>,
    /// Provider for signing schemes scoped by epoch.
    pub scheme_provider: Z,
    /// Strategy for parallel operations.
    pub strategy: S,
    /// Strategy for determining epoch boundaries.
    pub epocher: ES,
}

/// An [`Application`] adapter that handles epoch transitions and erasure coded broadcast.
///
/// This wrapper intercepts consensus operations to enforce epoch boundaries. It prevents
/// blocks from being produced outside their valid epoch and handles the special case of
/// re-proposing boundary blocks during epoch transitions.
#[allow(clippy::type_complexity)]
pub struct Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E>,
    B: CertifiableBlock<Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    context: Arc<TracedAsyncMutex<E>>,
    application: A,
    marshal: core::Mailbox<Z::Scheme, Coding<B, C, H, <Z::Scheme as Verifier>::PublicKey>>,
    shards: shards::Mailbox<B, C, H, <Z::Scheme as Verifier>::PublicKey>,
    scheme_provider: Z,
    epocher: ES,
    strategy: S,
    gates: Gates<Commitment, CodedBlock<B, C, H>>,

    build_duration: Timed,
    verify_duration: Timed,
    proposal_parent_fetch_duration: Timed,
    ancestor_fetch_duration: Timed,
    erasure_encode_duration: Timed,
}

impl<E, A, B, C, H, Z, S, ES> Clone for Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E>,
    B: CertifiableBlock<Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            application: self.application.clone(),
            marshal: self.marshal.clone(),
            shards: self.shards.clone(),
            scheme_provider: self.scheme_provider.clone(),
            epocher: self.epocher.clone(),
            strategy: self.strategy.clone(),
            gates: self.gates.clone(),
            build_duration: self.build_duration.clone(),
            verify_duration: self.verify_duration.clone(),
            proposal_parent_fetch_duration: self.proposal_parent_fetch_duration.clone(),
            ancestor_fetch_duration: self.ancestor_fetch_duration.clone(),
            erasure_encode_duration: self.erasure_encode_duration.clone(),
        }
    }
}

impl<E, A, B, C, H, Z, S, ES> Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    /// Creates a new [`Marshaled`] wrapper.
    ///
    /// # Panics
    ///
    /// Panics if the marshal metadata store cannot be initialized.
    pub fn new(context: E, cfg: MarshaledConfig<A, B, C, H, Z, S, ES>) -> Self {
        let MarshaledConfig {
            application,
            marshal,
            shards,
            scheme_provider,
            strategy,
            epocher,
        } = cfg;

        let build_histogram = context.histogram(
            "build_duration",
            "Histogram of time taken for the application to build a new block, in seconds",
            Buckets::LOCAL,
        );
        let build_duration = Timed::new(build_histogram);

        let verify_histogram = context.histogram(
            "verify_duration",
            "Histogram of time taken for the application to verify a block, in seconds",
            Buckets::LOCAL,
        );
        let verify_duration = Timed::new(verify_histogram);

        let parent_fetch_histogram = context.histogram(
            "parent_fetch_duration",
            "Histogram of time taken to fetch a parent block in proposal, in seconds",
            Buckets::LOCAL,
        );
        let proposal_parent_fetch_duration = Timed::new(parent_fetch_histogram);

        let ancestor_fetch_histogram = context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        );
        let ancestor_fetch_duration = Timed::new(ancestor_fetch_histogram);

        let erasure_histogram = context.histogram(
            "erasure_encode_duration",
            "Histogram of time taken to erasure encode a block, in seconds",
            Buckets::LOCAL,
        );
        let erasure_encode_duration = Timed::new(erasure_histogram);

        Self {
            context: Arc::new(TracedAsyncMutex::new("marshal.context", context)),
            application,
            marshal,
            shards,
            scheme_provider,
            strategy,
            epocher,
            gates: Gates::new(),

            build_duration,
            verify_duration,
            proposal_parent_fetch_duration,
            ancestor_fetch_duration,
            erasure_encode_duration,
        }
    }

    /// Verifies a proposed block within epoch boundaries.
    ///
    /// This method validates that:
    /// 1. The block is within the current epoch (unless it's a boundary block re-proposal)
    /// 2. Re-proposals are only allowed for the last block in an epoch
    /// 3. The block's parent digest matches the consensus context's expected parent
    /// 4. The block's height is exactly one greater than the parent's height
    /// 5. The block's embedded context digest matches the commitment
    /// 6. The block's embedded context matches the consensus context
    /// 7. The underlying application's verification logic passes
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result.
    ///
    /// If `prefetched_block` is provided, it will be used directly instead of fetching from
    /// the marshal. This is useful in `certify` when we've already fetched the block to
    /// extract its embedded context.
    async fn deferred_verify(
        &mut self,
        consensus_context: Context<Commitment, <Z::Scheme as Verifier>::PublicKey>,
        commitment: Commitment,
        prefetched_block: Option<Arc<CodedBlock<B, C, H>>>,
        stage: Stage,
    ) -> oneshot::Receiver<bool> {
        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let verify_duration = self.verify_duration.clone();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("deferred_verify")
            .with_attribute("round", consensus_context.round);
        let span = info_span!(
            "marshal.coding.verify.deferred",
            round = %consensus_context.round,
            commitment = %commitment
        );
        context.spawn(move |runtime_context| {
            async move {
                let round = consensus_context.round;
                let (parent_view, parent_commitment) = consensus_context.parent;

                // Start the parent fetch immediately so it can proceed in parallel
                // with candidate reconstruction. The parent round comes from the
                // caller's context (the certified consensus context in verify, the
                // quorum-defended embedded context in certify), never from the
                // unverified child block.
                let parent_request = marshal.subscribe_by_commitment(
                    parent_commitment,
                    core::CommitmentFallback::FetchByRound {
                        round: Round::new(consensus_context.epoch(), parent_view),
                    },
                );

                // Get the candidate block either from the caller or by waiting for
                // local reconstruction. Candidate data remains local-only: a
                // notarization is not sufficient reason to request it from peers.
                let block = if let Some(block) = prefetched_block {
                    block
                } else {
                    let block_request =
                        marshal.subscribe_by_commitment(commitment, core::CommitmentFallback::Wait);
                    select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping verification"
                            );
                            return;
                        },
                        result = block_request => match result {
                            Ok(block) => block,
                            Err(_) => {
                                debug!(reason = "block unavailable", "skipping verification");
                                return;
                            }
                        },
                    }
                };

                // Start the candidate store immediately: it depends on neither the
                // parent fetch (which may hit the network) nor the verdict below.
                // Storing before validation is intentional: these caches provide
                // candidate availability/recovery, not a validity decision. This
                // task gates the finalize vote by resolving true only after both
                // app verification succeeds and the store is durable.
                let store = stage.store(&marshal, round, Arc::clone(&block));
                let verify = async {
                    // Await the parent fetch we started above.
                    let parent = select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping verification"
                            );
                            return None;
                        },
                        result = parent_request => match result {
                            Ok(parent) => parent,
                            Err(_) => {
                                debug!(reason = "failed to fetch parent", "skipping verification");
                                return None;
                            }
                        },
                    };

                    if let Err(err) = validate_block::<H, _, _>(
                        &epocher,
                        block.as_ref(),
                        parent.as_ref(),
                        &consensus_context,
                        commitment,
                        parent_commitment,
                    ) {
                        debug!(
                            ?err,
                            expected_commitment = %commitment,
                            block_commitment = %block.commitment(),
                            expected_parent_commitment = %parent_commitment,
                            parent_commitment = %parent.commitment(),
                            expected_parent = %parent.digest(),
                            block_parent = %block.parent(),
                            parent_height = %parent.height(),
                            block_height = %block.height(),
                            "block failed coded invariant validation"
                        );
                        return Some(false);
                    }

                    let ancestry_stream = marshal.ancestor_stream(
                        Arc::new(runtime_context.child("ancestor_stream")),
                        [block.inner_shared(), parent.inner_shared()],
                        ancestor_fetch_duration,
                    );
                    let validity_request = application
                        .verify(
                            (
                                runtime_context.child("app_verify"),
                                consensus_context.clone(),
                            ),
                            ancestry_stream,
                        )
                        .instrument(info_span!(
                            "marshal.coding.application.verify",
                            round = %consensus_context.round,
                            commitment = %commitment,
                            parent_view = parent_view.traced(),
                            parent = %parent_commitment
                        ));

                    // If consensus drops the receiver, we can stop work early.
                    let timer = verify_duration.timer(&runtime_context);
                    let result = select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping verification"
                            );
                            None
                        },
                        is_valid = validity_request => Some(is_valid),
                    };
                    timer.observe(&runtime_context);
                    result
                };
                let (verdict, durable) = futures::join!(verify, store);

                // Publish only when the block is both valid and durable. App-invalid
                // candidates may already be in the cache from the concurrent store above,
                // so the gate verdict is the authority for consensus progress.
                if let Some(application_valid) = gates::resolve(verdict, durable) {
                    tx.send_lossy(application_valid);
                }
            }
            .instrument(span)
        });

        rx
    }

    async fn certify_from_embedded_context(
        &mut self,
        round: Round,
        payload: Commitment,
    ) -> oneshot::Receiver<bool> {
        // Certify may be reached without an earlier `verify`, so the shard
        // engine may not know the leader yet. A notarized commitment is still
        // enough to start reconstruction from sender-indexed gossip shards
        // already buffered for the commitment.
        self.shards.notarized(payload, round);

        // No in-progress task means we never verified this proposal locally.
        // We can use the block's embedded context to move to the next view. If a Byzantine
        // proposer embedded a malicious context, the f+1 honest validators from the notarizing quorum
        // will verify against the proper context and reject the mismatch, preventing a 2f+1
        // finalization quorum.
        //
        // We must fetch here rather than only wait for local reconstruction. A Byzantine
        // leader can send enough shards to just f+1 honest validators, collect enough honest
        // notarize votes to form a notarization, and leave the remaining honest validators
        // unable to reconstruct the block. Those validators need the notarized round to
        // recover and certify; otherwise they can remain stuck if the Byzantine validators
        // stop participating in the next view.
        //
        // Subscribe to the block and verify using its embedded context once available.
        debug!(
            ?round,
            ?payload,
            "subscribing to block for certification using embedded context"
        );
        let block_rx = self
            .marshal
            .subscribe_by_commitment(payload, core::CommitmentFallback::FetchByRound { round });
        let mut marshaled = self.clone();
        let shards = self.shards.clone();
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
                                ?payload,
                                reason = "failed to fetch block for certification",
                                "skipping certification"
                            );
                            return;
                        }
                    },
                };

                // Re-proposal detection for certify path: we don't have the consensus
                // context, only the block's embedded context from original proposal.
                // Infer re-proposal from:
                // 1. Block is at epoch boundary (only boundary blocks can be re-proposed)
                // 2. Certification round's view > embedded context's view (re-proposals
                //    retain their original embedded context, so a later view indicates
                //    the block was re-proposed)
                // 3. Same epoch (re-proposals don't cross epoch boundaries)
                let embedded_context = block.context();
                let is_reproposal = is_inferred_reproposal_at_certify(
                    &marshaled.epocher,
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

                // Inform the shard engine of an externally proposed commitment.
                shards.discovered(
                    payload,
                    embedded_context.leader.clone(),
                    embedded_context.round,
                );

                // Use the block's embedded context for verification, passing the
                // prefetched block to avoid fetching it again inside deferred_verify.
                let verify_rx = marshaled
                    .deferred_verify(embedded_context, payload, Some(block), Stage::Certified)
                    .await;
                if let Ok(result) = verify_rx.await {
                    tx.send_lossy(result);
                }
            }
            .instrument(info_span!(
                "marshal.coding.certify.embedded",
                round = %round,
                commitment = %payload
            ))
        });
        rx
    }

    #[allow(clippy::async_yields_async)]
    async fn certify_from_existing_task(
        &mut self,
        round: Round,
        payload: Commitment,
        task: oneshot::Receiver<bool>,
    ) -> oneshot::Receiver<bool> {
        // `verify()` intentionally waits only for local candidate data. Once
        // certification starts, a notarization exists and the same pending
        // verifier must be unblocked by round-bound recovery if local
        // reconstruction never completes.
        self.shards.notarized(payload, round);
        self.marshal.hint_notarized(round, payload);

        // A completed gate is a live local verdict. After an unclean restart the
        // in-memory task is gone, so recover via the embedded-context fetch path.
        let mut marshaled = self.clone();
        let (tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("certify_existing")
            .with_attribute("round", round);
        context.spawn(move |_| {
            gates::drive(tx, task, round, payload, move || async move {
                marshaled
                    .certify_from_embedded_context(round, payload)
                    .await
            })
            .instrument(info_span!(
                "marshal.coding.certify.existing",
                round = %round,
                commitment = %payload
            ))
        });
        rx
    }
}

impl<E, A, B, C, H, Z, S, ES> Automaton for Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Digest = Commitment;
    type Context = Context<Self::Digest, <Z::Scheme as Verifier>::PublicKey>;

    /// Proposes a new block or re-proposes the epoch boundary block.
    ///
    /// This method builds a new block from the underlying application unless the parent block
    /// is the last block in the current epoch. When at an epoch boundary, it re-proposes the
    /// boundary block to avoid creating blocks that would be invalidated by the epoch transition.
    ///
    /// The proposal operation is spawned in a background task and returns a receiver that will
    /// contain the proposed block's commitment when ready. The block is staged before the
    /// commitment is delivered and handed to marshal when consensus requests the relay
    /// broadcast, which persists it after the shards are sent. The resulting sync handle is
    /// awaited only at certification so it overlaps consensus voting. The commitment does not
    /// imply durability on its own. [`CertifiableAutomaton::certify`] awaits the registered
    /// certification gate before the finalize vote.
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.coding.propose", level = "info", skip_all, fields(round = %consensus_context.round))]
    async fn propose(
        &mut self,
        consensus_context: Context<Commitment, <Z::Scheme as Verifier>::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let strategy = self.strategy.clone();
        let gates = self.gates.clone();

        // If there's no scheme for the current epoch, we cannot verify the proposal.
        // Send back a receiver with a dropped sender.
        let Some(scheme) = self.scheme_provider.scheme(consensus_context.epoch()) else {
            debug!(
                round = %consensus_context.round,
                "no scheme for epoch, skipping propose"
            );
            let (_, rx) = oneshot::channel();
            return rx;
        };

        let n_participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        let coding_config = coding_config_for_participants(n_participants);

        // Metrics
        let build_duration = self.build_duration.clone();
        let proposal_parent_fetch_duration = self.proposal_parent_fetch_duration.clone();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();
        let erasure_encode_duration = self.erasure_encode_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("propose")
            .with_attribute("round", consensus_context.round);
        let span = info_span!(
            "marshal.coding.propose.task",
            round = %consensus_context.round
        );
        context.spawn(move |runtime_context| {
            async move {
                // On leader recovery, marshal may already hold a verified block
                // for this round (persisted by a pre-crash propose that reached
                // its relay broadcast).
                //
                // The pre-crash commitment may already have been broadcast,
                // so building a fresh block would equivocate. The stored
                // block is the only proposal we can broadcast for this round.
                //
                // The recovered block is safe to reuse only if its embedded
                // context matches the context simplex just recovered.
                // Otherwise the cached block was built against a different
                // parent and cannot be broadcast under the current header, so
                // drop the receiver and let the voter nullify the view via
                // timeout.
                if let Some(block) = marshal.get_verified(consensus_context.round).await {
                    let block_context = block.context();
                    if block_context != consensus_context {
                        debug!(
                            round = ?consensus_context.round,
                            ?consensus_context,
                            ?block_context,
                            "skipping proposal: cached verified block context no longer matches"
                        );
                        return;
                    }
                    // Stage the recovered block so the relay broadcast re-sends
                    // its shards through the same handshake as a fresh
                    // proposal. The relay-time persist deduplicates against the
                    // pre-crash write, with the handle covering the original.
                    let commitment = block.commitment();
                    let round = consensus_context.round;
                    debug!(
                        ?round,
                        ?commitment,
                        "reusing verified block from marshal on leader recovery"
                    );
                    gates
                        .stage(round, commitment, Arc::new(block), tx, "recovered block")
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
                let parent_request = marshal.subscribe_by_commitment(
                    parent_commitment,
                    core::CommitmentFallback::FetchByRound {
                        round: Round::new(consensus_context.epoch(), parent_view),
                    },
                );

                let parent_timer = proposal_parent_fetch_duration.timer(&runtime_context);
                let parent = select! {
                    _ = tx.closed() => {
                        debug!(reason = "consensus dropped receiver", "skipping proposal");
                        return;
                    },
                    result = parent_request => match result {
                        Ok(parent) => parent,
                        Err(_) => {
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

                // Special case: If the parent block is the last block in the epoch,
                // re-propose it as to not produce any blocks that will be cut out
                // by the epoch transition.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
                if parent.height() == last_in_epoch {
                    let commitment = parent.commitment();
                    let round = consensus_context.round;

                    gates
                        .stage(round, commitment, parent, tx, "re-proposed boundary block")
                        .await;
                    return;
                }

                let ancestor_stream = marshal.ancestor_stream(
                    Arc::new(runtime_context.child("ancestor_stream")),
                    [parent.inner_shared()],
                    ancestor_fetch_duration,
                );
                let build_request = application
                    .propose(
                        (
                            runtime_context.child("app_propose"),
                            consensus_context.clone(),
                        ),
                        ancestor_stream,
                    )
                    .instrument(info_span!(
                        "marshal.coding.application.propose",
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

                let erasure_timer = erasure_encode_duration.timer(&runtime_context);
                let coded_block = CodedBlock::<B, C, H>::new(built_block, coding_config, &strategy);
                erasure_timer.observe(&runtime_context);

                let commitment = coded_block.commitment();
                let round = consensus_context.round;

                gates
                    .stage(
                        round,
                        commitment,
                        Arc::new(coded_block),
                        tx,
                        "proposed block",
                    )
                    .await;
            }
            .instrument(span)
        });
        rx
    }

    /// Verifies a received shard for a given round.
    ///
    /// This method validates that:
    /// 1. The coding configuration matches the expected configuration for the current scheme.
    /// 2. The commitment's context digest matches the consensus context (unless this is a re-proposal).
    /// 3. The shard is contained within the consensus commitment.
    ///
    /// Verification is spawned in a background task and returns a receiver that will contain
    /// the verification result. Additionally, this method kicks off deferred verification to
    /// start block verification early (hidden behind shard validity and network latency).
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.coding.verify", level = "info", skip_all, fields(round = %consensus_context.round, commitment = %payload))]
    async fn verify(
        &mut self,
        consensus_context: Context<Self::Digest, <Z::Scheme as Verifier>::PublicKey>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // If there's no scheme for the current epoch, we cannot vote on the proposal.
        // Send back a receiver with a dropped sender.
        let Some(scheme) = self.scheme_provider.scheme(consensus_context.epoch()) else {
            debug!(
                round = %consensus_context.round,
                "no scheme for epoch, skipping verify"
            );
            let (_, rx) = oneshot::channel();
            return rx;
        };

        let n_participants =
            u16::try_from(scheme.participants().len()).expect("too many participants");
        let coding_config = coding_config_for_participants(n_participants);
        let is_reproposal = payload == consensus_context.parent.1;

        // Validate proposal-level invariants:
        // - coding config must match active participant set
        // - context digest must match unless this is a re-proposal
        let proposal_context = (!is_reproposal).then_some(&consensus_context);
        if let Err(err) = validate_proposal::<H, _>(payload, coding_config, proposal_context) {
            match err {
                ProposalError::CodingConfig => {
                    warn!(
                        round = %consensus_context.round,
                        got = ?payload.config(),
                        expected = ?coding_config,
                        "rejected proposal with unexpected coding configuration"
                    );
                }
                ProposalError::ContextDigest => {
                    let expected = hash_context::<H, _>(&consensus_context);
                    let got = payload.context::<H::Digest>();
                    warn!(
                        round = %consensus_context.round,
                        expected = ?expected,
                        got = ?got,
                        "rejected proposal with mismatched context digest"
                    );
                }
            }

            let (tx, rx) = oneshot::channel();
            tx.send_lossy(false);
            return rx;
        }

        // Re-proposals skip context-digest validation because the consensus context will point
        // at the prior epoch-boundary block while the embedded block context is from the
        // original proposal view.
        //
        // Re-proposals also skip shard-validity and deferred verification because:
        // 1. The block was already verified when originally proposed
        // 2. The parent-child height check would fail (parent IS the block)
        // 3. Waiting for shards could stall if the leader doesn't rebroadcast
        if is_reproposal {
            // Fetch the block to verify it's at the epoch boundary.
            // This should be fast since the parent block is typically already cached.
            let block_rx = self
                .marshal
                .subscribe_by_commitment(payload, core::CommitmentFallback::Wait);
            let marshal = self.marshal.clone();
            let epocher = self.epocher.clone();
            let round = consensus_context.round;
            let gates = self.gates.clone();

            // Register a certification gate task synchronously before spawning work so
            // `certify` can always find it (no race with task startup).
            let (task_tx, task_rx) = oneshot::channel();
            gates.insert(round, payload, task_rx);

            let (mut tx, rx) = oneshot::channel();
            let context = self
                .context
                .lock()
                .await
                .child("verify_reproposal")
                .with_attribute("round", round);
            context.spawn(move |_| {
                async move {
                    let block = select! {
                        _ = tx.closed() => {
                            debug!(
                                reason = "consensus dropped receiver",
                                "skipping re-proposal verification"
                            );
                            return;
                        },
                        block = block_rx => match block {
                            Ok(block) => block,
                            Err(_) => {
                                debug!(
                                    ?payload,
                                    reason = "failed to fetch block for re-proposal verification",
                                    "skipping re-proposal verification"
                                );
                                // Fetch failure is an availability issue, not an explicit
                                // invalidity proof. Do not synthesize `false` here.
                                return;
                            }
                        },
                    };

                    if !is_valid_reproposal_at_verify(&epocher, block.height(), round.epoch()) {
                        debug!(
                            height = %block.height(),
                            "re-proposal is not at epoch boundary"
                        );
                        task_tx.send_lossy(false);
                        tx.send_lossy(false);
                        return;
                    }

                    // Valid re-proposal: notify the marshal and complete the
                    // certification gate task for `certify`.
                    let durable = marshal.verified(round, block).await;
                    if !durable {
                        return;
                    }
                    task_tx.send_lossy(true);
                    tx.send_lossy(true);
                }
                .instrument(info_span!(
                    "marshal.coding.verify.reproposal",
                    round = %round,
                    commitment = %payload
                ))
            });
            return rx;
        }

        // Inform the shard engine of an externally proposed commitment.
        self.shards.discovered(
            payload,
            consensus_context.leader.clone(),
            consensus_context.round,
        );

        // Kick off deferred verification early to hide verification latency behind
        // shard validity checks and network latency for collecting votes.
        //
        // The task's cancellation signal is the gate receiver registered below,
        // not consensus's verify receiver. Nullification advances the view and
        // drops the verify receiver without cancelling certification for it, so
        // deferred verification must survive that drop for certify to consume.
        let round = consensus_context.round;
        let task = self
            .deferred_verify(consensus_context, payload, None, Stage::Verified)
            .await;
        self.gates.insert(round, payload, task);

        match scheme.me() {
            Some(_) => {
                // Subscribe to assigned shard verification. For participants, this
                // only completes once the leader-delivered shard for our
                // assigned index has been verified. Reconstructing the block
                // from peer gossip is useful for certification later, but is
                // not enough to emit a notarize vote.
                let validity_rx = self.shards.subscribe_assigned_shard_verified(payload);
                let (tx, rx) = oneshot::channel();
                let context = self
                    .context
                    .lock()
                    .await
                    .child("shard_validity_wait")
                    .with_attribute("round", round);
                context.spawn(move |_| {
                    async move {
                        if validity_rx.await.is_ok() {
                            tx.send_lossy(true);
                        }
                    }
                    .instrument(info_span!(
                        "marshal.coding.verify.shard_validity",
                        round = %round,
                        commitment = %payload
                    ))
                });
                rx
            }
            None => {
                // If we are not participating, there's no shard to verify; just accept the proposal.
                //
                // Later, when certifying, we will wait to receive the block from the network.
                let (tx, rx) = oneshot::channel();
                tx.send_lossy(true);
                rx
            }
        }
    }
}

impl<E, A, B, C, H, Z, S, ES> CertifiableAutomaton for Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<
        E,
        Block = B,
        SigningScheme = Z::Scheme,
        Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>,
    >,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.coding.certify", level = "info", skip_all, fields(round = %round, commitment = %payload))]
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        self.gates.flush_unrelayed(&self.marshal, round, payload);

        // First, check for an in-progress certification gate task.
        let task = self.gates.take(round, payload);
        if let Some(task) = task {
            return self.certify_from_existing_task(round, payload, task).await;
        }

        self.certify_from_embedded_context(round, payload).await
    }
}

impl<E, A, B, C, H, Z, S, ES> Relay for Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Digest = Commitment;
    type PublicKey = <Z::Scheme as Verifier>::PublicKey;
    type Plan = Plan<Self::PublicKey>;

    fn broadcast(&mut self, commitment: Self::Digest, plan: Self::Plan) -> Feedback {
        // Coding variant does not support targeted forwarding;
        // peers reconstruct blocks from erasure-coded shards.
        //
        // TODO(#3389): Support checked data forwarding for PhasedScheme.
        let Plan::Propose { round } = plan else {
            return Feedback::Ok;
        };

        let Some((block, ack)) = self.gates.take_staged(round, commitment) else {
            debug!(%round, %commitment, "no staged proposal to relay, attempting forwarding");
            return self.marshal.forward(round, commitment, Recipients::All);
        };
        self.marshal.proposed(round, block, Recipients::All, ack)
    }
}

impl<E, A, B, C, H, Z, S, ES> Reporter for Marshaled<E, A, B, C, H, Z, S, ES>
where
    E: Rng + Storage + Spawner + Metrics + Clock,
    A: Application<E, Block = B, Context = Context<Commitment, <Z::Scheme as Verifier>::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: CertifiableBlock<Context = <A as Application<E>>::Context>,
    C: CodingScheme,
    H: Hasher,
    Z: Provider<Scope = Epoch, Scheme: Scheme<Commitment>>,
    S: Strategy,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Relays a report to the underlying [`Application`] and cleans up old certification gate data.
    fn report(&mut self, update: Self::Activity) -> Feedback {
        // Clean up certification gate tasks and contexts for rounds <= the finalized round.
        if let Update::Tip(round, _, _) = &update {
            self.gates.retain_after(round);
        }
        self.application.report(update)
    }
}
