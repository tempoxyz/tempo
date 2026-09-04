//! Wrapper for standard marshal with inline verification.
//!
//! # Overview
//!
//! [`Inline`] adapts any [`Application`] to the marshal/consensus interfaces
//! while keeping block validation in the [`Automaton::verify`] path. Unlike
//! [`super::Deferred`], it does not defer application verification to certification.
//! Instead, it only reports `true` from `verify` after parent/height checks and
//! application verification complete.
//!
//! # Epoch Boundaries
//!
//! As with [`super::Deferred`], when the parent is the last block of the epoch,
//! [`Inline`] re-proposes that boundary block instead of building a new block.
//! This prevents proposing blocks that would be excluded by epoch transition.
//!
//! # Verification Model
//!
//! Inline mode intentionally avoids relying on embedded block context. This allows
//! usage with block types that implement [`crate::Block`] but not
//! [`crate::CertifiableBlock`].
//!
//! Because verification is completed inline, `certify` must only wait for data
//! availability in marshal. No additional deferred verification state needs to
//! be awaited at certify time.
//!
//! # Usage
//!
//! ```rust,ignore
//! let application = Inline::new(
//!     context,
//!     my_application,
//!     marshal_mailbox,
//!     epocher,
//! );
//! ```
//!
//! # When to Use
//!
//! Prefer this wrapper when:
//! - Your application block type is not certifiable.
//! - You prefer simpler verification semantics over deferred verification latency hiding.
//! - You are willing to perform full application verification before casting a notarize vote.

use crate::{
    marshal::{
        application::gates::{self, Gates},
        core::{CommitmentFallback, DigestFallback, Mailbox},
        standard::{
            relay,
            validation::{
                await_and_validate_parent, precheck_epoch_and_reproposal, run_app_verify, Decision,
                ParentCheck,
            },
            Standard,
        },
        Update,
    },
    simplex::{types::Context, Plan},
    types::{Epocher, Round},
    Application, Automaton, Block, CertifiableAutomaton, Epochable, Relay, Reporter,
};
use commonware_actor::Feedback;
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{
    telemetry::{
        metrics::{
            histogram::{Buckets, Timed},
            MetricsExt as _,
        },
        traces::TracedExt as _,
    },
    Clock, Metrics, Spawner,
};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::TracedAsyncMutex,
};
use rand_core::Rng;
use std::sync::Arc;
use tracing::{debug, info_span, Instrument as _};

/// Waits for a marshal block subscription while allowing consensus to cancel the work.
async fn await_block_subscription<T, D>(
    tx: &mut oneshot::Sender<bool>,
    block_rx: oneshot::Receiver<T>,
    digest: &D,
    stage: &'static str,
) -> Option<T>
where
    D: std::fmt::Debug,
{
    select! {
        _ = tx.closed() => {
            debug!(
                stage,
                reason = "consensus dropped receiver",
                "skipping block wait"
            );
            None
        },
        result = block_rx => {
            if result.is_err() {
                debug!(
                    stage,
                    ?digest,
                    reason = "failed to fetch block",
                    "skipping block wait"
                );
            }
            result.ok()
        },
    }
}

/// Standard marshal wrapper that verifies blocks inline in `verify`.
///
/// # Ancestry Validation
///
/// [`Inline`] always validates immediate ancestry before invoking application
/// verification:
/// - Parent digest matches consensus context's expected parent
/// - Child height is exactly parent height plus one
///
/// This is sufficient because the parent must have already been accepted by consensus.
///
/// # Certifiability
///
/// This wrapper requires only [`crate::Block`] for `B`, not
/// [`crate::CertifiableBlock`]. It is designed for applications that cannot
/// recover consensus context directly from block payloads.
pub struct Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: Block + Clone,
    ES: Epocher,
{
    context: Arc<TracedAsyncMutex<E>>,
    application: A,
    marshal: Mailbox<S, Standard<B>>,
    epocher: ES,
    gates: Gates<B::Digest, B>,

    build_duration: Timed,
    proposal_parent_fetch_duration: Timed,
    ancestor_fetch_duration: Timed,
}

impl<E, S, A, B, ES> Clone for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E>,
    B: Block + Clone,
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
        }
    }
}

impl<E, S, A, B, ES> Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, SigningScheme = S, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    /// Creates a new inline-verification wrapper.
    ///
    /// Registers a `build_duration` histogram for proposal latency.
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

        Self {
            context: Arc::new(TracedAsyncMutex::new("marshal.context", context)),
            application,
            marshal,
            epocher,
            gates: Gates::new(),
            build_duration,
            proposal_parent_fetch_duration,
            ancestor_fetch_duration,
        }
    }
}

impl<E, S, A, B, ES> Automaton for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, SigningScheme = S, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Digest = B::Digest;
    type Context = Context<Self::Digest, S::PublicKey>;

    /// Proposes a new block or re-proposes an epoch boundary block.
    ///
    /// Proposal runs in a spawned task and returns a receiver for the resulting digest. The
    /// block is staged before the digest is delivered and handed to marshal when consensus
    /// requests the relay broadcast, which persists it after the send. The resulting sync
    /// handle is awaited only at certification so it overlaps consensus voting. The digest does
    /// not imply durability on its own. [`CertifiableAutomaton::certify`] awaits the registered
    /// certification gate before the finalize vote.
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.inline.propose", level = "info", skip_all, fields(round = %consensus_context.round))]
    async fn propose(
        &mut self,
        consensus_context: Context<Self::Digest, S::PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let gates = self.gates.clone();
        let build_duration = self.build_duration.clone();
        let proposal_parent_fetch_duration = self.proposal_parent_fetch_duration.clone();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("propose")
            .with_attribute("round", consensus_context.round);
        let span = info_span!(
            "marshal.inline.propose.task",
            round = %consensus_context.round
        );
        context.spawn(move |runtime_context| {
            async move {
                // On leader recovery, marshal may already hold a verified block
                // for this round (persisted by a pre-crash propose that reached
                // its relay broadcast while the notarize vote never reached the
                // journal).
                //
                // The parent context recovered by simplex may differ from the one
                // the cached block was built against, so the stored block is not
                // safe to reuse, and proposing a fresh block for a round whose
                // digest may already have been broadcast would equivocate.
                //
                // Skip this view and let the voter nullify it via timeout.
                if marshal
                    .get_verified(consensus_context.round)
                    .await
                    .is_some()
                {
                    debug!(
                        round = ?consensus_context.round,
                        "skipping proposal: verified block already exists for round on restart"
                    );
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
                    CommitmentFallback::FetchByRound {
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

                // At epoch boundary, re-propose the parent block.
                let last_in_epoch = epocher
                    .last(consensus_context.epoch())
                    .expect("current epoch should exist");
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
                    )
                    .instrument(info_span!(
                        "marshal.inline.application.propose",
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

    /// Performs complete verification inline.
    ///
    /// This method:
    /// 1. Waits for the block by digest
    /// 2. Enforces epoch/re-proposal rules
    /// 3. Fetches and validates the parent relationship
    /// 4. Runs application verification over ancestry
    ///
    /// The notarize vote is cast as soon as application verification completes. The block's
    /// durable sync is deferred (it runs concurrently with consensus voting) and its
    /// completion is registered in `gates` for [`Self::certify`] to await before
    /// the finalize vote.
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.inline.verify", level = "info", skip_all, fields(round = %context.round, digest = %digest))]
    async fn verify(
        &mut self,
        context: Context<Self::Digest, S::PublicKey>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // Register the certification gate synchronously so `certify` always finds it, even
        // while the block subscription / durable sync is still in flight. A `true` result means
        // the block is durably persisted; a `false` result is a live local verdict; a dropped
        // sender means verification did not complete and certification should use recovery fetch.
        let round = context.round;
        let (durable_tx, durable_rx) = oneshot::channel();
        self.gates.insert(round, digest, durable_rx);

        let marshal = self.marshal.clone();
        let mut application = self.application.clone();
        let epocher = self.epocher.clone();
        let ancestor_fetch_duration = self.ancestor_fetch_duration.clone();

        let (mut tx, rx) = oneshot::channel();
        let runtime_context = self
            .context
            .lock()
            .await
            .child("inline_verify")
            .with_attribute("round", round);
        let span = info_span!(
            "marshal.inline.verify.task",
            round = %round,
            digest = %digest
        );
        runtime_context.spawn(move |runtime_context| {
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

                let block_request = marshal.subscribe_by_digest(digest, DigestFallback::Wait);
                let Some(block) =
                    await_block_subscription(&mut tx, block_request, &digest, "verification").await
                else {
                    return;
                };

                // Shared pre-checks:
                // - Blocks are invalid if they are not in the expected epoch and are
                //   not a valid boundary re-proposal.
                // - Re-proposals are detected when `digest == context.parent.1`.
                // - Re-proposals skip normal parent/height checks because:
                //   1) the block was already verified when originally proposed
                //   2) parent-child checks would fail by construction when parent == block
                let Some(decision) =
                    precheck_epoch_and_reproposal(&epocher, &marshal, &context, digest, block)
                        .await
                else {
                    return;
                };
                let block = match decision {
                    Decision::Complete(valid) => {
                        // Re-proposal: precheck already persisted the block (durable) when
                        // valid; epoch-reject when invalid. Hand the verdict to certify.
                        tx.send_lossy(valid);
                        durable_tx.send_lossy(valid);
                        return;
                    }
                    Decision::Continue(block) => block,
                };

                // `Continue` implies a non-reproposal, so the parent subscription
                // was started above.
                let parent_request =
                    parent_request.expect("non-reproposal has a parent subscription");

                // Start the candidate store immediately: it depends on neither the
                // parent fetch (which may hit the network) nor the verdict below.
                // Storing before validation is intentional: these caches provide
                // candidate availability/recovery, not a validity decision. The
                // notarize vote follows the app verdict, while certify awaits the
                // registered gate that resolves true only after both app
                // verification succeeds and the store is durable.
                //
                // The verify future below aborts when consensus drops its receiver
                // (the view exited via nullification or finalization), even though
                // certification can still fire for a nullified view. That is
                // deliberate: inline's certify fallback does not need the app
                // verdict (a notarization implies f+1 honest validators already
                // verified), and the store still completes through the join, so
                // the fallback rides the verified write instead of re-persisting.
                let store = marshal.verified(round, Arc::clone(&block));
                let verify_then_vote = async {
                    // Non-reproposal path: validate the parent we already started
                    // fetching.
                    let parent = match await_and_validate_parent(
                        context.parent.1,
                        block.as_ref(),
                        parent_request,
                        &mut tx,
                    )
                    .await
                    {
                        Some(ParentCheck::Valid(parent)) => parent,
                        Some(ParentCheck::Invalid) => {
                            tx.send_lossy(false);
                            return Some(false);
                        }
                        None => return None,
                    };
                    let valid = run_app_verify(
                        runtime_context,
                        context,
                        Arc::clone(&block),
                        parent,
                        &mut application,
                        &marshal,
                        &mut tx,
                        ancestor_fetch_duration,
                    )
                    .await;
                    if let Some(valid) = valid {
                        tx.send_lossy(valid);
                    }
                    valid
                };
                let (verdict, durable) = futures::join!(verify_then_vote, store);
                if let Some(valid) = gates::resolve(verdict, durable) {
                    durable_tx.send_lossy(valid);
                }
            }
            .instrument(span)
        });
        rx
    }
}

/// Inline certification consumes a registered certification gate when present, and
/// falls back to a round-bound fetch/persist path after restart.
impl<E, S, A, B, ES> CertifiableAutomaton for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, SigningScheme = S, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    #[allow(clippy::async_yields_async)]
    #[tracing::instrument(name = "marshal.inline.certify", level = "info", skip_all, fields(round = %round, digest = %digest))]
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        self.gates.flush_unrelayed(&self.marshal, round, digest);

        // `propose`/`verify` register an in-flight certification gate whose result resolves
        // once the block's sync handle completes. Awaiting it here is the durability barrier
        // for the finalize vote, and it lets the sync overlap consensus voting
        // instead of freezing certify with a fresh fsync.
        let task = self.gates.take(round, digest);

        // `verify()` waits only on local broadcast delivery, so nudge a
        // round-bound notarized fetch that can unblock the existing waiter
        // if local broadcast never arrives. For the standard variant, the
        // digest is also the variant commitment.
        if task.is_some() {
            self.marshal.hint_notarized(round, digest);
        }
        let marshal = self.marshal.clone();
        let (mut tx, rx) = oneshot::channel();
        let context = self
            .context
            .lock()
            .await
            .child("inline_certify")
            .with_attribute("round", round);
        context.spawn(move |_| {
            async move {
                // Preserve a live local verdict. Missing local state after an unclean restart
                // has no task and falls through to the round-bound fetch path below.
                if let Some(task) = task {
                    let result = select! {
                        _ = tx.closed() => {
                            debug!(reason = "consensus dropped receiver", "skipping certification");
                            return;
                        },
                        result = task => result,
                    };
                    if let Ok(verdict) = result {
                        tx.send_lossy(verdict);
                        return;
                    }
                }

                // No local certification gate task (for example after an unclean restart):
                // fetch the notarized block and persist it. A Byzantine leader can form a
                // notarization after sending the proposal to only f+1 honest validators, so
                // the validators left without the block must fetch it here to certify and
                // avoid getting stuck.
                let block_rx =
                    marshal.subscribe_by_digest(digest, DigestFallback::FetchByRound { round });
                let Some(block) =
                    await_block_subscription(&mut tx, block_rx, &digest, "certification").await
                else {
                    return;
                };
                if !marshal.certified(round, block).await {
                    return;
                }
                tx.send_lossy(true);
            }
            .instrument(info_span!(
                "marshal.inline.certify.task",
                round = %round,
                digest = %digest
            ))
        });

        rx
    }
}

impl<E, S, A, B, ES> Relay for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Digest = B::Digest;
    type PublicKey = S::PublicKey;
    type Plan = Plan<S::PublicKey>;

    fn broadcast(&mut self, commitment: Self::Digest, plan: Plan<S::PublicKey>) -> Feedback {
        relay::broadcast(&self.gates, &self.marshal, commitment, plan)
    }
}

impl<E, S, A, B, ES> Reporter for Inline<E, S, A, B, ES>
where
    E: Rng + Spawner + Metrics + Clock,
    S: Scheme,
    A: Application<E, Block = B, Context = Context<B::Digest, S::PublicKey>>
        + Reporter<Activity = Update<B>>,
    B: Block + Clone,
    ES: Epocher,
{
    type Activity = A::Activity;

    /// Forwards consensus activity to the wrapped application reporter.
    fn report(&mut self, update: Self::Activity) -> Feedback {
        if let Update::Tip(tip_round, _, _) = &update {
            self.gates.retain_after(tip_round);
        }
        self.application.report(update)
    }
}

#[cfg(test)]
mod tests {
    use super::Inline;
    use crate::{
        marshal::mocks::{
            harness::{
                default_leader, make_raw_block, setup_network_with_participants, Ctx,
                StandardHarness, TestHarness, B, BLOCKS_PER_EPOCH, NAMESPACE, NUM_VALIDATORS, S, V,
            },
            verifying::{GatedVerifyingApp, MockVerifyingApp},
        },
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Context},
        types::{Epoch, FixedEpocher, Height, Round, View},
        Application, Automaton, Block, CertifiableAutomaton, Relay,
    };
    use commonware_broadcast::Broadcaster;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Scheme},
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner, Supervisor as _};
    use commonware_utils::{channel::fallible::OneshotExt, NZUsize};
    use rand::Rng;
    use std::time::Duration;

    // Compile-time assertion only: inline standard wrapper must not require `CertifiableBlock`.
    #[allow(dead_code)]
    fn assert_non_certifiable_block_supported<E, S, A, B, ES>()
    where
        E: Rng + Spawner + Metrics + Clock,
        S: Scheme,
        A: Application<E, Block = B, SigningScheme = S, Context = Context<B::Digest, S::PublicKey>>,
        B: Block + Clone,
        ES: crate::types::Epocher,
    {
        fn assert_automaton<T: Automaton>() {}
        fn assert_certifiable<T: CertifiableAutomaton>() {}
        fn assert_relay<T: Relay>() {}

        assert_automaton::<Inline<E, S, A, B, ES>>();
        assert_certifiable::<Inline<E, S, A, B, ES>>();
        assert_relay::<Inline<E, S, A, B, ES>>();
    }

    #[test_traced("INFO")]
    fn test_certify_returns_immediately_after_verify_fetches_block() {
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Seed the parent and child blocks in marshal so verify can fetch locally.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = Ctx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(marshal.verified(parent_round, parent).await);

            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = Ctx {
                round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let block =
                B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
            let digest = block.digest();
            assert!(marshal.verified(round, block).await);

            // Complete verify first so the block is already available locally.
            let verify_rx = inline.verify(verify_context, digest).await;
            assert!(
                verify_rx.await.unwrap(),
                "verify should complete successfully before certify"
            );

            // Certify should return immediately instead of waiting on marshal.
            let certify_rx = inline.certify(round, digest).await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should return immediately once verify has fetched the block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not hang after local verify completed");
                },
            }
        });
    }

    #[test_traced("INFO")]
    fn test_certify_succeeds_without_verify_task() {
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            // Seed the parent and child blocks in marshal without starting a verify task.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = Ctx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis.digest()),
            };
            let parent = B::new::<Sha256>(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            assert!(marshal.verified(parent_round, parent).await);

            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = Ctx {
                round,
                leader: me,
                parent: (View::new(1), parent_digest),
            };
            let block =
                B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
            let digest = block.digest();
            assert!(marshal.verified(round, block).await);

            // Certify should still resolve by waiting on marshal block availability directly.
            let certify_rx = inline.certify(round, digest).await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should resolve once block availability is known"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not hang when block is already available in marshal");
                },
            }
        });
    }

    #[test_traced("INFO")]
    fn test_certify_reproposal_uses_available_blocks_after_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let mut oracle =
                setup_network_with_participants(context.child("network"), NZUsize!(1), participants.clone())
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
            let marshal_actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut inline = Inline::new(context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

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
            assert!(
                marshal.verified(boundary_round, boundary_block).await
            );

            let reproposal_round = Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
            let reproposal_context = Ctx {
                round: reproposal_round,
                leader: me,
                parent: (View::new(boundary_height.get()), boundary_digest),
            };

            let verify_rx = inline.verify(reproposal_context, boundary_digest).await;
            assert!(
                verify_rx.await.unwrap(),
                "verify should accept a valid boundary re-proposal"
            );

            marshal_actor_handle.abort();
            drop(marshal);
            context.sleep(Duration::from_millis(1)).await;

            let certify_rx = inline.certify(reproposal_round, boundary_digest).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify should use the available_blocks fast path for verified re-proposals"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should not depend on marshal after verify cached a re-proposal");
                },
            }
        });
    }

    /// Regression: `certify` resolving true drives the finalize vote in inline
    /// mode, so it must imply the block is durably persisted even when the
    /// certify path subscribed before `verify()` finished.
    #[test_traced("WARN")]
    fn test_inline_certify_persists_block_before_resolving() {
        for seed in 0u64..16 {
            inline_certify_persists_block_before_resolving_at(seed);
        }
    }

    fn inline_certify_persists_block_before_resolving_at(seed: u64) {
        let runner = deterministic::Runner::new(
            deterministic::Config::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(60))),
        );
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
            let actor_handle = setup.actor_handle;

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_digest),
            };
            let child = B::new::<Sha256>(child_ctx.clone(), parent_digest, Height::new(2), 200);
            let child_digest = child.digest();

            assert!(
                buffer
                    .broadcast(commonware_p2p::Recipients::Some(vec![]), parent.clone())
                    .accepted(),
                "buffer broadcast for parent should be accepted"
            );
            assert!(
                buffer
                    .broadcast(commonware_p2p::Recipients::Some(vec![]), child.clone())
                    .accepted(),
                "buffer broadcast for child should be accepted"
            );

            let verify_rx = inline.verify(child_ctx, child_digest).await;
            let certify_result = inline
                .certify(child_round, child_digest)
                .await
                .await
                .expect("certify result missing");
            assert!(certify_result, "certify should succeed");

            actor_handle.abort();
            drop(verify_rx);
            drop(inline);
            drop(marshal);
            drop(buffer);

            let setup2 = StandardHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            let post_restart = marshal2.get_block(&child_digest).await;
            assert!(
                post_restart.is_some(),
                "certify resolved true so block must be durably persisted (seed={seed})"
            );
        });
    }

    /// Regression: in inline mode `propose` registers a certification gate for the
    /// built block that `certify` awaits. After the leader certifies its own proposal,
    /// the block must be durably recoverable. This is the >=f+1 guarantee: the leader
    /// certifies its own block through marshal so it awaits durability before the
    /// finalize vote.
    #[test_traced("WARN")]
    fn test_inline_propose_then_certify_persists_block() {
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);

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
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest = inline
                .propose(ctx)
                .await
                .await
                .expect("propose must return a digest");
            assert_eq!(
                digest, child_digest,
                "propose must return the built block's digest"
            );

            // The leader certifies its own proposal, which awaits the deferred sync handle.
            assert!(
                inline
                    .certify(round, child_digest)
                    .await
                    .await
                    .expect("certify result missing"),
                "certify must succeed for the leader's own proposal"
            );

            // After certify, the block must be durable across an unclean restart.
            actor_handle.abort();
            drop(inline);
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

    /// Dropping the verify receiver before the block is available closes the
    /// synchronously-registered certification gate. `certify` must recover through
    /// the fetch/certified path instead of returning the closed gate to consensus.
    #[test_traced("WARN")]
    fn test_inline_certify_recovers_after_verify_receiver_drop() {
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut inline = Inline::new(
                context.child("inline"),
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

            let verify_rx = inline.verify(block_context, digest).await;
            drop(verify_rx);

            // Give the verify task a chance to observe the dropped receiver while its
            // block subscription is still pending.
            context.sleep(Duration::from_millis(10)).await;

            assert!(marshal.verified(round, block).await);
            let certify_rx = inline.certify(round, digest).await;
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

    /// The store request runs concurrently with `app.verify`, not after the
    /// notarize vote: while gated application verification is still blocked, the
    /// block has already reached marshal and is locally queryable even though the
    /// sync handle may still be pending. Releasing verification then lets the
    /// notarize vote resolve and certification await the registered certification
    /// gate. Separate restart tests cover durable recovery after certification.
    #[test_traced("WARN")]
    fn test_inline_store_overlaps_app_verify() {
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

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let (mock_app, verify_started, release_verify): (GatedVerifyingApp<B, S>, _, _) =
                GatedVerifyingApp::new();
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let parent = make_raw_block(genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = Ctx {
                round: child_round,
                leader: me.clone(),
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

            let verify_rx = inline.verify(child_ctx, child_digest).await;

            // Application verification is now blocked. The store request runs concurrently
            // with it, so the block is locally queryable even though the notarize vote has
            // not been cast and the sync handle may still be pending.
            verify_started
                .await
                .expect("verify should reach the gated application");
            assert!(
                marshal.get_block(&child_digest).await.is_some(),
                "the store request runs concurrently with app.verify, so the block is locally queryable while verification is still gated"
            );

            // Releasing verification resolves the notarize vote and lets certification
            // succeed (valid and durable).
            release_verify.send_lossy(());
            assert!(
                verify_rx.await.expect("verify result missing"),
                "inline verify should pass once verification is released"
            );
            let certify_rx = inline.certify(child_round, child_digest).await;
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

    /// Regression: if marshal persisted a verified block for a round before
    /// a crash (via a prior `propose` call) but the simplex notarize artifact
    /// never reached the journal, the restarted leader must skip proposing
    /// for that round. The cached block was built against a parent context
    /// that replay may have changed, so reusing it can broadcast a proposal
    /// whose payload no longer matches the recovered header. Building a
    /// fresh block would also be unsafe because the pre-crash digest may
    /// already have been broadcast, so a second proposal for the round would
    /// equivocate. Dropping the receiver lets the voter nullify the view via
    /// `MissingProposal`.
    #[test_traced("WARN")]
    fn test_propose_skips_when_verified_block_exists_on_restart() {
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
            let round = Round::new(Epoch::zero(), View::new(1));
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let ctx = Ctx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis.digest()),
            };

            // Pre-crash: seed `verified_blocks[V=1]` through the live mailbox,
            // mirroring an aborted pre-crash `Inline::propose` that persisted
            // its verified block before the voter could journal a notarize.
            let pre_setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let pre_marshal = pre_setup.mailbox;
            let pre_actor = pre_setup.actor_handle;
            let pre_extra = pre_setup.extra;
            let pre_application = pre_setup.application;

            let stale_block = B::new::<Sha256>(ctx.clone(), genesis.digest(), Height::new(1), 100);
            assert!(pre_marshal.verified(round, stale_block).await);

            // Simulate a crash: abort the actor and drop every handle so the
            // storage partition is fully released before reopening.
            pre_actor.abort();
            drop(pre_marshal);
            drop(pre_extra);
            drop(pre_application);

            // Post-crash: reopen the same partition. The verified block must
            // be recovered from storage during archive restore so that
            // `Message::GetVerified` on the new mailbox observes it.
            let post_setup = StandardHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let post_marshal = post_setup.mailbox;

            let fresh_block = B::new::<Sha256>(ctx.clone(), genesis.digest(), Height::new(1), 200);
            let mock_app: MockVerifyingApp<B, S> =
                MockVerifyingApp::new().with_propose_result(fresh_block);
            let mut inline = Inline::new(
                context.child("inline"),
                mock_app,
                post_marshal.clone(),
                FixedEpocher::new(BLOCKS_PER_EPOCH),
            );

            let digest_rx = inline.propose(ctx).await;
            assert!(
                digest_rx.await.is_err(),
                "propose must drop the receiver so the voter nullifies the round via timeout"
            );
        });
    }
}
