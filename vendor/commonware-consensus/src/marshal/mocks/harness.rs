//! Test harness for marshal variants.
//!
//! This module provides a trait-based abstraction that allows writing tests once
//! and running them against both the standard and coding marshal variants.

use crate::{
    marshal::{
        ancestry::BlockProvider,
        coding::{
            shards,
            types::{coding_config_for_participants, hash_context, CodedBlock},
            Coding,
        },
        config::{Config, Start},
        core::{Actor, CommitmentFallback, DigestFallback, Mailbox},
        mocks::{application::Application, block::Block},
        resolver::p2p as resolver,
        standard::Standard,
        Identifier,
    },
    simplex::{
        scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
        types::{Activity, Context, Finalization, Finalize, Notarization, Notarize, Proposal},
    },
    types::{coding::Commitment, Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
    Heightable, Reporter,
};
use commonware_broadcast::buffered;
use commonware_coding::{CodecConfig, ReedSolomon};
use commonware_cryptography::{
    bls12381::primitives::variant::MinPk,
    certificate::{mocks::Fixture, ConstantProvider, Provider, Scoped, Verifier as _},
    ed25519::{PrivateKey, PublicKey},
    sha256::{Digest as Sha256Digest, Sha256},
    Committable, Digest as DigestTrait, Digestible, Hasher as _, Signer,
};
use commonware_macros::select;
use commonware_p2p::simulated::{self, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef,
    deterministic,
    telemetry::metrics::{
        histogram::{Buckets, Timed},
        MetricsExt as _,
    },
    Clock, Quota, Runner, Supervisor as _,
};
use commonware_storage::{
    archive::{immutable, prunable},
    translator::EightCap,
};
use commonware_utils::{test_rng, vec::NonEmptyVec, NZUsize, TestRng, NZU16, NZU64};
use futures::StreamExt;
use rand::{
    seq::{IteratorRandom, SliceRandom},
    RngExt as _,
};
use std::{
    collections::BTreeMap,
    future::Future,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::info;

// Common type aliases
pub type D = Sha256Digest;
pub type K = PublicKey;
pub type Ctx = Context<D, K>;
pub type B = Block<D, Ctx>;
pub type V = MinPk;
pub type S = bls12381_threshold_vrf::Scheme<K, V>;
pub type P = ConstantProvider<S, Epoch>;

// Coding variant type aliases (uses Commitment in context)
pub type CodingCtx = Context<Commitment, K>;
pub type CodingB = Block<D, CodingCtx>;

// Common test constants
pub const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub const NAMESPACE: &[u8] = b"test";
pub const NUM_VALIDATORS: u32 = 4;
pub const QUORUM: u32 = 3;
pub const NUM_BLOCKS: u64 = 160;
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(20);
pub const LINK: Link = Link {
    latency: Duration::from_millis(100),
    jitter: Duration::from_millis(1),
    success_rate: 1.0,
};
pub const UNRELIABLE_LINK: Link = Link {
    latency: Duration::from_millis(200),
    jitter: Duration::from_millis(50),
    success_rate: 0.7,
};
pub const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// A provider that always returns `None`, modeling an application that
/// has pruned all epoch state.
#[derive(Clone)]
pub struct EmptyProvider;

impl Provider for EmptyProvider {
    type Scope = Epoch;
    type Scheme = S;

    fn scoped(&self, _scope: Epoch) -> Option<Scoped<S>> {
        None
    }
}

/// Default leader key for tests.
pub fn default_leader() -> K {
    PrivateKey::from_seed(0).public_key()
}

/// Create a raw test block with a derived context.
pub fn make_raw_block(parent: D, height: Height, timestamp: u64) -> B {
    let parent_view = height
        .previous()
        .map(|h| View::new(h.get()))
        .unwrap_or(View::zero());
    let context = Ctx {
        round: Round::new(Epoch::zero(), View::new(height.get())),
        leader: default_leader(),
        parent: (parent_view, parent),
    };
    B::new::<Sha256>(context, parent, height, timestamp)
}

/// Setup network for tests with an initial participant peer set.
pub async fn setup_network_with_participants<I>(
    context: deterministic::Context,
    tracked_peer_sets: NonZeroUsize,
    participants: I,
) -> Oracle<K, deterministic::Context>
where
    I: IntoIterator<Item = K>,
{
    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            disconnect_on_block: true,
            tracked_peer_sets,
        },
        participants,
    )
    .await;
    network.start();
    oracle
}

/// Setup network links between peers.
pub async fn setup_network_links(
    oracle: &mut Oracle<K, deterministic::Context>,
    peers: &[K],
    link: Link,
) {
    for p1 in peers.iter() {
        for p2 in peers.iter() {
            if p2 == p1 {
                continue;
            }
            let _ = oracle.add_link(p1.clone(), p2.clone(), link.clone()).await;
        }
    }
}

/// Result of setting up a validator.
pub struct ValidatorSetup<H: TestHarness> {
    pub application: Application<H::ApplicationBlock>,
    pub mailbox: Mailbox<S, H::Variant>,
    pub extra: H::ValidatorExtra,
    pub height: Option<Height>,
    pub actor_handle: commonware_runtime::Handle<()>,
}

/// Per-validator handle for test operations.
pub struct ValidatorHandle<H: TestHarness> {
    pub mailbox: Mailbox<S, H::Variant>,
    pub extra: H::ValidatorExtra,
}

impl<H: TestHarness> Clone for ValidatorHandle<H> {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            extra: self.extra.clone(),
        }
    }
}

/// A test harness that abstracts over marshal variant differences.
pub trait TestHarness: 'static + Sized {
    /// The application block type.
    /// Note: We require `Digestible<Digest = D>` so generic test functions can use
    /// `subscribe_by_digest` which expects the block's digest type.
    type ApplicationBlock: crate::Block + Digestible<Digest = D> + Clone + Send + 'static;

    /// The marshal variant type.
    type Variant: crate::marshal::core::Variant<
        ApplicationBlock = Self::ApplicationBlock,
        Commitment = Self::Commitment,
    >;

    /// The block type used in test operations.
    type TestBlock: Heightable
        + Clone
        + Send
        + Sync
        + Into<<Self::Variant as crate::marshal::core::Variant>::Block>;

    /// Additional per-validator state (e.g., shards mailbox for coding).
    type ValidatorExtra: Clone + Send;

    /// The commitment type for consensus certificates.
    type Commitment: DigestTrait;

    /// Setup a single validator with all necessary infrastructure.
    fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> impl Future<Output = ValidatorSetup<Self>> + Send;

    /// Setup a single validator with custom acknowledgement pipeline settings.
    fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> impl Future<Output = ValidatorSetup<Self>> + Send;

    /// Create a test block from parent and height.
    fn genesis_parent_commitment(num_participants: u16) -> Self::Commitment;

    /// Create a test block from parent and height.
    fn make_test_block(
        parent: D,
        parent_commitment: Self::Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> Self::TestBlock;

    /// Create the height-zero block used to seed a fresh marshal actor.
    fn genesis_block(num_participants: u16) -> Self::TestBlock {
        Self::make_test_block(
            Sha256::hash(b""),
            Self::genesis_parent_commitment(num_participants),
            Height::zero(),
            0,
            num_participants,
        )
    }

    /// Get the commitment from a test block.
    fn commitment(block: &Self::TestBlock) -> Self::Commitment;

    /// Get the digest from a test block.
    fn digest(block: &Self::TestBlock) -> D;

    /// Get the height from a test block.
    fn height(block: &Self::TestBlock) -> Height;

    /// Drive the leader's propose durability handshake: persist the proposed
    /// block and assert it is durable, without broadcasting it (mirroring the
    /// certify-time flush of a staged proposal whose broadcast was never
    /// requested). Scenarios drive dissemination explicitly, so a proposal
    /// must not pre-seed peer buffers and mask delivery and backfill paths.
    fn propose(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> impl Future<Output = ()> + Send {
        async move {
            let block: <Self::Variant as crate::marshal::core::Variant>::Block =
                block.clone().into();
            assert!(
                handle.mailbox.verified(round, block).await,
                "proposed block must be durable"
            );
        }
    }

    /// Mark a block as verified.
    fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        all_handles: &mut [ValidatorHandle<Self>],
    ) -> impl Future<Output = ()> + Send;

    /// Mark a block as certified.
    fn certify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> impl Future<Output = bool> + Send;

    /// Create a finalization certificate.
    fn make_finalization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, Self::Commitment>;

    /// Create a notarization certificate.
    fn make_notarization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, Self::Commitment>;

    /// Report a finalization to the mailbox.
    fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, Self::Commitment>,
    ) -> impl Future<Output = ()> + Send;

    /// Report a notarization to the mailbox.
    fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, Self::Commitment>,
    ) -> impl Future<Output = ()> + Send;

    /// Get the timeout duration for the finalize test.
    fn finalize_timeout() -> Duration;

    /// Setup validator for pruning test with prunable archives.
    #[allow(clippy::type_complexity)]
    fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> impl Future<
        Output = (
            Mailbox<S, Self::Variant>,
            Self::ValidatorExtra,
            Application<Self::ApplicationBlock>,
        ),
    > + Send;

    /// Verify a block for the pruning test (simpler than full verify).
    fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> impl Future<Output = ()> + Send;
}

fn contract_runner(seed: u64) -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30))),
    )
}

fn restart_cycles_for_seed(seed: u64) -> usize {
    let mut rng = TestRng::new(seed);
    rng.random_range(2..=4)
}

struct HailstormValidator<H: TestHarness> {
    application: Application<H::ApplicationBlock>,
    handle: ValidatorHandle<H>,
    actor_handle: commonware_runtime::Handle<()>,
}

type CanonicalEntry<H> = (Height, D, Finalization<S, <H as TestHarness>::Commitment>);
type CanonicalChain<H> = Vec<CanonicalEntry<H>>;

struct HailstormState<'a, H: TestHarness> {
    validators: &'a mut [Option<HailstormValidator<H>>],
    canonical: &'a mut CanonicalChain<H>,
    parent: &'a mut D,
    parent_commitment: &'a mut H::Commitment,
    participants: &'a [K],
    schemes: &'a [S],
}

fn active_validator_indices<H: TestHarness>(
    validators: &[Option<HailstormValidator<H>>],
) -> Vec<usize> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(idx, validator)| validator.as_ref().map(|_| idx))
        .collect()
}

async fn wait_for_validator_height<H: TestHarness>(
    context: &mut deterministic::Context,
    validator: &HailstormValidator<H>,
    height: Height,
    expected_digest: D,
    expected_finalization: &Finalization<S, H::Commitment>,
    label: &str,
) {
    loop {
        let block = validator.handle.mailbox.get_block(height).await;
        let finalization = validator.handle.mailbox.get_finalization(height).await;
        if let (Some(block), Some(finalization)) = (block, finalization) {
            assert_eq!(
                block.digest(),
                expected_digest,
                "{label}: wrong block digest at height {}",
                height.get()
            );
            assert_eq!(
                finalization.round(),
                expected_finalization.round(),
                "{label}: wrong finalization round at height {}",
                height.get()
            );
            assert_eq!(
                finalization.proposal.payload,
                expected_finalization.proposal.payload,
                "{label}: wrong finalization payload at height {}",
                height.get()
            );
            break;
        }
        context.sleep(Duration::from_millis(10)).await;
    }
}

async fn assert_validator_matches_canonical<H: TestHarness>(
    validator: &HailstormValidator<H>,
    canonical: &[CanonicalEntry<H>],
    num_participants: u16,
    label: &str,
) {
    let genesis_digest = H::digest(&H::genesis_block(num_participants));
    let delivered = validator.application.blocks();
    for (height, block) in delivered {
        let expected_digest = canonical
            .iter()
            .find(|(expected_height, _, _)| *expected_height == height)
            .map(|(_, digest, _)| *digest)
            .or_else(|| (height == Height::zero()).then_some(genesis_digest))
            .unwrap_or_else(|| {
                panic!(
                    "{label}: unexpected delivered block at height {}",
                    height.get()
                )
            });
        assert_eq!(
            block.digest(),
            expected_digest,
            "{label}: application delivered wrong digest at height {}",
            height.get()
        );
    }

    if let Some((height, digest)) = validator.application.tip() {
        let (expected_height, expected_digest) =
            if let Some((expected_height, expected_digest, _)) = canonical.last() {
                (*expected_height, *expected_digest)
            } else {
                (Height::zero(), genesis_digest)
            };
        assert_eq!(
            height, expected_height,
            "{label}: application reported wrong tip height",
        );
        assert_eq!(
            digest,
            expected_digest,
            "{label}: application reported wrong tip digest at height {}",
            height.get()
        );
    }

    for (height, expected_digest, expected_finalization) in canonical {
        let stored_block = validator
            .handle
            .mailbox
            .get_block(*height)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "{label}: missing finalized block at height {}",
                    height.get()
                )
            });
        assert_eq!(
            stored_block.digest(),
            *expected_digest,
            "{label}: stored wrong block digest at height {}",
            height.get()
        );

        let stored_finalization = validator
            .handle
            .mailbox
            .get_finalization(*height)
            .await
            .unwrap_or_else(|| panic!("{label}: missing finalization at height {}", height.get()));
        assert_eq!(
            stored_finalization.round(),
            expected_finalization.round(),
            "{label}: stored wrong finalization round at height {}",
            height.get()
        );
        assert_eq!(
            stored_finalization.proposal.payload,
            expected_finalization.proposal.payload,
            "{label}: stored wrong finalization payload at height {}",
            height.get()
        );
    }

    if let Some((height, digest, _)) = canonical.last() {
        assert_eq!(
            validator.handle.mailbox.get_info(Identifier::Latest).await,
            Some((*height, *digest)),
            "{label}: latest info should match the canonical tip",
        );
    }
}

async fn assert_active_validators_match_canonical<H: TestHarness>(
    validators: &[Option<HailstormValidator<H>>],
    canonical: &[CanonicalEntry<H>],
    num_participants: u16,
) {
    for idx in active_validator_indices(validators) {
        let validator = validators[idx]
            .as_ref()
            .expect("active validator should be present");
        assert_validator_matches_canonical(
            validator,
            canonical,
            num_participants,
            &format!("validator_{idx}"),
        )
        .await;
    }
}

/// A height that has been driven through propose + verify but has not yet had
/// its finalization reported to the validators.
struct PendingHailstormHeight<H: TestHarness> {
    height: Height,
    expected_digest: D,
    finalization: Finalization<S, H::Commitment>,
    next_parent: D,
    next_parent_commitment: H::Commitment,
}

/// Drives one height through the propose and verify phases without reporting
/// finalization. The returned pending height must be committed via
/// [`finalize_hailstorm_height`] to advance the canonical chain.
async fn drive_hailstorm_height_up_to_verify<H: TestHarness>(
    height_value: u64,
    context: &mut deterministic::Context,
    state: &mut HailstormState<'_, H>,
) -> PendingHailstormHeight<H> {
    let height = Height::new(height_value);
    let active = active_validator_indices(state.validators);
    let proposer_idx = active[context.random_range(0..active.len())];
    let verifier_count = usize::min(QUORUM as usize, active.len());
    let verifier_indices = active
        .iter()
        .copied()
        .filter(|idx| *idx != proposer_idx)
        .sample(context, verifier_count.saturating_sub(1));
    let block = H::make_test_block(
        *state.parent,
        *state.parent_commitment,
        height,
        height_value,
        state.participants.len() as u16,
    );
    let round = Round::new(Epoch::zero(), View::new(height_value));
    let proposal = Proposal {
        round,
        parent: height
            .previous()
            .map(|previous| View::new(previous.get()))
            .unwrap_or(View::zero()),
        payload: H::commitment(&block),
    };
    let expected_digest = H::digest(&block);
    let finalization = H::make_finalization(proposal.clone(), state.schemes, QUORUM);

    {
        let proposer = state.validators[proposer_idx]
            .as_mut()
            .expect("proposer should be active");
        H::propose(&mut proposer.handle, round, &block).await;
        H::report_notarization(
            &mut proposer.handle.mailbox,
            H::make_notarization(proposal, state.schemes, QUORUM),
        )
        .await;
    }

    for verifier_idx in verifier_indices.iter().copied() {
        let verifier = state.validators[verifier_idx]
            .as_mut()
            .expect("verifier should be active");
        H::verify(&mut verifier.handle, round, &block, &mut []).await;
    }

    PendingHailstormHeight {
        height,
        expected_digest,
        finalization,
        next_parent: expected_digest,
        next_parent_commitment: H::commitment(&block),
    }
}

/// Reports the finalization for a previously-driven pending height to every
/// currently-active validator, waits for them to reach the height, and updates
/// the canonical chain.
async fn finalize_hailstorm_height<H: TestHarness>(
    pending: PendingHailstormHeight<H>,
    context: &mut deterministic::Context,
    state: &mut HailstormState<'_, H>,
) {
    let PendingHailstormHeight {
        height,
        expected_digest,
        finalization,
        next_parent,
        next_parent_commitment,
    } = pending;

    for idx in active_validator_indices(state.validators) {
        let validator = state.validators[idx]
            .as_mut()
            .expect("validator should remain active");
        H::report_finalization(&mut validator.handle.mailbox, finalization.clone()).await;
    }

    state
        .canonical
        .push((height, expected_digest, finalization));
    *state.parent = next_parent;
    *state.parent_commitment = next_parent_commitment;

    let (_, _, expected_finalization) = state
        .canonical
        .last()
        .expect("canonical chain should contain the new height");
    for idx in active_validator_indices(state.validators) {
        let validator = state.validators[idx]
            .as_ref()
            .expect("validator should be active");
        wait_for_validator_height(
            context,
            validator,
            height,
            expected_digest,
            expected_finalization,
            &format!("validator_{idx}"),
        )
        .await;
    }
}

async fn advance_hailstorm_to<H: TestHarness>(
    target: u64,
    context: &mut deterministic::Context,
    state: &mut HailstormState<'_, H>,
) {
    for height_value in (state.canonical.len() as u64 + 1)..=target {
        let pending = drive_hailstorm_height_up_to_verify(height_value, context, state).await;
        finalize_hailstorm_height(pending, context, state).await;
    }

    assert_active_validators_match_canonical(
        state.validators,
        state.canonical,
        state.participants.len() as u16,
    )
    .await;
}

/// Stress marshal with repeated validator crashes and recoveries while a
/// canonical finalized chain continues to advance.
pub fn hailstorm<H: TestHarness>(
    seed: u64,
    shutdowns: usize,
    interval: u64,
    max_down: usize,
    link: Link,
) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(H::finalize_timeout())),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(3),
            participants.clone(),
        )
        .await;
        setup_network_links(&mut oracle, &participants, link.clone()).await;

        let mut validators = Vec::new();
        for (idx, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", idx),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[idx].clone()),
            )
            .await;
            validators.push(Some(HailstormValidator::<H> {
                application: setup.application,
                handle: ValidatorHandle {
                    mailbox: setup.mailbox,
                    extra: setup.extra,
                },
                actor_handle: setup.actor_handle,
            }));
        }

        let mut canonical = CanonicalChain::<H>::new();
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let mut target_height = 0u64;
        let max_interval = interval.max(1);
        let max_down = max_down.max(1);

        for shutdown_idx in 0..shutdowns {
            let leadup = context.random_range(1..=max_interval);
            target_height += leadup;

            // Pick validators to crash and compute how far the advance should
            // run before aborting them. `crash_after == leadup` fires the
            // crash after every new height has fully finalized; any smaller
            // value lands mid-cycle, after `verified` / `certified` have
            // returned for the post-crash height but before finalization is
            // reported for it.
            let active_pre = active_validator_indices(&validators);
            let down_limit = usize::min(max_down, active_pre.len().saturating_sub(1));
            let down_count = context.random_range(1..=down_limit.max(1));
            let mut selected = active_pre.iter().copied().sample(&mut context, down_count);
            selected.sort_unstable();
            let crash_after = context.random_range(0..=leadup);
            let persisted_height = target_height - leadup + crash_after;

            {
                let mut state = HailstormState {
                    validators: &mut validators,
                    canonical: &mut canonical,
                    parent: &mut parent,
                    parent_commitment: &mut parent_commitment,
                    participants: &participants,
                    schemes: &schemes,
                };
                advance_hailstorm_to(persisted_height, &mut context, &mut state).await;
            }

            // Crash mid-advance: drive propose + verify for the next height
            // and abort the selected validators before reporting
            // finalization. If `crash_after == leadup - 1` the crash still
            // happens after the last height's finalization because the loop
            // below is a no-op.
            let pending = if persisted_height < target_height {
                let mut state = HailstormState {
                    validators: &mut validators,
                    canonical: &mut canonical,
                    parent: &mut parent,
                    parent_commitment: &mut parent_commitment,
                    participants: &participants,
                    schemes: &schemes,
                };
                Some(
                    drive_hailstorm_height_up_to_verify(
                        persisted_height + 1,
                        &mut context,
                        &mut state,
                    )
                    .await,
                )
            } else {
                None
            };

            for idx in selected.iter().copied() {
                let crashed = validators[idx]
                    .take()
                    .expect("selected validator should be active");
                crashed.actor_handle.abort();
                let _ = crashed.actor_handle.await;
            }

            if let Some(pending) = pending {
                let mut state = HailstormState {
                    validators: &mut validators,
                    canonical: &mut canonical,
                    parent: &mut parent,
                    parent_commitment: &mut parent_commitment,
                    participants: &participants,
                    schemes: &schemes,
                };
                finalize_hailstorm_height(pending, &mut context, &mut state).await;
            }

            info!(
                seed,
                shutdown_idx,
                ?selected,
                down_count,
                persisted_height,
                leadup,
                crash_after,
                "marshal hailstorm shutdown"
            );

            let downtime = context.random_range(1..=max_interval);
            target_height += downtime;
            let mut state = HailstormState {
                validators: &mut validators,
                canonical: &mut canonical,
                parent: &mut parent,
                parent_commitment: &mut parent_commitment,
                participants: &participants,
                schemes: &schemes,
            };
            advance_hailstorm_to(target_height, &mut context, &mut state).await;

            for idx in selected.iter().copied() {
                let restarted = H::setup_validator(
                    context
                        .child("validator")
                        .with_attribute("index", idx)
                        .with_attribute("restart", shutdown_idx),
                    &mut oracle,
                    participants[idx].clone(),
                    ConstantProvider::new(schemes[idx].clone()),
                )
                .await;
                assert_eq!(
                    restarted.height,
                    Some(Height::new(persisted_height)),
                    "validator {idx} should recover its persisted finalized height before replay"
                );

                let mut restarted = HailstormValidator::<H> {
                    application: restarted.application,
                    handle: ValidatorHandle {
                        mailbox: restarted.mailbox,
                        extra: restarted.extra,
                    },
                    actor_handle: restarted.actor_handle,
                };
                for (_, _, finalization) in canonical.iter().skip(persisted_height as usize) {
                    H::report_finalization(&mut restarted.handle.mailbox, finalization.clone())
                        .await;
                }
                validators[idx] = Some(restarted);
            }

            for idx in selected.iter().copied() {
                let validator = validators[idx]
                    .as_ref()
                    .expect("restarted validator should be active");
                for (height, digest, finalization) in canonical.iter() {
                    wait_for_validator_height(
                        &mut context,
                        validator,
                        *height,
                        *digest,
                        finalization,
                        &format!("validator_{idx}_restarted"),
                    )
                    .await;
                }
            }
            assert_active_validators_match_canonical(
                &validators,
                &canonical,
                participants.len() as u16,
            )
            .await;
            info!(
                seed,
                shutdown_idx,
                ?selected,
                target_height,
                downtime,
                "marshal hailstorm recovered"
            );
        }

        context.auditor().state()
    })
}

/// Contract: a durable propose handshake (the proposal's sync handle
/// resolving durable) means the block survives an immediate crash and
/// repeated recoveries.
pub fn proposed_success_implies_recoverable_after_restart<H: TestHarness>(
    seeds: impl IntoIterator<Item = u64>,
) {
    for seed in seeds {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(
            &mut TestRng::new(seed),
            NAMESPACE,
            NUM_VALIDATORS,
        );

        let me = participants[0].clone();
        let provider = ConstantProvider::new(schemes[0].clone());
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = H::make_test_block(
            Sha256::hash(b""),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(1),
            100,
            NUM_VALIDATORS as u16,
        );
        let digest = H::digest(&block);
        let recovery_cycles = restart_cycles_for_seed(seed);

        let (_, mut checkpoint) = contract_runner(seed).start_and_recover({
            let participants = participants.clone();
            let me = me.clone();
            let provider = provider.clone();
            let block = block.clone();
            move |context| async move {
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let setup = H::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    provider.clone(),
                )
                .await;
                let mut handle = ValidatorHandle::<H> {
                    mailbox: setup.mailbox,
                    extra: setup.extra,
                };
                H::propose(&mut handle, round, &block).await;
            }
        });

        for cycle in 0..recovery_cycles {
            let ((), next_checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover({
                    let participants = participants.clone();
                    let me = me.clone();
                    let provider = provider.clone();
                    move |context| async move {
                        let mut oracle = setup_network_with_participants(
                            context.child("network"),
                            NZUsize!(1),
                            participants.clone(),
                        )
                        .await;
                        let restarted = H::setup_validator(
                            context
                                .child("validator")
                                .with_attribute("index", 0)
                                .with_attribute("restart", cycle),
                            &mut oracle,
                            me.clone(),
                            provider.clone(),
                        )
                        .await;
                        let recovered = restarted.mailbox.get_verified(round).await.unwrap_or_else(
                            || panic!("durable proposal lost after restart (seed={seed}, cycle={cycle})"),
                        );
                        assert_eq!(
                            recovered.digest(),
                            digest,
                            "get_verified(round) must return the proposed block \
                             (seed={seed}, cycle={cycle})"
                        );
                        assert!(
                            restarted.mailbox.get_block(&digest).await.is_some(),
                            "get_block(&digest) must also recover the proposed block \
                             (seed={seed}, cycle={cycle})"
                        );
                    }
                });
            checkpoint = next_checkpoint;
        }
    }
}

/// Contract: `marshal.verified(...)=true` means the block survives an
/// immediate crash and repeated recoveries.
pub fn verified_success_implies_recoverable_after_restart<H: TestHarness>(
    seeds: impl IntoIterator<Item = u64>,
) {
    for seed in seeds {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(
            &mut TestRng::new(seed),
            NAMESPACE,
            NUM_VALIDATORS,
        );

        let me = participants[0].clone();
        let provider = ConstantProvider::new(schemes[0].clone());
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = H::make_test_block(
            Sha256::hash(b""),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(1),
            100,
            NUM_VALIDATORS as u16,
        );
        let digest = H::digest(&block);
        let recovery_cycles = restart_cycles_for_seed(seed);

        let (_, mut checkpoint) = contract_runner(seed).start_and_recover({
            let participants = participants.clone();
            let me = me.clone();
            let provider = provider.clone();
            let block = block.clone();
            move |context| async move {
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let setup = H::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    provider.clone(),
                )
                .await;
                let mut handle = ValidatorHandle::<H> {
                    mailbox: setup.mailbox,
                    extra: setup.extra,
                };
                let mut peers: [ValidatorHandle<H>; 0] = [];
                H::verify(&mut handle, round, &block, &mut peers).await;
            }
        });

        for cycle in 0..recovery_cycles {
            let ((), next_checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover({
                    let participants = participants.clone();
                    let me = me.clone();
                    let provider = provider.clone();
                    move |context| async move {
                        let mut oracle = setup_network_with_participants(
                            context.child("network"),
                            NZUsize!(1),
                            participants.clone(),
                        )
                        .await;
                        let restarted = H::setup_validator(
                            context
                                .child("validator")
                                .with_attribute("index", 0)
                                .with_attribute("restart", cycle),
                            &mut oracle,
                            me.clone(),
                            provider.clone(),
                        )
                        .await;
                        let recovered =
                            restarted
                                .mailbox
                                .get_verified(round)
                                .await
                                .unwrap_or_else(|| {
                                    panic!(
                                        "marshal.verified() returning true must imply \
                                     get_verified(round) recovers the block after restart \
                                     (seed={seed}, cycle={cycle})"
                                    )
                                });
                        assert_eq!(
                            recovered.digest(),
                            digest,
                            "get_verified(round) must return the verified block \
                             (seed={seed}, cycle={cycle})"
                        );
                        assert!(
                            restarted.mailbox.get_block(&digest).await.is_some(),
                            "get_block(&digest) must also recover the verified block \
                             (seed={seed}, cycle={cycle})"
                        );
                    }
                });
            checkpoint = next_checkpoint;
        }
    }
}

/// Contract: `marshal.certified(...)=true` means the block survives an
/// immediate crash and repeated recoveries.
///
/// Complements [`verified_success_implies_recoverable_after_restart`] by
/// exercising the `Message::Certified -> put_notarized -> sync handle` handshake.
/// A regression that acked before the sync handle completed would surface here
/// as a missing block after restart.
pub fn certified_success_implies_recoverable_after_restart<H: TestHarness>(
    seeds: impl IntoIterator<Item = u64>,
) {
    for seed in seeds {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(
            &mut TestRng::new(seed),
            NAMESPACE,
            NUM_VALIDATORS,
        );

        let me = participants[0].clone();
        let provider = ConstantProvider::new(schemes[0].clone());
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = H::make_test_block(
            Sha256::hash(b""),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(1),
            100,
            NUM_VALIDATORS as u16,
        );
        let digest = H::digest(&block);
        let recovery_cycles = restart_cycles_for_seed(seed);

        let (_, mut checkpoint) = contract_runner(seed).start_and_recover({
            let participants = participants.clone();
            let me = me.clone();
            let provider = provider.clone();
            let block = block.clone();
            move |context| async move {
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let setup = H::setup_validator(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    provider.clone(),
                )
                .await;
                let mut handle = ValidatorHandle::<H> {
                    mailbox: setup.mailbox,
                    extra: setup.extra,
                };
                assert!(
                    H::certify(&mut handle, round, &block).await,
                    "certify must ack"
                );
            }
        });

        for cycle in 0..recovery_cycles {
            let ((), next_checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover({
                    let participants = participants.clone();
                    let me = me.clone();
                    let provider = provider.clone();
                    move |context| async move {
                        let mut oracle = setup_network_with_participants(
                            context.child("network"),
                            NZUsize!(1),
                            participants.clone(),
                        )
                        .await;
                        let restarted = H::setup_validator(
                            context
                                .child("validator")
                                .with_attribute("index", 0)
                                .with_attribute("restart", cycle),
                            &mut oracle,
                            me.clone(),
                            provider.clone(),
                        )
                        .await;
                        let recovered =
                            restarted
                                .mailbox
                                .get_block(&digest)
                                .await
                                .unwrap_or_else(|| {
                                    panic!(
                                        "marshal.certified() returning true must imply \
                                     get_block(&digest) recovers the block after restart \
                                     (seed={seed}, cycle={cycle})"
                                    )
                                });
                        assert_eq!(
                            recovered.digest(),
                            digest,
                            "get_block(&digest) must return the certified block \
                             (seed={seed}, cycle={cycle})"
                        );
                    }
                });
            checkpoint = next_checkpoint;
        }
    }
}

/// Regression: when the same block is verified at an earlier view and later
/// certified at a much later view (epoch-boundary reproposal), both writes
/// must land so retention can prune the earlier view without losing the
/// block. A naive "skip the sibling write if the block's digest is already
/// present in the other archive" optimization is unsafe because the two
/// archives prune per-view on the same boundary: if the block lives only in
/// `verified_blocks[V_early]` and never gets written to
/// `notarized_blocks[V_late]`, advancing retention past V_early drops the
/// block even though V_late is still within the window.
pub fn certify_at_later_view_survives_earlier_view_pruning<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            participants[0].clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let application = setup.application;
        let mut handle = ValidatorHandle::<H> {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // A repeated block that we will verify at an early view and certify
        // at a later view. Its height is intentionally well beyond the chain
        // we'll drive below, so it never enters the finalized archive via
        // gap repair and lives solely in the prunable caches.
        let repeated = H::make_test_block(
            Sha256::hash(b""),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(5_000),
            9_999,
            NUM_VALIDATORS as u16,
        );
        let repeated_digest = H::digest(&repeated);

        // Negative control: a verify-only block at a distinct early view.
        // Placing `orphan` at its own view V=2 keeps its retention behavior
        // independent of `repeated` at V=1. Because it is never certified, it
        // lives solely in that verified entry and must disappear once
        // retention pruning advances past V=2. Asserting it is gone (after
        // asserting it was present before pruning) confirms the prune
        // actually fires at the expected floor.
        let orphan = H::make_test_block(
            Sha256::hash(b"orphan"),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(6_000),
            9_998,
            NUM_VALIDATORS as u16,
        );
        let orphan_digest = H::digest(&orphan);

        // Verify `repeated` at V=1, then certify at V=25 (reproposal-style gap).
        // The chain below starts at V=3 so V=1 (`repeated`) and V=2 (`orphan`)
        // keep their own verified entries.
        let v_early = Round::new(Epoch::zero(), View::new(1));
        let v_orphan = Round::new(Epoch::zero(), View::new(2));
        let v_late = Round::new(Epoch::zero(), View::new(25));
        let mut peers: [ValidatorHandle<H>; 0] = [];
        H::verify(&mut handle, v_early, &repeated, &mut peers).await;
        assert!(
            H::certify(&mut handle, v_late, &repeated).await,
            "certify must ack"
        );

        // Verify `orphan` at its own distinct view V=2 (no certify).
        H::verify(&mut handle, v_orphan, &orphan, &mut peers).await;
        assert!(
            handle.mailbox.get_block(&orphan_digest).await.is_some(),
            "negative control assumes `orphan` is present before pruning; \
             if it is not, the V=2 write was dropped and the post-prune \
             assertion would pass vacuously"
        );

        // Drive the finalized chain forward to advance `last_processed_round`
        // past V=2's retention boundary but not past V=25's. With
        // view_retention_timeout=10 and prunable_items_per_section=10, the
        // prune floor snaps down to the section boundary and evicts V=1 and
        // V=2 while leaving V=25 intact.
        const CHAIN_LEN: u64 = 21;
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);
        for i in 1..=CHAIN_LEN {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                NUM_VALIDATORS as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i + 2));
            H::propose(&mut handle, round, &block).await;
            let proposal = Proposal {
                round,
                parent: View::new(i),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
            parent = digest;
            parent_commitment = commitment;
        }
        while application.tip().map(|(height, _)| height) != Some(Height::new(CHAIN_LEN)) {
            context.sleep(Duration::from_millis(10)).await;
        }
        context.sleep(Duration::from_millis(100)).await;

        // Negative control: the verify-only orphan at V=2 must be gone, which
        // proves retention pruning actually evicted the early-view entries at
        // the expected floor.
        assert!(
            handle.mailbox.get_block(&orphan_digest).await.is_none(),
            "verify-only block at V=2 must be evicted by retention pruning"
        );

        // The repeated block must still be retrievable: verified_blocks[V=1]
        // has been pruned, but notarized_blocks[V=25] still holds it.
        let recovered = handle.mailbox.get_block(&repeated_digest).await;
        assert!(
            recovered.is_some(),
            "block certified at V=25 must survive retention pruning of V=1"
        );
        assert_eq!(recovered.unwrap().digest(), repeated_digest);
    });
}

/// Regression: when a leader equivocates, a validator may verify one block
/// (A) and then certify a different block (B) at the same round. Both blocks
/// must remain retrievable: a same-round collision must not silently drop the
/// second block while the mailbox returns success.
pub fn certify_persists_equivocated_block<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            participants[0].clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle::<H> {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        let round = Round::new(Epoch::zero(), View::new(1));
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);

        // Two distinct blocks at the same height/round (leader equivocation):
        // distinct timestamps yield distinct digests.
        let block_a = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            NUM_VALIDATORS as u16,
        );
        let digest_a = H::digest(&block_a);
        let block_b = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            2,
            NUM_VALIDATORS as u16,
        );
        let digest_b = H::digest(&block_b);
        assert_ne!(digest_a, digest_b, "test requires distinct digests");

        let mut peers: [ValidatorHandle<H>; 0] = [];
        H::verify(&mut handle, round, &block_a, &mut peers).await;
        assert!(
            H::certify(&mut handle, round, &block_b).await,
            "certified must ack"
        );

        let got_a = handle.mailbox.get_block(&digest_a).await;
        assert!(
            got_a.is_some(),
            "verified block A must be persisted in verified_blocks"
        );
        assert_eq!(got_a.unwrap().digest(), digest_a);
        let got_b = handle.mailbox.get_block(&digest_b).await;
        assert!(
            got_b.is_some(),
            "certified block B must be persisted despite a verify at the same round"
        );
        assert_eq!(got_b.unwrap().digest(), digest_b);
    });
}

/// Regression: a pre-restart same-round candidate must not satisfy the
/// durability ack for a different block verified after restart. An
/// equivocating leader can land block A in the verified archive before a
/// crash. When the validator verifies block B at the same round after
/// restart, `verified()` acking durable success must imply B itself is
/// recoverable, not merely covered by A's stale same-round write.
pub fn verified_after_restart_reverify_same_round_implies_recoverable<H: TestHarness>() {
    reverify_same_round_implies_recoverable::<H, _, _>(
        "marshal.verified() returning true must imply get_block(&digest_b) \
         recovers the verified same-round block after restart",
        |mut handle, round, block_a, block_b| async move {
            // Re-verify A (a replayed duplicate of the pre-crash write), then
            // verify equivocated block B at the same round.
            let mut peers: [ValidatorHandle<H>; 0] = [];
            H::verify(&mut handle, round, &block_a, &mut peers).await;
            H::verify(&mut handle, round, &block_b, &mut peers).await;
        },
    );
}

/// Regression: extends
/// [`verified_after_restart_reverify_same_round_implies_recoverable`] through
/// certification. The certify path may reuse the verified archive's covering
/// sync for a block it believes that archive holds. A stale same-round write
/// for A must not be treated as coverage for certifying B: `certified()`
/// acking success must imply B is recoverable after restart.
pub fn certify_after_restart_reverify_same_round_implies_recoverable<H: TestHarness>() {
    reverify_same_round_implies_recoverable::<H, _, _>(
        "marshal.certified() returning true must imply get_block(&digest_b) \
         recovers the certified same-round block after restart",
        |mut handle, round, _block_a, block_b| async move {
            // Verify only equivocated block B, so certification is covered by
            // B's verified write (the elision path) rather than a fresh
            // notarized write, then certify it.
            let mut peers: [ValidatorHandle<H>; 0] = [];
            H::verify(&mut handle, round, &block_b, &mut peers).await;
            assert!(
                H::certify(&mut handle, round, &block_b).await,
                "certify must ack"
            );
        },
    );
}

/// Shared scaffolding for the same-round reverify-after-restart contracts.
///
/// Phase 1 verifies block A and crashes with it durable in the verified
/// archive. `phase_two` runs on the restarted validator and exercises the
/// equivocated same-round block B. Phase 3 restarts once more and asserts
/// both candidates are recoverable by digest, panicking with `durable_claim`
/// when B is missing.
fn reverify_same_round_implies_recoverable<H, F, Fut>(durable_claim: &'static str, phase_two: F)
where
    H: TestHarness,
    F: FnOnce(ValidatorHandle<H>, Round, H::TestBlock, H::TestBlock) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let Fixture {
        participants,
        schemes,
        ..
    } = bls12381_threshold_vrf::fixture::<V, _>(&mut test_rng(), NAMESPACE, NUM_VALIDATORS);

    let me = participants[0].clone();
    let provider = ConstantProvider::new(schemes[0].clone());
    let round = Round::new(Epoch::zero(), View::new(1));
    let parent = Sha256::hash(b"");
    let parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);

    // Two distinct blocks at the same height/round (leader equivocation):
    // distinct timestamps yield distinct digests.
    let block_a = H::make_test_block(
        parent,
        parent_commitment,
        Height::new(1),
        1,
        NUM_VALIDATORS as u16,
    );
    let digest_a = H::digest(&block_a);
    let block_b = H::make_test_block(
        parent,
        parent_commitment,
        Height::new(1),
        2,
        NUM_VALIDATORS as u16,
    );
    let digest_b = H::digest(&block_b);
    assert_ne!(digest_a, digest_b, "test requires distinct digests");

    // Phase 1: verify block A, then crash with A durable in the verified archive.
    let (_, checkpoint) = contract_runner(0).start_and_recover({
        let participants = participants.clone();
        let me = me.clone();
        let provider = provider.clone();
        let block_a = block_a.clone();
        move |context| async move {
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                provider.clone(),
            )
            .await;
            let mut handle = ValidatorHandle::<H> {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };
            let mut peers: [ValidatorHandle<H>; 0] = [];
            H::verify(&mut handle, round, &block_a, &mut peers).await;
        }
    });

    // Phase 2: restart and exercise equivocated block B at the same round,
    // then crash again. A's pre-crash write must not stand in for B's
    // durability.
    let (_, checkpoint) = deterministic::Runner::from(checkpoint).start_and_recover({
        let participants = participants.clone();
        let me = me.clone();
        let provider = provider.clone();
        move |context| async move {
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                participants.clone(),
            )
            .await;
            let setup = H::setup_validator(
                context
                    .child("validator")
                    .with_attribute("index", 0)
                    .with_attribute("restart", 0),
                &mut oracle,
                me.clone(),
                provider.clone(),
            )
            .await;
            let handle = ValidatorHandle::<H> {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };
            phase_two(handle, round, block_a, block_b).await;
        }
    });

    // Phase 3: both same-round candidates must be recoverable.
    deterministic::Runner::from(checkpoint).start(move |context| async move {
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;
        let restarted = H::setup_validator(
            context
                .child("validator")
                .with_attribute("index", 0)
                .with_attribute("restart", 1),
            &mut oracle,
            me.clone(),
            provider.clone(),
        )
        .await;
        assert!(
            restarted.mailbox.get_block(&digest_a).await.is_some(),
            "pre-restart verified block A must remain recoverable"
        );
        let recovered = restarted
            .mailbox
            .get_block(&digest_b)
            .await
            .unwrap_or_else(|| panic!("{durable_claim}"));
        assert_eq!(recovered.digest(), digest_b);
    });
}

/// Contract: once marshal has delivered a finalized block to the application,
/// that finalized block and its certificate must already be durable.
pub fn delivery_visibility_implies_recoverable_after_restart<H: TestHarness>(
    seeds: impl IntoIterator<Item = u64>,
) {
    for seed in seeds {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(
            &mut TestRng::new(seed),
            NAMESPACE,
            NUM_VALIDATORS,
        );

        let me = participants[0].clone();
        let provider = ConstantProvider::new(schemes[0].clone());
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let round = Round::new(Epoch::zero(), View::new(1));
        let block = H::make_test_block(
            Sha256::hash(b""),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            Height::new(1),
            100,
            NUM_VALIDATORS as u16,
        );
        let finalization = H::make_finalization(
            Proposal::new(round, View::zero(), H::commitment(&block)),
            &schemes,
            QUORUM,
        );
        let recovery_cycles = restart_cycles_for_seed(seed);

        let (_, mut checkpoint) = contract_runner(seed).start_and_recover({
            let participants = participants.clone();
            let me = me.clone();
            let provider = provider.clone();
            let application = application.clone();
            let block = block.clone();
            let finalization = finalization.clone();
            move |context| async move {
                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(1),
                    participants.clone(),
                )
                .await;
                let setup = H::setup_validator_with(
                    context.child("validator").with_attribute("index", 0),
                    &mut oracle,
                    me.clone(),
                    provider.clone(),
                    NZUsize!(1),
                    application.clone(),
                )
                .await;
                let mut mailbox = setup.mailbox;
                let mut handle = ValidatorHandle::<H> {
                    mailbox: mailbox.clone(),
                    extra: setup.extra,
                };
                let mut peers: [ValidatorHandle<H>; 0] = [];
                H::verify(&mut handle, round, &block, &mut peers).await;
                H::report_finalization(&mut mailbox, finalization.clone()).await;

                loop {
                    let height = application.acknowledged().await;
                    if height == Height::new(1) {
                        break;
                    }
                    assert_eq!(
                        height,
                        Height::zero(),
                        "only genesis may precede the first finalized block before restart \
                         (seed={seed})"
                    );
                }
            }
        });

        for cycle in 0..recovery_cycles {
            let expected_round = finalization.round();
            let ((), next_checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover({
                    let participants = participants.clone();
                    let me = me.clone();
                    let provider = provider.clone();
                    move |context| async move {
                        let mut oracle = setup_network_with_participants(
                            context.child("network"),
                            NZUsize!(1),
                            participants.clone(),
                        )
                        .await;
                        let restarted = H::setup_validator(
                            context
                                .child("validator")
                                .with_attribute("index", 0)
                                .with_attribute("restart", cycle),
                            &mut oracle,
                            me.clone(),
                            provider.clone(),
                        )
                        .await;
                        let recovered = restarted.mailbox.get_block(Height::new(1)).await.expect(
                            "delivered finalized block must be recoverable after restart \
                             (seed={seed}, cycle={cycle})",
                        );
                        assert_eq!(
                            recovered.height(),
                            Height::new(1),
                            "restart should recover the delivered finalized block by height \
                         (seed={seed}, cycle={cycle})"
                        );
                        assert_eq!(
                            restarted
                                .mailbox
                                .get_finalization(Height::new(1))
                                .await
                                .expect(
                                    "delivered finalization must be recoverable after restart \
                                 (seed={seed}, cycle={cycle})",
                                )
                                .round(),
                            expected_round,
                            "restart should recover the delivered finalization by height \
                         (seed={seed}, cycle={cycle})"
                        );
                    }
                });
            checkpoint = next_checkpoint;
        }
    }
}

// =============================================================================
// Standard Harness Implementation
// =============================================================================

/// Standard variant test harness.
pub struct StandardHarness;

impl TestHarness for StandardHarness {
    type ApplicationBlock = B;
    type Variant = Standard<B>;
    type TestBlock = B;
    type ValidatorExtra = buffered::Mailbox<K, B>;
    type Commitment = D;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        Self::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            NZUsize!(1),
            Application::default(),
        )
        .await
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(Self::genesis_block(NUM_VALIDATORS as u16)),
            mailbox_size: NZUsize!(100),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };
        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(context.child("resolver"), resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::new(context.child("broadcast"), broadcast_config);
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: NZU64!(10),
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: NZU64!(10),
                codec_config: config.block_codec_config,
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let (actor, mailbox, height) = Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let actor_handle = actor.start(application.clone(), buffer.clone(), resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: buffer,
            height,
            actor_handle,
        }
    }

    fn genesis_parent_commitment(_num_participants: u16) -> D {
        Sha256::hash(b"")
    }

    fn make_test_block(
        parent: D,
        _parent_commitment: D,
        height: Height,
        timestamp: u64,
        _num_participants: u16,
    ) -> B {
        make_raw_block(parent, height, timestamp)
    }

    fn commitment(block: &B) -> D {
        block.digest()
    }

    fn digest(block: &B) -> D {
        block.digest()
    }

    fn height(block: &B) -> Height {
        block.height()
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &B,
        _all_handles: &mut [ValidatorHandle<Self>],
    ) {
        assert!(handle.mailbox.verified(round, block.clone()).await);
    }

    async fn certify(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) -> bool {
        handle.mailbox.certified(round, block.clone()).await
    }

    fn make_finalization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Finalization<S, D> {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(proposal: Proposal<D>, schemes: &[S], quorum: u32) -> Notarization<S, D> {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, D>,
    ) {
        mailbox.report(Activity::Finalization(finalization));
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, D>,
    ) {
        mailbox.report(Activity::Notarization(notarization));
    }

    fn finalize_timeout() -> Duration {
        Duration::from_secs(600)
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<B>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(Self::genesis_block(NUM_VALIDATORS as u16)),
            mailbox_size: NZUsize!(100),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: page_cache.clone(),
            strategy: Sequential,
        };

        let backfill = control.register(0, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(context.child("resolver"), resolver_cfg, backfill);

        let broadcast_config = buffered::Config {
            public_key: validator.clone(),
            mailbox_size: config.mailbox_size,
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::new(context.child("broadcast"), broadcast_config);
        let network = control.register(1, TEST_QUOTA).await.unwrap();
        broadcast_engine.start(network);

        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalizations-by-height-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalizations-by-height-value", partition_prefix),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalized-blocks-value", partition_prefix),
                compression: None,
                codec_config: config.block_codec_config,
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (actor, mailbox, _) = Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<B>::default();
        actor.start(application.clone(), buffer.clone(), resolver);

        (mailbox, buffer, application)
    }

    async fn verify_for_prune(handle: &mut ValidatorHandle<Self>, round: Round, block: &B) {
        assert!(handle.mailbox.verified(round, block.clone()).await);
    }
}

/// Inline wrapper test harness for standard marshal behavior.
pub struct InlineHarness;

impl TestHarness for InlineHarness {
    type ApplicationBlock = <StandardHarness as TestHarness>::ApplicationBlock;
    type Variant = <StandardHarness as TestHarness>::Variant;
    type TestBlock = <StandardHarness as TestHarness>::TestBlock;
    type ValidatorExtra = <StandardHarness as TestHarness>::ValidatorExtra;
    type Commitment = <StandardHarness as TestHarness>::Commitment;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        let setup = StandardHarness::setup_validator(context, oracle, validator, provider).await;
        ValidatorSetup {
            application: setup.application,
            mailbox: setup.mailbox,
            extra: setup.extra,
            height: setup.height,
            actor_handle: setup.actor_handle,
        }
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let setup = StandardHarness::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            max_pending_acks,
            application,
        )
        .await;
        ValidatorSetup {
            application: setup.application,
            mailbox: setup.mailbox,
            extra: setup.extra,
            height: setup.height,
            actor_handle: setup.actor_handle,
        }
    }

    fn genesis_parent_commitment(num_participants: u16) -> Self::Commitment {
        StandardHarness::genesis_parent_commitment(num_participants)
    }

    fn make_test_block(
        parent: D,
        parent_commitment: Self::Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> Self::TestBlock {
        StandardHarness::make_test_block(
            parent,
            parent_commitment,
            height,
            timestamp,
            num_participants,
        )
    }

    fn commitment(block: &Self::TestBlock) -> Self::Commitment {
        StandardHarness::commitment(block)
    }

    fn digest(block: &Self::TestBlock) -> D {
        StandardHarness::digest(block)
    }

    fn height(block: &Self::TestBlock) -> Height {
        StandardHarness::height(block)
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        _all_handles: &mut [ValidatorHandle<Self>],
    ) {
        StandardHarness::verify(
            &mut ValidatorHandle::<StandardHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
            &mut [],
        )
        .await;
    }

    async fn certify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> bool {
        StandardHarness::certify(
            &mut ValidatorHandle::<StandardHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
        )
        .await
    }

    fn make_finalization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, Self::Commitment> {
        StandardHarness::make_finalization(proposal, schemes, quorum)
    }

    fn make_notarization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, Self::Commitment> {
        StandardHarness::make_notarization(proposal, schemes, quorum)
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, Self::Commitment>,
    ) {
        StandardHarness::report_finalization(mailbox, finalization).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, Self::Commitment>,
    ) {
        StandardHarness::report_notarization(mailbox, notarization).await;
    }

    fn finalize_timeout() -> Duration {
        StandardHarness::finalize_timeout()
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<Self::ApplicationBlock>,
    ) {
        StandardHarness::setup_prunable_validator(
            context,
            oracle,
            validator,
            schemes,
            partition_prefix,
            page_cache,
        )
        .await
    }

    async fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) {
        StandardHarness::verify_for_prune(
            &mut ValidatorHandle::<StandardHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
        )
        .await;
    }
}

/// Deferred wrapper test harness for standard marshal behavior.
pub struct DeferredHarness;

impl TestHarness for DeferredHarness {
    type ApplicationBlock = <InlineHarness as TestHarness>::ApplicationBlock;
    type Variant = <InlineHarness as TestHarness>::Variant;
    type TestBlock = <InlineHarness as TestHarness>::TestBlock;
    type ValidatorExtra = <InlineHarness as TestHarness>::ValidatorExtra;
    type Commitment = <InlineHarness as TestHarness>::Commitment;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        let setup = InlineHarness::setup_validator(context, oracle, validator, provider).await;
        ValidatorSetup {
            application: setup.application,
            mailbox: setup.mailbox,
            extra: setup.extra,
            height: setup.height,
            actor_handle: setup.actor_handle,
        }
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let setup = InlineHarness::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            max_pending_acks,
            application,
        )
        .await;
        ValidatorSetup {
            application: setup.application,
            mailbox: setup.mailbox,
            extra: setup.extra,
            height: setup.height,
            actor_handle: setup.actor_handle,
        }
    }

    fn genesis_parent_commitment(num_participants: u16) -> Self::Commitment {
        InlineHarness::genesis_parent_commitment(num_participants)
    }

    fn make_test_block(
        parent: D,
        parent_commitment: Self::Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> Self::TestBlock {
        InlineHarness::make_test_block(
            parent,
            parent_commitment,
            height,
            timestamp,
            num_participants,
        )
    }

    fn commitment(block: &Self::TestBlock) -> Self::Commitment {
        InlineHarness::commitment(block)
    }

    fn digest(block: &Self::TestBlock) -> D {
        InlineHarness::digest(block)
    }

    fn height(block: &Self::TestBlock) -> Height {
        InlineHarness::height(block)
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
        _all_handles: &mut [ValidatorHandle<Self>],
    ) {
        InlineHarness::verify(
            &mut ValidatorHandle::<InlineHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
            &mut [],
        )
        .await;
    }

    async fn certify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) -> bool {
        InlineHarness::certify(
            &mut ValidatorHandle::<InlineHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
        )
        .await
    }

    fn make_finalization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, Self::Commitment> {
        InlineHarness::make_finalization(proposal, schemes, quorum)
    }

    fn make_notarization(
        proposal: Proposal<Self::Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, Self::Commitment> {
        InlineHarness::make_notarization(proposal, schemes, quorum)
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, Self::Commitment>,
    ) {
        InlineHarness::report_finalization(mailbox, finalization).await;
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, Self::Commitment>,
    ) {
        InlineHarness::report_notarization(mailbox, notarization).await;
    }

    fn finalize_timeout() -> Duration {
        InlineHarness::finalize_timeout()
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<Self::ApplicationBlock>,
    ) {
        InlineHarness::setup_prunable_validator(
            context,
            oracle,
            validator,
            schemes,
            partition_prefix,
            page_cache,
        )
        .await
    }

    async fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &Self::TestBlock,
    ) {
        InlineHarness::verify_for_prune(
            &mut ValidatorHandle::<InlineHarness> {
                mailbox: handle.mailbox.clone(),
                extra: handle.extra.clone(),
            },
            round,
            block,
        )
        .await;
    }
}

// =============================================================================
// Coding Harness Implementation
// =============================================================================

/// Coding variant test harness.
pub struct CodingHarness;

type CodingVariant = Coding<CodingB, ReedSolomon<Sha256>, Sha256, K>;
type ShardsMailbox = shards::Mailbox<CodingB, ReedSolomon<Sha256>, Sha256, K>;

/// Genesis blocks use a special coding config that doesn't actually encode.
pub const GENESIS_CODING_CONFIG: commonware_coding::Config = commonware_coding::Config {
    minimum_shards: NZU16!(1),
    extra_shards: NZU16!(1),
};

/// Create a genesis Commitment (all zeros for digests, genesis config).
pub fn genesis_commitment() -> Commitment {
    Commitment::from((
        D::EMPTY,
        D::EMPTY,
        Sha256Digest::EMPTY,
        GENESIS_CODING_CONFIG,
    ))
}

/// Create the coding height-zero block used to seed fresh marshal actors.
pub fn make_coding_genesis_block() -> CodingB {
    let context = CodingCtx {
        round: Round::zero(),
        leader: default_leader(),
        parent: (View::zero(), genesis_commitment()),
    };
    make_coding_block(context, Sha256::hash(b""), Height::zero(), 0)
}

/// Create a test block with a Commitment-based context.
pub fn make_coding_block(context: CodingCtx, parent: D, height: Height, timestamp: u64) -> CodingB {
    CodingB::new::<Sha256>(context, parent, height, timestamp)
}

impl TestHarness for CodingHarness {
    type ApplicationBlock = CodingB;
    type Variant = CodingVariant;
    type TestBlock = CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>;
    type ValidatorExtra = ShardsMailbox;
    type Commitment = Commitment;

    async fn setup_validator(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
    ) -> ValidatorSetup<Self> {
        Self::setup_validator_with(
            context,
            oracle,
            validator,
            provider,
            NZUsize!(1),
            Application::default(),
        )
        .await
    }

    async fn setup_validator_with(
        context: deterministic::Context,
        oracle: &mut Oracle<K, deterministic::Context>,
        validator: K,
        provider: P,
        max_pending_acks: NonZeroUsize,
        application: Application<Self::ApplicationBlock>,
    ) -> ValidatorSetup<Self> {
        let config = Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(Self::genesis_block(NUM_VALIDATORS as u16)),
            mailbox_size: NZUsize!(100),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks,
            block_codec_config: (),
            partition_prefix: format!("validator-{}", validator.clone()),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };

        let control = oracle.control(validator.clone());
        let backfill = control.register(1, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: oracle.control(validator.clone()),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(context.child("resolver"), resolver_cfg, backfill);

        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalizations-by-height-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalizations-by-height-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: NZU64!(10),
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{}-finalized_blocks-freezer-key",
                    config.partition_prefix
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    config.partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: NZU64!(10),
                codec_config: config.block_codec_config,
                replay_buffer: config.replay_buffer,
                freezer_key_write_buffer: config.key_write_buffer,
                freezer_value_write_buffer: config.value_write_buffer,
                ordinal_write_buffer: config.key_write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

        let shard_config: shards::Config<_, _, _, _, _, Sha256, _, _> = shards::Config {
            scheme_provider: provider.clone(),
            blocker: oracle.control(validator.clone()),
            shard_codec_cfg: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
            block_codec_cfg: (),
            strategy: Sequential,
            mailbox_size: NZUsize!(10),
            peer_buffer_size: NZUsize!(64),
            background_channel_capacity: NZUsize!(1024),
            peer_provider: oracle.manager(),
        };
        let (shard_engine, shard_mailbox) =
            shards::Engine::new(context.child("shards"), shard_config);
        let network = control.register(2, TEST_QUOTA).await.unwrap();
        shard_engine.start(network);

        let (actor, mailbox, height) = Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let actor_handle = actor.start(application.clone(), shard_mailbox.clone(), resolver);

        ValidatorSetup {
            application,
            mailbox,
            extra: shard_mailbox,
            height,
            actor_handle,
        }
    }

    fn make_test_block(
        parent: D,
        parent_commitment: Commitment,
        height: Height,
        timestamp: u64,
        num_participants: u16,
    ) -> CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256> {
        let parent_view = height
            .previous()
            .map(|h| View::new(h.get()))
            .unwrap_or(View::zero());
        let context = CodingCtx {
            round: Round::new(Epoch::zero(), View::new(height.get())),
            leader: default_leader(),
            parent: (parent_view, parent_commitment),
        };
        let raw = CodingB::new::<Sha256>(context, parent, height, timestamp);
        let coding_config = coding_config_for_participants(num_participants);
        CodedBlock::new(raw, coding_config, &Sequential)
    }

    fn genesis_parent_commitment(_num_participants: u16) -> Commitment {
        genesis_commitment()
    }

    fn genesis_block(_num_participants: u16) -> Self::TestBlock {
        let inner = make_coding_genesis_block();
        let commitment = Commitment::from((
            inner.digest(),
            inner.digest(),
            hash_context::<Sha256, _>(&inner.context),
            GENESIS_CODING_CONFIG,
        ));
        CodedBlock::new_trusted(inner, commitment)
    }

    fn commitment(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> Commitment {
        block.commitment()
    }

    fn digest(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> D {
        block.digest()
    }

    fn height(block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>) -> Height {
        block.height()
    }

    async fn verify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>,
        _all_handles: &mut [ValidatorHandle<Self>],
    ) {
        assert!(handle.mailbox.verified(round, block.clone()).await);
    }

    async fn certify(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>,
    ) -> bool {
        handle.mailbox.certified(round, block.clone()).await
    }

    fn make_finalization(
        proposal: Proposal<Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Finalization<S, Commitment> {
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap()
    }

    fn make_notarization(
        proposal: Proposal<Commitment>,
        schemes: &[S],
        quorum: u32,
    ) -> Notarization<S, Commitment> {
        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap()
    }

    async fn report_finalization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        finalization: Finalization<S, Commitment>,
    ) {
        mailbox.report(Activity::Finalization(finalization));
    }

    async fn report_notarization(
        mailbox: &mut Mailbox<S, Self::Variant>,
        notarization: Notarization<S, Commitment>,
    ) {
        mailbox.report(Activity::Notarization(notarization));
    }

    fn finalize_timeout() -> Duration {
        Duration::from_secs(900)
    }

    async fn setup_prunable_validator(
        context: deterministic::Context,
        oracle: &Oracle<K, deterministic::Context>,
        validator: K,
        schemes: &[S],
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> (
        Mailbox<S, Self::Variant>,
        Self::ValidatorExtra,
        Application<CodingB>,
    ) {
        let control = oracle.control(validator.clone());
        let provider = ConstantProvider::new(schemes[0].clone());
        let config = Config {
            provider: provider.clone(),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(Self::genesis_block(NUM_VALIDATORS as u16)),
            mailbox_size: NZUsize!(100),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            block_codec_config: (),
            partition_prefix: partition_prefix.to_string(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: page_cache.clone(),
            strategy: Sequential,
        };

        let backfill = control.register(0, TEST_QUOTA).await.unwrap();
        let resolver_cfg = resolver::Config {
            public_key: validator.clone(),
            peer_provider: oracle.manager(),
            blocker: control.clone(),
            mailbox_size: config.mailbox_size,
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = resolver::init(context.child("resolver"), resolver_cfg, backfill);

        let shard_config: shards::Config<_, _, _, _, _, Sha256, _, _> = shards::Config {
            scheme_provider: provider.clone(),
            blocker: oracle.control(validator.clone()),
            shard_codec_cfg: CodecConfig {
                maximum_shard_size: 1024 * 1024,
            },
            block_codec_cfg: (),
            strategy: Sequential,
            mailbox_size: NZUsize!(10),
            peer_buffer_size: NZUsize!(64),
            background_channel_capacity: NZUsize!(1024),
            peer_provider: oracle.manager(),
        };
        let (shard_engine, shard_mailbox) =
            shards::Engine::new(context.child("shards"), shard_config);
        let network = control.register(1, TEST_QUOTA).await.unwrap();
        shard_engine.start(network);

        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalizations-by-height-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalizations-by-height-value", partition_prefix),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{}-finalized-blocks-key", partition_prefix),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{}-finalized-blocks-value", partition_prefix),
                compression: None,
                codec_config: config.block_codec_config,
                items_per_section: NZU64!(10),
                key_write_buffer: config.key_write_buffer,
                value_write_buffer: config.value_write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let (actor, mailbox, _) = Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let application = Application::<CodingB>::default();
        actor.start(application.clone(), shard_mailbox.clone(), resolver);

        (mailbox, shard_mailbox, application)
    }

    async fn verify_for_prune(
        handle: &mut ValidatorHandle<Self>,
        round: Round,
        block: &CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>,
    ) {
        assert!(handle.mailbox.verified(round, block.clone()).await);
    }
}

// =============================================================================
// Generic Test Functions
// =============================================================================

/// Run the finalization test with the given parameters.
pub fn finalize<H: TestHarness>(seed: u64, link: Link, quorum_sees_finalization: bool) -> String {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(H::finalize_timeout())),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(3),
            participants.clone(),
        )
        .await;

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants, link.clone()).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            parent = H::digest(&block);
            parent_commitment = H::commitment(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        blocks.shuffle(&mut context);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (NUM_VALIDATORS as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            context.sleep(link.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(height.previous().unwrap().get()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, QUORUM);
            if quorum_sees_finalization {
                let do_finalize = context.random_bool(0.2);
                for (i, h) in handles
                    .iter_mut()
                    .sample(&mut context, NUM_VALIDATORS as usize)
                    .iter_mut()
                    .enumerate()
                {
                    if (do_finalize && i < QUORUM as usize)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            } else {
                for h in handles.iter_mut() {
                    if context.random_bool(0.2)
                        || height.get() == NUM_BLOCKS
                        || height == bounds.last()
                    {
                        H::report_finalization(&mut h.mailbox, fin.clone()).await;
                    }
                }
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            if applications.len() != NUM_VALIDATORS as usize {
                continue;
            }
            finished = true;
            for app in applications.values() {
                if app.blocks().len() != (NUM_BLOCKS + 1) as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        context.auditor().state()
    })
}

/// Test that marshal can pipeline application acknowledgements up to the configured backlog.
pub fn ack_pipeline_backlog<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xA11CE)
            .with_timeout(Some(Duration::from_secs(120))),
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

        let validator = participants[0].clone();
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let setup = H::setup_validator_with(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator,
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            application,
        )
        .await;
        let application = setup.application;
        let mut handles = vec![ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        }];
        let mut handle = handles[0].clone();
        assert_eq!(application.acknowledged().await, Height::zero());

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);
        for i in 1..=5 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                NUM_VALIDATORS as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let round = Round::new(
                epocher.containing(H::height(&block)).unwrap().epoch(),
                View::new(i),
            );
            H::verify(&mut handle, round, &block, &mut handles).await;
            let proposal = Proposal {
                round,
                parent: View::new(i.saturating_sub(1)),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        // Backlog should fill to configured capacity before any ack is released.
        while application.blocks().len() < 3 || application.pending_ack_heights().len() < 3 {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            application.pending_ack_heights(),
            vec![Height::new(1), Height::new(2), Height::new(3)]
        );
        assert!(!application.blocks().contains_key(&Height::new(4)));
        assert!(!application.blocks().contains_key(&Height::new(5)));

        // Releasing acks should preserve FIFO order and allow further dispatch.
        for expected in 1..=5 {
            let expected = Height::new(expected);
            while application.pending_ack_heights().first().copied() != Some(expected) {
                context.sleep(Duration::from_millis(10)).await;
            }
            let acknowledged = application
                .acknowledge_next()
                .expect("pending ack should be present");
            assert_eq!(acknowledged, expected);
        }

        // All finalized blocks should eventually be delivered after draining the backlog.
        while application.blocks().len() < 5 || !application.pending_ack_heights().is_empty() {
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

/// Test that batched pending-ack progress survives restart.
pub fn ack_pipeline_backlog_persists_on_restart<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xA11CF)
            .with_timeout(Some(Duration::from_secs(120))),
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

        let validator = participants[0].clone();
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let setup = H::setup_validator_with(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            application,
        )
        .await;
        let application = setup.application;
        let mut handles = vec![ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        }];
        let mut handle = handles[0].clone();
        assert_eq!(application.acknowledged().await, Height::zero());

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);
        for i in 1..=3 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                NUM_VALIDATORS as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let round = Round::new(
                epocher.containing(H::height(&block)).unwrap().epoch(),
                View::new(i),
            );
            H::verify(&mut handle, round, &block, &mut handles).await;
            let proposal = Proposal {
                round,
                parent: View::new(i.saturating_sub(1)),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        while application.pending_ack_heights().len() < 3 {
            context.sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            application.pending_ack_heights(),
            vec![Height::new(1), Height::new(2), Height::new(3)]
        );

        // Acknowledge all pending blocks without yielding so marshal can drain
        // them in one ack arm and sync metadata once.
        assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
        assert_eq!(application.acknowledge_next(), Some(Height::new(2)));
        assert_eq!(application.acknowledge_next(), Some(Height::new(3)));

        // Yield to marshal.
        context.sleep(Duration::from_millis(10)).await;

        // Assert that the application has processed up to height 3.
        assert_eq!(
            application.tip().map(|(height, _)| height),
            Some(Height::new(3))
        );

        // Restart marshal and confirm the processed height restored from metadata.
        let restart = H::setup_validator_with(
            context
                .child("validator_restart")
                .with_attribute("index", 0),
            &mut oracle,
            validator,
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(3),
            Application::manual_ack(),
        )
        .await;
        assert_eq!(restart.height, Some(Height::new(3)));
    });
}

/// Test that genesis is delivered once and then suppressed after its ack is durable.
pub fn genesis_emitted_once<H: TestHarness>() {
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

        let validator = participants[0].clone();
        let setup = H::setup_validator_with(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(1),
            Application::<H::ApplicationBlock>::manual_ack(),
        )
        .await;
        assert_eq!(setup.height, None);
        assert_eq!(setup.mailbox.get_processed_height().await, None);
        assert_eq!(setup.application.acknowledged().await, Height::zero());
        context.sleep(Duration::from_millis(10)).await;
        assert_eq!(
            setup.mailbox.get_processed_height().await,
            Some(Height::zero())
        );
        assert!(setup.application.blocks().contains_key(&Height::zero()));

        // Let marshal persist the height-zero acknowledgement before restart.
        context.sleep(Duration::from_millis(10)).await;
        setup.actor_handle.abort();
        drop(setup.mailbox);
        drop(setup.extra);
        context.sleep(Duration::from_millis(10)).await;

        let restart = H::setup_validator_with(
            context
                .child("validator_restart")
                .with_attribute("index", 0),
            &mut oracle,
            validator,
            ConstantProvider::new(schemes[0].clone()),
            NZUsize!(1),
            Application::<H::ApplicationBlock>::manual_ack(),
        )
        .await;
        assert_eq!(restart.height, Some(Height::zero()));
        context.sleep(Duration::from_millis(100)).await;
        assert!(
            restart.application.blocks().is_empty(),
            "genesis should not be emitted again after height zero is acknowledged"
        );
        assert!(
            restart.application.pending_ack_heights().is_empty(),
            "restart should not leave a duplicate genesis ack pending"
        );
    });
}

/// Test sync height floor.
pub fn sync_height_floor<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xFF)
            .with_timeout(Some(Duration::from_secs(300))),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(3),
            participants.clone(),
        )
        .await;

        let mut applications = BTreeMap::new();
        let mut handles = Vec::new();

        // Skip first validator
        for (i, validator) in participants.iter().enumerate().skip(1) {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            applications.insert(validator.clone(), setup.application);
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        setup_network_links(&mut oracle, &participants[1..], LINK).await;

        let mut blocks = Vec::new();
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        for i in 1..=NUM_BLOCKS {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            parent = H::digest(&block);
            parent_commitment = H::commitment(&block);
            blocks.push(block);
        }

        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);

        for block in blocks.iter() {
            let height = H::height(block);
            assert!(
                !height.is_zero(),
                "genesis block should not have been generated"
            );

            let bounds = epocher.containing(height).unwrap();
            let round = Round::new(bounds.epoch(), View::new(height.get()));

            let actor_index: usize = (height.get() % (applications.len() as u64)) as usize;
            let mut handle = handles[actor_index].clone();
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(height.previous().unwrap().get()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let fin = H::make_finalization(proposal, &schemes, QUORUM);
            for h in handles.iter_mut() {
                H::report_finalization(&mut h.mailbox, fin.clone()).await;
            }
        }

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            for app in applications.values().skip(1) {
                if app.blocks().len() != (NUM_BLOCKS + 1) as usize {
                    finished = false;
                    break;
                }
                let Some((height, _)) = app.tip() else {
                    finished = false;
                    break;
                };
                if height.get() < NUM_BLOCKS {
                    finished = false;
                    break;
                }
            }
        }

        // Create the first validator now
        let validator = participants.first().unwrap();
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut mailbox = setup.mailbox;

        setup_network_links(&mut oracle, &participants, LINK).await;

        const NEW_SYNC_FLOOR: u64 = 100;
        let second_handle = &mut handles[1];
        let latest_finalization = second_handle
            .mailbox
            .get_finalization(Height::new(NUM_BLOCKS))
            .await
            .unwrap();
        let floor_finalization = second_handle
            .mailbox
            .get_finalization(Height::new(NEW_SYNC_FLOOR))
            .await
            .unwrap();

        mailbox.set_floor(floor_finalization);
        H::report_finalization(&mut mailbox, latest_finalization).await;

        let mut finished = false;
        while !finished {
            context.sleep(Duration::from_secs(1)).await;
            finished = true;
            if app.blocks().len() != (NUM_BLOCKS - NEW_SYNC_FLOOR + 2) as usize {
                finished = false;
                continue;
            }
            let Some((height, _)) = app.tip() else {
                finished = false;
                continue;
            };
            if height.get() < NUM_BLOCKS {
                finished = false;
                continue;
            }
        }

        for height in 1..=NUM_BLOCKS {
            let block = mailbox
                .get_block(Identifier::Height(Height::new(height)))
                .await;
            if height < NEW_SYNC_FLOOR {
                assert!(block.is_none());
            } else {
                assert_eq!(block.unwrap().height().get(), height);
            }
        }
    })
}

/// Test pruning of finalized archives.
pub fn prune_finalized_archives<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new().with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let oracle = setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;

        let validator = participants[0].clone();
        let partition_prefix = format!("prune-test-{}", validator.clone());
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

        let init_marshal = |ctx: deterministic::Context| {
            let validator = validator.clone();
            let schemes = schemes.clone();
            let partition_prefix = partition_prefix.clone();
            let page_cache = page_cache.clone();
            let oracle = &oracle;
            async move {
                H::setup_prunable_validator(
                    ctx,
                    oracle,
                    validator,
                    &schemes,
                    &partition_prefix,
                    page_cache,
                )
                .await
            }
        };

        let (mut mailbox, extra, application) = init_marshal(context.child("init")).await;
        let _ = extra; // Used by CodingHarness, silence warning for StandardHarness

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(NUM_VALIDATORS as u16);
        let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
        for i in 1..=20u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                NUM_VALIDATORS as u16,
            );
            let commitment = H::commitment(&block);
            parent = H::digest(&block);
            parent_commitment = commitment;
            let bounds = epocher.containing(Height::new(i)).unwrap();
            let round = Round::new(bounds.epoch(), View::new(i));

            let mut handle = ValidatorHandle {
                mailbox: mailbox.clone(),
                extra: extra.clone(),
            };
            H::verify_for_prune(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut mailbox, finalization).await;
        }

        while application.tip().map(|(height, _)| height) != Some(Height::new(20)) {
            context.sleep(Duration::from_millis(10)).await;
        }

        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should exist before pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should exist before pruning"
            );
        }

        mailbox.prune(Height::new(25));
        context.sleep(Duration::from_millis(50)).await;
        for i in 1..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning above floor"
            );
        }

        mailbox.prune(Height::new(10));
        context.sleep(Duration::from_millis(100)).await;
        for i in 1..10u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned"
            );
        }

        for i in 10..=20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_some(),
                "block {i} should still exist after pruning"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_some(),
                "finalization {i} should still exist after pruning"
            );
        }

        mailbox.prune(Height::new(20));
        context.sleep(Duration::from_millis(100)).await;
        for i in 10..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should be pruned after second prune"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should be pruned after second prune"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist"
        );

        drop(mailbox);
        drop(extra);
        let (mailbox, _extra, _application) = init_marshal(context.child("restart")).await;

        for i in 1..20u64 {
            assert!(
                mailbox.get_block(Height::new(i)).await.is_none(),
                "block {i} should still be pruned after restart"
            );
            assert!(
                mailbox.get_finalization(Height::new(i)).await.is_none(),
                "finalization {i} should still be pruned after restart"
            );
        }

        assert!(
            mailbox.get_block(Height::new(20)).await.is_some(),
            "block 20 should still exist after restart"
        );
        assert!(
            mailbox.get_finalization(Height::new(20)).await.is_some(),
            "finalization 20 should still exist after restart"
        );
    })
}

/// Regression test: delayed block backfill delivered after floor advancement must not crash.
///
/// This models a resolver peer that responds to `Key::Block` only after the
/// victim has advanced its floor and pruned finalized storage. The stale delivery
/// must be rejected and must not be persisted.
pub fn reject_stale_block_delivery_after_floor_update<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(0xBADC0DE)
            .with_timeout(Some(Duration::from_secs(120))),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let victim = participants[0].clone();
        let attacker = participants[1].clone();
        let peers = vec![victim.clone(), attacker.clone()];
        let mut oracle =
            setup_network_with_participants(context.child("network"), NZUsize!(1), peers.clone())
                .await;

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let (mut victim_mailbox, victim_extra, _victim_application) = H::setup_prunable_validator(
            context.child("victim"),
            &oracle,
            victim.clone(),
            &schemes,
            &format!("stale-floor-victim-{}", victim),
            page_cache.clone(),
        )
        .await;
        let (attacker_mailbox, attacker_extra, _attacker_application) =
            H::setup_prunable_validator(
                context.child("attacker"),
                &oracle,
                attacker.clone(),
                &schemes,
                &format!("stale-floor-attacker-{}", attacker),
                page_cache,
            )
            .await;
        setup_network_links(&mut oracle, &peers, LINK).await;
        oracle
            .remove_link(attacker.clone(), victim.clone())
            .await
            .unwrap();

        // Make the attacker able to serve the block by commitment.
        let stale_height = Height::new(5);
        let round = Round::new(Epoch::zero(), View::new(stale_height.get()));
        let stale_block = H::make_test_block(
            Sha256::hash(b"stale-parent"),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            stale_height,
            stale_height.get(),
            NUM_VALIDATORS as u16,
        );
        let commitment = H::commitment(&stale_block);
        let mut attacker_handle = ValidatorHandle {
            mailbox: attacker_mailbox,
            extra: attacker_extra,
        };
        H::propose(&mut attacker_handle, round, &stale_block).await;
        let mut no_handles: Vec<ValidatorHandle<H>> = Vec::new();
        H::verify(
            &mut attacker_handle,
            round,
            &stale_block,
            no_handles.as_mut_slice(),
        )
        .await;

        // Trigger victim fetch for this block via finalization report.
        let proposal = Proposal {
            round,
            parent: View::new(stale_height.get() - 1),
            payload: commitment,
        };
        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut victim_mailbox, finalization).await;

        // Let block requests get issued while responses are still blocked.
        context.sleep(Duration::from_millis(500)).await;

        // Advance floor beyond the stale block and prune.
        let floor = Height::new(10);
        let floor_parent = H::make_test_block(
            Sha256::hash(b"floor-grandparent"),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            floor.previous().expect("floor must have a parent"),
            floor.get() - 1,
            NUM_VALIDATORS as u16,
        );
        let floor_anchor = H::make_test_block(
            H::digest(&floor_parent),
            H::commitment(&floor_parent),
            floor,
            floor.get(),
            NUM_VALIDATORS as u16,
        );
        let floor_round = Round::new(Epoch::zero(), View::new(floor.get()));
        let floor_proposal = Proposal {
            round: floor_round,
            parent: View::new(floor.get() - 1),
            payload: H::commitment(&floor_anchor),
        };
        let floor_finalization = H::make_finalization(floor_proposal, &schemes, QUORUM);
        victim_mailbox.set_floor(floor_finalization);
        let mut victim_handle = ValidatorHandle {
            mailbox: victim_mailbox.clone(),
            extra: victim_extra,
        };
        let mut no_handles: Vec<ValidatorHandle<H>> = Vec::new();
        H::verify(
            &mut victim_handle,
            floor_round,
            &floor_anchor,
            no_handles.as_mut_slice(),
        )
        .await;
        // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
        // has been processed before we re-enable the delayed delivery path.
        let _ = victim_mailbox.get_finalization(floor).await;

        // Restore attacker -> victim traffic so delayed resolver responses can arrive.
        oracle
            .add_link(attacker.clone(), victim.clone(), LINK)
            .await
            .unwrap();
        context.sleep(Duration::from_secs(3)).await;

        // Stale-but-valid delivery should not be considered Byzantine behavior.
        let blocked = oracle.blocked().await.unwrap();
        assert!(
            !blocked
                .iter()
                .any(|(blocker, blocked)| blocker == &victim && blocked == &attacker),
            "stale delivery below floor must not block the serving peer"
        );

        assert!(
            victim_mailbox.get_block(stale_height).await.is_none(),
            "stale block below floor must not be persisted"
        );
        assert!(
            victim_mailbox
                .get_finalization(stale_height)
                .await
                .is_none(),
            "stale finalization below floor must not be persisted"
        );
    });
}

/// Regression test: commitment-fetched blocks must wake subscribers and cache by
/// decoded height even when the local pruning hint is far ahead.
pub fn commitment_fetch_height_hint_mismatch_wakes_subscriber<H: TestHarness>() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

        let victim = participants[0].clone();
        let server = participants[1].clone();
        let peers = vec![victim.clone(), server.clone()];
        let mut oracle =
            setup_network_with_participants(context.child("network"), NZUsize!(1), peers.clone())
                .await;

        let victim_setup = H::setup_validator(
            context.child("victim"),
            &mut oracle,
            victim.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let server_setup = H::setup_validator(
            context.child("server"),
            &mut oracle,
            server.clone(),
            ConstantProvider::new(schemes[1].clone()),
        )
        .await;

        let victim_handle: ValidatorHandle<H> = ValidatorHandle {
            mailbox: victim_setup.mailbox,
            extra: victim_setup.extra,
        };
        let mut server_handle: ValidatorHandle<H> = ValidatorHandle {
            mailbox: server_setup.mailbox,
            extra: server_setup.extra,
        };

        let actual_height = Height::new(7);
        let expected_height = Height::new(1_000_000);
        let block = H::make_test_block(
            Sha256::hash(b"commitment-fetch-height-hint-mismatch"),
            H::genesis_parent_commitment(NUM_VALIDATORS as u16),
            actual_height,
            7,
            NUM_VALIDATORS as u16,
        );
        let commitment = H::commitment(&block);
        H::propose(
            &mut server_handle,
            Round::new(Epoch::zero(), View::new(actual_height.get())),
            &block,
        )
        .await;

        let subscription = victim_handle.mailbox.subscribe_by_commitment(
            commitment,
            CommitmentFallback::FetchByCommitment {
                height: expected_height,
            },
        );

        setup_network_links(&mut oracle, &peers, LINK).await;

        let received = select! {
            result = subscription => {
                result.expect("commitment subscription should receive the fetched block")
            },
            _ = context.sleep(Duration::from_secs(5)) => {
                panic!("commitment subscription was not woken by height-hint-mismatched block");
            },
        };
        assert_eq!(
            <<H as TestHarness>::Variant as crate::marshal::core::Variant>::commitment(&received),
            commitment
        );
        assert_eq!(received.height(), actual_height);
        let cached = victim_handle
            .mailbox
            .get_block(&received.digest())
            .await
            .expect("height-hint-mismatched fetch should cache by decoded height");
        assert_eq!(cached.height(), actual_height);
    });
}

/// Test basic block subscription delivery.
pub fn subscribe_basic_block_delivery<H: TestHarness>() {
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

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        let subscription_rx = handle.mailbox.subscribe_by_digest(
            digest,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(1)),
            },
        );
        H::propose(&mut handle, Round::new(Epoch::zero(), View::new(1)), &block).await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block,
            &mut handles,
        )
        .await;

        let proposal = Proposal {
            round: Round::new(Epoch::zero(), View::new(1)),
            parent: View::zero(),
            payload: commitment,
        };
        let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization).await;

        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        let received_block = subscription_rx.await.unwrap();
        assert_eq!(received_block.digest(), digest);
        assert_eq!(received_block.height().get(), 1);
    })
}

/// Test multiple subscriptions.
pub fn subscribe_multiple_subscriptions<H: TestHarness>() {
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

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block1 = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle.mailbox.subscribe_by_digest(
            digest1,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(1)),
            },
        );
        let sub2_rx = handle.mailbox.subscribe_by_digest(
            digest2,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(2)),
            },
        );
        let sub3_rx = handle.mailbox.subscribe_by_digest(
            digest1,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(1)),
            },
        );
        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            let proposal = Proposal {
                round,
                parent: View::new(view.checked_sub(1).unwrap()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received1_sub1 = sub1_rx.await.unwrap();
        let received2 = sub2_rx.await.unwrap();
        let received1_sub3 = sub3_rx.await.unwrap();

        assert_eq!(received1_sub1.digest(), digest1);
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received1_sub3.digest(), digest1);
        assert_eq!(received1_sub1.height().get(), 1);
        assert_eq!(received2.height().get(), 2);
        assert_eq!(received1_sub3.height().get(), 1);
    })
}

/// Test canceled subscriptions.
pub fn subscribe_canceled_subscriptions<H: TestHarness>() {
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

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block1 = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            participants.len() as u16,
        );
        let digest1 = H::digest(&block1);
        let digest2 = H::digest(&block2);

        let sub1_rx = handle.mailbox.subscribe_by_digest(
            digest1,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(1)),
            },
        );
        let sub2_rx = handle.mailbox.subscribe_by_digest(
            digest2,
            DigestFallback::FetchByRound {
                round: Round::new(Epoch::zero(), View::new(2)),
            },
        );
        drop(sub1_rx);

        for (view, block) in [(1u64, &block1), (2, &block2)] {
            let round = Round::new(Epoch::zero(), View::new(view));
            H::propose(&mut handle, round, block).await;
            H::verify(&mut handle, round, block, &mut handles).await;

            let proposal = Proposal {
                round,
                parent: View::new(view.checked_sub(1).unwrap()),
                payload: H::commitment(block),
            };
            let notarization = H::make_notarization(proposal.clone(), &schemes, QUORUM);
            H::report_notarization(&mut handle.mailbox, notarization).await;

            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;
        }

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), digest2);
        assert_eq!(received2.height().get(), 2);
    })
}

/// Test blocks from different sources.
pub fn subscribe_blocks_from_different_sources<H: TestHarness>() {
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

        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate() {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }
        let mut handle = handles[0].clone();

        setup_network_links(&mut oracle, &participants, LINK).await;

        let parent = Sha256::hash(b"");
        let n = participants.len() as u16;
        let block1 = H::make_test_block(
            parent,
            H::genesis_parent_commitment(n),
            Height::new(1),
            1,
            n,
        );
        let block2 = H::make_test_block(
            H::digest(&block1),
            H::commitment(&block1),
            Height::new(2),
            2,
            n,
        );
        let block3 = H::make_test_block(
            H::digest(&block2),
            H::commitment(&block2),
            Height::new(3),
            3,
            n,
        );
        let block4 = H::make_test_block(
            H::digest(&block3),
            H::commitment(&block3),
            Height::new(4),
            4,
            n,
        );
        let block5 = H::make_test_block(
            H::digest(&block4),
            H::commitment(&block4),
            Height::new(5),
            5,
            n,
        );

        let sub1_rx = handle
            .mailbox
            .subscribe_by_digest(H::digest(&block1), DigestFallback::Wait);
        let sub2_rx = handle
            .mailbox
            .subscribe_by_digest(H::digest(&block2), DigestFallback::Wait);
        let sub3_rx = handle
            .mailbox
            .subscribe_by_digest(H::digest(&block3), DigestFallback::Wait);
        let sub4_rx = handle
            .mailbox
            .subscribe_by_digest(H::digest(&block4), DigestFallback::Wait);
        let sub5_rx = handle
            .mailbox
            .subscribe_by_digest(H::digest(&block5), DigestFallback::Wait);

        // Block1: Broadcasted by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(1)),
            &block1,
        )
        .await;
        context.sleep(Duration::from_millis(20)).await;

        let received1 = sub1_rx.await.unwrap();
        assert_eq!(received1.digest(), H::digest(&block1));
        assert_eq!(received1.height().get(), 1);

        // Block2: Verified by the actor
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(2)),
            &block2,
            &mut handles,
        )
        .await;

        let received2 = sub2_rx.await.unwrap();
        assert_eq!(received2.digest(), H::digest(&block2));
        assert_eq!(received2.height().get(), 2);

        // Block3: Notarized by the actor
        let proposal3 = Proposal {
            round: Round::new(Epoch::zero(), View::new(3)),
            parent: View::new(2),
            payload: H::commitment(&block3),
        };
        let notarization3 = H::make_notarization(proposal3.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization3).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(3)),
            &block3,
            &mut handles,
        )
        .await;

        let received3 = sub3_rx.await.unwrap();
        assert_eq!(received3.digest(), H::digest(&block3));
        assert_eq!(received3.height().get(), 3);

        // Block4: Finalized by the actor
        let finalization4 = H::make_finalization(
            Proposal {
                round: Round::new(Epoch::zero(), View::new(4)),
                parent: View::new(3),
                payload: H::commitment(&block4),
            },
            &schemes,
            QUORUM,
        );
        H::report_finalization(&mut handle.mailbox, finalization4).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(4)),
            &block4,
            &mut handles,
        )
        .await;

        let received4 = sub4_rx.await.unwrap();
        assert_eq!(received4.digest(), H::digest(&block4));
        assert_eq!(received4.height().get(), 4);

        // Block5: Finalized by the actor with notarization
        let proposal5 = Proposal {
            round: Round::new(Epoch::zero(), View::new(5)),
            parent: View::new(4),
            payload: H::commitment(&block5),
        };
        let notarization5 = H::make_notarization(proposal5.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handle.mailbox, notarization5).await;
        let finalization5 = H::make_finalization(proposal5, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization5).await;
        H::propose(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
        )
        .await;
        H::verify(
            &mut handle,
            Round::new(Epoch::zero(), View::new(5)),
            &block5,
            &mut handles,
        )
        .await;

        let received5 = sub5_rx.await.unwrap();
        assert_eq!(received5.digest(), H::digest(&block5));
        assert_eq!(received5.height().get(), 5);
    })
}

/// Test basic get_info queries for present and missing data.
pub fn get_info_basic_queries_present_and_missing<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no latest
        assert!(handle.mailbox.get_info(Identifier::Latest).await.is_none());

        // The genesis anchor is stored as a finalized block without a finalization row.
        let genesis = H::genesis_block(participants.len() as u16);
        let genesis_digest = H::digest(&genesis);
        assert_eq!(
            handle.mailbox.get_info(Height::zero()).await,
            Some((Height::zero(), genesis_digest))
        );
        assert_eq!(
            handle.mailbox.get_info(&genesis_digest).await,
            Some((Height::zero(), genesis_digest))
        );

        // Before finalization, specific height returns None
        assert!(handle.mailbox.get_info(Height::new(1)).await.is_none());

        // Create and verify a block, then finalize it
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block).await;
        context.sleep(LINK.latency).await;

        let proposal = Proposal {
            round,
            parent: View::zero(),
            payload: commitment,
        };
        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Latest should now be the finalized block
        assert_eq!(
            handle.mailbox.get_info(Identifier::Latest).await,
            Some((Height::new(1), digest))
        );

        // Height 1 now present
        assert_eq!(
            handle.mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Commitment should map to its height
        assert_eq!(
            handle.mailbox.get_info(&digest).await,
            Some((Height::new(1), digest))
        );

        // Missing height
        assert!(handle.mailbox.get_info(Height::new(2)).await.is_none());

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_info(&missing).await.is_none());
    })
}

/// Test get_info latest progression with multiple finalizations.
pub fn get_info_latest_progression_multiple_finalizations<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let mut digests = Vec::new();

        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Latest should always point to most recently finalized
            assert_eq!(
                handle.mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(i), digest))
            );

            parent = digest;
            parent_commitment = commitment;
            digests.push(digest);
        }

        // Verify each height is accessible
        for (i, digest) in digests.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            assert_eq!(
                handle.mailbox.get_info(height).await,
                Some((height, *digest))
            );
        }
    })
}

/// Test get_block by height and latest.
pub fn get_block_by_height_and_latest<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no blocks
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(1)))
            .await
            .is_none());
        assert!(handle.mailbox.get_block(Identifier::Latest).await.is_none());

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let mut blocks = Vec::new();

        for i in 1..=3u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
            blocks.push((digest, block));
        }

        // Verify each block by height
        for (i, (digest, _block)) in blocks.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            let fetched = handle
                .mailbox
                .get_block(Identifier::Height(height))
                .await
                .unwrap();
            assert_eq!(fetched.digest(), *digest);
            assert_eq!(fetched.height(), height);
        }

        // Latest should be last block
        let latest = handle.mailbox.get_block(Identifier::Latest).await.unwrap();
        assert_eq!(latest.digest(), blocks[2].0);
        assert_eq!(latest.height(), Height::new(3));

        // Missing height
        assert!(handle
            .mailbox
            .get_block(Identifier::Height(Height::new(10)))
            .await
            .is_none());
    })
}

/// Test get_block by commitment from various sources.
pub fn get_block_by_commitment_from_sources_and_missing<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create and finalize a block
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);
        let round = Round::new(Epoch::zero(), View::new(1));

        H::propose(&mut handle, round, &block).await;
        context.sleep(LINK.latency).await;

        let proposal = Proposal {
            round,
            parent: View::zero(),
            payload: commitment,
        };
        let finalization = H::make_finalization(proposal, &schemes, QUORUM);
        H::report_finalization(&mut handle.mailbox, finalization).await;

        // Get by commitment
        let fetched = handle.mailbox.get_block(&digest).await.unwrap();
        assert_eq!(fetched.digest(), digest);
        assert_eq!(fetched.height(), Height::new(1));

        // Missing commitment
        let missing = Sha256::hash(b"missing");
        assert!(handle.mailbox.get_block(&missing).await.is_none());
    })
}

/// Test get_finalization by height.
pub fn get_finalization_by_height<H: TestHarness>() {
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Initially, no finalization
        assert!(handle
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .is_none());

        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);

        for i in 1..=3u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal.clone(), &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            // Verify finalization is retrievable
            let fin = handle
                .mailbox
                .get_finalization(Height::new(i))
                .await
                .unwrap();
            assert_eq!(fin.proposal.payload, commitment);
            assert_eq!(fin.round().view(), View::new(i));

            parent = digest;
            parent_commitment = commitment;
        }

        // Missing height
        assert!(handle
            .mailbox
            .get_finalization(Height::new(10))
            .await
            .is_none());
    })
}

/// Test hint_finalized triggers fetch.
pub fn hint_finalized_triggers_fetch<H: TestHarness>() {
    let runner = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(42)
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
            NZUsize!(3),
            participants.clone(),
        )
        .await;

        // Set up two validators
        let setup0 = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            participants[0].clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app0 = setup0.application;
        let mut handle0 = ValidatorHandle {
            mailbox: setup0.mailbox,
            extra: setup0.extra,
        };

        let setup1 = H::setup_validator(
            context.child("validator").with_attribute("index", 1),
            &mut oracle,
            participants[1].clone(),
            ConstantProvider::new(schemes[1].clone()),
        )
        .await;
        let handle1: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup1.mailbox,
            extra: setup1.extra,
        };

        // Add links between validators
        setup_network_links(&mut oracle, &participants[..2], LINK).await;

        // Validator 0: Create and finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::new(0), View::new(i));

            H::propose(&mut handle0, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle0.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Wait for validator 0 to process all blocks
        while app0.tip().map(|(height, _)| height) != Some(Height::new(5)) {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Validator 1 should not have block 5 yet
        assert!(handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none());

        // Validator 1: hint that block 5 is finalized, targeting validator 0
        handle1
            .mailbox
            .hint_finalized(Height::new(5), NonEmptyVec::new(participants[0].clone()));

        // Wait for the fetch to complete
        while handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .is_none()
        {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Verify validator 1 now has the finalization
        let finalization = handle1
            .mailbox
            .get_finalization(Height::new(5))
            .await
            .expect("finalization should be fetched");
        assert_eq!(finalization.proposal.round.view(), View::new(5));
    })
}

/// Test ancestry stream.
pub fn ancestry_stream<H: TestHarness>()
where
    Mailbox<S, H::Variant>: BlockProvider<Block = H::ApplicationBlock>,
{
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
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            me,
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Finalize blocks at heights 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Stream from latest -> height 1
        let (_, commitment) = handle.mailbox.get_info(Identifier::Latest).await.unwrap();
        let fetch_duration = Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        ));
        let ancestry = handle
            .mailbox
            .ancestry(
                Arc::new(context.child("ancestor_stream")),
                (DigestFallback::Wait, commitment),
                fetch_duration,
            )
            .await
            .unwrap();
        let blocks = ancestry.collect::<Vec<_>>().await;

        // Ensure correct delivery order: 5,4,3,2,1
        assert_eq!(blocks.len(), 5);
        (0..5).for_each(|i| {
            assert_eq!(blocks[i].height().get(), 5 - i as u64);
        });
    })
}

/// Test finalize same height different views.
pub fn finalize_same_height_different_views<H: TestHarness>() {
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

        // Set up two validators
        let mut handles = Vec::new();
        for (i, validator) in participants.iter().enumerate().take(2) {
            let setup = H::setup_validator(
                context.child("validator").with_attribute("index", i),
                &mut oracle,
                validator.clone(),
                ConstantProvider::new(schemes[i].clone()),
            )
            .await;
            handles.push(ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            });
        }

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Both validators receive the block
        for handle in handles.iter_mut() {
            H::propose(handle, Round::new(Epoch::new(0), View::new(1)), &block).await;
        }
        context.sleep(LINK.latency).await;

        // Validator 0: Finalize with view 1
        let proposal_v1 = Proposal {
            round: Round::new(Epoch::new(0), View::new(1)),
            parent: View::new(0),
            payload: commitment,
        };
        let notarization_v1 = H::make_notarization(proposal_v1.clone(), &schemes, QUORUM);
        let finalization_v1 = H::make_finalization(proposal_v1.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handles[0].mailbox, notarization_v1.clone()).await;
        H::report_finalization(&mut handles[0].mailbox, finalization_v1.clone()).await;

        // Validator 1: Finalize with view 2 (simulates receiving finalization from different view)
        let proposal_v2 = Proposal {
            round: Round::new(Epoch::new(0), View::new(2)), // Different view
            parent: View::new(0),
            payload: commitment, // Same block
        };
        let notarization_v2 = H::make_notarization(proposal_v2.clone(), &schemes, QUORUM);
        let finalization_v2 = H::make_finalization(proposal_v2.clone(), &schemes, QUORUM);
        H::report_notarization(&mut handles[1].mailbox, notarization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v2.clone()).await;

        // Wait for finalization processing
        context.sleep(Duration::from_millis(100)).await;

        // Verify both validators stored the block correctly
        let block0 = handles[0].mailbox.get_block(Height::new(1)).await.unwrap();
        let block1 = handles[1].mailbox.get_block(Height::new(1)).await.unwrap();
        assert_eq!(block0.digest(), digest);
        assert_eq!(block1.digest(), digest);

        // Verify both validators have finalizations stored
        let fin0 = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        let fin1 = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();

        // Verify the finalizations have the expected different views
        assert_eq!(fin0.proposal.payload, commitment);
        assert_eq!(fin0.round().view(), View::new(1));
        assert_eq!(fin1.proposal.payload, commitment);
        assert_eq!(fin1.round().view(), View::new(2));

        // Both validators can retrieve block by height
        assert_eq!(
            handles[0].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );
        assert_eq!(
            handles[1].mailbox.get_info(Height::new(1)).await,
            Some((Height::new(1), digest))
        );

        // Test that a validator receiving BOTH finalizations handles it correctly
        H::report_finalization(&mut handles[0].mailbox, finalization_v2.clone()).await;
        H::report_finalization(&mut handles[1].mailbox, finalization_v1.clone()).await;
        context.sleep(Duration::from_millis(100)).await;

        // Validator 0 should still have the original finalization (v1)
        let fin0_after = handles[0]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(fin0_after.round().view(), View::new(1));

        // Validator 1 should still have the original finalization (v2)
        let fin1_after = handles[1]
            .mailbox
            .get_finalization(Height::new(1))
            .await
            .unwrap();
        assert_eq!(fin1_after.round().view(), View::new(2));
    })
}

/// Test init processed height.
pub fn init_processed_height<H: TestHarness>() {
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

        let validator = participants[0].clone();

        // First session: create validator and finalize some blocks
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let app = setup.application;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };
        let initial_height = setup.height;

        // Initially no block has been durably acknowledged.
        assert_eq!(initial_height, None);

        // Finalize blocks 1-5
        let mut parent = Sha256::hash(b"");
        let mut parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        for i in 1..=5u64 {
            let block = H::make_test_block(
                parent,
                parent_commitment,
                Height::new(i),
                i,
                participants.len() as u16,
            );
            let digest = H::digest(&block);
            let commitment = H::commitment(&block);
            let round = Round::new(Epoch::zero(), View::new(i));

            H::propose(&mut handle, round, &block).await;
            context.sleep(LINK.latency).await;

            let proposal = Proposal {
                round,
                parent: View::new(i - 1),
                payload: commitment,
            };
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            H::report_finalization(&mut handle.mailbox, finalization).await;

            parent = digest;
            parent_commitment = commitment;
        }

        // Wait for application to process all blocks
        while app.tip().map(|(height, _)| height) != Some(Height::new(5)) {
            context.sleep(Duration::from_millis(10)).await;
        }

        // Drop the handle to simulate shutdown
        drop(handle);

        // Second session: create new validator instance, should recover processed height
        let setup2 = H::setup_validator(
            context
                .child("validator_restart")
                .with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let recovered_height = setup2.height;

        // Should have recovered to height 5
        assert_eq!(recovered_height, Some(Height::new(5)));
    })
}

/// Test broadcast caches block.
pub fn broadcast_caches_block<H: TestHarness>() {
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

        // Set up one validator
        let validator = participants[0].clone();
        let setup = H::setup_validator(
            context.child("validator").with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle = ValidatorHandle {
            mailbox: setup.mailbox,
            extra: setup.extra,
        };

        // Create block at height 1
        let parent = Sha256::hash(b"");
        let parent_commitment = H::genesis_parent_commitment(participants.len() as u16);
        let block = H::make_test_block(
            parent,
            parent_commitment,
            Height::new(1),
            1,
            participants.len() as u16,
        );
        let digest = H::digest(&block);
        let commitment = H::commitment(&block);

        // Broadcast the block
        H::propose(&mut handle, Round::new(Epoch::new(0), View::new(1)), &block).await;

        // Ensure the block is cached and retrievable
        handle
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");

        // Restart marshal, removing any in-memory cache
        let setup2 = H::setup_validator(
            context
                .child("validator_restart")
                .with_attribute("index", 0),
            &mut oracle,
            validator.clone(),
            ConstantProvider::new(schemes[0].clone()),
        )
        .await;
        let mut handle2: ValidatorHandle<H> = ValidatorHandle {
            mailbox: setup2.mailbox,
            extra: setup2.extra,
        };

        // Put a notarization into the cache to re-initialize the ephemeral cache for the
        // first epoch.
        let notarization = H::make_notarization(
            Proposal {
                round: Round::new(Epoch::new(0), View::new(1)),
                parent: View::new(0),
                payload: commitment,
            },
            &schemes,
            QUORUM,
        );
        H::report_notarization(&mut handle2.mailbox, notarization).await;

        // Ensure the block is cached and retrievable
        handle2
            .mailbox
            .get_block(&digest)
            .await
            .expect("block should be cached after broadcast");
    })
}
