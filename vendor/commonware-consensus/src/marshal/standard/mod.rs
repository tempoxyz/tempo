//! Standard variant for Marshal.
//!
//! # Overview
//!
//! The standard variant broadcasts complete blocks to all peers. Each validator
//! receives the full block directly from the proposer or via gossip.
//!
//! # Components
//!
//! - [`Standard`]: The variant marker type that configures marshal for full-block broadcast.
//! - [`Deferred`]: Deferred-verification wrapper that enforces epoch boundaries and
//!   coordinates with the marshal actor.
//! - [`Inline`]: Inline-verification wrapper for applications whose blocks do not
//!   implement [`crate::CertifiableBlock`].
//!
//! # Usage
//!
//! The standard variant uses the core [`crate::marshal::core::Actor`] and
//! [`crate::marshal::core::Mailbox`] with [`Standard`] as the variant type parameter.
//! Blocks are broadcast through [`commonware_broadcast::buffered`].
//!
//! # When to Use
//!
//! Prefer this variant when block sizes are small enough that shipping full blocks
//! to every peer is acceptable or if participants have sufficiently powerful networking
//! and want to avoid encoding / decoding overhead.

commonware_macros::stability_scope!(ALPHA {
    mod deferred;
    pub use deferred::Deferred;

    mod inline;
    pub use inline::Inline;

    mod relay;
    /// Relay a staged proposal or forward a previously stored block.
    pub use relay::broadcast as relay_broadcast;

    /// Shared durability gates for custom inline application adapters.
    pub use crate::marshal::application::gates::{
        resolve as resolve_verification, Gates,
    };
    mod validation;
});

mod variant;
pub use variant::Standard;

#[cfg(test)]
mod tests {
    use super::{relay, Deferred, Inline, Standard};
    use crate::{
        marshal::{
            ancestry::BlockProvider,
            application::gates::Gates,
            config::{Config, Start},
            core::{
                cache, durability::Durable as _, Actor, CommitmentFallback, DigestFallback, Mailbox,
            },
            mocks::{
                application::Application,
                harness::{
                    self, default_leader, make_raw_block, setup_network_links,
                    setup_network_with_participants, Ctx, DeferredHarness, EmptyProvider,
                    InlineHarness, StandardHarness, TestHarness, ValidatorHandle, B,
                    BLOCKS_PER_EPOCH, D, LINK, NAMESPACE, NUM_VALIDATORS, PAGE_CACHE_SIZE,
                    PAGE_SIZE, QUORUM, S, UNRELIABLE_LINK, V,
                },
                verifying::MockVerifyingApp,
            },
            resolver::handler,
            Identifier, Update,
        },
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{Finalization, Proposal},
            Plan,
        },
        types::{Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
        Automaton, CertifiableAutomaton, Heightable, Reporter,
    };
    use bytes::Bytes;
    use commonware_actor::{mailbox, Feedback};
    use commonware_broadcast::{buffered, Broadcaster as _};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Provider, Scoped, Verifier as _},
        ed25519::PublicKey,
        sha256::Sha256,
        Digestible, Hasher as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{self, Network},
        Manager as _, Recipients,
    };
    use commonware_parallel::Sequential;
    use commonware_resolver::{Consumer, Delivery, Fetch, Resolver, TargetedResolver};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Quota, Runner, Spawner,
        Supervisor as _,
    };
    use commonware_storage::{
        archive::{immutable, prunable, Archive as _},
        metadata::{self, Metadata},
        translator::{EightCap, TwoCap},
    };
    use commonware_utils::{
        acknowledgement::Exact,
        channel::{fallible::OneshotExt, mpsc, oneshot, oneshot::error::TryRecvError},
        ordered::Set,
        sequence::U64,
        sync::Mutex,
        vec::NonEmptyVec,
        Acknowledgement as _, NZUsize, NZU16, NZU64,
    };
    use std::{
        num::{NonZeroU32, NonZeroU64, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };

    #[test]
    fn mailbox_provides_application_blocks() {
        fn assert_provider<P: BlockProvider<Block = B>>() {}
        assert_provider::<Mailbox<S, Standard<B>>>();
    }

    #[derive(Clone)]
    struct VerifierProvider {
        scheme: Arc<S>,
    }

    impl VerifierProvider {
        fn new(scheme: S) -> Self {
            Self {
                scheme: Arc::new(scheme),
            }
        }
    }

    impl Provider for VerifierProvider {
        type Scope = Epoch;
        type Scheme = S;

        fn scoped(&self, _: Epoch) -> Option<Scoped<S>> {
            Some(Scoped::verifier(self.scheme.clone()))
        }
    }

    #[test_traced("WARN")]
    fn test_standard_block_provider_parent_fetches_by_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let buffer = RecordingBuffer::default();
            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-provider-parent-commitment",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(buffer),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let parent = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let child = make_raw_block(parent.digest(), Height::new(2), 200);
            let subscription = mailbox.subscribe_parent(&child);

            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                buffer.commitment_subscription_count(),
                1,
                "parent walkback should use the standard parent commitment"
            );
            drop(subscription);
        });
    }

    fn assert_finalize_deterministic<H: TestHarness>(
        seed: u64,
        link: commonware_p2p::simulated::Link,
        quorum_sees_finalization: bool,
    ) {
        let r1 = harness::finalize::<H>(seed, link.clone(), quorum_sees_finalization);
        let r2 = harness::finalize::<H>(seed, link, quorum_sees_finalization);
        assert_eq!(r1, r2);
    }

    fn assert_hailstorm_deterministic<H: TestHarness>(seed: u64) {
        let r1 = harness::hailstorm::<H>(seed, 4, 4, 1, LINK);
        let r2 = harness::hailstorm::<H>(seed, 4, 4, 1, LINK);
        assert_eq!(r1, r2);
    }

    fn assert_hailstorm_multi_deterministic<H: TestHarness>(seed: u64) {
        let r1 = harness::hailstorm::<H>(seed, 4, 4, 2, LINK);
        let r2 = harness::hailstorm::<H>(seed, 4, 4, 2, LINK);
        assert_eq!(r1, r2);
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_good_links() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, LINK, false);
            assert_finalize_deterministic::<DeferredHarness>(seed, LINK, false);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, UNRELIABLE_LINK, false);
            assert_finalize_deterministic::<DeferredHarness>(seed, UNRELIABLE_LINK, false);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, LINK, true);
            assert_finalize_deterministic::<DeferredHarness>(seed, LINK, true);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            assert_finalize_deterministic::<InlineHarness>(seed, UNRELIABLE_LINK, true);
            assert_finalize_deterministic::<DeferredHarness>(seed, UNRELIABLE_LINK, true);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_hailstorm_restarts() {
        for seed in 0..2 {
            assert_hailstorm_deterministic::<InlineHarness>(seed);
            assert_hailstorm_deterministic::<DeferredHarness>(seed);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_standard_hailstorm_multi_restarts() {
        for seed in 0..2 {
            assert_hailstorm_multi_deterministic::<InlineHarness>(seed);
            assert_hailstorm_multi_deterministic::<DeferredHarness>(seed);
        }
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog() {
        harness::ack_pipeline_backlog::<InlineHarness>();
        harness::ack_pipeline_backlog::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ack_pipeline_backlog_persists_on_restart() {
        harness::ack_pipeline_backlog_persists_on_restart::<InlineHarness>();
        harness::ack_pipeline_backlog_persists_on_restart::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_genesis_emitted_once() {
        harness::genesis_emitted_once::<InlineHarness>();
        harness::genesis_emitted_once::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_proposed_success_implies_recoverable_after_restart() {
        harness::proposed_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::proposed_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_verified_success_implies_recoverable_after_restart() {
        harness::verified_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::verified_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_certify_persists_equivocated_block() {
        harness::certify_persists_equivocated_block::<InlineHarness>();
        harness::certify_persists_equivocated_block::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_verified_after_restart_reverify_same_round_implies_recoverable() {
        harness::verified_after_restart_reverify_same_round_implies_recoverable::<InlineHarness>();
        harness::verified_after_restart_reverify_same_round_implies_recoverable::<DeferredHarness>(
        );
    }

    #[test_traced("WARN")]
    fn test_standard_certify_after_restart_reverify_same_round_implies_recoverable() {
        harness::certify_after_restart_reverify_same_round_implies_recoverable::<InlineHarness>();
        harness::certify_after_restart_reverify_same_round_implies_recoverable::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_certified_success_implies_recoverable_after_restart() {
        harness::certified_success_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::certified_success_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_certify_at_later_view_survives_earlier_view_pruning() {
        harness::certify_at_later_view_survives_earlier_view_pruning::<InlineHarness>();
        harness::certify_at_later_view_survives_earlier_view_pruning::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_delivery_visibility_implies_recoverable_after_restart() {
        harness::delivery_visibility_implies_recoverable_after_restart::<InlineHarness>(0..16);
        harness::delivery_visibility_implies_recoverable_after_restart::<DeferredHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_standard_sync_height_floor() {
        harness::sync_height_floor::<InlineHarness>();
        harness::sync_height_floor::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_reject_stale_block_delivery_after_floor_update() {
        harness::reject_stale_block_delivery_after_floor_update::<InlineHarness>();
        harness::reject_stale_block_delivery_after_floor_update::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_commitment_fetch_height_hint_mismatch_wakes_subscriber() {
        harness::commitment_fetch_height_hint_mismatch_wakes_subscriber::<InlineHarness>();
        harness::commitment_fetch_height_hint_mismatch_wakes_subscriber::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_prune_finalized_archives() {
        harness::prune_finalized_archives::<InlineHarness>();
        harness::prune_finalized_archives::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<InlineHarness>();
        harness::subscribe_basic_block_delivery::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<InlineHarness>();
        harness::subscribe_multiple_subscriptions::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<InlineHarness>();
        harness::subscribe_canceled_subscriptions::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<InlineHarness>();
        harness::subscribe_blocks_from_different_sources::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<InlineHarness>();
        harness::get_info_basic_queries_present_and_missing::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<InlineHarness>();
        harness::get_info_latest_progression_multiple_finalizations::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<InlineHarness>();
        harness::get_block_by_height_and_latest::<DeferredHarness>();
    }

    // Directly writes blocks and finalizations into the storage archives
    // used by the marshal, bypassing the normal finalization flow. This lets
    // us manufacture inconsistent on-disk state (a finalization without
    // its corresponding block) to simulate crash-recovery scenarios.
    async fn seed_inconsistent_restart_state(
        context: deterministic::Context,
        partition_prefix: &str,
        blocks: &[B],
        finalizations: &[(Height, Finalization<S, D>)],
    ) {
        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let replay_buffer = NonZeroUsize::new(1024).unwrap();
        let write_buffer = NonZeroUsize::new(1024).unwrap();
        let items_per_section = NonZeroU64::new(10).unwrap();

        let mut finalizations_by_height = immutable::Archive::init(
            context.child("seed_finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-key"
                ),
                freezer_key_page_cache: page_cache.clone(),
                freezer_value_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
                items_per_section,
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations archive for seeded restart state");

        let mut finalized_blocks = immutable::Archive::init(
            context.child("seed_finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalized_blocks-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalized_blocks-freezer-key"),
                freezer_key_page_cache: page_cache,
                freezer_value_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalized_blocks-ordinal"),
                items_per_section,
                codec_config: (),
                replay_buffer,
                freezer_key_write_buffer: write_buffer,
                freezer_value_write_buffer: write_buffer,
                ordinal_write_buffer: write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive for seeded restart state");

        for block in blocks {
            finalized_blocks
                .put(block.height().get(), block.digest(), block.clone())
                .await
                .expect("failed to seed finalized block");
        }
        finalized_blocks
            .sync()
            .await
            .expect("failed to sync seeded finalized blocks");

        for (height, finalization) in finalizations {
            finalizations_by_height
                .put(
                    height.get(),
                    finalization.proposal.payload,
                    finalization.clone(),
                )
                .await
                .expect("failed to seed finalization");
        }
        finalizations_by_height
            .sync()
            .await
            .expect("failed to sync seeded finalizations");
    }

    async fn seed_processed_height(
        context: deterministic::Context,
        partition_prefix: &str,
        height: Height,
    ) {
        let mut metadata: Metadata<deterministic::Context, U64, Height> = Metadata::init(
            context.child("seed_application_metadata"),
            metadata::Config {
                partition: format!("{partition_prefix}-application-metadata"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata for seeded restart state");
        metadata.put(U64::new(0xFF), height);
        metadata
            .sync()
            .await
            .expect("failed to sync seeded application metadata");
    }

    // Writes a block directly into the cache's per-epoch notarized storage,
    // simulating a block that was notarized but never finalized before a crash.
    async fn seed_cache_block(
        context: deterministic::Context,
        partition_prefix: &str,
        epoch: Epoch,
        view: View,
        block: &B,
    ) {
        let cache_prefix = format!("{partition_prefix}-cache");
        let replay_buffer = NonZeroUsize::new(1024).unwrap();
        let write_buffer = NonZeroUsize::new(1024).unwrap();

        let mut metadata: Metadata<deterministic::Context, u8, (Epoch, Epoch)> = Metadata::init(
            context.child("seed_cache_metadata"),
            metadata::Config {
                partition: format!("{cache_prefix}-metadata"),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize cache metadata");
        metadata.put(0, (epoch, epoch));
        metadata
            .sync()
            .await
            .expect("failed to sync cache metadata");

        let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let mut notarized: prunable::Archive<TwoCap, deterministic::Context, D, B> =
            prunable::Archive::init(
                context.child("seed_notarized"),
                prunable::Config {
                    translator: TwoCap,
                    key_partition: format!("{cache_prefix}-cache-{epoch}-notarized-key"),
                    key_page_cache: page_cache,
                    value_partition: format!("{cache_prefix}-cache-{epoch}-notarized-value"),
                    items_per_section: NonZeroU64::new(10).unwrap(),
                    compression: None,
                    codec_config: (),
                    replay_buffer,
                    key_write_buffer: write_buffer,
                    value_write_buffer: write_buffer,
                },
            )
            .await
            .expect("failed to initialize notarized blocks archive");
        notarized
            .put_sync(view.get(), block.digest(), block.clone())
            .await
            .expect("failed to seed notarized block");
    }

    // Verifies that a validator whose finalized-blocks archive is missing
    // the block at the tip (has finalization for height 2 but only block 1)
    // fetches the missing block from a peer on restart.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_trailing_missing_finalized_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build chain: genesis -> block_one -> block_two
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_two.clone()).await;
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: has block_one but only a finalization
            // (no block data) for height 2.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            // Start the recovering validator and verify initial state.
            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all blocks sequentially. Block 2 must be
            // repaired from the peer before it can be dispatched.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that a validator missing an internal block (has blocks 1 and 3
    // but not 2, with finalizations for both 2 and 3) fetches the gap from a
    // peer on restart.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_internal_missing_finalized_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build chain: genesis -> block_one -> block_two -> block_three
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let block_three = make_raw_block(block_two.digest(), Height::new(3), 300);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );
            let finalization_three = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(3)),
                    View::new(2),
                    StandardHarness::commitment(&block_three),
                ),
                &schemes,
                3,
            );

            // Give the peer all blocks so it can serve them during repair.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(1)), block_one.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), block_two.clone())
                    .await
            );

            assert!(
                peer_mailbox
                    .verified(Round::new(Epoch::zero(), View::new(3)), block_three.clone())
                    .await
            );
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_two.clone()).await;
            StandardHarness::report_finalization(&mut peer_mailbox, finalization_three.clone())
                .await;
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: has blocks 1 and 3 but is missing
            // block 2 (an internal gap in the finalized chain).
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one, block_three.clone()],
                &[
                    (Height::new(2), finalization_two),
                    (Height::new(3), finalization_three),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all three blocks sequentially. Block 2 must be
            // repaired from the peer before it can be dispatched.
            for expected_height in 1..=3 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that a block persisted at a height beyond the last finalization
    // is still surfaced via get_block and dispatched to the application. This
    // can happen if a crash occurs after persisting the block but before
    // persisting its finalization.
    #[test_traced("WARN")]
    fn test_standard_restart_surfaces_block_without_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();

            // Build chain: genesis -> block_one -> block_two
            // Only block_one gets a finalization; block_two is an orphan.
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_one = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    StandardHarness::commitment(&block_one),
                ),
                &schemes,
                3,
            );

            // Seed state: both blocks persisted, but only block_one has a
            // finalization. block_two is a block without a corresponding
            // finalization row.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[(Height::new(1), finalization_one)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;

            // The tip tracks the highest finalization, not the highest block.
            assert_eq!(
                recovering.mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(1), block_one.digest())),
                "latest tip should be derived from the highest stored finalization"
            );
            assert_eq!(
                recovering.mailbox.get_block(Height::new(2)).await,
                Some(block_two.clone()),
                "block without a finalization row should still be queryable by height"
            );
            assert_eq!(
                recovering.mailbox.get_info(Height::new(2)).await,
                Some((Height::new(2), block_two.digest())),
                "block info should fall back to the finalized-block archive"
            );

            // Walk the application through sequential acks. Even though
            // block_two has no finalization, it is still dispatched because
            // its block data exists in the archive.
            assert_eq!(recovering.application.acknowledged().await, Height::zero());
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies repair when many trailing blocks are missing. Seed state has
    // only block_one's data but finalizations for heights 1-5. The recovering
    // validator must fetch blocks 2-5 from the peer.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_multiple_trailing_missing_finalized_blocks() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();

            // Build a 5-block chain.
            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let block_three = make_raw_block(block_two.digest(), Height::new(3), 300);
            let block_four = make_raw_block(block_three.digest(), Height::new(4), 400);
            let block_five = make_raw_block(block_four.digest(), Height::new(5), 500);

            let mut finalizations = Vec::new();
            let blocks = [
                &block_one,
                &block_two,
                &block_three,
                &block_four,
                &block_five,
            ];
            for (i, block) in blocks.iter().enumerate() {
                let view = View::new(block.height().get());
                let parent_view = if i == 0 {
                    View::zero()
                } else {
                    View::new(blocks[i - 1].height().get())
                };
                finalizations.push(StandardHarness::make_finalization(
                    Proposal::new(
                        Round::new(Epoch::zero(), view),
                        parent_view,
                        StandardHarness::commitment(block),
                    ),
                    &schemes,
                    3,
                ));
            }

            // Give the peer all blocks and finalizations.
            let mut peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            for (i, block) in blocks.iter().enumerate() {
                assert!(
                    peer_mailbox
                        .verified(
                            Round::new(Epoch::zero(), View::new(block.height().get())),
                            (*block).clone(),
                        )
                        .await
                );
                StandardHarness::report_finalization(&mut peer_mailbox, finalizations[i].clone())
                    .await;
            }
            context.sleep(Duration::from_millis(200)).await;

            // Seed inconsistent state: only block_one persisted but all 5
            // finalizations exist, leaving blocks 2-5 missing.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &finalizations
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (Height::new(i as u64 + 1), f.clone()))
                    .collect::<Vec<_>>(),
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through all five blocks sequentially. Blocks 2-5 must be
            // repaired from the peer before they can be dispatched.
            for expected_height in 1..=5 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies repair when the finalized tip is far ahead of the last stored
    // block and only the tip has a direct finalization. This forces recovery to
    // walk the chain backwards by block commitment for more than `max_repair`
    // missing heights.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_large_pending_tip_by_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(120));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();
            let peer_validator = participants[1].clone();
            let pending_tip = 18;

            let mut blocks = Vec::new();
            let mut parent = Sha256::hash(b"");
            for height in 1..=pending_tip {
                let block = make_raw_block(parent, Height::new(height), height * 100);
                parent = block.digest();
                blocks.push(block);
            }
            let tip_block = blocks.last().expect("tip block exists");
            let tip_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(pending_tip)),
                    View::new(pending_tip - 1),
                    StandardHarness::commitment(tip_block),
                ),
                &schemes,
                QUORUM,
            );

            // Give the peer every block, but the recovering validator will only
            // know the tip finalization. The repair loop must fetch blocks
            // 18 down to 2 by commitment.
            let peer_mailbox = StandardHarness::setup_validator(
                context.child("peer_validator"),
                &mut oracle,
                peer_validator.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await
            .mailbox;
            for block in blocks.iter() {
                assert!(
                    peer_mailbox
                        .verified(
                            Round::new(Epoch::zero(), View::new(block.height().get())),
                            block.clone(),
                        )
                        .await
                );
            }
            context.sleep(Duration::from_millis(200)).await;

            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[blocks[0].clone()],
                &[(Height::new(pending_tip), tip_finalization)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;

            for _ in 0..100 {
                if recovering.application.tip().map(|(height, _)| height)
                    == Some(Height::new(pending_tip))
                {
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                recovering.application.tip().map(|(height, _)| height),
                Some(Height::new(pending_tip)),
                "restart should surface the pending finalized tip before all blocks are repaired"
            );

            assert_eq!(recovering.application.acknowledged().await, Height::zero());
            for expected_height in 1..=pending_tip {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }

            for height in [2, 10, pending_tip] {
                let block = recovering
                    .mailbox
                    .get_block(Height::new(height))
                    .await
                    .unwrap_or_else(|| panic!("block {height} should be recoverable"));
                assert_eq!(block.digest(), blocks[(height - 1) as usize].digest());
            }
        });
    }

    // Verifies that when all finalized blocks are already present on disk,
    // restart completes normally with no repair needed. Acts as a baseline
    // to confirm the repair logic is a no-op in the consistent case.
    #[test_traced("WARN")]
    fn test_standard_restart_no_trailing_finalizations_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
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
            setup_network_links(&mut oracle, &participants, LINK).await;

            let recovering_validator = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_one = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    StandardHarness::commitment(&block_one),
                ),
                &schemes,
                3,
            );
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            // Seed fully consistent state: both blocks and both finalizations.
            let partition_prefix = format!("validator-{recovering_validator}");
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one.clone(), block_two.clone()],
                &[
                    (Height::new(1), finalization_one),
                    (Height::new(2), finalization_two),
                ],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through sequential acks to confirm no repair was needed.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that trailing repair can source a missing block from the local
    // cache (notarized storage) instead of fetching from a peer. This covers
    // the case where a block was notarized and cached but the finalized-blocks
    // archive was not updated before a crash.
    #[test_traced("WARN")]
    fn test_standard_restart_repairs_trailing_block_from_local_cache() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            // No network links: forces repair to rely on local cache only.
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(3),
                participants.clone(),
            )
            .await;

            let recovering_validator = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let block_one = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_two = make_raw_block(block_one.digest(), Height::new(2), 200);
            let finalization_two = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(2)),
                    View::new(1),
                    StandardHarness::commitment(&block_two),
                ),
                &schemes,
                3,
            );

            let partition_prefix = format!("validator-{recovering_validator}");

            // Seed block_two into the cache's notarized storage so the
            // recovering validator can find it locally during trailing repair,
            // without needing a peer to serve it.
            seed_cache_block(
                context.child("storage"),
                &partition_prefix,
                Epoch::zero(),
                View::new(2),
                &block_two,
            )
            .await;

            // Seed inconsistent state: block_one in the finalized archive,
            // finalization for height 2 but no block_two in the archive.
            // block_two only exists in the cache's notarized storage.
            seed_inconsistent_restart_state(
                context.child("storage"),
                &partition_prefix,
                &[block_one],
                &[(Height::new(2), finalization_two)],
            )
            .await;

            let recovering = StandardHarness::setup_validator_with(
                context.child("recovering_validator"),
                &mut oracle,
                recovering_validator,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                crate::marshal::mocks::application::Application::manual_ack(),
            )
            .await;
            assert_eq!(recovering.application.acknowledged().await, Height::zero());

            // Walk through both blocks to confirm repair recovered them.
            for expected_height in 1..=2 {
                let h = recovering.application.acknowledged().await;
                assert_eq!(h, Height::new(expected_height));
            }
        });
    }

    // Verifies that cache::Manager::load_persisted_epochs re-opens epoch
    // archives from disk, making blocks written in a prior session findable
    // via find_block after restart.
    #[test_traced("WARN")]
    fn test_cache_load_persisted_epochs_finds_blocks() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            let prefix = "test-cache";
            let make_cfg = || cache::Config {
                partition_prefix: prefix.to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NonZeroUsize::new(1024).unwrap(),
                key_write_buffer: NonZeroUsize::new(1024).unwrap(),
                value_write_buffer: NonZeroUsize::new(1024).unwrap(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));

            // Write a block into the cache.
            {
                let mut mgr = cache::Manager::<_, Standard<B>, S>::init(
                    context.child("write"),
                    make_cfg(),
                    (),
                )
                .await;
                mgr.put_notarized(round, digest, block.clone())
                    .await
                    .await
                    .expect("failed to sync block");
            }

            // Re-init the cache (simulating restart). find_block should fail
            // before loading persisted epochs.
            let mut mgr =
                cache::Manager::<_, Standard<B>, S>::init(context.child("read"), make_cfg(), ())
                    .await;
            assert_eq!(
                mgr.find_block_matching(digest, |_| true).await,
                None,
                "cache should not find block before loading persisted epochs"
            );

            mgr.load_persisted_epochs().await;
            assert_eq!(
                mgr.find_block_matching(digest, |_| true).await,
                Some(block),
                "cache should find block after loading persisted epochs"
            );
        });
    }

    // The certify barrier folds in notarization durability via
    // `start_sync_notarizations`: the handle it returns covers a notarization
    // write accepted earlier (whose own handle was dropped unawaited), so
    // awaiting the barrier guarantees the certificate is recoverable.
    #[test_traced("WARN")]
    fn test_cache_start_sync_notarizations_covers_prior_write() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let prefix = "test-cache-notarizations";
            let make_cfg = || cache::Config {
                partition_prefix: prefix.to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NonZeroUsize::new(1024).unwrap(),
                key_write_buffer: NonZeroUsize::new(1024).unwrap(),
                value_write_buffer: NonZeroUsize::new(1024).unwrap(),
                key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };

            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();
            let round = Round::new(Epoch::zero(), View::new(1));
            let notarization = StandardHarness::make_notarization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            {
                let mut mgr = cache::Manager::<_, Standard<B>, S>::init(
                    context.child("write"),
                    make_cfg(),
                    (),
                )
                .await;
                drop(mgr.put_notarization(round, digest, notarization).await);
                mgr.start_sync_notarizations(round)
                    .await
                    .await
                    .expect("failed to sync notarizations");
            }

            let mut mgr =
                cache::Manager::<_, Standard<B>, S>::init(context.child("read"), make_cfg(), ())
                    .await;
            mgr.load_persisted_epochs().await;
            assert!(
                mgr.get_notarization(round).await.is_some(),
                "notarization covered by the barrier must be durable"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<InlineHarness>();
        harness::get_block_by_commitment_from_sources_and_missing::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_get_finalization_by_height() {
        harness::get_finalization_by_height::<InlineHarness>();
        harness::get_finalization_by_height::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<InlineHarness>();
        harness::hint_finalized_triggers_fetch::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_ancestry_stream() {
        harness::ancestry_stream::<InlineHarness>();
        harness::ancestry_stream::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<InlineHarness>();
        harness::finalize_same_height_different_views::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_init_processed_height() {
        harness::init_processed_height::<InlineHarness>();
        harness::init_processed_height::<DeferredHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_broadcast_caches_block() {
        harness::broadcast_caches_block::<InlineHarness>();
        harness::broadcast_caches_block::<DeferredHarness>();
    }

    #[test_traced("INFO")]
    fn test_standard_rejects_block_delivery_below_floor() {
        harness::reject_stale_block_delivery_after_floor_update::<InlineHarness>();
        harness::reject_stale_block_delivery_after_floor_update::<DeferredHarness>();
    }

    #[test_traced("WARN")]
    fn test_standard_buffered_block_installs_floor_anchor() {
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

            // No links are added, so the resolver fetch started by `set_floor`
            // can never complete. The anchor can only arrive through the buffer.
            let setup = StandardHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let app = setup.application;
            let mailbox = setup.mailbox;
            let buffer = setup.extra;

            // Build a chain whose tip is the floor anchor.
            const ANCHOR_HEIGHT: u64 = 5;
            let mut parent = Sha256::hash(b"");
            let mut anchor = None;
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                anchor = Some(block);
            }
            let anchor = anchor.unwrap();

            // Subscribe to the anchor, creating a buffer-backed waiter.
            let subscription = mailbox.subscribe_by_digest(anchor.digest(), DigestFallback::Wait);

            // Set a floor whose anchor block is not yet available locally.
            let round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));
            let finalization = StandardHarness::make_finalization(
                Proposal {
                    round,
                    parent: View::new(ANCHOR_HEIGHT - 1),
                    payload: anchor.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded a pending anchor before the buffer delivers the block.
            assert!(mailbox
                .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                .await
                .is_none());

            // Deliver the anchor through the broadcast buffer, completing the waiter.
            let _ = buffer.broadcast(Recipients::All, anchor.clone());

            // The waiter must wake the subscriber.
            let received = subscription.await.unwrap();
            assert_eq!(received.digest(), anchor.digest());

            // The waiter must also install the floor anchor and resume dispatch.
            while !app.blocks().contains_key(&Height::new(ANCHOR_HEIGHT)) {
                context.sleep(Duration::from_millis(50)).await;
            }
            let (tip_height, tip_digest) = app.tip().unwrap();
            assert_eq!(tip_height, Height::new(ANCHOR_HEIGHT));
            assert_eq!(tip_digest, anchor.digest());
            let stored = mailbox
                .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                .await
                .unwrap();
            assert_eq!(stored.digest(), anchor.digest());
        })
    }

    #[test_traced("WARN")]
    fn test_standard_resolver_floor_anchor_install_wakes_subscriber() {
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
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                peers.clone(),
            )
            .await;

            let victim_setup = StandardHarness::setup_validator(
                context.child("victim"),
                &mut oracle,
                victim.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let server_setup = StandardHarness::setup_validator(
                context.child("server"),
                &mut oracle,
                server.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let app = victim_setup.application;
            let mailbox = victim_setup.mailbox;
            let mut server_handle: ValidatorHandle<StandardHarness> = ValidatorHandle {
                mailbox: server_setup.mailbox,
                extra: server_setup.extra,
            };

            // Build a chain whose tip is the floor anchor.
            const ANCHOR_HEIGHT: u64 = 5;
            let mut parent = Sha256::hash(b"");
            let mut anchor = None;
            for i in 1..=ANCHOR_HEIGHT {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                anchor = Some(block);
            }
            let anchor = anchor.unwrap();
            let round = Round::new(Epoch::zero(), View::new(ANCHOR_HEIGHT));

            // The server caches the anchor so it can serve the resolver fetch.
            StandardHarness::propose(&mut server_handle, round, &anchor).await;

            // Subscribe while the anchor is unavailable on the victim.
            let subscription = mailbox.subscribe_by_digest(anchor.digest(), DigestFallback::Wait);

            // Record a pending floor anchor and start the resolver fetch.
            let finalization = StandardHarness::make_finalization(
                Proposal {
                    round,
                    parent: View::new(ANCHOR_HEIGHT - 1),
                    payload: anchor.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded the pending anchor.
            assert!(mailbox
                .get_block(Identifier::Height(Height::new(ANCHOR_HEIGHT)))
                .await
                .is_none());

            // Links come up only now, so the anchor can only arrive through
            // the resolver fetch started by `set_floor`.
            setup_network_links(&mut oracle, &peers, LINK).await;

            // The delivery installs the floor anchor and must wake subscribers.
            let received = select! {
                result = subscription => {
                    result.expect("subscription should receive the floor anchor")
                },
                _ = context.sleep(Duration::from_secs(10)) => {
                    panic!("subscriber not woken by installed anchor delivery");
                },
            };
            assert_eq!(received.digest(), anchor.digest());

            // The install resumed dispatch at the anchor.
            while !app.blocks().contains_key(&Height::new(ANCHOR_HEIGHT)) {
                context.sleep(Duration::from_millis(50)).await;
            }
            let (tip_height, tip_digest) = app.tip().unwrap();
            assert_eq!(tip_height, Height::new(ANCHOR_HEIGHT));
            assert_eq!(tip_digest, anchor.digest());
        })
    }

    #[test_traced("WARN")]
    fn test_standard_below_floor_anchor_delivery_wakes_subscriber() {
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
            let mut oracle = setup_network_with_participants(
                context.child("network"),
                NZUsize!(1),
                peers.clone(),
            )
            .await;

            let victim_setup = StandardHarness::setup_validator(
                context.child("victim"),
                &mut oracle,
                victim.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let server_setup = StandardHarness::setup_validator(
                context.child("server"),
                &mut oracle,
                server.clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;
            let app = victim_setup.application;
            let mut mailbox = victim_setup.mailbox;
            let mut server_handle: ValidatorHandle<StandardHarness> = ValidatorHandle {
                mailbox: server_setup.mailbox,
                extra: server_setup.extra,
            };

            // Advance the victim's processed floor to height 3 on the canonical chain.
            let mut parent = Sha256::hash(b"");
            let mut canonical = Vec::new();
            for i in 1..=3u64 {
                let block = make_raw_block(parent, Height::new(i), i);
                parent = block.digest();
                canonical.push(block);
            }
            for block in &canonical {
                let height = block.height();
                let round = Round::new(Epoch::zero(), View::new(height.get()));
                assert!(mailbox.verified(round, block.clone()).await);
                let finalization = StandardHarness::make_finalization(
                    Proposal {
                        round,
                        parent: View::new(height.get() - 1),
                        payload: block.digest(),
                    },
                    &schemes,
                    QUORUM,
                );
                StandardHarness::report_finalization(&mut mailbox, finalization).await;
            }
            while !app.blocks().contains_key(&Height::new(3)) {
                context.sleep(Duration::from_millis(50)).await;
            }

            // A conflicting finalization commits to a fork block at a height at
            // or below the processed floor (only reachable when a Byzantine
            // quorum double-finalizes).
            let fork = make_raw_block(canonical[0].digest(), Height::new(2), 999);
            let fork_round = Round::new(Epoch::zero(), View::new(4));

            // The server caches the fork block so it can serve the resolver fetch.
            StandardHarness::propose(&mut server_handle, fork_round, &fork).await;

            // Subscribe while the fork block is unavailable on the victim.
            let subscription = mailbox.subscribe_by_digest(fork.digest(), DigestFallback::Wait);

            // Record a pending floor anchor for the unavailable fork block and
            // start the resolver fetch.
            let fork_finalization = StandardHarness::make_finalization(
                Proposal {
                    round: fork_round,
                    parent: View::new(1),
                    payload: fork.digest(),
                },
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(fork_finalization);

            // Barrier: mailbox messages are FIFO, so this confirms `set_floor`
            // recorded the pending anchor.
            assert!(mailbox.get_block(&fork.digest()).await.is_none());

            // Links come up only now, so the fork block can only arrive through
            // the resolver fetch started by `set_floor`.
            setup_network_links(&mut oracle, &peers, LINK).await;

            // The delivery takes the at-or-below-floor branch, which must still
            // wake subscribers waiting on the block.
            let received = select! {
                result = subscription => {
                    result.expect("subscription should receive the floor anchor")
                },
                _ = context.sleep(Duration::from_secs(10)) => {
                    panic!("subscriber not woken by below-floor anchor delivery");
                },
            };
            assert_eq!(received.digest(), fork.digest());

            // The pending floor was consumed, so dispatch continues on the
            // canonical chain.
            let next = make_raw_block(canonical[2].digest(), Height::new(4), 4);
            let next_round = Round::new(Epoch::zero(), View::new(5));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal {
                    round: next_round,
                    parent: View::new(3),
                    payload: next.digest(),
                },
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            while !app.blocks().contains_key(&Height::new(4)) {
                context.sleep(Duration::from_millis(50)).await;
            }
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WrapperKind {
        Inline,
        Deferred,
    }

    fn wrapper_kinds() -> [WrapperKind; 2] {
        [WrapperKind::Inline, WrapperKind::Deferred]
    }

    type Runtime = deterministic::Context;
    type App = MockVerifyingApp<B, S>;
    type InlineWrapper = Inline<Runtime, S, App, B, FixedEpocher>;
    type DeferredWrapper = Deferred<Runtime, S, App, B, FixedEpocher>;

    enum Wrapper {
        Inline(InlineWrapper),
        Deferred(DeferredWrapper),
    }

    impl Wrapper {
        fn new(
            kind: WrapperKind,
            context: Runtime,
            app: App,
            marshal: Mailbox<S, Standard<B>>,
        ) -> Self {
            match kind {
                WrapperKind::Inline => Self::Inline(Inline::new(
                    context,
                    app,
                    marshal,
                    FixedEpocher::new(BLOCKS_PER_EPOCH),
                )),
                WrapperKind::Deferred => Self::Deferred(Deferred::new(
                    context,
                    app,
                    marshal,
                    FixedEpocher::new(BLOCKS_PER_EPOCH),
                )),
            }
        }

        fn kind(&self) -> WrapperKind {
            match self {
                Self::Inline(_) => WrapperKind::Inline,
                Self::Deferred(_) => WrapperKind::Deferred,
            }
        }

        async fn propose(&mut self, context: Ctx) -> oneshot::Receiver<D> {
            match self {
                Self::Inline(inline) => inline.propose(context).await,
                Self::Deferred(deferred) => deferred.propose(context).await,
            }
        }

        async fn verify(&mut self, context: Ctx, digest: D) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.verify(context, digest).await,
                Self::Deferred(deferred) => deferred.verify(context, digest).await,
            }
        }

        async fn certify(&mut self, round: Round, digest: D) -> oneshot::Receiver<bool> {
            match self {
                Self::Inline(inline) => inline.certify(round, digest).await,
                Self::Deferred(deferred) => deferred.certify(round, digest).await,
            }
        }
    }

    #[test_traced("WARN")]
    fn test_standard_certify_first_block_fetches_genesis_parent() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
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
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let block_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let block =
                    B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);
                let digest = block.digest();
                assert!(marshal.verified(round, block).await);

                context.sleep(Duration::from_millis(10)).await;

                let verify_result = wrapper
                    .verify(block_context, digest)
                    .await
                    .await
                    .expect("verify result missing");
                assert!(
                    verify_result,
                    "{kind:?}: height-1 block should verify with genesis as parent"
                );

                let certify_result = wrapper
                    .certify(round, digest)
                    .await
                    .await
                    .expect("certify result missing");
                assert!(
                    certify_result,
                    "{kind:?}: height-1 block should certify with genesis as parent"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_verify_missing_candidate_waits_without_fetching() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
                let buffer = buffer.expect("buffer was provided");
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let consensus_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let missing = Sha256::hash(b"missing candidate");
                let mut verify = wrapper.verify(consensus_context, missing).await;

                context.sleep(Duration::from_millis(50)).await;
                assert!(
                    buffer.subscription_count() > 0,
                    "{kind:?}: unavailable candidate verification must register a local wait"
                );
                assert!(
                    resolver.fetches().is_empty(),
                    "{kind:?}: unavailable candidate verification must not fetch from peers"
                );
                assert!(
                    resolver.targeted_is_empty(),
                    "{kind:?}: unavailable candidate verification must not issue targeted fetches"
                );
                assert!(
                    matches!(
                        verify.try_recv(),
                        Err(commonware_utils::channel::oneshot::error::TryRecvError::Empty)
                    ),
                    "{kind:?}: unavailable candidate verification must remain pending"
                );

                drop(verify);
                context.sleep(Duration::from_millis(10)).await;
                assert!(
                    resolver.fetches().is_empty(),
                    "{kind:?}: canceling a missing candidate wait must not fetch from peers"
                );
            });
        }
    }

    /// Crash-recovery shape: after an unclean shutdown, Simplex may recover a
    /// notarized payload while marshal has no local certification gate task and no
    /// durable block. If another participant has the block, certification should
    /// fetch it by notarized round and persist it instead of treating the missing
    /// local copy as a hard failure.
    #[test_traced("WARN")]
    fn test_standard_certify_missing_candidate_fetches_by_round() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("missing-certify-candidate-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
                let buffer = buffer.expect("buffer was provided");
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let block_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let block = B::new::<Sha256>(block_context, genesis.digest(), Height::new(1), 100);
                let digest = block.digest();
                let proposal = Proposal::new(round, View::zero(), digest);
                let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
                resolver.respond_to_next_fetch((notarization, block).encode());
                let certify = wrapper.certify(round, digest).await;

                let result = certify.await.expect("certify result missing");
                assert!(
                    result,
                    "{kind:?}: fetched notarized candidate should certify"
                );
                assert!(
                    resolver.wait_for_delivery_response().await,
                    "{kind:?}: notarized delivery should validate"
                );
                assert!(
                    resolver.fetches().iter().any(|fetch| matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Notarized { round: request_round },
                            handler::Annotation::Notarization { round: subscriber_round },
                        ) if *request_round == round && *subscriber_round == round
                    )),
                    "{kind:?}: certify should fetch notarized block by round"
                );

                assert!(
                    buffer.subscription_count() > 0,
                    "{kind:?}: unavailable candidate certification must register a local wait"
                );
                assert!(
                    resolver.targeted_is_empty(),
                    "{kind:?}: certification must not issue targeted fetches"
                );
            });
        }
    }

    /// Regression for certify's `hint_notarized` bump. When `verify` has an
    /// in-progress certification gate with the block still missing locally,
    /// `certify` must take that gate AND nudge a round-bound notarized fetch.
    /// Otherwise the gate's verify task would wait forever on a local-only
    /// subscription that nothing drives. Removing the `hint_notarized` call
    /// makes this test hang.
    #[test_traced("WARN")]
    fn test_standard_certify_bumps_notarized_fetch_for_pending_verify() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("certify-bumps-fetch-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let round = Round::new(Epoch::zero(), View::new(1));
                let block_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::zero(), genesis.digest()),
                };
                let block =
                    B::new::<Sha256>(block_context.clone(), genesis.digest(), Height::new(1), 100);
                let digest = block.digest();

                // `verify` registers a pending certification gate whose `Wait`
                // block subscription cannot pull from peers, so it stays parked
                // until something delivers the block locally.
                let verify_rx = wrapper.verify(block_context, digest).await;

                // Stage the notarized response so the bump's fetch can resolve.
                let proposal = Proposal::new(round, View::zero(), digest);
                let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
                resolver.respond_to_next_fetch((notarization, block).encode());

                // `certify` takes the in-progress gate and calls `hint_notarized`,
                // which issues a round-bound `Key::Notarized`. The recording
                // resolver delivers, and the marshal stores the block and wakes
                // verify's digest subscription, letting the pending verify task
                // resolve the gate that certify awaits.
                let certify_rx = wrapper.certify(round, digest).await;

                select! {
                    result = verify_rx => {
                        assert!(
                            result.expect("verify resolves"),
                            "{kind:?}: verify should accept the fetched block"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "{kind:?}: verify must resolve after certification bumps a notarized fetch"
                        );
                    },
                }
                select! {
                    result = certify_rx => {
                        assert!(
                            result.expect("certify resolves"),
                            "{kind:?}: certify should succeed via the shared gate"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("{kind:?}: certify must resolve via the bumped notarized fetch");
                    },
                }

                assert!(
                    resolver.fetches().iter().any(|fetch| matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Notarized { round: request_round },
                            handler::Annotation::Notarization { round: subscriber_round },
                        ) if *request_round == round && *subscriber_round == round
                    )),
                    "{kind:?}: certify must bump a notarized round fetch when verify is in progress"
                );
            });
        }
    }

    /// Regression: if consensus drops the optimistic verify receiver before the
    /// block arrives, the registered deferred task can close. Certification must
    /// not return that stale receiver as its final result; it should recover the
    /// notarized block and certify through the embedded-context path.
    #[test_traced("WARN")]
    fn test_standard_deferred_certify_falls_back_after_canceled_verify() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "deferred-certify-canceled-verify",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
            let mut wrapper = Wrapper::new(
                WrapperKind::Deferred,
                context.child("wrapper"),
                mock_app,
                marshal.clone(),
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

            let verify_rx = wrapper.verify(block_context, digest).await;
            drop(verify_rx);
            context.sleep(Duration::from_millis(10)).await;

            let proposal = Proposal::new(round, View::zero(), digest);
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);
            resolver.respond_to_next_fetch((notarization, block).encode());
            let certify_rx = wrapper.certify(round, digest).await;

            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify should recover after canceled optimistic verify"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should recover after canceled optimistic verify");
                },
            }
            assert!(
                resolver.wait_for_delivery_response().await,
                "notarized delivery should validate"
            );
            assert!(
                resolver.fetches().iter().any(|fetch| matches!(
                    (&fetch.key, &fetch.subscriber),
                    (
                        handler::Key::Notarized { round: request_round },
                        handler::Annotation::Notarization { round: subscriber_round },
                    ) if *request_round == round && *subscriber_round == round
                )),
                "certify must recover by fetching the notarized round"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_verify_height_lie_parent_fetch_is_round_bound() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let me = participants[0].clone();

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let (marshal, _buffer, resolver, _actor_handle) = start_standard_actor(
                    context.child("validator"),
                    &format!("height-lie-{kind:?}"),
                    ConstantProvider::new(schemes[0].clone()),
                    Application::<B>::manual_ack(),
                    Some(RecordingBuffer::default()),
                    Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                )
                .await;
                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();

                let child_round = Round::new(Epoch::zero(), View::new(2));
                let child_context = Ctx {
                    round: child_round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let child =
                    B::new::<Sha256>(child_context.clone(), parent_digest, Height::new(3), 200);
                let child_digest = child.digest();
                assert!(marshal.verified(child_round, child).await);

                let verify = wrapper.verify(child_context, child_digest).await;
                wait_until(
                    &context,
                    Duration::from_secs(5),
                    "round-bound parent fetch",
                    || {
                        resolver.fetches().iter().any(|fetch| {
                            matches!(
                                fetch.key,
                                handler::Key::Notarized { round } if round == parent_round
                            ) && matches!(
                                fetch.subscriber,
                                handler::Annotation::Notarization { round }
                                    if round == parent_round
                            )
                        })
                    },
                )
                .await;

                let fetches = resolver.fetches();
                assert!(
                    fetches.iter().all(|fetch| {
                        !matches!(fetch.key, handler::Key::Block(_))
                            && !matches!(
                                fetch.subscriber,
                                handler::Annotation::Certified { height }
                                    if height == Height::new(2)
                            )
                    }),
                    "{kind:?}: malicious child height must not drive parent fetches"
                );

                assert!(marshal.verified(parent_round, parent).await);
                let verify_result = verify.await.expect("verify result missing");
                if kind == WrapperKind::Inline {
                    assert!(
                        !verify_result,
                        "inline verify should reject non-contiguous ancestry"
                    );
                } else {
                    assert!(
                        verify_result,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper.certify(child_round, child_digest).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject non-contiguous ancestry"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_standard_verify_parent_fetch_invalid_first_retries() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
                let victim = participants[0].clone();
                let malicious = participants[1].clone();
                let honest = participants[2].clone();

                let mut oracle = setup_network_with_participants(
                    context.child("network"),
                    NZUsize!(2),
                    [victim.clone(), malicious.clone()],
                )
                .await;
                setup_network_links(
                    &mut oracle,
                    &[victim.clone(), malicious.clone()],
                    LINK,
                )
                .await;

                let victim_setup = StandardHarness::setup_validator(
                    context.child("victim").with_attribute("index", 0),
                    &mut oracle,
                    victim.clone(),
                    ConstantProvider::new(schemes[0].clone()),
                )
                .await;
                let victim_mailbox = victim_setup.mailbox;

                let honest_setup = StandardHarness::setup_validator(
                    context.child("honest").with_attribute("index", 2),
                    &mut oracle,
                    honest.clone(),
                    ConstantProvider::new(schemes[2].clone()),
                )
                .await;
                let mut honest_mailbox = honest_setup.mailbox;

                let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: victim.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();

                let parent_proposal = Proposal::new(parent_round, View::zero(), parent_digest);
                let parent_notarization =
                    StandardHarness::make_notarization(parent_proposal, &schemes, QUORUM);
                assert!(honest_mailbox.verified(parent_round, parent.clone()).await);
                StandardHarness::report_notarization(&mut honest_mailbox, parent_notarization)
                    .await;
                assert!(honest_mailbox.get_block(&parent_digest).await.is_some());

                let malicious_backfill = oracle
                    .control(malicious.clone())
                    .register(1, Quota::per_second(NonZeroU32::MAX))
                    .await
                    .unwrap();
                let (malicious_engine, _malicious_mailbox) = commonware_resolver::p2p::Engine::new(
                    context.child("malicious_resolver"),
                    commonware_resolver::p2p::Config {
                        peer_provider: oracle.manager(),
                        blocker: oracle.control(malicious.clone()),
                        consumer: NoopConsumer,
                        producer: StaticProducer::new(
                            handler::Key::Notarized {
                                round: parent_round,
                            },
                            Bytes::from_static(b"not a valid notarization"),
                        ),
                        mailbox_size: NZUsize!(100),
                        me: Some(malicious.clone()),
                        initial: Duration::from_secs(1),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(100),
                        priority_requests: false,
                        priority_responses: false,
                    },
                );
                malicious_engine.start(malicious_backfill);

                let child_round = Round::new(Epoch::zero(), View::new(2));
                let child_context = Ctx {
                    round: child_round,
                    leader: victim.clone(),
                    parent: (View::new(1), parent_digest),
                };
                let child =
                    B::new::<Sha256>(child_context.clone(), parent_digest, Height::new(2), 200);
                let child_digest = child.digest();
                assert!(victim_mailbox.verified(child_round, child).await);

                let mock_app: MockVerifyingApp<B, S> = MockVerifyingApp::new();
                let mut wrapper = Wrapper::new(
                    kind,
                    context.child("wrapper"),
                    mock_app,
                    victim_mailbox.clone(),
                );
                let verify = wrapper.verify(child_context, child_digest).await;
                let verify_or_certify = if kind == WrapperKind::Deferred {
                    let optimistic = verify.await.expect("verify result missing");
                    assert!(optimistic, "deferred verify should optimistically succeed");
                    wrapper.certify(child_round, child_digest).await
                } else {
                    verify
                };

                let start = context.current();
                loop {
                    let blocked = oracle.blocked().await.unwrap();
                    if blocked
                        .iter()
                        .any(|(blocker, blocked)| blocker == &victim && blocked == &malicious)
                    {
                        break;
                    }
                    if context.current().duration_since(start).unwrap_or_default()
                        > Duration::from_secs(5)
                    {
                        panic!("{kind:?}: malicious peer was not blocked");
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }

                oracle
                    .add_link(victim.clone(), honest.clone(), LINK)
                    .await
                    .unwrap();
                oracle
                    .add_link(honest.clone(), victim.clone(), LINK)
                    .await
                    .unwrap();
                let mut manager = oracle.manager();
                manager.track(1, Set::from_iter_dedup([honest.clone()]));

                select! {
                    result = verify_or_certify => {
                        assert!(
                            result.expect("verification result missing"),
                            "{kind:?}: verification should retry against the honest peer and complete"
                        );
                    },
                    _ = context.sleep(Duration::from_secs(10)) => {
                        panic!("{kind:?}: verification did not complete after honest retry");
                    },
                }

                let blocked = oracle.blocked().await.unwrap();
                assert!(
                    blocked
                        .iter()
                        .any(|(blocker, blocked)| blocker == &victim && blocked == &malicious),
                    "{kind:?}: malicious peer should remain blocked"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_propose_paths() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
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
                let mut wrapper = Wrapper::new(
                    kind,
                    context.child("wrapper_under_test"),
                    mock_app,
                    marshal.clone(),
                );

                // Non-boundary propose should drop the response because mock app cannot build.
                let non_boundary_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(1)),
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let proposal_rx = wrapper.propose(non_boundary_context).await;
                assert!(
                    proposal_rx.await.is_err(),
                    "{kind:?}: proposal should be dropped when application returns no block"
                );
                assert!(
                    context
                        .encode()
                        .contains("wrapper_under_test_build_duration_count 0"),
                    "{kind:?}: failed application builds should not be timed"
                );

                // Boundary propose should re-propose the parent block even if the app cannot build.
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
                    marshal
                        .clone()
                        .verified(boundary_round, boundary_block.clone())
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let reproposal_round =
                    Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
                let reproposal_context = Ctx {
                    round: reproposal_round,
                    leader: me,
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                let reproposal_rx = wrapper.propose(reproposal_context).await;
                assert_eq!(
                    reproposal_rx.await.expect("reproposal result missing"),
                    boundary_digest,
                    "{kind:?}: epoch-boundary proposal should re-propose parent digest"
                );

                // The re-proposal registers a certification gate whose durability
                // certify awaits before the finalize vote.
                let certify_rx = wrapper.certify(reproposal_round, boundary_digest).await;
                assert!(
                    certify_rx.await.expect("certify result missing"),
                    "{kind:?}: certify must succeed for the re-proposed boundary block"
                );
                assert!(
                    marshal.get_verified(reproposal_round).await.is_some(),
                    "{kind:?}: re-proposed boundary block must be stored at the re-proposal round"
                );
            });
        }
    }

    #[test_traced("WARN")]
    fn test_verify_reproposal_validation() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
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
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

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
                    marshal
                        .clone()
                        .verified(boundary_round, boundary_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                // Valid re-proposal: boundary block in the same epoch.
                let valid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(boundary_height.get() + 1)),
                    leader: me.clone(),
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                assert!(
                    wrapper
                        .verify(valid_reproposal_context, boundary_digest)
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: boundary re-proposal should be accepted"
                );

                // Invalid re-proposal: non-boundary block.
                let non_boundary_height = Height::new(10);
                let non_boundary_round =
                    Round::new(Epoch::zero(), View::new(non_boundary_height.get()));
                let non_boundary_block = B::new::<Sha256>(
                    Ctx {
                        round: non_boundary_round,
                        leader: default_leader(),
                        parent: (View::zero(), genesis.digest()),
                    },
                    genesis.digest(),
                    non_boundary_height,
                    1000,
                );
                let non_boundary_digest = non_boundary_block.digest();

                assert!(
                    marshal
                        .clone()
                        .verified(non_boundary_round, non_boundary_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                // Attempt to re-propose a non-boundary block.
                let invalid_reproposal_context = Ctx {
                    round: Round::new(Epoch::zero(), View::new(15)),
                    leader: me.clone(),
                    parent: (View::new(non_boundary_height.get()), non_boundary_digest),
                };
                assert!(
                    !wrapper
                        .verify(invalid_reproposal_context, non_boundary_digest)
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: non-boundary re-proposal should be rejected"
                );

                // Invalid re-proposal: cross-epoch context.
                let cross_epoch_context = Ctx {
                    round: Round::new(Epoch::new(1), View::new(boundary_height.get() + 1)),
                    leader: me,
                    parent: (View::new(boundary_height.get()), boundary_digest),
                };
                assert!(
                    !wrapper
                        .verify(cross_epoch_context, boundary_digest)
                        .await
                        .await
                        .expect("verify result missing"),
                    "{kind:?}: cross-epoch re-proposal should be rejected"
                );

                if wrapper.kind() == WrapperKind::Deferred {
                    // Deferred-only crash-recovery path: certify without prior verify.
                    let certify_only_round = Round::new(Epoch::zero(), View::new(21));
                    let certify_result = wrapper
                        .certify(certify_only_round, boundary_digest)
                        .await
                        .await;
                    assert!(
                        certify_result.expect("certify result missing"),
                        "deferred certify-only path for re-proposal should succeed"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_verify_rejects_invalid_ancestry() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } = bls12381_threshold_vrf::fixture::<V, _>(
                    &mut context,
                    NAMESPACE,
                    NUM_VALIDATORS,
                );
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
                let mut wrapper =
                    Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                // Test case 1: non-contiguous height.
                // Malformed block: parent is genesis but height skips from 0 to 2.
                let malformed_round = Round::new(Epoch::zero(), View::new(2));
                let malformed_context = Ctx {
                    round: malformed_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let malformed_block = B::new::<Sha256>(
                    malformed_context.clone(),
                    genesis.digest(),
                    Height::new(2),
                    200,
                );
                let malformed_digest = malformed_block.digest();

                assert!(
                    marshal
                        .clone()
                        .verified(malformed_round, malformed_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let malformed_verify = wrapper
                    .verify(malformed_context.clone(), malformed_digest)
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    // Inline verifies fully in `verify`.
                    assert!(
                        !malformed_verify,
                        "inline verify should reject non-contiguous ancestry"
                    );
                } else {
                    // Deferred verify is optimistic; final verdict is observed in `certify`.
                    assert!(
                        malformed_verify,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper.certify(malformed_round, malformed_digest).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject non-contiguous ancestry"
                    );
                }

                // Test case 2: mismatched parent commitment with contiguous heights.
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent =
                    B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 300);
                let parent_digest = parent.digest();
                assert!(marshal.verified(parent_round, parent).await);

                let mismatch_round = Round::new(Epoch::zero(), View::new(3));
                let mismatched_context = Ctx {
                    round: mismatch_round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let mismatched_block = B::new::<Sha256>(
                    mismatched_context.clone(),
                    genesis.digest(),
                    Height::new(2),
                    400,
                );
                let mismatched_digest = mismatched_block.digest();

                assert!(
                    marshal
                        .clone()
                        .verified(mismatch_round, mismatched_block)
                        .await
                );

                context.sleep(Duration::from_millis(10)).await;

                let mismatch_verify = wrapper
                    .verify(mismatched_context, mismatched_digest)
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    // Inline returns the full verification result directly.
                    assert!(
                        !mismatch_verify,
                        "inline verify should reject mismatched parent digest"
                    );
                } else {
                    // Deferred reports optimistic success and relies on `certify`.
                    assert!(
                        mismatch_verify,
                        "deferred verify should optimistically pass pre-checks"
                    );
                    let certify = wrapper.certify(mismatch_round, mismatched_digest).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should reject mismatched parent digest"
                    );
                }
            });
        }
    }

    #[test_traced("WARN")]
    fn test_application_verify_failure() {
        for kind in wrapper_kinds() {
            let runner = deterministic::Runner::timed(Duration::from_secs(30));
            runner.start(|mut context| async move {
                let Fixture {
                    participants,
                    schemes,
                    ..
                } =
                    bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
                let mut oracle = setup_network_with_participants(context.child("network"),
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
                let mock_app: MockVerifyingApp<B, S> =
                    MockVerifyingApp::with_verify_result(false);
                let mut wrapper = Wrapper::new(kind, context.child("wrapper"), mock_app, marshal.clone());

                // 1) Set up a valid parent so structural checks can pass.
                let parent_round = Round::new(Epoch::zero(), View::new(1));
                let parent_context = Ctx {
                    round: parent_round,
                    leader: me.clone(),
                    parent: (View::zero(), genesis.digest()),
                };
                let parent = B::new::<Sha256>(parent_context, genesis.digest(), Height::new(1), 100);
                let parent_digest = parent.digest();
                assert!(marshal.verified(parent_round, parent).await);

                // 2) Publish a valid child; only application-level verification should fail.
                let round = Round::new(Epoch::zero(), View::new(2));
                let verify_context = Ctx {
                    round,
                    leader: me,
                    parent: (View::new(1), parent_digest),
                };
                let block = B::new::<Sha256>(verify_context.clone(), parent_digest, Height::new(2), 200);
                let digest = block.digest();
                assert!(marshal.verified(round, block).await);

                context.sleep(Duration::from_millis(10)).await;

                // 3) Compare wrapper behavior:
                //    - Inline fails in `verify`.
                //    - Deferred returns optimistic success and fails in `certify`.
                let verify_result = wrapper
                    .verify(verify_context, digest)
                    .await
                    .await
                    .expect("verify result missing");
                if kind == WrapperKind::Inline {
                    assert!(
                        !verify_result,
                        "inline verify should return application-level failure"
                    );
                } else {
                    assert!(
                        verify_result,
                        "deferred verify should pass pre-checks and schedule deferred verification"
                    );
                    let certify = wrapper.certify(round, digest).await;
                    assert!(
                        !certify.await.expect("certify result missing"),
                        "deferred certify should propagate deferred application verification failure"
                    );
                }
            });
        }
    }

    // The sync failure surfaces when `verified` awaits the durable-sync handle, which
    // applies the fatal policy: panic rather than resolve a recoverable verdict.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync verified")]
    fn test_mailbox_verified_sync_failure_panics() {
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

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let marshal = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            // Sync failures are fatal to the local storage state. They must not be
            // converted into a `false` certification/verification verdict.
            context.storage_fault_config().write().sync_rate = Some(1.0);

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            // `verified` awaits the durable-sync handle internally; a storage sync
            // failure must panic here (fatal), never resolve to a recoverable verdict.
            let _ = marshal.verified(round, block).await;
        });
    }

    // Twin of `test_mailbox_verified_sync_failure_panics` for the certify barrier:
    // `certified` awaits the composed block + notarization sync handle.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync certified")]
    fn test_mailbox_certified_sync_failure_panics() {
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

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let marshal = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            context.storage_fault_config().write().sync_rate = Some(1.0);

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let _ = marshal.certified(round, block).await;
        });
    }

    // A notarization's durable sync is observed by the actor's sync pool rather than
    // a consensus caller. The fatal policy must still apply: a sync failure panics
    // the actor instead of being silently swallowed.
    #[test_traced("WARN")]
    #[should_panic(expected = "failed to sync notarization")]
    fn test_notarization_sync_failure_panics() {
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

            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me,
                ConstantProvider::new(schemes[0].clone()),
                NZUsize!(1),
                application.clone(),
            )
            .await;
            let mut mailbox = setup.mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());
            context.sleep(Duration::from_millis(10)).await;

            context.storage_fault_config().write().sync_rate = Some(1.0);

            let genesis = make_raw_block(Sha256::hash(b""), Height::zero(), 0);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let notarization = StandardHarness::make_notarization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_notarization(&mut mailbox, notarization).await;

            // The failure surfaces asynchronously when the pool observes the sync.
            context.sleep(Duration::from_secs(5)).await;
        });
    }

    // A certified block that the verified archive already holds is not re-written to
    // the notarized archive; the verified archive's sync handle vouches for it. The
    // block must still be recoverable after an unclean restart.
    #[test_traced("WARN")]
    fn test_certified_covered_by_verified_write_recoverable_after_restart() {
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
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = B::new::<Sha256>(
                Ctx {
                    round,
                    leader: default_leader(),
                    parent: (View::zero(), genesis.digest()),
                },
                genesis.digest(),
                Height::new(1),
                100,
            );
            let digest = block.digest();

            // The verified write records the round's digest, so the subsequent
            // certified delivery for the same block skips the notarized-archive
            // copy and leans on the verified archive's durability.
            assert!(marshal.verified(round, block.clone()).await);
            assert!(marshal.certified(round, block).await);

            actor_handle.abort();
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
                marshal2.get_block(&digest).await.is_some(),
                "certified block covered by a verified write must survive restart"
            );
        });
    }

    /// Recorded `send` call on the [`RecordingBuffer`].
    type BufferSend = (Round, Arc<B>, Recipients<PublicKey>);

    /// A buffer that records each `send` invocation, keeps subscriptions open,
    /// and optionally serves locally inserted blocks.
    #[derive(Clone, Default)]
    struct RecordingBuffer {
        blocks: Arc<Mutex<Vec<B>>>,
        digest_subscriptions: Arc<Mutex<Vec<oneshot::Sender<Arc<B>>>>>,
        commitment_subscriptions: Arc<Mutex<Vec<oneshot::Sender<Arc<B>>>>>,
        sends: Arc<Mutex<Vec<BufferSend>>>,
    }

    impl RecordingBuffer {
        fn insert(&self, block: B) {
            self.blocks.lock().push(block);
        }

        fn sends(&self) -> Vec<BufferSend> {
            self.sends.lock().clone()
        }

        fn subscription_count(&self) -> usize {
            self.digest_subscriptions.lock().len() + self.commitment_subscriptions.lock().len()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscriptions.lock().len()
        }
    }

    impl crate::marshal::core::Buffer<Standard<B>> for RecordingBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, digest: D) -> Option<Arc<B>> {
            self.blocks
                .lock()
                .iter()
                .find(|block| block.digest() == digest)
                .cloned()
                .map(Arc::new)
        }

        async fn find_by_commitment(&self, commitment: D) -> Option<Arc<B>> {
            self.blocks
                .lock()
                .iter()
                .find(|block| block.digest() == commitment)
                .cloned()
                .map(Arc::new)
        }

        fn subscribe_by_digest(&self, _digest: D) -> Option<oneshot::Receiver<Arc<B>>> {
            let (sender, receiver) = oneshot::channel();
            self.digest_subscriptions.lock().push(sender);
            Some(receiver)
        }

        fn subscribe_by_commitment(&self, _commitment: D) -> Option<oneshot::Receiver<Arc<B>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscriptions.lock().push(sender);
            Some(receiver)
        }

        fn finalized(&self, _commitment: D) {}

        fn send(&self, round: Round, block: Arc<B>, recipients: Recipients<PublicKey>) {
            self.sends.lock().push((round, block, recipients));
        }
    }

    /// Recorded `fetch_targeted` call on the [`RecordingResolver`].
    type TargetedFetch = (handler::Key<D>, NonEmptyVec<PublicKey>);

    /// Recorded `fetch` call on the [`RecordingResolver`].
    type FetchRecord = Fetch<handler::Key<D>, handler::Annotation>;

    /// A resolver that records each fetch invocation; other methods are no-ops.
    ///
    /// `_keepalive` optionally retains a resolver-message sender so the
    /// actor's corresponding receiver stays alive when nothing else owns it.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        fetches: Arc<Mutex<Vec<FetchRecord>>>,
        active_fetches: Arc<Mutex<Vec<FetchRecord>>>,
        targeted: Arc<Mutex<Vec<TargetedFetch>>>,
        retains: Arc<Mutex<usize>>,
        auto_delivery: Arc<Mutex<Option<Bytes>>>,
        delivery_responses: Arc<Mutex<Vec<oneshot::Receiver<bool>>>>,
        sender: Option<mailbox::Sender<handler::Message<D>>>,
    }

    impl RecordingResolver {
        fn holding(metrics: impl Metrics) -> (handler::Receiver<D>, Self) {
            let (sender, receiver) = mailbox::new(metrics, NZUsize!(100));
            (
                handler::Receiver::new(receiver),
                Self {
                    fetches: Arc::new(Mutex::new(Vec::new())),
                    active_fetches: Arc::new(Mutex::new(Vec::new())),
                    targeted: Arc::new(Mutex::new(Vec::new())),
                    retains: Arc::new(Mutex::new(0)),
                    auto_delivery: Arc::new(Mutex::new(None)),
                    delivery_responses: Arc::new(Mutex::new(Vec::new())),
                    sender: Some(sender),
                },
            )
        }

        fn record_fetch(&self, fetch: FetchRecord) {
            self.fetches.lock().push(fetch.clone());
            self.active_fetches.lock().push(fetch.clone());
            let Some(value) = self.auto_delivery.lock().take() else {
                return;
            };
            let Some(sender) = &self.sender else {
                return;
            };
            let (response, response_rx) = oneshot::channel();
            self.delivery_responses.lock().push(response_rx);
            let _ = sender.enqueue(handler::Message::Deliver {
                delivery: Delivery {
                    key: fetch.key,
                    subscribers: NonEmptyVec::new((fetch.subscriber, tracing::Span::none())),
                },
                value,
                response,
            });
        }

        fn respond_to_next_fetch(&self, value: Bytes) {
            let replaced = self.auto_delivery.lock().replace(value);
            assert!(
                replaced.is_none(),
                "recording resolver already has an automatic delivery"
            );
        }

        async fn wait_for_delivery_response(&self) -> bool {
            let response = self
                .delivery_responses
                .lock()
                .pop()
                .expect("delivery response missing");
            response.await.expect("delivery response sender dropped")
        }

        fn fetches(&self) -> Vec<FetchRecord> {
            self.fetches.lock().clone()
        }

        fn active_fetches(&self) -> Vec<FetchRecord> {
            self.active_fetches.lock().clone()
        }

        fn targeted(&self) -> Vec<TargetedFetch> {
            self.targeted.lock().clone()
        }

        fn targeted_is_empty(&self) -> bool {
            self.targeted.lock().is_empty()
        }

        fn retain_count(&self) -> usize {
            *self.retains.lock()
        }

        fn enqueue(&self, message: handler::Message<D>) -> Feedback {
            self.sender
                .as_ref()
                .expect("recording resolver sender missing")
                .enqueue(message)
        }
    }

    impl Resolver for RecordingResolver {
        type Key = handler::Key<D>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.record_fetch(fetch.into());
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            for fetch in fetches {
                self.record_fetch(fetch.into());
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            self.active_fetches
                .lock()
                .retain(|fetch| predicate(&fetch.key, &fetch.subscriber));
            *self.retains.lock() += 1;
            Feedback::Ok
        }
    }

    impl TargetedResolver for RecordingResolver {
        type PublicKey = PublicKey;

        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            self.targeted.lock().push((fetch.into().key, targets));
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let mut targeted = self.targeted.lock();
            for (fetch, targets) in fetches {
                targeted.push((fetch.into().key, targets));
            }
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopConsumer;

    impl Consumer for NoopConsumer {
        type Key = handler::Key<D>;
        type Value = Bytes;
        type Subscriber = handler::Annotation;

        fn deliver(
            &mut self,
            _delivery: Delivery<Self::Key, Self::Subscriber>,
            _value: Self::Value,
        ) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            sender.send_lossy(false);
            receiver
        }
    }

    #[derive(Clone)]
    struct StaticProducer {
        key: handler::Key<D>,
        value: Bytes,
    }

    impl StaticProducer {
        fn new(key: handler::Key<D>, value: Bytes) -> Self {
            Self { key, value }
        }
    }

    impl commonware_resolver::p2p::Producer for StaticProducer {
        type Key = handler::Key<D>;

        fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
            let (sender, receiver) = oneshot::channel();
            if key == self.key {
                sender.send_lossy(self.value.clone());
            }
            receiver
        }
    }

    /// Poll `cond` on a 10ms tick until it returns true, panicking on timeout.
    async fn wait_until<F: FnMut() -> bool>(
        context: &deterministic::Context,
        deadline: Duration,
        label: &str,
        mut cond: F,
    ) {
        let start = context.current();
        while !cond() {
            if context.current().duration_since(start).unwrap_or_default() > deadline {
                panic!("{label} did not hold within {deadline:?}");
            }
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// A reporter that signals when application delivery starts and holds the
    /// block acknowledgement open.
    #[derive(Clone)]
    struct HoldingBlockReporter {
        started: Arc<Mutex<Option<oneshot::Sender<Height>>>>,
        pending: Arc<Mutex<Vec<Exact>>>,
        min_signal_height: Height,
    }

    impl HoldingBlockReporter {
        fn new() -> (Self, oneshot::Receiver<Height>) {
            Self::new_from(Height::zero())
        }

        fn new_after(height: Height) -> (Self, oneshot::Receiver<Height>) {
            Self::new_from(height.next())
        }

        fn new_from(min_signal_height: Height) -> (Self, oneshot::Receiver<Height>) {
            let (started_tx, started_rx) = oneshot::channel();
            (
                Self {
                    started: Arc::new(Mutex::new(Some(started_tx))),
                    pending: Arc::new(Mutex::new(Vec::new())),
                    min_signal_height,
                },
                started_rx,
            )
        }
    }

    impl Reporter for HoldingBlockReporter {
        type Activity = Update<B>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            match activity {
                Update::Block(block, ack) => {
                    if block.height() < self.min_signal_height {
                        ack.acknowledge();
                        return Feedback::Ok;
                    }
                    if let Some(started) = self.started.lock().take() {
                        started.send_lossy(block.height());
                    }
                    self.pending.lock().push(ack);
                }
                Update::Tip(_, _, _) => {}
            }
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct ApplicationReporter {
        updates: mpsc::UnboundedSender<Update<B>>,
    }

    impl Reporter for ApplicationReporter {
        type Activity = Update<B>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if self.updates.send(activity).is_ok() {
                Feedback::Ok
            } else {
                Feedback::Closed
            }
        }
    }

    async fn start_standard_actor<R, Buf, P>(
        context: deterministic::Context,
        partition_prefix: &str,
        provider: P,
        application: R,
        buffer: Option<Buf>,
        start: Start<S, D, B>,
    ) -> (
        Mailbox<S, Standard<B>>,
        Option<Buf>,
        RecordingResolver,
        commonware_runtime::Handle<()>,
    )
    where
        R: Reporter<Activity = Update<B>>,
        P: Provider<Scope = Epoch, Scheme = S>,
        Buf: crate::marshal::core::Buffer<Standard<B>, PublicKey = PublicKey> + Clone,
    {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start,
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
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        };
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalizations-by-height-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-key"
                ),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{partition_prefix}-finalizations-by-height-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalizations-by-height-ordinal"),
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
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{partition_prefix}-finalized_blocks-metadata"),
                freezer_table_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-table"
                ),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 10,
                freezer_table_resize_chunk_size: 10,
                freezer_key_partition: format!("{partition_prefix}-finalized_blocks-freezer-key"),
                freezer_key_page_cache: config.page_cache.clone(),
                freezer_value_partition: format!(
                    "{partition_prefix}-finalized_blocks-freezer-value"
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{partition_prefix}-finalized_blocks-ordinal"),
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
        let (actor, mailbox, _) = Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let (resolver_rx, resolver) = RecordingResolver::holding(context.child("mailbox"));
        let actor_handle = if let Some(buffer) = buffer.clone() {
            actor.start(application, buffer, (resolver_rx, resolver.clone()))
        } else {
            actor.start_unbuffered(application, (resolver_rx, resolver.clone()))
        };
        (mailbox, buffer, resolver, actor_handle)
    }

    #[test_traced("WARN")]
    fn test_standard_application_shutdown_redelivers_pending_ack_after_restart() {
        const PARTITION_PREFIX: &str = "application-shutdown-with-pending-ack";
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        let first_run = |mut context: deterministic::Context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);

            // Model an application that handles genesis normally, then owns the first
            // non-genesis acknowledgement while its work remains in flight.
            let (updates, mut application_mailbox) = mpsc::unbounded_channel::<Update<B>>();
            let (delivered, delivery) = oneshot::channel();
            let application_handle = context.child("application").spawn(move |_| async move {
                let mut delivered = Some(delivered);
                while let Some(update) = application_mailbox.recv().await {
                    let Update::Block(block, acknowledgement) = update else {
                        continue;
                    };
                    if block.height() == Height::zero() {
                        acknowledgement.acknowledge();
                        continue;
                    }

                    delivered
                        .take()
                        .expect("normal block should only be delivered once")
                        .send_lossy(block.height());

                    // Keep the acknowledgement in the suspended future so aborting this task
                    // exercises application-owned cancellation during shutdown.
                    std::future::pending::<()>().await;
                    acknowledgement.acknowledge();
                }
            });

            // Retain marshal's mailbox, buffer, and resolver until the exit assertion so no other
            // input closing can account for the actor's exit.
            let (mut mailbox, _buffer, _resolver, marshal_handle) = start_standard_actor(
                context.child("validator"),
                PARTITION_PREFIX,
                provider.clone(),
                ApplicationReporter { updates },
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone()),
            )
            .await;

            // Deliver a normal finalized block and wait until the application owns its
            // acknowledgement before beginning shutdown.
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block_digest = block.digest();
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(round, block).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            assert_eq!(
                delivery.await.expect("normal block should be delivered"),
                Height::new(1)
            );

            // Drop the application first; the pending acknowledgement must stop marshal cleanly.
            application_handle.abort();
            let _ = application_handle.await;
            marshal_handle
                .await
                .expect("application shutdown should stop marshal cleanly");

            (provider, genesis, block_digest)
        };

        // Shut down with a pending acknowledgement, then recover the runtime.
        let ((provider, genesis, block_digest), checkpoint) = runner.start_and_recover(first_run);
        deterministic::Runner::from(checkpoint).start(move |context| async move {
            // The canceled acknowledgement must leave the processed floor behind the block so the
            // recovered application receives the same finalized block again.
            let restart_application = Application::<B>::manual_ack();
            let (_mailbox, _buffer, _resolver, _marshal_handle) = start_standard_actor(
                context.child("validator").with_attribute("restart", 0),
                PARTITION_PREFIX,
                provider,
                restart_application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis),
            )
            .await;
            select! {
                height = restart_application.acknowledged() => {
                    assert_eq!(height, Height::new(1));
                    assert_eq!(
                        restart_application
                            .blocks()
                            .get(&height)
                            .expect("redelivered block must be recorded")
                            .digest(),
                        block_digest,
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("unacknowledged block was not redelivered after restart");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_actor_starts_without_buffer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-no-buffer",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                None::<RecordingBuffer>,
                Start::Genesis(genesis.clone()),
            )
            .await;

            let stored_genesis = mailbox
                .get_block(Identifier::Height(Height::zero()))
                .await
                .expect("genesis should be available without a buffer");
            assert_eq!(stored_genesis.digest(), genesis.digest());

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            let digest = block.digest();
            assert!(mailbox.verified(round, block).await);
            mailbox.forward(
                round,
                digest,
                Recipients::Some(vec![participants[1].clone()]),
            );
            let verified = mailbox
                .get_verified(round)
                .await
                .expect("verified block should remain available without a buffer");
            assert_eq!(verified.digest(), digest);
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "floor finalization must verify")]
    fn test_standard_start_floor_rejects_invalid_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let Fixture {
                schemes: wrong_schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, _started_rx) = HoldingBlockReporter::new();
            let (_mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-invalid",
                ConstantProvider::new(wrong_schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;
            context.sleep(Duration::from_secs(1)).await;
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "floor finalization must verify")]
    fn test_standard_set_floor_rejects_invalid_finalization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let Fixture {
                schemes: wrong_schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-invalid",
                ConstantProvider::new(wrong_schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            mailbox.set_floor(floor_finalization);
            context.sleep(Duration::from_secs(1)).await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_fetches_async_and_serves_requests() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-async",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let served = make_raw_block(Sha256::hash(b"served-parent"), Height::new(1), 100);
            let served_round = Round::new(Epoch::zero(), View::new(1));
            assert!(mailbox.verified(served_round, served.clone()).await);
            let (response, response_rx) = oneshot::channel();
            resolver.enqueue(handler::Message::Produce {
                key: handler::Key::Block(StandardHarness::commitment(&served)),
                response,
            });
            assert_eq!(response_rx.await.unwrap(), served.encode());

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            let mut mailbox_for_report = mailbox.clone();
            StandardHarness::report_finalization(&mut mailbox_for_report, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            assert!(mailbox.verified(floor_round, floor_block).await);
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_applies_local_anchor_without_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block =
                make_raw_block(Sha256::hash(b"local-floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let buffer = RecordingBuffer::default();
            buffer.insert(floor_block.clone());

            let (application, started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "start-floor-local-anchor",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(buffer),
                Start::Floor(floor_finalization),
            )
            .await;
            let mut mailbox = mailbox;

            wait_until(
                &context,
                Duration::from_secs(5),
                "local floor anchor application",
                || resolver.retain_count() >= 2,
            )
            .await;
            assert!(
                resolver.fetches().is_empty(),
                "local startup floor anchor must not be fetched"
            );
            assert_eq!(
                mailbox.get_block(Height::new(5)).await.unwrap().digest(),
                floor_block.digest()
            );

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_start_floor_height_one_without_metadata_delivers_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "start-floor-height-one-without-metadata";

            let floor_round = Round::new(Epoch::zero(), View::new(1));
            let floor_block = make_raw_block(Sha256::hash(b"genesis-parent"), Height::new(1), 100);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::zero(),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let blocks = [floor_block.clone()];
            let finalizations = [(Height::new(1), floor_finalization.clone())];
            seed_inconsistent_restart_state(
                context.child("seed_restart_state"),
                partition_prefix,
                &blocks,
                &finalizations,
            )
            .await;

            let (application, started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            select! {
                height = started_rx => {
                    assert_eq!(
                        height.expect("floor anchor delivery signal missing"),
                        Height::new(1),
                        "height-one startup floor must be delivered without prior metadata"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("height-one startup floor was not delivered");
                },
            }
            assert!(
                resolver.fetches().is_empty(),
                "stored startup floor anchor must not be fetched"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_holds_dispatch_until_anchor_arrives() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-holds-dispatch",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            let floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&floor_block)
                    )
                })
                .expect("floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: floor_fetch.key,
                        subscribers: NonEmptyVec::new((
                            floor_fetch.subscriber,
                            tracing::Span::none()
                        )),
                    },
                    value: floor_block.encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "floor block delivery should validate"
            );

            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_floor_jump_ignores_stale_application_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "floor-jump-ignores-stale-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // The anchor is not local yet, so SetFloor must install a pending
            // floor before the old height 1 ack can be released.
            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block.clone()).await);
            assert_eq!(
                mailbox
                    .get_block(Height::new(5))
                    .await
                    .expect("floor block missing")
                    .digest(),
                floor_block.digest()
            );

            // Release the stale ack after the remote floor has been applied.
            // It must not lower the processed floor back below height 5.
            let fetches_after_floor = resolver.fetches().len();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            let _subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"below-floor-after-stale-ack"),
                CommitmentFallback::FetchByCommitment {
                    height: Height::new(2),
                },
            );
            let _ = mailbox.get_block(Height::new(5)).await;
            assert_eq!(
                resolver.fetches().len(),
                fetches_after_floor,
                "stale pre-floor ack must not lower the processed height floor"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_jump_ignores_stale_application_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let buffer = RecordingBuffer::default();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "local-floor-jump-ignores-stale-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(buffer.clone()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block =
                make_raw_block(Sha256::hash(b"local-floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // The anchor is already local, so this covers the immediate
            // install path where no pending-anchor fetch is started.
            buffer.insert(floor_block.clone());
            mailbox.set_floor(floor_finalization);
            assert_eq!(
                mailbox
                    .get_block(Height::new(5))
                    .await
                    .expect("floor block missing")
                    .digest(),
                floor_block.digest()
            );
            assert!(
                resolver.fetches().is_empty(),
                "local floor anchor must not be fetched"
            );

            // Release the old ack after the local floor is installed. It must
            // not make lower-height commitment subscriptions eligible again.
            let fetches_after_floor = resolver.fetches().len();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            let _subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"below-local-floor-after-stale-ack"),
                CommitmentFallback::FetchByCommitment {
                    height: Height::new(2),
                },
            );
            let _ = mailbox.get_block(Height::new(5)).await;
            assert_eq!(
                resolver.fetches().len(),
                fetches_after_floor,
                "stale pre-floor ack must not lower a locally installed floor"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_repairs_gap_after_anchor_arrives() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-repairs-gap-after-anchor",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let missing = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let later = make_raw_block(missing.digest(), Height::new(7), 700);
            let later_round = Round::new(Epoch::zero(), View::new(7));
            assert!(mailbox.verified(later_round, later.clone()).await);
            let later_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    later_round,
                    View::new(6),
                    StandardHarness::commitment(&later),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, later_finalization).await;
            assert!(mailbox.get_finalization(Height::new(7)).await.is_some());
            assert!(
                resolver.fetches().iter().all(|fetch| {
                    !matches!(
                        (&fetch.key, &fetch.subscriber),
                        (
                            handler::Key::Block(commitment),
                            handler::Annotation::Finalized(handler::Finalized::ByHeight { height })
                        ) if *commitment == missing.digest() && *height == Height::new(6)
                    )
                }),
                "gap repair must wait until the floor anchor is resolved"
            );

            assert!(mailbox.verified(floor_round, floor_block).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "missing post-floor parent fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Block(commitment),
                                handler::Annotation::Finalized(
                                    handler::Finalized::ByHeight { height }
                                )
                            ) if *commitment == missing.digest() && *height == Height::new(6)
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_anchor_resumes_gap_repair() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            let next_round = Round::new(Epoch::zero(), View::new(6));
            let next_block = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    next_round,
                    View::new(5),
                    StandardHarness::commitment(&next_block),
                ),
                &schemes,
                QUORUM,
            );

            let partition_prefix = "local-floor-anchor-resumes-gap-repair";
            seed_inconsistent_restart_state(
                context.child("storage"),
                partition_prefix,
                &[],
                &[(Height::new(6), next_finalization)],
            )
            .await;

            let (application, _started_rx) = HoldingBlockReporter::new();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Floor(floor_finalization),
            )
            .await;

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "gap repair after local floor anchor",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&next_block)
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_newer_pending_floor_supersedes_older_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-supersedes-pending",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            let old_floor_round = Round::new(Epoch::zero(), View::new(5));
            let old_floor_block =
                make_raw_block(Sha256::hash(b"old-floor-parent"), Height::new(5), 500);
            let old_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    old_floor_round,
                    View::new(4),
                    StandardHarness::commitment(&old_floor_block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(old_floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "old floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&old_floor_block)
                        )
                    })
                },
            )
            .await;

            let new_floor_round = Round::new(Epoch::zero(), View::new(7));
            let new_floor_block =
                make_raw_block(Sha256::hash(b"new-floor-parent"), Height::new(7), 700);
            let new_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    new_floor_round,
                    View::new(6),
                    StandardHarness::commitment(&new_floor_block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(new_floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "new floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&new_floor_block)
                        )
                    })
                },
            )
            .await;

            let old_next_round = Round::new(Epoch::zero(), View::new(6));
            let old_next = make_raw_block(old_floor_block.digest(), Height::new(6), 600);
            assert!(mailbox.verified(old_next_round, old_next.clone()).await);
            let old_next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    old_next_round,
                    View::new(5),
                    StandardHarness::commitment(&old_next),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, old_next_finalization).await;
            assert!(mailbox.get_finalization(Height::new(6)).await.is_some());

            let new_next_round = Round::new(Epoch::zero(), View::new(8));
            let new_next = make_raw_block(new_floor_block.digest(), Height::new(8), 800);
            assert!(mailbox.verified(new_next_round, new_next.clone()).await);
            let new_next_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    new_next_round,
                    View::new(7),
                    StandardHarness::commitment(&new_next),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, new_next_finalization).await;
            assert!(mailbox.get_finalization(Height::new(8)).await.is_some());

            let old_floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&old_floor_block)
                    )
                })
                .expect("old floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: old_floor_fetch.key,
                        subscribers: NonEmptyVec::new((
                            old_floor_fetch.subscriber,
                            tracing::Span::none()
                        )),
                    },
                    value: old_floor_block.encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx
                    .await
                    .expect("old floor delivery response missing"),
                "old floor block delivery should validate"
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            let new_floor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&new_floor_block)
                    )
                })
                .expect("new floor fetch missing");
            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: new_floor_fetch.key,
                        subscribers: NonEmptyVec::new((
                            new_floor_fetch.subscriber,
                            tracing::Span::none()
                        )),
                    },
                    value: new_floor_block.encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx
                    .await
                    .expect("new floor delivery response missing"),
                "new floor block delivery should validate"
            );
            assert_eq!(started_rx.await.unwrap(), Height::new(7));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_applies_buffered_anchor_on_notarization() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_proposal = Proposal::new(
                floor_round,
                View::new(4),
                StandardHarness::commitment(&floor_block),
            );
            let floor_finalization =
                StandardHarness::make_finalization(floor_proposal.clone(), &schemes, QUORUM);
            let (application, mut started_rx) = HoldingBlockReporter::new_after(Height::zero());
            let buffer = RecordingBuffer::default();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-buffered-anchor-notarization",
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(buffer.clone()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;

            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            let next = make_raw_block(floor_block.digest(), Height::new(6), 600);
            let next_round = Round::new(Epoch::zero(), View::new(6));
            assert!(mailbox.verified(next_round, next.clone()).await);
            let next_finalization = StandardHarness::make_finalization(
                Proposal::new(next_round, View::new(5), StandardHarness::commitment(&next)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, next_finalization).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(matches!(started_rx.try_recv(), Err(TryRecvError::Empty)));

            buffer.insert(floor_block);
            let floor_notarization =
                StandardHarness::make_notarization(floor_proposal, &schemes, QUORUM);
            StandardHarness::report_notarization(&mut mailbox, floor_notarization).await;
            assert_eq!(started_rx.await.unwrap(), Height::new(5));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_pending_floor_drops_in_flight_ack_before_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "pending-floor-drops-in-flight-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"stale-floor"), Height::zero(), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            // Keep the anchor missing so SetFloor has to wait on a pending
            // floor fetch while the height 1 application ack is in flight.
            mailbox.set_floor(floor_finalization);
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale floor fetch",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Block(commitment)
                                if commitment == StandardHarness::commitment(&floor_block)
                        )
                    })
                },
            )
            .await;

            // Finalize the successor while the pending floor is waiting. It
            // should not dispatch until the anchor is installed.
            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            assert!(mailbox.get_finalization(Height::new(2)).await.is_some());
            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(application.pending_ack_heights(), vec![Height::new(1)]);

            // This ack is released while the anchor is still unknown. The
            // pending floor should have removed it from the active waiters.
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            context.sleep(Duration::from_millis(100)).await;

            // Once the anchor arrives, dispatch restarts at the floor
            // successor instead of treating the stale ack as progress.
            assert!(mailbox.verified(floor_round, floor_block).await);
            select! {
                height = application.acknowledged() => {
                    assert_eq!(
                        height,
                        Height::new(1),
                        "floor install must ignore acks released while the anchor is pending"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("pending floor anchor did not restart dispatch at its successor");
                },
            }
            assert_eq!(application.acknowledged().await, Height::new(2));
        });
    }

    #[test_traced("WARN")]
    fn test_standard_local_floor_below_in_flight_keeps_pending_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "local-floor-below-in-flight-keeps-pending-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&genesis),
                ),
                &schemes,
                QUORUM,
            );

            // The genesis anchor is already local and below the in-flight
            // height 1 ack, so applying it must not touch pending acks.
            mailbox.set_floor(floor_finalization);
            assert!(mailbox.get_block(Height::zero()).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(1)],
                "local floor below the in-flight block must not clear or duplicate its ack"
            );

            let retain_before_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_ack,
            )
            .await;
            assert!(application.pending_ack_heights().is_empty());
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_below_processed_height_preserves_in_flight_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-below-processed-height-preserves-in-flight-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(genesis.clone()),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(genesis.digest(), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let retain_before_block1_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_block1_ack,
            )
            .await;

            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "second block dispatch",
                || application.pending_ack_heights() == vec![Height::new(2)],
            )
            .await;

            // Keep a round-bound resolver request live so the stale floor's
            // round-floor side effect is covered separately from ack handling.
            let stale_floor_round = Round::new(Epoch::zero(), View::new(5));
            let missing = Sha256::hash(b"missing-before-stale-lower-floor");
            let _subscription = mailbox.subscribe_by_commitment(
                missing,
                CommitmentFallback::FetchByRound {
                    round: stale_floor_round,
                },
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch before stale lower floor",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Notarized { round } if round == stale_floor_round
                        )
                    })
                },
            )
            .await;

            let stale_floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    stale_floor_round,
                    View::new(4),
                    StandardHarness::commitment(&genesis),
                ),
                &schemes,
                QUORUM,
            );

            // This lower local anchor is already behind processed height. It
            // may advance the round floor, but must leave height 2 in flight.
            mailbox.set_floor(stale_floor_finalization);
            assert!(mailbox.get_block(Height::zero()).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(2)],
                "stale lower floor must not clear or duplicate in-flight acks"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale lower floor round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(
                            fetch.key,
                            handler::Key::Notarized { round } if round == stale_floor_round
                        )
                    })
                },
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_same_height_floor_anchor_keeps_pending_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "same-height-floor-keeps-pending-ack",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block1_round = Round::new(Epoch::zero(), View::new(1));
            let block1 = make_raw_block(Sha256::hash(b"block1-parent"), Height::new(1), 100);
            let block1_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block1_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block1_round, block1.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, block1_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "first block dispatch",
                || application.pending_ack_heights() == vec![Height::new(1)],
            )
            .await;

            let retain_before_ack = resolver.retain_count();
            assert_eq!(application.acknowledge_next(), Some(Height::new(1)));
            wait_until(
                &context,
                Duration::from_secs(5),
                "first ack processed",
                || resolver.retain_count() > retain_before_ack,
            )
            .await;

            let block2_round = Round::new(Epoch::zero(), View::new(2));
            let block2 = make_raw_block(block1.digest(), Height::new(2), 200);
            let block2_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block2_round,
                    View::new(1),
                    StandardHarness::commitment(&block2),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block2_round, block2).await);
            StandardHarness::report_finalization(&mut mailbox, block2_finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "second block dispatch",
                || application.pending_ack_heights() == vec![Height::new(2)],
            )
            .await;

            let same_height_round = Round::new(Epoch::zero(), View::new(5));
            let same_height_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    same_height_round,
                    View::zero(),
                    StandardHarness::commitment(&block1),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(same_height_finalization);
            assert!(mailbox.get_block(Height::new(1)).await.is_some());

            assert_eq!(
                application.pending_ack_heights(),
                vec![Height::new(2)],
                "same-height floor anchor must not clear or duplicate in-flight acks"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_stale_floor_anchor_advances_round_floor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "stale-floor-anchor-round-floor",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            let block_round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b"processed-parent"), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    block_round,
                    View::zero(),
                    StandardHarness::commitment(&block),
                ),
                &schemes,
                QUORUM,
            );
            assert!(mailbox.verified(block_round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            assert_eq!(application.acknowledged().await, Height::new(1));

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let missing = Sha256::hash(b"missing-before-stale-floor");
            let _subscription = mailbox.subscribe_by_commitment(
                missing,
                CommitmentFallback::FetchByRound { round: floor_round },
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch before stale floor",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(
                            fetch.key,
                            handler::Key::Notarized { round } if round == floor_round
                        )
                    })
                },
            )
            .await;

            let stale_floor = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::zero(),
                    StandardHarness::commitment(&block),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(stale_floor);
            wait_until(
                &context,
                Duration::from_secs(5),
                "stale floor round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(
                            fetch.key,
                            handler::Key::Notarized { round } if round == floor_round
                        )
                    })
                },
            )
            .await;

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(floor_round, Sha256::hash(b"missing-after-stale-floor"));
            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "stale floor anchor must apply its round floor to future fetches"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_floor_anchor_uses_parent_digest_as_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "standard-floor-parent-digest-commitment",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = Ctx {
                round: parent_round,
                leader: me.clone(),
                parent: (
                    View::zero(),
                    StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                ),
            };
            let parent = B::new::<Sha256>(parent_context, Sha256::hash(b""), Height::new(1), 100);

            let floor_round = Round::new(Epoch::zero(), View::new(2));
            let bad_context = Ctx {
                round: floor_round,
                leader: me,
                parent: (
                    View::new(1),
                    StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                ),
            };
            let floor_block = B::new::<Sha256>(bad_context, parent.digest(), Height::new(2), 200);
            assert_ne!(floor_block.parent, floor_block.context.parent.1);

            // Standard commitments are digests, so the generic floor-anchor
            // parent check uses the block's parent digest. Context-parent
            // mismatches are rejected by the standard verification wrappers.
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(1),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );
            resolver.respond_to_next_fetch(floor_block.encode());
            mailbox.set_floor(finalization);

            wait_until(
                &context,
                Duration::from_secs(5),
                "floor block fetch",
                || !resolver.fetches().is_empty(),
            )
            .await;
            assert!(
                resolver.wait_for_delivery_response().await,
                "floor block delivery should be accepted at the resolver boundary"
            );

            assert!(
                mailbox.get_block(Height::new(2)).await.is_some(),
                "standard floor anchor should be archived using its parent digest"
            );
            assert!(
                mailbox.get_finalization(Height::new(2)).await.is_some(),
                "standard floor finalization should be archived by height"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_notarized_delivery_wakes_fetch_by_round_subscriber() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "notarized-delivery-wakes-subscriber",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let subscription = mailbox.subscribe_by_commitment(
                notarization.proposal.payload,
                CommitmentFallback::FetchByRound { round },
            );

            wait_until(
                &context,
                Duration::from_secs(5),
                "fetch-by-round request",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Notarized { round: request_round },
                                handler::Annotation::Notarization { round: subscriber_round },
                            ) if *request_round == round && *subscriber_round == round
                        )
                    })
                },
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized { round },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization { round },
                            tracing::Span::none(),
                        )),
                    },
                    value: (notarization, block.clone()).encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "notarized delivery should validate"
            );

            select! {
                result = subscription => {
                    let delivered = result.expect("block subscription should resolve");
                    assert_eq!(delivered.digest(), block.digest());
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("notarized delivery did not wake block subscriber");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_notarized_delivery_rejects_wrong_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let requested_round = Round::new(Epoch::new(1), View::new(1));
            let delivered_round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(
                delivered_round,
                View::zero(),
                StandardHarness::commitment(&block),
            );
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);

            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "notarized-delivery-wrong-round",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized {
                            round: requested_round,
                        },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization {
                                round: requested_round,
                            },
                            tracing::Span::none(),
                        )),
                    },
                    value: (notarization, block).encode(),
                    response,
                })
                .accepted());
            assert!(
                !response_rx.await.expect("delivery response missing"),
                "wrong-round notarized delivery must not satisfy the request"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_notarized_delivery_acknowledges_stale_without_full_scheme() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let notarization = StandardHarness::make_notarization(proposal, &schemes, QUORUM);

            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "notarized-delivery-stale-certificate-only",
                VerifierProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized { round },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization { round },
                            tracing::Span::none(),
                        )),
                    },
                    value: (notarization, block).encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "stale notarized delivery should acknowledge without blaming the peer"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalized_delivery_verifies_with_verify_only_scope() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let height = Height::new(1);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), height, 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);

            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "finalized-delivery-verify-only",
                VerifierProvider::new(schemes[0].clone()),
                Application::<B>::default(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Finalized { height },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Finalized(handler::Finalized::ByHeight { height }),
                            tracing::Span::none(),
                        )),
                    },
                    value: (finalization, block).encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "finalization verified through a verify-only scope should be accepted"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalized_delivery_rejects_epoch_mismatch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            // Height 1 lives in epoch 0 under `FixedEpocher`, but the finalization claims epoch 1.
            // The certificate decodes against epoch 0's config, so the epoch-equality guard must
            // reject it and blame the peer before any verification.
            let height = Height::new(1);
            let round = Round::new(Epoch::new(1), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), height, 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);

            let (_mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "finalized-delivery-epoch-mismatch",
                VerifierProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Finalized { height },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Finalized(handler::Finalized::ByHeight { height }),
                            tracing::Span::none(),
                        )),
                    },
                    value: (finalization, block).encode(),
                    response,
                })
                .accepted());
            assert!(
                !response_rx.await.expect("delivery response missing"),
                "finalization whose epoch mismatches the height's epoch must blame the peer"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_fetches_reject_processed_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "fetch-notarized-processed-round",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(
                mailbox.verified(round, block.clone()).await,
                "verified block should persist before finalization"
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(
                application.acknowledged().await,
                Height::new(1),
                "application should receive the finalized block"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(round, Sha256::hash(b"missing-at-processed-round"));
            let subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"missing-subscription-at-processed-round"),
                CommitmentFallback::FetchByRound { round },
            );

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await,
                "barrier verification should be processed"
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "hint_notarized must not enqueue the already-pruned processed round"
            );
            select! {
                result = subscription => {
                    assert!(
                        result.is_err(),
                        "processed-round subscription should be canceled without a fetch"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("processed-round subscription remained open");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_finalization_rejects_processed_round_block_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "finalization-processed-round-fetch",
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(application.acknowledged().await, Height::new(1));
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;

            let fetches_before = resolver.fetches().len();
            let stale_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    round,
                    View::zero(),
                    Sha256::hash(b"missing-finalized-at-processed-round"),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, stale_finalization).await;

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "stale finalization must not enqueue a round-bound block fetch"
            );
        });
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "stored genesis block does not match configured anchor")]
    fn test_standard_restart_rejects_mismatched_genesis_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "restart-keeps-existing-genesis";

            let original_genesis =
                make_raw_block(Sha256::hash(b"original-genesis"), Height::zero(), 0);
            let replacement_genesis =
                make_raw_block(Sha256::hash(b"replacement-genesis"), Height::zero(), 1);
            assert_ne!(original_genesis.digest(), replacement_genesis.digest());

            let (mailbox, buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(original_genesis.clone()),
            )
            .await;
            assert_eq!(
                mailbox.get_block(Height::zero()).await.unwrap().digest(),
                original_genesis.digest()
            );

            actor_handle.abort();
            drop(mailbox);
            drop(buffer);
            drop(resolver);
            context.sleep(Duration::from_millis(1)).await;

            let (_mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator_restart"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(replacement_genesis.clone()),
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_standard_processed_round_restored_after_restart() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let partition_prefix = format!("processed-round-restart-{me}");

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let application = Application::<B>::manual_ack();
            let (mailbox, _buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application.clone(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let mut mailbox = mailbox;
            assert_eq!(application.acknowledged().await, Height::zero());

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            let retain_floor = resolver.retain_count() + 2;
            assert_eq!(application.acknowledged().await, Height::new(1));
            wait_until(
                &context,
                Duration::from_secs(5),
                "processed-round pruning",
                || resolver.retain_count() >= retain_floor,
            )
            .await;
            assert_eq!(
                mailbox.get_info(Identifier::Latest).await,
                Some((Height::new(1), block.digest()))
            );

            actor_handle.abort();
            drop(mailbox);
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(round, Sha256::hash(b"missing-after-restart"));
            let subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"missing-subscription-after-restart"),
                CommitmentFallback::FetchByRound { round },
            );

            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "restart must restore the processed round floor"
            );
            select! {
                result = subscription => {
                    assert!(
                        result.is_err(),
                        "processed-round subscription should be canceled after restart"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("processed-round subscription remained open after restart");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_floor_does_not_restore_missing_next_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "round-floor-missing-next-block";

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let proposal = Proposal::new(round, View::zero(), StandardHarness::commitment(&block));
            let notarization =
                StandardHarness::make_notarization(proposal.clone(), &schemes, QUORUM);
            let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);

            seed_processed_height(context.child("metadata"), partition_prefix, Height::zero())
                .await;
            seed_inconsistent_restart_state(
                context.child("storage"),
                partition_prefix,
                &[],
                &[(Height::new(1), finalization)],
            )
            .await;

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let mut subscription = mailbox.subscribe_by_commitment(
                StandardHarness::commitment(&block),
                CommitmentFallback::FetchByRound { round },
            );
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(subscription.try_recv(), Err(TryRecvError::Empty)),
                "missing next block must not advance the restored round floor"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "fetch-by-round after missing-next restart",
                || {
                    resolver.fetches().iter().any(|fetch| {
                        matches!(
                            (&fetch.key, &fetch.subscriber),
                            (
                                handler::Key::Notarized { round: request_round },
                                handler::Annotation::Notarization { round: subscriber_round },
                            ) if *request_round == round && *subscriber_round == round
                        )
                    })
                },
            )
            .await;

            let (response, response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized { round },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization { round },
                            tracing::Span::none(),
                        )),
                    },
                    value: (notarization, block.clone()).encode(),
                    response,
                })
                .accepted());
            assert!(
                response_rx.await.expect("delivery response missing"),
                "notarized delivery should validate"
            );
            select! {
                result = subscription => {
                    let delivered = result.expect("block subscription should resolve");
                    assert_eq!(delivered.digest(), block.digest());
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("round-floor subscription did not resolve");
                },
            }
        });
    }

    #[test_traced("WARN")]
    fn test_standard_round_floor_does_not_restore_unacknowledged_anchor() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let partition_prefix = "round-floor-before-anchor-ack";

            let floor_round = Round::new(Epoch::zero(), View::new(5));
            let floor_block = make_raw_block(Sha256::hash(b"floor-parent"), Height::new(5), 500);
            let floor_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(4),
                    StandardHarness::commitment(&floor_block),
                ),
                &schemes,
                QUORUM,
            );

            let (application, started) = HoldingBlockReporter::new_after(Height::zero());
            let (mailbox, buffer, resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.verified(floor_round, floor_block.clone()).await);
            mailbox.set_floor(floor_finalization);
            select! {
                height = started => {
                    assert_eq!(
                        height.expect("floor anchor delivery signal missing"),
                        Height::new(5),
                        "floor anchor should be delivered before the simulated crash"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("floor anchor was not delivered before restart");
                },
            }

            actor_handle.abort();
            drop(mailbox);
            drop(buffer);
            drop(resolver);
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let fetches_before = resolver.fetches().len();
            let mut subscription = mailbox.subscribe_by_commitment(
                Sha256::hash(b"missing-before-anchor-ack"),
                CommitmentFallback::FetchByRound { round: floor_round },
            );
            let barrier = make_raw_block(floor_block.digest(), Height::new(6), 600);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(6)), barrier)
                    .await,
                "barrier verification should be processed"
            );
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch before anchor ack",
                || {
                    resolver.fetches().len() > fetches_before
                        && resolver.fetches().iter().any(|fetch| {
                            matches!(
                                fetch.key,
                                handler::Key::Notarized { round } if round == floor_round
                            )
                        })
                },
            )
            .await;
            assert!(
                matches!(subscription.try_recv(), Err(TryRecvError::Empty)),
                "unacknowledged anchor round must remain subscribable after restart"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_standard_set_floor_prunes_round_bound_fetches() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator"),
                "set-floor-round-prune",
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let missing = Sha256::hash(b"missing-before-set-floor");
            let _subscription = mailbox
                .subscribe_by_commitment(missing, CommitmentFallback::FetchByRound { round });
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound fetch",
                || {
                    resolver.active_fetches().iter().any(|fetch| {
                        matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
                    })
                },
            )
            .await;

            mailbox.set_floor(finalization.clone());
            assert!(mailbox.verified(round, block.clone()).await);
            wait_until(
                &context,
                Duration::from_secs(5),
                "round-bound prune",
                || {
                    resolver.active_fetches().iter().all(|fetch| {
                        !matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
                    })
                },
            )
            .await;
            assert!(
                resolver.active_fetches().iter().all(|fetch| {
                    !matches!(fetch.key, handler::Key::Notarized { round: r } if r == round)
                }),
                "processed finalization after set_floor must prune existing round-bound fetches"
            );

            let fetches_before = resolver.fetches().len();
            mailbox.hint_notarized(round, Sha256::hash(b"missing-after-set-floor"));
            let barrier = make_raw_block(block.digest(), Height::new(2), 200);

            assert!(
                mailbox
                    .verified(Round::new(Epoch::zero(), View::new(2)), barrier)
                    .await
            );
            assert_eq!(
                resolver.fetches().len(),
                fetches_before,
                "set_floor must apply the round floor to future fetches"
            );
        });
    }

    /// When the provider has no verifier for an epoch, in-flight deliveries
    /// for that epoch must be acknowledged (`true`) so the serving peer is
    /// not blamed, rather than rejected (`false`).
    #[test_traced("WARN")]
    fn test_standard_stale_finalized_delivery_does_not_block_peer() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|context| async move {
            let me = default_leader();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                vec![me.clone()],
            )
            .await;
            network.start();
            let control = oracle.control(me.clone());
            let network_channel = control
                .register(0, Quota::per_second(NonZeroU32::MAX))
                .await
                .unwrap();

            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10));
            let partition_prefix = "stale-finalized-test".to_string();
            let config = Config {
                provider: EmptyProvider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                block_codec_config: (),
                partition_prefix: partition_prefix.clone(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: page_cache.clone(),
                strategy: Sequential,
            };
            let finalizations_by_height = prunable::Archive::init(
                context.child("finalizations_by_height"),
                prunable::Config {
                    translator: EightCap,
                    key_partition: format!("{partition_prefix}-fbh-key"),
                    key_page_cache: page_cache.clone(),
                    value_partition: format!("{partition_prefix}-fbh-value"),
                    compression: None,
                    codec_config: S::certificate_codec_config_unbounded(),
                    items_per_section: NZU64!(10),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            )
            .await
            .expect("failed to initialize finalizations archive");
            let finalized_blocks = prunable::Archive::init(
                context.child("finalized_blocks"),
                prunable::Config {
                    translator: EightCap,
                    key_partition: format!("{partition_prefix}-fb-key"),
                    key_page_cache: page_cache,
                    value_partition: format!("{partition_prefix}-fb-value"),
                    compression: None,
                    codec_config: (),
                    items_per_section: NZU64!(10),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            )
            .await
            .expect("failed to initialize finalized blocks archive");

            let broadcast_config = buffered::Config {
                public_key: me.clone(),
                mailbox_size: NZUsize!(100),
                deque_size: 10,
                priority: false,
                codec_config: (),
                peer_provider: oracle.manager(),
            };
            let (broadcast_engine, buffer) =
                buffered::Engine::new(context.child("broadcast"), broadcast_config);
            broadcast_engine.start(network_channel);

            let (resolver_tx, resolver_rx) = mailbox::new(context.child("mailbox"), NZUsize!(100));

            let (actor, _mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            actor.start(
                Application::<B>::default(),
                buffer,
                (
                    handler::Receiver::new(resolver_rx),
                    RecordingResolver::default(),
                ),
            );

            // Inject a Finalized delivery with garbage payload. The
            // provider has no verifier, so the marshal cannot decode it and
            // must ack (true) rather than blame the peer (false).
            let (response, response_rx) = oneshot::channel();
            assert!(resolver_tx
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Finalized {
                            height: Height::new(5),
                        },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Finalized(handler::Finalized::ByHeight {
                                height: Height::new(5),
                            }),
                            tracing::Span::none(),
                        )),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .accepted());
            assert!(response_rx.await.unwrap());

            // Same for a Notarized delivery.
            let (response, response_rx) = oneshot::channel();
            assert!(resolver_tx
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized {
                            round: Round::new(Epoch::zero(), View::new(1)),
                        },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization {
                                round: Round::new(Epoch::zero(), View::new(1)),
                            },
                            tracing::Span::none(),
                        )),
                    },
                    value: Bytes::from_static(b"unverifiable"),
                    response,
                })
                .accepted());
            assert!(response_rx.await.unwrap());
        });
    }

    /// Regression: application delivery of a finalized block must only happen
    /// after the finalized archives are durably synced. Otherwise a crash after
    /// the application observes the block, but before it acknowledges it, can
    /// expose derived state ahead of marshal's height-indexed finalization.
    #[test_traced("WARN")]
    fn test_standard_dispatches_finalized_blocks_after_sync() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let partition_prefix = format!("validator-{me}");
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (application, started) = HoldingBlockReporter::new_after(Height::zero());
            let (mut mailbox, _buffer, _resolver, actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                application,
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization.clone()).await;

            select! {
                height = started => {
                    assert_eq!(
                        height.expect("delivery signal missing"),
                        Height::new(1),
                        "application should observe the first finalized block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("application should observe block delivery promptly");
                },
            }

            actor_handle.abort();
            drop(mailbox);

            // Yield once so the aborted actor drops its storage handles before restart.
            context.sleep(Duration::from_millis(1)).await;

            let (mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &partition_prefix,
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let recovered = mailbox
                .get_block(Height::new(1))
                .await
                .expect("finalized block must be durable before delivery");
            assert_eq!(
                recovered.digest(),
                block.digest(),
                "restart should recover the delivered finalized block by height"
            );
            assert_eq!(
                mailbox
                    .get_finalization(Height::new(1))
                    .await
                    .expect("finalization must be durable before delivery")
                    .round(),
                round,
                "restart should recover the delivered finalization by height"
            );
        });
    }

    /// A finalized-store wrapper that delays durability by `pace` of
    /// deterministic time to model a slow sync: `sync` blocks the caller for
    /// the pace, while `start_sync` returns immediately with a handle that
    /// completes after the pace (like an archive with a non-blocking sync
    /// path, e.g. [`prunable::Archive`]).
    struct PacedStore<T> {
        inner: T,
        context: deterministic::Context,
        pace: Duration,
    }

    impl<T: crate::marshal::store::Blocks> crate::marshal::store::Blocks for PacedStore<T> {
        type Block = T::Block;
        type Error = T::Error;

        async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
            self.inner.put(block).await
        }

        async fn sync(&mut self) -> Result<(), Self::Error> {
            self.context.sleep(self.pace).await;
            self.inner.sync().await
        }

        async fn start_sync(&mut self) -> Result<commonware_runtime::Handle<()>, Self::Error> {
            let inner = self.inner.start_sync().await?;
            let sleep = self.context.sleep(self.pace);
            Ok(commonware_runtime::Handle::from_future(async move {
                sleep.await;
                inner.await
            }))
        }

        async fn get(
            &self,
            id: commonware_storage::archive::Identifier<'_, <Self::Block as Digestible>::Digest>,
        ) -> Result<Option<Self::Block>, Self::Error> {
            self.inner.get(id).await
        }

        async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
            self.inner.prune(min).await
        }

        fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
            self.inner.missing_items(start, max)
        }

        fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
            self.inner.next_gap(value)
        }

        fn last_index(&self) -> Option<Height> {
            self.inner.last_index()
        }
    }

    impl<T: crate::marshal::store::Certificates> crate::marshal::store::Certificates for PacedStore<T> {
        type BlockDigest = T::BlockDigest;
        type Commitment = T::Commitment;
        type Scheme = T::Scheme;
        type Error = T::Error;

        async fn put(
            &mut self,
            height: Height,
            digest: Self::BlockDigest,
            finalization: Finalization<Self::Scheme, Self::Commitment>,
        ) -> Result<(), Self::Error> {
            self.inner.put(height, digest, finalization).await
        }

        async fn sync(&mut self) -> Result<(), Self::Error> {
            self.context.sleep(self.pace).await;
            self.inner.sync().await
        }

        async fn start_sync(&mut self) -> Result<commonware_runtime::Handle<()>, Self::Error> {
            let inner = self.inner.start_sync().await?;
            let sleep = self.context.sleep(self.pace);
            Ok(commonware_runtime::Handle::from_future(async move {
                sleep.await;
                inner.await
            }))
        }

        async fn get(
            &self,
            id: commonware_storage::archive::Identifier<'_, Self::BlockDigest>,
        ) -> Result<Option<Finalization<Self::Scheme, Self::Commitment>>, Self::Error> {
            self.inner.get(id).await
        }

        async fn has(&self, height: Height) -> Result<bool, Self::Error> {
            self.inner.has(height).await
        }

        async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
            self.inner.prune(min).await
        }

        fn last_index(&self) -> Option<Height> {
            self.inner.last_index()
        }

        fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
            self.inner.ranges_from(from)
        }
    }

    /// Initialize paced prunable finalized stores for direct actor tests.
    #[allow(clippy::type_complexity)]
    async fn paced_finalized_stores(
        context: &deterministic::Context,
        partition_prefix: &str,
        pace: Duration,
    ) -> (
        PacedStore<prunable::Archive<EightCap, deterministic::Context, D, Finalization<S, D>>>,
        PacedStore<prunable::Archive<EightCap, deterministic::Context, D, B>>,
    ) {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let finalizations_by_height = prunable::Archive::init(
            context.child("finalizations_by_height"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{partition_prefix}-fbh-key"),
                key_page_cache: page_cache.clone(),
                value_partition: format!("{partition_prefix}-fbh-value"),
                compression: None,
                codec_config: S::certificate_codec_config_unbounded(),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = prunable::Archive::init(
            context.child("finalized_blocks"),
            prunable::Config {
                translator: EightCap,
                key_partition: format!("{partition_prefix}-fb-key"),
                key_page_cache: page_cache,
                value_partition: format!("{partition_prefix}-fb-value"),
                compression: None,
                codec_config: (),
                items_per_section: NZU64!(10),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        (
            PacedStore {
                inner: finalizations_by_height,
                context: context.child("finalizations_pacer"),
                pace,
            },
            PacedStore {
                inner: finalized_blocks,
                context: context.child("blocks_pacer"),
                pace,
            },
        )
    }

    /// A slow finalized-archive sync must not block the marshal mailbox.
    ///
    /// Processing a finalization requires making the finalized archives
    /// durable before the block is dispatched to the application, but the
    /// sync itself must not serialize unrelated mailbox traffic: a proposer's
    /// `get_verified` (a pure prunable-cache read) issued while the sync is in
    /// flight must be answered immediately.
    ///
    /// Paces both finalized stores so sync completion takes 100ms of
    /// deterministic time, processes a finalization, issues `get_verified` 1ms
    /// later, and asserts that (1) the read is served while the sync is still
    /// in flight and (2) the finalized block reaches the application only
    /// after the paced sync completes (the durability barrier).
    #[test_traced("WARN")]
    fn test_standard_finalization_sync_does_not_block_mailbox() {
        const PACE: Duration = Duration::from_millis(100);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = Config {
                provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                block_codec_config: (),
                partition_prefix: "paced-finalized-sync".to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "paced-finalized-sync", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver));

            // Wait for the genesis block to flow through dispatch so the ack
            // pipeline is idle before the measurement starts.
            wait_until(
                &context,
                Duration::from_secs(1),
                "genesis dispatched",
                || application.blocks().contains_key(&Height::zero()),
            )
            .await;

            // Store a verified block for round 1 in the (unpaced) prunable cache.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(round, block.clone()).await);

            // Report the finalization: the actor buffers the block into the
            // finalized archives and starts the paced 100ms sync.
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            let finalized_at = context.current();
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Issue a get_verified 1ms later: it must not queue behind the sync.
            context.sleep(Duration::from_millis(1)).await;
            let requested_at = context.current();
            let verified = mailbox.get_verified(round).await;
            let elapsed = context
                .current()
                .duration_since(requested_at)
                .expect("time went backwards");
            assert_eq!(
                verified.expect("verified block missing").digest(),
                block.digest()
            );
            tracing::info!(?elapsed, "get_verified answered");
            assert!(
                elapsed < Duration::from_millis(5),
                "get_verified queued behind the finalized-archive sync: took {elapsed:?}"
            );

            // Durability barrier: the finalized block must not reach the
            // application until the paced sync completes.
            assert!(
                !application.blocks().contains_key(&Height::new(1)),
                "block dispatched before the finalized archives were durable"
            );
            context.sleep(Duration::from_millis(90)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(1)),
                "block dispatched before the finalized archives were durable"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "finalized block dispatched",
                || application.blocks().contains_key(&Height::new(1)),
            )
            .await;
            let dispatched = context
                .current()
                .duration_since(finalized_at)
                .expect("time went backwards");
            tracing::info!(?dispatched, "finalized block dispatched");
            assert!(
                dispatched >= PACE,
                "block dispatched before the paced sync completed: {dispatched:?}"
            );
        });
    }

    /// A buffered finalized-archive write must freeze dispatch even when a
    /// stale floor anchor triggers dispatch before the batch's sync starts.
    ///
    /// Within one resolver batch, a repair delivery can buffer a block at the
    /// dispatch frontier and a later delivery can resolve a pending floor
    /// anchor whose height is at or below the processed height. That anchor
    /// path calls `try_dispatch_blocks` mid-batch, before the batch-end
    /// `start_finalized_sync` runs, so dispatch must be gated by the write
    /// itself (via `DispatchGate::defer`) rather than by a started sync.
    /// Without the gate, the frontier block reaches the application while its
    /// archive write is still buffered, and a crash after the application ack
    /// could durably advance the processed floor past a lost write.
    ///
    /// The stale anchor models adversarial input: a verified finalization at
    /// a round above the round floor naming a block marshal never stored at a
    /// height it already processed. Marshal cannot cross-check certificates
    /// against each other, so it must stay crash-safe when one lands in
    /// `apply_pending_floor`'s stale-anchor branch.
    ///
    /// The two repair blocks are delivered in ascending height order, so the
    /// batch entry must keep the lowest written height. Tracking the latest
    /// write instead would leave the gate above the first block and let it
    /// dispatch non-durably.
    #[test_traced("WARN")]
    fn test_standard_stale_floor_anchor_holds_dispatch_until_durable() {
        const PACE: Duration = Duration::from_millis(100);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = Config {
                provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(4),
                block_codec_config: (),
                partition_prefix: "stale-floor-anchor".to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "stale-floor-anchor", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver.clone()));

            // Finalize block 1 and wait until the application has acknowledged
            // it, so the processed height reaches the anchor height below.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(round, block.clone()).await);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            wait_until(
                &context,
                Duration::from_secs(5),
                "block 1 processed",
                || parse_processed_height(&context.encode()) == Some(1),
            )
            .await;

            // Install a pending floor anchor for a forked block at height 1:
            // a valid certificate at a round above the round floor whose block
            // is unknown locally, so marshal fetches it. Its height (at or
            // below the processed height) routes the arriving anchor into the
            // stale-anchor branch.
            let fork = make_raw_block(genesis.digest(), Height::new(1), 999);
            let fork_finalization = StandardHarness::make_finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(5)),
                    View::new(4),
                    StandardHarness::commitment(&fork),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(fork_finalization);
            wait_until(&context, Duration::from_secs(5), "anchor fetch", || {
                resolver.fetches().iter().any(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&fork)
                    )
                })
            })
            .await;
            let anchor_fetch = resolver
                .fetches()
                .into_iter()
                .find(|fetch| {
                    matches!(
                        fetch.key,
                        handler::Key::Block(commitment)
                            if commitment == StandardHarness::commitment(&fork)
                    )
                })
                .expect("anchor fetch missing");

            // Enqueue all deliveries back-to-back (no intervening await) so
            // the actor drains them in a single resolver batch: two repair
            // blocks at and above the dispatch frontier (buffered
            // finalized-archive writes, ascending), then the stale floor
            // anchor.
            let next = make_raw_block(block.digest(), Height::new(2), 200);
            let (next_response, next_response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Block(StandardHarness::commitment(&next)),
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Finalized(handler::Finalized::ByHeight {
                                height: Height::new(2),
                            }),
                            tracing::Span::none(),
                        )),
                    },
                    value: next.encode(),
                    response: next_response,
                })
                .accepted());
            let above = make_raw_block(next.digest(), Height::new(3), 300);
            let (above_response, above_response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Block(StandardHarness::commitment(&above)),
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Finalized(handler::Finalized::ByHeight {
                                height: Height::new(3),
                            }),
                            tracing::Span::none(),
                        )),
                    },
                    value: above.encode(),
                    response: above_response,
                })
                .accepted());
            let (anchor_response, anchor_response_rx) = oneshot::channel();
            assert!(resolver
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: anchor_fetch.key,
                        subscribers: NonEmptyVec::new((
                            anchor_fetch.subscriber,
                            tracing::Span::none()
                        )),
                    },
                    value: fork.encode(),
                    response: anchor_response,
                })
                .accepted());
            let delivered_at = context.current();
            assert!(
                next_response_rx.await.expect("repair response missing"),
                "repair block delivery should validate"
            );
            assert!(
                above_response_rx.await.expect("repair response missing"),
                "repair block delivery should validate"
            );
            assert!(
                anchor_response_rx.await.expect("anchor response missing"),
                "anchor delivery should validate"
            );

            // Durability barrier: the stale-anchor branch runs dispatch before
            // the batch's sync starts, so the repair block at height 2 must
            // stay held until the paced sync completes.
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before the finalized archives were durable"
            );
            context.sleep(Duration::from_millis(90)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before the finalized archives were durable"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "repair blocks dispatched",
                || application.blocks().contains_key(&Height::new(3)),
            )
            .await;
            assert!(application.blocks().contains_key(&Height::new(2)));
            let dispatched = context
                .current()
                .duration_since(delivered_at)
                .expect("time went backwards");
            tracing::info!(?dispatched, "repair blocks dispatched");
            assert!(
                dispatched >= PACE,
                "block dispatched before the paced sync completed: {dispatched:?}"
            );
        });
    }

    /// Overlapping pooled syncs must release the dispatch gate per batch.
    ///
    /// Two finalizations arrive 50ms apart, each starting its own paced 100ms
    /// sync. The first sync covers only the first write, so block 1 must
    /// dispatch as soon as that sync completes while block 2 stays held until
    /// the second sync completes. This pins the batch accounting in
    /// `start_finalized_sync`: if the second write were folded into the first
    /// sync's batch, that sync's completion would release a write it never
    /// covered.
    #[test_traced("WARN")]
    fn test_standard_overlapping_finalized_syncs_release_per_batch() {
        const PACE: Duration = Duration::from_millis(100);
        const STAGGER: Duration = Duration::from_millis(50);
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture { schemes, .. } =
                bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let config = Config {
                provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                start: Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
                mailbox_size: NZUsize!(100),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(4),
                block_codec_config: (),
                partition_prefix: "overlapping-finalized-syncs".to_string(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            };
            let (finalizations_by_height, finalized_blocks) =
                paced_finalized_stores(&context, "overlapping-finalized-syncs", PACE).await;
            let (actor, mut mailbox, _) = Actor::init(
                context.child("actor"),
                finalizations_by_height,
                finalized_blocks,
                config,
            )
            .await;
            let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
            let application = Application::<B>::default();
            let _actor_handle =
                actor.start_unbuffered(application.clone(), (resolver_rx, resolver));
            wait_until(
                &context,
                Duration::from_secs(5),
                "genesis processed",
                || parse_processed_height(&context.encode()) == Some(0),
            )
            .await;

            // Store both verified blocks, then finalize them one STAGGER
            // apart so their pooled syncs overlap.
            let genesis = StandardHarness::genesis_block(NUM_VALIDATORS as u16);
            let first_round = Round::new(Epoch::zero(), View::new(1));
            let first = make_raw_block(genesis.digest(), Height::new(1), 100);
            assert!(mailbox.verified(first_round, first.clone()).await);
            let second_round = Round::new(Epoch::zero(), View::new(2));
            let second = make_raw_block(first.digest(), Height::new(2), 200);
            assert!(mailbox.verified(second_round, second.clone()).await);

            let started_at = context.current();
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    first_round,
                    View::zero(),
                    StandardHarness::commitment(&first),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;
            context.sleep(STAGGER).await;
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    second_round,
                    View::new(1),
                    StandardHarness::commitment(&second),
                ),
                &schemes,
                QUORUM,
            );
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Block 1 dispatches as soon as the first sync completes, without
            // waiting for the second sync.
            wait_until(
                &context,
                Duration::from_millis(150),
                "first block dispatched",
                || application.blocks().contains_key(&Height::new(1)),
            )
            .await;
            let first_dispatched = context
                .current()
                .duration_since(started_at)
                .expect("time went backwards");
            tracing::info!(?first_dispatched, "first block dispatched");
            assert!(
                first_dispatched >= PACE,
                "block dispatched before its sync completed: {first_dispatched:?}"
            );
            assert!(
                first_dispatched < STAGGER + PACE,
                "first block waited for the second sync: {first_dispatched:?}"
            );

            // Block 2 stays held until its own sync completes.
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before its sync completed"
            );
            context.sleep(Duration::from_millis(20)).await;
            assert!(
                !application.blocks().contains_key(&Height::new(2)),
                "block dispatched before its sync completed"
            );
            wait_until(
                &context,
                Duration::from_millis(50),
                "second block dispatched",
                || application.blocks().contains_key(&Height::new(2)),
            )
            .await;
            let second_dispatched = context
                .current()
                .duration_since(started_at)
                .expect("time went backwards");
            tracing::info!(?second_dispatched, "second block dispatched");
            assert!(
                second_dispatched >= STAGGER + PACE,
                "block dispatched before its sync completed: {second_dispatched:?}"
            );
        });
    }

    /// Parse the `processed_height` gauge value from a prometheus-encoded
    /// metrics dump produced by `Metrics::encode`. Looks for any line of the
    /// form `<prefix>processed_height <value>` or
    /// `<prefix>processed_height{labels} <value>`.
    fn parse_processed_height(metrics: &str) -> Option<u64> {
        for line in metrics.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }

            let Some(idx) = line.find("processed_height") else {
                continue;
            };
            let mut rest = &line[idx + "processed_height".len()..];
            if let Some(labeled) = rest.strip_prefix('{') {
                let Some(labels_end) = labeled.find('}') else {
                    continue;
                };
                rest = &labeled[labels_end + 1..];
            }
            if rest.chars().next().is_some_and(char::is_whitespace) {
                let value = rest.split_whitespace().next()?;
                return value.parse().ok();
            }
        }
        None
    }

    /// Regression test for the [`crate::marshal::Update::Block`] pruning
    /// contract.
    ///
    /// Asserts that for every block at height `H` the application has
    /// received, marshal's `processed_height` gauge is at least
    /// `H - max_pending_acks`. Because `processed_height` is monotonic, the
    /// invariant holds at *every* observation point, so the test simply
    /// drives the pipeline (fill, drain, refill) and re-checks the bound
    /// after each step.
    #[test_traced("WARN")]
    fn test_standard_update_block_processed_height_invariant() {
        const MAX_PENDING_ACKS: u64 = 4;
        const NUM_BLOCKS: u64 = 12;

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
            let application = Application::<B>::manual_ack();
            let setup = StandardHarness::setup_validator_with(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                validator,
                ConstantProvider::new(schemes[0].clone()),
                NonZeroUsize::new(MAX_PENDING_ACKS as usize).unwrap(),
                application,
            )
            .await;
            let application = setup.application;
            let mut handle = ValidatorHandle {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };
            let mut handles = vec![handle.clone()];
            assert_eq!(application.acknowledged().await, Height::zero());

            // Submit finalizations; marshal dispatches up to MAX_PENDING_ACKS
            // blocks at a time and stalls until the application acks.
            let epocher = FixedEpocher::new(BLOCKS_PER_EPOCH);
            let mut parent = Sha256::hash(b"");
            let mut parent_commitment =
                StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16);
            for i in 1..=NUM_BLOCKS {
                let block = StandardHarness::make_test_block(
                    parent,
                    parent_commitment,
                    Height::new(i),
                    i,
                    NUM_VALIDATORS as u16,
                );
                let commitment = StandardHarness::commitment(&block);
                parent = StandardHarness::digest(&block);
                parent_commitment = commitment;
                let round = Round::new(
                    epocher
                        .containing(StandardHarness::height(&block))
                        .unwrap()
                        .epoch(),
                    View::new(i),
                );
                StandardHarness::verify(&mut handle, round, &block, &mut handles).await;
                let proposal = Proposal {
                    round,
                    parent: View::new(i.saturating_sub(1)),
                    payload: commitment,
                };
                let finalization = StandardHarness::make_finalization(proposal, &schemes, QUORUM);
                StandardHarness::report_finalization(&mut handle.mailbox, finalization).await;
            }

            let check_invariant = |label: &str| {
                let Some(highest) = application.blocks().keys().max().copied() else {
                    return;
                };
                let processed = parse_processed_height(&context.encode())
                    .expect("processed_height gauge missing");
                let gap = highest.get().saturating_sub(processed);
                assert!(
                    gap <= MAX_PENDING_ACKS,
                    "{label}: highest={} processed={} gap={} > max_pending_acks={}",
                    highest.get(),
                    processed,
                    gap,
                    MAX_PENDING_ACKS,
                );
            };

            // Wait until marshal has dispatched up to the pipeline limit
            // (we submitted more than MAX_PENDING_ACKS finalizations above,
            // so the pipeline must stall at MAX_PENDING_ACKS unacked blocks).
            // This is the peak-gap observation point.
            while (application.blocks().len() as u64) < MAX_PENDING_ACKS {
                context.sleep(Duration::from_millis(10)).await;
            }
            check_invariant("pipeline full");

            // Drain: acknowledge blocks as they arrive; re-check the bound
            // after each dispatch cycle.
            loop {
                let acked = application.acknowledged().await;
                check_invariant(&format!("after ack {acked}"));
                if acked.get() == NUM_BLOCKS {
                    break;
                }
            }
        });
    }

    /// `Forward` for an unknown commitment must early-return without
    /// dispatching, even when peers are provided.
    #[test_traced("WARN")]
    fn test_standard_forward_unknown_block_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let unknown = Sha256::hash(b"unknown-block");

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-unknown-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            mailbox.forward(
                round,
                unknown,
                Recipients::Some(vec![participants[1].clone()]),
            );
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                buffer.sends().is_empty(),
                "forward for an unknown block must not dispatch"
            );
        });
    }

    /// A block relayed via `Proposed` must be dispatched to the buffer and
    /// persisted, with the sync handle resolving durable. A subsequent
    /// `Forward` for the same `(round, commitment)` serves the persisted
    /// block from storage.
    #[test_traced("WARN")]
    fn test_standard_proposed_broadcasts_then_persists() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("proposed-cache-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let targets = vec![participants[1].clone()];
            let (ack, persist) = oneshot::channel();
            mailbox.proposed(round, block.clone(), Recipients::Some(targets.clone()), ack);
            wait_until(&context, Duration::from_secs(5), "proposed send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "proposal must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);

            // The message persists the block after broadcasting it, so the
            // sync handle must resolve durable.
            let sync = persist.await.expect("proposed sync handle missing");
            assert!(sync.durable(round, "proposed").await);

            // A forward for the same commitment must serve the persisted
            // block from storage.
            mailbox.forward(round, digest, Recipients::Some(targets));
            wait_until(&context, Duration::from_secs(5), "forward send", || {
                buffer.sends.lock().len() >= 2
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 2);
            assert_eq!(sends[1].1.digest(), digest);
        });
    }

    /// A propose relay that finds no staged proposal must fall back to
    /// forwarding the persisted block. Staging then flushing at certify (the
    /// recovered-leader race) persists the block and resolves the
    /// certification gate through the staged ack, so the subsequent relay
    /// broadcast re-sends the block from storage instead of dropping it.
    #[test_traced("WARN")]
    fn test_standard_propose_relay_miss_forwards_persisted_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("relay-miss-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            // Stage the proposal as propose would, then flush it as certify
            // does when certification wins the race against the relay.
            let gates = Gates::new();
            let (tx, rx) = oneshot::channel();
            context.child("stager").spawn({
                let gates = gates.clone();
                let block = block.clone();
                move |_| async move {
                    gates
                        .stage(round, digest, Arc::new(block), tx, "test")
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round, digest).expect("gate registered");
            gates.flush_unrelayed(&mailbox, round, digest);
            assert!(
                gate.await.expect("gate resolved"),
                "certify flush must resolve the gate durably"
            );

            // The relay finds nothing staged and must forward the persisted
            // block instead of dropping the broadcast.
            let feedback = relay::broadcast(&gates, &mailbox, digest, Plan::Propose { round });
            assert!(matches!(feedback, Feedback::Ok));
            wait_until(&context, Duration::from_secs(5), "fallback send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "fallback must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);
            assert!(matches!(sends[0].2, Recipients::All));
        });
    }

    /// A propose relay with a staged proposal must dispatch it through the
    /// `Proposed` message and complete the durability handshake. The block is
    /// never persisted beforehand, so the forward fallback has nothing to
    /// serve: only the staged-hit path can produce the send.
    #[test_traced("WARN")]
    fn test_standard_propose_relay_sends_staged_block() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("relay-hit-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            // Stage the proposal as propose would.
            let gates = Gates::new();
            let (tx, rx) = oneshot::channel();
            context.child("stager").spawn({
                let gates = gates.clone();
                let block = block.clone();
                move |_| async move {
                    gates
                        .stage(round, digest, Arc::new(block), tx, "test")
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round, digest).expect("gate registered");

            // The relay must take the staged proposal and dispatch it.
            let feedback = relay::broadcast(&gates, &mailbox, digest, Plan::Propose { round });
            assert!(matches!(feedback, Feedback::Ok));
            wait_until(&context, Duration::from_secs(5), "staged send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1, "staged proposal must dispatch exactly once");
            assert_eq!(sends[0].0, round);
            assert_eq!(sends[0].1.digest(), digest);
            assert!(matches!(sends[0].2, Recipients::All));
            assert!(
                gates.take_staged(round, digest).is_none(),
                "relay must consume the staged proposal"
            );

            // The relayed proposal is persisted through the staged ack, so
            // the certification gate resolves durably.
            assert!(
                gate.await.expect("gate resolved"),
                "relay handshake must resolve the gate durably"
            );
        });
    }

    /// A proposer that relays conflicting blocks for the same round must not
    /// be blocked by its own conflict: a leader that crashes after the send
    /// may legitimately propose a different block for the round after
    /// restart. The verified archive stores candidates with multi-put
    /// semantics, so both `Proposed` handshakes must broadcast and resolve
    /// durable.
    #[test_traced("WARN")]
    fn test_standard_proposed_conflicting_blocks_both_ack() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block_a = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let block_b = make_raw_block(Sha256::hash(b""), Height::new(1), 200);
            assert_ne!(block_a.digest(), block_b.digest());

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("proposed-conflict-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            let (ack_a, persist_a) = oneshot::channel();
            mailbox.proposed(round, block_a.clone(), Recipients::All, ack_a);
            let (ack_b, persist_b) = oneshot::channel();
            mailbox.proposed(round, block_b.clone(), Recipients::All, ack_b);

            let sync_a = persist_a.await.expect("first proposed sync handle missing");
            assert!(sync_a.durable(round, "proposed").await);
            let sync_b = persist_b
                .await
                .expect("second proposed sync handle missing");
            assert!(sync_b.durable(round, "proposed").await);

            let sends = buffer.sends();
            assert_eq!(sends.len(), 2, "both conflicting proposals must dispatch");
            assert_eq!(sends[0].1.digest(), block_a.digest());
            assert_eq!(sends[1].1.digest(), block_b.digest());
        });
    }

    /// `Forward` for a block that marshal has cached must dispatch that block
    /// to exactly the provided peer set via the buffer.
    #[test_traced("WARN")]
    fn test_standard_forward_cached_block_sends_to_peers() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let digest = block.digest();

            let (mailbox, buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("forward-cached-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;
            let buffer = buffer.expect("buffer was provided");

            assert!(mailbox.verified(round, block.clone()).await);

            let targets = vec![participants[1].clone(), participants[2].clone()];
            mailbox.forward(round, digest, Recipients::Some(targets.clone()));
            wait_until(&context, Duration::from_secs(5), "buffer.send", || {
                !buffer.sends.lock().is_empty()
            })
            .await;

            let sends = buffer.sends();
            assert_eq!(sends.len(), 1);
            let (sent_round, sent_block, sent_recipients) = &sends[0];
            assert_eq!(*sent_round, round);
            assert_eq!(sent_block.digest(), digest);
            match sent_recipients {
                Recipients::Some(peers) => assert_eq!(peers, &targets),
                other => panic!("expected Recipients::Some, got {other:?}"),
            }
        });
    }

    /// `HintFinalized` at or below the floor must be a no-op: marshal must
    /// not fire a targeted resolver fetch since the hint is stale.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_below_floor_is_noop() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-below-floor-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            // Raise the floor above the hint we are about to send.
            let floor_anchor = StandardHarness::make_test_block(
                Sha256::hash(b"floor-parent"),
                StandardHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                Height::new(10),
                10,
                NUM_VALIDATORS as u16,
            );
            let floor_round = Round::new(Epoch::zero(), View::new(10));
            let finalization = StandardHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(9),
                    StandardHarness::commitment(&floor_anchor),
                ),
                &schemes,
                QUORUM,
            );
            mailbox.set_floor(finalization);
            assert!(mailbox.verified(floor_round, floor_anchor).await);
            context.sleep(Duration::from_millis(50)).await;

            mailbox.hint_finalized(Height::new(5), NonEmptyVec::new(participants[1].clone()));
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                resolver.targeted_is_empty(),
                "hint at or below floor must not fetch"
            );
        });
    }

    /// `HintFinalized` for a height whose finalization is already durable must
    /// be a no-op: marshal already has everything needed and must not
    /// initiate a redundant fetch.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_skips_when_already_finalized() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (mut mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-already-final-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            // Wait until marshal has durably stored the finalization.
            while mailbox.get_finalization(Height::new(1)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            mailbox.hint_finalized(Height::new(1), NonEmptyVec::new(participants[1].clone()));
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                resolver.targeted_is_empty(),
                "hint for a locally-finalized height must not fetch"
            );
        });
    }

    /// `HintFinalized` above the floor for a not-yet-finalized height must
    /// trigger exactly one targeted fetch via the resolver.
    #[test_traced("WARN")]
    fn test_standard_hint_finalized_emits_targeted_fetch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();

            let (mailbox, _buffer, resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("hint-targets-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            let target = participants[1].clone();
            mailbox.hint_finalized(Height::new(7), NonEmptyVec::new(target.clone()));
            wait_until(&context, Duration::from_secs(5), "fetch_targeted", || {
                !resolver.targeted.lock().is_empty()
            })
            .await;

            let targeted = resolver.targeted();
            assert_eq!(targeted.len(), 1);
            let (request, targets) = &targeted[0];
            assert_eq!(
                request,
                &handler::Key::Finalized {
                    height: Height::new(7)
                }
            );
            assert_eq!(&targets[..], &[target]);
        });
    }

    /// `Prune` for a height above the floor must be rejected (warn + continue)
    /// and must not advance the floor or alter the finalized archive contents.
    #[test_traced("WARN")]
    fn test_standard_prune_above_floor_is_rejected() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let me = participants[0].clone();
            let round = Round::new(Epoch::zero(), View::new(1));
            let block = make_raw_block(Sha256::hash(b""), Height::new(1), 100);
            let finalization = StandardHarness::make_finalization(
                Proposal::new(round, View::zero(), StandardHarness::commitment(&block)),
                &schemes,
                QUORUM,
            );

            let (mut mailbox, _buffer, _resolver, _actor_handle) = start_standard_actor(
                context.child("validator").with_attribute("index", 0),
                &format!("prune-above-floor-{me}"),
                ConstantProvider::new(schemes[0].clone()),
                Application::<B>::manual_ack(),
                Some(RecordingBuffer::default()),
                Start::Genesis(StandardHarness::genesis_block(NUM_VALIDATORS as u16)),
            )
            .await;

            assert!(mailbox.verified(round, block.clone()).await);
            StandardHarness::report_finalization(&mut mailbox, finalization).await;

            while mailbox.get_finalization(Height::new(1)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Prune above the floor must be a no-op, not an error.
            mailbox.prune(Height::new(100));
            context.sleep(Duration::from_millis(50)).await;

            // The finalized block and its finalization must still be retrievable.
            assert!(mailbox.get_block(Height::new(1)).await.is_some());
            assert!(mailbox.get_finalization(Height::new(1)).await.is_some());
        });
    }
}
