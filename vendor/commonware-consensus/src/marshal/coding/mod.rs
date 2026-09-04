//! Ordered delivery of erasure-coded blocks.
//!
//! # Overview
//!
//! The coding marshal couples the consensus pipeline with erasure-coded block broadcast.
//! Blocks are produced by an application, encoded into [`types::Shard`]s, fanned out to peers, and
//! later reconstructed when a notarization or finalization proves that the data is needed.
//! Compared to [`super::standard`], this variant makes more efficient usage of the network's bandwidth
//! by spreading the load of block dissemination across all participants.
//!
//! # Components
//!
//! - [`crate::marshal::core::Actor`]: The unified marshal actor that orders finalized blocks,
//!   handles acknowledgements from the application, and requests repairs when gaps are detected.
//!   Used with [`Coding`] as the variant type parameter.
//! - [`crate::marshal::core::Mailbox`]: Accepts requests from other local subsystems and forwards
//!   them to the actor. Used with [`Coding`] as the variant type parameter.
//! - [`shards::Engine`]: Broadcasts shards, verifies locally held fragments, and reconstructs
//!   entire [`types::CodedBlock`]s on demand.
//! - [`crate::marshal::resolver`]: Issues outbound fetches to remote peers when marshal is missing
//!   a block, notarization, or finalization referenced by consensus.
//! - [`types`]: Defines commitments, distribution shards, and helper builders used across the
//!   module.
//! - [`Marshaled`]: Wraps an [`crate::Application`] implementation so it automatically enforces
//!   epoch boundaries and performs erasure encoding before a proposal leaves the application.
//!
//! # Data Flow
//!
//! 1. The application produces a block through [`Marshaled`], which encodes the payload and
//!    obtains a [`crate::types::coding::Commitment`] describing the shard layout.
//! 2. The block is broadcast via [`shards::Engine`]; each participant receives exactly one shard
//!    and reshares it to everyone else once it verifies the fragment.
//! 3. The actor ingests notarizations/finalizations from `simplex`, pulls reconstructed blocks
//!    from the shard engine or backfills them through [`crate::marshal::resolver`], and durably
//!    persists the ordered data.
//! 4. The actor reports finalized blocks to the node's [`crate::Reporter`] at-least-once and
//!    drives repair loops whenever notarizations reference yet-to-be-delivered payloads.
//!
//! # Storage and Repair
//!
//! Notarized data and certificates live in prunable archives managed internally, while finalized
//! blocks are migrated into immutable archives. Any gaps are filled by asking peers for specific
//! commitments through the resolver pipeline. The shard engine keeps only ephemeral, in-memory
//! caches; once a block is finalized it is evicted from the reconstruction map, reducing memory
//! pressure.
//!
//! # When to Use
//!
//! Choose this module when the consensus deployment wants erasure-coded dissemination with the
//! same ordering guarantees provided by [`super::standard`]. The API is a breaking change from
//! the standard marshal: applications must adapt to the coding-specific variant type and buffer
//! implementation required by this module.

pub mod shards;
pub mod types;
pub(crate) mod validation;

mod variant;
pub use variant::Coding;

mod marshaled;
pub use marshaled::{Marshaled, MarshaledConfig};

#[cfg(test)]
mod tests {
    use crate::{
        marshal::{
            ancestry::BlockProvider,
            coding::{
                shards,
                types::{coding_config_for_participants, hash_context, CodedBlock},
                Coding, Marshaled, MarshaledConfig,
            },
            config::{Config, Start},
            core,
            mocks::{
                application::Application,
                harness::{
                    self, default_leader, genesis_commitment, make_coding_block,
                    setup_network_links, setup_network_with_participants, CodingB, CodingCtx,
                    CodingHarness, EmptyProvider, TestHarness, BLOCKS_PER_EPOCH, D, K, LINK,
                    NAMESPACE, NUM_VALIDATORS, QUORUM, S, TEST_QUOTA, UNRELIABLE_LINK, V,
                },
                verifying::{GatedVerifyingApp, MockVerifyingApp},
            },
            resolver::handler,
        },
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal, Plan,
        },
        types::{coding::Commitment, Epoch, Epocher, FixedEpocher, Height, Round, View, ViewDelta},
        Automaton, Block, CertifiableAutomaton, CertifiableBlock, Relay,
    };
    use bytes::Bytes;
    use commonware_actor::{mailbox, Feedback};
    use commonware_codec::{Encode, FixedSize};
    use commonware_coding::{CodecConfig, Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider, Verifier as _},
        sha256::Sha256,
        Committable, Digestible, Hasher,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::Recipients;
    use commonware_parallel::Sequential;
    use commonware_resolver::{Delivery, Fetch, Resolver, TargetedResolver};
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        channel::oneshot, sync::Mutex, vec::NonEmptyVec, NZUsize, NZU16, NZU64,
    };
    use std::{sync::Arc, time::Duration};

    type TestCodingVariant = Coding<CodingB, ReedSolomon<Sha256>, Sha256, K>;
    type TestCodedBlock = CodedBlock<CodingB, ReedSolomon<Sha256>, Sha256>;
    type CodingSendRecord = (Round, Arc<TestCodedBlock>, Recipients<K>);

    // Smallest valid coding config used to build trusted genesis commitments.
    const GENESIS_CODING_CONFIG: CodingConfig = CodingConfig {
        minimum_shards: NZU16!(1),
        extra_shards: NZU16!(1),
    };

    #[test]
    fn mailbox_provides_application_blocks() {
        fn assert_provider<P: BlockProvider<Block = CodingB>>() {}
        assert_provider::<core::Mailbox<S, TestCodingVariant>>();
    }

    /// A coding buffer that records subscriptions and never resolves them.
    #[derive(Clone, Default)]
    struct RecordingCodingBuffer {
        digest_subscriptions: Arc<Mutex<Vec<oneshot::Sender<Arc<TestCodedBlock>>>>>,
        commitment_subscriptions: Arc<Mutex<Vec<oneshot::Sender<Arc<TestCodedBlock>>>>>,
        sends: Arc<Mutex<Vec<CodingSendRecord>>>,
    }

    impl RecordingCodingBuffer {
        fn subscription_count(&self) -> usize {
            self.digest_subscriptions.lock().len() + self.commitment_subscriptions.lock().len()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscriptions.lock().len()
        }
    }

    impl core::Buffer<TestCodingVariant> for RecordingCodingBuffer {
        type PublicKey = K;

        async fn find_by_digest(&self, _digest: D) -> Option<Arc<TestCodedBlock>> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Commitment) -> Option<Arc<TestCodedBlock>> {
            None
        }

        fn subscribe_by_digest(
            &self,
            _digest: D,
        ) -> Option<oneshot::Receiver<Arc<TestCodedBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.digest_subscriptions.lock().push(sender);
            Some(receiver)
        }

        fn subscribe_by_commitment(
            &self,
            _commitment: Commitment,
        ) -> Option<oneshot::Receiver<Arc<TestCodedBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscriptions.lock().push(sender);
            Some(receiver)
        }

        fn finalized(&self, _commitment: Commitment) {}

        fn send(&self, round: Round, block: Arc<TestCodedBlock>, recipients: Recipients<K>) {
            self.sends.lock().push((round, block, recipients));
        }
    }

    type CodingFetchRecord = Fetch<handler::Key<Commitment>, handler::Annotation>;
    type CodingTargetedFetch = (handler::Key<Commitment>, NonEmptyVec<K>);

    /// A resolver that records each fetch invocation; other methods are no-ops.
    #[derive(Clone, Default)]
    struct RecordingResolver {
        fetches: Arc<Mutex<Vec<CodingFetchRecord>>>,
        targeted: Arc<Mutex<Vec<CodingTargetedFetch>>>,
        auto_delivery: Arc<Mutex<Option<Bytes>>>,
        delivery_responses: Arc<Mutex<Vec<oneshot::Receiver<bool>>>>,
        sender: Option<mailbox::Sender<handler::Message<Commitment>>>,
    }

    impl RecordingResolver {
        fn holding(metrics: impl Metrics) -> (handler::Receiver<Commitment>, Self) {
            let (sender, receiver) = mailbox::new(metrics, NZUsize!(100));
            (
                handler::Receiver::new(receiver),
                Self {
                    fetches: Arc::new(Mutex::new(Vec::new())),
                    targeted: Arc::new(Mutex::new(Vec::new())),
                    auto_delivery: Arc::new(Mutex::new(None)),
                    delivery_responses: Arc::new(Mutex::new(Vec::new())),
                    sender: Some(sender),
                },
            )
        }

        fn record_fetch(&self, fetch: CodingFetchRecord) {
            self.fetches.lock().push(fetch.clone());
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

        fn fetches(&self) -> Vec<CodingFetchRecord> {
            self.fetches.lock().clone()
        }

        fn targeted(&self) -> Vec<CodingTargetedFetch> {
            self.targeted.lock().clone()
        }
    }

    impl Resolver for RecordingResolver {
        type Key = handler::Key<Commitment>;
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
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for RecordingResolver {
        type PublicKey = K;

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

    async fn start_coding_actor_with_recording(
        context: deterministic::Context,
        partition_prefix: &str,
        provider: ConstantProvider<S, Epoch>,
        buffer: RecordingCodingBuffer,
    ) -> (
        core::Mailbox<S, TestCodingVariant>,
        RecordingResolver,
        commonware_runtime::Handle<()>,
    ) {
        let config = Config {
            provider,
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            start: Start::Genesis(CodingHarness::genesis_block(NUM_VALIDATORS as u16)),
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
            page_cache: CacheRef::from_pooler(
                &context,
                harness::PAGE_SIZE,
                harness::PAGE_CACHE_SIZE,
            ),
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

        let (actor, mailbox, _) = core::Actor::init(
            context.child("actor"),
            finalizations_by_height,
            finalized_blocks,
            config,
        )
        .await;
        let (resolver_rx, resolver) = RecordingResolver::holding(context.child("resolver"));
        let actor_handle = actor.start(
            Application::<CodingB>::default(),
            buffer,
            (resolver_rx, resolver.clone()),
        );
        (mailbox, resolver, actor_handle)
    }

    async fn start_shard_mailbox(
        context: deterministic::Context,
        participants: Vec<K>,
        provider: ConstantProvider<S, Epoch>,
    ) -> shards::Mailbox<CodingB, ReedSolomon<Sha256>, Sha256, K> {
        let me = participants[0].clone();
        let oracle =
            setup_network_with_participants(context.child("network"), NZUsize!(1), participants)
                .await;
        let control = oracle.control(me.clone());
        let shard_config: shards::Config<_, _, _, _, _, Sha256, _, _> = shards::Config {
            scheme_provider: provider,
            blocker: control.clone(),
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
        let network = control.register(0, TEST_QUOTA).await.unwrap();
        shard_engine.start(network);
        shard_mailbox
    }

    fn genesis_block() -> CodingB {
        let genesis_ctx = CodingCtx {
            round: Round::zero(),
            leader: default_leader(),
            parent: (View::zero(), genesis_commitment()),
        };
        make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0)
    }

    fn genesis_coding_commitment<H: Hasher, B: CertifiableBlock>(block: &B) -> Commitment {
        Commitment::from((
            block.digest(),
            block.digest(),
            hash_context::<H, _>(&block.context()),
            GENESIS_CODING_CONFIG,
        ))
    }

    fn missing_candidate(me: K) -> (CodingCtx, TestCodedBlock) {
        let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
        let genesis = genesis_block();
        let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);
        let round = Round::new(Epoch::zero(), View::new(1));
        let candidate_ctx = CodingCtx {
            round,
            leader: me,
            parent: (View::zero(), genesis_parent_commitment),
        };
        let candidate =
            make_coding_block(candidate_ctx.clone(), genesis.digest(), Height::new(1), 100);
        let coded_candidate: TestCodedBlock =
            CodedBlock::new(candidate, coding_config, &Sequential);
        (candidate_ctx, coded_candidate)
    }

    #[test_traced("WARN")]
    fn test_coding_notarized_delivery_rejects_dishonest_payload_config() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let honest_config = coding_config_for_participants(NUM_VALIDATORS as u16);
            let dishonest_config = coding_config_for_participants((NUM_VALIDATORS + 3) as u16);
            assert_ne!(honest_config, dishonest_config);

            let buffer = RecordingCodingBuffer::default();
            let (marshal, resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("actor_stack"),
                "coding-dishonest-payload-config",
                provider,
                buffer,
            )
            .await;
            let resolver_tx = resolver
                .sender
                .clone()
                .expect("recording resolver should keep its sender");

            let genesis = genesis_block();
            let round = Round::new(Epoch::zero(), View::new(1));
            let height = Height::new(1);
            let candidate_ctx = CodingCtx {
                round,
                leader: participants[0].clone(),
                parent: (
                    View::zero(),
                    genesis_coding_commitment::<Sha256, _>(&genesis),
                ),
            };
            let candidate = make_coding_block(candidate_ctx, genesis.digest(), height, 100);
            let dishonest_block: TestCodedBlock =
                CodedBlock::new(candidate.clone(), dishonest_config, &Sequential);
            let proposal = Proposal {
                round,
                parent: View::zero(),
                payload: dishonest_block.commitment(),
            };
            let notarization = CodingHarness::make_notarization(proposal, &schemes, QUORUM);

            let (response, response_rx) = oneshot::channel();
            assert!(resolver_tx
                .enqueue(handler::Message::Deliver {
                    delivery: Delivery {
                        key: handler::Key::Notarized { round },
                        subscribers: NonEmptyVec::new((
                            handler::Annotation::Notarization { round },
                            tracing::Span::none(),
                        )),
                    },
                    value: (notarization, dishonest_block).encode(),
                    response,
                })
                .accepted());
            assert!(
                !response_rx.await.unwrap(),
                "notarized delivery should reject a dishonest coding config"
            );

            context.sleep(Duration::from_millis(100)).await;
            assert!(
                marshal.get_block(height).await.is_none(),
                "dishonest deliveries must not store a finalized block"
            );
            assert!(
                marshal.get_finalization(height).await.is_none(),
                "dishonest deliveries must not archive a finalization"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_coding_block_provider_parent_fetches_by_commitment() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let buffer = RecordingCodingBuffer::default();
            let (marshal, _resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("actor_stack"),
                "coding-provider-parent-commitment",
                provider,
                buffer.clone(),
            )
            .await;

            let (parent_ctx, parent) = missing_candidate(participants[0].clone());
            let child_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(2)),
                leader: participants[0].clone(),
                parent: (parent_ctx.round.view(), parent.commitment()),
            };
            let child = make_coding_block(child_ctx, parent.digest(), Height::new(2), 200);
            let subscription = marshal.subscribe_parent(&child);

            context.sleep(Duration::from_millis(100)).await;
            assert_eq!(
                buffer.commitment_subscription_count(),
                1,
                "parent walkback should use the coding parent commitment"
            );
            drop(subscription);
        });
    }

    #[test_traced("WARN")]
    fn test_coding_verify_missing_candidate_waits_without_fetching() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let me = participants[0].clone();
            let buffer = RecordingCodingBuffer::default();
            let (marshal, resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("actor_stack"),
                "coding-verify-missing-candidate",
                provider.clone(),
                buffer.clone(),
            )
            .await;
            let shards =
                start_shard_mailbox(context.child("shard_stack"), participants, provider.clone())
                    .await;
            let (candidate_ctx, candidate) = missing_candidate(me);
            let commitment = candidate.commitment();

            let cfg = MarshaledConfig {
                application: MockVerifyingApp::<CodingB, S>::new(),
                marshal,
                shards,
                scheme_provider: provider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let verify_rx = marshaled.verify(candidate_ctx, commitment).await;
            context.sleep(Duration::from_millis(100)).await;

            assert!(
                buffer.subscription_count() > 0,
                "missing candidate should register a local buffer wait"
            );
            assert!(
                resolver.fetches().is_empty(),
                "missing candidate verify must not fetch from peers"
            );
            assert!(
                resolver.targeted().is_empty(),
                "missing candidate verify must not issue targeted fetches"
            );
            drop(verify_rx);
        });
    }

    /// Crash-recovery shape: after an unclean shutdown, Simplex may recover a
    /// notarized commitment while marshal has no local certification gate task and no
    /// durable block. If enough shards or a peer response can provide the block,
    /// certification should fetch it by notarized round and persist it instead
    /// of treating the missing local copy as a hard failure.
    #[test_traced("WARN")]
    fn test_coding_certify_missing_candidate_fetches_by_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let me = participants[0].clone();
            let buffer = RecordingCodingBuffer::default();
            let (marshal, resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("actor_stack"),
                "coding-certify-missing-candidate",
                provider.clone(),
                buffer.clone(),
            )
            .await;
            let shards =
                start_shard_mailbox(context.child("shard_stack"), participants, provider.clone())
                    .await;

            let cfg = MarshaledConfig {
                application: MockVerifyingApp::<CodingB, S>::new(),
                marshal,
                shards,
                scheme_provider: provider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let (candidate_ctx, candidate) = missing_candidate(me);
            let commitment = candidate.commitment();
            let round = candidate_ctx.round;
            let proposal = Proposal::new(round, View::zero(), commitment);
            let notarization = CodingHarness::make_notarization(proposal, &schemes, QUORUM);
            resolver.respond_to_next_fetch((notarization, candidate).encode());
            let certify_rx = marshaled.certify(round, commitment).await;

            let result = certify_rx.await.expect("certify result missing");
            assert!(result, "fetched notarized candidate should certify");
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
                "certify should fetch notarized block by round"
            );

            assert!(
                buffer.subscription_count() > 0,
                "missing candidate should register a local buffer wait"
            );
            assert!(
                resolver.targeted().is_empty(),
                "missing candidate certify must not issue targeted fetches"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_coding_certify_pending_verify_fetches_by_round() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let provider = ConstantProvider::new(schemes[0].clone());
            let me = participants[0].clone();
            let buffer = RecordingCodingBuffer::default();
            let (marshal, resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("actor_stack"),
                "coding-certify-pending-verify",
                provider.clone(),
                buffer,
            )
            .await;
            let shards =
                start_shard_mailbox(context.child("shard_stack"), participants, provider.clone())
                    .await;

            let cfg = MarshaledConfig {
                application: MockVerifyingApp::<CodingB, S>::new(),
                marshal,
                shards,
                scheme_provider: provider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let (candidate_ctx, candidate) = missing_candidate(me);
            let commitment = candidate.commitment();
            let round = candidate_ctx.round;
            let _verify_rx = marshaled.verify(candidate_ctx, commitment).await;

            let proposal = Proposal::new(round, View::zero(), commitment);
            let notarization = CodingHarness::make_notarization(proposal, &schemes, QUORUM);
            resolver.respond_to_next_fetch((notarization, candidate).encode());
            let certify_rx = marshaled.certify(round, commitment).await;

            let result = certify_rx.await.expect("certify result missing");
            assert!(
                result,
                "pending verify should complete after certification recovery"
            );
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
                "certify should recover a pending verify by notarized round"
            );
            assert!(
                resolver.targeted().is_empty(),
                "certify recovery must not issue targeted fetches"
            );
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_good_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, false);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_good_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_finalize_bad_links_quorum_sees_finalization() {
        for seed in 0..5 {
            let r1 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            let r2 = harness::finalize::<CodingHarness>(seed, UNRELIABLE_LINK, true);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_hailstorm_restarts() {
        for seed in 0..2 {
            let r1 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 1, LINK);
            let r2 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 1, LINK);
            assert_eq!(r1, r2);
        }
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_coding_hailstorm_multi_restarts() {
        for seed in 0..2 {
            let r1 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 2, LINK);
            let r2 = harness::hailstorm::<CodingHarness>(seed, 4, 4, 2, LINK);
            assert_eq!(r1, r2);
        }
    }

    #[test_traced("WARN")]
    fn test_coding_ack_pipeline_backlog() {
        harness::ack_pipeline_backlog::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ack_pipeline_backlog_persists_on_restart() {
        harness::ack_pipeline_backlog_persists_on_restart::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_genesis_emitted_once() {
        harness::genesis_emitted_once::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_proposed_success_implies_recoverable_after_restart() {
        harness::proposed_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_verified_success_implies_recoverable_after_restart() {
        harness::verified_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_certified_success_implies_recoverable_after_restart() {
        harness::certified_success_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_delivery_visibility_implies_recoverable_after_restart() {
        harness::delivery_visibility_implies_recoverable_after_restart::<CodingHarness>(0..16);
    }

    #[test_traced("WARN")]
    fn test_coding_sync_height_floor() {
        harness::sync_height_floor::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_prune_finalized_archives() {
        harness::prune_finalized_archives::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_rejects_block_delivery_below_floor() {
        harness::reject_stale_block_delivery_after_floor_update::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_commitment_fetch_height_hint_mismatch_wakes_subscriber() {
        harness::commitment_fetch_height_hint_mismatch_wakes_subscriber::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_basic_block_delivery() {
        harness::subscribe_basic_block_delivery::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_multiple_subscriptions() {
        harness::subscribe_multiple_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_canceled_subscriptions() {
        harness::subscribe_canceled_subscriptions::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_subscribe_blocks_from_different_sources() {
        harness::subscribe_blocks_from_different_sources::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_basic_queries_present_and_missing() {
        harness::get_info_basic_queries_present_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_info_latest_progression_multiple_finalizations() {
        harness::get_info_latest_progression_multiple_finalizations::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_height_and_latest() {
        harness::get_block_by_height_and_latest::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_block_by_commitment_from_sources_and_missing() {
        harness::get_block_by_commitment_from_sources_and_missing::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_get_finalization_by_height() {
        harness::get_finalization_by_height::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_hint_finalized_triggers_fetch() {
        harness::hint_finalized_triggers_fetch::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_ancestry_stream() {
        harness::ancestry_stream::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_finalize_same_height_different_views() {
        harness::finalize_same_height_different_views::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_persists_equivocated_block() {
        harness::certify_persists_equivocated_block::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_verified_after_restart_reverify_same_round_implies_recoverable() {
        harness::verified_after_restart_reverify_same_round_implies_recoverable::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_after_restart_reverify_same_round_implies_recoverable() {
        harness::certify_after_restart_reverify_same_round_implies_recoverable::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_at_later_view_survives_earlier_view_pruning() {
        harness::certify_at_later_view_survives_earlier_view_pruning::<CodingHarness>();
    }

    #[test_traced("WARN")]
    fn test_coding_certify_first_block_fetches_genesis_parent() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            let round = Round::new(Epoch::zero(), View::new(1));
            let block_ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let block = make_coding_block(block_ctx.clone(), genesis.digest(), Height::new(1), 100);
            let coded_block = CodedBlock::new(block, coding_config, &Sequential);
            let commitment = coded_block.commitment();
            shards.proposed(round, coded_block);

            context.sleep(Duration::from_millis(10)).await;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal,
                shards,
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let shard_validity = marshaled
                .verify(block_ctx, commitment)
                .await
                .await
                .expect("verify result missing");
            assert!(shard_validity, "shard validity should pass");

            let certify_result = marshaled
                .certify(round, commitment)
                .await
                .await
                .expect("certify result missing");
            assert!(
                certify_result,
                "height-1 block should certify with genesis as parent"
            );
        });
    }

    /// Finalizing a descendant must not height-prune the shard-engine buffer before
    /// `try_repair_gaps` has consumed buffer-only ancestors.
    ///
    /// Places parent (height 1) and descendant (height 2) in the shard engine's
    /// reconstructed-block cache via `proposed()`, then reports a finalization
    /// for the descendant only.
    #[test_traced("WARN")]
    fn test_coding_store_finalization_does_not_prune_buffer_before_repair() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let mut handle = harness::ValidatorHandle::<CodingHarness> {
                mailbox: setup.mailbox,
                extra: setup.extra,
            };

            // Build a 2-block chain: parent at height 1, descendant at height 2.
            let parent_block = CodingHarness::make_test_block(
                Sha256::hash(b""),
                CodingHarness::genesis_parent_commitment(NUM_VALIDATORS as u16),
                Height::new(1),
                1,
                NUM_VALIDATORS as u16,
            );
            let parent_digest = CodingHarness::digest(&parent_block);
            let parent_commitment = CodingHarness::commitment(&parent_block);

            let descendant_block = CodingHarness::make_test_block(
                parent_digest,
                parent_commitment,
                Height::new(2),
                2,
                NUM_VALIDATORS as u16,
            );
            let descendant_commitment = CodingHarness::commitment(&descendant_block);

            // Seed the shard engine's reconstructed-block cache with both blocks.
            CodingHarness::propose(
                &mut handle,
                Round::new(Epoch::new(0), View::new(1)),
                &parent_block,
            )
            .await;
            CodingHarness::propose(
                &mut handle,
                Round::new(Epoch::new(0), View::new(2)),
                &descendant_block,
            )
            .await;

            // Report finalization for the descendant only. The parent has no
            // finalization certificate: it must be archived by walking the
            // parent link from the descendant and sourcing the block from the
            // shard-engine buffer.
            let descendant_proposal = Proposal {
                round: Round::new(Epoch::new(0), View::new(2)),
                parent: View::new(1),
                payload: descendant_commitment,
            };
            let descendant_finalization =
                CodingHarness::make_finalization(descendant_proposal, &schemes, QUORUM);
            CodingHarness::report_finalization(&mut handle.mailbox, descendant_finalization).await;

            // Wait until the descendant is archived: that proves finalization processing
            // has completed, at which point the parent must already have been repaired
            // from the shard buffer.
            while handle.mailbox.get_block(Height::new(2)).await.is_none() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let parent = handle.mailbox.get_block(Height::new(1)).await;
            assert!(
                parent.is_some(),
                "parent must be archived from shard buffer before height-prune evicts it"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_coding_init_processed_height() {
        harness::init_processed_height::<CodingHarness>();
    }

    #[test_traced("INFO")]
    fn test_coding_broadcast_caches_block() {
        harness::broadcast_caches_block::<CodingHarness>();
    }

    /// Test that certifying a lower-view block after a higher-view block succeeds.
    ///
    /// This is a critical test for crash recovery scenarios where a validator may need
    /// to certify blocks in non-sequential view order.
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Create parent block at height 1
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(0), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::new(0), View::new(1)), coded_parent);

            // Block A at view 5 (height 2) - create with context matching what verify will receive
            let round_a = Round::new(Epoch::new(0), View::new(5));
            let context_a = CodingCtx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = make_coding_block(context_a.clone(), parent_digest, Height::new(2), 200);
            let coded_block_a = CodedBlock::new(block_a.clone(), coding_config, &Sequential);
            let commitment_a = coded_block_a.commitment();
            shards.proposed(round_a, coded_block_a);

            // Block B at view 10 (height 2, different block same height - could happen with
            // different proposers or re-proposals)
            let round_b = Round::new(Epoch::new(0), View::new(10));
            let context_b = CodingCtx {
                round: round_b,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_b = make_coding_block(context_b.clone(), parent_digest, Height::new(2), 300);
            let coded_block_b = CodedBlock::new(block_b.clone(), coding_config, &Sequential);
            let commitment_b = coded_block_b.commitment();
            shards.proposed(round_b, coded_block_b);

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

            // Use select with timeout to detect never-resolving receiver
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

    /// Regression test for re-proposal validation in optimistic_verify.
    ///
    /// Verifies that:
    /// 1. Valid re-proposals at epoch boundaries are accepted
    /// 2. Invalid re-proposals (not at epoch boundary) are rejected
    ///
    /// A re-proposal occurs when the parent digest equals the block being verified,
    /// meaning the same block is being proposed again in a new view.
    #[test_traced("INFO")]
    fn test_marshaled_reproposal_validation() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Build a chain up to the epoch boundary (height 19 is the last block in epoch 0
            // with BLOCKS_PER_EPOCH=20, since epoch 0 covers heights 0-19)
            let mut parent = genesis.digest();
            let mut last_view = View::zero();
            let mut last_commitment = genesis_commitment();
            for i in 1..BLOCKS_PER_EPOCH.get() {
                let round = Round::new(Epoch::new(0), View::new(i));
                let ctx = CodingCtx {
                    round,
                    leader: me.clone(),
                    parent: (last_view, last_commitment),
                };
                let block = make_coding_block(ctx.clone(), parent, Height::new(i), i * 100);
                let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
                last_commitment = coded_block.commitment();
                shards.proposed(round, coded_block);
                parent = block.digest();
                last_view = View::new(i);
            }

            // Create the epoch boundary block (height 19, last block in epoch 0)
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::new(0), View::new(boundary_height.get()));
            let boundary_context = CodingCtx {
                round: boundary_round,
                leader: me.clone(),
                parent: (last_view, last_commitment),
            };
            let boundary_block = make_coding_block(
                boundary_context.clone(),
                parent,
                boundary_height,
                boundary_height.get() * 100,
            );
            let coded_boundary =
                CodedBlock::new(boundary_block.clone(), coding_config, &Sequential);
            let boundary_commitment = coded_boundary.commitment();
            shards.proposed(boundary_round, coded_boundary);

            context.sleep(Duration::from_millis(10)).await;

            // Test 1: Valid re-proposal at epoch boundary should be accepted
            // Re-proposal context: parent digest equals the block being verified
            // Re-proposals happen within the same epoch when the parent is the last block
            //
            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We call verify() to register the certification gate task,
            // then certify() returns the deferred_verify result.
            let reproposal_round = Round::new(Epoch::new(0), View::new(20));
            let reproposal_context = CodingCtx {
                round: reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment), // Parent IS the boundary block
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the certification gate task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(reproposal_context.clone(), boundary_commitment)
                .await
                .await;
            assert!(
                shard_validity.unwrap(),
                "Re-proposal verify should return true for shard validity"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                certify_result.unwrap(),
                "Valid re-proposal at epoch boundary should be accepted"
            );

            // Test 2: Invalid re-proposal (not at epoch boundary) should be rejected
            // Create a block at height 10 (not at epoch boundary)
            let non_boundary_height = Height::new(10);
            let non_boundary_round = Round::new(Epoch::new(0), View::new(10));
            // For simplicity, we'll create a fresh non-boundary block and test re-proposal
            let non_boundary_context = CodingCtx {
                round: non_boundary_round,
                leader: me.clone(),
                parent: (View::new(9), last_commitment), // Use a prior commitment
            };
            let non_boundary_block = make_coding_block(
                non_boundary_context.clone(),
                parent,
                non_boundary_height,
                1000,
            );
            let coded_non_boundary =
                CodedBlock::new(non_boundary_block.clone(), coding_config, &Sequential);
            let non_boundary_commitment = coded_non_boundary.commitment();

            // Make the non-boundary block available
            shards.proposed(non_boundary_round, coded_non_boundary);

            context.sleep(Duration::from_millis(10)).await;

            // Attempt to re-propose the non-boundary block
            let invalid_reproposal_round = Round::new(Epoch::new(0), View::new(15));
            let invalid_reproposal_context = CodingCtx {
                round: invalid_reproposal_round,
                leader: me.clone(),
                parent: (View::new(10), non_boundary_commitment),
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the certification gate task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(invalid_reproposal_context, non_boundary_commitment)
                .await
                .await;
            assert!(
                !shard_validity.unwrap(),
                "Invalid re-proposal verify should return false"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(invalid_reproposal_round, non_boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Invalid re-proposal (not at epoch boundary) should be rejected"
            );

            // Test 3: Re-proposal with mismatched epoch should be rejected
            // This is a regression test - re-proposals must be in the same epoch as the block.
            let cross_epoch_reproposal_round = Round::new(Epoch::new(1), View::new(20));
            let cross_epoch_reproposal_context = CodingCtx {
                round: cross_epoch_reproposal_round,
                leader: me.clone(),
                parent: (View::new(boundary_height.get()), boundary_commitment),
            };

            // Call verify to kick off deferred verification.
            // We must await the verify result to ensure the certification gate task is
            // registered before calling certify.
            let shard_validity = marshaled
                .verify(cross_epoch_reproposal_context.clone(), boundary_commitment)
                .await
                .await;
            assert!(
                !shard_validity.unwrap(),
                "Cross-epoch re-proposal verify should return false"
            );

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(cross_epoch_reproposal_round, boundary_commitment)
                .await
                .await;
            assert!(
                !certify_result.unwrap(),
                "Re-proposal with mismatched epoch should be rejected"
            );

            // Note: Tests for certify-only paths (crash recovery scenarios) are not included here
            // because they require multiple validators to reconstruct blocks from shards. In a
            // single-validator test setup, block reconstruction fails due to insufficient shards.
            // These paths are tested in integration tests with multiple validators.
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_mismatched_context_digest() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create parent block at height 1 so the commitment is well-formed.
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::zero(), View::new(1)), coded_parent);

            // Build a block with context A (commitment hash uses this context).
            let round_a = Round::new(Epoch::zero(), View::new(2));
            let context_a = CodingCtx {
                round: round_a,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let block_a = make_coding_block(context_a, parent.digest(), Height::new(2), 200);
            let coded_block_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block_a, coding_config, &Sequential);
            let commitment_a = coded_block_a.commitment();

            // Verify using a different consensus context B (hash mismatch).
            let round_b = Round::new(Epoch::zero(), View::new(3));
            let context_b = CodingCtx {
                round: round_b,
                leader: participants[1].clone(),
                parent: (View::new(1), parent_commitment),
            };

            let verify_rx = marshaled.verify(context_b, commitment_a).await;
            select! {
                result = verify_rx => {
                    assert!(
                        !result.unwrap(),
                        "mismatched context digest should be rejected"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should reject mismatched context digest promptly");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_reproposal_certify_recovers_after_verify_receiver_drop() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Build a valid boundary re-proposal, but keep it unavailable until
            // after the optimistic verify receiver has been dropped.
            let boundary_height = Height::new(BLOCKS_PER_EPOCH.get() - 1);
            let boundary_round = Round::new(Epoch::zero(), View::new(boundary_height.get()));
            let boundary_context = CodingCtx {
                round: boundary_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let boundary_block = make_coding_block(
                boundary_context,
                genesis.digest(),
                boundary_height,
                boundary_height.get() * 100,
            );
            let coded_boundary = CodedBlock::new(boundary_block, coding_config, &Sequential);
            let boundary_commitment = coded_boundary.commitment();
            let reproposal_round = Round::new(Epoch::zero(), View::new(boundary_height.get() + 1));
            let reproposal_context = CodingCtx {
                round: reproposal_round,
                leader: me,
                parent: (View::new(boundary_height.get()), boundary_commitment),
            };

            // Start verify, then drop the receiver before the block is available.
            let verify_rx = marshaled
                .verify(reproposal_context, boundary_commitment)
                .await;
            drop(verify_rx);
            context.sleep(Duration::from_millis(10)).await;

            shards.proposed(boundary_round, coded_boundary);
            context.sleep(Duration::from_millis(10)).await;

            // Certify should not return the stale closed certification gate task; it
            // should recover through the embedded-context certification path.
            let certify_rx = marshaled
                .certify(reproposal_round, boundary_commitment)
                .await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.expect("certify result missing"),
                        "certify should recover after verify receiver drop"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should recover after verify receiver drop");
                },
            }
        })
    }

    #[test_traced("WARN")]
    fn test_reproposal_missing_block_does_not_synthesize_false() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Re-proposal payload with valid coding config, but no block available.
            let missing_payload = Commitment::from((
                Sha256::hash(b"missing_block"),
                Sha256::hash(b"missing_root"),
                Sha256::hash(b"missing_context"),
                coding_config,
            ));
            let round = Round::new(Epoch::zero(), View::new(1));
            let reproposal_context = CodingCtx {
                round,
                leader: me,
                parent: (View::zero(), missing_payload),
            };

            // Verify must not synthesize `false` when the block cannot be fetched.
            let verify_rx = marshaled.verify(reproposal_context, missing_payload).await;

            // Ensure the certification gate task has registered its subscription, then
            // force cancellation by pruning the missing commitment.
            context.sleep(Duration::from_millis(100)).await;
            shards.prune(missing_payload);

            select! {
                result = verify_rx => {
                    assert!(
                        result.is_err(),
                        "verify should resolve without explicit false when re-proposal block is unavailable"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("verify should resolve promptly when re-proposal block is unavailable");
                },
            }

            // Certify should not surface the closed certification gate task as the final result.
            // With no block available, it remains pending on the recovery path until the
            // certifier's caller times out or data arrives.
            let mut certify_rx = marshaled.certify(round, missing_payload).await;
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                matches!(
                    certify_rx.try_recv(),
                    Err(commonware_utils::channel::oneshot::error::TryRecvError::Empty)
                ),
                "certify should remain pending without explicit false or stale cancellation"
            );
            drop(certify_rx);
        })
    }

    #[test_traced("WARN")]
    fn test_core_subscription_closes_when_coding_buffer_prunes_missing_commitment() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
            let missing_commitment = Commitment::from((
                Sha256::hash(b"missing_block"),
                Sha256::hash(b"missing_root"),
                Sha256::hash(b"missing_context"),
                coding_config,
            ));
            let round = Round::new(Epoch::zero(), View::new(1));

            // Subscribe through the core actor. This internally subscribes to the
            // coding shard buffer and registers local waiters.
            let block_rx = marshal.subscribe_by_commitment(
                missing_commitment,
                core::CommitmentFallback::FetchByRound { round },
            );

            // Allow core actor to register the underlying buffer subscription.
            context.sleep(Duration::from_millis(100)).await;

            // Prune the missing commitment in the shard engine, which should cancel
            // the underlying buffer subscription.
            shards.prune(missing_commitment);

            // The core actor must surface cancellation by closing the subscription,
            // not by panicking or leaving the waiter parked indefinitely.
            select! {
                result = block_rx => {
                    assert!(
                        result.is_err(),
                        "core subscription should close when coding buffer drops subscription"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("core subscription should resolve promptly after coding prune");
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let limited_epocher = LimitedEpocher {
                inner: FixedEpocher::new(BLOCKS_PER_EPOCH),
                max_epoch: 0,
            };
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: limited_epocher,
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create a parent block at height 19 (last block in epoch 0, which is supported)
            let parent_ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(19)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(19), 1000);
            let parent_digest = parent.digest();
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::zero(), View::new(19)), coded_parent);

            // Create a block at height 20 (first block in epoch 1, which is NOT supported)
            let block_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(20)),
                leader: default_leader(),
                parent: (View::new(19), parent_commitment),
            };
            let block = make_coding_block(block_ctx, parent_digest, Height::new(20), 2000);
            let coded_block = CodedBlock::new(block.clone(), coding_config, &Sequential);
            let block_commitment = coded_block.commitment();
            shards.proposed(Round::new(Epoch::new(1), View::new(20)), coded_block);

            context.sleep(Duration::from_millis(10)).await;

            // In the coding marshal, verify() returns shard validity while deferred_verify
            // runs in the background. We need to use certify() to get the deferred_verify result.
            let unsupported_round = Round::new(Epoch::new(1), View::new(20));
            let unsupported_context = CodingCtx {
                round: unsupported_round,
                leader: me.clone(),
                parent: (View::new(19), parent_commitment),
            };

            // Call verify to kick off deferred verification
            let _shard_validity = marshaled
                .verify(unsupported_context, block_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(unsupported_round, block_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Block in unsupported epoch should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_marshaled_rejects_invalid_ancestry() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            // Create genesis block
            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Wrap with Marshaled verifier
            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Test case 1: Non-contiguous height
            //
            // We need both blocks in the same epoch.
            // With BLOCKS_PER_EPOCH=20: epoch 0 is heights 0-19, epoch 1 is heights 20-39
            //
            // Store honest parent at height 21 (epoch 1)
            let honest_parent_ctx = CodingCtx {
                round: Round::new(Epoch::new(1), View::new(21)),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let honest_parent = make_coding_block(
                honest_parent_ctx,
                genesis.digest(),
                Height::new(BLOCKS_PER_EPOCH.get() + 1),
                1000,
            );
            let parent_digest = honest_parent.digest();
            let coded_parent = CodedBlock::new(honest_parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(Round::new(Epoch::new(1), View::new(21)), coded_parent);

            // Byzantine proposer broadcasts malicious block at height 35
            // The block has the correct context (matching what consensus will provide)
            // but contains invalid content (non-contiguous height: 21 -> 35 instead of 21 -> 22)
            let byzantine_round = Round::new(Epoch::new(1), View::new(35));
            let byzantine_context = CodingCtx {
                round: byzantine_round,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };
            let malicious_block = make_coding_block(
                byzantine_context.clone(),
                parent_digest,
                Height::new(BLOCKS_PER_EPOCH.get() + 15), // Byzantine: non-contiguous height
                2000,
            );
            let coded_malicious =
                CodedBlock::new(malicious_block.clone(), coding_config, &Sequential);
            let malicious_commitment = coded_malicious.commitment();
            shards.proposed(byzantine_round, coded_malicious);

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 35) from marshal based on digest
            // 3. Validate height is contiguous (fail)
            // 4. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context, malicious_commitment)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round, malicious_commitment)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with non-contiguous heights should be rejected"
            );

            // Test case 2: Mismatched parent digest
            //
            // Create another malicious block with correct context and height
            // but referencing the wrong parent digest (genesis instead of honest_parent)
            let byzantine_round2 = Round::new(Epoch::new(1), View::new(22));
            let byzantine_context2 = CodingCtx {
                round: byzantine_round2,
                leader: me.clone(),
                parent: (View::new(21), parent_commitment), // Consensus says parent is at height 21
            };
            let malicious_block2 = make_coding_block(
                byzantine_context2.clone(),
                genesis.digest(), // Byzantine: wrong parent digest
                Height::new(BLOCKS_PER_EPOCH.get() + 2),
                3000,
            );
            let coded_malicious2 =
                CodedBlock::new(malicious_block2.clone(), coding_config, &Sequential);
            let malicious_commitment2 = coded_malicious2.commitment();
            shards.proposed(byzantine_round2, coded_malicious2);

            // Small delay to ensure broadcast is processed
            context.sleep(Duration::from_millis(10)).await;

            // Marshaled.verify() kicks off deferred verification in the background.
            // The Marshaled verifier will:
            // 1. Fetch honest_parent (height 21) from marshal based on context.parent
            // 2. Fetch malicious_block (height 22) from marshal based on digest
            // 3. Validate height is contiguous
            // 4. Validate parent commitment matches (fail)
            // 5. Return false
            let _shard_validity = marshaled
                .verify(byzantine_context2, malicious_commitment2)
                .await;

            // Use certify to get the actual deferred_verify result
            let certify_result = marshaled
                .certify(byzantine_round2, malicious_commitment2)
                .await
                .await;

            assert!(
                !certify_result.unwrap(),
                "Byzantine block with mismatched parent commitment should be rejected"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_certify_without_prior_verify_crash_recovery() {
        // After a crash, consensus may call certify() without a prior verify().
        // The certify path should:
        //   1. Find no in-progress certification gate task
        //   2. Subscribe to the block from the shard engine
        //   3. Use the block's embedded context for deferred_verify
        //   4. Return Ok(true) for a valid block
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Create parent at height 1.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = CodingCtx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            // Create child at height 2.
            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = CodingCtx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let child = make_coding_block(child_ctx, parent.digest(), Height::new(2), 200);
            let coded_child = CodedBlock::new(child, coding_config, &Sequential);
            let child_commitment = coded_child.commitment();
            shards.proposed(child_round, coded_child);

            context.sleep(Duration::from_millis(10)).await;

            // Call certify directly without any prior verify (simulating crash recovery).
            let certify_rx = marshaled.certify(child_round, child_commitment).await;
            select! {
                result = certify_rx => {
                    assert!(
                        result.unwrap(),
                        "certify without prior verify should succeed for valid block"
                    );
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("certify should complete within timeout");
                },
            }
        })
    }

    /// Regression test: a Byzantine leader must not be able to crash honest nodes
    /// by proposing a `Commitment` with invalid `CodingConfig` bytes (e.g.
    /// zero-valued `NonZeroU16` fields). The fix validates the embedded config
    /// during deserialization so malformed commitments are rejected at the codec
    /// level before reaching `verify()`.
    #[test_traced("WARN")]
    fn test_malformed_commitment_config_rejected_at_deserialization() {
        use commonware_codec::{Encode, ReadExt};

        // Construct a Commitment with all-zero bytes (invalid CodingConfig:
        // minimum_shards=0, extra_shards=0). Serialize it and attempt to
        // deserialize -- this must fail.
        let malformed_bytes = [0u8; Commitment::SIZE];
        let result = Commitment::read(&mut &malformed_bytes[..]);
        assert!(
            result.is_err(),
            "deserialization of Commitment with zeroed CodingConfig must fail"
        );

        // A validly-constructed Commitment must still round-trip.
        let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
        let valid = Commitment::from((
            Sha256::hash(b"block"),
            Sha256::hash(b"root"),
            Sha256::hash(b"context"),
            coding_config,
        ));
        let encoded = valid.encode();
        let decoded =
            Commitment::read(&mut &encoded[..]).expect("valid Commitment must deserialize");
        assert_eq!(valid, decoded);
    }

    #[test_traced("WARN")]
    fn test_certify_propagates_application_verify_failure() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            // 1) Set up a single validator marshal stack.
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            // 2) Force application verification to fail in deferred verification.
            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::with_verify_result(false);

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = CodingCtx {
                round: parent_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_context, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            // 3) Publish a valid child so optimistic verify can succeed.
            let round = Round::new(Epoch::zero(), View::new(2));
            let verify_context = CodingCtx {
                round,
                leader: me,
                parent: (View::new(1), parent_commitment),
            };
            let block =
                make_coding_block(verify_context.clone(), parent.digest(), Height::new(2), 200);
            let coded_block = CodedBlock::new(block, coding_config, &Sequential);
            let commitment = coded_block.commitment();
            shards.proposed(round, coded_block);

            context.sleep(Duration::from_millis(10)).await;

            let optimistic = marshaled.verify(verify_context, commitment).await;
            assert!(
                optimistic.await.expect("verify result missing"),
                "optimistic verify should pass pre-checks and schedule deferred verification"
            );

            // 4) Certify must observe the deferred application failure and return false.
            let certify = marshaled.certify(round, commitment).await;
            assert!(
                !certify.await.expect("certify result missing"),
                "certify should propagate deferred application verify failure"
            );
        })
    }

    #[test_traced("WARN")]
    fn test_backfill_block_mismatched_commitment() {
        // Regression: when backfilling by Key::Block(commitment), a peer may return
        // a coded block with matching inner digest but a different coding commitment.
        // If a finalization for this digest is already cached, marshal must reject
        // the block unless V::commitment(block) matches the finalization payload.
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
                participants[..2].iter().cloned(),
            )
            .await;

            let coding_config_a = coding_config_for_participants(NUM_VALIDATORS as u16);
            // Same total shards (4) but different min/extra split produces a different
            // coding root and config bytes, yielding a different commitment.
            let coding_config_b = commonware_coding::Config {
                minimum_shards: coding_config_a.minimum_shards.checked_add(1).unwrap(),
                extra_shards: NZU16!(coding_config_a.extra_shards.get() - 1),
            };

            let v0_setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                participants[0].clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let v1_setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 1),
                &mut oracle,
                participants[1].clone(),
                ConstantProvider::new(schemes[1].clone()),
            )
            .await;

            setup_network_links(&mut oracle, &participants[..2], LINK).await;

            let mut v0_mailbox = v0_setup.mailbox;
            let v1_mailbox = v1_setup.mailbox;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            let round1 = Round::new(Epoch::zero(), View::new(1));
            let block1_ctx = CodingCtx {
                round: round1,
                leader: participants[0].clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let block1 = make_coding_block(block1_ctx, genesis.digest(), Height::new(1), 100);

            let coded_block_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block1.clone(), coding_config_a, &Sequential);
            let commitment_a = coded_block_a.commitment();

            let coded_block_b: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block1.clone(), coding_config_b, &Sequential);
            let commitment_b = coded_block_b.commitment();

            assert_eq!(coded_block_a.digest(), coded_block_b.digest());
            assert_ne!(commitment_a, commitment_b);

            // Validator 1 proposes coded_block_b (same inner block, different coding).
            // This stores it in v1's shard engine and actor cache.
            assert!(v1_mailbox.verified(round1, coded_block_b.clone()).await);
            context.sleep(Duration::from_millis(100)).await;

            // Create finalization referencing commitment_a (the "correct" commitment).
            let proposal: Proposal<Commitment> = Proposal {
                round: round1,
                parent: View::zero(),
                payload: commitment_a,
            };
            let finalization = CodingHarness::make_finalization(proposal.clone(), &schemes, QUORUM);

            // Report finalization to v0. v0 doesn't have the block:
            //   - it fetches Key::Block(commitment)
            //   - v1 responds with coded_block_b (same digest, wrong commitment)
            //   - deliver path must reject because the response commitment does not
            //     match the request key
            CodingHarness::report_finalization(&mut v0_mailbox, finalization).await;

            // Wait for the fetch cycle to complete.
            context.sleep(Duration::from_secs(5)).await;

            // The mismatched block must not be stored.
            let stored = v0_mailbox.get_block(Height::new(1)).await;
            assert!(
                stored.is_none(),
                "v0 should reject backfilled block with mismatched commitment"
            );

            // Without the block, finalization should not be persisted by height yet.
            let stored_finalization = v0_mailbox.get_finalization(Height::new(1)).await;
            assert!(
                stored_finalization.is_none(),
                "finalization should not be archived until matching block is available"
            );
        })
    }

    #[test_traced("WARN")]
    #[should_panic(expected = "floor block parent commitment mismatch")]
    fn test_coding_floor_anchor_panics_on_parent_commitment_mismatch() {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));
        runner.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
            let (mailbox, resolver, _actor_handle) = start_coding_actor_with_recording(
                context.child("validator"),
                "floor-parent-commitment-mismatch",
                ConstantProvider::new(schemes[0].clone()),
                RecordingCodingBuffer::default(),
            )
            .await;

            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_context = CodingCtx {
                round: parent_round,
                leader: participants[0].clone(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_context, Sha256::hash(b""), Height::new(1), 100);

            let floor_round = Round::new(Epoch::zero(), View::new(2));
            let bad_context = CodingCtx {
                round: floor_round,
                leader: participants[0].clone(),
                parent: (View::new(1), genesis_commitment()),
            };
            let floor_block = make_coding_block(bad_context, parent.digest(), Height::new(2), 200);
            let coded_floor = CodedBlock::new(floor_block, coding_config, &Sequential);
            assert_ne!(
                coded_floor.parent(),
                coded_floor.context().parent.1.block::<D>()
            );

            let finalization = CodingHarness::make_finalization(
                Proposal::new(
                    floor_round,
                    View::new(1),
                    CodingHarness::commitment(&coded_floor),
                ),
                &schemes,
                QUORUM,
            );
            resolver.respond_to_next_fetch(coded_floor.encode());
            mailbox.set_floor(finalization);
            context.sleep(Duration::from_secs(5)).await;
        })
    }

    /// When the scheme provider has no entry for the current epoch,
    /// `Marshaled::propose` and `Marshaled::verify` must return a dropped
    /// receiver (the consensus engine treats `RecvError` as "abstain").
    #[test_traced("WARN")]
    fn test_marshaled_missing_scheme_skips_propose_and_verify() {
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

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();

            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: setup.mailbox,
                shards: setup.extra,
                scheme_provider: EmptyProvider,
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let ctx = CodingCtx {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: me.clone(),
                parent: (View::zero(), genesis_commitment()),
            };

            // propose with a missing scheme returns a dropped sender
            let rx = marshaled.propose(ctx.clone()).await;
            assert!(rx.await.is_err());

            // verify with a missing scheme returns a dropped sender
            let rx = marshaled.verify(ctx, genesis_commitment()).await;
            assert!(rx.await.is_err());
        });
    }

    /// Regression: a validator must not vote finalize on a block that is not
    /// durably persisted. If `certify` resolves true, the block is on disk for
    /// this validator. We assert this by aborting the marshal actor the
    /// instant `certify` returns true, then restarting from the same partition.
    #[test_traced("WARN")]
    fn test_marshaled_certify_persists_block_before_resolving() {
        for seed in 0u64..16 {
            certify_persists_block_before_resolving_at(seed);
        }
    }

    fn certify_persists_block_before_resolving_at(seed: u64) {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;
            let marshal_actor_handle = setup.actor_handle;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);

            // Push parent (height 1) and child (height 2) into the shards
            // engine. These are reconstructable but NOT durably persisted.
            let parent_round = Round::new(Epoch::zero(), View::new(1));
            let parent_ctx = CodingCtx {
                round: parent_round,
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let parent = make_coding_block(parent_ctx, genesis.digest(), Height::new(1), 100);
            let coded_parent = CodedBlock::new(parent.clone(), coding_config, &Sequential);
            let parent_commitment = coded_parent.commitment();
            shards.proposed(parent_round, coded_parent);

            let child_round = Round::new(Epoch::zero(), View::new(2));
            let child_ctx = CodingCtx {
                round: child_round,
                leader: me.clone(),
                parent: (View::new(1), parent_commitment),
            };
            let child = make_coding_block(child_ctx.clone(), parent.digest(), Height::new(2), 200);
            let coded_child = CodedBlock::new(child.clone(), coding_config, &Sequential);
            let child_commitment = coded_child.commitment();
            let child_digest = coded_child.digest();
            shards.proposed(child_round, coded_child);

            context.sleep(Duration::from_millis(10)).await;

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Optimistic verify - returns shard validity (true).
            let shard_validity = marshaled
                .verify(child_ctx, child_commitment)
                .await
                .await
                .expect("verify result missing");
            assert!(shard_validity, "shard validity should pass");

            // Certify - this is the safety gate before finalize voting.
            let certify_result = marshaled
                .certify(child_round, child_commitment)
                .await
                .await
                .expect("certify result missing");
            assert!(certify_result, "certify should succeed");

            // Abort marshal immediately after certify returns to prove the
            // block is already persisted at that point.
            marshal_actor_handle.abort();
            drop(marshaled);
            drop(marshal);
            drop(shards);

            // Restart from the same partition. The block must be durably
            // persisted - otherwise the validator would have voted finalize
            // for a block it cannot serve from local storage.
            let setup2 = CodingHarness::setup_validator(
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
                "certify resolved true, so block must be durably persisted"
            );
        });
    }

    /// Regression: a leader must be able to recover its own block across an unclean restart.
    /// `propose` registers a certification gate, so the leader establishes durability by
    /// certifying its own proposal. After certify, the block must survive restart even if
    /// `Relay::broadcast` never runs. This is the >= f+1 guarantee for the leader's own block.
    #[test_traced("WARN")]
    fn test_marshaled_proposed_block_persists_across_restart() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;
            let marshal_actor_handle = setup.actor_handle;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            // Build the block we want propose() to return. Its embedded context
            // uses the proper genesis commitment so the parent lookup matches
            // the cached genesis.
            let propose_round = Round::new(Epoch::zero(), View::new(1));
            let propose_context = CodingCtx {
                round: propose_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let block_to_propose = make_coding_block(
                propose_context.clone(),
                genesis.digest(),
                Height::new(1),
                100,
            );
            let block_digest = block_to_propose.digest();
            let expected_commitment = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(
                block_to_propose.clone(),
                coding_config,
                &Sequential,
            )
            .commitment();

            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::new().with_propose_result(block_to_propose);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            // Drive the leader-side propose path. `propose` stages the block
            // and returns the commitment. Durability is established by the
            // certify flush below.
            let commitment = marshaled
                .propose(propose_context)
                .await
                .await
                .expect("propose should produce a commitment");
            assert_eq!(commitment, expected_commitment);

            // The leader certifies its own proposal, which awaits the deferred propose
            // sync handle and establishes durability before the finalize vote.
            assert!(
                marshaled
                    .certify(propose_round, commitment)
                    .await
                    .await
                    .expect("certify result missing"),
                "certify must succeed for the leader's own proposal"
            );

            // Abort marshal after certify; the leader's own block must be durable.
            marshal_actor_handle.abort();
            drop(marshaled);
            drop(marshal);
            drop(shards);

            let setup2 = CodingHarness::setup_validator(
                context
                    .child("validator_restart")
                    .with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal2 = setup2.mailbox;

            // The proposer must recover its own block after restart. Without
            // the broadcast-path persistence fix, the block lived only in the
            // shards engine's in-memory cache and is now gone.
            let post_restart = marshal2.get_block(&block_digest).await;
            assert!(
                post_restart.is_some(),
                "proposer should recover its own block after restart"
            );
        });
    }

    /// A propose relay with a staged proposal must send it through the shard
    /// engine and complete the durability handshake. The freshly built block
    /// is nowhere persisted at broadcast time, so the forward fallback has
    /// nothing to serve: only the staged-hit path can seed the shard engine.
    #[test_traced("WARN")]
    fn test_marshaled_propose_relay_sends_staged_block() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            let propose_round = Round::new(Epoch::zero(), View::new(1));
            let propose_context = CodingCtx {
                round: propose_round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let block_to_propose = make_coding_block(
                propose_context.clone(),
                genesis.digest(),
                Height::new(1),
                100,
            );
            let block_digest = block_to_propose.digest();
            let expected_commitment = CodedBlock::<_, ReedSolomon<Sha256>, Sha256>::new(
                block_to_propose.clone(),
                coding_config,
                &Sequential,
            )
            .commitment();

            let mock_app: MockVerifyingApp<CodingB, S> =
                MockVerifyingApp::new().with_propose_result(block_to_propose);
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let commitment = marshaled
                .propose(propose_context)
                .await
                .await
                .expect("propose should produce a commitment");
            assert_eq!(commitment, expected_commitment);

            // The relay must take the staged proposal and broadcast its
            // shards, seeding the shard engine's local cache.
            let subscription = shards.subscribe(commitment);
            let _ = marshaled.broadcast(
                commitment,
                Plan::Propose {
                    round: propose_round,
                },
            );
            let cached = subscription
                .await
                .expect("shard engine must cache the relayed proposal");
            assert_eq!(cached.digest(), block_digest);

            // The relayed proposal is persisted through the staged ack, so
            // certification resolves durably without a flush.
            assert!(
                marshaled
                    .certify(propose_round, commitment)
                    .await
                    .await
                    .expect("certify result missing"),
                "certify must succeed for the relayed proposal"
            );
        });
    }

    /// Regression: if marshal already holds a verified block for a round
    /// (say, persisted by a pre-crash propose whose notarize vote never
    /// reached the journal), a restarted leader's `propose` must return
    /// that block's commitment instead of rebuilding. The pre-crash
    /// commitment may already have been broadcast, so proposing a rebuilt
    /// block for the same round would equivocate. The recovered proposal
    /// must also be staged for the relay, so the broadcast re-sends its
    /// shards and certification resolves through the deduplicated
    /// re-persist.
    #[test_traced("WARN")]
    fn test_propose_reuses_verified_block_on_restart() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            let round = Round::new(Epoch::zero(), View::new(1));
            let ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };

            // Seed block A in marshal's verified cache for `round`.
            let block_a = make_coding_block(ctx.clone(), genesis.digest(), Height::new(1), 100);
            let coded_a: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(block_a.clone(), coding_config, &Sequential);
            let commitment_a = coded_a.commitment();
            assert!(marshal.verified(round, coded_a).await);

            // The app cannot build (`propose` returns None) and its
            // verification never completes, so the assertions below hold
            // only if the stored block is reused as-is and certification
            // resolves through the durability gate registered by the
            // recovery staging.
            let (mock_app, verify_started, _release_verify): (GatedVerifyingApp<CodingB, S>, _, _) =
                GatedVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let commitment = marshaled
                .propose(ctx)
                .await
                .await
                .expect("propose must return a commitment");
            assert_eq!(
                commitment, commitment_a,
                "propose must reuse the block marshal already persisted for this round"
            );

            // The relay broadcast must find the recovered proposal staged and
            // re-persist it (a dedup no-op whose handle covers the pre-crash
            // write), resolving the certification gate registered by the
            // recovery path.
            let _ = marshaled.broadcast(commitment, Plan::Propose { round });
            let certify_rx = marshaled.certify(round, commitment).await;
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

    /// Regression: if a pre-crash leader persisted a verified block for a
    /// round but the simplex `Notarize` never reached the journal, replay
    /// can recover a `consensus_context` whose parent differs from the one
    /// the cached block was built against. The restarted leader must then
    /// drop the receiver so the voter nullifies the view via
    /// `MissingProposal`, rather than broadcasting the stale cached block
    /// under a header that peers will reject.
    #[test_traced("WARN")]
    fn test_propose_skips_when_verified_block_context_changed() {
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
            let coding_config = coding_config_for_participants(NUM_VALIDATORS as u16);

            let setup = CodingHarness::setup_validator(
                context.child("validator").with_attribute("index", 0),
                &mut oracle,
                me.clone(),
                ConstantProvider::new(schemes[0].clone()),
            )
            .await;
            let marshal = setup.mailbox;
            let shards = setup.extra;

            let genesis_ctx = CodingCtx {
                round: Round::zero(),
                leader: default_leader(),
                parent: (View::zero(), genesis_commitment()),
            };
            let genesis = make_coding_block(genesis_ctx, Sha256::hash(b""), Height::zero(), 0);
            let genesis_parent_commitment = genesis_coding_commitment::<Sha256, _>(&genesis);

            // Stash a stale block built against genesis as its parent at round V=2.
            let round = Round::new(Epoch::zero(), View::new(2));
            let stale_ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::zero(), genesis_parent_commitment),
            };
            let stale_block = make_coding_block(stale_ctx, genesis.digest(), Height::new(1), 100);
            let stale_coded: CodedBlock<_, ReedSolomon<Sha256>, Sha256> =
                CodedBlock::new(stale_block, coding_config, &Sequential);
            assert!(marshal.verified(round, stale_coded).await);

            // Simulate a replay where parent selection now points to a
            // different parent commitment than the cached block was built for.
            let new_parent_commitment = Commitment::from((
                Sha256::hash(b"different-parent-block"),
                Sha256::hash(b"different-parent-inner"),
                Sha256::hash(b"different-parent-ctx"),
                coding_config,
            ));
            let new_ctx = CodingCtx {
                round,
                leader: me.clone(),
                parent: (View::new(1), new_parent_commitment),
            };

            let mock_app: MockVerifyingApp<CodingB, S> = MockVerifyingApp::new();
            let cfg = MarshaledConfig {
                application: mock_app,
                marshal: marshal.clone(),
                shards: shards.clone(),
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                strategy: Sequential,
            };
            let mut marshaled = Marshaled::new(context.child("marshaled"), cfg);

            let commitment_rx = marshaled.propose(new_ctx).await;
            assert!(
                commitment_rx.await.is_err(),
                "propose must drop the receiver when the cached block's context no longer matches"
            );
        });
    }
}
