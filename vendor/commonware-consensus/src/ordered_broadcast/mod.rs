//! Ordered, reliable broadcast across reconfigurable participants.
//!
//! # Concepts
//!
//! The system has two types of network participants: `sequencers` and `validators`. Their sets may
//! overlap and are defined by the current `epoch`, a monotonically increasing integer. This module
//! can handle reconfiguration of these sets across different epochs.
//!
//! Sequencers broadcast data. The smallest unit of data is a `chunk`. Sequencers broadcast `node`s
//! that contain a chunk and a certificate over the previous chunk, forming a linked chain
//! of nodes from each sequencer.
//!
//! Validators verify and sign chunks. These signatures can be combined to form a quorum
//! certificate, ensuring a quorum verifies each chunk. The certificate allows external parties
//! to confirm that the chunk was reliably broadcast.
//!
//! Network participants persist any new nodes to a journal. This enables recovery from crashes and
//! ensures that sequencers do not broadcast conflicting chunks and that validators do not sign
//! them. "Conflicting" chunks are chunks from the same sequencer at the same height with different
//! payloads.
//!
//! # Pluggable Cryptography
//!
//! The ordered broadcast module is generic over the signing scheme, allowing users to choose the
//! cryptographic scheme best suited for their requirements:
//!
//! - [`ed25519`][scheme::ed25519]: Attributable signatures with individual verification.
//!   HSM-friendly, no trusted setup required. Certificates contain individual signatures.
//!
//! - [`secp256r1`][scheme::secp256r1]: Attributable signatures with individual verification.
//!   HSM-friendly, no trusted setup required. Certificates contain individual signatures.
//!
//! - [`bls12381_multisig`][scheme::bls12381_multisig]: Attributable signatures with aggregated
//!   verification. Produces compact certificates while preserving signer attribution.
//!
//! - [`bls12381_threshold`][scheme::bls12381_threshold]: Non-attributable threshold signatures.
//!   Produces succinct constant-size certificates. Requires trusted setup (DKG).
//!
//! # Design
//!
//! The core of the module is the [Engine]. It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer's chain
//! - Assembling certificates from a quorum of signatures
//! - Notifying other actors of new chunks and certificates
//!
//! # Acknowledgements
//!
//! [Autobahn](https://arxiv.org/abs/2401.10369) provided the insight that a succinct
//! proof-of-availability could be produced by linking sequencer broadcasts.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod ack_manager;
        use ack_manager::AckManager;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod tip_manager;
        use tip_manager::TipManager;
    }
}

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{
        mocks,
        types::{ChunkSigner, ChunkVerifier},
        Config, Engine,
    };
    use crate::{
        ordered_broadcast::scheme::{
            bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme,
        },
        types::{Epoch, EpochDelta, Height, HeightDelta},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{self, mocks::Fixture},
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Signer as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        Clock, Quota, Runner, Spawner, Supervisor as _,
    };
    use commonware_utils::{
        channel::{fallible::OneshotExt, oneshot},
        NZUsize, NZU16, NZU64,
    };
    use futures::future::join_all;
    use std::{
        collections::{BTreeMap, HashMap},
        num::{NonZeroU16, NonZeroU32, NonZeroUsize},
        time::Duration,
    };
    use tracing::debug;

    // Invoke `$cb!($($args)*, $suffix, $fixture)` once per canonical scheme fixture.
    macro_rules! for_each_fixture {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, bls12381_threshold_min_pk, bls12381_threshold::fixture::<MinPk, _>);
            $cb!($($args)*, bls12381_threshold_min_sig, bls12381_threshold::fixture::<MinSig, _>);
            $cb!($($args)*, bls12381_multisig_min_pk, bls12381_multisig::fixture::<MinPk, _>);
            $cb!($($args)*, bls12381_multisig_min_sig, bls12381_multisig::fixture::<MinSig, _>);
            $cb!($($args)*, ed25519, ed25519::fixture);
            $cb!($($args)*, secp256r1, secp256r1::fixture);
        };
    }

    // Generate one `#[test_group("slow")] #[test_traced]` test per scheme
    // fixture, named `test_<callee>_<suffix>`, calling `callee(fixture)`.
    macro_rules! test_for_all_fixtures {
        ($callee:ident) => {
            for_each_fixture!(test_for_all_fixtures!(@emit $callee));
        };
        (@emit $callee:ident, $suffix:ident, $fixture:expr) => {
            paste::paste! {
                #[test_group("slow")]
                #[test_traced]
                fn [<test_ $callee _ $suffix>]() {
                    $callee($fixture);
                }
            }
        };
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
    const TEST_NAMESPACE: &[u8] = b"ordered_broadcast_test";

    type Registrations<P> = BTreeMap<
        P,
        (
            (Sender<P, deterministic::Context>, Receiver<P>),
            (Sender<P, deterministic::Context>, Receiver<P>),
        ),
    >;

    async fn register_participants(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let control = oracle.control(participant.clone());
            let (a1, a2) = control.register(0, TEST_QUOTA).await.unwrap();
            let (b1, b2) = control.register(1, TEST_QUOTA).await.unwrap();
            registrations.insert(participant.clone(), ((a1, a2), (b1, b2)));
        }
        registrations
    }

    enum Action {
        Link(Link),
        Update(Link),
        Unlink,
    }

    async fn link_participants(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        participants: &[PublicKey],
        action: Action,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in participants.iter().enumerate() {
            for (i2, v2) in participants.iter().enumerate() {
                if v2 == v1 {
                    continue;
                }
                if let Some(f) = restrict_to {
                    if !f(participants.len(), i1, i2) {
                        continue;
                    }
                }
                if matches!(action, Action::Update(_) | Action::Unlink) {
                    oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                }
                if let Action::Link(ref link) | Action::Update(ref link) = action {
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }
        }
    }

    const RELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    async fn initialize_simulation<S: certificate::Scheme>(
        context: Context,
        fixture: &Fixture<S>,
        link: Link,
    ) -> (
        Oracle<PublicKey, deterministic::Context>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            fixture.participants.clone(),
        )
        .await;
        network.start();

        let registrations = register_participants(&mut oracle, &fixture.participants).await;
        link_participants(&mut oracle, &fixture.participants, Action::Link(link), None).await;
        (oracle, registrations)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_validator_engines<S>(
        context: Context,
        fixture: &Fixture<S>,
        sequencer_pks: &[PublicKey],
        registrations: &mut Registrations<PublicKey>,
        rebroadcast_timeout: Duration,
        invalid_when: fn(Height) -> bool,
        misses_allowed: Option<usize>,
        epoch: Epoch,
    ) -> BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, S, Sha256Digest>>
    where
        S: Scheme<PublicKey, Sha256Digest>,
    {
        let mut reporters = BTreeMap::new();
        let namespace = b"my testing namespace";

        for (idx, validator) in fixture.participants.iter().enumerate() {
            let context = context
                .child("validator")
                .with_attribute("public_key", validator);
            let monitor = mocks::Monitor::new(epoch);
            let sequencers = mocks::Sequencers::<PublicKey>::new(sequencer_pks.to_vec());

            // Create Provider and register only this validator's scheme for the epoch
            let validators_provider = mocks::Provider::new();
            assert!(validators_provider.register(epoch, fixture.schemes[idx].clone()));

            let automaton = mocks::Automaton::<PublicKey>::new(invalid_when);
            let chunk_verifier = ChunkVerifier::new(namespace);
            let (reporter, reporter_mailbox) = mocks::Reporter::new(
                context.child("reporter"),
                chunk_verifier.clone(),
                fixture.verifier.clone(),
                misses_allowed,
            );
            reporter.start();
            reporters.insert(validator.clone(), reporter_mailbox);

            let engine = Engine::new(
                context.child("engine"),
                Config {
                    sequencer_signer: Some(ChunkSigner::new(
                        namespace,
                        fixture.private_keys[idx].clone(),
                    )),
                    chunk_verifier,
                    sequencers_provider: sequencers,
                    validators_provider,
                    automaton: automaton.clone(),
                    relay: automaton.clone(),
                    reporter: reporters.get(validator).unwrap().clone(),
                    monitor,
                    priority_proposals: false,
                    priority_acks: false,
                    rebroadcast_timeout,
                    epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                    height_bound: HeightDelta::new(2),
                    journal_heights_per_section: NZU64!(10),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_write_buffer: NZUsize!(4096),
                    journal_name_prefix: format!("ordered-broadcast-seq-{validator}-"),
                    journal_compression: Some(3),
                    journal_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    strategy: Sequential,
                },
            );

            let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
            engine.start((a1, a2), (b1, b2));
        }
        reporters
    }

    async fn await_reporters<S>(
        context: Context,
        sequencers: Vec<PublicKey>,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, S, Sha256Digest>>,
        threshold: (Height, Epoch, bool),
    ) where
        S: certificate::Scheme,
    {
        let (threshold_height, threshold_epoch, require_contiguous) =
            (threshold.0, threshold.1, threshold.2);
        let mut receivers = Vec::new();
        for (reporter, mailbox) in reporters.iter() {
            // Spawn a watcher for the reporter.
            for sequencer in sequencers.iter() {
                // Create a oneshot channel to signal when the reporter has reached the threshold.
                let (tx, rx) = oneshot::channel();
                receivers.push(rx);

                context.child("reporter_watcher").spawn({
                    let reporter = reporter.clone();
                    let sequencer = sequencer.clone();
                    let mut mailbox = mailbox.clone();
                    move |context| async move {
                        loop {
                            let (height, epoch) = mailbox
                                .get_tip(sequencer.clone())
                                .await
                                .unwrap_or((Height::zero(), Epoch::zero()));
                            debug!(height = %height, epoch = %epoch, ?sequencer, ?reporter, "reporter");
                            let contiguous_height = mailbox
                                .get_contiguous_tip(sequencer.clone())
                                .await
                                .unwrap_or(Height::zero());
                            if height >= threshold_height
                                && epoch >= threshold_epoch
                                && (!require_contiguous || contiguous_height >= threshold_height)
                            {
                                tx.send_lossy(sequencer.clone());
                                break;
                            }
                            context.sleep(Duration::from_millis(100)).await;
                        }
                    }
                });
            }
        }

        // Wait for all oneshot receivers to complete.
        let results = join_all(receivers).await;
        assert_eq!(results.len(), sequencers.len() * reporters.len());

        // Check that none were cancelled.
        for result in results {
            assert!(result.is_ok(), "reporter was cancelled");
        }
    }

    async fn get_max_height<S: certificate::Scheme>(
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, S, Sha256Digest>>,
    ) -> Height {
        let mut max_height = Height::zero();
        for (sequencer, mailbox) in reporters.iter_mut() {
            let (height, _) = mailbox
                .get_tip(sequencer.clone())
                .await
                .unwrap_or((Height::zero(), Epoch::zero()));
            if height > max_height {
                max_height = height;
            }
        }
        max_height
    }

    fn all_online<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(120));

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            let (_oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validators"),
                &fixture,
                &fixture.participants,
                &mut registrations,
                Duration::from_secs(5),
                |_| false,
                Some(5),
                epoch,
            );

            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (Height::new(100), epoch, true),
            )
            .await;
        });
    }

    test_for_all_fixtures!(all_online);

    fn unclean_shutdown<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Clone,
    {
        let mut prev_checkpoint = None;
        let epoch = Epoch::new(111);
        let num_validators = 4;
        let crash_after = Duration::from_secs(5);
        let target_height = Height::new(30);

        loop {
            let fixture = fixture.clone();
            let f = |mut context: deterministic::Context| async move {
                let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

                let (network, mut oracle) = Network::new_with_peers(
                    context.child("network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: NZUsize!(1),
                    },
                    fixture.participants.clone(),
                )
                .await;
                network.start();

                let mut registrations =
                    register_participants(&mut oracle, &fixture.participants).await;
                link_participants(
                    &mut oracle,
                    &fixture.participants,
                    Action::Link(RELIABLE_LINK),
                    None,
                )
                .await;

                let reporters = spawn_validator_engines(
                    context.child("validator"),
                    &fixture,
                    &fixture.participants,
                    &mut registrations,
                    Duration::from_secs(5),
                    |_| false,
                    None,
                    epoch,
                );

                // Either crash after `crash_after` or succeed once everyone reaches `target_height`.
                let crash = context.sleep(crash_after);
                let run = await_reporters(
                    context.child("reporter"),
                    reporters.keys().cloned().collect::<Vec<_>>(),
                    &reporters,
                    (target_height, epoch, true),
                );

                select! {
                    _ = crash => false,
                    _ = run => true,
                }
            };

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || deterministic::Runner::timed(Duration::from_secs(180)),
                    deterministic::Runner::from,
                )
                .start_and_recover(f);

            if complete {
                break;
            }

            prev_checkpoint = Some(checkpoint);
        }
    }

    test_for_all_fixtures!(unclean_shutdown);

    fn network_partition<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            // Configure the network
            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;
            let mut reporters = spawn_validator_engines(
                context.child("validators"),
                &fixture,
                &fixture.participants,
                &mut registrations,
                Duration::from_secs(1),
                |_| false,
                None,
                epoch,
            );

            // Simulate partition by removing all links.
            link_participants(&mut oracle, &fixture.participants, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Heal the partition by re-adding links.
            link_participants(
                &mut oracle,
                &fixture.participants,
                Action::Link(RELIABLE_LINK),
                None,
            )
            .await;
            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (
                    max_height.saturating_add(HeightDelta::new(100)),
                    epoch,
                    false,
                ),
            )
            .await;
        });
    }

    test_for_all_fixtures!(network_partition);

    fn slow_and_lossy_links_seeded<S, F>(fixture: F, seed: u64) -> String
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(40)));
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;
            let delayed_link = Link {
                latency: Duration::from_millis(50),
                jitter: Duration::from_millis(40),
                success_rate: 0.5,
            };
            link_participants(
                &mut oracle,
                &fixture.participants,
                Action::Update(delayed_link),
                None,
            )
            .await;

            let reporters = spawn_validator_engines(
                context.child("validators"),
                &fixture,
                &fixture.participants,
                &mut registrations,
                Duration::from_millis(150),
                |_| false,
                None,
                epoch,
            );

            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (Height::new(40), epoch, false),
            )
            .await;

            context.auditor().state()
        })
    }

    fn slow_and_lossy_links<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        slow_and_lossy_links_seeded(fixture, 0);
    }

    test_for_all_fixtures!(slow_and_lossy_links);

    fn determinism<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Copy,
    {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            assert_eq!(
                slow_and_lossy_links_seeded(fixture, seed),
                slow_and_lossy_links_seeded(fixture, seed),
            );
        }
    }

    test_for_all_fixtures!(determinism);

    #[test_group("slow")]
    #[test_traced]
    fn test_distinct_states() {
        // Sanity check that different schemes produce different audit states.
        macro_rules! collect {
            ($vec:ident, $suffix:ident, $fixture:expr) => {
                $vec.push((
                    stringify!($suffix),
                    slow_and_lossy_links_seeded($fixture, 7),
                ));
            };
        }
        let mut states = Vec::new();
        for_each_fixture!(collect!(states));
        for pair in states.windows(2) {
            assert_ne!(
                pair[0].1, pair[1].1,
                "state {} equals state {}",
                pair[0].0, pair[1].0
            );
        }
    }

    fn invalid_signature_injection<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            let (_oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validators"),
                &fixture,
                &fixture.participants,
                &mut registrations,
                Duration::from_secs(5),
                |i| i.get() % 10 == 0,
                None,
                epoch,
            );

            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (Height::new(100), epoch, true),
            )
            .await;
        });
    }

    test_for_all_fixtures!(invalid_signature_injection);

    fn updated_epoch<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            // Setup network
            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let mut reporters = BTreeMap::new();

            // Create validators instances that we can update later for epoch changes
            let mut validators_providers = HashMap::new();
            let mut monitors = HashMap::new();
            let namespace = b"my testing namespace";

            for (idx, validator) in fixture.participants.iter().enumerate() {
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                let monitor = mocks::Monitor::new(epoch);
                monitors.insert(validator.clone(), monitor.clone());
                let sequencers = mocks::Sequencers::<PublicKey>::new(fixture.participants.clone());

                // Create and store Provider so we can register new epochs later
                let validators_provider = mocks::Provider::new();
                assert!(validators_provider.register(epoch, fixture.schemes[idx].clone()));
                validators_providers.insert(validator.clone(), validators_provider.clone());

                let automaton = mocks::Automaton::<PublicKey>::new(|_| false);
                let chunk_verifier = ChunkVerifier::new(namespace);
                let (reporter, reporter_mailbox) = mocks::Reporter::new(
                    context.child("reporter"),
                    chunk_verifier.clone(),
                    fixture.verifier.clone(),
                    Some(5),
                );
                reporter.start();
                reporters.insert(validator.clone(), reporter_mailbox);

                let engine = Engine::new(
                    context.child("engine"),
                    Config {
                        sequencer_signer: Some(ChunkSigner::new(
                            namespace,
                            fixture.private_keys[idx].clone(),
                        )),
                        chunk_verifier,
                        sequencers_provider: sequencers,
                        validators_provider,
                        relay: automaton.clone(),
                        automaton: automaton.clone(),
                        reporter: reporters.get(validator).unwrap().clone(),
                        monitor,
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        height_bound: HeightDelta::new(2),
                        rebroadcast_timeout: Duration::from_secs(1),
                        priority_acks: false,
                        priority_proposals: false,
                        journal_heights_per_section: NZU64!(10),
                        journal_replay_buffer: NZUsize!(4096),
                        journal_write_buffer: NZUsize!(4096),
                        journal_name_prefix: format!("ordered-broadcast-seq-{validator}-"),
                        journal_compression: Some(3),
                        journal_page_cache: CacheRef::from_pooler(
                            &context,
                            PAGE_SIZE,
                            PAGE_CACHE_SIZE,
                        ),
                        strategy: Sequential,
                    },
                );

                let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                engine.start((a1, a2), (b1, b2));
            }

            // Perform some work
            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (Height::new(100), epoch, true),
            )
            .await;

            // Simulate partition by removing all links.
            link_participants(&mut oracle, &fixture.participants, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Update the epoch and register schemes for new epoch
            let next_epoch = epoch.next();
            for (validator, monitor) in monitors.iter() {
                monitor.update(next_epoch);
                // Register the scheme for the new epoch
                let idx = fixture
                    .participants
                    .iter()
                    .position(|v| v == validator)
                    .unwrap();
                let validators_provider = validators_providers.get(validator).unwrap();
                assert!(validators_provider.register(next_epoch, fixture.schemes[idx].clone()));
            }

            // Heal the partition by re-adding links.
            link_participants(
                &mut oracle,
                &fixture.participants,
                Action::Link(RELIABLE_LINK),
                None,
            )
            .await;
            await_reporters(
                context.child("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (
                    max_height.saturating_add(HeightDelta::new(100)),
                    next_epoch,
                    true,
                ),
            )
            .await;
        });
    }

    test_for_all_fixtures!(updated_epoch);

    fn external_sequencer<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            // Generate sequencer (external, not a validator)
            let sequencer = PrivateKey::from_seed(u64::MAX);

            // Generate network participants (validators + sequencer)
            let mut participants = fixture.participants.clone();
            participants.push(sequencer.public_key());

            // Create network
            let (network, mut oracle) = Network::new_with_peers(
                context.child("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                participants.clone(),
            )
            .await;
            network.start();

            // Register all participants
            let mut registrations = register_participants(&mut oracle, &participants).await;
            link_participants(
                &mut oracle,
                &participants,
                Action::Link(RELIABLE_LINK),
                None,
            )
            .await;

            // Setup engines
            let mut reporters = BTreeMap::new();
            let namespace = b"my testing namespace";

            // Spawn validator engines (no signing key, only validate)
            for (idx, validator) in fixture.participants.iter().enumerate() {
                let context = context
                    .child("validator")
                    .with_attribute("public_key", validator);
                let monitor = mocks::Monitor::new(epoch);
                let sequencers = mocks::Sequencers::<PublicKey>::new(vec![sequencer.public_key()]);

                // Create Provider and register this validator's scheme
                let validators_provider = mocks::Provider::new();
                assert!(validators_provider.register(epoch, fixture.schemes[idx].clone()));

                let automaton = mocks::Automaton::<PublicKey>::new(|_| false);

                let chunk_verifier = ChunkVerifier::new(namespace);
                let (reporter, reporter_mailbox) = mocks::Reporter::new(
                    context.child("reporter"),
                    chunk_verifier.clone(),
                    fixture.verifier.clone(),
                    Some(5),
                );
                reporter.start();
                reporters.insert(validator.clone(), reporter_mailbox);

                let engine = Engine::new(
                    context.child("engine"),
                    Config {
                        sequencer_signer: None::<ChunkSigner<PrivateKey>>, // Validators don't propose in this test
                        chunk_verifier,
                        sequencers_provider: sequencers,
                        validators_provider,
                        relay: automaton.clone(),
                        automaton: automaton.clone(),
                        reporter: reporters.get(validator).unwrap().clone(),
                        monitor,
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        height_bound: HeightDelta::new(2),
                        rebroadcast_timeout: Duration::from_secs(5),
                        priority_acks: false,
                        priority_proposals: false,
                        journal_heights_per_section: NZU64!(10),
                        journal_replay_buffer: NZUsize!(4096),
                        journal_write_buffer: NZUsize!(4096),
                        journal_name_prefix: format!("ordered-broadcast-seq-{validator}-"),
                        journal_compression: Some(3),
                        journal_page_cache: CacheRef::from_pooler(
                            &context,
                            PAGE_SIZE,
                            PAGE_CACHE_SIZE,
                        ),
                        strategy: Sequential,
                    },
                );

                let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                engine.start((a1, a2), (b1, b2));
            }

            // Spawn sequencer engine
            {
                let context = context.child("sequencer");
                let automaton = mocks::Automaton::<PublicKey>::new(|_| false);
                let chunk_verifier = ChunkVerifier::new(namespace);
                let (reporter, reporter_mailbox) = mocks::Reporter::new(
                    context.child("reporter"),
                    chunk_verifier.clone(),
                    fixture.verifier.clone(),
                    Some(5),
                );
                reporter.start();
                reporters.insert(sequencer.public_key(), reporter_mailbox);

                // Sequencer doesn't need a scheme (it uses ed25519 signing directly)
                // But it needs the verifier to validate acks from validators
                let validators_provider = mocks::Provider::new();
                assert!(validators_provider.register(epoch, fixture.verifier.clone()));

                let engine = Engine::new(
                    context.child("engine"),
                    Config {
                        sequencer_signer: Some(ChunkSigner::new(namespace, sequencer.clone())),
                        chunk_verifier,
                        sequencers_provider: mocks::Sequencers::<PublicKey>::new(vec![
                            sequencer.public_key()
                        ]),
                        validators_provider,
                        relay: automaton.clone(),
                        automaton,
                        reporter: reporters.get(&sequencer.public_key()).unwrap().clone(),
                        monitor: mocks::Monitor::new(epoch),
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        height_bound: HeightDelta::new(2),
                        rebroadcast_timeout: Duration::from_secs(5),
                        priority_acks: false,
                        priority_proposals: false,
                        journal_heights_per_section: NZU64!(10),
                        journal_replay_buffer: NZUsize!(4096),
                        journal_write_buffer: NZUsize!(4096),
                        journal_name_prefix: format!(
                            "ordered-broadcast-seq-{}-",
                            sequencer.public_key()
                        ),
                        journal_compression: Some(3),
                        journal_page_cache: CacheRef::from_pooler(
                            &context,
                            PAGE_SIZE,
                            PAGE_CACHE_SIZE,
                        ),
                        strategy: Sequential,
                    },
                );

                let ((a1, a2), (b1, b2)) = registrations.remove(&sequencer.public_key()).unwrap();
                engine.start((a1, a2), (b1, b2));
            }

            // Await reporters
            await_reporters(
                context.child("reporter"),
                vec![sequencer.public_key()],
                &reporters,
                (Height::new(100), epoch, true),
            )
            .await;
        });
    }

    test_for_all_fixtures!(external_sequencer);

    fn run_1k<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let cfg = deterministic::Config::new();
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let epoch = Epoch::new(111);
            let num_validators = 10;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);

            let delayed_link = Link {
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            // Update to delayed links
            link_participants(
                &mut oracle,
                &fixture.participants,
                Action::Update(delayed_link),
                None,
            )
            .await;

            // Use first half of validators as sequencers
            let sequencers: Vec<PublicKey> =
                fixture.participants[0..num_validators as usize / 2].to_vec();

            let reporters = spawn_validator_engines(
                context.child("validators"),
                &fixture,
                &sequencers,
                &mut registrations,
                Duration::from_millis(150),
                |_| false,
                None,
                epoch,
            );

            await_reporters(
                context.child("reporter"),
                sequencers,
                &reporters,
                (Height::new(1_000), epoch, false),
            )
            .await;
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k() {
        run_1k(mocks::scheme::fixture);
    }
}
