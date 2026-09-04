//! Recover quorum certificates over an externally synchronized sequencer of items.
//!
//! This module allows a dynamic set of participants to collectively produce quorum certificates
//! for any ordered sequence of items.
//!
//! The primary use case for this primitive is to allow blockchain validators to agree on a series
//! of state roots emitted from an opaque consensus process. Because some chains may finalize transaction
//! data but not the output of said transactions during consensus, agreement must be achieved asynchronously
//! over the output of consensus to support state sync and client balance proofs.
//!
//! _For applications that want to collect quorum certificates over concurrent, sequencer-driven broadcast,
//! check out [crate::ordered_broadcast]._
//!
//! # Pluggable Cryptography
//!
//! The aggregation module is generic over the signing scheme, allowing users to choose the
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
//! # Architecture
//!
//! The core of the module is the [Engine]. It manages the agreement process by:
//! - Requesting externally synchronized [commonware_cryptography::Digest]s
//! - Signing said digests with the configured scheme's signature type
//! - Multicasting signatures/shares to other validators
//! - Assembling certificates from a quorum of signatures
//! - Monitoring recovery progress and notifying the application layer of recoveries
//!
//! The engine interacts with four main components:
//! - [crate::Automaton]: Provides external digests
//! - [crate::Reporter]: Receives agreement confirmations
//! - [crate::Monitor]: Tracks epoch transitions
//! - [commonware_cryptography::certificate::Provider]: Manages validator sets and network identities
//!
//! # Design Decisions
//!
//! ## Missing Certificate Resolution
//!
//! The engine does not try to "fill gaps" when certificates are missing. When validators
//! fall behind or miss signatures for certain indices, the tip may skip ahead and those
//! certificates may never be emitted by the local engine. Before skipping ahead, we ensure that
//! at-least-one honest validator has the certificate for any skipped height.
//!
//! Like other consensus primitives, aggregation's design prioritizes doing useful work at tip and
//! minimal complexity over providing a comprehensive recovery mechanism. As a result, applications that need
//! to build a complete history of all formed [types::Certificate]s must implement their own mechanism to synchronize
//! historical results.
//!
//! ## Recovering Certificates
//!
//! In aggregation, participants never gossip recovered certificates. Rather, they gossip [types::TipAck]s
//! with signatures over some height and their latest tip. This approach reduces the overhead of running aggregation
//! concurrently with a consensus mechanism and consistently results in local recovery on stable networks. To increase
//! the likelihood of local recovery, participants should tune the [Config::activity_timeout] to a value larger than the expected
//! drift of online participants (even if all participants are synchronous the tip advancement logic will advance to the `f+1`th highest
//! reported tip and drop all work below that tip minus the [Config::activity_timeout]).
//!
//! ## Epoch-Independent Signatures
//!
//! The attestation in a [types::Ack] covers only the [types::Item] (height and digest), not the
//! epoch, and the ack namespace does not rotate per epoch. This is intentional: participants
//! attest to an externally agreed-upon log that does not change across epochs, so an attestation
//! to an item is valid regardless of the epoch in which it was produced. [types::Certificate]s
//! likewise do not bind an epoch, keeping them verifiable across epoch transitions.
//!
//! The epoch field on [types::Ack] is unauthenticated metadata that selects the scheme used to
//! verify the attestation and assemble the certificate. This is safe because the engine
//! only accepts an ack delivered by its signer (the authenticated sender must match the
//! attestation's signer index), and a signer gains nothing by relabeling its own ack that it could
//! not achieve by signing the item directly in the target epoch. Integrations that perform
//! per-epoch accounting from [types::Activity] should not treat the epoch as signed intent.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod safe_tip;

        #[cfg(test)]
        pub mod mocks;
    }
}

#[cfg(test)]
mod tests {
    use super::{mocks, Config, Engine};
    use crate::{
        aggregation::scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
        types::{Epoch, EpochDelta, Height, HeightDelta},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
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
        test_rng, NZUsize, NonZeroDuration, TestRng, NZU16,
    };
    use futures::future::join_all;
    use rand::RngExt as _;
    use std::{
        collections::BTreeMap,
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

    // Generate one `#[test_traced("INFO")]` test per scheme fixture, named
    // `test_<callee>_<suffix>`, calling `callee(fixture)`. Prefix the callee with
    // `slow` to additionally tag each generated test with `#[test_group("slow")]`.
    macro_rules! test_for_all_fixtures {
        ($callee:ident) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [] $callee));
        };
        (slow $callee:ident) => {
            for_each_fixture!(test_for_all_fixtures!(@emit [#[test_group("slow")]] $callee));
        };
        (@emit [$(#[$attr:meta])*] $callee:ident, $suffix:ident, $fixture:expr) => {
            paste::paste! {
                $(#[$attr])*
                #[test_traced("INFO")]
                fn [<test_ $callee _ $suffix>]() {
                    $callee($fixture);
                }
            }
        };
    }

    type Registrations<P> = BTreeMap<P, (Sender<P, deterministic::Context>, Receiver<P>)>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
    const TEST_NAMESPACE: &[u8] = b"my testing namespace";

    /// Reliable network link configuration for testing.
    const RELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    /// Register all participants with the network oracle.
    async fn register_participants(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let (sender, receiver) = oracle
                .control(participant.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            registrations.insert(participant.clone(), (sender, receiver));
        }
        registrations
    }

    /// Establish network links between all participants.
    async fn link_participants(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        participants: &[PublicKey],
        link: Link,
    ) {
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v2 == v1 {
                    continue;
                }
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    /// Initialize a simulated network environment.
    async fn initialize_simulation<S: Scheme<Sha256Digest, PublicKey = PublicKey>>(
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
        link_participants(&mut oracle, &fixture.participants, link).await;

        (oracle, registrations)
    }

    /// Spawn aggregation engines for all validators.
    fn spawn_validator_engines<S: Scheme<Sha256Digest, PublicKey = PublicKey>>(
        context: Context,
        fixture: &Fixture<S>,
        registrations: &mut Registrations<PublicKey>,
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        epoch: Epoch,
        rebroadcast_timeout: Duration,
        incorrect: Vec<usize>,
    ) -> BTreeMap<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>> {
        let mut reporters = BTreeMap::new();

        for (idx, participant) in fixture.participants.iter().enumerate() {
            let context = context
                .child("participant")
                .with_attribute("public_key", participant);

            // Create Provider and register scheme for epoch
            let provider = mocks::Provider::new();
            assert!(provider.register(epoch, fixture.schemes[idx].clone()));

            // Create monitor
            let monitor = mocks::Monitor::new(epoch);

            // Create automaton with Incorrect strategy for byzantine validators
            let strategy = if incorrect.contains(&idx) {
                mocks::Strategy::Incorrect
            } else {
                mocks::Strategy::Correct
            };
            let automaton = mocks::Application::new(strategy);

            // Create reporter with verifier scheme
            let (reporter, reporter_mailbox) =
                mocks::Reporter::new(context.child("reporter"), fixture.verifier.clone());
            reporter.start();
            reporters.insert(participant.clone(), reporter_mailbox.clone());

            // Create blocker
            let blocker = oracle.control(participant.clone());

            // Create and start engine
            let engine = Engine::new(
                context.child("engine"),
                Config {
                    monitor,
                    provider,
                    automaton,
                    reporter: reporter_mailbox,
                    blocker,
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(rebroadcast_timeout),
                    epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                    window: std::num::NonZeroU64::new(10).unwrap(),
                    activity_timeout: HeightDelta::new(100),
                    journal_partition: format!("aggregation-{participant}"),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                    journal_compression: Some(3),
                    journal_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                    strategy: Sequential,
                },
            );

            let (sender, receiver) = registrations.remove(participant).unwrap();
            engine.start((sender, receiver));
        }

        reporters
    }

    /// Wait for all reporters to reach the specified consensus threshold.
    async fn await_reporters<S: Scheme<Sha256Digest, PublicKey = PublicKey>>(
        context: Context,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>,
        threshold_height: Height,
        threshold_epoch: Epoch,
    ) {
        let mut receivers = Vec::new();
        for (reporter, mailbox) in reporters.iter() {
            // Create a oneshot channel to signal when the reporter has reached the threshold.
            let (tx, rx) = oneshot::channel();
            receivers.push(rx);

            context
                .child("reporter_watcher")
                .with_attribute("reporter", reporter)
                .spawn({
                    let reporter = reporter.clone();
                    let mut mailbox = mailbox.clone();
                    move |context| async move {
                        loop {
                            let (height, epoch) = mailbox
                                .get_tip()
                                .await
                                .unwrap_or((Height::zero(), Epoch::zero()));
                            debug!(
                                %height,
                                epoch = %epoch,
                                %threshold_height,
                                threshold_epoch = %threshold_epoch,
                                ?reporter,
                                "reporter status"
                            );
                            if height >= threshold_height && epoch >= threshold_epoch {
                                debug!(
                                    ?reporter,
                                    "reporter reached threshold, signaling completion"
                                );
                                tx.send_lossy(reporter.clone());
                                break;
                            }
                            context.sleep(Duration::from_millis(100)).await;
                        }
                    }
                });
        }

        // Wait for all oneshot receivers to complete.
        let results = join_all(receivers).await;
        assert_eq!(results.len(), reporters.len());

        // Check that none were cancelled.
        for result in results {
            assert!(result.is_ok(), "reporter was cancelled");
        }
    }

    /// Test aggregation consensus with all validators online.
    fn all_online<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(5),
                vec![],
            );

            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(100),
                epoch,
            )
            .await;
        });
    }

    test_for_all_fixtures!(slow all_online);

    /// Test consensus resilience to Byzantine behavior.
    fn byzantine_proposer<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(5),
                vec![0],
            );

            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(100),
                epoch,
            )
            .await;
        });
    }

    test_for_all_fixtures!(byzantine_proposer);

    fn unclean_byzantine_shutdown<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Test parameters
        let num_validators = 4;
        let target_height = Height::new(200); // Target multiple rounds of signing
        let min_shutdowns = 4; // Minimum number of shutdowns per validator
        let max_shutdowns = 10; // Maximum number of shutdowns per validator
        let shutdown_range_min = Duration::from_millis(100);
        let shutdown_range_max = Duration::from_millis(1_000);
        let rebroadcast_timeout = NonZeroDuration::new_panic(Duration::from_millis(20));

        let mut prev_checkpoint = None;

        // Generate fixture once (persists across restarts)
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, TEST_NAMESPACE, num_validators);

        // Continue until shared reporter reaches target or max shutdowns exceeded
        let mut shutdown_count = 0;
        while shutdown_count < max_shutdowns {
            let fixture = fixture.clone();
            let f = move |mut context: Context| {
                async move {
                    let epoch = Epoch::new(111);

                    let (oracle, mut registrations) =
                        initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK)
                            .await;

                    // Create a shared reporter
                    //
                    // We rely on replay to populate this reporter with a contiguous history of certificates.
                    let (reporter, mut reporter_mailbox) =
                        mocks::Reporter::new(context.child("reporter"), fixture.verifier.clone());
                    reporter.start();

                    // Spawn validator engines
                    for (idx, participant) in fixture.participants.iter().enumerate() {
                        let validator_context = context
                            .child("participant")
                            .with_attribute("public_key", participant);

                        // Create Provider and register scheme for epoch
                        let provider = mocks::Provider::new();
                        assert!(provider.register(epoch, fixture.schemes[idx].clone()));

                        // Create monitor
                        let monitor = mocks::Monitor::new(epoch);

                        // Create automaton (validator 0 is Byzantine)
                        let strategy = if idx == 0 {
                            mocks::Strategy::Incorrect
                        } else {
                            mocks::Strategy::Correct
                        };
                        let automaton = mocks::Application::new(strategy);

                        // Create blocker
                        let blocker = oracle.control(participant.clone());

                        // Create and start engine
                        let engine = Engine::new(
                            validator_context.child("engine"),
                            Config {
                                monitor,
                                provider,
                                automaton,
                                reporter: reporter_mailbox.clone(),
                                blocker,
                                priority_acks: false,
                                rebroadcast_timeout,
                                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                                window: std::num::NonZeroU64::new(10).unwrap(),
                                activity_timeout: HeightDelta::new(1_024), // ensure we don't drop any certificates
                                journal_partition: format!("unclean_shutdown_test_{participant}"),
                                journal_write_buffer: NZUsize!(4096),
                                journal_replay_buffer: NZUsize!(4096),
                                journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                                journal_compression: Some(3),
                                journal_page_cache: CacheRef::from_pooler(
                                    &context,
                                    PAGE_SIZE,
                                    PAGE_CACHE_SIZE,
                                ),
                                strategy: Sequential,
                            },
                        );

                        let (sender, receiver) = registrations.remove(participant).unwrap();
                        engine.start((sender, receiver));
                    }

                    // Create a single completion watcher for the shared reporter
                    let completion =
                        context
                            .child("completion_watcher")
                            .spawn(move |context| async move {
                                loop {
                                    if let Some(tip_height) =
                                        reporter_mailbox.get_contiguous_tip().await
                                    {
                                        if tip_height >= target_height {
                                            break;
                                        }
                                    }
                                    context.sleep(Duration::from_millis(50)).await;
                                }
                            });

                    // Random shutdown timing to simulate unclean shutdown
                    let shutdown_wait =
                        context.random_range(shutdown_range_min..shutdown_range_max);
                    select! {
                        _ = context.sleep(shutdown_wait) => {
                            debug!(shutdown_wait = ?shutdown_wait, "Simulating unclean shutdown");
                            false // Unclean shutdown
                        },
                        _ = completion => {
                            debug!("Shared reporter completed normally");
                            true // Clean completion
                        },
                    }
                }
            };

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || {
                        debug!("Starting initial run");
                        deterministic::Runner::timed(Duration::from_secs(45))
                    },
                    |prev_checkpoint| {
                        debug!(shutdown_count, "Restarting from previous context");
                        deterministic::Runner::from(prev_checkpoint)
                    },
                )
                .start_and_recover(f);

            if complete && shutdown_count >= min_shutdowns {
                debug!("Test completed successfully");
                break;
            }

            prev_checkpoint = Some(checkpoint);
            shutdown_count += 1;
        }
    }

    test_for_all_fixtures!(slow unclean_byzantine_shutdown);

    fn unclean_shutdown_with_unsigned_height<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Test parameters
        let num_validators = 4;
        let skip_height = Height::new(50); // Height where no one will sign
        let window = HeightDelta::new(10);
        let target_height = Height::new(100);

        // Generate fixture once (persists across restarts)
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, TEST_NAMESPACE, num_validators);

        // First run: let validators skip signing at skip_height and reach beyond it
        let f = |context: Context| {
            let fixture = fixture.clone();
            async move {
                let epoch = Epoch::new(111);

                // Set up simulated network
                let (oracle, mut registrations) =
                    initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK)
                        .await;

                // Create a shared reporter
                let (reporter, mut reporter_mailbox) =
                    mocks::Reporter::new(context.child("reporter"), fixture.verifier.clone());
                reporter.start();

                // Start validator engines with Skip strategy for skip_height
                for (idx, participant) in fixture.participants.iter().enumerate() {
                    let validator_context = context
                        .child("participant")
                        .with_attribute("public_key", participant);

                    // Create Provider and register scheme for epoch
                    let provider = mocks::Provider::new();
                    assert!(provider.register(epoch, fixture.schemes[idx].clone()));

                    // Create monitor
                    let monitor = mocks::Monitor::new(epoch);

                    // All validators use Skip strategy for skip_height
                    let automaton = mocks::Application::new(mocks::Strategy::Skip {
                        height: skip_height,
                    });

                    // Create blocker
                    let blocker = oracle.control(participant.clone());

                    // Create and start engine
                    let engine = Engine::new(
                        validator_context.child("engine"),
                        Config {
                            monitor,
                            provider,
                            automaton,
                            reporter: reporter_mailbox.clone(),
                            blocker,
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
                                100,
                            )),
                            epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                            window: std::num::NonZeroU64::new(window.get()).unwrap(),
                            activity_timeout: HeightDelta::new(100),
                            journal_partition: format!("unsigned_height_test_{participant}"),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                            journal_compression: Some(3),
                            journal_page_cache: CacheRef::from_pooler(
                                &context,
                                PAGE_SIZE,
                                PAGE_CACHE_SIZE,
                            ),
                            strategy: Sequential,
                        },
                    );

                    let (sender, receiver) = registrations.remove(participant).unwrap();
                    engine.start((sender, receiver));
                }

                // Wait for validators to reach target_height (past skip_height)
                loop {
                    if let Some((tip_height, _)) = reporter_mailbox.get_tip().await {
                        debug!(%tip_height, %skip_height, %target_height, "reporter status");
                        if tip_height >= skip_height.saturating_add(window).previous().unwrap() {
                            // max we can proceed before item confirmed
                            return;
                        }
                    }
                    context.sleep(Duration::from_millis(50)).await;
                }
            }
        };

        let (_, checkpoint) =
            deterministic::Runner::timed(Duration::from_secs(60)).start_and_recover(f);

        // Second run: restart and verify the skip_height gets confirmed
        let f2 = |context: Context| {
            async move {
                let epoch = Epoch::new(111);

                // Set up simulated network
                let (oracle, mut registrations) =
                    initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK)
                        .await;

                // Create a shared reporter
                let (reporter, mut reporter_mailbox) =
                    mocks::Reporter::new(context.child("reporter"), fixture.verifier.clone());
                reporter.start();

                // Start validator engines with Correct strategy (will sign everything now)
                for (idx, participant) in fixture.participants.iter().enumerate() {
                    let validator_context = context
                        .child("participant")
                        .with_attribute("public_key", participant);

                    // Create Provider and register scheme for epoch
                    let provider = mocks::Provider::new();
                    assert!(provider.register(epoch, fixture.schemes[idx].clone()));

                    // Create monitor
                    let monitor = mocks::Monitor::new(epoch);

                    // Now all validators use Correct strategy
                    let automaton = mocks::Application::new(mocks::Strategy::Correct);

                    // Create blocker
                    let blocker = oracle.control(participant.clone());

                    // Create and start engine
                    let engine = Engine::new(
                        validator_context.child("engine"),
                        Config {
                            monitor,
                            provider,
                            automaton,
                            reporter: reporter_mailbox.clone(),
                            blocker,
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
                                100,
                            )),
                            epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                            window: std::num::NonZeroU64::new(10).unwrap(),
                            activity_timeout: HeightDelta::new(100),
                            journal_partition: format!("unsigned_height_test_{participant}"),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                            journal_compression: Some(3),
                            journal_page_cache: CacheRef::from_pooler(
                                &context,
                                PAGE_SIZE,
                                PAGE_CACHE_SIZE,
                            ),
                            strategy: Sequential,
                        },
                    );

                    let (sender, receiver) = registrations.remove(participant).unwrap();
                    engine.start((sender, receiver));
                }

                // Wait for skip_height to be confirmed (should happen on replay)
                loop {
                    if let Some(tip_height) = reporter_mailbox.get_contiguous_tip().await {
                        debug!(
                            %tip_height,
                            %skip_height, %target_height, "reporter status on restart"
                        );
                        if tip_height >= target_height {
                            break;
                        }
                    }
                    context.sleep(Duration::from_millis(50)).await;
                }
            }
        };

        deterministic::Runner::from(checkpoint).start(f2);
    }

    test_for_all_fixtures!(slow unclean_shutdown_with_unsigned_height);

    fn slow_and_lossy_links_seeded<S, F>(fixture: F, seed: u64) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            // Use degraded network links with realistic conditions
            let degraded_link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.5,
            };

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, degraded_link).await;

            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(2),
                vec![],
            );

            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(100),
                epoch,
            )
            .await;

            context.auditor().state()
        })
    }

    fn slow_and_lossy_links<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        slow_and_lossy_links_seeded(fixture, 0);
    }

    test_for_all_fixtures!(slow slow_and_lossy_links);

    fn determinism<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S> + Copy,
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

    test_for_all_fixtures!(slow determinism);

    #[test_group("slow")]
    #[test_traced("INFO")]
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

    fn one_offline<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let num_validators = 5;
            let mut fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            // Truncate to only 4 validators (one offline)
            fixture.participants.truncate(4);
            fixture.schemes.truncate(4);

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(5),
                vec![],
            );

            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(100),
                epoch,
            )
            .await;
        });
    }

    test_for_all_fixtures!(slow one_offline);

    /// Test consensus recovery after a network partition.
    fn network_partition<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let num_validators = 4;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK).await;

            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(5),
                vec![],
            );

            // Partition network (remove all links)
            for v1 in fixture.participants.iter() {
                for v2 in fixture.participants.iter() {
                    if v2 == v1 {
                        continue;
                    }
                    oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                }
            }
            context.sleep(Duration::from_secs(20)).await;

            // Restore network links
            for v1 in fixture.participants.iter() {
                for v2 in fixture.participants.iter() {
                    if v2 == v1 {
                        continue;
                    }
                    oracle
                        .add_link(v1.clone(), v2.clone(), RELIABLE_LINK)
                        .await
                        .unwrap();
                }
            }

            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(100),
                epoch,
            )
            .await;
        });
    }

    test_for_all_fixtures!(network_partition);

    /// Test insufficient validator participation (below quorum).
    fn insufficient_validators<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let runner = deterministic::Runner::timed(Duration::from_secs(15));

        runner.start(|mut context| async move {
            let num_validators = 5;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            // Set up simulated network
            let (oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, RELIABLE_LINK)
                    .await;

            // Create reporters (one per online validator)
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

            // Start only 2 out of 5 validators (below quorum of 3)
            for (idx, participant) in fixture.participants.iter().take(2).enumerate() {
                let context = context.child("participant").with_attribute("public_key", participant);

                // Create Provider and register scheme for epoch
                let provider = mocks::Provider::new();
                assert!(provider.register(epoch, fixture.schemes[idx].clone()));

                // Create monitor
                let monitor = mocks::Monitor::new(epoch);

                // Create automaton with Correct strategy
                let automaton = mocks::Application::new(mocks::Strategy::Correct);

                // Create reporter with verifier scheme
                let (reporter, reporter_mailbox) =
                    mocks::Reporter::new(context.child("reporter"), fixture.verifier.clone());
                reporter.start();
                reporters.insert(participant.clone(), reporter_mailbox.clone());

                // Create blocker
                let blocker = oracle.control(participant.clone());

                // Create and start engine
                let engine = Engine::new(
                    context.child("engine"),
                    Config {
                        monitor,
                        provider,
                        automaton,
                        reporter: reporter_mailbox,
                        blocker,
                        priority_acks: false,
                        rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(3)),
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        window: std::num::NonZeroU64::new(10).unwrap(),
                        activity_timeout: HeightDelta::new(100),
                        journal_partition: format!("aggregation-{participant}"),
                        journal_write_buffer: NZUsize!(4096),
                        journal_replay_buffer: NZUsize!(4096),
                        journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                        journal_compression: Some(3),
                        journal_page_cache: CacheRef::from_pooler(
                            &context,
                            PAGE_SIZE,
                            PAGE_CACHE_SIZE,
                        ),
                        strategy: Sequential,
                    },
                );

                let (sender, receiver) = registrations.remove(participant).unwrap();
                engine.start((sender, receiver));
            }

            // With insufficient validators, consensus should not be achievable
            // Wait long enough for any potential consensus attempts to complete
            context.sleep(Duration::from_secs(12)).await;

            // Check that no validator achieved consensus
            let mut any_consensus = false;
            for (validator_pk, mut reporter_mailbox) in reporters {
                let (tip, _) = reporter_mailbox
                    .get_tip()
                    .await
                    .unwrap_or((Height::zero(), Epoch::zero()));
                if !tip.is_zero() {
                    any_consensus = true;
                    tracing::warn!(
                        ?validator_pk,
                        %tip,
                        "Unexpected consensus with insufficient validators"
                    );
                }
            }

            // With only 2 out of 5 validators (below quorum of 3), consensus should not succeed
            assert!(
                !any_consensus,
                "Consensus should not be achieved with insufficient validator participation (below quorum)"
            );
        });
    }

    test_for_all_fixtures!(insufficient_validators);

    fn run_1k<S, F>(fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnOnce(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let cfg = deterministic::Config::new();
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            // Create validators
            let num_validators = 10;
            let fixture = fixture(&mut context, TEST_NAMESPACE, num_validators);
            let epoch = Epoch::new(111);

            // Configure a delayed, lossy link
            let delayed_link = Link {
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };

            // Initialize the simulated network
            let (mut oracle, mut registrations) =
                initialize_simulation(context.child("simulation"), &fixture, delayed_link).await;

            // Start all validators
            let reporters = spawn_validator_engines(
                context.child("validator"),
                &fixture,
                &mut registrations,
                &mut oracle,
                epoch,
                Duration::from_secs(5),
                vec![],
            );

            // Wait for every validator to recover 1,000 certificates
            await_reporters(
                context.child("reporter"),
                &reporters,
                Height::new(1_000),
                epoch,
            )
            .await;
        });
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k() {
        run_1k(mocks::scheme::fixture);
    }
}
