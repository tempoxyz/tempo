mod actor;
mod ingress;
mod round;
mod verifier;

use crate::{
    simplex::config::ForwardingPolicy,
    types::{Epoch, ViewDelta},
    Relay, Reporter,
};
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
pub use ingress::{Mailbox, Message};
pub use round::Round;
use std::num::NonZeroUsize;
pub use verifier::Verifier;

pub struct Config<S: Scheme, B: Blocker, Re: Reporter, Rl: Relay, T: Strategy> {
    pub scheme: S,

    pub blocker: B,
    pub reporter: Re,
    pub relay: Rl,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,
    pub forwarding: ForwardingPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            actors::voter,
            config::ForwardingPolicy,
            elector::RoundRobin,
            metrics::TimeoutReason,
            mocks, quorum,
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1, Scheme,
            },
            types::{
                Activity, Certificate, Finalization, Finalize, Notarization, Notarize,
                Nullification, Nullify, Proposal, Vote,
            },
            Plan,
        },
        types::{Epoch, Participant, Round, View},
        Viewable,
    };
    use commonware_actor::{mailbox, Feedback};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Hasher as _, Sha256, Signer,
    };
    use commonware_macros::{select, test_collect_traces, test_traced};
    use commonware_p2p::{
        simulated::{Config as NConfig, Link, Network, Oracle},
        Manager as _, Recipients, Sender as _, TrackedPeers,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        deterministic,
        telemetry::traces::{collector::TraceStorage, TracedExt as _},
        tokio, Clock, Metrics as _, Quota, Runner, Strategizer as _, Supervisor as _,
    };
    use commonware_utils::{ordered::Set, sync::Mutex, test_rng, NZUsize, TestRng};
    use std::{marker::PhantomData, num::NonZeroU32, sync::Arc, time::Duration};
    use tracing::{Level, Span};

    type Broadcasts = Arc<Mutex<Vec<(Sha256Digest, Round, Vec<PublicKey>)>>>;

    /// No-op relay for batcher tests that records targeted broadcasts.
    #[derive(Clone)]
    struct MockRelay {
        broadcasts: Broadcasts,
    }

    impl MockRelay {
        fn new() -> Self {
            Self {
                broadcasts: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl crate::Relay for MockRelay {
        type Digest = Sha256Digest;
        type PublicKey = PublicKey;
        type Plan = Plan<PublicKey>;

        fn broadcast(&mut self, payload: Sha256Digest, plan: Self::Plan) -> Feedback {
            if let Plan::Forward {
                round,
                recipients: Recipients::Some(peers),
            } = plan
            {
                self.broadcasts.lock().push((payload, round, peers));
            }
            Feedback::Ok
        }
    }

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    async fn start_test_network_with_peers<I>(
        context: deterministic::Context,
        peers: I,
    ) -> Oracle<PublicKey, deterministic::Context>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        oracle
    }

    async fn track_test_peers(
        context: &mut deterministic::Context,
        oracle: &commonware_p2p::simulated::Oracle<PublicKey, deterministic::Context>,
        id: u64,
        primary: &[PublicKey],
        secondary: &[PublicKey],
    ) {
        oracle.manager().track(
            id,
            TrackedPeers::new(
                Set::from_iter_dedup(primary.iter().cloned()),
                Set::from_iter_dedup(secondary.iter().cloned()),
            ),
        );
        context.sleep(Duration::from_millis(10)).await;
    }

    async fn expect_timeout<S: Scheme<Sha256Digest>>(
        context: &mut deterministic::Context,
        voter_receiver: &mut mailbox::Receiver<voter::Message<S, Sha256Digest>>,
        expected_view: View,
        expected_reason: TimeoutReason,
    ) {
        loop {
            select! {
                message = voter_receiver.recv() => match message {
                    Some(voter::Message::Timeout { round, reason, .. }) => {
                        assert_eq!(round.view(), expected_view);
                        assert_eq!(reason, expected_reason);
                        break;
                    }
                    Some(_) => {}
                    None => panic!("voter receiver closed"),
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("timed out waiting for voter timeout");
                },
            }
        }
    }

    async fn expect_no_timeout<S: Scheme<Sha256Digest>>(
        context: &mut deterministic::Context,
        voter_receiver: &mut mailbox::Receiver<voter::Message<S, Sha256Digest>>,
    ) {
        loop {
            select! {
                message = voter_receiver.recv() => match message {
                    Some(voter::Message::Timeout { round, reason, .. }) => {
                        panic!(
                            "unexpected voter timeout for view {}: {reason:?}",
                            round.view()
                        );
                    }
                    Some(_) => {}
                    None => panic!("voter receiver closed"),
                },
                _ = context.sleep(Duration::from_millis(50)) => break,
            }
        }
    }

    fn build_notarization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Notarization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(&schemes[0], &votes, &Sequential)
            .expect("notarization requires a quorum of votes")
    }

    fn build_nullification<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        round: Round,
        count: usize,
    ) -> Nullification<S> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(&schemes[0], &votes, &Sequential)
            .expect("nullification requires a quorum of votes")
    }

    fn build_finalization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: usize,
    ) -> Finalization<S, Sha256Digest> {
        let votes: Vec<_> = schemes
            .iter()
            .take(count)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(&schemes[0], &votes, &Sequential)
            .expect("finalization requires a quorum of votes")
    }

    /// A blocker that drops all block requests.
    #[derive(Clone)]
    struct NoopBlocker;

    impl commonware_p2p::Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }
    }

    /// A reporter that drops all activity.
    struct NoopReporter<S>(PhantomData<S>);

    impl<S> Clone for NoopReporter<S> {
        fn clone(&self) -> Self {
            Self(PhantomData)
        }
    }

    impl<S: Scheme<Sha256Digest>> crate::Reporter for NoopReporter<S> {
        type Activity = Activity<S, Sha256Digest>;

        fn report(&mut self, _: Self::Activity) -> Feedback {
            Feedback::Ok
        }
    }

    /// Drives a full quorum of network votes through a [Round]'s batch-verify and
    /// certificate-recovery offloads using `strategy`.
    async fn verify_and_construct<S, F>(mut fixture: F, strategy: impl Strategy)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            verifier,
            ..
        } = fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
        );

        // Route a quorum of notarizes through the round as network votes.
        let proposal = Proposal::new(round_id, View::new(0), Sha256::hash(b"payload"));
        round.set_leader(Participant::from_usize(0));
        for (i, scheme) in schemes.iter().enumerate() {
            let notarize = Notarize::sign(scheme, proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Notarize(notarize)));
        }

        // Batch verify the pending votes on the strategy's pool.
        assert!(round.ready_notarizes());
        let (batch, invalid) = round.verify_notarizes(&mut rng, &strategy).await;
        assert_eq!(batch, schemes.len());
        assert!(invalid.is_empty());

        // Recover the certificate on the strategy's pool.
        let notarization = round
            .try_construct_notarization(&strategy)
            .await
            .expect("verified quorum must construct a notarization");
        assert_eq!(notarization.proposal, proposal);
        assert!(notarization.verify(&mut rng, &verifier, &Sequential));

        // Construction is one-shot per round.
        assert!(round.try_construct_notarization(&strategy).await.is_none());
    }

    /// Deterministic-runtime tests drive `Strategy::spawn` inline: the deterministic runtime's
    /// shared pool is single-threaded, so `Rayon::spawn` short-circuits to the calling thread.
    /// This test runs the batcher's offload paths on the tokio runtime with a two-worker pool,
    /// so jobs execute on pool threads and completion must wake the awaiting task across threads.
    #[test_traced]
    fn test_offload_on_multithreaded_pool() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let strategy = context.strategy(NZUsize!(2));
            verify_and_construct(
                bls12381_threshold_vrf::fixture::<MinPk, _>,
                strategy.clone(),
            )
            .await;
            verify_and_construct(bls12381_multisig::fixture::<MinSig, _>, strategy.clone()).await;
            verify_and_construct(ed25519::fixture, strategy.clone()).await;
            verify_and_construct(secp256r1::fixture, strategy).await;
        });
    }

    fn certificate_forwarding_from_network<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Create a peer to inject certificates
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Set up link from injector to batcher
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(0), View::zero(), None);

            // Build certificates
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            let notarization = build_notarization(&schemes, &proposal, quorum);
            let nullification = build_nullification(&schemes, round, quorum);
            let finalization = build_finalization(&schemes, &proposal, quorum);

            // Send notarization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view)
            );

            // Send nullification from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification.clone())
                        .encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Nullification(n), .. } if n.view() == view)
            );

            // Send finalization from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Finalization(finalization.clone()).encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Finalization(f), .. } if f.view() == view)
            );
        });
    }

    #[test_traced]
    fn test_certificate_forwarding_from_network() {
        certificate_forwarding_from_network(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certificate_forwarding_from_network(bls12381_threshold_std::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_threshold_std::fixture::<MinSig, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinPk, _>);
        certificate_forwarding_from_network(bls12381_multisig::fixture::<MinSig, _>);
        certificate_forwarding_from_network(ed25519::fixture);
        certificate_forwarding_from_network(secp256r1::fixture);
    }

    /// Regression: an old notarization for view `V` is still forwarded to voter even
    /// after a nullification for `V` has been observed and current view moved to `V+1`.
    fn old_notarization_after_nullification_is_forwarded<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_old_notarization_after_nullification".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network.
            // Get participants.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock.
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor.
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to.
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Create a peer to inject certificates.
            let injector_pk = PrivateKey::from_seed(1_000_001).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Set up link from injector to batcher.
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            // Start the batcher.
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher at target view.
            let target_view = View::new(1);
            batcher_mailbox
                .update(Span::none(), target_view, Participant::new(0), View::zero(), None);

            // Build certificates for the same target view.
            let round = Round::new(epoch, target_view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let nullification = build_nullification(&schemes, round, quorum_size);
            let notarization = build_notarization(&schemes, &proposal, quorum_size);

            // Send nullification for V first.
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Nullification(n), .. } if n.view() == target_view)
            );

            // Simulate voter-driven view advance after nullification to V+1.
            batcher_mailbox
                .update(Span::none(), target_view.next(), Participant::new(1), View::zero(), None);

            // Send old notarization for V after moving current view forward.
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            // Old notarization must still be forwarded to voter.
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == target_view)
            );
        });
    }

    #[test_traced]
    fn test_old_notarization_after_nullification_is_forwarded() {
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        old_notarization_after_nullification_is_forwarded(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        old_notarization_after_nullification_is_forwarded(bls12381_multisig::fixture::<MinPk, _>);
        old_notarization_after_nullification_is_forwarded(bls12381_multisig::fixture::<MinSig, _>);
        old_notarization_after_nullification_is_forwarded(ed25519::fixture);
        old_notarization_after_nullification_is_forwarded(secp256r1::fixture);
    }

    fn quorum_votes_construct_certificate<S, F>(mut fixture: F, traces: TraceStorage)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    // Batcher is participant 0, skip
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            // (so we can test leader proposal forwarding when vote arrives from network)
            let view = View::new(1);
            let leader = Participant::new(1);
            let span = tracing::info_span!(
                parent: None,
                "simplex.voter.view",
                epoch = epoch.traced(),
                view = view.traced()
            );
            batcher_mailbox.update(span, view, leader, View::zero(), None);

            // Build proposal and votes
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send notarize votes from participants 1..quorum_size (excluding participant 0)
            // Participant 0's vote will be sent via mailbox.constructed()
            // Participant 1 is the leader, so their vote triggers proposal forwarding
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own vote via constructed message
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote));

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(100)).await;

            // Should receive the leader's proposal first (participant 1 is leader)
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(b"test_payload"))
            );

            // Should receive notarization certificate from quorum of votes
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view));

            // ForwardingPolicy::Disabled must not produce any broadcasts
            assert!(
                relay.broadcasts.lock().is_empty(),
                "disabled forwarding should produce no broadcasts"
            );

            // Batch verification and certificate construction are attributed
            // to the view span adopted from the update.
            traces
                .get_by_level(Level::TRACE)
                .expect_event(|event| {
                    event.metadata.content == "batch verified votes"
                        && event
                            .expect_span_at_index(0, |span| {
                                span.expect_content_exact("simplex.voter.view")
                            })
                            .is_ok()
                })
                .unwrap();
            traces
                .get_by_level(Level::DEBUG)
                .expect_event(|event| {
                    event.metadata.content == "constructed notarization, forwarding to voter"
                        && event
                            .expect_span_at_index(0, |span| {
                                span.expect_content_exact("simplex.voter.view")
                            })
                            .is_ok()
                })
                .unwrap();
        });
    }

    macro_rules! quorum_votes_construct_certificate_test {
        ($name:ident, $fixture:path) => {
            #[test_collect_traces]
            fn $name(traces: TraceStorage) {
                quorum_votes_construct_certificate($fixture, traces);
            }
        };
    }

    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_threshold_vrf_min_pk,
        bls12381_threshold_vrf::fixture::<MinPk, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_threshold_vrf_min_sig,
        bls12381_threshold_vrf::fixture::<MinSig, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_threshold_std_min_pk,
        bls12381_threshold_std::fixture::<MinPk, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_threshold_std_min_sig,
        bls12381_threshold_std::fixture::<MinSig, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_multisig_min_pk,
        bls12381_multisig::fixture::<MinPk, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_bls12381_multisig_min_sig,
        bls12381_multisig::fixture::<MinSig, _>
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_ed25519,
        ed25519::fixture
    );
    quorum_votes_construct_certificate_test!(
        test_quorum_votes_construct_certificate_secp256r1,
        secp256r1::fixture
    );

    /// Test that constructing a notarization does not forward immediately, but
    /// entering the next view with an explicit forwardable proposal does.
    fn forward_emitted_on_view_advance_with_forwardable_proposal<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_forwarding".to_vec();
        let epoch = Epoch::new(1);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentVoters,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Register network participants and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Only quorum_size participants (0..quorum_size) vote, leaving
            // participants quorum_size..n without votes.
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send notarize votes from participants 1..quorum_size via network
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own vote (participant 0) via constructed
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote));

            // Give the batcher time to process and construct the notarization.
            context.sleep(Duration::from_millis(100)).await;

            // Drain voter messages (proposal + notarization)
            let _ = voter_receiver.recv().await.unwrap();
            let _ = voter_receiver.recv().await.unwrap();

            {
                let broadcasts = relay.broadcasts.lock();
                assert!(
                    broadcasts.is_empty(),
                    "notarization alone should not trigger forwarding"
                );
            }

            // Advancing to the next view with this proposal marked
            // forwardable should trigger exactly one targeted forward.
            batcher_mailbox.update(
                Span::none(),
                View::new(2),
                Participant::new(2),
                View::zero(),
                Some(proposal.clone()),
            );
            context.sleep(Duration::from_millis(50)).await;

            // Participants 0..3 voted for this proposal, so only participant 4
            // should remain in the forwarding set.
            let broadcasts = relay.broadcasts.lock();
            assert_eq!(
                broadcasts.len(),
                1,
                "expected exactly one targeted broadcast"
            );
            let (ref digest, forwarded_round, ref peers) = broadcasts[0];
            assert_eq!(*digest, proposal.payload);
            assert_eq!(forwarded_round, proposal.round);
            assert_eq!(peers, &vec![participants[4].clone()]);
        });
    }

    #[test_traced]
    fn test_forward_emitted_on_view_advance_with_forwardable_proposal() {
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        forward_emitted_on_view_advance_with_forwardable_proposal(ed25519::fixture);
        forward_emitted_on_view_advance_with_forwardable_proposal(secp256r1::fixture);
    }

    /// Test that `SilentLeader` forwards only to the newly entered leader, and
    /// only when that leader's matching vote was not observed locally.
    fn silent_leader_forwarding_respects_missing_vote<S, F>(mut fixture: F, leader_voted: bool)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_silent_leader_forwarding".to_vec();
        let epoch = Epoch::new(101);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentLeader,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Enter view 1 under participant 1, then advance to participant 2
            // as the next leader so the policy has a single candidate target.
            let view = View::new(1);
            let next_leader = Participant::new(2);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let proposal = Proposal::new(
                Round::new(epoch, view),
                View::zero(),
                Sha256::hash(b"silent_leader_payload"),
            );

            // Toggle whether the next leader appears in the observed vote set.
            let voter_indices: &[usize] = if leader_voted { &[1, 2, 3] } else { &[1, 3, 4] };
            for &i in voter_indices {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote));

            // Wait until the batcher has a notarization for the proposal. That
            // alone should still not emit any targeted forward.
            let mut saw_notarization = false;
            loop {
                let output = select! {
                    output = voter_receiver.recv() => output,
                    _ = context.sleep(Duration::from_millis(100)) => None,
                };
                let Some(output) = output else {
                    break;
                };
                if matches!(
                    output,
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view
                ) {
                    saw_notarization = true;
                    break;
                }
            }
            assert!(saw_notarization, "expected notarization");

            {
                let broadcasts = relay.broadcasts.lock();
                assert!(
                    broadcasts.is_empty(),
                    "notarization alone should not trigger forwarding"
                );
            }

            // `SilentLeader` forwarding should either target only participant 2
            // or nobody, depending on whether that vote was observed above.
            batcher_mailbox.update(
                Span::none(),
                View::new(2),
                next_leader,
                View::zero(),
                Some(proposal.clone()),
            );
            context.sleep(Duration::from_millis(50)).await;

            // If the next leader already voted for this proposal, there should
            // be no forward. Otherwise the only target should be participant 2.
            let broadcasts = relay.broadcasts.lock();
            if leader_voted {
                assert!(
                    broadcasts.is_empty(),
                    "next leader should not be forwarded to when their vote was observed"
                );
            } else {
                assert_eq!(
                    broadcasts.len(),
                    1,
                    "expected exactly one targeted broadcast"
                );
                let (ref digest, forwarded_round, ref peers) = broadcasts[0];
                assert_eq!(*digest, proposal.payload);
                assert_eq!(forwarded_round, proposal.round);
                assert_eq!(peers, &vec![participants[2].clone()]);
            }
        });
    }

    #[test_traced]
    fn test_silent_leader_forwarding_targets_missing_leader() {
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_std::fixture::<MinPk, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_std::fixture::<MinSig, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_multisig::fixture::<MinPk, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_multisig::fixture::<MinSig, _>,
            false,
        );
        silent_leader_forwarding_respects_missing_vote(ed25519::fixture, false);
        silent_leader_forwarding_respects_missing_vote(secp256r1::fixture, false);
    }

    #[test_traced]
    fn test_silent_leader_forwarding_skips_observed_leader() {
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_std::fixture::<MinPk, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_threshold_std::fixture::<MinSig, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_multisig::fixture::<MinPk, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(
            bls12381_multisig::fixture::<MinSig, _>,
            true,
        );
        silent_leader_forwarding_respects_missing_vote(ed25519::fixture, true);
        silent_leader_forwarding_respects_missing_vote(secp256r1::fixture, true);
    }

    /// Test that a network notarization waits until the next-view update marks
    /// the previous proposal as certified before forwarding the block.
    fn forward_emitted_for_network_notarization_on_view_advance<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_network_notarization_forwarding".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentVoters,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            let injector_pk = PrivateKey::from_seed(2_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(injector_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Send sub-quorum votes for view 1, then inject a network
            // notarization. The batcher should wait for local finalize and the
            // next-view transition before forwarding to peers whose matching
            // vote was not observed locally.
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let proposal = Proposal::new(
                Round::new(epoch, view),
                View::zero(),
                Sha256::hash(b"payload"),
            );
            for i in 1..(quorum_size - 1) {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote));

            // The injected certificate completes notarization, but forwarding
            // still waits for the next view to mark the proposal forwardable.
            let notarization = build_notarization(&schemes, &proposal, quorum_size);
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization).encode(),
                    true,
                );

            let mut saw_notarization = false;
            loop {
                let output = select! {
                    output = voter_receiver.recv() => output,
                    _ = context.sleep(Duration::from_millis(100)) => None,
                };
                let Some(output) = output else {
                    break;
                };
                if matches!(
                    output,
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view
                ) {
                    saw_notarization = true;
                    break;
                }
            }
            assert!(
                saw_notarization,
                "expected notarization from certificate_receiver"
            );

            {
                let broadcasts = relay.broadcasts.lock();
                assert!(
                    broadcasts.is_empty(),
                    "network notarization alone should not trigger forwarding"
                );
            }

            // Only participants 3 and 4 missed a matching vote, so only they
            // should be targeted after the view advance.
            batcher_mailbox.update(
                Span::none(),
                View::new(2),
                Participant::new(2),
                View::zero(),
                Some(proposal.clone()),
            );
            context.sleep(Duration::from_millis(50)).await;

            let broadcasts = relay.broadcasts.lock();
            assert_eq!(
                broadcasts.len(),
                1,
                "expected exactly one targeted broadcast"
            );
            let (ref digest, forwarded_round, ref peers) = broadcasts[0];
            assert_eq!(*digest, proposal.payload);
            assert_eq!(forwarded_round, proposal.round);
            assert_eq!(
                peers,
                &vec![participants[3].clone(), participants[4].clone()]
            );
        });
    }

    #[test_traced]
    fn test_forward_emitted_for_network_notarization_on_view_advance() {
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        forward_emitted_for_network_notarization_on_view_advance(ed25519::fixture);
        forward_emitted_for_network_notarization_on_view_advance(secp256r1::fixture);
    }

    /// Regression: when forwarding a certificate-only proposal, the batcher
    /// must not target itself even though no local matching vote was observed.
    fn self_excluded_from_forward_targets<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_self_excluded_forward_targets".to_vec();
        let epoch = Epoch::new(444);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentVoters,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let injector_pk = PrivateKey::from_seed(3_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(injector_pk.clone(), me.clone(), link)
                .await
                .unwrap();
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Enter view 1 without constructing or receiving any matching
            // votes. The batcher should learn this proposal only from the
            // certificate injected below.
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            // Build and inject a notarization from the network so the batcher
            // sees a certificate-only proposal. Without the self-filter, it
            // would treat every participant as missing, including itself.
            let proposal = Proposal::new(
                Round::new(epoch, view),
                View::zero(),
                Sha256::hash(b"certificate_only_payload"),
            );
            let notarization = build_notarization(&schemes, &proposal, quorum_size);
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization).encode(),
                    true,
                );

            // Wait until the batcher has recovered the notarization from the
            // certificate path before advancing to the next view.
            let mut saw_notarization = false;
            loop {
                let output = select! {
                    output = voter_receiver.recv() => output,
                    _ = context.sleep(Duration::from_millis(100)) => None,
                };
                let Some(output) = output else {
                    break;
                };
                if matches!(
                    output,
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view
                ) {
                    saw_notarization = true;
                    break;
                }
            }
            assert!(
                saw_notarization,
                "expected notarization from certificate_receiver"
            );

            // Mark the previous view as forwardable and advance views. This
            // exercises the forwarding path that resolves missing peers from
            // the certificate-only proposal.
            batcher_mailbox.update(
                Span::none(),
                View::new(2),
                Participant::new(2),
                View::zero(),
                Some(proposal.clone()),
            );
            context.sleep(Duration::from_millis(50)).await;

            // Only remote participants should be targeted once the previous
            // view is marked forwardable.
            let broadcasts = relay.broadcasts.lock();
            assert_eq!(
                broadcasts.len(),
                1,
                "expected exactly one targeted broadcast"
            );
            let (ref digest, forwarded_round, ref peers) = broadcasts[0];
            assert_eq!(*digest, proposal.payload);
            assert_eq!(forwarded_round, proposal.round);
            assert_eq!(peers, &participants[1..].to_vec());
            assert!(
                !peers.contains(&participants[0]),
                "batcher must not target itself when forwarding"
            );
        });
    }

    #[test_traced]
    fn test_self_excluded_from_forward_targets() {
        self_excluded_from_forward_targets(bls12381_threshold_vrf::fixture::<MinPk, _>);
        self_excluded_from_forward_targets(bls12381_threshold_vrf::fixture::<MinSig, _>);
        self_excluded_from_forward_targets(bls12381_threshold_std::fixture::<MinPk, _>);
        self_excluded_from_forward_targets(bls12381_threshold_std::fixture::<MinSig, _>);
        self_excluded_from_forward_targets(bls12381_multisig::fixture::<MinPk, _>);
        self_excluded_from_forward_targets(bls12381_multisig::fixture::<MinSig, _>);
        self_excluded_from_forward_targets(ed25519::fixture);
        self_excluded_from_forward_targets(secp256r1::fixture);
    }

    /// Regression: a peer that voted for a conflicting proposal still needs the
    /// leader proposal forwarded if it did not vote for the winning notarization.
    fn conflicting_notarize_voter_is_forwarded<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 7;
        let namespace = b"batcher_conflicting_notarize_forwarding".to_vec();
        let epoch = Epoch::new(444);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentVoters,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // View 2: participant 2 votes for a conflicting proposal and should
            // still be considered missing for forwarding the leader proposal.
            let view2 = View::new(2);
            let leader2 = Participant::new(1);
            batcher_mailbox.update(Span::none(), view2, leader2, View::zero(), None);

            let round2 = Round::new(epoch, view2);
            let proposal_a = Proposal::new(round2, View::new(1), Sha256::hash(b"proposal_a"));
            let proposal_b = Proposal::new(round2, View::new(1), Sha256::hash(b"proposal_b"));

            let leader_vote = Notarize::sign(&schemes[1], proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(leader_vote).encode(),
                        true,
                    );
            }

            let active_nullify = Nullify::sign::<Sha256Digest>(&schemes[6], round2).unwrap();
            if let Some(ref mut sender) = participant_senders[6] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(active_nullify).encode(),
                        true,
                    );
            }

            context.sleep(Duration::from_millis(50)).await;

            let conflicting_vote = Notarize::sign(&schemes[2], proposal_b).unwrap();
            if let Some(ref mut sender) = participant_senders[2] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(conflicting_vote).encode(),
                        true,
                    );
            }

            // Participants 3..5 vote for the leader proposal, so the batcher
            // can still notarize it even though participant 2 equivocated.
            for i in 3..=5 {
                let honest_vote = Notarize::sign(&schemes[i], proposal_a.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(honest_vote).encode(),
                            true,
                        );
                }
            }

            let our_vote2 = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote2));

            context.sleep(Duration::from_millis(100)).await;
            let mut saw_notarization = false;
            loop {
                let output = select! {
                    output = voter_receiver.recv() => output,
                    _ = context.sleep(Duration::from_millis(100)) => None,
                };
                let Some(output) = output else {
                    break;
                };
                match output {
                    voter::Message::Proposal { proposal: p, .. } => {
                        assert_eq!(p.view(), view2);
                        assert_eq!(p.payload, proposal_a.payload);
                    }
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } => {
                        assert_eq!(n.view(), view2);
                        assert_eq!(n.proposal.payload, proposal_a.payload);
                        saw_notarization = true;
                        break;
                    }
                    _ => panic!("unexpected batcher output"),
                }
            }
            assert!(
                saw_notarization,
                "expected notarization for the leader proposal"
            );

            {
                let broadcasts = relay.broadcasts.lock();
                assert!(
                    broadcasts.is_empty(),
                    "notarization alone should not trigger forwarding"
                );
            }

            // Mark the winning proposal forwardable on the next view so we can
            // check which non-matching voters remain missing for it.
            let view3 = View::new(3);
            let leader3 = Participant::new(3);
            batcher_mailbox.update(Span::none(), view3, leader3, View::zero(), Some(proposal_a.clone()));
            context.sleep(Duration::from_millis(50)).await;

            // Participant 2 voted for a conflicting proposal and participant 6
            // only nullified, so both still need the leader proposal forwarded.
            let broadcasts = relay.broadcasts.lock();
            assert_eq!(
                broadcasts.len(),
                1,
                "expected exactly one targeted broadcast"
            );
            let (ref digest, forwarded_round, ref peers) = broadcasts[0];
            assert_eq!(*digest, proposal_a.payload);
            assert_eq!(forwarded_round, proposal_a.round);
            assert_eq!(
                peers,
                &vec![participants[2].clone(), participants[6].clone()]
            );
        });
    }

    #[test_traced]
    fn test_conflicting_notarize_voter_is_forwarded() {
        conflicting_notarize_voter_is_forwarded(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_notarize_voter_is_forwarded(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_notarize_voter_is_forwarded(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_notarize_voter_is_forwarded(bls12381_threshold_std::fixture::<MinSig, _>);
        conflicting_notarize_voter_is_forwarded(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarize_voter_is_forwarded(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarize_voter_is_forwarded(ed25519::fixture);
        conflicting_notarize_voter_is_forwarded(secp256r1::fixture);
    }

    /// Regression: a participant who sent a finalize vote for the same proposal
    /// already has the block and must not be included in the forwarding set.
    fn finalize_voter_excluded_from_forwarding<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 7;
        let namespace = b"batcher_finalize_voter_forwarding".to_vec();
        let epoch = Epoch::new(555);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: relay.clone(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::SilentVoters,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // View 2: participants 0..4 notarize, participant 6 sends a
            // finalize (implying they already have the block). Only
            // participant 5 should appear in the forwarding set.
            let view2 = View::new(2);
            let leader2 = Participant::new(1);
            batcher_mailbox.update(Span::none(), view2, leader2, View::zero(), None);

            let round2 = Round::new(epoch, view2);
            let proposal = Proposal::new(round2, View::new(1), Sha256::hash(b"payload"));

            // Send finalize BEFORE notarize votes so it is processed before
            // quorum is reached and missing_voters is called.
            let finalize_vote = Finalize::sign(&schemes[6], proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[6] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Finalize(finalize_vote).encode(),
                        true,
                    );
            }

            // Wait for finalize to be delivered and processed
            context.sleep(Duration::from_millis(5)).await;

            // Send notarize votes from participants 1..5 (quorum = 5 for n=7)
            for i in 1..5 {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Our own notarize vote (participant 0)
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote));

            context.sleep(Duration::from_millis(100)).await;
            let mut saw_notarization = false;
            loop {
                let output = select! {
                    output = voter_receiver.recv() => output,
                    _ = context.sleep(Duration::from_millis(100)) => None,
                };
                let Some(output) = output else {
                    break;
                };
                match output {
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } => {
                        assert_eq!(n.view(), view2);
                        saw_notarization = true;
                        break;
                    }
                    voter::Message::Proposal { .. } => {}
                    _ => panic!("unexpected batcher output"),
                }
            }
            assert!(saw_notarization, "expected notarization");

            {
                let broadcasts = relay.broadcasts.lock();
                assert!(
                    broadcasts.is_empty(),
                    "notarization alone should not trigger forwarding"
                );
            }

            let view3 = View::new(3);
            // Advance with the proposal marked forwardable. Participant 6
            // already sent a finalize for it, so only participant 5 should
            // still need the proposal.
            batcher_mailbox.update(
                Span::none(),
                view3,
                Participant::new(3),
                View::zero(),
                Some(proposal.clone()),
            );
            context.sleep(Duration::from_millis(50)).await;

            let broadcasts = relay.broadcasts.lock();
            assert_eq!(
                broadcasts.len(),
                1,
                "expected exactly one targeted broadcast"
            );
            let (ref digest, forwarded_round, ref peers) = broadcasts[0];
            assert_eq!(*digest, proposal.payload);
            assert_eq!(forwarded_round, proposal.round);
            // Only participant 5 should be forwarded to; participant 6 sent
            // a finalize and already has the block.
            assert_eq!(peers, &vec![participants[5].clone()]);
        });
    }

    #[test_traced]
    fn test_finalize_voter_excluded_from_forwarding() {
        finalize_voter_excluded_from_forwarding(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalize_voter_excluded_from_forwarding(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalize_voter_excluded_from_forwarding(bls12381_threshold_std::fixture::<MinPk, _>);
        finalize_voter_excluded_from_forwarding(bls12381_threshold_std::fixture::<MinSig, _>);
        finalize_voter_excluded_from_forwarding(bls12381_multisig::fixture::<MinPk, _>);
        finalize_voter_excluded_from_forwarding(bls12381_multisig::fixture::<MinSig, _>);
        finalize_voter_excluded_from_forwarding(ed25519::fixture);
        finalize_voter_excluded_from_forwarding(secp256r1::fixture);
    }

    /// Test that if both votes and a certificate arrive, only one certificate is sent to voter.
    fn votes_and_certificate_deduplication<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Create an injector peer to send certificates (on channel 1)
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _injector_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(injector_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            let view = View::new(1);
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Build proposal, votes, and certificate
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let notarization = build_notarization(&schemes, &proposal, quorum_size);

            // Send some votes (but not enough for quorum), starting with leader (participant 1)
            // This triggers proposal forwarding
            for i in 1..quorum_size - 1 {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own vote
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_vote));

            // Give network time to deliver votes
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal (participant 1)
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view));

            // Now send the certificate from network
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Notarization(notarization.clone()).encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Should receive exactly one notarization
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view)
            );

            // Now send enough votes to reach quorum (this vote would complete quorum)
            let last_vote =
                Notarize::sign(&schemes[quorum_size - 1], proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[quorum_size - 1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(last_vote).encode(),
                        true,
                    );
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Try to receive another message (with timeout)
            let got_duplicate = select! {
                _ = voter_receiver.recv() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };

            // Should not receive another notarization since we already have one
            assert!(!got_duplicate, "Should not receive duplicate certificate");
        });
    }

    #[test_traced]
    fn test_votes_and_certificate_deduplication() {
        votes_and_certificate_deduplication(bls12381_threshold_vrf::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_threshold_vrf::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(bls12381_threshold_std::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_threshold_std::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinPk, _>);
        votes_and_certificate_deduplication(bls12381_multisig::fixture::<MinSig, _>);
        votes_and_certificate_deduplication(ed25519::fixture);
        votes_and_certificate_deduplication(secp256r1::fixture);
    }

    fn conflicting_votes_dont_produce_invalid_certificate<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 7;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Set up batcher as participant 0
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    // Batcher is participant 0, skip
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle.control(pk.clone()).register(0, TEST_QUOTA).await.unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            let view = View::new(1);
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Build TWO different proposals for the same view
            let round = Round::new(epoch, view);
            let proposal_a = Proposal::new(round, View::zero(), Sha256::hash(b"payload_a"));
            let proposal_b = Proposal::new(round, View::zero(), Sha256::hash(b"payload_b"));

            // Send vote for proposal_a from participant 1 (the leader)
            // This establishes proposal_a as the leader's proposal
            let leader_vote =
                Notarize::sign(&schemes[1], proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(leader_vote).encode(),
                        true,
                    );
            }

            // Give time for leader's vote to arrive and set leader_proposal
            context.sleep(Duration::from_millis(50)).await;

            // The batcher should receive the leader's proposal
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(
                &output,
                voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(b"payload_a")
            ));

            // Now send votes for proposal_b from participants 2, 3, 4, 5 (4 votes)
            // These are for a DIFFERENT proposal and should be filtered out by BatchVerifier
            for i in 2..=5 {
                let vote = Notarize::sign(&schemes[i], proposal_b.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Give time for votes to be processed
            context.sleep(Duration::from_millis(100)).await;

            // At this point we have:
            // - 1 vote for proposal_a (from leader, participant 1)
            // - 4 votes for proposal_b (from participants 2,3,4,5) - should be filtered
            // Total verified votes for proposal_a: only 1

            // Should NOT have a certificate yet
            let got_certificate = select! {
                _output = voter_receiver.recv() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };
            assert!(
                !got_certificate,
                "Should not have certificate - only 1 vote for leader's proposal"
            );

            // Now send 4 more votes for proposal_a (from participants 0,2,3,4)
            // Participant 0 is us, use constructed
            let our_vote = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote));

            // Participants 6 hasn't voted yet - use them for proposal_a
            let vote6 = Notarize::sign(&schemes[6], proposal_a.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[6] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(vote6).encode(),
                        true,
                    );
            }

            // Give time for processing
            context.sleep(Duration::from_millis(100)).await;

            // Still should not have certificate (only 3 votes for proposal_a: 0, 1, 6)
            let got_certificate = select! {
                _output = voter_receiver.recv() => { true },
                _ = context.sleep(Duration::from_millis(100)) => { false },
            };
            assert!(
                !got_certificate,
                "Should not have certificate - only 3 votes for leader's proposal"
            );
        });
    }

    #[test_traced]
    fn test_conflicting_votes_dont_produce_invalid_certificate() {
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_votes_dont_produce_invalid_certificate(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_votes_dont_produce_invalid_certificate(ed25519::fixture);
        conflicting_votes_dont_produce_invalid_certificate(secp256r1::fixture);
    }

    /// Test that when we receive a leader's notarize vote AFTER setting the leader,
    /// the proposal is forwarded to the voter (when we are not the leader).
    fn proposal_forwarded_after_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor as participant 0
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) =
                oracle.control(leader_pk.clone()).register(0, TEST_QUOTA).await.unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize batcher with view 1, participant 1 as leader
            // We (participant 0) are NOT the leader
            let view = View::new(1);
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Give time for update to process
            context.sleep(Duration::from_millis(10)).await;

            // Build proposal and leader's vote
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], proposal.clone()).unwrap();

            // Now send the leader's vote - this should trigger proposal forwarding
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                );

            // Give network time to deliver and batcher time to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_after_leader_set() {
        proposal_forwarded_after_leader_set(bls12381_threshold_vrf::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_vrf::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_std::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_threshold_std::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_after_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_after_leader_set(ed25519::fixture);
        proposal_forwarded_after_leader_set(secp256r1::fixture);
    }

    /// Test that when we receive a leader's notarize vote BEFORE setting the leader,
    /// the proposal is forwarded to the voter once the leader is set (when we are not the leader).
    fn proposal_forwarded_before_leader_set<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor as participant 0
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) =
                oracle.control(me.clone()).register(0, TEST_QUOTA).await.unwrap();
            let (_certificate_sender, certificate_receiver) =
                oracle.control(me.clone()).register(1, TEST_QUOTA).await.unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) =
                oracle.control(leader_pk.clone()).register(0, TEST_QUOTA).await.unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher - but don't set leader yet
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Build proposal and leader's vote for view 1 with participant 1 as leader
            let view = View::new(1);
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], proposal.clone()).unwrap();

            // Send the leader's vote BEFORE setting the leader
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Now set the leader - this should cause the proposal to be forwarded
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Give time for batcher to process
            context.sleep(Duration::from_millis(50)).await;

            // Should receive the leader's proposal forwarded to voter
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(b"test_payload")),
                "Expected proposal to be forwarded after leader set (vote arrived before leader was known)"
            );
        });
    }

    #[test_traced]
    fn test_proposal_forwarded_before_leader_set() {
        proposal_forwarded_before_leader_set(bls12381_threshold_vrf::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_vrf::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_std::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_threshold_std::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinPk, _>);
        proposal_forwarded_before_leader_set(bls12381_multisig::fixture::<MinSig, _>);
        proposal_forwarded_before_leader_set(ed25519::fixture);
        proposal_forwarded_before_leader_set(secp256r1::fixture);
    }

    /// Test that leader activity detection works correctly:
    /// 1. Early views (before skip_timeout) always return active
    /// 2. Once `skip_timeout` views have elapsed without a message, the leader is inactive
    /// 3. Recent inbound messages keep the leader active
    /// 4. Large view gaps cause earlier activity to expire
    fn leader_activity_detection<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Register leader (participant 1) on the network
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Test 1: Early views (before skip_timeout) should always return active
            // Views 1 through skip_timeout-1 are before the threshold
            let leader = Participant::new(1);
            for v in 1..skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Test 2: At view skip_timeout, the leader has been silent for
            // skip_timeout tracked views and should be marked inactive.
            let view = View::new(skip_timeout);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                view,
                TimeoutReason::Inactivity,
            )
            .await;

            // Test 3: Send a vote from the leader for the current view (view 5)
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let leader_vote = Notarize::sign(&schemes[1], proposal).unwrap();
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                );

            // Give network time to deliver
            context.sleep(Duration::from_millis(50)).await;

            // Test 4: Advance to view skip_timeout + 1 (view 6)
            // Leader voted in view 5, which is in the recent window, so should be active
            let view = View::new(skip_timeout + 1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Test 5: Jump far ahead. The last seen message is now outside the
            // skip window, so the leader becomes inactive again.
            let view = View::new(100);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                view,
                TimeoutReason::Inactivity,
            )
            .await;

            // Test 6: local leader inactivity should not trigger a fast-timeout hint.
            let self_leader = Participant::new(0);
            let view = View::new(101);
            batcher_mailbox.update(Span::none(), view, self_leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;
        });
    }

    #[test_traced]
    fn test_leader_activity_detection() {
        leader_activity_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_activity_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinPk, _>);
        leader_activity_detection(bls12381_multisig::fixture::<MinSig, _>);
        leader_activity_detection(ed25519::fixture);
        leader_activity_detection(secp256r1::fixture);
    }

    /// Test that nullify-only participation marks a leader as active for skip-timeout
    /// heuristics.
    fn leader_nullify_marks_active<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_nullify_activity_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader_pk = participants[1].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let leader = Participant::new(1);
            for v in 1..=skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                View::new(skip_timeout),
                TimeoutReason::Inactivity,
            )
            .await;

            // Send a nullify vote from the leader in view skip_timeout.
            let round = Round::new(epoch, View::new(skip_timeout));
            let leader_vote = Nullify::sign::<Sha256Digest>(&schemes[1], round).unwrap();
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::<S, Sha256Digest>::Nullify(leader_vote).encode(),
                    true,
                );

            context.sleep(Duration::from_millis(50)).await;

            // Nullify-only activity should still count as activity for skip-timeout.
            let next_view = View::new(skip_timeout + 1);
            batcher_mailbox.update(Span::none(), next_view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;
        });
    }

    #[test_traced]
    fn test_leader_nullify_marks_active() {
        leader_nullify_marks_active(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_marks_active(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_marks_active(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_marks_active(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_marks_active(ed25519::fixture);
        leader_nullify_marks_active(secp256r1::fixture);
    }

    /// Test that certificate relays keep a leader active for skip-timeout heuristics
    /// even when the leader does not emit any vote.
    fn leader_certificate_marks_active<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_certificate_activity_test".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(skip_timeout),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let leader = Participant::new(1);
            let leader_pk = participants[usize::from(leader)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Advance through the early views with no leader traffic. The skip-timeout
            // heuristic should not fire before the threshold is reached.
            for v in 1..skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }

            // Enter the threshold view with no activity. The batcher should signal the
            // voter to fast-timeout because the leader has been silent for skip_timeout
            // views.
            let active_view = View::new(skip_timeout);
            batcher_mailbox.update(Span::none(), active_view, leader, View::zero(), None);

            // Deliver a certificate from the leader on the certificate channel. Even
            // without any vote traffic, that relay should count as fresh activity.
            let round = Round::new(epoch, active_view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));
            let finalization = build_finalization(&schemes, &proposal, quorum_size);
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Finalization(finalization.clone()).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            // The threshold-view update should produce a fast-timeout, followed by the
            // verified finalization once the certificate is processed.
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                active_view,
                TimeoutReason::Inactivity,
            )
            .await;
            assert!(matches!(
                voter_receiver.recv().await.expect("verified"),
                voter::Message::Verified { certificate: Certificate::Finalization(f), .. } if f.view() == active_view
            ));

            // The next view should still consider the leader active because of the
            // relayed certificate we just processed, so no further timeout should fire.
            let next_view = active_view.next();
            batcher_mailbox.update(Span::none(), next_view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;
        });
    }

    #[test_traced]
    fn test_leader_certificate_marks_active() {
        leader_certificate_marks_active(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_certificate_marks_active(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_certificate_marks_active(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_certificate_marks_active(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_certificate_marks_active(bls12381_multisig::fixture::<MinPk, _>);
        leader_certificate_marks_active(bls12381_multisig::fixture::<MinSig, _>);
        leader_certificate_marks_active(ed25519::fixture);
        leader_certificate_marks_active(secp256r1::fixture);
    }

    /// Test that if a leader nullify for `v+1` is buffered while current view is `v`,
    /// entering `v+1` reports the leader inactive so the voter skips timeout immediately.
    fn leader_nullify_expire_on_view_entry<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_leader_nullify_expire_on_view_entry".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let leader_idx = Participant::new(2);
            let leader_pk = participants[usize::from(leader_idx)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    leader_pk.clone(),
                    me.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Enter view 1 first.
            batcher_mailbox.update(Span::none(), View::new(1), Participant::new(1), View::zero(), None);

            // Buffer a leader nullify for view 2 while current is still view 1.
            let buffered_view = View::new(2);
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Vote::<S, Sha256Digest>::Nullify(
                        Nullify::sign::<Sha256Digest>(
                            &schemes[usize::from(leader_idx)],
                            Round::new(epoch, buffered_view),
                        )
                        .expect("nullify"),
                    )
                    .encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            // Move current view to 2 with that same leader; this should fast-path timeout
            // through the voter mailbox.
            batcher_mailbox.update(Span::none(), buffered_view, leader_idx, View::zero(), None);
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                buffered_view,
                TimeoutReason::LeaderNullify,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_leader_nullify_expire_on_view_entry() {
        leader_nullify_expire_on_view_entry(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_expire_on_view_entry(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_expire_on_view_entry(ed25519::fixture);
        leader_nullify_expire_on_view_entry(secp256r1::fixture);
    }

    /// Test that we do not signal expiry when the sender is the current leader but the
    /// nullify vote is for a different view.
    fn leader_nullify_wrong_view_no_expire<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_leader_nullify_wrong_view_no_expire".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let leader = Participant::new(2);
            let leader_pk = participants[usize::from(leader)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    leader_pk,
                    me.clone(),
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: 1.0,
                    },
                )
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let current_view = View::new(2);
            batcher_mailbox.update(Span::none(), current_view, leader, View::zero(), None);

            let wrong_view = current_view.next();
            let leader_nullify = Nullify::sign::<Sha256Digest>(
                &schemes[usize::from(leader)],
                Round::new(epoch, wrong_view),
            )
            .expect("nullify");
            leader_sender
                .send(
                    Recipients::One(me),
                    Vote::<S, Sha256Digest>::Nullify(leader_nullify).encode(),
                    true,
                );

            expect_no_timeout(&mut context, &mut voter_receiver).await;
        });
    }

    #[test_traced]
    fn test_leader_nullify_wrong_view_no_expire() {
        leader_nullify_wrong_view_no_expire(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(bls12381_multisig::fixture::<MinPk, _>);
        leader_nullify_wrong_view_no_expire(bls12381_multisig::fixture::<MinSig, _>);
        leader_nullify_wrong_view_no_expire(ed25519::fixture);
        leader_nullify_wrong_view_no_expire(secp256r1::fixture);
    }

    /// Test that votes above finalized trigger verification/construction,
    /// but votes at or below finalized do not.
    fn votes_skipped_for_finalized_views<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Register all participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Start with finalized=0, current=1 (view 1 is above finalized)
            let view1 = View::new(1);
            let view2 = View::new(2);
            let leader = Participant::new(1);

            batcher_mailbox.update(Span::none(), view1, leader, View::zero(), None);

            // Part 1: Send NOTARIZE votes for view 1 (above finalized=0, should succeed)
            let round1 = Round::new(epoch, view1);
            let proposal1 = Proposal::new(round1, View::zero(), Sha256::hash(b"payload1"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal1.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own notarize vote for view 1 via constructed
            let our_notarize = Notarize::sign(&schemes[0], proposal1.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_notarize));

            // Should receive a notarization certificate (view 1 is above finalized=0)
            loop {
                let output = voter_receiver.recv().await.unwrap();
                match output {
                    voter::Message::Proposal { .. } => continue,
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } => {
                        assert_eq!(
                            n.view(),
                            view1,
                            "Should construct notarization for view above finalized"
                        );
                        break;
                    }
                    _ => panic!("Unexpected message type"),
                }
            }

            // Part 2: Advance finalized to view 2
            // Now test NOTARIZE votes for view 2 which should NOT be processed (at finalized=2)
            let view3 = View::new(3);
            batcher_mailbox.update(Span::none(), view3, leader, view2, None);

            // Send NOTARIZE votes for view 2 (now at finalized=2, should NOT succeed)
            let round2 = Round::new(epoch, view2);
            let proposal2 = Proposal::new(round2, view1, Sha256::hash(b"payload2"));
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal2.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own notarize vote for view 2 via constructed
            let our_notarize2 = Notarize::sign(&schemes[0], proposal2.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(our_notarize2));

            // Should NOT receive any certificate for the finalized view
            select! {
                msg = voter_receiver.recv() => match msg {
                    Some(voter::Message::Proposal { .. }) => {}
                    Some(voter::Message::Verified { certificate: cert, .. }) if cert.view() == view2 => {
                        panic!("should not receive any certificate for the finalized view");
                    }
                    _ => {}
                },
                _ = context.sleep(Duration::from_millis(200)) => {},
            };
        });
    }

    #[test_traced]
    fn test_votes_skipped_for_finalized_views() {
        votes_skipped_for_finalized_views(bls12381_threshold_vrf::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_vrf::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_std::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_threshold_std::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinPk, _>);
        votes_skipped_for_finalized_views(bls12381_multisig::fixture::<MinSig, _>);
        votes_skipped_for_finalized_views(ed25519::fixture);
        votes_skipped_for_finalized_views(secp256r1::fixture);
    }

    fn latest_vote_metric_tracking<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
            )
            .await;

            // Setup reporter mock
            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_context = context.child("batcher");
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(batcher_context, batcher_cfg);

            // Verify all participants are initialized to view 0 in the metric
            let buffer = context.encode();
            for participant in &participants {
                let expected = format!("latest_vote{{peer=\"{}\"}} 0", participant);
                assert!(
                    buffer.contains(&expected),
                    "Expected metric for participant {} to be initialized to 0, got: {}",
                    participant,
                    buffer
                );
            }

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(context.child("mailbox"), NZUsize!(1024));
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Register participants on the network and set up links
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate() {
                if i == 0 {
                    participant_senders.push(None);
                    continue;
                }
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push(Some(sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Prime leader activity before jumping straight to view 5 so the
            // inactivity heuristic does not interfere with the metric assertions.
            let leader = Participant::new(1);
            let warmup_vote = Nullify::sign::<Sha256Digest>(
                &schemes[usize::from(leader)],
                Round::new(epoch, View::new(1)),
            )
            .unwrap();
            if let Some(ref mut sender) = participant_senders[usize::from(leader)] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(warmup_vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            // Initialize batcher with view 5, participant 1 as leader
            let view = View::new(5);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Build proposal and send enough votes to reach quorum
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send votes from participants 1 through quorum_size-1 (excluding 0, our own)
            for i in 1..quorum_size {
                let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                if let Some(ref mut sender) = participant_senders[i] {
                    sender
                        .send(
                            Recipients::One(me.clone()),
                            Vote::Notarize(vote).encode(),
                            true,
                        );
                }
            }

            // Send our own vote to complete the quorum
            let our_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox
                .constructed(Vote::Notarize(our_vote));

            // Give network time to deliver and batcher time to process and construct certificate
            context.sleep(Duration::from_millis(100)).await;

            // Receive proposal and certificate
            loop {
                let output = voter_receiver.recv().await.unwrap();
                match output {
                    voter::Message::Proposal { .. } => continue,
                    voter::Message::Verified { certificate: Certificate::Notarization(n), .. } => {
                        assert_eq!(n.view(), view, "Should construct notarization");
                        break;
                    }
                    _ => panic!("Unexpected message type"),
                }
            }

            // Verify votes were tracked for participants who voted
            let buffer = context.encode();
            for (i, participant) in participants.iter().enumerate().take(quorum_size).skip(1) {
                let expected = format!("latest_vote{{peer=\"{}\"}} 5", participant);
                assert!(
                    buffer.contains(&expected),
                    "Expected participant {} to have latest_vote=5, got: {}",
                    i,
                    buffer
                );
            }

            // Now send a vote from a participant who hasn't voted yet (after quorum)
            // This tests that votes are still tracked even after certificate construction
            let late_voter = quorum_size;
            let late_vote = Notarize::sign(&schemes[late_voter], proposal.clone()).unwrap();
            if let Some(ref mut sender) = participant_senders[late_voter] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(late_vote).encode(),
                        true,
                    );
            }

            // Give network time to deliver
            context.sleep(Duration::from_millis(100)).await;

            // Verify the late vote was still tracked
            let buffer = context.encode();
            let expected_late = format!("latest_vote{{peer=\"{}\"}} 5", participants[late_voter]);
            assert!(
                buffer.contains(&expected_late),
                "Expected late voter (participant {}) to have latest_vote=5 even after quorum, got: {}",
                late_voter,
                buffer
            );

            // Send a vote for a LOWER view (view 3) from participant 1 who already voted at view 5
            // to verify the metric doesn't decrease
            let view3 = View::new(3);
            let round3 = Round::new(epoch, view3);
            let proposal3 = Proposal::new(round3, View::zero(), Sha256::hash(b"payload3"));
            let vote_v3 = Notarize::sign(&schemes[1], proposal3).unwrap();
            if let Some(ref mut sender) = participant_senders[1] {
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(vote_v3).encode(),
                        true,
                    );
            }

            context.sleep(Duration::from_millis(100)).await;

            // Verify participant 1 STILL has latest_vote = 5 (not decreased to 3)
            let buffer = context.encode();
            let expected_v5 = format!("latest_vote{{peer=\"{}\"}} 5", participants[1]);
            assert!(
                buffer.contains(&expected_v5),
                "Expected participant 1 to still have latest_vote=5 after receiving lower view vote, got: {}",
                buffer
            );
        });
    }

    #[test_traced]
    fn test_latest_vote_metric_tracking() {
        latest_vote_metric_tracking(bls12381_threshold_vrf::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_threshold_vrf::fixture::<MinSig, _>);
        latest_vote_metric_tracking(bls12381_threshold_std::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_threshold_std::fixture::<MinSig, _>);
        latest_vote_metric_tracking(bls12381_multisig::fixture::<MinPk, _>);
        latest_vote_metric_tracking(bls12381_multisig::fixture::<MinSig, _>);
        latest_vote_metric_tracking(ed25519::fixture);
        latest_vote_metric_tracking(secp256r1::fixture);
    }

    fn duplicate_vote_with_different_attestation_blocks_peer<S, F, V>(mut fixture: F, sign_vote: V)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        V: Fn(&S, Proposal<Sha256Digest>) -> Vote<S, Sha256Digest> + Send + 'static,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, _voter_receiver) = mailbox::new::<voter::Message<S, Sha256Digest>>(
                context.child("mailbox"),
                NZUsize!(1024),
            );
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Set up participant 1 as sender
            let sender_pk = participants[1].clone();
            let (mut sender, _receiver) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(b"test_payload"));

            // Send first valid vote from participant 1
            let vote1 = sign_vote(&schemes[1], proposal.clone());
            sender.send(Recipients::One(me.clone()), vote1.encode(), true);

            context.sleep(Duration::from_millis(50)).await;

            // Verify not blocked yet
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "No peers should be blocked after first vote"
            );

            // Send same vote again (exact duplicate) - should be ignored, not blocked
            sender.send(Recipients::One(me.clone()), vote1.encode(), true);

            context.sleep(Duration::from_millis(50)).await;

            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "Duplicate vote should be ignored, not blocked"
            );

            // Now send a vote with the SAME proposal but with a different signature
            let vote2 = sign_vote(&schemes[2], proposal.clone());
            sender.send(Recipients::One(me.clone()), vote2.encode(), true);

            context.sleep(Duration::from_millis(50)).await;

            // Participant 1 should be blocked because they sent 2 votes with different attestations
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.iter().any(|(_, blocked)| blocked == &sender_pk),
                "Sender should be blocked for vote with mismatched signer"
            );
        });
    }

    fn sign_notarize<S: Scheme<Sha256Digest>>(
        scheme: &S,
        p: Proposal<Sha256Digest>,
    ) -> Vote<S, Sha256Digest> {
        Vote::Notarize(Notarize::sign(scheme, p).unwrap())
    }

    fn sign_finalize<S: Scheme<Sha256Digest>>(
        scheme: &S,
        p: Proposal<Sha256Digest>,
    ) -> Vote<S, Sha256Digest> {
        Vote::Finalize(Finalize::sign(scheme, p).unwrap())
    }

    #[test_traced]
    fn test_duplicate_notarize_with_different_attestation_blocks_peer() {
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_notarize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(ed25519::fixture, sign_notarize);
        duplicate_vote_with_different_attestation_blocks_peer(secp256r1::fixture, sign_notarize);
    }

    #[test_traced]
    fn test_duplicate_finalize_with_different_attestation_blocks_peer() {
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_finalize,
        );
        duplicate_vote_with_different_attestation_blocks_peer(ed25519::fixture, sign_finalize);
        duplicate_vote_with_different_attestation_blocks_peer(secp256r1::fixture, sign_finalize);
    }

    fn conflicting_vote_creates_evidence<S, F, V, A>(
        mut fixture: F,
        sign_vote: V,
        is_expected_activity: A,
    ) where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        V: Fn(&S, Proposal<Sha256Digest>) -> Vote<S, Sha256Digest> + Send + 'static,
        A: Fn(&Activity<S, Sha256Digest>) -> bool + Send + 'static,
    {
        let n = 5;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter_cfg = mocks::reporter::Config {
                participants: schemes[0].participants().clone(),
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            let me = participants[0].clone();
            let batcher_cfg = Config {
                scheme: schemes[0].clone(),
                blocker: oracle.control(me.clone()),
                reporter: reporter.clone(),
                relay: MockRelay::new(),
                strategy: Sequential,
                activity_timeout: ViewDelta::new(10),
                skip_timeout: ViewDelta::new(5),
                epoch,
                mailbox_size: NZUsize!(128),
                forwarding: ForwardingPolicy::Disabled,
            };
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, _voter_receiver) = mailbox::new::<voter::Message<S, Sha256Digest>>(
                context.child("mailbox"),
                NZUsize!(1024),
            );
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            let (_vote_sender, vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (_certificate_sender, certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Set up participant 1 as sender
            let sender_pk = participants[1].clone();
            let (mut sender, _receiver) = oracle
                .control(sender_pk.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let round = Round::new(epoch, view);
            let proposal1 = Proposal::new(round, View::zero(), Sha256::hash(b"payload1"));
            let proposal2 = Proposal::new(round, View::zero(), Sha256::hash(b"payload2"));

            // Send first valid vote for proposal1
            let vote1 = sign_vote(&schemes[1], proposal1);
            sender.send(Recipients::One(me.clone()), vote1.encode(), true);

            context.sleep(Duration::from_millis(50)).await;

            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "No peers should be blocked after first vote"
            );

            // Send conflicting vote for proposal2 (different payload = different proposal)
            let vote2 = sign_vote(&schemes[1], proposal2);
            sender.send(Recipients::One(me.clone()), vote2.encode(), true);

            context.sleep(Duration::from_millis(50)).await;

            // Participant 1 should be blocked for sending conflicting votes
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.iter().any(|(_, blocked)| blocked == &sender_pk),
                "Sender should be blocked for conflicting vote"
            );

            // Verify conflicting evidence was reported via faults
            let faults = reporter.faults.lock();
            let has_expected_fault = faults
                .get(&sender_pk)
                .and_then(|sf| sf.get(&view))
                .is_some_and(|vf| vf.iter().any(&is_expected_activity));
            assert!(has_expected_fault, "Should have conflicting fault reported");
        });
    }

    fn is_conflicting_notarize<S: Scheme<Sha256Digest>>(a: &Activity<S, Sha256Digest>) -> bool {
        matches!(a, Activity::ConflictingNotarize(_))
    }

    fn is_conflicting_finalize<S: Scheme<Sha256Digest>>(a: &Activity<S, Sha256Digest>) -> bool {
        matches!(a, Activity::ConflictingFinalize(_))
    }

    #[test_traced]
    fn test_conflicting_notarize_creates_evidence() {
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_notarize,
            is_conflicting_notarize,
        );
        conflicting_vote_creates_evidence(ed25519::fixture, sign_notarize, is_conflicting_notarize);
        conflicting_vote_creates_evidence(
            secp256r1::fixture,
            sign_notarize,
            is_conflicting_notarize,
        );
    }

    #[test_traced]
    fn test_conflicting_finalize_creates_evidence() {
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_threshold_std::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinPk, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(
            bls12381_multisig::fixture::<MinSig, _>,
            sign_finalize,
            is_conflicting_finalize,
        );
        conflicting_vote_creates_evidence(ed25519::fixture, sign_finalize, is_conflicting_finalize);
        conflicting_vote_creates_evidence(
            secp256r1::fixture,
            sign_finalize,
            is_conflicting_finalize,
        );
    }
}
