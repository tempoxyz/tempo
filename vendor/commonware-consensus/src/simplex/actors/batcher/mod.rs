mod actor;
mod ingress;
mod round;
mod verifier;

use crate::{
    Relay, Reporter,
    simplex::{
        Lookahead,
        config::{ForwardPolicy, SkipPolicy},
    },
    types::{Epoch, View, ViewDelta},
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
    pub track_historical_votes: bool,
    pub relay: Rl,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub view_retention: ViewDelta,
    pub skip: SkipPolicy,
    pub epoch: Epoch,
    pub mailbox_size: NonZeroUsize,

    /// Controls term boundaries and how far ahead votes are processed optimistically.
    pub lookahead: Lookahead,
    pub forward: ForwardPolicy,

    /// Highest finalized view at startup; anchors the viewport before
    /// the voter's first update.
    pub floor: View,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Viewable,
        simplex::{
            Plan,
            actors::voter,
            config::{ForwardPolicy, SkipBudget},
            elector::RoundRobin,
            metrics::TimeoutReason,
            mocks, quorum,
            scheme::{
                Scheme, bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1,
            },
            types::{
                Activity, Certificate, Finalization, Finalize, Kind, Notarization, Notarize,
                Nullification, Nullify, Outcome, Proposal, Vote,
            },
        },
        types::{Epoch, Participant, Round, TermLength, View},
    };
    use commonware_actor::{Feedback, mailbox};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Hasher as _, Sha256, Signer,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_async, test_collect_traces, test_traced};
    use commonware_p2p::{
        Manager as _, Recipients, Sender as _, TrackedPeers,
        simulated::{Config as NConfig, Link, Network, Oracle, Sender},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock, Metrics as _, Quota, Runner, Strategizer as _, Supervisor as _, deterministic,
        telemetry::traces::{TracedExt as _, collector::TraceStorage},
        tokio,
    };
    use commonware_utils::{
        NZUsize, TestRng, non_empty, ordered::Set, probability, sync::Mutex, test_rng,
    };
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
        let peers: Vec<_> = peers.into_iter().collect();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NConfig {
                max_size: 1024 * 1024,
                // Certificate-injection tests add one secondary peer to the committee.
                max_peers_per_set: NZUsize!(peers.len() + 1),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        oracle
    }

    /// Registers `peer` on `channel` and links it to `me` with a reliable
    /// connection of the given latency, returning the peer's sender.
    async fn register_and_link_peer(
        oracle: &Oracle<PublicKey, deterministic::Context>,
        peer: PublicKey,
        me: PublicKey,
        channel: u64,
        latency: Duration,
    ) -> Sender<PublicKey, deterministic::Context> {
        let (sender, _receiver) = oracle
            .control(peer.clone())
            .register(channel, TEST_QUOTA)
            .await
            .unwrap();
        oracle
            .add_link(
                peer,
                me,
                Link {
                    latency,
                    jitter: Duration::from_millis(0),
                    success_rate: probability!(1.0),
                },
            )
            .await
            .unwrap();
        sender
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

    /// Builds the standard reporter mock used by batcher tests.
    fn test_reporter<S: Scheme<Sha256Digest>>(
        context: &mut deterministic::Context,
        scheme: &S,
    ) -> mocks::reporter::Reporter<deterministic::Context, S, RoundRobin, Sha256Digest> {
        let reporter_cfg = mocks::reporter::Config {
            participants: scheme.participants().clone(),
            scheme: scheme.clone(),
            elector: <RoundRobin>::default(),
        };
        mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg)
    }

    /// Batcher [Config] fields that vary across tests; everything else is
    /// fixed by [test_config].
    struct BatcherOptions {
        view_retention: ViewDelta,
        skip: SkipPolicy,
        lookahead: Lookahead,
        forward: ForwardPolicy,
        track_historical_votes: bool,
        floor: View,
    }

    impl Default for BatcherOptions {
        fn default() -> Self {
            Self {
                view_retention: ViewDelta::new(10),
                skip: SkipPolicy::Enabled {
                    timeout: Duration::from_secs(5),
                    budget: SkipBudget::Participants,
                },
                lookahead: Lookahead {
                    term_length: TermLength::ONE,
                    optimistic_views: ViewDelta::new(0),
                },
                forward: ForwardPolicy::Disabled,
                track_historical_votes: false,
                floor: View::zero(),
            }
        }
    }

    /// Builds a batcher [Config] with the standard test defaults, overriding
    /// only the fields in `options`.
    fn test_config<S: Scheme<Sha256Digest>, B: Blocker, Re: crate::Reporter, Rl: Relay>(
        scheme: S,
        blocker: B,
        reporter: Re,
        relay: Rl,
        epoch: Epoch,
        options: BatcherOptions,
    ) -> Config<S, B, Re, Rl, Sequential> {
        Config {
            scheme,
            blocker,
            reporter,
            track_historical_votes: options.track_historical_votes,
            relay,
            strategy: Sequential,
            view_retention: options.view_retention,
            skip: options.skip,
            epoch,
            mailbox_size: NZUsize!(128),
            lookahead: options.lookahead,
            forward: options.forward,
            floor: options.floor,
        }
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
        Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential)
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
        Nullification::from_nullifies(&schemes[0], non_empty![@&votes], &Sequential)
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
        Finalization::from_finalizes(&schemes[0], non_empty![@&votes], &Sequential)
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

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    #[derive(Clone)]
    struct RecordingBlocker(Arc<Mutex<Vec<PublicKey>>>);

    impl commonware_p2p::Blocker for RecordingBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, peer: Self::PublicKey) -> Feedback {
            self.0.lock().push(peer);
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
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

    #[derive(Clone)]
    struct RecordingReporter<S: Scheme<Sha256Digest>>(Arc<Mutex<Vec<Activity<S, Sha256Digest>>>>);

    impl<S: Scheme<Sha256Digest>> crate::Reporter for RecordingReporter<S> {
        type Activity = Activity<S, Sha256Digest>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            self.0.lock().push(activity);
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
            false,
        );

        // Route a quorum of notarizes through the round as network votes.
        let proposal = Proposal::new(round_id, View::new(0), Sha256::hash(&[b"payload"]));
        round.set_leader(Participant::from_usize(0));
        for (i, scheme) in schemes.iter().enumerate() {
            let notarize = Notarize::sign(scheme, proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Notarize(notarize)));
        }

        // Batch verify the pending votes on the strategy's pool.
        let (batch, invalid) = round
            .try_verify(&mut rng, &strategy)
            .await
            .expect("quorum of notarizes must be ready");
        assert_eq!(batch, schemes.len());
        assert!(invalid.is_empty());

        // Recover the certificate on the strategy's pool.
        let certificate = round
            .try_construct_certificate(&strategy)
            .await
            .expect("verified quorum must construct a certificate");
        let Certificate::Notarization(notarization) = certificate else {
            panic!("expected a notarization");
        };
        assert_eq!(notarization.proposal, proposal);
        assert!(notarization.verify(&mut rng, &verifier, &Sequential));

        // Construction is one-shot per round.
        assert!(round.try_construct_certificate(&strategy).await.is_none());
    }

    /// A locally constructed vote and its network duplicate must count once
    /// toward the verifier quorum.
    #[test_async]
    async fn test_constructed_leader_notarize_is_not_reverified() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let quorum = quorum(5) as usize;
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        round.set_leader(Participant::from_usize(0));

        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        let leader_vote = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
        assert!(matches!(
            round.accept_vote(Vote::Notarize(leader_vote.clone()), true),
            Outcome::Added { retained: true }
        ));

        // VoteTracker rejects the network copy before it reaches the verifier.
        assert!(!round.add_network(participants[0].clone(), Vote::Notarize(leader_vote)));
        for i in 1..quorum - 1 {
            let vote = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Notarize(vote)));
        }
        assert!(round.try_verify(&mut rng, &Sequential).await.is_none());

        let vote = Notarize::sign(&schemes[quorum - 1], proposal).unwrap();
        assert!(round.add_network(participants[quorum - 1].clone(), Vote::Notarize(vote)));
        let (batch, invalid) = round
            .try_verify(&mut rng, &Sequential)
            .await
            .expect("unique signer quorum must be ready");
        assert_eq!(batch, quorum - 1);
        assert!(invalid.is_empty());
        assert!(matches!(
            round.try_construct_certificate(&Sequential).await,
            Some(Certificate::Notarization(_))
        ));
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

    /// A notarization observed before the leader is known establishes a
    /// proposal that can be forwarded immediately.
    #[test]
    fn test_forward_proposal_from_notarization_without_leader() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[1].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );

        // The leader's notarize arrives before the leader is known
        let proposal = Proposal::new(round_id, View::new(0), Sha256::hash(&[b"payload"]));
        let notarize = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
        assert!(round.add_network(participants[0].clone(), Vote::Notarize(notarize)));

        // A verified notarization establishes the proposal and drops the
        // verifier's notarize buffers
        let notarization = build_notarization(&schemes, &proposal, quorum(5) as usize);
        assert!(round.record_certificate(&Certificate::Notarization(notarization)));
        assert!(round.has_certificate(Kind::Notarization));

        // The proposal can be forwarded before the leader is known
        assert_eq!(
            round.try_forward_proposal(Participant::from_usize(1)),
            Some(proposal)
        );
    }

    fn certified_conflict_outcome(
        track_historical_votes: bool,
        kind: Kind,
        first_matches: bool,
    ) -> (bool, bool) {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        let conflicting = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"conflicting"]));
        let (first, second) = if first_matches {
            (&proposal, &conflicting)
        } else {
            (&conflicting, &proposal)
        };
        let activities = Arc::new(Mutex::new(Vec::new()));
        let blocked = Arc::new(Mutex::new(Vec::new()));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            RecordingBlocker(blocked.clone()),
            RecordingReporter(activities.clone()),
            track_historical_votes,
        );

        match kind {
            Kind::Notarization => {
                let vote = Notarize::sign(&schemes[0], first.clone()).unwrap();
                assert!(round.add_network(participants[0].clone(), Vote::Notarize(vote)));
                let certificate = build_notarization(&schemes, &proposal, quorum(5) as usize);
                assert!(round.record_certificate(&Certificate::Notarization(certificate)));
                let vote = Notarize::sign(&schemes[0], second.clone()).unwrap();
                assert!(!round.add_network(participants[0].clone(), Vote::Notarize(vote)));
            }
            Kind::Finalization => {
                let vote = Finalize::sign(&schemes[0], first.clone()).unwrap();
                assert!(round.add_network(participants[0].clone(), Vote::Finalize(vote)));
                let certificate = build_finalization(&schemes, &proposal, quorum(5) as usize);
                assert!(!round.record_certificate(&Certificate::Finalization(certificate)));
                let vote = Finalize::sign(&schemes[0], second.clone()).unwrap();
                assert!(!round.add_network(participants[0].clone(), Vote::Finalize(vote)));
            }
            Kind::Nullification => unreachable!("nullify votes do not carry proposals"),
        }
        let reported = activities.lock().iter().any(|activity| match kind {
            Kind::Notarization => matches!(activity, Activity::ConflictingNotarize(_)),
            Kind::Finalization => matches!(activity, Activity::ConflictingFinalize(_)),
            Kind::Nullification => false,
        });
        let blocked = blocked.lock().contains(&participants[0]);
        (reported, blocked)
    }

    #[test]
    fn test_certificate_releases_votes_without_retention() {
        for kind in [Kind::Notarization, Kind::Finalization] {
            for first_matches in [false, true] {
                let (reported, blocked) = certified_conflict_outcome(false, kind, first_matches);
                assert!(!reported);
                assert!(blocked, "compact proposal conflict should block its signer");
            }
        }
    }

    #[test]
    fn test_certificate_retains_votes_when_configured() {
        for kind in [Kind::Notarization, Kind::Finalization] {
            for first_matches in [false, true] {
                let (reported, blocked) = certified_conflict_outcome(true, kind, first_matches);
                assert!(reported);
                assert!(blocked);
            }
        }
    }

    #[test]
    fn test_nullify_finalize_conflicts_reported_while_evidence_available() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        let activities = Arc::new(Mutex::new(Vec::new()));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            RecordingReporter(activities.clone()),
            false,
        );

        assert!(round.add_network(
            participants[1].clone(),
            Vote::Finalize(Finalize::sign(&schemes[1], proposal.clone()).unwrap()),
        ));
        assert!(!round.add_network(
            participants[1].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[1], round_id).unwrap()),
        ));

        assert!(round.add_network(
            participants[2].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[2], round_id).unwrap()),
        ));
        assert!(!round.add_network(
            participants[2].clone(),
            Vote::Finalize(Finalize::sign(&schemes[2], proposal).unwrap()),
        ));

        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            RecordingReporter(activities.clone()),
            false,
        );
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        assert!(round.add_network(
            participants[1].clone(),
            Vote::Finalize(Finalize::sign(&schemes[1], proposal.clone()).unwrap()),
        ));
        round.record_certificate(&Certificate::Nullification(build_nullification(
            &schemes,
            round_id,
            quorum(5) as usize,
        )));
        assert!(!round.add_network(
            participants[1].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[1], round_id).unwrap()),
        ));

        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            RecordingReporter(activities.clone()),
            false,
        );
        assert!(round.add_network(
            participants[2].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[2], round_id).unwrap()),
        ));
        round.record_certificate(&Certificate::Finalization(build_finalization(
            &schemes,
            &proposal,
            quorum(5) as usize,
        )));
        assert!(!round.add_network(
            participants[2].clone(),
            Vote::Finalize(Finalize::sign(&schemes[2], proposal).unwrap()),
        ));

        assert_eq!(
            activities
                .lock()
                .iter()
                .filter(|activity| matches!(activity, Activity::NullifyFinalize(_)))
                .count(),
            4
        );
    }

    #[test]
    fn test_compacted_votes_still_block_nullify_finalize_conflicts() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));

        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        assert!(round.add_network(
            participants[1].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[1], round_id).unwrap()),
        ));
        round.record_certificate(&Certificate::Nullification(build_nullification(
            &schemes,
            round_id,
            quorum(5) as usize,
        )));
        assert!(!round.add_network(
            participants[1].clone(),
            Vote::Finalize(Finalize::sign(&schemes[1], proposal.clone()).unwrap()),
        ));

        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        assert!(round.add_network(
            participants[2].clone(),
            Vote::Finalize(Finalize::sign(&schemes[2], proposal.clone()).unwrap()),
        ));
        round.record_certificate(&Certificate::Finalization(build_finalization(
            &schemes,
            &proposal,
            quorum(5) as usize,
        )));
        assert!(!round.add_network(
            participants[2].clone(),
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[2], round_id).unwrap()),
        ));
    }

    #[test]
    fn test_constructed_votes_reported_after_existing_certificates() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        let activities = Arc::new(Mutex::new(Vec::new()));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            RecordingReporter(activities.clone()),
            false,
        );
        let quorum = quorum(5) as usize;

        round.record_certificate(&Certificate::Notarization(build_notarization(
            &schemes, &proposal, quorum,
        )));
        round.accept_vote(
            Vote::Notarize(Notarize::sign(&schemes[0], proposal.clone()).unwrap()),
            true,
        );

        round.record_certificate(&Certificate::Nullification(build_nullification(
            &schemes, round_id, quorum,
        )));
        round.accept_vote(
            Vote::Nullify(Nullify::sign::<Sha256Digest>(&schemes[0], round_id).unwrap()),
            true,
        );

        round.record_certificate(&Certificate::Finalization(build_finalization(
            &schemes, &proposal, quorum,
        )));
        round.accept_vote(
            Vote::Finalize(Finalize::sign(&schemes[0], proposal).unwrap()),
            true,
        );

        let activities = activities.lock();
        assert_eq!(
            activities
                .iter()
                .filter(|activity| matches!(activity, Activity::Notarize(_)))
                .count(),
            1
        );
        assert_eq!(
            activities
                .iter()
                .filter(|activity| matches!(activity, Activity::Nullify(_)))
                .count(),
            1
        );
        assert_eq!(
            activities
                .iter()
                .filter(|activity| matches!(activity, Activity::Finalize(_)))
                .count(),
            1
        );
    }

    #[test]
    fn test_nullify_retry_after_certificate_is_not_reported_twice() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let activities = Arc::new(Mutex::new(Vec::new()));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            RecordingReporter(activities.clone()),
            false,
        );
        let nullify = Nullify::sign::<Sha256Digest>(&schemes[0], round_id).unwrap();

        round.accept_vote(Vote::Nullify(nullify.clone()), true);
        round.record_certificate(&Certificate::Nullification(build_nullification(
            &schemes,
            round_id,
            quorum(5) as usize,
        )));
        round.accept_vote(Vote::Nullify(nullify), true);

        assert_eq!(
            activities
                .lock()
                .iter()
                .filter(|activity| matches!(activity, Activity::Nullify(_)))
                .count(),
            1
        );
    }

    /// A finalization replaces a conflicting leader-selected proposal and
    /// makes its proposal authoritative.
    #[test]
    fn test_finalization_establishes_proposal() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[1].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );

        // The leader's notarize arrives before the leader is known.
        let leader_proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"leader"]));
        let notarize = Notarize::sign(&schemes[0], leader_proposal).unwrap();
        assert!(round.add_network(participants[0].clone(), Vote::Notarize(notarize)));

        // Setting the leader selects its buffered proposal.
        round.set_leader(Participant::from_usize(0));

        // The finalization replaces the leader-selected proposal.
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"finalized"]));
        let finalization = build_finalization(&schemes, &proposal, quorum(5) as usize);
        assert!(!round.record_certificate(&Certificate::Finalization(finalization)));
        assert!(round.has_certificate(Kind::Finalization));

        // The finalization's proposal remains selected.
        assert_eq!(
            round.try_forward_proposal(Participant::from_usize(1)),
            Some(proposal)
        );
    }

    /// A locally constructed finalize establishes the proposal without a known
    /// leader.
    #[test]
    fn test_constructed_finalize_establishes_proposal() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(
            round_id,
            View::zero(),
            Sha256::hash(&[b"notarized_payload"]),
        );
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );

        // The constructed finalize establishes the proposal without relying
        // on a leader vote.
        let finalize = Finalize::sign(&schemes[0], proposal.clone()).unwrap();
        round.accept_vote(Vote::Finalize(finalize), true);
        assert_eq!(
            round.try_forward_proposal(Participant::from_usize(0)),
            Some(proposal)
        );
    }

    /// A locally recovered certificate makes its proposal authoritative before
    /// compacting the corresponding vote phase.
    #[test_async]
    async fn test_local_certificate_preserves_proposal_authority() {
        for kind in [Kind::Notarization, Kind::Finalization] {
            let mut rng = test_rng();
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = ed25519::fixture(&mut rng, b"batcher_test", 5);
            let quorum_size = quorum(5) as usize;
            let round_id = Round::new(Epoch::new(0), View::new(1));
            let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"certified"]));
            let mut round = super::Round::new(
                round_id,
                Arc::new(verifier),
                NoopBlocker,
                NoopReporter(PhantomData),
                false,
            );

            let leader = Participant::from_usize(0);
            let notarize = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            assert!(round.add_network(participants[0].clone(), Vote::Notarize(notarize)));
            round.set_leader(leader);
            match kind {
                Kind::Notarization => {
                    for i in 1..quorum_size {
                        let notarize = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                        assert!(
                            round.add_network(participants[i].clone(), Vote::Notarize(notarize))
                        );
                    }
                }
                Kind::Finalization => {
                    for i in 0..quorum_size {
                        let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
                        assert!(
                            round.add_network(participants[i].clone(), Vote::Finalize(finalize))
                        );
                    }
                }
                Kind::Nullification => unreachable!(),
            }

            let (batch, invalid) = round
                .try_verify(&mut rng, &Sequential)
                .await
                .expect("certificate quorum must be ready");
            assert_eq!(batch, quorum_size);
            assert!(invalid.is_empty());
            let certificate = round
                .try_construct_certificate(&Sequential)
                .await
                .expect("verified quorum must construct a certificate");
            assert_eq!(certificate.kind(), kind);

            let conflicting =
                Proposal::new(round_id, View::zero(), Sha256::hash(&[b"conflicting"]));
            let conflicting = match kind {
                Kind::Notarization => Certificate::Finalization(build_finalization(
                    &schemes,
                    &conflicting,
                    quorum_size,
                )),
                Kind::Finalization => Certificate::Notarization(build_notarization(
                    &schemes,
                    &conflicting,
                    quorum_size,
                )),
                Kind::Nullification => unreachable!(),
            };
            assert!(!round.record_certificate(&conflicting));
            assert_eq!(
                round.try_forward_proposal(Participant::from_usize(1)),
                Some(proposal)
            );
        }
    }

    /// A constructed finalize is added as verified while restoring only
    /// matching network votes after replacing a conflicting leader proposal.
    #[test_async]
    async fn test_constructed_finalize_restores_only_network_votes() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            verifier,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let quorum_size = quorum(5) as usize;
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(verifier),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"notarized"]));

        // Select a conflicting proposal from the leader's buffered vote.
        let leader = Participant::from_usize(quorum_size);
        let conflicting = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"conflicting"]));
        let notarize = Notarize::sign(&schemes[quorum_size], conflicting).unwrap();
        assert!(round.add_network(participants[quorum_size].clone(), Vote::Notarize(notarize)));
        round.set_leader(leader);

        // These votes are retained by the tracker but filtered from the verifier.
        for i in 1..quorum_size {
            let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Finalize(finalize)));
        }

        // The constructed finalize replaces the proposal and restores the
        // matching network votes before it enters the tracker itself.
        let finalize = Finalize::sign(&schemes[0], proposal.clone()).unwrap();
        round.accept_vote(Vote::Finalize(finalize), true);

        // Only the network votes require verification.
        let (batch, invalid) = round
            .try_verify(&mut rng, &Sequential)
            .await
            .expect("restored finalize quorum must be ready");
        assert_eq!(batch, quorum_size - 1);
        assert!(invalid.is_empty());
        let certificate = round
            .try_construct_certificate(&Sequential)
            .await
            .expect("restored finalize quorum must construct a certificate");
        assert!(
            matches!(certificate, Certificate::Finalization(finalization) if finalization.proposal == proposal)
        );
    }

    /// A notarization restores matching finalize votes that were filtered when
    /// a conflicting leader proposal was selected.
    #[test_async]
    async fn test_notarization_restores_filtered_finalizes() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            verifier,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let quorum_size = quorum(5) as usize;
        let round_id = Round::new(Epoch::new(0), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(verifier),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"notarized"]));

        // Buffer some matching finalizes before selecting a proposal.
        for i in 0..quorum_size / 2 {
            let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Finalize(finalize)));
        }

        // Selecting a conflicting leader proposal filters the buffered votes.
        let leader = Participant::from_usize(quorum_size);
        let conflicting = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"conflicting"]));
        let notarize = Notarize::sign(&schemes[quorum_size], conflicting).unwrap();
        assert!(round.add_network(participants[quorum_size].clone(), Vote::Notarize(notarize)));
        round.set_leader(leader);

        // Matching finalizes received afterward are retained only by the vote
        // tracker because they do not match the selected proposal.
        for i in quorum_size / 2..quorum_size {
            let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Finalize(finalize)));
        }

        // The authoritative notarization restores both sets of votes.
        let notarization = build_notarization(&schemes, &proposal, quorum_size);
        assert!(round.record_certificate(&Certificate::Notarization(notarization)));
        let (batch, invalid) = round
            .try_verify(&mut rng, &Sequential)
            .await
            .expect("restored finalize quorum must be ready");
        assert_eq!(batch, quorum_size);
        assert!(invalid.is_empty());
        let certificate = round
            .try_construct_certificate(&Sequential)
            .await
            .expect("restored finalize quorum must construct a certificate");
        assert!(
            matches!(certificate, Certificate::Finalization(finalization) if finalization.proposal == proposal)
        );
    }

    /// When multiple kinds are verifiable, votes verify in kind order.
    #[test_async]
    async fn test_verify_prioritizes_kinds_in_order() {
        let mut rng = test_rng();
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut rng, b"batcher_test", 5);
        let quorum = quorum(5) as usize;
        let round_id = Round::new(Epoch::new(333), View::new(1));
        let mut round = super::Round::new(
            round_id,
            Arc::new(schemes[0].clone()),
            NoopBlocker,
            NoopReporter(PhantomData),
            false,
        );

        // A quorum of notarizes and a nullify from every participant
        let proposal = Proposal::new(round_id, View::zero(), Sha256::hash(&[b"payload"]));
        for (i, scheme) in schemes.iter().enumerate() {
            if i < quorum {
                let vote = Notarize::sign(scheme, proposal.clone()).unwrap();
                assert!(round.add_network(participants[i].clone(), Vote::Notarize(vote)));
            }
            let vote = Nullify::sign::<Sha256Digest>(scheme, round_id).unwrap();
            assert!(round.add_network(participants[i].clone(), Vote::Nullify(vote)));
        }
        round.set_leader(Participant::from_usize(0));

        // Notarizes verify first, then nullifies, then nothing
        let (batch, _) = round.try_verify(&mut rng, &Sequential).await.unwrap();
        assert_eq!(batch, quorum);
        let (batch, _) = round.try_verify(&mut rng, &Sequential).await.unwrap();
        assert_eq!(batch, schemes.len());
        assert!(round.try_verify(&mut rng, &Sequential).await.is_none());
    }

    /// The leader's notarize reveals the proposal while both a finalize
    /// quorum and a notarize quorum are already buffered; a single pass must
    /// verify every ready vote kind, yielding the proposal, a notarization,
    /// and a finalization together.
    #[test_traced]
    fn test_leader_proposal_verifies_all_ready_vote_kinds() {
        let n = 5;
        let namespace = b"batcher_test";
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;
            let reporter = test_reporter(&mut context, &schemes[0]);
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter,
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<_, Sha256Digest>>(
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

            let mut participant_senders = Vec::with_capacity(n as usize);
            participant_senders.push(None);
            for participant in participants.iter().skip(1) {
                let sender = register_and_link_peer(
                    &oracle,
                    participant.clone(),
                    me.clone(),
                    0,
                    Duration::from_millis(1),
                )
                .await;
                participant_senders.push(Some(sender));
            }
            track_test_peers(&mut context, &oracle, 1, &participants, &[]).await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            let leader = Participant::from_usize(4);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"payload"]));

            // Buffer finalizes and non-leader notarizes while the leader's
            // proposal is unknown. Both kinds become verifiable together when
            // the leader's notarize arrives.
            for i in 1..n as usize {
                let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
                participant_senders[i]
                    .as_mut()
                    .unwrap()
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Finalize(finalize).encode(),
                        true,
                    );
            }
            for i in 1..usize::from(leader) {
                let notarize = Notarize::sign(&schemes[i], proposal.clone()).unwrap();
                participant_senders[i]
                    .as_mut()
                    .unwrap()
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Notarize(notarize).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            let leader = usize::from(leader);
            let notarize = Notarize::sign(&schemes[leader], proposal).unwrap();
            participant_senders[leader]
                .as_mut()
                .unwrap()
                .send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(notarize).encode(),
                    true,
                );

            let mut received_proposal = false;
            let mut received_notarization = false;
            let mut received_finalization = false;
            for _ in 0..3 {
                let message = select! {
                    message = voter_receiver.recv() => {
                        message.expect("voter receiver closed")
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {
                        panic!("timed out waiting for all ready vote kinds")
                    },
                };
                match message {
                    voter::Message::Proposal { .. } => received_proposal = true,
                    voter::Message::Verified {
                        certificate: Certificate::Notarization(_),
                        ..
                    } => received_notarization = true,
                    voter::Message::Verified {
                        certificate: Certificate::Finalization(_),
                        ..
                    } => received_finalization = true,
                    _ => panic!("unexpected voter message"),
                }
            }

            assert!(received_proposal);
            assert!(received_notarization);
            assert!(received_finalization);
        });
    }

    /// A round accumulates a numerical quorum of finalizes (`quorum - 1` for
    /// the leader's proposal A plus one for the certified override B) split
    /// across two proposals; the batcher must not mix them into a
    /// finalization certificate.
    #[test_traced]
    fn test_finalization_construction_filters_overridden_proposal() {
        let n = 5;
        let quorum = quorum(n) as usize;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|_context| async move {
            let mut rng = test_rng();
            let Fixture { schemes, .. } = ed25519::fixture(&mut rng, b"batcher_test", n);
            let round_id = Round::new(Epoch::new(333), View::new(7));
            let mut round = super::Round::new(
                round_id,
                Arc::new(schemes[0].clone()),
                NoopBlocker,
                NoopReporter(PhantomData),
                false,
            );

            let proposal_a = Proposal::new(round_id, View::new(6), Sha256::hash(&[b"proposal_a"]));
            let proposal_b = Proposal::new(round_id, View::new(6), Sha256::hash(&[b"proposal_b"]));
            round.set_leader(Participant::new(0));
            round.accept_vote(
                Vote::Notarize(Notarize::sign(&schemes[0], proposal_a.clone()).unwrap()),
                true,
            );
            for scheme in schemes.iter().take(quorum - 1) {
                round.accept_vote(
                    Vote::Finalize(Finalize::sign(scheme, proposal_a.clone()).unwrap()),
                    true,
                );
            }

            let notarization_b = build_notarization(&schemes, &proposal_b, quorum);
            round.record_certificate(&Certificate::Notarization(notarization_b));
            round.accept_vote(
                Vote::Finalize(Finalize::sign(&schemes[quorum - 1], proposal_b.clone()).unwrap()),
                true,
            );
            assert!(
                round.try_construct_certificate(&Sequential).await.is_none(),
                "mixed finalizes for old and certified proposals must not form a certificate"
            );

            // Control: all finalizes match the certified proposal.
            let mut round = super::Round::new(
                round_id,
                Arc::new(schemes[0].clone()),
                NoopBlocker,
                NoopReporter(PhantomData),
                false,
            );
            round.record_certificate(&Certificate::Notarization(build_notarization(
                &schemes,
                &proposal_b,
                quorum,
            )));
            for scheme in schemes.iter().take(quorum) {
                round.accept_vote(
                    Vote::Finalize(Finalize::sign(scheme, proposal_b.clone()).unwrap()),
                    true,
                );
            }
            let certificate = round
                .try_construct_certificate(&Sequential)
                .await
                .expect("matching finalizes should form a certificate");
            let Certificate::Finalization(finalization) = certificate else {
                panic!("expected a finalization certificate");
            };
            assert_eq!(finalization.proposal, proposal_b);
        });
    }

    /// Harness for the buffered-finalization tests: a started batcher for
    /// participant 0 (leader 1, view 1) with a finalize quorum for `proposal`
    /// buffered but not yet verifiable, since the leader's proposal is not
    /// yet known.
    struct BufferedFinalization {
        oracle: Oracle<PublicKey, deterministic::Context>,
        participants: Vec<PublicKey>,
        schemes: Vec<ed25519::Scheme>,
        /// Vote-channel senders per participant (`None` for the local node).
        participant_senders: Vec<Option<Sender<PublicKey, deterministic::Context>>>,
        me: PublicKey,
        proposal: Proposal<Sha256Digest>,
        quorum: usize,
        voter_receiver: mailbox::Receiver<voter::Message<ed25519::Scheme, Sha256Digest>>,
        /// Keeps the batcher's mailbox open for the life of the test.
        _batcher_mailbox: Mailbox<ed25519::Scheme, Sha256Digest>,
        /// Keeps the local node's registered channels open.
        _local_senders: (
            Sender<PublicKey, deterministic::Context>,
            Sender<PublicKey, deterministic::Context>,
        ),
    }

    /// Builds a [`BufferedFinalization`]: finalize votes cannot be verified
    /// while the leader's proposal is unknown, so each test reveals the
    /// proposal its own way and expects the buffered quorum to drain.
    async fn buffered_finalization_setup(
        context: &mut deterministic::Context,
    ) -> BufferedFinalization {
        let n = 5;
        let quorum = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let epoch = Epoch::new(333);
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(context, &namespace, n);
        let oracle =
            start_test_network_with_peers(context.child("network"), participants.clone()).await;
        let reporter = test_reporter(context, &schemes[0]);

        let me = participants[0].clone();
        let batcher_cfg = test_config(
            schemes[0].clone(),
            oracle.control(me.clone()),
            reporter,
            MockRelay::new(),
            epoch,
            BatcherOptions::default(),
        );
        let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);
        let (voter_sender, voter_receiver) = mailbox::new::<
            voter::Message<ed25519::Scheme, Sha256Digest>,
        >(context.child("mailbox"), NZUsize!(1024));
        let voter_mailbox = voter::Mailbox::new(voter_sender);

        let (vote_sender, vote_receiver) = oracle
            .control(me.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (certificate_sender, certificate_receiver) = oracle
            .control(me.clone())
            .register(1, TEST_QUOTA)
            .await
            .unwrap();

        let mut participant_senders = Vec::new();
        for (i, pk) in participants.iter().enumerate() {
            if i == 0 {
                participant_senders.push(None);
                continue;
            }
            let sender = register_and_link_peer(
                &oracle,
                pk.clone(),
                me.clone(),
                0,
                Duration::from_millis(1),
            )
            .await;
            participant_senders.push(Some(sender));
        }
        track_test_peers(context, &oracle, 1, &participants, &[]).await;

        batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

        let view = View::new(1);
        let leader = Participant::new(1);
        batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
        context.sleep(Duration::from_millis(5)).await;

        let round = Round::new(epoch, view);
        let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

        for i in 1..=quorum {
            let vote = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
            participant_senders[i]
                .as_mut()
                .expect("participant sender")
                .send(
                    Recipients::One(me.clone()),
                    Vote::Finalize(vote).encode(),
                    true,
                );
        }
        context.sleep(Duration::from_millis(10)).await;

        BufferedFinalization {
            oracle,
            participants,
            schemes,
            participant_senders,
            me,
            proposal,
            quorum,
            voter_receiver,
            _batcher_mailbox: batcher_mailbox,
            _local_senders: (vote_sender, certificate_sender),
        }
    }

    /// Drains voter messages until both a notarization and a finalization for
    /// `proposal` arrive, panicking on anything else or on timeout.
    async fn expect_notarization_and_finalization<S: Scheme<Sha256Digest>>(
        context: &mut deterministic::Context,
        voter_receiver: &mut mailbox::Receiver<voter::Message<S, Sha256Digest>>,
        proposal: &Proposal<Sha256Digest>,
    ) {
        let mut saw_notarization = false;
        let mut saw_finalization = false;
        while !(saw_notarization && saw_finalization) {
            select! {
                output = voter_receiver.recv() => match output {
                    Some(voter::Message::Proposal { proposal: p, .. }) => {
                        assert_eq!(&p, proposal);
                    }
                    Some(voter::Message::Verified {
                        certificate: Certificate::Notarization(n),
                        ..
                    }) => {
                        assert_eq!(&n.proposal, proposal);
                        saw_notarization = true;
                    }
                    Some(voter::Message::Verified {
                        certificate: Certificate::Finalization(f),
                        ..
                    }) => {
                        assert_eq!(&f.proposal, proposal);
                        saw_finalization = true;
                    }
                    Some(_) => panic!("unexpected batcher output"),
                    None => panic!("voter receiver closed"),
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("timed out waiting for notarization and finalization");
                },
            }
        }
    }

    /// The leader's notarize vote arrives last, after a full finalize quorum
    /// is already buffered, so setting the proposal must drain the ready
    /// finalize batch in the same pass, yielding both certificates. (The
    /// notarize loop starts at signer 2 to keep the leader's vote, which
    /// reveals the proposal, for the end.)
    #[test_traced]
    fn test_local_notarization_drains_ready_finalization() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let mut s = buffered_finalization_setup(&mut context).await;

            for i in 2..=s.quorum {
                let vote = Notarize::sign(&s.schemes[i], s.proposal.clone()).unwrap();
                s.participant_senders[i]
                    .as_mut()
                    .expect("participant sender")
                    .send(
                        Recipients::One(s.me.clone()),
                        Vote::Notarize(vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(10)).await;

            let leader_vote = Notarize::sign(&s.schemes[1], s.proposal.clone()).unwrap();
            s.participant_senders[1]
                .as_mut()
                .expect("leader sender")
                .send(
                    Recipients::One(s.me.clone()),
                    Vote::Notarize(leader_vote).encode(),
                    true,
                );

            expect_notarization_and_finalization(&mut context, &mut s.voter_receiver, &s.proposal)
                .await;
        });
    }

    /// A notarization certificate received from the network reveals the
    /// proposal, so the actor must revisit the round, forward the
    /// certificate, and construct a finalization from the votes it unlocked.
    #[test_traced]
    fn test_network_notarization_unlocks_buffered_finalization() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let mut s = buffered_finalization_setup(&mut context).await;

            // Certificate channel for participant 1 (the vote link already exists).
            let (mut certificate_injector, _receiver) = s
                .oracle
                .control(s.participants[1].clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let notarization = build_notarization(&s.schemes, &s.proposal, s.quorum);
            certificate_injector.send(
                Recipients::One(s.me.clone()),
                Certificate::<ed25519::Scheme, Sha256Digest>::Notarization(notarization).encode(),
                true,
            );

            expect_notarization_and_finalization(&mut context, &mut s.voter_receiver, &s.proposal)
                .await;
        });
    }

    #[test_traced]
    fn test_rejected_finalize_still_detects_conflicting_finalize() {
        let n = 5;
        let quorum = quorum(n) as usize;
        let namespace = b"batcher_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);
            let reporter = test_reporter(&mut context, &schemes[0]);
            let round_id = Round::new(Epoch::new(333), View::new(7));
            let mut round = super::Round::new(
                round_id,
                Arc::new(schemes[0].clone()),
                NoopBlocker,
                reporter.clone(),
                false,
            );

            let proposal_a = Proposal::new(round_id, View::new(6), Sha256::hash(&[b"proposal_a"]));
            let proposal_b = Proposal::new(round_id, View::new(6), Sha256::hash(&[b"proposal_b"]));
            round.record_certificate(&Certificate::Notarization(build_notarization(
                &schemes,
                &proposal_b,
                quorum,
            )));

            // The first finalize is reserved in the tracker even though the
            // verifier filters it (it references the displaced proposal).
            let sender = participants[1].clone();
            let finalize_a = Finalize::sign(&schemes[1], proposal_a).unwrap();
            assert!(round.add_network(sender.clone(), Vote::Finalize(finalize_a)));
            assert!(
                reporter.faults.lock().is_empty(),
                "a single filtered finalize is not conflicting evidence"
            );

            let finalize_b = Finalize::sign(&schemes[1], proposal_b).unwrap();
            assert!(!round.add_network(sender.clone(), Vote::Finalize(finalize_b)));
            let faults = reporter.faults.lock();
            let has_expected_fault = faults
                .get(&sender)
                .and_then(|sf| sf.get(&round_id.view()))
                .is_some_and(|vf| vf.iter().any(is_conflicting_finalize));
            assert!(
                has_expected_fault,
                "conflicting finalize should be reported even if the first vote was not accepted for verification"
            );
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(
                    context.child("mailbox"),
                    NZUsize!(1024),
                );
            let voter_mailbox = voter::Mailbox::new(voter_sender);

            // Register the batcher's vote and certificate channels.
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

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

    /// Regression: a notarization for a future view must unlock already-buffered
    /// finalize votes even though that view's leader is not yet known.
    fn notarization_unlocks_future_finalizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_notarization_unlocks_future_finalizes".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Get participants.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock.
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor.
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter,
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to.
            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(
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

            // Register finalize-vote senders and link them to the batcher.
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            let mut finalize_senders = Vec::new();
            for (i, participant) in participants
                .iter()
                .enumerate()
                .skip(1)
                .take(quorum_size - 1)
            {
                let (sender, _receiver) = oracle
                    .control(participant.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(participant.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                finalize_senders.push((i, sender));
            }

            // Register a sender for the notarization certificate.
            let (mut notarization_sender, _receiver) = oracle
                .control(participants[1].clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the batcher.
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Initialize the batcher. The future view's leader remains unknown.
            let current = View::new(1);
            batcher_mailbox.update(
                Span::none(),
                current,
                Participant::new(0),
                View::zero(),
                None,
            );

            // Build a proposal for the future view.
            let future = current.next();
            let proposal = Proposal::new(
                Round::new(epoch, future),
                current,
                Sha256::hash(&[b"future_payload"]),
            );

            // Buffer the network finalize votes before the notarization. The
            // future round has no leader yet, so they cannot be verified.
            for (i, mut sender) in finalize_senders {
                let finalize = Finalize::sign(&schemes[i], proposal.clone()).unwrap();
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::Finalize(finalize).encode(),
                        true,
                    );
            }

            // Allow all finalize votes to arrive before the notarization.
            context.sleep(Duration::from_millis(50)).await;

            // The notarization authenticates the proposal without announcing
            // the future round's leader.
            let notarization = build_notarization(&schemes, &proposal, quorum_size);
            notarization_sender
                .send(
                    Recipients::One(me),
                    Certificate::Notarization(notarization).encode(),
                    true,
                );

            // The notarization is forwarded before the recovered finalization.
            let mut saw_notarization = false;
            loop {
                let message = select! {
                    message = voter_receiver.recv() => message,
                    _ = context.sleep(Duration::from_millis(100)) => {
                        panic!("timed out waiting for finalization");
                    },
                };
                match message.unwrap() {
                    voter::Message::Verified {
                        certificate: Certificate::Notarization(notarization),
                        ..
                    } => {
                        assert_eq!(notarization.proposal, proposal);

                        // Complete the quorum only after the notarization has made
                        // the buffered network votes eligible.
                        let finalize = Finalize::sign(&schemes[0], proposal.clone()).unwrap();
                        batcher_mailbox.constructed(Vote::Finalize(finalize));
                        saw_notarization = true;
                    }
                    voter::Message::Verified {
                        certificate: Certificate::Finalization(finalization),
                        ..
                    } => {
                        assert!(saw_notarization);
                        assert_eq!(finalization.proposal, proposal);
                        break;
                    },
                    _ => {}
                }
            };
        });
    }

    #[test_traced]
    fn test_notarization_unlocks_future_finalizes() {
        notarization_unlocks_future_finalizes(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_unlocks_future_finalizes(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_unlocks_future_finalizes(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_unlocks_future_finalizes(bls12381_threshold_std::fixture::<MinSig, _>);
        notarization_unlocks_future_finalizes(bls12381_multisig::fixture::<MinPk, _>);
        notarization_unlocks_future_finalizes(bls12381_multisig::fixture::<MinSig, _>);
        notarization_unlocks_future_finalizes(ed25519::fixture);
        notarization_unlocks_future_finalizes(secp256r1::fixture);
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor.
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to.
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

            // Create a peer to inject certificates.
            let injector_pk = PrivateKey::from_seed(1_000_001).public_key();
            let mut injector_sender = register_and_link_peer(
                &oracle,
                injector_pk.clone(),
                me.clone(),
                1,
                Duration::from_millis(1),
            )
            .await;
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));
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

    /// A certificate that fails verification must block the sender, while a
    /// valid certificate from the same sender must not.
    fn invalid_certificate_blocks_sender<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_invalid_certificate".to_vec();
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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

            // Create a peer to inject certificates.
            let injector_pk = PrivateKey::from_seed(1_000_001).public_key();
            let mut injector_sender = register_and_link_peer(
                &oracle,
                injector_pk.clone(),
                me.clone(),
                1,
                Duration::from_millis(1),
            )
            .await;
            track_test_peers(
                &mut context,
                &oracle,
                1,
                &participants,
                std::slice::from_ref(&injector_pk),
            )
            .await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let target_view = View::new(1);
            batcher_mailbox.update(
                Span::none(),
                target_view,
                Participant::new(0),
                View::zero(),
                None,
            );

            let round = Round::new(epoch, target_view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

            // A valid certificate must not block the sender.
            let nullification = build_nullification(&schemes, round, quorum_size);
            injector_sender.send(
                Recipients::One(me.clone()),
                Certificate::<S, Sha256Digest>::Nullification(nullification).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.is_empty(),
                "Valid certificate should not block the sender"
            );

            // Tamper with a valid notarization: the certificate no longer
            // covers the substituted proposal, so verification must fail and
            // the sender must be blocked.
            let mut notarization = build_notarization(&schemes, &proposal, quorum_size);
            notarization.proposal =
                Proposal::new(round, View::zero(), Sha256::hash(&[b"other_payload"]));
            injector_sender.send(
                Recipients::One(me.clone()),
                Certificate::Notarization(notarization).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;
            let blocked = oracle.blocked().await.unwrap();
            assert!(
                blocked.iter().any(|(_, blocked)| blocked == &injector_pk),
                "Sender should be blocked for invalid certificate"
            );
        });
    }

    #[test_traced]
    fn test_invalid_certificate_blocks_sender() {
        invalid_certificate_blocks_sender(bls12381_threshold_vrf::fixture::<MinPk, _>);
        invalid_certificate_blocks_sender(bls12381_threshold_vrf::fixture::<MinSig, _>);
        invalid_certificate_blocks_sender(bls12381_threshold_std::fixture::<MinPk, _>);
        invalid_certificate_blocks_sender(bls12381_threshold_std::fixture::<MinSig, _>);
        invalid_certificate_blocks_sender(bls12381_multisig::fixture::<MinPk, _>);
        invalid_certificate_blocks_sender(bls12381_multisig::fixture::<MinSig, _>);
        invalid_certificate_blocks_sender(ed25519::fixture);
        invalid_certificate_blocks_sender(secp256r1::fixture);
    }

    /// Regression: a valid notarization for a view beyond the admission
    /// window creates a round with a certificate proposal but no leader. The
    /// batcher must not panic on the missing leader and must forward the
    /// certificate-established proposal.
    fn future_notarization_without_leader_does_not_panic<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum_size = quorum(n) as usize;
        let namespace = b"batcher_future_notarization_without_leader".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor.
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to.
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

            // Create a peer to inject certificates.
            let injector_pk = PrivateKey::from_seed(1_000_001).public_key();
            let mut injector_sender = register_and_link_peer(
                &oracle,
                injector_pk.clone(),
                me.clone(),
                1,
                Duration::from_millis(1),
            )
            .await;
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

            // Initialize batcher at view 1.
            let current_view = View::new(1);
            batcher_mailbox
                .update(Span::none(), current_view, Participant::new(0), View::zero(), None);

            // Send a valid notarization for a view beyond the admission
            // window (the leader is a signer other than us, so the proposal is
            // a candidate for forwarding).
            let future_view = View::new(3);
            let future_round = Round::new(epoch, future_view);
            let future_proposal =
                Proposal::new(future_round, View::zero(), Sha256::hash(&[b"future_payload"]));
            let notarization = build_notarization(&schemes, &future_proposal, quorum_size);
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Notarization(notarization).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            // The certificate must be forwarded to the voter.
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == future_view)
            );

            // The certificate-established proposal is forwarded even though
            // no leader is known for the round.
            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(&output, voter::Message::Proposal { proposal, .. } if proposal == &future_proposal)
            );

            // The batcher must still be alive to process further certificates.
            let current_round = Round::new(epoch, current_view);
            let nullification = build_nullification(&schemes, current_round, quorum_size);
            injector_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::<S, Sha256Digest>::Nullification(nullification).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

            let output = voter_receiver.recv().await.unwrap();
            assert!(
                matches!(output, voter::Message::Verified { certificate: Certificate::Nullification(n), .. } if n.view() == current_view)
            );
        });
    }

    #[test_traced]
    fn test_future_notarization_without_leader_does_not_panic() {
        // The missing-leader path is scheme-independent; one batchable and
        // one non-batchable scheme cover both verification flows.
        future_notarization_without_leader_does_not_panic(ed25519::fixture);
        future_notarization_without_leader_does_not_panic(secp256r1::fixture);
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

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
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(&[b"test_payload"]))
            );

            // Should receive notarization certificate from quorum of votes
            let output = voter_receiver.recv().await.unwrap();
            assert!(matches!(output, voter::Message::Verified { certificate: Certificate::Notarization(n), .. } if n.view() == view));

            // ForwardPolicy::Disabled must not produce any broadcasts
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
                    event.metadata.content == "constructed certificate, forwarding to voter"
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentVoters, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentLeader, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
                Sha256::hash(&[b"silent_leader_payload"]),
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
    /// the previous proposal as forwardable before forwarding the block.
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentVoters, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
                Sha256::hash(&[b"payload"]),
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentVoters, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
                Sha256::hash(&[b"certificate_only_payload"]),
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentVoters, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
            let proposal_a = Proposal::new(round2, View::new(1), Sha256::hash(&[b"proposal_a"]));
            let proposal_b = Proposal::new(round2, View::new(1), Sha256::hash(&[b"proposal_b"]));

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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let relay = MockRelay::new();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                relay.clone(),
                epoch,
                BatcherOptions { forward: ForwardPolicy::SilentVoters, ..Default::default() },
            );
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round2, View::new(1), Sha256::hash(&[b"payload"]));

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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Set up batcher as participant 0
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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
            let proposal_a = Proposal::new(round, View::zero(), Sha256::hash(&[b"payload_a"]));
            let proposal_b = Proposal::new(round, View::zero(), Sha256::hash(&[b"payload_b"]));

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
                voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(&[b"payload_a"])
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor as participant 0
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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

            // Initialize batcher with view 1, participant 1 as leader
            // We (participant 0) are NOT the leader
            let view = View::new(1);
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);

            // Give time for update to process
            context.sleep(Duration::from_millis(10)).await;

            // Build proposal and leader's vote
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));
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
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(&[b"test_payload"])),
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor as participant 0
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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

            // Start the batcher - but don't set leader yet
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Build proposal and leader's vote for view 1 with participant 1 as leader
            let view = View::new(1);
            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));
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
                matches!(&output, voter::Message::Proposal { proposal: p, .. } if p.view() == view && p.payload == Sha256::hash(&[b"test_payload"])),
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

    /// Regression: a leader vote for an in-window optimistic future view must forward
    /// its proposal to the voter even when current view is behind.
    fn optimistic_future_proposal_forwarded<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_optimistic_future_proposal_forwarded".to_vec();
        let epoch = Epoch::new(335);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter,
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    lookahead: Lookahead {
                        term_length: TermLength::new(commonware_utils::NZU32!(5)),
                        optimistic_views: ViewDelta::new(2),
                    },
                    ..Default::default()
                },
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(
                    context.child("voter_mailbox"),
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

            let leader = Participant::new(1);
            let leader_pk = participants[usize::from(leader)].clone();
            let mut leader_sender = register_and_link_peer(
                &oracle,
                leader_pk,
                me.clone(),
                0,
                Duration::from_millis(1),
            )
            .await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let current_view = View::new(1);
            batcher_mailbox.update(Span::none(), current_view, leader, View::zero(), None);

            let future_view = View::new(3);
            let proposal = Proposal::new(
                Round::new(epoch, future_view),
                View::new(2),
                Sha256::hash(&[b"optimistic_future_proposal"]),
            );
            let vote = Notarize::sign(&schemes[usize::from(leader)], proposal.clone()).unwrap();
            let _ = leader_sender.send(
                Recipients::One(me),
                Vote::<S, Sha256Digest>::Notarize(vote).encode(),
                true,
            );

            select! {
                message = voter_receiver.recv() => match message {
                    Some(voter::Message::Proposal { proposal: p, .. }) => {
                        assert_eq!(p.view(), future_view);
                        assert_eq!(p.payload, proposal.payload);
                    },
                    Some(_) => panic!("expected forwarded optimistic future proposal"),
                    None => panic!("voter channel closed"),
                },
                _ = context.sleep(Duration::from_millis(250)) => {
                    panic!("expected forwarded optimistic future proposal for view {}", future_view)
                }
            }
        });
    }

    /// Admission-window forwarding does not touch signature handling, so one
    /// scheme is enough.
    #[test_traced]
    fn test_optimistic_future_proposal_forwarded() {
        optimistic_future_proposal_forwarded(ed25519::fixture);
    }

    /// Test that leader activity detection works correctly:
    /// 1. Leaders remain active before `skip_timeout` elapses.
    /// 2. Quiet networks fail open until a quorum has recent activity.
    /// 3. Local leader inactivity is suppressed.
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(skip_timeout),
                        budget: SkipBudget::Participants,
                    },
                    ..Default::default()
                },
            );
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

            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            let mut peer_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate().skip(1) {
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                peer_senders.push((i, sender));
            }

            // Start the batcher
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Test 1: Before skip_timeout elapses, leaders should stay active.
            let leader = Participant::new(1);
            for v in 1..skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Test 2: Even at the skip timeout, we fail open while fewer than a quorum of
            // participants have been recently active.
            let view = View::new(skip_timeout);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Test 3: Jump far ahead. We still fail open because we never observed a quorum of
            // recently active participants.
            let view = View::new(100);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Seed quorum activity from peers only. If local-leader suppression
            // were removed, the next update would return Inactivity.
            for (i, mut sender) in peer_senders {
                let vote =
                    Nullify::sign::<Sha256Digest>(&schemes[i], Round::new(epoch, View::new(99)))
                        .unwrap();
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            // Test 4: local leader inactivity should not trigger a fast-timeout hint.
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

    /// Test that a stale leader is reported inactive once the rest of the network is active.
    fn leader_inactivity_reported_after_quorum_activity<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_inactivity_after_quorum_activity".to_vec();
        let epoch = Epoch::new(333);
        let skip_timeout = 5u64;
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(skip_timeout),
                        budget: SkipBudget::Participants,
                    },
                    ..Default::default()
                },
            );
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

            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate().skip(2) {
                let sender = register_and_link_peer(
                    &oracle,
                    pk.clone(),
                    me.clone(),
                    0,
                    Duration::from_millis(1),
                )
                .await;
                participant_senders.push((i, sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let leader = Participant::new(1);
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            let self_vote = Nullify::sign::<Sha256Digest>(&schemes[0], Round::new(epoch, view))
                .expect("self nullify");
            batcher_mailbox.constructed(Vote::<S, Sha256Digest>::Nullify(self_vote));

            for (i, mut sender) in participant_senders {
                let vote = Nullify::sign::<Sha256Digest>(&schemes[i], Round::new(epoch, view))
                    .expect("peer nullify");
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            let next_view = view.next();
            batcher_mailbox.update(Span::none(), next_view, leader, View::zero(), None);
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                next_view,
                TimeoutReason::Inactivity,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_leader_inactivity_reported_after_quorum_activity() {
        leader_inactivity_reported_after_quorum_activity(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        leader_inactivity_reported_after_quorum_activity(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        leader_inactivity_reported_after_quorum_activity(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        leader_inactivity_reported_after_quorum_activity(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        leader_inactivity_reported_after_quorum_activity(bls12381_multisig::fixture::<MinPk, _>);
        leader_inactivity_reported_after_quorum_activity(bls12381_multisig::fixture::<MinSig, _>);
        leader_inactivity_reported_after_quorum_activity(ed25519::fixture);
        leader_inactivity_reported_after_quorum_activity(secp256r1::fixture);
    }

    /// Test that an inactivity hint does not suppress the later leader-nullify
    /// fast path for the same view.
    ///
    /// The voter treats inactivity as advisory and ignores it when the leader's
    /// proposal is already buffered, so the batcher must still deliver the
    /// leader's own nullify.
    ///
    /// The interaction is in the batcher's timeout bookkeeping and does not
    /// touch signature handling, so one scheme is enough.
    #[test_traced]
    fn test_leader_nullify_after_inactivity_still_fast_paths() {
        let n = 5;
        let namespace = b"batcher_leader_nullify_after_inactivity".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) = mailbox::new::<
                voter::Message<ed25519::Scheme, Sha256Digest>,
            >(
                context.child("mailbox"), NZUsize!(1024)
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

            let leader = Participant::new(1);
            let mut leader_sender = register_and_link_peer(
                &oracle,
                participants[usize::from(leader)].clone(),
                me.clone(),
                0,
                Duration::from_millis(1),
            )
            .await;
            let mut peer_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate().skip(2) {
                let sender = register_and_link_peer(
                    &oracle,
                    pk.clone(),
                    me.clone(),
                    0,
                    Duration::from_millis(1),
                )
                .await;
                peer_senders.push((i, sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Make everyone but the leader recently active so the inactivity
            // heuristic arms for the next view.
            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            for (i, sender) in peer_senders.iter_mut() {
                let vote = Nullify::sign::<Sha256Digest>(&schemes[*i], Round::new(epoch, view))
                    .expect("peer nullify");
                sender.send(
                    Recipients::One(me.clone()),
                    Vote::<ed25519::Scheme, Sha256Digest>::Nullify(vote).encode(),
                    true,
                );
            }
            context.sleep(Duration::from_millis(50)).await;

            let next_view = view.next();
            batcher_mailbox.update(Span::none(), next_view, leader, View::zero(), None);
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                next_view,
                TimeoutReason::Inactivity,
            )
            .await;

            // The leader is silent but alive: its nullify must still reach the
            // voter, which may have discarded the advisory hint above.
            let leader_nullify = Nullify::sign::<Sha256Digest>(
                &schemes[usize::from(leader)],
                Round::new(epoch, next_view),
            )
            .expect("leader nullify");
            leader_sender.send(
                Recipients::One(me.clone()),
                Vote::<ed25519::Scheme, Sha256Digest>::Nullify(leader_nullify).encode(),
                true,
            );
            expect_timeout(
                &mut context,
                &mut voter_receiver,
                next_view,
                TimeoutReason::LeaderNullify,
            )
            .await;
        });
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(skip_timeout),
                        budget: SkipBudget::Participants,
                    },
                    ..Default::default()
                },
            );
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
                success_rate: probability!(1.0),
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
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate().skip(2) {
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push((i, sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let leader = Participant::new(1);
            for v in 1..=skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Seed quorum activity without the leader. If the leader nullify below
            // is not recorded as activity, the next update will return Inactivity.
            let self_vote = Nullify::sign::<Sha256Digest>(
                &schemes[0],
                Round::new(epoch, View::new(skip_timeout - 1)),
            )
            .unwrap();
            batcher_mailbox.constructed(Vote::<S, Sha256Digest>::Nullify(self_vote));
            for (i, mut sender) in participant_senders {
                let vote = Nullify::sign::<Sha256Digest>(
                    &schemes[i],
                    Round::new(epoch, View::new(skip_timeout)),
                )
                .unwrap();
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            // Send a nullify vote from the leader for a prior view. This records
            // activity without triggering the current-view leader-nullify fast path.
            let round = Round::new(epoch, View::new(skip_timeout - 1));
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    skip: SkipPolicy::Enabled {
                        timeout: Duration::from_secs(skip_timeout),
                        budget: SkipBudget::Participants,
                    },
                    ..Default::default()
                },
            );
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
                success_rate: probability!(1.0),
            };
            let leader = Participant::new(1);
            let leader_pk = participants[usize::from(leader)].clone();
            let (mut leader_sender, _leader_receiver) = oracle
                .control(leader_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(leader_pk.clone(), me.clone(), link.clone())
                .await
                .unwrap();
            let mut participant_senders = Vec::new();
            for (i, pk) in participants.iter().enumerate().skip(2) {
                let (sender, _receiver) = oracle
                    .control(pk.clone())
                    .register(0, TEST_QUOTA)
                    .await
                    .unwrap();
                oracle
                    .add_link(pk.clone(), me.clone(), link.clone())
                    .await
                    .unwrap();
                participant_senders.push((i, sender));
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Advance through the early views with no leader traffic. The skip-timeout
            // heuristic should not fire before the threshold is reached.
            for v in 1..skip_timeout {
                let view = View::new(v);
                batcher_mailbox.update(Span::none(), view, leader, View::zero(), None);
            }

            // Enter the threshold view with no activity and confirm that we fail open while the
            // network is quiet.
            let active_view = View::new(skip_timeout);
            batcher_mailbox.update(Span::none(), active_view, leader, View::zero(), None);
            expect_no_timeout(&mut context, &mut voter_receiver).await;

            // Seed quorum activity without the leader. If the leader certificate below
            // is not recorded as activity, the next update will return Inactivity.
            let self_vote = Nullify::sign::<Sha256Digest>(
                &schemes[0],
                Round::new(epoch, active_view.previous().unwrap()),
            )
            .unwrap();
            batcher_mailbox.constructed(Vote::<S, Sha256Digest>::Nullify(self_vote));
            for (i, mut sender) in participant_senders {
                let vote =
                    Nullify::sign::<Sha256Digest>(&schemes[i], Round::new(epoch, active_view))
                        .unwrap();
                sender
                    .send(
                        Recipients::One(me.clone()),
                        Vote::<S, Sha256Digest>::Nullify(vote).encode(),
                        true,
                    );
            }
            context.sleep(Duration::from_millis(50)).await;

            // Deliver a certificate from the leader on the certificate channel. Even
            // without any vote traffic, that relay should count as fresh activity.
            let round = Round::new(epoch, active_view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));
            let finalization = build_finalization(&schemes, &proposal, quorum_size);
            leader_sender
                .send(
                    Recipients::One(me.clone()),
                    Certificate::Finalization(finalization.clone()).encode(),
                    true,
                );
            context.sleep(Duration::from_millis(50)).await;

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

    /// Verifies how the configured skip policy handles a buffered leader nullify
    /// when its view becomes current.
    fn leader_nullify_on_view_entry<S, F>(mut fixture: F, skip: SkipPolicy)
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    skip,
                    ..Default::default()
                },
            );
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
                        success_rate: probability!(1.0),
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

            // Enter the buffered view with the same leader. Enabled skipping reports the
            // leader nullify to the voter immediately; disabled skipping reports nothing.
            batcher_mailbox.update(Span::none(), buffered_view, leader_idx, View::zero(), None);
            if matches!(skip, SkipPolicy::Enabled { .. }) {
                expect_timeout(
                    &mut context,
                    &mut voter_receiver,
                    buffered_view,
                    TimeoutReason::LeaderNullify,
                )
                .await;
            } else {
                expect_no_timeout(&mut context, &mut voter_receiver).await;
            }
        });
    }

    #[test_traced]
    fn test_leader_nullify_expire_on_view_entry() {
        let skip = SkipPolicy::Enabled {
            timeout: Duration::from_secs(5),
            budget: SkipBudget::Participants,
        };
        leader_nullify_on_view_entry(bls12381_threshold_vrf::fixture::<MinPk, _>, skip);
        leader_nullify_on_view_entry(bls12381_threshold_vrf::fixture::<MinSig, _>, skip);
        leader_nullify_on_view_entry(bls12381_threshold_std::fixture::<MinPk, _>, skip);
        leader_nullify_on_view_entry(bls12381_threshold_std::fixture::<MinSig, _>, skip);
        leader_nullify_on_view_entry(bls12381_multisig::fixture::<MinPk, _>, skip);
        leader_nullify_on_view_entry(bls12381_multisig::fixture::<MinSig, _>, skip);
        leader_nullify_on_view_entry(ed25519::fixture, skip);
        leader_nullify_on_view_entry(secp256r1::fixture, skip);
    }

    #[test_traced]
    fn test_disabled_skip_policy_ignores_leader_nullify_hint() {
        leader_nullify_on_view_entry(ed25519::fixture, SkipPolicy::Disabled);
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                        success_rate: probability!(1.0),
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

    /// Admission is observed through the reporter: an admitted vote is
    /// reported immediately, a vote beyond the window is not (see the
    /// companion `..._can_construct_notarization` for buffered votes becoming
    /// usable).
    fn same_term_optimistic_future_votes_are_admitted<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace = b"batcher_same_term_optimistic_future_votes_are_admitted".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    lookahead: Lookahead {
                        term_length: TermLength::new(commonware_utils::NZU32!(5)),
                        optimistic_views: ViewDelta::new(2),
                    },
                    ..Default::default()
                },
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, _voter_receiver) = mailbox::new::<voter::Message<S, Sha256Digest>>(
                context.child("voter_mailbox"),
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

            let peer = Participant::new(1);
            let peer_pk = participants[usize::from(peer)].clone();
            let mut peer_sender = register_and_link_peer(
                &oracle,
                peer_pk.clone(),
                me.clone(),
                0,
                Duration::from_millis(0),
            )
            .await;

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let current_view = View::new(1);
            batcher_mailbox.update(Span::none(), current_view, peer, View::zero(), None);

            // With optimistic_views=2 and term_length=5, view 3 is accepted while
            // view 4 is still too far in the future.
            let accepted_view = View::new(3);
            let accepted_payload = Sha256::hash(&[b"accepted_optimistic_view"]);
            let accepted_vote = Notarize::sign(
                &schemes[usize::from(peer)],
                Proposal::new(
                    Round::new(epoch, accepted_view),
                    View::new(2),
                    accepted_payload,
                ),
            )
            .expect("notarize");
            let _ = peer_sender.send(
                Recipients::One(me.clone()),
                Vote::<S, Sha256Digest>::Notarize(accepted_vote).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;

            {
                let notarizes = reporter.notarizes.lock();
                let payloads = notarizes
                    .get(&accepted_view)
                    .expect("accepted optimistic future view should be tracked");
                let signers = payloads
                    .get(&accepted_payload)
                    .expect("accepted optimistic future vote should be recorded");
                assert!(
                    signers.contains(&peer_pk),
                    "accepted optimistic future vote should include sender"
                );
            }

            let rejected_view = View::new(4);
            let rejected_vote = Notarize::sign(
                &schemes[usize::from(peer)],
                Proposal::new(
                    Round::new(epoch, rejected_view),
                    View::new(3),
                    Sha256::hash(&[b"rejected_optimistic_view"]),
                ),
            )
            .expect("notarize");
            let _ = peer_sender.send(
                Recipients::One(me),
                Vote::<S, Sha256Digest>::Notarize(rejected_vote).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;

            assert!(
                !reporter.notarizes.lock().contains_key(&rejected_view),
                "view beyond optimistic depth should still be dropped"
            );
        });
    }

    fn same_term_optimistic_future_votes_can_construct_notarization<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let namespace =
            b"batcher_same_term_optimistic_future_votes_can_construct_notarization".to_vec();
        let epoch = Epoch::new(334);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter,
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    lookahead: Lookahead {
                        term_length: TermLength::new(commonware_utils::NZU32!(5)),
                        optimistic_views: ViewDelta::new(2),
                    },
                    ..Default::default()
                },
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            let (voter_sender, mut voter_receiver) =
                mailbox::new::<voter::Message<S, Sha256Digest>>(
                    context.child("voter_mailbox"),
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

            let mut peer_senders = Vec::new();
            for peer_pk in participants.iter().skip(1).cloned() {
                let peer_sender = register_and_link_peer(
                    &oracle,
                    peer_pk,
                    me.clone(),
                    0,
                    Duration::from_millis(0),
                )
                .await;
                peer_senders.push(peer_sender);
            }

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let current_view = View::new(1);
            let leader = Participant::new(1);
            batcher_mailbox.update(Span::none(), current_view, leader, View::zero(), None);

            let future_view = View::new(3);
            let proposal = Proposal::new(
                Round::new(epoch, future_view),
                View::new(2),
                Sha256::hash(&[b"same_term_future_notarization"]),
            );

            // Send quorum votes for an optimistic future view while current remains at view 1.
            let quorum_votes = usize::try_from(quorum(n)).expect("quorum fits");
            for (scheme, sender) in schemes
                .iter()
                .skip(1)
                .zip(peer_senders.iter_mut())
                .take(quorum_votes)
            {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("notarize");
                let _ = sender.send(
                    Recipients::One(me.clone()),
                    Vote::<S, Sha256Digest>::Notarize(vote).encode(),
                    true,
                );
            }

            loop {
                select! {
                    message = voter_receiver.recv() => {
                        if matches!(
                            message,
                            Some(voter::Message::Verified {
                                certificate: Certificate::Notarization(ref notarization),
                                from_resolver: false,
                                ..
                            }) if notarization.view() == future_view
                        ) {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!(
                            "expected notarization for optimistic future view {} without waiting for view update",
                            future_view
                        );
                    }
                }
            }
        });
    }

    /// Admission-window bookkeeping does not touch signature handling, so one
    /// scheme is enough.
    #[test_traced]
    fn test_same_term_optimistic_future_votes_are_admitted() {
        same_term_optimistic_future_votes_are_admitted(ed25519::fixture);
    }

    /// Certificate construction is scheme-dependent, so cover one
    /// threshold-recovered scheme and one individual-signature scheme.
    #[test_traced]
    fn test_same_term_optimistic_future_votes_can_construct_notarization() {
        same_term_optimistic_future_votes_can_construct_notarization(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        same_term_optimistic_future_votes_can_construct_notarization(ed25519::fixture);
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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
            let proposal1 = Proposal::new(round1, View::zero(), Sha256::hash(&[b"payload1"]));
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
            let proposal2 = Proposal::new(round2, view1, Sha256::hash(&[b"payload2"]));
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

    fn startup_votes_below_activity_window_not_reported<S, F>(mut fixture: F)
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
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0) with a restored
            // finalized floor, simulating a restart before the voter has
            // replayed its journal and published the first update.
            let me = participants[0].clone();
            let floor = View::new(10);
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    view_retention: ViewDelta::new(2),
                    floor,
                    ..Default::default()
                },
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
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

            // Register a peer on the network and link it to us
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            let (mut peer_sender, _receiver) = oracle
                .control(participants[1].clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(participants[1].clone(), me.clone(), link)
                .await
                .unwrap();

            // Start the batcher without sending an initial update
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            // Send a stale view-1 vote before the first update
            let stale_view = View::new(1);
            let stale_proposal = Proposal::new(
                Round::new(epoch, stale_view),
                View::zero(),
                Sha256::hash(&[b"stale"]),
            );
            let stale = Notarize::sign(&schemes[1], stale_proposal.clone()).unwrap();
            peer_sender.send(
                Recipients::One(me.clone()),
                Vote::Notarize(stale).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;

            // Publish the restored view and send a live vote to confirm the
            // pipeline reports activity above the floor
            let current = floor.next();
            batcher_mailbox.update(Span::none(), current, Participant::new(1), floor, None);
            let live_proposal =
                Proposal::new(Round::new(epoch, current), floor, Sha256::hash(&[b"live"]));
            let live = Notarize::sign(&schemes[1], live_proposal.clone()).unwrap();
            peer_sender.send(Recipients::One(me), Vote::Notarize(live).encode(), true);
            while reporter
                .notarizes
                .lock()
                .get(&current)
                .and_then(|payloads| payloads.get(&live_proposal.payload))
                .is_none_or(|participants| participants.is_empty())
            {
                context.sleep(Duration::from_millis(1)).await;
            }

            // The stale vote below the activity window must not have produced
            // any activity (votes within `view_retention` of the floor are
            // still reported)
            assert!(
                reporter.notarizes.lock().get(&stale_view).is_none(),
                "votes below the activity window must not be reported before the first update"
            );
        });
    }

    #[test_traced]
    fn test_startup_votes_below_activity_window_not_reported() {
        startup_votes_below_activity_window_not_reported(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        startup_votes_below_activity_window_not_reported(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        startup_votes_below_activity_window_not_reported(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        startup_votes_below_activity_window_not_reported(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        startup_votes_below_activity_window_not_reported(bls12381_multisig::fixture::<MinPk, _>);
        startup_votes_below_activity_window_not_reported(bls12381_multisig::fixture::<MinSig, _>);
        startup_votes_below_activity_window_not_reported(ed25519::fixture);
        startup_votes_below_activity_window_not_reported(secp256r1::fixture);
    }

    fn votes_below_finalized_within_activity_window_reported<S, F>(mut fixture: F)
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
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions {
                    view_retention: ViewDelta::new(2),
                    ..Default::default()
                },
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
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

            // Register a peer on the network and link it to us
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: probability!(1.0),
            };
            let (mut peer_sender, _receiver) = oracle
                .control(participants[1].clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(participants[1].clone(), me.clone(), link)
                .await
                .unwrap();

            // Start the batcher and advance past the straggler's view
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);
            let finalized = View::new(10);
            batcher_mailbox.update(
                Span::none(),
                finalized.next(),
                Participant::new(1),
                finalized,
                None,
            );

            // Send a vote below the activity window, which must be ignored
            let stale_view = View::new(7);
            let stale_proposal = Proposal::new(
                Round::new(epoch, stale_view),
                View::new(6),
                Sha256::hash(&[b"stale"]),
            );
            let stale = Notarize::sign(&schemes[1], stale_proposal).unwrap();
            peer_sender.send(
                Recipients::One(me.clone()),
                Vote::Notarize(stale).encode(),
                true,
            );
            context.sleep(Duration::from_millis(50)).await;

            // Send a straggler vote at or below the finalized tip but within
            // the activity window, which must still be reported
            let window_view = View::new(9);
            let window_proposal = Proposal::new(
                Round::new(epoch, window_view),
                View::new(8),
                Sha256::hash(&[b"window"]),
            );
            let window = Notarize::sign(&schemes[1], window_proposal.clone()).unwrap();
            peer_sender.send(Recipients::One(me), Vote::Notarize(window).encode(), true);
            while reporter
                .notarizes
                .lock()
                .get(&window_view)
                .and_then(|payloads| payloads.get(&window_proposal.payload))
                .is_none_or(|participants| participants.is_empty())
            {
                context.sleep(Duration::from_millis(1)).await;
            }

            // The below-window vote must not have produced any activity
            assert!(
                reporter.notarizes.lock().get(&stale_view).is_none(),
                "votes below the activity window must not be reported"
            );
        });
    }

    #[test_traced]
    fn test_votes_below_finalized_within_activity_window_reported() {
        votes_below_finalized_within_activity_window_reported(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        votes_below_finalized_within_activity_window_reported(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        votes_below_finalized_within_activity_window_reported(
            bls12381_threshold_std::fixture::<MinPk, _>,
        );
        votes_below_finalized_within_activity_window_reported(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        votes_below_finalized_within_activity_window_reported(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        votes_below_finalized_within_activity_window_reported(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        votes_below_finalized_within_activity_window_reported(ed25519::fixture);
        votes_below_finalized_within_activity_window_reported(secp256r1::fixture);
    }

    fn constructed_votes_are_not_future_bounded<S, F>(mut fixture: F)
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
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone()).await;

            // Setup reporter mock
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
            let (batcher, mut batcher_mailbox) = Actor::new(context.child("actor"), batcher_cfg);

            // Create voter mailbox for batcher to send to
            let (voter_sender, mut voter_receiver) = mailbox::new::<voter::Message<S, Sha256Digest>>(
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

            // Register the participants that will send votes later.
            let quorum_size = quorum(n) as usize;
            let mut participant_senders = Vec::new();
            for pk in participants.iter().skip(1).take(quorum_size - 1) {
                participant_senders.push(
                    register_and_link_peer(
                        &oracle,
                        pk.clone(),
                        me.clone(),
                        0,
                        Duration::from_millis(1),
                    )
                    .await,
                );
            }

            // Start the batcher at view 1
            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);
            batcher_mailbox.update(
                Span::none(),
                View::new(1),
                Participant::new(1),
                View::zero(),
                None,
            );

            // A locally constructed vote can be ahead of the batcher's view:
            // the voter constructs votes before sending the update that
            // advances it (e.g. after a certificate jump). It must be added
            // to the verifier, not future-bounded like network input.
            let future_view = View::new(6);
            let proposal = Proposal::new(
                Round::new(epoch, future_view),
                View::new(1),
                Sha256::hash(&[b"ahead"]),
            );
            let notarize = Notarize::sign(&schemes[0], proposal.clone()).unwrap();
            batcher_mailbox.constructed(Vote::Notarize(notarize));
            context.sleep(Duration::from_millis(50)).await;

            let metrics = context.encode();
            assert!(
                metrics.contains("added_total 1"),
                "constructed vote ahead of the batcher's view must be added: {metrics}"
            );

            // Advancing into the stored vote's view reactivates it: with
            // quorum-1 network votes on top, the batcher constructs the
            // notarization and forwards it to the voter.
            batcher_mailbox.update(
                Span::none(),
                future_view,
                Participant::new(0),
                View::zero(),
                None,
            );
            for (scheme, sender) in schemes[1..quorum_size].iter().zip(&mut participant_senders) {
                let vote = Notarize::sign(scheme, proposal.clone()).unwrap();
                sender.send(
                    Recipients::One(me.clone()),
                    Vote::Notarize(vote).encode(),
                    true,
                );
            }
            loop {
                select! {
                    message = voter_receiver.recv() => {
                        let message = message.expect("voter mailbox closed");
                        if matches!(
                            &message,
                            voter::Message::Verified { certificate: Certificate::Notarization(n), .. }
                                if n.view() == future_view
                        ) {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("stored constructed vote was never processed");
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_constructed_votes_are_not_future_bounded() {
        // Retention and reactivation are scheme-independent; one batchable
        // and one non-batchable scheme cover both certificate flows.
        constructed_votes_are_not_future_bounded(ed25519::fixture);
        constructed_votes_are_not_future_bounded(secp256r1::fixture);
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
            let reporter = test_reporter(&mut context, &schemes[0]);

            // Initialize batcher actor (participant 0)
            let me = participants[0].clone();
            let batcher_context = context.child("batcher");
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
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
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

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
            let proposal3 = Proposal::new(round3, View::zero(), Sha256::hash(&[b"payload3"]));
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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let round = Round::new(epoch, view);
            let proposal = Proposal::new(round, View::zero(), Sha256::hash(&[b"test_payload"]));

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

            let reporter = test_reporter(&mut context, &schemes[0]);

            let me = participants[0].clone();
            let batcher_cfg = test_config(
                schemes[0].clone(),
                oracle.control(me.clone()),
                reporter.clone(),
                MockRelay::new(),
                epoch,
                BatcherOptions::default(),
            );
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
                success_rate: probability!(1.0),
            };
            oracle
                .add_link(sender_pk.clone(), me.clone(), link)
                .await
                .unwrap();

            batcher.start(voter_mailbox, vote_receiver, certificate_receiver);

            let view = View::new(1);
            batcher_mailbox.update(Span::none(), view, Participant::new(1), View::zero(), None);

            let round = Round::new(epoch, view);
            let proposal1 = Proposal::new(round, View::zero(), Sha256::hash(&[b"payload1"]));
            let proposal2 = Proposal::new(round, View::zero(), Sha256::hash(&[b"payload2"]));

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
