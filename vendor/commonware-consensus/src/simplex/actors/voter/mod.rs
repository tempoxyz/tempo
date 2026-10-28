mod actor;
mod ingress;
mod round;
mod slot;
mod state;

use crate::{
    CertifiableAutomaton, Relay, Reporter,
    simplex::{Floor, Plan, elector::Elector, types::Activity},
    types::{Epoch, ViewDelta},
};
pub use actor::Actor;
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::paged::CacheRef;
use core::num::NonZeroUsize;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::Message;
use std::time::Duration;

pub struct Config<
    S: Scheme,
    L: Elector<S>,
    B: Blocker,
    D: Digest,
    A: CertifiableAutomaton,
    R: Relay<Digest = D, PublicKey = S::PublicKey, Plan = Plan<S::PublicKey>>,
    F: Reporter<Activity = Activity<S, D>>,
> {
    pub scheme: S,
    pub elector: L,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,

    pub partition: String,
    pub epoch: Epoch,
    pub floor: Floor<S, D>,
    pub mailbox_size: NonZeroUsize,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub skip_budget: u64,
    pub view_retention: ViewDelta,
    pub replay_buffer: NonZeroUsize,
    pub write_buffer: NonZeroUsize,
    pub page_cache: CacheRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Viewable,
        simplex::{
            actors::{
                batcher,
                resolver::{self, MailboxMessage},
            },
            elector::{self, Config as _, Random, RandomVersion, RoundRobin, RoundRobinElector},
            metrics::TimeoutReason,
            mocks, quorum,
            scheme::{
                Scheme, bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf,
                ed25519, secp256r1,
            },
            types::{
                Artifact, Certificate, Finalization, Finalize, Notarization, Notarize,
                Nullification, Nullify, Proposal, Vote,
            },
        },
        types::{Participant, Round, TermLength, View},
    };
    use commonware_actor::mailbox;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        Hasher as _, Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{Scheme as _, Verifier as _, mocks::Fixture},
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_collect_traces, test_traced};
    use commonware_p2p::{
        Receiver as _, Recipients,
        simulated::{Config as NConfig, Link, Network, Oracle},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock, Metrics, Quota, Runner, Spawner, Storage, Supervisor as _,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
        reschedule,
        telemetry::traces::collector::{RecordedEvents, TraceStorage},
    };
    use commonware_storage::journal::segmented::variable::{Config as JConfig, Journal};
    use commonware_utils::{NZU16, NZU32, NZUsize, non_empty, probability, sync::Mutex};
    use futures::FutureExt;
    use rand_core::CryptoRng;
    use std::{
        num::{NonZeroU16, NonZeroU32},
        sync::Arc,
        time::Duration,
    };
    use tracing::Level;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    async fn start_test_network_with_peers<I>(
        context: deterministic::Context,
        peers: I,
        disconnect_on_block: bool,
    ) -> Oracle<PublicKey, deterministic::Context>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let peers: Vec<_> = peers.into_iter().collect();
        let (network, oracle) = Network::new_with_peers(
            context.child("network"),
            NConfig {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(peers.len()),
                disconnect_on_block,
                tracked_peer_sets: NZUsize!(1),
            },
            peers,
        )
        .await;
        network.start();
        oracle
    }

    fn build_notarization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Notarize<S, Sha256Digest>>,
        Notarization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential)
                .expect("notarization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_finalization<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        proposal: &Proposal<Sha256Digest>,
        count: u32,
    ) -> (
        Vec<Finalize<S, Sha256Digest>>,
        Finalization<S, Sha256Digest>,
    ) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Finalization::from_finalizes(&schemes[0], non_empty![@&votes], &Sequential)
                .expect("finalization requires a quorum of votes");
        (votes, certificate)
    }

    fn build_nullification<S: Scheme<Sha256Digest>>(
        schemes: &[S],
        round: Round,
        count: u32,
    ) -> (Vec<Nullify<S>>, Nullification<S>) {
        let votes: Vec<_> = schemes
            .iter()
            .take(count as usize)
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        let certificate =
            Nullification::from_nullifies(&schemes[0], non_empty![@&votes], &Sequential)
                .expect("nullification requires a quorum of votes");
        (votes, certificate)
    }

    /// Voter knobs for [`setup_voter`], named so call sites cannot transpose
    /// the timeouts. Tests override only the fields they exercise.
    struct VoterOptions {
        leader_timeout: Duration,
        certification_timeout: Duration,
        timeout_retry: Duration,
        /// Index of the participant hosting the voter under test.
        local_index: usize,
        /// Mock application propose latency, in milliseconds.
        propose_latency_ms: f64,
        /// Views whose proposal requests reached the mock application.
        propose_requests: Option<Arc<Mutex<Vec<View>>>>,
        /// Whether proposal responses should remain pending indefinitely.
        stall_proposals: bool,
        /// Mock application verify latency, in milliseconds.
        verify_latency_ms: f64,
        /// Mock application certify latency, in milliseconds.
        certify_latency_ms: f64,
        /// Views whose verification requests reached the mock application.
        verify_requests: Option<Arc<Mutex<Vec<View>>>>,
        /// Whether every mock application verification should fail.
        fail_verification: bool,
        certifier: mocks::application::Certifier<Sha256Digest>,
    }

    impl Default for VoterOptions {
        /// A short leader timeout with certification and retry timeouts far
        /// beyond test duration, so only leader timeouts fire.
        fn default() -> Self {
            Self {
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                local_index: 0,
                propose_latency_ms: 1.0,
                propose_requests: None,
                stall_proposals: false,
                verify_latency_ms: 1.0,
                certify_latency_ms: 1.0,
                verify_requests: None,
                fail_verification: false,
                certifier: mocks::application::Certifier::Always,
            }
        }
    }

    /// Helper to set up a voter actor for tests.
    async fn setup_voter<E, S, L>(
        context: &E,
        oracle: &commonware_p2p::simulated::Oracle<S::PublicKey, deterministic::Context>,
        participants: &[S::PublicKey],
        schemes: &[S],
        elector: L,
        options: VoterOptions,
    ) -> (
        Mailbox<S, Sha256Digest>,
        mailbox::Receiver<batcher::Message<S, Sha256Digest>>,
        mailbox::Receiver<resolver::MailboxMessage<S, Sha256Digest>>,
        Arc<mocks::relay::Relay<Sha256Digest, S::PublicKey>>,
        mocks::reporter::Reporter<E, S, L, Sha256Digest>,
    )
    where
        E: BufferPooler + Clock + CryptoRng + Spawner + Storage + Metrics,
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        L: elector::Config<S>,
    {
        let signing = schemes[options.local_index].clone();
        let me = participants[options.local_index].clone();
        let reporter_cfg = mocks::reporter::Config {
            participants: participants.to_vec().try_into().unwrap(),
            scheme: signing.clone(),
            elector: elector.clone(),
        };
        let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
        let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
        let elector = elector.build(signing.participants());
        let propose_requests = options.propose_requests;
        let verify_requests = options.verify_requests;

        let application_cfg = mocks::application::Config::<Sha256, _> {
            relay: relay.clone(),
            me: me.clone(),
            propose_latency: (options.propose_latency_ms, 0.0),
            verify_latency: (options.verify_latency_ms, 0.0),
            certify_latency: (options.certify_latency_ms, 0.0),
            should_certify: options.certifier,
        };
        let (mut actor, application) =
            mocks::application::Application::new(context.child("app"), application_cfg);
        actor.set_stall_proposals(options.stall_proposals);
        actor.set_fail_verification(options.fail_verification);
        if let Some(propose_requests) = propose_requests {
            actor.set_propose_observer(Box::new(move |context| {
                propose_requests.lock().push(context.view());
            }));
        }
        if let Some(verify_requests) = verify_requests {
            actor.set_verify_observer(Box::new(move |context, _| {
                verify_requests.lock().push(context.view());
            }));
        }
        actor.start();

        let voter_cfg = Config {
            scheme: signing.clone(),
            elector,
            blocker: oracle.control(me.clone()),
            automaton: application.clone(),
            relay: application.clone(),
            reporter: reporter.clone(),
            partition: format!("voter_test_{me}"),
            epoch: Epoch::new(333),
            floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
            mailbox_size: NZUsize!(128),
            leader_timeout: options.leader_timeout,
            certification_timeout: options.certification_timeout,
            timeout_retry: options.timeout_retry,
            skip_budget: u64::MAX,
            view_retention: ViewDelta::new(10),
            replay_buffer: NZUsize!(10240),
            write_buffer: NZUsize!(10240),
            page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        let (voter, mailbox) = Actor::new(context.child("actor"), voter_cfg);

        let (resolver_sender, resolver_receiver) =
            mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
        let (batcher_sender, batcher_receiver) =
            mailbox::new(context.child("batcher_mailbox"), NZUsize!(16));

        let (vote_sender, _) = oracle
            .control(me.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (certificate_sender, _) = oracle
            .control(me.clone())
            .register(1, TEST_QUOTA)
            .await
            .unwrap();

        voter.start(
            batcher::Mailbox::new(batcher_sender),
            resolver::Mailbox::new(resolver_sender),
            vote_sender,
            certificate_sender,
        );

        (
            mailbox,
            batcher_receiver,
            resolver_receiver,
            relay,
            reporter,
        )
    }

    async fn wait_for_request(
        context: &deterministic::Context,
        requests: &Arc<Mutex<Vec<View>>>,
        view: View,
    ) {
        let deadline = context.current() + Duration::from_secs(1);
        while !requests.lock().contains(&view) {
            if context.current() >= deadline {
                panic!("application did not receive request for {view}");
            }
            context.sleep(Duration::from_millis(1)).await;
        }
    }

    fn trace_position(
        events: &RecordedEvents,
        content: &str,
        span_name: &str,
        view: View,
    ) -> usize {
        let view = view.to_string();
        events
            .iter()
            .position(|event| {
                event.metadata.content == content
                    && event
                        .expect_span_at_index(0, |span| {
                            span.expect_content_exact(span_name)?;
                            span.expect_field_exact("view", &view)
                        })
                        .is_ok()
            })
            .unwrap_or_else(|| panic!("missing {content} trace for view {view}"))
    }

    async fn seed_voter_journal<S>(
        context: deterministic::Context,
        partition: String,
        page_cache: CacheRef,
        scheme: &S,
        finalization: Finalization<S, Sha256Digest>,
    ) where
        S: Scheme<Sha256Digest>,
    {
        seed_voter_journal_artifacts(
            context,
            partition,
            page_cache,
            scheme,
            finalization.view(),
            vec![Artifact::Finalization(finalization)],
        )
        .await;
    }

    async fn seed_voter_journal_artifacts<S>(
        context: deterministic::Context,
        partition: String,
        page_cache: CacheRef,
        scheme: &S,
        view: View,
        artifacts: Vec<Artifact<S, Sha256Digest>>,
    ) where
        S: Scheme<Sha256Digest>,
    {
        let mut journal = Journal::<_, Artifact<S, Sha256Digest>>::init(
            context.child("journal"),
            JConfig {
                partition,
                compression: None,
                codec_config: scheme.certificate_codec_config(),
                page_cache,
                write_buffer: NZUsize!(1024 * 1024),
            },
        )
        .await
        .expect("unable to initialize voter journal");
        for artifact in artifacts {
            assert_eq!(artifact.view(), view);
            (journal, _, _) = journal
                .append(view.get(), &artifact)
                .await
                .expect("unable to append voter journal artifact");
        }
        journal
            .sync(view.get())
            .await
            .expect("unable to sync voter journal");
    }

    struct VoterFloorStart<S>
    where
        S: Scheme<Sha256Digest>,
    {
        partition: String,
        epoch: Epoch,
        floor: Floor<S, Sha256Digest>,
        skip_budget: u64,
        page_cache: CacheRef,
    }

    #[allow(clippy::type_complexity)]
    async fn start_voter_with_floor<S, L>(
        context: &mut deterministic::Context,
        oracle: &Oracle<S::PublicKey, deterministic::Context>,
        participants: &[S::PublicKey],
        schemes: &[S],
        elector: L,
        start: VoterFloorStart<S>,
    ) -> (
        Mailbox<S, Sha256Digest>,
        mailbox::Receiver<batcher::Message<S, Sha256Digest>>,
        mailbox::Receiver<resolver::MailboxMessage<S, Sha256Digest>>,
        Arc<mocks::relay::Relay<Sha256Digest, S::PublicKey>>,
        mocks::reporter::Reporter<deterministic::Context, S, L, Sha256Digest>,
        commonware_runtime::Handle<()>,
    )
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        L: elector::Config<S>,
    {
        let VoterFloorStart {
            partition,
            epoch,
            floor,
            skip_budget,
            page_cache,
        } = start;
        let me = participants[0].clone();
        let reporter_cfg = mocks::reporter::Config {
            participants: participants.to_vec().try_into().unwrap(),
            scheme: schemes[0].clone(),
            elector: elector.clone(),
        };
        let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
        let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
        let elector = elector.build(schemes[0].participants());
        let application_cfg = mocks::application::Config::<Sha256, _> {
            relay: relay.clone(),
            me: me.clone(),
            propose_latency: (1.0, 0.0),
            verify_latency: (1.0, 0.0),
            certify_latency: (1.0, 0.0),
            should_certify: mocks::application::Certifier::Always,
        };
        let (app_actor, application) =
            mocks::application::Application::new(context.child("app"), application_cfg);
        app_actor.start();

        let voter_cfg = Config {
            scheme: schemes[0].clone(),
            elector,
            blocker: oracle.control(me.clone()),
            automaton: application.clone(),
            relay: application,
            reporter: reporter.clone(),
            partition,
            epoch,
            floor,
            mailbox_size: NZUsize!(128),
            leader_timeout: Duration::from_secs(5),
            certification_timeout: Duration::from_secs(6),
            timeout_retry: Duration::from_mins(60),
            skip_budget,
            view_retention: ViewDelta::new(10),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024 * 1024),
            page_cache,
        };
        let (voter, mailbox) = Actor::new(context.child("voter"), voter_cfg);
        let (resolver_sender, resolver_receiver) =
            mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
        let (batcher_sender, batcher_receiver) =
            mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
        let (vote_sender, _) = oracle
            .control(me.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (certificate_sender, _) = oracle.control(me).register(1, TEST_QUOTA).await.unwrap();
        let handle = voter.start(
            batcher::Mailbox::new(batcher_sender),
            resolver::Mailbox::new(resolver_sender),
            vote_sender,
            certificate_sender,
        );

        (
            mailbox,
            batcher_receiver,
            resolver_receiver,
            relay,
            reporter,
            handle,
        )
    }

    async fn expect_restarted_voter_at_floor<S>(
        context: &mut deterministic::Context,
        batcher_receiver: &mut mailbox::Receiver<batcher::Message<S, Sha256Digest>>,
        resolver_receiver: &mut mailbox::Receiver<resolver::MailboxMessage<S, Sha256Digest>>,
        finalized: View,
    ) where
        S: Scheme<Sha256Digest>,
    {
        let mut saw_update = false;
        let mut saw_finalization = false;
        loop {
            select! {
                msg = batcher_receiver.recv() => {
                    if let batcher::Message::Update {
                        current,
                        finalized: found,
                        ..
                    } = msg.expect("batcher mailbox closed")
                    {
                        assert_eq!(current, finalized.next());
                        assert_eq!(found, finalized);
                        saw_update = true;
                    }
                },
                msg = resolver_receiver.recv() => {
                    if let resolver::MailboxMessage::Certificate {
                        certificate: Certificate::Finalization(finalization),
                        ..
                    } = msg.expect("resolver mailbox closed")
                    {
                        let view = finalization.view();
                        assert!(
                            view <= finalized,
                            "restarted voter reported finalization above expected floor: {view}"
                        );
                        saw_finalization |= view == finalized;
                    }
                },
                _ = context.sleep(Duration::from_secs(5)) => {
                    panic!("timed out waiting for restarted voter at finalized view {finalized}");
                },
            }
            if saw_update && saw_finalization {
                break;
            }
        }
    }

    #[test_traced("WARN")]
    fn test_voter_restart_newer_floor_skips_stale_journal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(20));
        runner.start(|mut context| async move {
            let n = 5;
            let quorum = quorum(n);
            let epoch = Epoch::new(333);
            let namespace = b"voter_restart_newer_floor".to_vec();
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let partition = "voter_restart_newer_floor".to_string();
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

            // Persist a stale finalization that should be ignored once the
            // configured floor is applied before replay.
            let old_view = View::new(3);
            let old_proposal = Proposal::new(
                Round::new(epoch, old_view),
                old_view.previous().unwrap(),
                Sha256::hash(&[b"old-journal-finalization"]),
            );
            let (_, old_finalization) = build_finalization(&schemes, &old_proposal, quorum);
            seed_voter_journal(
                context.child("seed_journal"),
                partition.clone(),
                page_cache.clone(),
                &schemes[0],
                old_finalization,
            )
            .await;

            // Start from a newer finalized floor over the same journal partition.
            let floor_view = View::new(8);
            let floor_proposal = Proposal::new(
                Round::new(epoch, floor_view),
                floor_view.previous().unwrap(),
                Sha256::hash(&[b"newer-floor-finalization"]),
            );
            let (_, floor_finalization) = build_finalization(&schemes, &floor_proposal, quorum);
            let (_mailbox, mut batcher_receiver, mut resolver_receiver, _relay, reporter, _handle) =
                start_voter_with_floor(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    RoundRobin::<Sha256>::default(),
                    VoterFloorStart {
                        partition,
                        epoch,
                        floor: Floor::Finalized(floor_finalization),
                        skip_budget: u64::MAX,
                        page_cache,
                    },
                )
                .await;

            // The voter should seed its in-memory state from the configured floor
            // and should not surface the older journal finalization.
            expect_restarted_voter_at_floor(
                &mut context,
                &mut batcher_receiver,
                &mut resolver_receiver,
                floor_view,
            )
            .await;

            let finalizations = reporter.finalizations.lock();
            assert!(finalizations.contains_key(&floor_view));
            assert!(
                !finalizations.contains_key(&old_view),
                "stale journal finalization must be skipped when the configured floor is newer"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_voter_restart_older_floor_ignored_for_newer_journal() {
        let runner = deterministic::Runner::timed(Duration::from_secs(20));
        runner.start(|mut context| async move {
            let n = 5;
            let quorum = quorum(n);
            let epoch = Epoch::new(333);
            let namespace = b"voter_restart_older_floor".to_vec();
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let partition = "voter_restart_older_floor".to_string();
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

            // Persist a newer finalization so replay can advance past the
            // configured floor.
            let journal_view = View::new(8);
            let journal_proposal = Proposal::new(
                Round::new(epoch, journal_view),
                journal_view.previous().unwrap(),
                Sha256::hash(&[b"newer-journal-finalization"]),
            );
            let (_, journal_finalization) = build_finalization(&schemes, &journal_proposal, quorum);
            seed_voter_journal(
                context.child("seed_journal"),
                partition.clone(),
                page_cache.clone(),
                &schemes[0],
                journal_finalization,
            )
            .await;

            // Provide an older floor; journal replay should supersede it.
            let floor_view = View::new(3);
            let floor_proposal = Proposal::new(
                Round::new(epoch, floor_view),
                floor_view.previous().unwrap(),
                Sha256::hash(&[b"older-floor-finalization"]),
            );
            let (_, floor_finalization) = build_finalization(&schemes, &floor_proposal, quorum);
            let (_mailbox, mut batcher_receiver, mut resolver_receiver, _relay, reporter, _handle) =
                start_voter_with_floor(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    RoundRobin::<Sha256>::default(),
                    VoterFloorStart {
                        partition,
                        epoch,
                        floor: Floor::Finalized(floor_finalization),
                        skip_budget: u64::MAX,
                        page_cache,
                    },
                )
                .await;

            // The configured floor may be reported before replay, but the
            // replayed finalization should become the active floor.
            expect_restarted_voter_at_floor(
                &mut context,
                &mut batcher_receiver,
                &mut resolver_receiver,
                journal_view,
            )
            .await;

            let finalizations = reporter.finalizations.lock();
            assert!(finalizations.contains_key(&journal_view));
            assert!(
                finalizations.contains_key(&floor_view),
                "configured floor should be reported before journal replay supersedes it"
            );
        });
    }

    #[test_traced("WARN")]
    fn test_voter_replay_floor_does_not_move_during_replay() {
        let runner = deterministic::Runner::timed(Duration::from_secs(20));
        runner.start(|mut context| async move {
            let n = 5;
            let quorum = quorum(n);
            let epoch = Epoch::new(333);
            let namespace = b"voter_replay_floor_static".to_vec();
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let partition = "voter_replay_floor_static".to_string();
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

            let floor_view = View::new(3);
            let floor_proposal = Proposal::new(
                Round::new(epoch, floor_view),
                floor_view.previous().unwrap(),
                Sha256::hash(&[b"static-replay-floor"]),
            );
            let (_, floor_finalization) = build_finalization(&schemes, &floor_proposal, quorum);

            // Place two above-floor artifacts in the same journal section. The
            // first one advances `last_finalized`, but the second must still
            // replay because it is above the configured floor.
            let journal_view = View::new(8);
            let journal_proposal = Proposal::new(
                Round::new(epoch, journal_view),
                journal_view.previous().unwrap(),
                Sha256::hash(&[b"same-section-finalize"]),
            );
            let (mut finalizes, journal_finalization) =
                build_finalization(&schemes, &journal_proposal, quorum);
            let finalize = finalizes.remove(0);
            let finalized_payload = finalize.proposal.payload;
            seed_voter_journal_artifacts(
                context.child("seed_journal"),
                partition.clone(),
                page_cache.clone(),
                &schemes[0],
                journal_view,
                vec![
                    Artifact::Finalization(journal_finalization),
                    Artifact::Finalize(finalize),
                ],
            )
            .await;

            let (_mailbox, mut batcher_receiver, mut resolver_receiver, _relay, reporter, _handle) =
                start_voter_with_floor(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    RoundRobin::<Sha256>::default(),
                    VoterFloorStart {
                        partition,
                        epoch,
                        floor: Floor::Finalized(floor_finalization),
                        skip_budget: u64::MAX,
                        page_cache,
                    },
                )
                .await;

            expect_restarted_voter_at_floor(
                &mut context,
                &mut batcher_receiver,
                &mut resolver_receiver,
                journal_view,
            )
            .await;

            let finalizes = reporter.finalizes.lock();
            let signers = finalizes
                .get(&journal_view)
                .and_then(|payloads| payloads.get(&finalized_payload))
                .expect("above-floor finalize vote should replay");
            assert!(signers.contains(&participants[0]));
        });
    }

    /// Helper to advance to a specific view by sending a finalization for the previous view.
    async fn advance_to_view<S: Scheme<Sha256Digest>>(
        mailbox: &mut Mailbox<S, Sha256Digest>,
        batcher_receiver: &mut mailbox::Receiver<batcher::Message<S, Sha256Digest>>,
        schemes: &[S],
        quorum: u32,
        target: View,
    ) -> Sha256Digest {
        let prev_view = target.previous().expect("target view must be > 0");
        let payload = Sha256::hash(&[&prev_view.get().to_be_bytes()]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(333), prev_view),
            prev_view.previous().unwrap_or(View::zero()),
            payload,
        );
        let (_, finalization) = build_finalization(schemes, &proposal, quorum);
        mailbox.resolved(Certificate::Finalization(finalization));

        // Wait for target view update
        loop {
            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { current, .. } => {
                    if current < target {
                        continue;
                    }
                    assert_eq!(current, target);
                    break;
                }
                batcher::Message::Constructed(_) => {}
            }
        }

        payload
    }

    /// Trigger processing of an uninteresting view from the resolver after
    /// jumping ahead to a new finalize view:
    ///
    /// 1. Send a finalization for view 100.
    /// 2. Send a notarization from resolver for view 50 (should be ignored).
    /// 3. Send a finalization for view 300 (should be processed).
    fn stale_backfill<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                false,
            )
            .await;

            // Initialize voter actor
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let elector = elector.build(schemes[0].participants());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(10),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                write_buffer: NonZeroUsize::new(1024 * 1024).unwrap(),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, mut mailbox) = Actor::new(context.child("actor"), cfg);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(10));
            let resolver = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(1024));
            let batcher = batcher::Mailbox::new(batcher_sender);

            // Create network senders for broadcasting votes and certificates
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Run the actor
            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send finalization via voter mailbox (view 100)
            let payload = Sha256::hash(&[b"test"]);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(100)),
                View::new(50),
                payload,
            );
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        ..
                    } => {
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization.view(), View::new(100));
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send old notarization from resolver that should be ignored (view 50)
            let payload = Sha256::hash(&[b"test2"]);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(50)),
                View::new(49),
                payload,
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Send new finalization via voter mailbox (view 300)
            let payload = Sha256::hash(&[b"test3"]);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), View::new(300)),
                View::new(100),
                payload,
            );
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        ..
                    } => {
                        assert_eq!(current, View::new(301));
                        assert_eq!(finalized, View::new(300));
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization.view(), View::new(300));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_stale_backfill() {
        stale_backfill::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        stale_backfill::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        stale_backfill::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        stale_backfill::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        stale_backfill::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        stale_backfill::<_, _, RoundRobin>(secp256r1::fixture, RoundRobin::default());
    }

    /// Process an interesting view below the oldest tracked view:
    ///
    /// 1. Advance last_finalized to a view 50.
    /// 2. Ensure self.views contains a view V_A (45) which is interesting,
    ///    and becomes the 'oldest' view when prune_views runs, setting the journal floor.
    ///    Crucially, ensure there's a "gap" so that V_A is not LF - view_retention.
    /// 3. Let prune_views run, setting the journal floor to V_A.
    /// 4. Inject a message for V_B such that V_B < V_A but V_B is still "interesting"
    ///    relative to the current last_finalized.
    fn append_old_interesting_view<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"test_prune_panic".to_vec();
        let view_retention = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup the target Voter actor (validator 0)
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let elector = elector.build(signing.participants());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let app_config = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("app"), app_config);
            actor.start();
            let voter_config = Config {
                scheme: signing.clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_actor_test_{me}"),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_millis(1000),
                timeout_retry: Duration::from_millis(1000),
                skip_budget: u64::MAX,
                view_retention,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, mut mailbox) = Actor::new(context.child("actor"), voter_config);

            // Create a dummy resolver mailbox
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(10));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);

            // Create a dummy batcher mailbox
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(10));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Create network senders for broadcasting votes and certificates
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            actor.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Establish Prune Floor (50 - 10 + 5 = 45)
            //
            // Theoretical retention floor is 50-10 = 40.
            // We want journal pruned at 45.
            let lf_target = View::new(50);
            let journal_floor_target = lf_target
                .saturating_sub(view_retention)
                .saturating_add(ViewDelta::new(5));

            // Send Finalization via voter mailbox to advance last_finalized
            let proposal_lf = Proposal::new(
                Round::new(Epoch::new(333), lf_target),
                lf_target.previous().unwrap(),
                Sha256::hash(&[b"test"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal_lf, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        ..
                    } => {
                        assert_eq!(current, View::new(51));
                        assert_eq!(finalized, View::new(50));
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization.view(), View::new(50));
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send a Notarization for `journal_floor_target` to ensure it's in `actor.views`
            let proposal_jft = Proposal::new(
                Round::new(Epoch::new(333), journal_floor_target),
                journal_floor_target.previous().unwrap(),
                Sha256::hash(&[b"test2"]),
            );
            let (_, notarization_for_floor) = build_notarization(&schemes, &proposal_jft, quorum);
            mailbox.recovered(Certificate::Notarization(notarization_for_floor));

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(notarization),
                    ..
                } => {
                    assert_eq!(notarization.view(), journal_floor_target);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send notarization below oldest tracked view (42)
            //
            // problematic_view (42) < journal_floor_target (45)
            // Viewport::retains(42): 42 >= floor (LF(50) - AT(10) = 40)
            let problematic_view = journal_floor_target.saturating_sub(ViewDelta::new(3));
            let proposal_bft = Proposal::new(
                Round::new(Epoch::new(333), problematic_view),
                problematic_view.previous().unwrap(),
                Sha256::hash(&[b"test3"]),
            );
            let (_, notarization_for_bft) = build_notarization(&schemes, &proposal_bft, quorum);
            mailbox.recovered(Certificate::Notarization(notarization_for_bft));

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(notarization),
                    ..
                } => {
                    assert_eq!(notarization.view(), problematic_view);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Send Finalization via voter mailbox to new view (100)
            let proposal_lf = Proposal::new(
                Round::new(Epoch::new(333), View::new(100)),
                View::new(99),
                Sha256::hash(&[b"test4"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal_lf, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        ..
                    } => {
                        assert_eq!(current, View::new(101));
                        assert_eq!(finalized, View::new(100));
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait for resolver to be notified
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization.view(), View::new(100));
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_append_old_interesting_view() {
        append_old_interesting_view::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        append_old_interesting_view::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        append_old_interesting_view::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        append_old_interesting_view::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        append_old_interesting_view::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        append_old_interesting_view::<_, _, RoundRobin>(secp256r1::fixture, RoundRobin::default());
    }

    /// Test that voter can process finalization from batcher without notarization.
    fn finalization_without_notarization_certificate<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_without_notarization".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    VoterOptions::default(),
                )
                .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build a finalization certificate (without notarization)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"finalize_without_notarization"]),
            );
            let (_, expected_finalization) = build_finalization(&schemes, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox.recovered(Certificate::Finalization(expected_finalization.clone()));

            // Wait for the actor to report the finalization
            let mut finalized_view = None;
            while let Some(message) = resolver_receiver.recv().await {
                match message {
                    MailboxMessage::Certificate {
                        certificate: Certificate::Finalization(finalization),
                        ..
                    } => {
                        finalized_view = Some(finalization.view());
                        break;
                    }
                    _ => continue,
                }
            }
            assert_eq!(finalized_view, Some(view));

            // Wait for a finalization to be recorded
            loop {
                {
                    let finalizations = reporter.finalizations.lock();
                    // Finalization must match the signatures recovered from finalize votes
                    if matches!(
                        finalizations.get(&view),
                        Some(finalization) if finalization == &expected_finalization
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Verify no notarization certificate was recorded
            let notarizations = reporter.notarizations.lock();
            assert!(notarizations.is_empty());
        });
    }

    #[test_traced]
    fn test_finalization_without_notarization_certificate() {
        finalization_without_notarization_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        finalization_without_notarization_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        finalization_without_notarization_certificate::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    fn certificate_conflicts_proposal<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    VoterOptions::default(),
                )
                .await;

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send proposal A from batcher (simulating leader's proposal being forwarded)
            let view = View::new(2);
            let proposal_a = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal_a"]),
            );
            mailbox.proposal(proposal_a.clone());

            // Give it time to process the proposal
            context.sleep(Duration::from_millis(10)).await;

            // Send notarization certificate for a DIFFERENT proposal B
            let proposal_b = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal_b"]),
            );
            let (_, notarization_b) = build_notarization(&schemes, &proposal_b, quorum);

            mailbox.recovered(Certificate::Notarization(notarization_b.clone()));

            // Verify the certificate was accepted
            let msg = resolver_receiver
                .recv()
                .await
                .expect("failed to receive resolver message");
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(notarization),
                    ..
                } => {
                    assert_eq!(notarization.proposal, proposal_b);
                    assert_eq!(notarization, notarization_b);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization B to be recorded (not A)
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
                    if matches!(
                        notarizations.get(&view),
                        Some(notarization) if notarization == &notarization_b
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Ensure no finalize vote is broadcast (don't vote on conflict)
            context.sleep(Duration::from_millis(100)).await;
            loop {
                let Some(Some(message)) = batcher_receiver.recv().now_or_never() else {
                    break;
                };
                match message {
                    batcher::Message::Constructed(Vote::Finalize(_)) => {
                        panic!("finalize vote should not be broadcast");
                    }
                    batcher::Message::Update { .. } => {}
                    _ => continue,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_conflicts_proposal() {
        certificate_conflicts_proposal::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        certificate_conflicts_proposal::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        certificate_conflicts_proposal::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        certificate_conflicts_proposal::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        certificate_conflicts_proposal::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        certificate_conflicts_proposal::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    fn proposal_conflicts_certificate<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"proposal_conflicts_certificate_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    VoterOptions::default(),
                )
                .await;

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { .. } => {}
                _ => panic!("unexpected batcher message"),
            }

            let view = View::new(2);
            let proposal_a = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal_a"]),
            );
            let proposal_b = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal_b"]),
            );

            // Send certificate for proposal A FIRST
            let (_, notarization_a) = build_notarization(&schemes, &proposal_a, quorum);
            mailbox.recovered(Certificate::Notarization(notarization_a.clone()));

            // Verify the certificate was accepted
            let msg = resolver_receiver.recv().await.unwrap();
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(notarization),
                    ..
                } => {
                    assert_eq!(notarization.proposal, proposal_a);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization A to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
                    if matches!(
                        notarizations.get(&view),
                        Some(notarization) if notarization == &notarization_a
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Ensure finalize vote is sent
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(
                            finalize.proposal, proposal_a,
                            "finalize should be for certificate's proposal A"
                        );
                        break;
                    }
                    batcher::Message::Update { .. } => {}
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }

            // Now send proposal B from batcher
            mailbox.proposal(proposal_b.clone());

            // Wait for proposal B to be recorded (no issue)
            context.sleep(Duration::from_millis(100)).await;
        });
    }

    #[test_traced]
    fn test_proposal_conflicts_certificate() {
        proposal_conflicts_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        proposal_conflicts_certificate::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        proposal_conflicts_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        proposal_conflicts_certificate::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        proposal_conflicts_certificate::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        proposal_conflicts_certificate::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    fn certificate_verifies_proposal<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certificate_conflicts_proposal_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (100_000.0, 0.0), // Very slow verification
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);
            actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_certificate_verifies_proposal_test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let me = participants[0].clone();
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { .. } => {}
                _ => panic!("unexpected batcher message"),
            }

            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"same_proposal"]),
            );

            // Send proposal from batcher first
            mailbox.proposal(proposal.clone());

            // Give it time to start verification (but it won't complete due to slow latency)
            context.sleep(Duration::from_millis(10)).await;

            // Send certificate for the SAME proposal
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Notarization(notarization.clone()));

            // The certificate should verify the proposal immediately
            let msg = resolver_receiver.recv().await.unwrap();
            match msg {
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(n),
                    ..
                } => {
                    assert_eq!(n.proposal, proposal);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Wait for notarization to be recorded
            loop {
                {
                    let notarizations = reporter.notarizations.lock();
                    if matches!(
                        notarizations.get(&view),
                        Some(n) if n == &notarization
                    ) {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(10)).await;
            }

            // Should be able to finalize since the proposal was verified by the certificate
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(finalize)) => {
                        assert_eq!(finalize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Update { .. } => {}
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test_traced]
    fn test_certificate_verifies_proposal() {
        certificate_verifies_proposal::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        certificate_verifies_proposal::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        certificate_verifies_proposal::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        certificate_verifies_proposal::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        certificate_verifies_proposal::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        certificate_verifies_proposal::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Test that our proposal is dropped when it conflicts with a peer's notarize vote.
    ///
    /// This is a regression test for a byzantine scenario where multiple nodes share the
    /// same signing key:
    /// 1. A peer with our identity sends a notarize vote for proposal A
    /// 2. Our automaton completes with a different proposal B
    /// 3. Our proposal should be dropped when the conflict is detected
    fn drop_our_proposal_on_conflict<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"drop_our_proposal_on_conflict_test".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Figure out who the leader will be for view 2
            let view2_round = Round::new(epoch, View::new(2));
            let elector_config = RoundRobin::<Sha256>::default();
            let temp_elector: RoundRobinElector<S> =
                elector_config.clone().build(schemes[0].participants());
            let leader_idx = temp_elector.elect(view2_round, None);
            let leader = participants[usize::from(leader_idx)].clone();

            // Create a voter with the leader's identity
            let leader_scheme = schemes[usize::from(leader_idx)].clone();

            // Setup application mock with some latency so we can inject peer
            // message before automaton completes
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: leader.clone(),
                propose_latency: (50.0, 10.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);
            actor.start();

            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: leader_scheme.clone(),
                elector: elector_config.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: leader_scheme.clone(),
                elector: elector_config.clone().build(leader_scheme.participants()),
                blocker: oracle.control(leader.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_leader".to_string(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels
            let (vote_sender, _) = oracle
                .control(leader.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(leader.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the voter
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher notification
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Now create a finalization certificate for view 1 to advance to view 2
            let view1_round = Round::new(epoch, View::new(1));
            let view1_proposal =
                Proposal::new(view1_round, View::new(0), Sha256::hash(&[b"view1_payload"]));

            let (_, finalization) = build_finalization(&schemes, &view1_proposal, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for batcher to be notified
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update {
                        current,
                        leader: _,
                        finalized,
                        ..
                    } => {
                        assert_eq!(current, View::new(2));
                        assert_eq!(finalized, View::new(1));
                        break;
                    }
                    _ => {
                        continue;
                    }
                }
            }

            // Wait a bit for the voter to request a proposal from automaton for view 2
            context.sleep(Duration::from_millis(5)).await;

            // Create a conflicting proposal from ourselves (equivocating) for view 2
            let conflicting_proposal = Proposal::new(
                view2_round,
                View::new(1),
                Sha256::hash(&[b"leader_proposal"]),
            );

            // Send the proposal via mailbox (simulating batcher receiving leader's notarize)
            // This happens AFTER we requested a proposal but BEFORE the automaton responds
            mailbox.proposal(conflicting_proposal.clone());

            // Ensure we construct a notarize for our proposal
            while let Ok(message) = batcher_receiver.try_recv() {
                match message {
                    batcher::Message::Constructed(Vote::Notarize(notarize)) => {
                        assert!(notarize.proposal == conflicting_proposal);
                    }
                    _ => panic!("unexpected batcher message"),
                }
            }

            // Now wait for our automaton to complete its proposal
            // This should trigger `our_proposal` which will see the conflicting proposal
            context.sleep(Duration::from_millis(100)).await;

            // Add a notarization certificate for conflicting proposal
            let (_, conflicting_notarization) =
                build_notarization(&schemes, &conflicting_proposal, quorum);
            mailbox.recovered(Certificate::Notarization(conflicting_notarization.clone()));

            // Wait for a finalize vote to be broadcast (we drop our own conflicting proposal rather than marking as replaced)
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Constructed(Vote::Finalize(f)) => {
                        assert_eq!(f.proposal, conflicting_proposal);
                        break;
                    }
                    batcher::Message::Update { .. } => {}
                    _ => context.sleep(Duration::from_millis(10)).await,
                }
            }
        });
    }

    #[test_traced]
    fn test_drop_our_proposal_on_conflict() {
        drop_our_proposal_on_conflict(bls12381_threshold_vrf::fixture::<MinPk, _>);
        drop_our_proposal_on_conflict(bls12381_threshold_vrf::fixture::<MinSig, _>);
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinPk, _>);
        drop_our_proposal_on_conflict(bls12381_multisig::fixture::<MinSig, _>);
        drop_our_proposal_on_conflict(ed25519::fixture);
        drop_our_proposal_on_conflict(secp256r1::fixture);
    }

    fn populate_resolver_on_restart<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"populate_resolver_on_restart_test".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);
            actor.start();

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let me = participants[0].clone();
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            let handle = voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build finalization certificate for view 2
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"finalize_without_notarization"]),
            );
            let (_, expected_finalization) = build_finalization(&schemes, &proposal, quorum);

            // Send finalization certificate via voter mailbox
            mailbox.recovered(Certificate::Finalization(expected_finalization.clone()));

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.recv().await.unwrap();
            match finalization {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
            }

            // Restart voter
            handle.abort();

            // Initialize voter actor
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(participants[0].clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "voter_populate_resolver_on_restart_test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register new network channels for the validator (we don't use p2p, so this doesn't matter)
            let me = participants[0].clone();
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(3));
                    assert_eq!(finalized, View::new(2));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Wait for finalization to be sent to resolver
            let finalization = resolver_receiver.recv().await.unwrap();
            match finalization {
                MailboxMessage::Certificate {
                    certificate: Certificate::Finalization(finalization),
                    ..
                } => {
                    assert_eq!(finalization, expected_finalization);
                }
                _ => panic!("unexpected resolver message"),
            }
        });
    }

    #[test_traced]
    fn test_populate_resolver_on_restart() {
        populate_resolver_on_restart::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        populate_resolver_on_restart::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        populate_resolver_on_restart::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        populate_resolver_on_restart::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        populate_resolver_on_restart::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        populate_resolver_on_restart::<_, _, RoundRobin>(secp256r1::fixture, RoundRobin::default());
    }

    /// Regression: startup must consume timeout hints returned by initial batcher update.
    ///
    /// On restart, we recover into `target_view` and inject `LeaderNullify` from the
    /// first `batcher.update`. Even with long timeouts, voter must emit `nullify(target_view)`
    /// immediately rather than waiting for `leader_timeout`.
    fn startup_update_timeout_hint_nullifies_recovered_view<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"startup_update_timeout_hint_nullify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
                true,
            )
            .await;
            let me = participants[0].clone();

            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let elector = elector.build(schemes[0].participants());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let partition = "voter_startup_update_timeout_hint_nullify".to_string();
            let epoch = Epoch::new(333);
            let make_cfg = |page_cache: CacheRef| Config {
                scheme: schemes[0].clone(),
                elector: elector.clone(),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                // Long deadlines prove nullify comes from startup timeout hint, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache,
            };

            // First run: persist progress to a later view.
            let cfg = make_cfg(CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE));
            let (voter, mut mailbox) = Actor::new(context.child("voter_initial"), cfg);

            let (resolver_sender, _resolver_receiver) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(32));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                certificate_sender,
            );

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { .. } => {},
                _ => panic!("expected initial update"),
            }

            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            handle.abort();

            // Restart and inject startup timeout hint from first update.
            let cfg = make_cfg(CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE));
            let (voter, mut mailbox) = Actor::new(context.child("voter_restarted"), cfg);

            let (resolver_sender, _resolver_receiver) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(32));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                certificate_sender,
            );

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update {
                    current,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, target_view);
                    assert_eq!(finalized, target_view.previous().unwrap());
                    mailbox.timeout(Round::new(Epoch::new(333), current), TimeoutReason::LeaderNullify);
                }
                _ => panic!("expected startup update after restart"),
            }

            // Expect immediate nullify from startup timeout hint despite 10s timeouts.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected immediate nullify for recovered view {target_view} from startup timeout hint"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_startup_update_timeout_hint_nullifies_recovered_view() {
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(ed25519::fixture);
        startup_update_timeout_hint_nullifies_recovered_view::<_, _>(secp256r1::fixture);
    }

    /// Skip eligibility after replay is derived from durable finalization and
    /// term progress. Restarting must not restore budget consumed by an unfinalized
    /// term, while a later finalization must make a pending timeout eligible.
    #[test_traced("WARN")]
    fn test_replay_preserves_exhausted_skip_budget() {
        let runner = deterministic::Runner::timed(Duration::from_secs(20));
        runner.start(|mut context| async move {
            let n = 5;
            let quorum = quorum(n);
            let epoch = Epoch::new(333);
            let namespace = b"voter_replay_skip_budget".to_vec();
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let partition = "voter_replay_skip_budget".to_string();
            let page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);

            // Persist the artifacts produced when view 1 is skipped. Replaying the
            // nullification enters view 2 without advancing the finalized floor.
            let skipped_view = View::new(1);
            let skipped_round = Round::new(epoch, skipped_view);
            let (mut nullifies, nullification) =
                build_nullification(&schemes, skipped_round, quorum);
            let local_nullify = nullifies.remove(0);
            seed_voter_journal_artifacts(
                context.child("seed_journal"),
                partition.clone(),
                page_cache.clone(),
                &schemes[0],
                skipped_view,
                vec![
                    Artifact::Nullify(local_nullify),
                    Artifact::Nullification(nullification),
                ],
            )
            .await;

            let (mut mailbox, mut batcher_receiver, _resolver_receiver, _relay, _reporter, _handle) =
                start_voter_with_floor(
                    &mut context,
                    &oracle,
                    &participants,
                    &schemes,
                    RoundRobin::<Sha256>::default(),
                    VoterFloorStart {
                        partition,
                        epoch,
                        floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                        skip_budget: 1,
                        page_cache,
                    },
                )
                .await;

            let recovered_view = View::new(2);
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, finalized, ..
                    } => {
                        assert_eq!(current, recovered_view);
                        assert_eq!(finalized, View::zero());
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // The replayed term has exhausted budget 1, so this one-shot hint must remain pending
            // rather than trigger a skip before the five-second leader deadline.
            mailbox.timeout(
                Round::new(epoch, recovered_view),
                TimeoutReason::LeaderNullify,
            );
            let no_skip_deadline = context.current() + Duration::from_secs(1);
            loop {
                select! {
                    _ = context.sleep_until(no_skip_deadline) => break,
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Nullify(nullify)) = msg.unwrap()
                            && nullify.view() == recovered_view
                        {
                            panic!("replay restored skip budget for {recovered_view}");
                        }
                    },
                }
            }

            // Finalizing view 1 moves the first unfinalized term to view 2. The
            // retained hint is now eligible and must fire before the ordinary deadline.
            let proposal = Proposal::new(
                skipped_round,
                View::zero(),
                Sha256::hash(&[b"restore-skip-budget"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Finalization(finalization));

            let restored_deadline = context.current() + Duration::from_secs(1);
            loop {
                select! {
                    _ = context.sleep_until(restored_deadline) => {
                        panic!("finalization did not restore skip budget for {recovered_view}");
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Nullify(nullify)) = msg.unwrap()
                            && nullify.view() == recovered_view
                        {
                            break;
                        }
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_nullification_notification_omits_floor_but_retry_broadcasts_entry() {
        let n = 5;
        let quorum = quorum(n);
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, b"nullification_floor_broadcast", n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let me = participants[0].clone();
            let observer = participants[1].clone();
            let (_, mut certificates) = oracle
                .control(observer.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    me,
                    observer,
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: probability!(1.0),
                    },
                )
                .await
                .unwrap();

            let (mut mailbox, mut batcher, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                VoterOptions {
                    leader_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_millis(100),
                    ..Default::default()
                },
            )
            .await;
            assert!(matches!(
                batcher.recv().await.unwrap(),
                batcher::Message::Update { current, .. } if current == View::new(1)
            ));

            advance_to_view(&mut mailbox, &mut batcher, &schemes, quorum, View::new(2)).await;
            loop {
                match batcher.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == View::new(2) =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
            let (_, encoded) = certificates.recv().await.unwrap();
            let certificate: Certificate<ed25519::Scheme, Sha256Digest> = Certificate::decode_cfg(
                &mut encoded.as_ref(),
                &schemes[0].certificate_codec_config(),
            )
            .unwrap();
            assert!(matches!(
                certificate,
                Certificate::Finalization(finalization) if finalization.view() == View::new(1)
            ));

            let (_, nullification) =
                build_nullification(&schemes, Round::new(epoch, View::new(2)), quorum);
            mailbox.resolved(Certificate::Nullification(nullification.clone()));
            let (_, encoded) = certificates.recv().await.unwrap();
            let certificate: Certificate<ed25519::Scheme, Sha256Digest> = Certificate::decode_cfg(
                &mut encoded.as_ref(),
                &schemes[0].certificate_codec_config(),
            )
            .unwrap();
            assert!(matches!(
                certificate,
                Certificate::Nullification(received) if received == nullification
            ));
            select! {
                message = certificates.recv() => {
                    panic!("unexpected certificate after nullification: {message:?}");
                },
                _ = context.sleep(Duration::from_millis(10)) => {},
            }

            loop {
                match batcher.recv().await.unwrap() {
                    batcher::Message::Update { current, .. } if current == View::new(3) => break,
                    _ => {}
                }
            }
            mailbox.timeout(Round::new(epoch, View::new(3)), TimeoutReason::Inactivity);
            loop {
                match batcher.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == View::new(3) =>
                    {
                        break;
                    }
                    _ => {}
                }
            }

            let (_, encoded) = certificates.recv().await.unwrap();
            let certificate: Certificate<ed25519::Scheme, Sha256Digest> = Certificate::decode_cfg(
                &mut encoded.as_ref(),
                &schemes[0].certificate_codec_config(),
            )
            .unwrap();
            assert!(matches!(
                certificate,
                Certificate::Nullification(received) if received == nullification
            ));
        });
    }

    fn stall_timeout_nullifies_current_view<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"stall_timeout_nullifies_current_view".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let elector = RoundRobin::<Sha256>::default().with_term(
                TermLength::new(NZU32!(2)),
                Duration::from_secs(5),
                ViewDelta::new(0),
            );
            let first_round = Round::new(Epoch::new(333), View::new(1));
            let built_elector: RoundRobinElector<S> =
                elector.clone().build(schemes[0].participants());
            let leader_idx = built_elector.elect(first_round, None);
            let leader = participants[usize::from(leader_idx)].clone();
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(3),
                    certification_timeout: Duration::from_secs(4),
                    timeout_retry: Duration::from_secs(2),
                    certify_latency_ms: 3500.0,
                    ..Default::default()
                },
            )
            .await;

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { .. } => {}
                _ => panic!("expected initial update"),
            }

            let view_1 = View::new(1);
            let genesis =
                Sha256::hash(&[&(bytes::Bytes::from_static(b"genesis"), Epoch::new(333)).encode()]);
            let proposal_1 = Proposal::new(
                Round::new(Epoch::new(333), view_1),
                View::zero(),
                Sha256::hash(&[b"same_term_timeout_view_1"]),
            );
            let contents = (proposal_1.round, genesis, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_1.payload, contents));
            mailbox.proposal(proposal_1.clone());

            let (_, notarization_1) = build_notarization(&schemes, &proposal_1, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_1));

            loop {
                if let batcher::Message::Update { current, .. } =
                    batcher_receiver.recv().await.unwrap()
                    && current == View::new(2)
                {
                    break;
                }
            }

            select! {
                msg = batcher_receiver.recv() => match msg.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify)) => {
                        assert_eq!(nullify.view(), View::new(2));
                    }
                    batcher::Message::Update { .. } => {
                        panic!("expected current-view nullify before the next update");
                    }
                    batcher::Message::Constructed(Vote::Notarize(_)) => {
                        panic!("expected same-term timeout nullify, got notarize");
                    }
                    batcher::Message::Constructed(Vote::Finalize(_)) => {
                        panic!("expected same-term timeout nullify, got finalize");
                    }
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("expected current-view nullify before leader timeout expired");
                }
            }
        });
    }

    #[test_traced]
    fn test_stall_timeout_nullifies_current_view() {
        stall_timeout_nullifies_current_view::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        stall_timeout_nullifies_current_view::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        stall_timeout_nullifies_current_view::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        stall_timeout_nullifies_current_view::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        stall_timeout_nullifies_current_view::<_, _>(ed25519::fixture);
        stall_timeout_nullifies_current_view::<_, _>(secp256r1::fixture);
    }

    fn finalize_resumes_after_same_term_heal<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalize_resumes_after_same_term_heal".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let (network, oracle) = Network::new(
                context.child("network"),
                NConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let elector =
                RoundRobin::<Sha256>::default().with_term(TermLength::new(NZU32!(3)), Duration::from_secs(20), ViewDelta::new(0));
            let (mut mailbox, mut batcher_receiver, _, _relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(10),
                    certify_latency_ms: 0.0,
                    ..Default::default()
                },
            )
            .await;

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { .. } => {}
                _ => panic!("expected initial update"),
            }

            // The leader of term [1,3] never proposes, so the leader timeout
            // fires and we nullify view 1.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify)) => {
                        assert_eq!(nullify.view(), View::new(1));
                        break;
                    }
                    batcher::Message::Update { .. } => {}
                    _ => panic!("expected nullify for view 1"),
                }
            }

            // Views 1 and 2 notarize and certify anyway, advancing us to view
            // 3. The finalize votes are blocked by the same-term nullify at
            // view 1 (no finalization observed yet).
            let view_1 = View::new(1);
            let proposal_1 = Proposal::new(
                Round::new(Epoch::new(333), view_1),
                View::zero(),
                Sha256::hash(&[b"finalize_resume_view_1"]),
            );
            let (_, notarization_1) = build_notarization(&schemes, &proposal_1, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_1));

            let view_2 = View::new(2);
            let proposal_2 = Proposal::new(
                Round::new(Epoch::new(333), view_2),
                view_1,
                Sha256::hash(&[b"finalize_resume_view_2"]),
            );
            let (_, notarization_2) = build_notarization(&schemes, &proposal_2, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_2));
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { current, .. } if current == View::new(3) => break,
                    batcher::Message::Constructed(Vote::Finalize(_)) => {
                        panic!("finalize must be blocked by the same-term nullify");
                    }
                    _ => {}
                }
            }

            // The finalization for view 1 arrives: our nullify can never form
            // a nullification, so the gate heals.
            let (_, finalization_1) = build_finalization(&schemes, &proposal_1, quorum);
            mailbox.resolved(Certificate::Finalization(finalization_1));

            // View 3 (same term) notarizes and certifies: with the gate
            // healed, its finalize vote must be broadcast.
            let view_3 = View::new(3);
            let proposal_3 = Proposal::new(
                Round::new(Epoch::new(333), view_3),
                view_2,
                Sha256::hash(&[b"finalize_resume_view_3"]),
            );
            let (_, notarization_3) = build_notarization(&schemes, &proposal_3, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_3));
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Finalize(finalize)) = msg.unwrap() {
                            assert_eq!(
                                finalize.view(),
                                View::new(3),
                                "finalize voting should resume at the first view certified after the heal"
                            );
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected finalize for view 3 after heal");
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_finalize_resumes_after_same_term_heal() {
        finalize_resumes_after_same_term_heal::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalize_resumes_after_same_term_heal::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalize_resumes_after_same_term_heal::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        finalize_resumes_after_same_term_heal::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        finalize_resumes_after_same_term_heal::<_, _>(ed25519::fixture);
        finalize_resumes_after_same_term_heal::<_, _>(secp256r1::fixture);
    }

    /// Regression: an optimistic future proposal request must survive the
    /// loop iteration that handles the current view's timeout while the
    /// request is in flight.
    #[test_traced]
    fn test_optimistic_future_proposal_survives_interleaved_timeout() {
        let n = 5;
        let namespace = b"optimistic_future_proposal_survives_interleaved_timeout".to_vec();
        let epoch = Epoch::new(333);
        let term_length = TermLength::new(NZU32!(5));
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let built_elector: elector::RoundRobinElector<ed25519::Scheme> =
                elector.clone().build(schemes[0].participants());
            let local_index =
                usize::from(built_elector.elect(Round::new(epoch, View::new(1)), None));

            let (_mailbox, mut batcher_receiver, _, _relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(2),
                    // The certification timeout fires between the view-2
                    // optimistic proposal request (issued with view 1's
                    // notarize after one propose latency) and its response
                    // (a second propose latency later): handling the view-1
                    // timeout must not drop the in-flight request.
                    certification_timeout: Duration::from_millis(300),
                    timeout_retry: Duration::from_secs(10),
                    local_index,
                    propose_latency_ms: 200.0,
                    ..Default::default()
                },
            )
            .await;

            let mut saw_view_1_notarize = false;
            let mut saw_view_1_nullify = false;
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Update { .. } => {}
                            batcher::Message::Constructed(Vote::Notarize(notarize)) => {
                                if notarize.view() == View::new(1) {
                                    saw_view_1_notarize = true;
                                }
                                if notarize.view() == View::new(2) {
                                    assert!(
                                        saw_view_1_notarize,
                                        "expected view 1 notarize before optimistic view 2 notarize"
                                    );
                                    assert!(
                                        saw_view_1_nullify,
                                        "expected the view-1 timeout to interleave before the view-2 notarize"
                                    );
                                    break;
                                }
                            }
                            batcher::Message::Constructed(Vote::Nullify(nullify))
                                if nullify.view() == View::new(1) =>
                            {
                                saw_view_1_nullify = true;
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(8)) => {
                        panic!(
                            "expected optimistic notarize for view 2 despite interleaved timeout handling"
                        );
                    }
                }
            }
        });
    }

    /// The next view's proposal request reaches the application while the
    /// current view's notarize is waiting for journal sync.
    #[test_traced]
    fn test_next_propose_dispatches_before_sync() {
        let n = 5;
        let namespace = b"next_propose_dispatches_before_sync".to_vec();
        let epoch = Epoch::new(333);
        let term_length = TermLength::new(NZU32!(5));
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle = start_test_network_with_peers(
                context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let built_elector: elector::RoundRobinElector<ed25519::Scheme> =
                elector.clone().build(schemes[0].participants());
            let local_index =
                usize::from(built_elector.elect(Round::new(epoch, View::new(1)), None));

            let pending_syncs = PendingSyncs::default();
            let voter_context = DelayedSyncContext {
                inner: context.child("voter"),
                pending: pending_syncs.clone(),
            };
            let propose_requests = Arc::new(Mutex::new(Vec::new()));
            let (_mailbox, mut batcher_receiver, _, _relay, _) = setup_voter(
                &voter_context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    local_index,
                    propose_latency_ms: 200.0,
                    propose_requests: Some(propose_requests.clone()),
                    ..Default::default()
                },
            )
            .await;

            // Once the view 1 propose request is in flight, gate the journal so
            // the sync covering the view 1 notarize blocks until released.
            wait_for_request(&context, &propose_requests, View::new(1)).await;
            pending_syncs.arm();

            // The voter appends the view 1 notarize and blocks on the gated
            // sync. The view 2 propose request must still reach the application.
            let deferred = next_pending_sync(&pending_syncs);
            deferred
                .blocked
                .await
                .expect("view 1 journal sync was dropped");
            wait_for_request(&context, &propose_requests, View::new(2)).await;

            // Nothing constructed for view 1 may reach the batcher while its
            // sync is blocked.
            while let Some(msg) = batcher_receiver.recv().now_or_never().flatten() {
                assert!(
                    !matches!(
                        msg,
                        batcher::Message::Constructed(Vote::Notarize(ref notarize))
                            if notarize.view() == View::new(1)
                    ),
                    "view 1 notarize reached the batcher before journal sync"
                );
            }
            assert_eq!(
                pending_syncs.calls(),
                1,
                "expected one journal sync after the gate was armed"
            );

            // Release the sync. The view 1 notarize must now be published.
            deferred.release.send(Ok(())).unwrap();
            pending_syncs.unblock();

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Notarize(notarize)) = msg.unwrap()
                            && notarize.view() == View::new(1)
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize for view 1 after journal sync");
                    }
                }
            }
        });
    }

    /// An exited view's pending proposal must not suppress replacement work.
    #[test_collect_traces]
    fn test_stale_propose_does_not_block_replacement_dispatch(traces: TraceStorage) {
        let n = 1;
        let namespace = b"stale_propose_does_not_block_replacement_dispatch".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let elector = RoundRobin::<Sha256>::default().with_term(
                TermLength::new(NZU32!(2)),
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let propose_requests = Arc::new(Mutex::new(Vec::new()));
            let (mut mailbox, mut batcher_receiver, _, _relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_millis(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    propose_requests: Some(propose_requests.clone()),
                    stall_proposals: true,
                    ..Default::default()
                },
            )
            .await;

            assert!(matches!(
                batcher_receiver.recv().await.unwrap(),
                batcher::Message::Update { .. }
            ));
            // The view 1 propose request stalls forever, occupying the pending
            // request slot.
            wait_for_request(&context, &propose_requests, View::new(1)).await;

            // The leader timeout fires while the request is still outstanding.
            let nullify = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Nullify(nullify)) = msg.unwrap()
                            && nullify.view() == View::new(1)
                        {
                            break nullify;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected nullify for view 1");
                    }
                }
            };
            let nullification =
                Nullification::from_nullifies(&schemes[0], non_empty![&nullify], &Sequential)
                    .expect("one signer forms quorum");

            // The nullification exits view 1. A mid-term view requires its
            // immediate parent, so view 2 can never propose. The voter skips to
            // view 3, the term start, which builds on genesis. The stalled
            // view 1 request must not suppress the view 3 request.
            mailbox.resolved(Certificate::Nullification(nullification));
            wait_for_request(&context, &propose_requests, View::new(3)).await;

            // The replacement must dispatch at the same-iteration checkpoint,
            // before the nullification broadcast.
            let events = traces.get_by_level(Level::DEBUG);
            let replacement = trace_position(
                &events,
                "requested proposal from automaton",
                "simplex.voter.propose",
                View::new(3),
            );
            let broadcast = trace_position(
                &events,
                "broadcasting nullification",
                "simplex.voter.notify",
                View::new(1),
            );
            assert!(
                replacement < broadcast,
                "replacement proposal must dispatch before the view 1 nullification broadcast \
                 (replacement at {replacement}, broadcast at {broadcast})"
            );
        });
    }

    /// A buffered optimistic child starts verification as soon as the local
    /// parent notarize makes its ancestry available.
    #[test_collect_traces]
    fn test_optimistic_future_verify_uses_local_parent_notarize(traces: TraceStorage) {
        let n = 5;
        let namespace = b"optimistic_future_verify_uses_local_parent_notarize".to_vec();
        let epoch = Epoch::new(333);
        let term_length = TermLength::new(NZU32!(5));
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let elector = RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let built_elector: elector::RoundRobinElector<ed25519::Scheme> =
                elector.clone().build(schemes[0].participants());
            let leader_idx = built_elector.elect(Round::new(epoch, View::new(1)), None);
            let local_index = (usize::from(leader_idx) + 1) % participants.len();
            let leader = participants[usize::from(leader_idx)].clone();
            let verify_requests = Arc::new(Mutex::new(Vec::new()));

            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    // Timeouts long enough that none fires within the test:
                    // any progress past view 1 can only come from optimistic
                    // verification against the local parent notarize.
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    local_index,
                    verify_latency_ms: 200.0,
                    verify_requests: Some(verify_requests.clone()),
                    ..Default::default()
                },
            )
            .await;

            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { .. } => {}
                _ => panic!("expected initial update"),
            }

            let genesis = mocks::application::genesis::<Sha256>(epoch);

            let proposal_1 = Proposal::new(
                Round::new(epoch, View::new(1)),
                View::zero(),
                Sha256::hash(&[b"optimistic_future_verify_view_1"]),
            );
            let contents_1 = (proposal_1.round, genesis, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_1.payload, contents_1));
            mailbox.proposal(proposal_1.clone());
            wait_for_request(&context, &verify_requests, View::new(1)).await;

            let proposal_2 = Proposal::new(
                Round::new(epoch, View::new(2)),
                View::new(1),
                Sha256::hash(&[b"optimistic_future_verify_view_2"]),
            );
            let contents_2 = (proposal_2.round, proposal_1.payload, 1u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_2.payload, contents_2));
            mailbox.proposal(proposal_2.clone());

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Update { .. } => {}
                            batcher::Message::Constructed(Vote::Notarize(notarize))
                                if notarize.view() == View::new(2) =>
                            {
                                break;
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(8)) => {
                        panic!(
                            "expected optimistic notarize for view 2 after local parent notarize"
                        );
                    }
                }
            }

            // Verification for view 2 must dispatch at the same-iteration
            // checkpoint, before the view 1 notarize broadcast.
            let events = traces.get_by_level(Level::DEBUG);
            let verify_next = trace_position(
                &events,
                "requested proposal verification",
                "simplex.voter.verify",
                View::new(2),
            );
            let broadcast = trace_position(
                &events,
                "broadcasting notarize",
                "simplex.voter.notify",
                View::new(1),
            );
            assert!(
                verify_next < broadcast,
                "view 2 verification must dispatch before the view 1 notarize broadcast \
                 (verify at {verify_next}, broadcast at {broadcast})"
            );
        });
    }

    /// A directly notarized descendant must not hide a local certification
    /// failure in its same-term ancestry.
    #[test_traced]
    fn test_failed_certification_blocks_direct_descendant_verify() {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"failed_certification_blocks_direct_descendant_verify".to_vec();
        let epoch = Epoch::new(333);
        let term_length = TermLength::new(NZU32!(5));
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            // Build a stable-leader network with a follower whose application
            // rejects certification for view 1.
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, &namespace, n);

            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let elector = RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let built_elector: elector::RoundRobinElector<ed25519::Scheme> =
                elector.clone().build(schemes[0].participants());
            let leader_idx = built_elector.elect(Round::new(epoch, View::new(1)), None);
            let local_index = (usize::from(leader_idx) + 1) % participants.len();
            let leader = participants[usize::from(leader_idx)].clone();
            let verify_requests = Arc::new(Mutex::new(Vec::new()));

            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    local_index,
                    verify_requests: Some(verify_requests.clone()),
                    certifier: mocks::application::Certifier::Custom(Box::new(|round, _| {
                        round.view() != View::new(1)
                    })),
                    ..Default::default()
                },
            )
            .await;

            assert!(matches!(
                batcher_receiver.recv().await.unwrap(),
                batcher::Message::Update { .. }
            ));

            // Locally notarize view 1 so its child enters the optimistic
            // issuance window.
            let genesis = mocks::application::genesis::<Sha256>(epoch);
            let proposal_1 = Proposal::new(
                Round::new(epoch, View::new(1)),
                View::zero(),
                Sha256::hash(&[b"failed_ancestor_view_1"]),
            );
            let contents_1 = (proposal_1.round, genesis, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_1.payload, contents_1));
            mailbox.proposal(proposal_1.clone());

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Notarize(notarize)) = msg.unwrap()
                            && notarize.view() == View::new(1)
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize for view 1");
                    }
                }
            }

            // Extend the chain optimistically before view 1's certificate
            // arrives.
            let proposal_2 = Proposal::new(
                Round::new(epoch, View::new(2)),
                View::new(1),
                Sha256::hash(&[b"failed_ancestor_view_2"]),
            );
            let contents_2 = (proposal_2.round, proposal_1.payload, 1u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_2.payload, contents_2));
            mailbox.proposal(proposal_2.clone());

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Notarize(notarize)) = msg.unwrap()
                            && notarize.view() == View::new(2)
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected optimistic notarize for view 2");
                    }
                }
            }

            // Prepare both certificates, but deliver only view 1. Its
            // certification rejection must emit a nullify before view 2
            // becomes directly notarized.
            let (_, notarization_1) = build_notarization(&schemes, &proposal_1, quorum);
            let (_, notarization_2) = build_notarization(&schemes, &proposal_2, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_1));

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Nullify(nullify)) = msg.unwrap()
                            && nullify.view() == View::new(1)
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected failed certification to nullify view 1");
                    }
                }
            }

            // Deliver view 2's certificate and extend the direct chain. The
            // unresolved view-1 rejection must block view 3 before application
            // verification.
            mailbox.resolved(Certificate::Notarization(notarization_2));
            let proposal_3 = Proposal::new(
                Round::new(epoch, View::new(3)),
                View::new(2),
                Sha256::hash(&[b"failed_ancestor_view_3"]),
            );
            let contents_3 = (proposal_3.round, proposal_2.payload, 2u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_3.payload, contents_3));
            mailbox.proposal(proposal_3);

            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Notarize(notarize)) = msg.unwrap()
                            && notarize.view() == View::new(3)
                        {
                            panic!("rejected ancestry must not produce a view 3 notarize");
                        }
                    },
                    _ = context.sleep(Duration::from_secs(1)) => break,
                }
            }
            assert!(
                !verify_requests.lock().contains(&View::new(3)),
                "rejected ancestry must not reach application verification"
            );

            // Nullify the failed ancestor to abandon the term and confirm the
            // voter can advance.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(epoch, View::new(1)), quorum);
            mailbox.resolved(Certificate::Nullification(nullification));
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current == View::new(6)
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected nullification to advance to the next term");
                    }
                }
            }
        });
    }

    fn finalization_from_resolver<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        // This is a regression test as the resolver didn't use to send
        // finalizations to the voter
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"finalization_from_resolver".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let (mut mailbox, mut batcher_receiver, _, _, reporter) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions::default(),
            )
            .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send a finalization from resolver (view 2, which is current+1)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"finalization_from_resolver"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Finalization(finalization.clone()));

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update { finalized, .. } if finalized == view => break,
                    _ => continue,
                }
            }

            // Verify finalization was recorded by checking reporter
            let finalizations = reporter.finalizations.lock();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
        });
    }

    #[test_traced]
    fn test_finalization_from_resolver() {
        finalization_from_resolver::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        finalization_from_resolver::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        finalization_from_resolver::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        finalization_from_resolver::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        finalization_from_resolver::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        finalization_from_resolver::<_, _, RoundRobin>(secp256r1::fixture, RoundRobin::default());
    }

    /// Test that certificates received from the resolver are not sent back to it.
    ///
    /// This is a regression test for the "boomerang" bug where:
    /// 1. Resolver sends a certificate to the voter
    /// 2. Voter processes it and constructs the same certificate
    /// 3. Voter sends it back to resolver (unnecessary)
    fn no_resolver_boomerang<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_resolver_boomerang".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, reporter) =
                setup_voter(
                    &context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    VoterOptions::default(),
                )
                .await;

            // Wait for batcher to be notified
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current,
                    leader: _,
                    finalized,
                    ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Send a finalization from resolver (simulating resolver sending us a certificate)
            let view = View::new(2);
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"no_resolver_boomerang"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Finalization(finalization.clone()));

            // Wait for batcher to be notified of finalization
            loop {
                let message = batcher_receiver.recv().await.unwrap();
                match message {
                    batcher::Message::Update { finalized, .. } if finalized == view => {
                        break;
                    }
                    batcher::Message::Update { .. } => {}
                    _ => continue,
                }
            }

            // Verify finalization was recorded
            let finalizations = reporter.finalizations.lock();
            let recorded = finalizations
                .get(&view)
                .expect("finalization should be recorded");
            assert_eq!(recorded, &finalization);
            drop(finalizations);

            // Ensure resolver hasn't been sent any messages (no boomerang)
            assert!(
                resolver_receiver.recv().now_or_never().is_none(),
                "resolver should not receive the certificate back"
            );
        });
    }

    #[test_traced]
    fn test_no_resolver_boomerang() {
        no_resolver_boomerang::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        no_resolver_boomerang::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        no_resolver_boomerang::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        no_resolver_boomerang::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        no_resolver_boomerang::<_, _, RoundRobin>(ed25519::fixture, RoundRobin::default());
        no_resolver_boomerang::<_, _, RoundRobin>(secp256r1::fixture, RoundRobin::default());
    }

    /// Regression: a voter that misses one mid-term notarization must request
    /// it from the resolver. Certification of every later view in the term
    /// requires the exact-view certificate, so without a fetch the voter can
    /// never certify or advance again. A quorum-critical voter wedged this
    /// way halts the network.
    fn missed_notarization_is_fetched<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 4;
        let quorum = quorum(n);
        let namespace = b"missed_notarization_is_fetched".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Stable leader with optimistic validation enabled. Participant 0
            // (the voter under test) is a follower for term 1.
            let elector = RoundRobin::<Sha256>::default().with_term(
                TermLength::new(NZU32!(5)),
                Duration::from_secs(30),
                ViewDelta::new(2),
            );
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, _reporter) =
                setup_voter(
                    &context,
                    &oracle,
                    &participants,
                    &schemes,
                    elector,
                    VoterOptions::default(),
                )
                .await;

            // Build the term's proposal chain.
            let epoch = Epoch::new(333);
            let proposal = |view: u64, parent: u64| {
                Proposal::new(
                    Round::new(epoch, View::new(view)),
                    View::new(parent),
                    Sha256::hash(&[&view.to_be_bytes()]),
                )
            };
            let (_, notarization_1) = build_notarization(&schemes, &proposal(1, 0), quorum);
            let (_, notarization_2) = build_notarization(&schemes, &proposal(2, 1), quorum);
            let (_, notarization_3) = build_notarization(&schemes, &proposal(3, 2), quorum);

            // Deliver notarization(1) and wait for the voter to certify it and
            // enter view 2.
            mailbox.recovered(Certificate::Notarization(notarization_1));
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { current, .. } if current == View::new(2) => break,
                    _ => continue,
                }
            }
            while resolver_receiver.recv().now_or_never().flatten().is_some() {}

            // Deliver notarization(3) without notarization(2). The voter saw
            // the certificate for view 3 but missed the one for view 2.
            // Certifying view 3 requires the exact certificate for view 2, so
            // the voter asks any validator for it.
            mailbox.recovered(Certificate::Notarization(notarization_3));
            assert!(matches!(
                resolver_receiver.recv().await.unwrap(),
                MailboxMessage::Certificate {
                    certificate: Certificate::Notarization(notarization),
                    ..
                } if notarization.view() == View::new(3)
            ));
            loop {
                select! {
                    message = resolver_receiver.recv() => {
                        let MailboxMessage::Resolve {
                            proposal,
                            view,
                            kind,
                            target,
                            ..
                        } = message.unwrap() else {
                            continue;
                        };
                        assert_eq!(proposal, View::new(3));
                        assert_eq!(view, View::new(2));
                        assert!(matches!(kind, crate::simplex::actors::Kind::Notarization));
                        assert!(target.is_none());
                        break;
                    },
                    _ = context.sleep(Duration::from_secs(20)) => {
                        panic!("voter never requested the missed notarization");
                    },
                }
            }

            // Deliver the fetched parent. The voter must certify the parent
            // before the child and then resume finalize voting.
            while batcher_receiver.recv().now_or_never().flatten().is_some() {}
            mailbox.recovered(Certificate::Notarization(notarization_2));
            let mut certified = Vec::new();
            let mut finalized = Vec::new();
            loop {
                select! {
                    message = resolver_receiver.recv() => match message.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == View::new(2) || view == View::new(3) =>
                        {
                            assert!(success);
                            certified.push(view);
                        }
                        MailboxMessage::Certificate { .. }
                        | MailboxMessage::Certified { .. }
                        | MailboxMessage::Resolve { .. } => {}
                    },
                    message = batcher_receiver.recv() => {
                        if let batcher::Message::Constructed(Vote::Finalize(vote)) = message.unwrap()
                            && (vote.view() == View::new(2) || vote.view() == View::new(3))
                        {
                            finalized.push(vote.view());
                        }
                    },
                    _ = context.sleep(Duration::from_secs(20)) => {
                        panic!(
                            "recovery stalled: certified={certified:?}, finalized={finalized:?}"
                        );
                    },
                }
                if certified == [View::new(2), View::new(3)]
                    && finalized.contains(&View::new(3))
                {
                    break;
                }
            }
        });
    }

    #[test_traced]
    fn test_missed_notarization_is_fetched() {
        // Request routing is scheme-independent; one scheme is enough.
        missed_notarization_is_fetched(ed25519::fixture);
    }

    /// Tests that when proposal verification fails, the voter emits a nullify vote
    /// immediately rather than waiting for the timeout.
    fn verification_failure_emits_nullify_immediately<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let view_retention = ViewDelta::new(10);
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Use participant[0] as the voter
            let signing = schemes[0].clone();
            let me = participants[0].clone();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (10.0, 0.0), // 10ms verification latency
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);

            // Configure application to always fail verification
            actor.set_fail_verification(true);
            actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                elector: elector.clone().build(signing.participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_verify_fail_test_{me}"),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                // Use long timeouts to prove nullify comes immediately, not from timeout
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention,
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            // Resolver and batcher mailboxes
            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(2));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(16));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            // Register network channels for the validator
            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Start the actor
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Wait for initial batcher update
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update { .. } => {}
                _ => panic!("expected Update message"),
            }

            // Advance views until we find one where we're NOT the leader (so we verify
            // rather than propose). Keep track of the previous view's proposal for parent.
            let mut current_view = View::new(1);
            let mut prev_proposal = Proposal::new(
                Round::new(Epoch::new(333), current_view),
                View::zero(),
                Sha256::hash(&[b"v0"]),
            );

            let (target_view, leader) = loop {
                // Send finalization to advance to next view
                let (_, finalization) = build_finalization(&schemes, &prev_proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                // Wait for the view update
                let (new_view, leader) = loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } => {
                            if current > current_view {
                                break (current, leader);
                            }
                        }
                        batcher::Message::Constructed(_) => {}
                    }
                };

                current_view = new_view;

                // Check if we're NOT the leader for this view
                if leader != Participant::new(0) {
                    break (current_view, participants[usize::from(leader)].clone());
                }

                // We're the leader, advance to next view
                prev_proposal = Proposal::new(
                    Round::new(Epoch::new(333), current_view),
                    current_view.previous().unwrap(),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
            };

            // Create proposal for the target view (where we are a verifier)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"test_proposal"]),
            );

            // Broadcast the payload contents so verification can complete (the automaton waits
            // for the contents via the relay).
            let parent_payload = Sha256::hash(&[target_view
                .previous()
                .unwrap()
                .get()
                .to_be_bytes()
                .as_slice()]);
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal);

            // Wait for nullify vote for target_view. Since timeouts are 10s, receiving it
            // within 1s proves it came from verification failure, not timeout.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_verification_failure_emits_nullify_immediately() {
        verification_failure_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        verification_failure_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        verification_failure_emits_nullify_immediately::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Tests that a leader-nullify timeout hint fast-paths local nullify construction.
    fn leader_nullify_timeout_hint_fast_paths_nullify<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"leader_nullify_timeout_hint_fast_paths_nullify".to_vec();
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(5));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                elector: elector.clone().build(signing.participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_leader_nullify_fast_path_{me}"),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                // Long timeouts prove nullify came from fast-path, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(32));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, leader, ..
                    } => (current, leader),
                    _ => panic!("expected initial update"),
                };

            // Move to a non-leader view so we act as a verifier.
            while current_leader == me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } if current > current_view => {
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            let target_view = current_view;
            mailbox.timeout(
                Round::new(Epoch::new(333), target_view),
                TimeoutReason::LeaderNullify,
            );

            // Expect local nullify quickly despite 10s timeouts.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Send the same expire signal again. Duplicates should not retrigger the fast-path.
            mailbox.timeout(
                Round::new(Epoch::new(333), target_view),
                TimeoutReason::LeaderNullify,
            );

            let duplicate_window = context.current() + Duration::from_millis(300);
            loop {
                select! {
                    _ = context.sleep_until(duplicate_window) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!("duplicate leader nullify should not retrigger fast-path");
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_leader_nullify_timeout_hint_fast_paths_nullify() {
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        leader_nullify_timeout_hint_fast_paths_nullify::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Tests that if the application drops proposal requests, the leader emits `nullify`
    /// immediately instead of waiting for timeout.
    fn dropped_propose_emits_nullify_immediately<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_propose_emits_nullify_immediately".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.set_drop_proposals(true);
            app_actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                elector: elector.clone().build(signing.participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_drop_propose_test_{me}"),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                // Long timeouts prove nullify came from fast-path, not timer expiry.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(32));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, leader, ..
                    } => (current, leader),
                    _ => panic!("expected initial update"),
                };

            // Move to a leader view.
            while current_leader != me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } if current > current_view => {
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            let target_view = current_view;

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on dropped propose.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_dropped_propose_emits_nullify_immediately() {
        dropped_propose_emits_nullify_immediately(bls12381_threshold_vrf::fixture::<MinPk, _>);
        dropped_propose_emits_nullify_immediately(bls12381_threshold_vrf::fixture::<MinSig, _>);
        dropped_propose_emits_nullify_immediately(bls12381_multisig::fixture::<MinPk, _>);
        dropped_propose_emits_nullify_immediately(bls12381_multisig::fixture::<MinSig, _>);
        dropped_propose_emits_nullify_immediately(ed25519::fixture);
        dropped_propose_emits_nullify_immediately(secp256r1::fixture);
    }

    /// Tests that if the application drops verification requests, the voter emits `nullify`
    /// immediately instead of waiting for timeout.
    fn dropped_verify_emits_nullify_immediately<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_verify_emits_nullify_immediately".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let signing = schemes[0].clone();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);
            app_actor.set_drop_verifications(true);
            app_actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                elector: elector.clone().build(signing.participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_drop_verify_test_{me}"),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                // Use long timeouts so a fast nullify proves we did not wait for timeout.
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(32));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            // Initial batcher update.
            match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update { .. } => {}
                _ => panic!("expected initial update"),
            }

            // Find a view where we are a verifier (not leader).
            let mut current_view = View::new(1);
            let (target_view, leader) = loop {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                let (new_view, leader) = loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } => {
                            if current > current_view {
                                break (current, leader);
                            }
                        }
                        batcher::Message::Constructed(_) => {}
                    }
                };
                current_view = new_view;
                if leader != Participant::new(0) {
                    break (current_view, participants[usize::from(leader)].clone());
                }
            };

            // Trigger verification in target view. The application drops the verify response,
            // which should immediately trigger nullify.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"drop_verify"]),
            );
            let contents = (
                proposal.round,
                Sha256::hash(&[target_view
                    .previous()
                    .unwrap()
                    .get()
                    .to_be_bytes()
                    .as_slice()]),
                7u64,
            )
                .encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal);

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on dropped verify.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Ensure dropped verify maps to the expected timeout reason metric.
            let encoded = context.encode();
            assert!(
                encoded.lines().any(|line| {
                    line.contains("_timeouts")
                        && line.contains("reason=\"IgnoredProposal\"")
                        && !line.ends_with(" 0")
                }),
                "expected non-zero timeout metric with reason=IgnoredProposal"
            );
        });
    }

    #[test_traced]
    fn test_dropped_verify_emits_nullify_immediately() {
        dropped_verify_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        dropped_verify_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        dropped_verify_emits_nullify_immediately::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// A view-exiting certificate cancels an in-flight verification before
    /// its completion can be processed into a vote for the exited view.
    #[test_traced]
    fn test_finalization_cancels_inflight_verification() {
        let n = 4;
        let quorum = quorum(n);
        let epoch = Epoch::new(333);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, b"finalization_cancels_verify", n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<ed25519::Scheme> =
                elector.clone().build(schemes[0].participants());
            let leader_index =
                usize::from(built_elector.elect(Round::new(epoch, View::new(1)), None));
            let local_index = (leader_index + 1) % schemes.len();
            let verify_requests = Arc::new(Mutex::new(Vec::new()));
            let (mut mailbox, mut batcher_receiver, _, relay, reporter) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(5),
                    certification_timeout: Duration::from_secs(5),
                    local_index,
                    verify_latency_ms: 1_000.0,
                    verify_requests: Some(verify_requests.clone()),
                    ..Default::default()
                },
            )
            .await;

            let (target_view, leader) = match batcher_receiver.recv().await.unwrap() {
                batcher::Message::Update {
                    current, leader, ..
                } => (current, leader),
                _ => panic!("expected initial update"),
            };
            assert_eq!(target_view, View::new(1));
            assert_eq!(usize::from(leader), leader_index);
            assert_ne!(usize::from(leader), local_index);

            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap_or(View::zero()),
                Sha256::hash(&[b"verification_overtaken_by_finalization"]),
            );
            let contents = (
                proposal.round,
                mocks::application::genesis::<Sha256>(epoch),
                7u64,
            )
                .encode();
            relay.broadcast(
                &participants[leader_index],
                Recipients::All,
                (proposal.payload, contents),
            );
            mailbox.proposal(proposal.clone());

            context.sleep(Duration::from_millis(10)).await;
            assert!(
                verify_requests.lock().contains(&target_view),
                "verification must be in flight before finalization arrives"
            );

            let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { current, .. } if current > target_view => break,
                    _ => {}
                }
            }

            // Let the application finish the now-canceled verification. The
            // old view must not regain a path into vote construction.
            context.sleep(Duration::from_secs(2)).await;
            assert!(
                !reporter.notarizes.lock().contains_key(&target_view),
                "verification completed after finalization must not emit a notarize vote"
            );
        });
    }

    /// Tests that permanently invalid proposal ancestry fast-paths `nullify`
    /// instead of waiting for the local timeout.
    fn invalid_ancestry_emits_nullify_immediately<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"invalid_ancestry_emits_nullify_immediately".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_mins(60),
                    ..Default::default()
                },
            )
            .await;

            // Advance until we are a verifier in a post-finalization view.
            let me = Participant::new(0);
            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, leader, ..
                    } => (current, leader),
                    _ => panic!("expected initial update"),
                };

            while current_view == View::new(1) || current_leader == me {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } if current > current_view => {
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }

            // Inject a proposal whose parent is below the finalized floor.
            let target_view = current_view;
            let invalid_parent = target_view
                .previous()
                .expect("target view must have a finalized predecessor")
                .previous()
                .unwrap_or(View::zero());
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                invalid_parent,
                Sha256::hash(&[b"invalid_parent_before_finalized"]),
            );
            mailbox.proposal(proposal);

            // With 10s timeouts, seeing nullify within 1s proves we fast-pathed on invalid ancestry.
            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(_) => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!(
                            "expected nullify for view {} within 1s (timeouts are 10s)",
                            target_view
                        );
                    },
                }
            }

            // Ensure invalid ancestry maps to the expected timeout reason metric.
            let encoded = context.encode();
            assert!(
                encoded.lines().any(|line| {
                    line.contains("_timeouts")
                        && line.contains("reason=\"InvalidProposal\"")
                        && !line.ends_with(" 0")
                }),
                "expected non-zero timeout metric with reason=InvalidProposal"
            );
        });
    }

    #[test_traced]
    fn test_invalid_ancestry_emits_nullify_immediately() {
        invalid_ancestry_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        invalid_ancestry_emits_nullify_immediately::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Tests that a later dropped verification still yields network voting after
    /// prior successful participation.
    fn dropped_verify_still_votes_after_prior_participation<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"dropped_verify_still_votes_after_prior_participation".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let me_idx = Participant::new(0);
            let signing = schemes[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: signing.clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), application_cfg);
            app_actor.set_drop_verifications(true);
            app_actor.start();

            let voter_cfg = Config {
                scheme: signing.clone(),
                elector: elector.clone().build(signing.participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: format!("voter_dropped_verify_after_participation_{me}"),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(250),
                certification_timeout: Duration::from_millis(250),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(10240),
                write_buffer: NZUsize!(10240),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let resolver_mailbox = resolver::Mailbox::new(resolver_sender);
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(64));
            let batcher_mailbox = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let observer = participants[1].clone();
            let (_, mut observer_vote_receiver) = oracle
                .control(observer.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    me.clone(),
                    observer,
                    Link {
                        latency: Duration::from_millis(0),
                        jitter: Duration::from_millis(0),
                        success_rate: probability!(1.0),
                    },
                )
                .await
                .unwrap();

            voter.start(
                batcher_mailbox,
                resolver_mailbox,
                vote_sender,
                certificate_sender,
            );

            let (mut current_view, mut current_leader) =
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, leader, ..
                    } => (current, leader),
                    _ => panic!("expected initial update"),
                };

            // Move to a view where we are leader.
            while current_leader != me_idx {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } if current > current_view => {
                            current_view = current;
                            current_leader = leader;
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    }
                }
            }
            let leader_view = current_view;

            // Wait until we actually broadcast a vote in our leader view.
            let ready_deadline = context.current() + Duration::from_secs(1);
            let mut became_ready = false;
            loop {
                select! {
                    _ = context.sleep_until(ready_deadline) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    },
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        if vote.view() == leader_view {
                            became_ready = true;
                            break;
                        }
                    },
                }
            }
            assert!(
                became_ready,
                "expected a network vote in leader view {leader_view}"
            );

            // Move to a non-leader view to trigger dropped verification.
            let (target_view, target_leader) = loop {
                let proposal = Proposal::new(
                    Round::new(epoch, current_view),
                    current_view.previous().unwrap_or(View::zero()),
                    Sha256::hash(&[&current_view.get().to_be_bytes()]),
                );
                let (_, finalization) = build_finalization(&schemes, &proposal, quorum);
                mailbox.resolved(Certificate::Finalization(finalization));

                let mut found = None;
                loop {
                    match batcher_receiver.recv().await.unwrap() {
                        batcher::Message::Update {
                            current, leader, ..
                        } if current > current_view => {
                            current_view = current;
                            if leader != me_idx {
                                found = Some((current, participants[usize::from(leader)].clone()));
                            }
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    }
                }
                if let Some(target) = found {
                    break target;
                }
            };

            // This verify request will be dropped by the application.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"drop_verify_after_ready"]),
            );
            let contents = (
                proposal.round,
                Sha256::hash(&[target_view
                    .previous()
                    .unwrap()
                    .get()
                    .to_be_bytes()
                    .as_slice()]),
                11u64,
            )
                .encode();
            relay.broadcast(
                &target_leader,
                Recipients::All,
                (proposal.payload, contents),
            );
            mailbox.proposal(proposal);

            // We should still broadcast for target_view (typically a nullify after timeout).
            let target_deadline = context.current() + Duration::from_secs(1);
            let mut saw_target_network_vote = false;
            loop {
                select! {
                    _ = context.sleep_until(target_deadline) => break,
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Update { .. } => {}
                        batcher::Message::Constructed(_) => {}
                    },
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        if vote.view() == target_view {
                            saw_target_network_vote = true;
                            break;
                        }
                    },
                }
            }
            assert!(
                saw_target_network_vote,
                "expected a network vote for target view {target_view} after dropped verification"
            );
        });
    }

    #[test_traced]
    fn test_dropped_verify_still_votes_after_prior_participation() {
        dropped_verify_still_votes_after_prior_participation(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        dropped_verify_still_votes_after_prior_participation(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        dropped_verify_still_votes_after_prior_participation(ed25519::fixture);
        dropped_verify_still_votes_after_prior_participation(secp256r1::fixture);
    }

    /// Tests that after replay, we do not re-certify views that have already
    /// been certified or finalized. Tests both scenarios in the same journal:
    /// 1. Finalization at view 2 (certify never called)
    /// 2. Notarization at view 3 with certification (certify called once)
    ///
    /// After restart, certify should not be called for either view.
    fn no_recertification_after_replay<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_recertification_after_replay".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Track certify calls across restarts
            let certify_calls: Arc<Mutex<Vec<Sha256Digest>>> = Arc::new(Mutex::new(Vec::new()));
            let tracker = certify_calls.clone();

            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let me = participants[0].clone();

            // Create application with certify tracking
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(move |_, d| {
                    tracker.lock().push(d);
                    true
                })),
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "no_recertification_after_replay".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);

            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for initial batcher notification
            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Step 1: Send finalization for view 2 (certify should NOT be called)
            let view2 = View::new(2);
            let proposal2 = Proposal::new(
                Round::new(Epoch::new(333), view2),
                View::new(1),
                Sha256::hash(&[b"finalized_payload"]),
            );
            let (_, finalization) = build_finalization(&schemes, &proposal2, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for finalization
            loop {
                if let batcher::Message::Update { finalized, .. } =
                    batcher_receiver.recv().await.unwrap()
                    && finalized >= view2
                {
                    break;
                }
            }

            assert_eq!(
                certify_calls.lock().len(),
                0,
                "certify should not be called for finalization"
            );

            // Step 2: Send notarization for view 3 (certify SHOULD be called)
            let view3 = View::new(3);
            let digest3 = Sha256::hash(&[b"payload_for_certification"]);
            let proposal3 = Proposal::new(Round::new(Epoch::new(333), view3), view2, digest3);

            // Broadcast payload and send proposal
            let contents = (proposal3.round, proposal2.payload, 0u64).encode();
            relay.broadcast(&me, Recipients::All, (digest3, contents));
            mailbox.proposal(proposal3.clone());

            // Send notarization
            let (_, notarization) = build_notarization(&schemes, &proposal3, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Wait for view advancement (certification complete)
            loop {
                if let batcher::Message::Update { current, .. } =
                    batcher_receiver.recv().await.unwrap()
                    && current > view3
                {
                    break;
                }
            }

            assert_eq!(
                certify_calls.lock().len(),
                1,
                "certify should be called once for notarization"
            );

            // Restart voter
            handle.abort();

            // Create new application with same tracker
            let tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(move |_, d| {
                    tracker.lock().push(d);
                    true
                })),
            };
            let (actor, application) = mocks::application::Application::new(
                context.child("app").with_attribute("index", 2),
                app_cfg,
            );
            actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "no_recertification_after_replay".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1000),
                timeout_retry: Duration::from_secs(1000),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);

            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete
            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Give time for any erroneous certification attempts
            context.sleep(Duration::from_millis(100)).await;

            // Verify no additional certify calls after replay
            assert_eq!(
                certify_calls.lock().len(),
                1,
                "certify should not be called again after replay"
            );
        });
    }

    #[test_traced]
    fn test_no_recertification_after_replay() {
        no_recertification_after_replay::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        no_recertification_after_replay::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        no_recertification_after_replay::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        no_recertification_after_replay::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        no_recertification_after_replay::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        no_recertification_after_replay::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// When the voter is the leader of a view and builds its own proposal, it
    /// must not subsequently ask the automaton to verify that same proposal.
    ///
    /// This is guarded by `Slot::built` (which sets `status = Verified` and
    /// `requested_verify = true`) and by `Round::verify_ready` short-circuiting
    /// for leader-owned views. This test asserts the end-to-end invariant on
    /// the live path (no restart): after calling `automaton.propose`, the voter
    /// must never call `automaton.verify` for the produced payload.
    fn no_self_verify_when_proposing<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_verify_when_proposing".to_vec();
        let partition = "no_self_verify_when_proposing".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Install propose + verify observers from the start so we can assert the
            // leader's propose call fires but no verify call is issued for our proposal.
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the voter wired to the observing application.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {

                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the voter to time out (leader_timeout) and construct a Nullify
            // for the view. By that point the voter has already run the full propose
            // flow (so propose_observer should have fired) and any spurious verify for
            // the same payload would have fired before the timeout.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the live invariant: propose fired (precondition proving the leader
            // flow ran) but verify did not fire for the payload we just built.
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                proposed.contains(&target_view),
                "test precondition: voter must have called automaton.propose for the leader-owned view (observed: {proposed:?})"
            );
            assert!(
                !verified.contains(&target_view),
                "voter must not verify its own leader-built proposal (observed: {verified:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_verify_when_proposing() {
        no_self_verify_when_proposing(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_verify_when_proposing(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_verify_when_proposing(bls12381_multisig::fixture::<MinPk, _>);
        no_self_verify_when_proposing(bls12381_multisig::fixture::<MinSig, _>);
        no_self_verify_when_proposing(ed25519::fixture);
        no_self_verify_when_proposing(secp256r1::fixture);
    }

    /// Restart analogue of `no_self_verify_when_proposing`: after the voter has
    /// proposed and journaled a local notarize as leader, restarting must not
    /// cause the voter to re-propose or to verify its own proposal when it is
    /// re-delivered (e.g. via peer echo through the automaton).
    ///
    /// Replay of the journaled local notarize must restore the slot's proposal,
    /// `requested_build`, and `requested_verify` flags so that:
    /// - `should_build` returns false on the next run-loop iteration (no new
    ///   `automaton.propose` call for a payload the voter already proposed
    ///   and voted on pre-crash), and
    /// - subsequent delivery of the same proposal is a no-op (no
    ///   `automaton.verify` call for a payload the voter built itself).
    fn no_self_propose_or_verify_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_propose_or_verify_after_restart".to_vec();
        let partition = "no_self_propose_or_verify_after_restart".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Pre-restart: plain application (no observers) so the voter can
            // cleanly propose and journal its own notarize vote for view 2.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            // Build and start the pre-restart voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {

                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the voter to emit its own notarize (journaled). The captured
            // proposal is reused post-restart to exercise the re-delivery path.
            let proposal = loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        break notarize.proposal;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            };

            // Restart: abort the voter and construct a fresh application with
            // propose + verify observers to catch any spurious work for the
            // leader-owned view that has a journaled local notarize vote.
            handle.abort();
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) = mocks::application::Application::new(
                context.child("app_restarted"),
                app_cfg,
            );
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the post-restart voter against the same journal partition.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) =
                Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete; confirm we re-entered the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        ..
                    } => {

                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::new(0));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Re-deliver the proposal via the automaton, simulating peer echo after
            // restart. Any spurious propose/verify for this view would fire on the next
            // run-loop iteration. Then wait for leader_timeout to fire a Nullify,
            // proving the voter ran its full flow without ever advancing.
            mailbox.proposal(proposal.clone());
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the restart invariant: neither propose nor verify fires post-restart
            // for a leader-owned view whose journaled notarize replay should have
            // restored the slot's proposal state.
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                !proposed.contains(&target_view),
                "voter must not propose for a leader-owned view after restart (observed: {proposed:?})"
            );
            assert!(
                !verified.contains(&target_view),
                "voter must not verify its own leader-built proposal after restart (observed: {verified:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_propose_or_verify_after_restart() {
        no_self_propose_or_verify_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_propose_or_verify_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_propose_or_verify_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        no_self_propose_or_verify_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        no_self_propose_or_verify_after_restart(ed25519::fixture);
        no_self_propose_or_verify_after_restart(secp256r1::fixture);
    }

    /// Regression: a leader that crashes after calling `automaton.propose` but
    /// before journaling its local `Notarize` must, on restart, issue at most a
    /// single `automaton.propose` call for the leader-owned view and exit that
    /// view via `Vote::Nullify` instead of retrying proposals through the live
    /// run loop.
    fn nullify_after_crash_in_propose_window<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"nullify_after_crash_in_propose_window".to_vec();
        let partition = "nullify_after_crash_in_propose_window".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Pre-crash: drop every propose response. The leader calls
            // `automaton.propose`, the mock swallows the request, and nothing
            // is journaled. An observer records that the pre-crash leader
            // actually got as far as requesting a proposal so the test knows
            // the abort happens inside the propose window rather than before
            // the voter even became leader.
            let pre_propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let pre_propose_tracker = pre_propose_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            // Stall (not drop) so the voter's receiver stays open indefinitely.
            // Dropping the sender would fire `MissingProposal` and journal a
            // `Nullify` before we can abort, which would in turn cause replay
            // to skip the propose path entirely post-restart.
            app_actor.set_stall_proposals(true);
            app_actor.set_propose_observer(Box::new(move |ctx| {
                pre_propose_tracker.lock().push(ctx.view());
            }));
            app_actor.start();

            // Build and start the pre-crash voter. `leader_timeout` is long
            // enough that the voter won't auto-nullify before we abort,
            // guaranteeing the journal contains no `Nullify` either.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(600),
                certification_timeout: Duration::from_secs(600),
                timeout_retry: Duration::from_secs(600),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance into the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the pre-crash voter to call `automaton.propose` for
            // the leader-owned view. The observer fires before the mock parks
            // the response sender, so seeing this entry confirms the voter
            // entered the propose window and is now blocked on a response
            // that will never arrive. Driving the runtime forward with a
            // short `context.sleep` lets the voter and application tasks
            // progress to their next await points without consuming batcher
            // messages we still need for later assertions.
            for _ in 0..100 {
                if pre_propose_calls.lock().contains(&target_view) {
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(
                pre_propose_calls.lock().contains(&target_view),
                "pre-crash voter must reach the propose window for the leader-owned view"
            );

            // Crash: abort the voter. Because `propose` never returned, no
            // `Notarize` (or any other artifact for the target view) reached
            // the journal.
            handle.abort();

            // Post-restart: install a fresh application that also drops
            // `propose` responses. This mirrors the marshal's post-restart
            // behavior when `get_verified` sees a cached block for the round
            // and deliberately drops the tx, forcing the voter to nullify
            // the view rather than reuse the stale block. A propose observer
            // on this application is the assertion anchor: it must record
            // exactly one call for the target view.
            let post_propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let post_propose_tracker = post_propose_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app_restarted"), app_cfg);
            app_actor.set_drop_proposals(true);
            app_actor.set_propose_observer(Box::new(move |ctx| {
                post_propose_tracker.lock().push(ctx.view());
            }));
            app_actor.start();

            // Build and start the post-restart voter on the same partition
            // with a short `leader_timeout` so the nullify path fires promptly
            // once the restarted voter has had a chance to issue its single
            // (dropped) propose request.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(600),
                timeout_retry: Duration::from_secs(600),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete and confirm we re-entered the
            // leader-owned target view. Journal replay saw no notarize for
            // this view, so the slot starts empty and the voter will call
            // `automaton.propose` from scratch.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, leader, ..
                    } => {
                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::new(0));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Wait for the leader-timeout nullify. This also proves the
            // run loop stayed responsive after the dropped propose request:
            // the voter did not livelock trying to re-propose, it reached the
            // timeout path and emitted the nullify vote.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        panic!(
                            "restarted voter must not emit a new Notarize for the \
                             leader-owned view; its stale verified block could \
                             still be cached in marshal"
                        );
                    }
                    batcher::Message::Update { .. } => {}
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the core restart invariant: the restarted voter issued
            // `automaton.propose` at most once for the target view and then
            // nullified instead of retrying.
            let proposed = post_propose_calls.lock();
            let target_call_count = proposed.iter().filter(|v| **v == target_view).count();
            assert_eq!(
                target_call_count, 1,
                "restarted voter must call automaton.propose exactly once for the \
                 leader-owned view before nullifying (observed: {proposed:?})"
            );
        });
    }

    #[test_traced]
    fn test_nullify_after_crash_in_propose_window() {
        nullify_after_crash_in_propose_window(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_after_crash_in_propose_window(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_after_crash_in_propose_window(bls12381_multisig::fixture::<MinPk, _>);
        nullify_after_crash_in_propose_window(bls12381_multisig::fixture::<MinSig, _>);
        nullify_after_crash_in_propose_window(ed25519::fixture);
        nullify_after_crash_in_propose_window(secp256r1::fixture);
    }

    /// After restart, a proposal we already voted on must not be re-verified
    /// when it is re-delivered to the voter (e.g. via the automaton after
    /// peer vote aggregation reconstructs it).
    ///
    /// Uses a view where we are a follower (so `verify_ready` does not
    /// short-circuit). Pre-restart the voter verifies the leader's proposal,
    /// emits a `Notarize` vote, and journals it. Post-restart the voter
    /// replays the journaled `Notarize`; the proposal must be restored as
    /// `Verified` so that re-delivering the proposal does not trigger another
    /// `automaton.verify` call.
    fn no_self_verify_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"no_self_verify_after_restart".to_vec();
        let partition = "no_self_verify_after_restart".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 3 -> leader=Participant::new(1).
            // We are Participant::new(0), so view 3 is a follower view.
            let target_view = View::new(3);
            let target_leader_idx = 1usize;
            let me = participants[0].clone();
            let leader_pk = participants[target_leader_idx].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Pre-restart: plain application (no observers) so the voter can verify
            // the leader's proposal and journal its own notarize vote for view 3.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            // Build and start the pre-restart voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to view 3 via a synthetic finalization for
            // view 2. `advance_to_view` uses Sha256::hash(&[prev_view.to_be_bytes()]) as the
            // parent payload, which we reuse below.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {

                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Simulate the leader's proposal: broadcast its payload contents to the
            // application via the relay, then deliver the proposal to the voter.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"follower_proposal"]),
            );
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader_pk, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Wait for our local notarize (journaled) so replay has something to restore.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        assert_eq!(notarize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Restart: abort the voter and construct a fresh application with
            // propose + verify observers to catch any spurious work for the
            // follower view that has a journaled local notarize vote.
            handle.abort();
            let propose_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let verify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let propose_tracker = propose_calls.clone();
            let verify_tracker = verify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (mut app_actor, application) = mocks::application::Application::new(
                context.child("app_restarted"),
                app_cfg,
            );
            app_actor
                .set_propose_observer(Box::new(move |ctx| propose_tracker.lock().push(ctx.view())));
            app_actor.set_verify_observer(Box::new(move |ctx, _| {
                verify_tracker.lock().push(ctx.view())
            }));
            app_actor.start();

            // Build and start the post-restart voter against the same journal partition.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_millis(500),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_secs(1),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) =
                Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete; confirm we re-entered the follower view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        ..
                    } => {

                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::from_usize(target_leader_idx));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Re-deliver the proposal via the automaton (simulating peer echo after restart).
            // Any spurious verify for the follower view would fire on the next run-loop
            // iteration after the proposal is processed. We then wait for the voter to time
            // out (leader_timeout) and construct a Nullify for the view: by that point the
            // run loop has had ample opportunity to request verification, and emitting a
            // Nullify proves the voter reached the timeout path without ever advancing.
            mailbox.proposal(proposal.clone());
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        break;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the restart invariant: verify does not fire for the previously-voted
            // follower proposal (primary) and propose does not fire for the follower view
            // (trivially, since we are not its leader).
            let proposed = propose_calls.lock();
            let verified = verify_calls.lock();
            assert!(
                !verified.contains(&target_view),
                "voter must not request verification for a previously-voted view after restart (observed: {verified:?})"
            );
            assert!(
                !proposed.contains(&target_view),
                "voter must not propose for a previously-voted view after restart (observed: {proposed:?})"
            );
        });
    }

    #[test_traced]
    fn test_no_self_verify_after_restart() {
        no_self_verify_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        no_self_verify_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        no_self_verify_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        no_self_verify_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        no_self_verify_after_restart(ed25519::fixture);
        no_self_verify_after_restart(secp256r1::fixture);
    }

    /// When the voter is the leader of a view and later reconstructs a
    /// notarization for the proposal it built locally, it certifies that proposal
    /// through the automaton like any other.
    ///
    /// Certification is the durability barrier: the leader awaits its own
    /// proposal's persistence (via the automaton's `certify`) before casting a
    /// finalize vote, so it must not short-circuit. The test asserts the end-to-end
    /// invariant on the live path: a `Finalize` is emitted for the leader-owned
    /// view and the certify observer fires for that view.
    fn certifies_own_proposal_when_proposing<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certifies_own_proposal_when_proposing".to_vec();
        let partition = "certifies_own_proposal_when_proposing".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Install a certify observer to confirm the leader certifies its own
            // proposal for the leader-owned view.
            let certify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let certify_tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(
                    move |round, _| {
                        certify_tracker.lock().push(round.view());
                        true
                    },
                )),
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            // Build and start the voter wired to the observing application.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {

                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Capture the leader's local notarize so we can resolve the matching
            // notarization back into the voter to drive certification.
            let proposal = loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        break notarize.proposal;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            };
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization));

            // A finalize for the leader-owned view proves the voter certified its
            // own proposal without consulting the automaton.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Finalize(finalize))
                        if finalize.view() == target_view =>
                    {
                        assert_eq!(finalize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        panic!(
                            "leader-owned proposal should certify locally instead of nullifying view {target_view}"
                        );
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the live invariant: the certify observer fired for the
            // leader-owned proposal we built ourselves.
            let certified = certify_calls.lock();
            assert!(
                certified.contains(&target_view),
                "voter must certify its own leader-built proposal through the automaton \
                 (the durability barrier before finalize); observed: {certified:?}"
            );
        });
    }

    #[test_traced]
    fn test_certifies_own_proposal_when_proposing() {
        certifies_own_proposal_when_proposing(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certifies_own_proposal_when_proposing(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certifies_own_proposal_when_proposing(bls12381_multisig::fixture::<MinPk, _>);
        certifies_own_proposal_when_proposing(bls12381_multisig::fixture::<MinSig, _>);
        certifies_own_proposal_when_proposing(ed25519::fixture);
        certifies_own_proposal_when_proposing(secp256r1::fixture);
    }

    /// Restart analogue of `certifies_own_proposal_when_proposing`: after the voter
    /// has proposed and journaled a local notarize as leader, restarting recovers
    /// that local proposal evidence and still certifies through the automaton once
    /// the corresponding notarization is resolved.
    ///
    /// The replayed local notarize is what distinguishes this case from merely
    /// observing a leader-owned proposal certificate during catch-up.
    fn certifies_own_proposal_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certifies_own_proposal_after_restart".to_vec();
        let partition = "certifies_own_proposal_after_restart".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Pre-restart: plain application (no observers) so the voter can
            // cleanly propose and journal its own notarize vote for view 2.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            // Build and start the pre-restart voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance to the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {

                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the voter to emit and journal its own notarize for the
            // leader-owned view. The captured proposal is reused post-restart
            // to drive certification.
            let proposal = loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        break notarize.proposal;
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            };

            // Restart: abort the voter and construct a fresh application with a
            // certify observer to catch any spurious certify call for the
            // leader-owned view post-replay.
            handle.abort();
            let certify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let certify_tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(
                    move |round, _| {
                        certify_tracker.lock().push(round.view());
                        true
                    },
                )),
            };
            let (app_actor, application) = mocks::application::Application::new(
                context.child("app_restarted"),
                app_cfg,
            );
            app_actor.start();

            // Build and start the post-restart voter against the same journal partition.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) =
                Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for replay to complete; confirm we re-entered the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current,
                        leader,
                        ..
                    } => {

                        assert_eq!(current, target_view);
                        assert_eq!(leader, Participant::new(0));
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Resolve the matching notarization to drive certification on the
            // restarted voter.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization));

            // A finalize for the leader-owned view proves replay restored the
            // local proposal state and the voter certified it through the automaton.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Finalize(finalize))
                        if finalize.view() == target_view =>
                    {
                        assert_eq!(finalize.proposal, proposal);
                        break;
                    }
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        panic!(
                            "leader-owned recovered proposal should certify locally instead of nullifying view {target_view}"
                        );
                    }
                    batcher::Message::Update { .. } => {},
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Assert the restart invariant: certify fired for the leader-owned
            // view whose journaled local notarize replay restored the local
            // proposal evidence.
            let certified = certify_calls.lock();
            assert!(
                certified.contains(&target_view),
                "voter must certify its own leader-built proposal after restart (observed: {certified:?})"
            );
        });
    }

    #[test_traced]
    fn test_certifies_own_proposal_after_restart() {
        certifies_own_proposal_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certifies_own_proposal_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certifies_own_proposal_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        certifies_own_proposal_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        certifies_own_proposal_after_restart(ed25519::fixture);
        certifies_own_proposal_after_restart(secp256r1::fixture);
    }

    /// Regression: when an elected leader receives an external notarization
    /// for a proposal it did *not* build locally, it must invoke
    /// `automaton.certify` before finalizing the view. The voter certifies every
    /// notarized proposal through the automaton, including externally-recovered
    /// proposals on a leader-owned view.
    fn certify_observer_fires_for_external_leader_proposal<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certify_observer_fires_for_external_leader_proposal".to_vec();
        let partition = "certify_observer_fires_for_external_leader_proposal".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            // Set up the simulated network.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // RoundRobin with epoch=333, n=5: view 2 -> leader=Participant::new(0) = us.
            let target_view = View::new(2);
            let target_epoch = Epoch::new(333);
            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            // Stall the propose response so the slot is never populated with
            // a locally-built proposal. The slot stays empty (proposal=None,
            // status=None) while the voter's internal flag `requested_build`
            // is true, exactly the state in which an externally-recovered
            // proposal lands at the leader.
            //
            // The certify observer records every `automaton.certify` call so the
            // final assertion can confirm certification ran for the recovered
            // leader-owned proposal.
            let certify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let certify_tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(move |round, _| {
                    certify_tracker.lock().push(round.view());
                    true
                })),
            };
            let (mut app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.set_stall_proposals(true);
            app_actor.start();

            // Build and start the voter. Use long `leader_timeout` so the
            // stalled proposal does not trigger a nullify before the
            // conflicting notarization reaches the voter.
            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch: target_epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(target_epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(600),
                certification_timeout: Duration::from_secs(600),
                timeout_retry: Duration::from_secs(600),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, _) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for startup, then advance into the leader-owned view.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update { .. } => {
                        break;
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Craft a proposal the voter could not have built locally
            // (distinct payload) and build its notarization from all validator
            // schemes. The notarization is well-formed; quorum-worth of signers
            // cover the proposal so it will pass `add_notarization`.
            let foreign_payload = Sha256::hash(&[b"foreign_leader_owned_proposal"]);
            let foreign_proposal = Proposal::new(
                Round::new(target_epoch, target_view),
                target_view.previous().unwrap_or(View::zero()),
                foreign_payload,
            );
            let (_, foreign_notarization) = build_notarization(&schemes, &foreign_proposal, quorum);

            // Deliver the foreign notarization. This seeds the voter's slot
            // with a proposal it never built.
            mailbox.resolved(Certificate::Notarization(foreign_notarization));

            // Wait for a `Finalize` on the leader-owned view. Observing
            // finalize proves the certify callback both fired and resolved
            // successfully. Any `Nullify` here would mean the voter never
            // reached the certification branch.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Finalize(finalize))
                        if finalize.view() == target_view =>
                    {
                        assert_eq!(finalize.proposal, foreign_proposal);
                        break;
                    }
                    batcher::Message::Constructed(Vote::Nullify(nullify))
                        if nullify.view() == target_view =>
                    {
                        panic!(
                            "leader-owned view with an externally-recovered proposal \
                             must certify via the automaton instead of nullifying \
                             view {target_view}"
                        );
                    }
                    batcher::Message::Update { .. } => {}
                    batcher::Message::Constructed(_) => {}
                }
            }

            // The certify callback must fire for the leader-owned view: the voter
            // certifies its own proposals through the automaton.
            let certified = certify_calls.lock();
            assert!(
                certified.contains(&target_view),
                "voter must invoke automaton.certify for an externally-recovered \
                 leader-owned proposal (observed: {certified:?})"
            );
        });
    }

    #[test_traced]
    fn test_certify_observer_fires_for_external_leader_proposal() {
        certify_observer_fires_for_external_leader_proposal(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certify_observer_fires_for_external_leader_proposal(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certify_observer_fires_for_external_leader_proposal(bls12381_multisig::fixture::<MinPk, _>);
        certify_observer_fires_for_external_leader_proposal(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certify_observer_fires_for_external_leader_proposal(ed25519::fixture);
        certify_observer_fires_for_external_leader_proposal(secp256r1::fixture);
    }

    /// Test that in-flight certification requests are cancelled when finalization occurs.
    ///
    /// 1. Use a very long certify latency to ensure certification is in-flight.
    /// 2. Send a notarization to trigger certification.
    /// 3. Send a finalization for the same view before certification completes.
    /// 4. Verify that no Certified message is sent to the resolver.
    fn certification_cancelled_on_finalization<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let elector = elector.build(schemes[0].participants());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();

            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "cert_cancel_test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, mut mailbox) = Actor::new(context.child("actor"), cfg);

            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(10));
            let resolver = resolver::Mailbox::new(resolver_sender);

            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(1024));
            let batcher = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for initial batcher notification
            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Send a notarization for view 5 to trigger certification
            let view5 = View::new(5);
            let digest5 = Sha256::hash(&[b"payload_to_certify"]);
            let proposal5 =
                Proposal::new(Round::new(Epoch::new(333), view5), View::new(0), digest5);

            // Broadcast payload
            let contents = (proposal5.round, Sha256::hash(&[b"genesis"]), 42u64).encode();
            relay.broadcast(&me, Recipients::All, (digest5, contents));

            // Send proposal to verify
            mailbox.proposal(proposal5.clone());

            // Send notarization
            let (_, notarization) = build_notarization(&schemes, &proposal5, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Wait for certification to start (it will be slow due to latency)
            context.sleep(Duration::from_millis(100)).await;

            // Send finalization for view 5 before certification completes
            let (_, finalization) = build_finalization(&schemes, &proposal5, quorum);
            mailbox.recovered(Certificate::Finalization(finalization));

            // Wait for finalization to be processed
            loop {
                if let batcher::Message::Update { finalized, .. } =
                    batcher_receiver.recv().await.unwrap()
                    && finalized >= view5
                {
                    break;
                }
            }

            // Wait for resolver finalization message (skip other certificates)
            loop {
                let msg = resolver_receiver
                    .recv()
                    .await
                    .expect("expected resolver msg");
                match msg {
                    MailboxMessage::Certificate {
                        certificate: Certificate::Finalization(f),
                        ..
                    } => {
                        assert_eq!(f.view(), view5);
                        break;
                    }
                    MailboxMessage::Certificate { .. } => continue,
                    MailboxMessage::Resolve { .. } => continue,
                    MailboxMessage::Certified { .. } => {
                        panic!("unexpected Certified message before finalization processed")
                    }
                }
            }

            // Wait longer than certify_latency (2s) to verify certification was cancelled.
            // If certification wasn't cancelled, it would complete and send a Certified message.
            let certified_received = select! {
                msg = resolver_receiver.recv() => {
                    matches!(msg, Some(MailboxMessage::Certified { .. }))
                },
                _ = context.sleep(Duration::from_secs(4)) => false,
            };

            assert!(
                !certified_received,
                "Certified message should NOT have been sent - certification should be cancelled"
            );
        });
    }

    #[test_traced]
    fn test_certification_cancelled_on_finalization() {
        certification_cancelled_on_finalization::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        certification_cancelled_on_finalization::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        certification_cancelled_on_finalization::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    #[test_traced]
    fn test_stale_same_parent_verification_failure_does_not_nullify_replacement() {
        let n = 5;
        let quorum = quorum(n);
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = ed25519::fixture(&mut context, b"stale-same-parent-verification", n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let verify_requests = Arc::new(Mutex::new(Vec::new()));
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                VoterOptions {
                    leader_timeout: Duration::from_secs(5),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    verify_latency_ms: 100.0,
                    certify_latency_ms: 500.0,
                    verify_requests: Some(verify_requests.clone()),
                    fail_verification: true,
                    ..Default::default()
                },
            )
            .await;

            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}
            let view = View::new(5);
            let parent_payload =
                advance_to_view(&mut mailbox, &mut batcher_receiver, &schemes, quorum, view).await;

            let proposal_a = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal-a"]),
            );
            relay.broadcast(
                &participants[1],
                Recipients::All,
                (
                    proposal_a.payload,
                    (proposal_a.round, parent_payload, 1u64).encode(),
                ),
            );
            mailbox.proposal(proposal_a);
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(*verify_requests.lock(), vec![view]);

            let proposal_b = Proposal::new(
                Round::new(Epoch::new(333), view),
                view.previous().unwrap(),
                Sha256::hash(&[b"proposal-b"]),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal_b, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            loop {
                select! {
                    message = batcher_receiver.recv() => match message.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == view =>
                        {
                            panic!("stale verification failure nullified the replacement proposal");
                        }
                        batcher::Message::Update { .. }
                        | batcher::Message::Constructed(_) => {}
                    },
                    message = resolver_receiver.recv() => match message.unwrap() {
                        MailboxMessage::Certified { view: certified, success, .. }
                            if certified == view =>
                        {
                            assert!(success);
                            break;
                        }
                        MailboxMessage::Certificate { .. }
                        | MailboxMessage::Certified { .. }
                        | MailboxMessage::Resolve { .. } => {}
                    },
                    _ = context.sleep(Duration::from_secs(3)) => {
                        panic!("replacement proposal did not finish certification");
                    },
                }
            }
        });
    }

    /// Test that in-flight certification is still reported to resolver after nullification.
    ///
    /// 1. Use a long certify latency so certification remains in-flight.
    /// 2. Send notarization to trigger certification.
    /// 3. Send nullification for the same view before certification completes.
    /// 4. Verify that a Certified message is still sent to resolver when certification completes.
    fn certification_still_reports_to_resolver_after_nullification<S, F, L>(
        mut fixture: F,
        elector: L,
    ) where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let reporter_config = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_config);
            let elector = elector.build(schemes[0].participants());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let application_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (actor, application) =
                mocks::application::Application::new(context.child("application"), application_cfg);
            actor.start();

            let cfg = Config {
                scheme: schemes[0].clone(),
                elector,
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: "cert_after_nullification_test".to_string(),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (actor, mut mailbox) = Actor::new(context.child("actor"), cfg);

            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(10));
            let resolver = resolver::Mailbox::new(resolver_sender);

            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(1024));
            let batcher = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            actor.start(batcher, resolver, vote_sender, certificate_sender);

            // Wait for initial batcher notification
            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Send a notarization for view 5 to trigger certification
            let view5 = View::new(5);
            let digest5 = Sha256::hash(&[b"payload_to_certify"]);
            let proposal5 =
                Proposal::new(Round::new(Epoch::new(333), view5), View::new(0), digest5);

            // Broadcast payload
            let contents = (proposal5.round, Sha256::hash(&[b"genesis"]), 42u64).encode();
            relay.broadcast(&me, Recipients::All, (digest5, contents));

            // Send proposal and notarization
            mailbox.proposal(proposal5.clone());
            let (_, notarization) = build_notarization(&schemes, &proposal5, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Wait for certification to start (it will be slow due to latency)
            context.sleep(Duration::from_millis(100)).await;

            // Send nullification for the same view before certification completes
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), view5), quorum);
            mailbox.recovered(Certificate::Nullification(nullification));

            // Even after nullification, late certification should still be forwarded to resolver.
            let reported = loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == view5 =>
                        {
                            break Some(success);
                        }
                        MailboxMessage::Certified { .. }
                        | MailboxMessage::Certificate { .. }
                        | MailboxMessage::Resolve { .. } => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { .. } = msg.unwrap() {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        break None;
                    },
                }
            };

            assert_eq!(
                reported,
                Some(true),
                "expected resolver to receive successful certification after nullification"
            );
        });
    }

    #[test_traced]
    fn test_certification_still_reports_to_resolver_after_nullification() {
        certification_still_reports_to_resolver_after_nullification::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        certification_still_reports_to_resolver_after_nullification::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Regression: a notarization arriving after nullification for the same view
    /// should still trigger certification.
    fn late_notarization_after_nullification_still_certifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"late_notarization_after_nullification".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network.
            // Build participants and voter.
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;
            let (mut mailbox, mut batcher_receiver, mut resolver_receiver, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                VoterOptions {
                    leader_timeout: Duration::from_secs(5),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_secs(5),
                    ..Default::default()
                },
            )
            .await;

            // Move into a concrete current view.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Nullify current view first.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), target_view), quorum);
            mailbox.resolved(Certificate::Nullification(nullification));

            // Then provide notarization for that same view.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"late_notarization_after_nullification"]),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            let certified = loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == target_view =>
                        {
                            break Some(success);
                        }
                        MailboxMessage::Certified { .. }
                        | MailboxMessage::Certificate { .. }
                        | MailboxMessage::Resolve { .. } => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { .. } = msg.unwrap() {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => break None,
                }
            };

            assert_eq!(
                certified,
                Some(true),
                "expected notarization after nullification to still trigger certification"
            );
        });
    }

    #[test_traced]
    fn test_late_notarization_after_nullification_still_certifies() {
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        late_notarization_after_nullification_still_certifies::<_, _>(ed25519::fixture);
        late_notarization_after_nullification_still_certifies::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: timeout -> receive notarization -> certify.
    /// This test does NOT send a notarize vote first (we timeout before receiving a proposal).
    fn certification_after_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(100),
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_ne!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should not be leader at view 3"
            );

            // Wait for timeout (nullify vote) WITHOUT sending notarize first
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(15)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate (simulating delayed network delivery)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"timeout_test"]),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > target_view
                        {
                            break true;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (timeout case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_timeout() {
        certification_after_timeout::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        certification_after_timeout::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        certification_after_timeout::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        certification_after_timeout::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        certification_after_timeout::<_, _>(ed25519::fixture);
        certification_after_timeout::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: notarize -> timeout -> receive notarization -> certify.
    /// This test runs when we are NOT the leader (receiving proposal from another participant).
    fn certification_after_notarize_timeout_as_follower<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_notarize_timeout_as_follower".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(100),
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_ne!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should not be leader at view 3"
            );

            // Create and send proposal as if from the leader (participant 1)
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"follower_test"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Wait for notarize vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize vote");
                    },
                }
            }

            // Trigger timeout
            context.sleep(Duration::from_secs(11)).await;

            // Wait for nullify vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > target_view
                        {
                            break true;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (follower case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_notarize_timeout_as_follower() {
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_follower::<_, _>(ed25519::fixture);
        certification_after_notarize_timeout_as_follower::<_, _>(secp256r1::fixture);
    }

    /// Tests certification after: notarize -> timeout -> receive notarization -> certify.
    /// This test runs when we ARE the leader (proposing ourselves).
    fn certification_after_notarize_timeout_as_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"certification_after_notarize_timeout_as_leader".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup application mock and voter
            let elector = RoundRobin::<Sha256>::default();
            let built_elector: RoundRobinElector<S> = elector
                .clone()
                .build(&participants.clone().try_into().unwrap());
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(100),
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 2 where we ARE the leader.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 2: leader = 0 (us)
            let target_view = View::new(2);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;
            assert_eq!(
                built_elector.elect(Round::new(Epoch::new(333), target_view), None),
                Participant::new(0),
                "we should be leader at view 2"
            );

            // As leader, wait for our own notarize vote (automaton will propose)
            let proposal = loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                        {
                            break n.proposal.clone();
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected notarize vote as leader");
                    },
                }
            };

            // Trigger timeout
            context.sleep(Duration::from_secs(11)).await;

            // Wait for nullify vote
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                            break,
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(1)) => {
                        panic!("expected nullify vote");
                    },
                }
            }

            // Send notarization certificate (as if other participants formed it)
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.recovered(Certificate::Notarization(notarization));

            // Verify view advances
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > target_view
                        {
                            break true;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        break false;
                    },
                }
            };
            assert!(
                advanced,
                "view should advance after certification (leader case)"
            );
        });
    }

    #[test_traced]
    fn test_certification_after_notarize_timeout_as_leader() {
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_after_notarize_timeout_as_leader::<_, _>(ed25519::fixture);
        certification_after_notarize_timeout_as_leader::<_, _>(secp256r1::fixture);
    }

    /// Tests that when certification returns a cancelled receiver, the voter doesn't hang
    /// and continues to make progress (via voting to nullify the view that could not be certified).
    fn cancelled_certification_does_not_hang<S, F>(mut fixture: F, traces: TraceStorage)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
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
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Cancel
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    certification_timeout: Duration::from_millis(500),
                    timeout_retry: Duration::from_mins(60),
                    certifier: mocks::application::Certifier::Cancel,
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 3 where we're a follower.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            // View 3: leader = 1 (not us)
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"test_proposal"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay
                .broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Build and send notarization so the voter tries to certify
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization));

            // Certification will be cancelled, so the voter should eventually timeout
            // and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Constructed(Vote::Nullify(nullify)) if nullify.view() == target_view => {
                                break;
                            }
                            batcher::Message::Update { .. } => {},
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} despite cancelled certification",
                        );
                    },
                }
            }

            // Verify the "failed to certify proposal" log was emitted with the correct round
            let expected_round = format!("Round {{ epoch: Epoch(333), view: View({target_view}) }}");
            traces
                .get_by_level(Level::DEBUG)
                .expect_event(|event| {
                    event.metadata.content == "failed to certify proposal"
                        && event
                            .metadata
                            .fields
                            .iter()
                            .any(|(name, value)| name == "err" && value == "RecvError(())")
                        && event
                            .metadata
                            .fields
                            .iter()
                            .any(|(name, value)| name == "round" && value == &expected_round)
                })
                .unwrap();
        });
    }

    #[test_collect_traces]
    fn test_cancelled_certification_does_not_hang(traces: TraceStorage) {
        cancelled_certification_does_not_hang(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_multisig::fixture::<MinPk, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(
            bls12381_multisig::fixture::<MinSig, _>,
            traces.clone(),
        );
        cancelled_certification_does_not_hang(ed25519::fixture, traces.clone());
        cancelled_certification_does_not_hang(secp256r1::fixture, traces);
    }

    /// Verifies that per-view work is attributed to view-scoped spans:
    /// 1. The automaton propose request nests under `simplex.voter.view`.
    /// 2. Vote broadcast (within notify) nests under `simplex.voter.view`.
    /// 3. Mailbox messages carry their enqueue span into voter processing.
    fn view_spans_track_automaton_boundary<S, F>(mut fixture: F, traces: TraceStorage)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"consensus".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(5),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 2, where we are the leader.
            // With RoundRobin, epoch=333, n=5: leader = (333 + view) % 5
            let target_view = View::new(2);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Wait for the notarize vote on our own proposal.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Constructed(Vote::Notarize(notarize))
                        if notarize.view() == target_view =>
                    {
                        break;
                    }
                    _ => {}
                }
            }

            // The propose request to the automaton runs under the view span.
            traces
                .get_by_level(Level::DEBUG)
                .expect_event(|event| {
                    event.metadata.content == "requested proposal from automaton"
                        && event
                            .expect_span_at_index(0, |span| {
                                span.expect_content_exact("simplex.voter.propose")?;
                                // Operation spans carry both epoch and view so they
                                // are unambiguous when viewed standalone.
                                span.expect_field_exact("epoch", "333")?;
                                span.expect_field_exact("view", "2")
                            })
                            .is_ok()
                        && event
                            .expect_span(|span| {
                                span.content == "simplex.voter.view"
                                    && span.expect_field_exact("epoch", "333").is_ok()
                                    && span.expect_field_exact("view", "2").is_ok()
                            })
                            .is_ok()
                })
                .unwrap();

            // The notarize broadcast happens within notify under the view span.
            traces
                .get_by_level(Level::DEBUG)
                .expect_event(|event| {
                    event.metadata.content == "broadcasting notarize"
                        && event
                            .expect_span_at_index(0, |span| {
                                span.expect_content_exact("simplex.voter.notify")
                            })
                            .is_ok()
                        && event
                            .expect_span(|span| span.content == "simplex.voter.view")
                            .is_ok()
                })
                .unwrap();

            // Mailbox messages carry their enqueue span into voter processing.
            traces
                .get_by_level(Level::TRACE)
                .expect_event(|event| {
                    event.metadata.content == "received finalization"
                        && event
                            .expect_span_at_index(0, |span| {
                                span.expect_content_exact("simplex.voter.process")
                            })
                            .is_ok()
                        && event
                            .expect_span(|span| span.content == "simplex.voter.mailbox.resolved")
                            .is_ok()
                })
                .unwrap();
        });
    }

    #[test_collect_traces]
    fn test_view_spans_track_automaton_boundary(traces: TraceStorage) {
        view_spans_track_automaton_boundary(ed25519::fixture, traces);
    }

    /// Regression: a canceled certification attempt must not be persisted as failure.
    ///
    /// We first trigger a canceled certify receiver, restart the voter, and then require:
    /// 1. successful certification for the same view from replayed notarization state, and
    /// 2. no immediate timeout/nullify for that view after restart.
    fn cancelled_certification_recertifies_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"cancelled_cert_restart_recertify".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let partition = "cancelled_certification_recertifies_after_restart".to_string();
            let epoch = Epoch::new(333);

            // First run: certification receiver gets cancelled.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Cancel,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app_cancel"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter_cancel"), voter_cfg);

            let (resolver_sender, _resolver_receiver) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { .. } =
                batcher_receiver.recv().await.unwrap()
            {

            }

            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"restart_recertify_payload"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization));

            // Give the canceled certification attempt time to run before restart.
            context.sleep(Duration::from_millis(200)).await;

            // Sanity check: canceled certification should not have advanced this view yet.
            let advanced_before_restart = select! {
                msg = batcher_receiver.recv() => {
                    if let batcher::Message::Update {
                        current, ..
                    } = msg.unwrap()
                    {

                        current > target_view
                    } else {
                        false
                    }
                },
                _ = context.sleep(Duration::from_millis(200)) => false,
            };
            assert!(
                !advanced_before_restart,
                "view should not advance before restart when certification receiver is canceled"
            );

            // Restart voter.
            handle.abort();

            // Second run: certification should succeed from replayed state.
            // Use a longer certify latency so there is a real window where an
            // incorrect immediate nullify could fire after restart.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (2_000.0, 0.0), // 2 seconds
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app_restarted"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition,
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);

            let (resolver_sender, mut resolver_receiver) = mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) = mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { .. } =
                batcher_receiver.recv().await.unwrap()
            {

            }

            loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. } if view == target_view => {
                            assert!(success, "expected successful certification after restart for canceled certification view");
                            break;
                        }
                        MailboxMessage::Certified { .. }
                        | MailboxMessage::Certificate { .. }
                        | MailboxMessage::Resolve { .. } => {}
                    },
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Constructed(Vote::Nullify(nullify))
                                if nullify.view() == target_view =>
                            {
                                panic!("unexpected immediate nullify for view {target_view} after restart");
                            }
                            batcher::Message::Update { .. } => {

                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "timed out waiting for successful certification for restarted view {target_view}"
                        );
                    },
                }
            };

            // Give reporter a moment to ingest any late events and ensure no nullify artifacts
            // were emitted for the restarted target view.
            context.sleep(Duration::from_millis(100)).await;
            assert!(
                !reporter.nullifies.lock().contains_key(&target_view),
                "did not expect nullify votes for restarted view {target_view}"
            );
            assert!(
                !reporter.nullifications.lock().contains_key(&target_view),
                "did not expect nullification certificate for restarted view {target_view}"
            );
        });
    }

    #[test_traced]
    fn test_cancelled_certification_recertifies_after_restart() {
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        cancelled_certification_recertifies_after_restart::<_, _>(ed25519::fixture);
        cancelled_certification_recertifies_after_restart::<_, _>(secp256r1::fixture);
    }

    /// Demonstrates that validators in future views cannot retroactively help
    /// stuck validators escape via nullification.
    ///
    /// This test extends the previous scenario to show that:
    /// 1. A stuck validator (view 3) cannot be rescued by notarizations from future views
    /// 2. The only escape route is a finalization certificate (which requires Byzantine cooperation)
    ///
    /// Once the f+1 honest validators certify view 3 and advance to view 4,
    /// they can only vote to nullify view 4 (their current view) without equivocating.
    /// The `timeout` function only votes to nullify `self.view` (current view).
    fn only_finalization_rescues_validator<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 4;
        let quorum = quorum(n);
        let namespace = b"future_notarization_no_rescue".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(60));
        executor.start(|mut context| async move {
            // Get participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            // Setup voter with Certifier::Cancel to simulate missing verification context.
            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector.clone(),
                VoterOptions {
                    leader_timeout: Duration::from_secs(2),
                    certification_timeout: Duration::from_secs(3),
                    timeout_retry: Duration::from_secs(1),
                    certifier: mocks::application::Certifier::Cancel,
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 4 so the stuck round is not leader-owned by this validator.
            let view_4 = View::new(4);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                view_4,
            )
            .await;

            let proposal_4 = Proposal::new(
                Round::new(Epoch::new(333), view_4),
                view_4.previous().unwrap(),
                Sha256::hash(&[b"view_4_proposal"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal_4.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal_4.payload, contents));
            mailbox.proposal(proposal_4.clone());

            let (_, notarization_4) = build_notarization(&schemes, &proposal_4, quorum);
            mailbox.resolved(Certificate::Notarization(notarization_4));

            // Wait for the first nullify vote (confirms stuck state)
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n)) if n.view() == view_4 =>
                            break,
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(10)) => {
                        panic!("expected nullify vote for view 4");
                    },
                }
            }

            // Now simulate what the "advanced" validators (f+1 honest with context) are doing:
            // They certified view 4 and advanced to view 5, where they're making progress.
            // Send a notarization for view 5 to the stuck validator.
            let view_5 = View::new(5);
            let proposal_5 = Proposal::new(
                Round::new(Epoch::new(333), view_5),
                view_4, // Parent is view 4 (certified by the advanced validators)
                Sha256::hash(&[b"view_5_proposal"]),
            );
            let (_, notarization_5) = build_notarization(&schemes, &proposal_5, quorum);

            // Send the view 5 notarization to the stuck validator
            mailbox.resolved(Certificate::Notarization(notarization_5));

            // The stuck validator should still not advance.
            //
            // Receiving a notarization for view 5 doesn't help because:
            // 1. add_notarization() does not call enter_view() - it only adds to certification_candidates
            // 2. To advance past view 4, the validator needs EITHER:
            //    a. Certification of view 4 to succeed (impossible - no context)
            //    b. A nullification certificate for view 4 (impossible - only f votes)
            //    c. A finalization certificate (requires Byzantine to vote finalize)
            // Use a fixed deadline: timeout retries re-send the nullify vote every
            // second, which would otherwise restart a per-iteration sleep forever.
            let deadline = context.current() + Duration::from_secs(5);
            let advanced = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        match msg.unwrap() {
                            batcher::Message::Update { current, .. } if current > view_4 => {
                                break true;
                            }
                            batcher::Message::Constructed(Vote::Nullify(n)) => {
                                // Still voting nullify for view 4 - expected
                                assert_eq!(
                                    n.view(),
                                    view_4,
                                    "should only vote nullify for stuck view"
                                );
                            }
                            _ => {}
                        }
                    },
                    _ = context.sleep_until(deadline) => {
                        break false;
                    },
                }
            };

            assert!(
                !advanced,
                "receiving a notarization for view 5 should NOT rescue the stuck validator - \
                 they still can't certify view 4 (no context) and can't form a nullification \
                 (not enough votes). The f+1 honest validators who advanced to view 5 cannot \
                 retroactively help because they can only vote nullify for their current view (5), \
                 not for view 4."
            );

            // HOWEVER: A finalization certificate WOULD rescue the stuck validator.
            // If the Byzantine validators eventually cooperate and vote finalize,
            // the finalization would abort the stuck certification and advance the view.
            //
            // Let's demonstrate this escape route works (if Byzantine cooperate):
            let (_, finalization_5) = build_finalization(&schemes, &proposal_5, quorum);
            mailbox.resolved(Certificate::Finalization(finalization_5));

            // Now the validator SHOULD advance (finalization aborts stuck certification)
            let deadline = context.current() + Duration::from_secs(5);
            let rescued = loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > view_5
                        {
                            break true;
                        }
                    },
                    _ = context.sleep_until(deadline) => {
                        break false;
                    },
                }
            };

            assert!(
                rescued,
                "a finalization certificate SHOULD rescue the stuck validator - \
                 this is the ONLY escape route, but it requires Byzantine cooperation \
                 (they must vote finalize). If Byzantine permanently withhold finalize votes, \
                 the stuck validators are permanently excluded from consensus."
            );
        });
    }

    #[test_traced]
    fn test_only_finalization_rescues_validator() {
        only_finalization_rescues_validator::<_, _>(bls12381_threshold_vrf::fixture::<MinPk, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_threshold_vrf::fixture::<MinSig, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        only_finalization_rescues_validator::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        only_finalization_rescues_validator::<_, _>(ed25519::fixture);
        only_finalization_rescues_validator::<_, _>(secp256r1::fixture);
    }

    /// Tests that when certification explicitly fails (returns false), the voter:
    /// 1. Can vote nullify even after having voted notarize
    /// 2. Will emit a nullify vote immediately after certification failure
    ///
    /// This simulates the coding marshal scenario where:
    /// - verify() returns true (shard validity passes)
    /// - Voter votes notarize
    /// - Notarization forms
    /// - certify() returns false (block context mismatch discovered during deferred_verify)
    /// - Voter should vote nullify to attempt to advance
    ///
    /// The liveness concern is: if only f honest validators can vote nullify (the ones who
    /// never saw the shard/never verified), then nullification quorum (2f+1) cannot form
    /// since the f+1 honest who voted notarize need to also vote nullify.
    fn certification_failure_allows_nullify_after_notarize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"cert_fail_nullify".to_vec();
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
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Custom that always returns false
            // This simulates coding marshal's deferred_verify finding context mismatch
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    // Long timeouts to prove nullify comes from cert failure
                    leader_timeout: Duration::from_secs(100),
                    certification_timeout: Duration::from_secs(100),
                    timeout_retry: Duration::from_secs(100),
                    certifier: mocks::application::Certifier::Custom(Box::new(|_, _| false)),
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 3 where we're a follower.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"test_proposal"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Wait for notarize vote first (verification passes)
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n)) if n.view() == target_view => {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // Build and send notarization so the voter tries to certify
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .resolved(Certificate::Notarization(notarization));

            // Certification will fail (returns false), so the voter should emit a nullify vote.
            // This must happen quickly (not after 100s timeout) to prove it's from cert failure.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify)) if nullify.view() == target_view => {
                            // Successfully voted nullify after having voted notarize
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} after certification failure, \
                             even though it already voted notarize"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_certification_failure_allows_nullify_after_notarize() {
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        certification_failure_allows_nullify_after_notarize::<_, _>(ed25519::fixture);
        certification_failure_allows_nullify_after_notarize::<_, _>(secp256r1::fixture);
    }

    /// Verify that a voter recovers via timeout when certification hangs indefinitely.
    ///
    /// This simulates the scenario where a notarization forms but the block is
    /// unrecoverable. This includes the restart case where the local block was not
    /// durable and no peer can provide enough data for reconstruction. In this
    /// case, `certify()` subscribes to the block
    /// but the subscription never resolves. The voter must rely on the view timeout
    /// to emit a nullify vote and advance the chain.
    ///
    /// Unlike `Cancel` mode (where the certify receiver errors immediately), `Pending`
    /// mode holds the certify sender alive so the future never completes, forcing the
    /// voter to recover purely through its timeout mechanism.
    fn pending_certification_nullifies_on_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"pending_cert_nullify".to_vec();
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
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let elector = RoundRobin::<Sha256>::default();

            // Set up voter with Certifier::Pending (certify hangs indefinitely).
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(3),
                    certification_timeout: Duration::from_secs(4),
                    timeout_retry: Duration::from_mins(60),
                    certifier: mocks::application::Certifier::Pending,
                    ..Default::default()
                },
            )
            .await;

            // Advance to view 3 where we're a follower.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Broadcast the payload contents so verification can complete.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"test_proposal"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Wait for notarize vote (verification passes).
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(n))
                            if n.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // Build and send notarization so the voter tries to certify.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            // Certification hangs (sender held alive, receiver pending). The voter
            // must recover via the view timeout and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            // Timeout fired and voter emitted nullify despite
                            // certification being indefinitely pending.
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(8)) => {
                        panic!(
                            "voter should emit nullify for view {target_view} via timeout \
                             when certification hangs indefinitely",
                        );
                    },
                }
            }

            // The local nullify vote alone is not enough to advance. Without a
            // nullification or finalization certificate, the voter must remain in
            // the same view while certification is still pending.
            let advanced_without_certificate = loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Update { current, .. } if current > target_view => {
                            break true;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        break false;
                    },
                }
            };
            assert!(
                !advanced_without_certificate,
                "voter should not advance past view {target_view} without a nullification or finalization certificate"
            );
        });
    }

    #[test_traced]
    fn test_pending_certification_nullifies_on_timeout() {
        pending_certification_nullifies_on_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        pending_certification_nullifies_on_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        pending_certification_nullifies_on_timeout::<_, _>(bls12381_multisig::fixture::<MinPk, _>);
        pending_certification_nullifies_on_timeout::<_, _>(bls12381_multisig::fixture::<MinSig, _>);
        pending_certification_nullifies_on_timeout::<_, _>(ed25519::fixture);
        pending_certification_nullifies_on_timeout::<_, _>(secp256r1::fixture);
    }

    /// Regression: once a proposal is received, leader timeout must no longer fire for that view.
    ///
    /// We require:
    /// 1. No nullify before `certification_timeout` even though `leader_timeout` has elapsed.
    /// 2. Nullify eventually arrives only after `certification_timeout` when no
    ///    certificate progress occurs.
    fn proposal_clears_leader_timeout_before_certification_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"proposal_clears_leader_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, relay, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    ..Default::default()
                },
            )
            .await;

            // Advance to a follower view.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Submit proposal quickly so leader timeout is cleared.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"proposal_clears_leader_timeout"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Ensure proposal verification path ran.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(v)) if v.view() == target_view => {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize vote for view {target_view}");
                    },
                }
            }

            // `leader_timeout` is 1s and `certification_timeout` is 5s. We should not
            // see nullify in this 2s window after proposal handling, even though
            // leader timeout has elapsed.
            let no_nullify_deadline = context.current() + Duration::from_secs(2);
            loop {
                select! {
                    _ = context.sleep_until(no_nullify_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!(
                                "received nullify for view {target_view} before certification timeout"
                            );
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    }
                }
            }

            // After certification timeout elapses, timeout recovery must emit nullify.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        panic!(
                            "expected nullify for view {target_view} after certification timeout"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_proposal_clears_leader_timeout_before_certification_timeout() {
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(ed25519::fixture);
        proposal_clears_leader_timeout_before_certification_timeout::<_, _>(secp256r1::fixture);
    }

    /// Regression: proposals recovered from notarization certificates must clear the
    /// current view's leader timeout without emitting a local notarize vote.
    ///
    /// We require:
    /// 1. No nullify before `certification_timeout` even though `leader_timeout` has elapsed.
    /// 2. Nullify eventually arrives only after `certification_timeout` when certification
    ///    remains pending.
    fn recovered_proposal_clears_leader_timeout_before_certification_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"recovered_proposal_clears_leader_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let elector = RoundRobin::<Sha256>::default();
            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    certifier: mocks::application::Certifier::Pending,
                    ..Default::default()
                },
            )
            .await;

            // Advance to a follower view.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Recover a notarization that carries the proposal for this view.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"recovered_proposal_clears_leader_timeout"]),
            );
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox
                .recovered(Certificate::Notarization(notarization));

            // `leader_timeout` is 1s and `certification_timeout` is 5s. We should not
            // emit a notarize vote or nullify in this 2s window after certificate handling,
            // even though leader timeout has elapsed.
            let quiet_deadline = context.current() + Duration::from_secs(2);
            loop {
                select! {
                    _ = context.sleep_until(quiet_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(v)) if v.view() == target_view => {
                            panic!(
                                "unexpected notarize for view {target_view} from recovered certificate"
                            );
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            panic!(
                                "received nullify for view {target_view} before certification timeout after recovered certificate"
                            );
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    }
                }
            }

            // After certification timeout elapses, timeout recovery must emit nullify.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(6)) => {
                        panic!(
                            "expected nullify for view {target_view} after certification timeout with recovered certificate"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_recovered_proposal_clears_leader_timeout_before_certification_timeout() {
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            ed25519::fixture,
        );
        recovered_proposal_clears_leader_timeout_before_certification_timeout::<_, _>(
            secp256r1::fixture,
        );
    }

    /// Regression: after a timed-out view is nullified and the voter advances,
    /// the next view must start with a fresh leader timeout.
    fn next_view_gets_fresh_timeout_after_prior_view_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"next_view_gets_fresh_timeout_after_prior_view_nullifies".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle = start_test_network_with_peers(context.child("network"),
                participants.clone(),
                true,
            )
            .await;

            let (mut mailbox, mut batcher_receiver, _, _, _) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                RoundRobin::<Sha256>::default(),
                VoterOptions {
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    ..Default::default()
                },
            )
            .await;

            // Wait for the initial view 1 batcher update.
            loop {
                match batcher_receiver.recv().await.unwrap() {
                    batcher::Message::Update {
                        current, ..
                    } => {

                        if current == View::new(1) {
                            break;
                        }
                    }
                    batcher::Message::Constructed(_) => {}
                }
            }

            // Allow view 1 to time out and emit a nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected nullify for view 1");
                    },
                }
            }

            // Deliver a nullification certificate for view 1 so the voter enters view 2.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(Epoch::new(333), View::new(1)), quorum);
            mailbox
                .resolved(Certificate::Nullification(nullification));

            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(2) =>
                        {
                            panic!(
                                "received nullify for view 2 before its fresh leader timeout elapsed"
                            );
                        }
                        batcher::Message::Update { current, .. } if current == View::new(2) => {
                            break;
                        }
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected voter to advance to view 2");
                    },
                }
            }

            // The old view timed out, but the new view should still get its own leader timeout
            // rather than immediately nullifying on entry.
            let quiet_deadline = context.current() + Duration::from_millis(500);
            loop {
                select! {
                    _ = context.sleep_until(quiet_deadline) => break,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(2) =>
                        {
                            panic!(
                                "received nullify for view 2 before its fresh leader timeout elapsed"
                            );
                        }
                        batcher::Message::Update { .. } => {},
                        _ => {}
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_next_view_gets_fresh_timeout_after_prior_view_nullifies() {
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(ed25519::fixture);
        next_view_gets_fresh_timeout_after_prior_view_nullifies::<_, _>(secp256r1::fixture);
    }

    /// Regression: the first view should make progress without timing out when peers are online.
    ///
    /// We require:
    /// 1. No `nullify(1)` is emitted while quorum certificates arrive promptly.
    /// 2. The voter emits `notarize(1)`.
    /// 3. After successful certification, the voter emits `finalize(1)` before
    ///    advancing to view 2.
    fn first_view_progress_without_timeout<S, F, L>(mut fixture: F, elector: L)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: elector::Config<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"first_view_progress_without_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(15));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);

            // Create simulated network
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let first_round = Round::new(Epoch::new(333), View::new(1));
            let leader_idx = elector
                .clone()
                .build(schemes[0].participants())
                .elect(first_round, None);
            let leader = participants[usize::from(leader_idx)].clone();

            let (mut mailbox, mut batcher_receiver, _, relay, reporter) = setup_voter(
                &context,
                &oracle,
                &participants,
                &schemes,
                elector,
                VoterOptions {
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(5),
                    timeout_retry: Duration::from_mins(60),
                    ..Default::default()
                },
            )
            .await;

            // Wait for initial batcher notification.
            let message = batcher_receiver.recv().await.unwrap();
            match message {
                batcher::Message::Update {
                    current, finalized, ..
                } => {
                    assert_eq!(current, View::new(1));
                    assert_eq!(finalized, View::new(0));
                }
                _ => panic!("unexpected batcher message"),
            }

            // Build a valid first-view proposal (parent is genesis at view 0).
            let genesis =
                Sha256::hash(&[&(bytes::Bytes::from_static(b"genesis"), Epoch::new(333)).encode()]);
            let proposal = Proposal::new(
                first_round,
                View::zero(),
                Sha256::hash(&[b"first_view_progress_without_timeout"]),
            );
            let contents = (proposal.round, genesis, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // The voter should notarize view 1 and must not nullify it.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(notarize))
                            if notarize.view() == View::new(1) =>
                        {
                            break;
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(2)) => {
                        panic!("expected notarize for view 1");
                    },
                }
            }

            // Deliver quorum notarization and ensure we finalize + advance to view 2 without nullify.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            let deadline = context.current() + Duration::from_secs(3);
            let reached_view2 = loop {
                select! {
                    _ = context.sleep_until(deadline) => break false,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Finalize(finalize))
                            if finalize.view() == View::new(1) =>
                        {
                            break false;
                        }
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update { current, .. } if current >= View::new(2) => {
                            break true;
                        }
                        _ => {}
                    },
                }
            };
            assert!(!reached_view2, "view advanced before finalize for view 1");

            let reached_view2 = loop {
                select! {
                    _ = context.sleep_until(deadline) => break false,
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == View::new(1) =>
                        {
                            panic!("unexpected nullify for view 1 while peers are online");
                        }
                        batcher::Message::Update { current, .. } if current >= View::new(2) => {
                            break true;
                        }
                        _ => {}
                    },
                }
            };
            assert!(reached_view2, "expected progress to view 2 from view 1");

            // Give the reporter a moment to receive any late events and verify no first-view nullify artifacts.
            context.sleep(Duration::from_millis(50)).await;
            assert!(
                !reporter.nullifies.lock().contains_key(&View::new(1)),
                "did not expect nullify votes for view 1"
            );
            assert!(
                !reporter.nullifications.lock().contains_key(&View::new(1)),
                "did not expect a nullification certificate for view 1"
            );
        });
    }

    #[test_traced]
    fn test_first_view_progress_without_timeout() {
        first_view_progress_without_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
            Random::new(RandomVersion::V1),
        );
        first_view_progress_without_timeout::<_, _, Random>(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
            Random::new(RandomVersion::V1),
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
            RoundRobin::default(),
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
            RoundRobin::default(),
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            ed25519::fixture,
            RoundRobin::default(),
        );
        first_view_progress_without_timeout::<_, _, RoundRobin>(
            secp256r1::fixture,
            RoundRobin::default(),
        );
    }

    /// Certification and the finalize vote share one durable section sync.
    ///
    /// 1. Gate the sync and verify the finalize reaches neither batcher nor network.
    /// 2. Release the sync, observe both deliveries, and abort the voter.
    /// 3. Restart, replay both artifacts, and advance without re-certifying.
    fn successful_certification_replayed_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"successful_cert_replay".to_vec();
        let partition = "successful_cert_replay".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true).await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg.clone());
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let epoch = Epoch::new(333);
            let target_view = View::new(3);

            let pending_syncs = PendingSyncs::default();
            let voter_context = DelayedSyncContext {
                inner: context.child("voter"),
                pending: pending_syncs.clone(),
            };
            let pending_syncs_for_certifier = pending_syncs.clone();

            // Arm the sync gate immediately before the target certification succeeds.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(
                    move |round, _| {
                        assert_eq!(round.view(), target_view);
                        pending_syncs_for_certifier.arm();
                        true
                    },
                )),
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(
                    &voter_context,
                    PAGE_SIZE,
                    PAGE_CACHE_SIZE,
                ),
            };
            let (voter, mut mailbox) = Actor::new(voter_context, voter_cfg);
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let observer = participants[1].clone();
            let (_, mut observer_vote_receiver) = oracle
                .control(observer.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(
                    me.clone(),
                    observer,
                    Link {
                        latency: Duration::ZERO,
                        jitter: Duration::ZERO,
                        success_rate: probability!(1.0),
                    },
                )
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            assert!(matches!(
                batcher_receiver.recv().await.unwrap(),
                batcher::Message::Update { .. }
            ));

            // Advance to follower view 3 (leader = participant 1).
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Send proposal + payload so verification passes.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"cert_replay_payload"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Wait until the notarize for the target view is constructed. The gate is armed
            // in the strictly later iteration that requests certification, by which point the
            // notarize iteration's journal sync has completed, keeping the gate focused on
            // the certification and finalize appends.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Notarize(notarize))
                            if notarize.view() == target_view => break,
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("timed out waiting for notarize in view {target_view}");
                    },
                }
            }

            // Send notarization to trigger certification.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            // Wait until the first durability operation reaches the gate. Both artifacts must have
            // been appended by this point, but notify must still be waiting behind the sync.
            while pending_syncs.lock().is_empty() {
                reschedule().await;
            }
            let deferred = next_pending_sync(&pending_syncs);
            let blocked = deferred.blocked;
            blocked.await.expect("gated section sync was dropped");

            let mut certified_before_sync = false;
            while let Some(msg) = resolver_receiver.recv().now_or_never().flatten() {
                if let MailboxMessage::Certified { view, success, .. } = msg
                    && view == target_view {
                        assert!(success, "expected successful certification");
                        certified_before_sync = true;
                    }
            }
            assert!(
                !certified_before_sync,
                "resolver observed certification before the section sync completed"
            );

            let mut finalize_constructed = false;
            while let Some(msg) = batcher_receiver.recv().now_or_never().flatten() {
                if matches!(
                    msg,
                    batcher::Message::Constructed(Vote::Finalize(ref finalize))
                        if finalize.view() == target_view
                ) {
                    finalize_constructed = true;
                }
            }
            assert!(
                !finalize_constructed,
                "finalize reached the batcher before the section sync completed"
            );
            assert_eq!(
                pending_syncs.calls(),
                1,
                "certification and finalize must share one section sync"
            );

            // While the section sync is blocked, no target finalize may reach the network.
            let deadline = context.current() + Duration::from_millis(10);
            loop {
                select! {
                    _ = context.sleep_until(deadline) => break,
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        assert!(
                            !matches!(
                                vote,
                                Vote::Finalize(ref finalize) if finalize.view() == target_view
                            ),
                            "finalize reached the network before its section sync completed"
                        );
                    },
                }
            }

            deferred.release.send(Ok(())).unwrap();

            // The batcher may report our vote, so it must only receive the
            // finalize after the vote is durable.
            let deadline = context.current() + Duration::from_secs(5);
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if matches!(
                            msg.unwrap(),
                            batcher::Message::Constructed(Vote::Finalize(ref finalize))
                                if finalize.view() == target_view
                        ) {
                            break;
                        }
                    },
                    _ = context.sleep_until(deadline) => {
                        panic!("timed out waiting for durable finalize in view {target_view}");
                    },
                }
            }

            // The resolver should observe certification only after the section sync completes.
            let mut certified = false;
            let deadline = context.current() + Duration::from_secs(5);
            while !certified {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == target_view =>
                        {
                            assert!(success, "expected successful certification");
                            certified = true;
                        }
                        _ => {}
                    },
                    _ = context.sleep_until(deadline) => {
                        panic!("timed out waiting for certification after section sync");
                    },
                }
            }

            // The durable finalize should be broadcast, without another section sync.
            let deadline = context.current() + Duration::from_secs(5);
            loop {
                select! {
                    _ = context.sleep_until(deadline) => {
                        panic!("timed out waiting for finalize in view {target_view}");
                    },
                    message = commonware_p2p::Receiver::recv(&mut observer_vote_receiver) => {
                        let (_, message) = message.unwrap();
                        let vote: Vote<S, Sha256Digest> = Vote::decode(message).unwrap();
                        if matches!(
                            vote,
                            Vote::Finalize(ref finalize) if finalize.view() == target_view
                        ) {
                            break;
                        }
                    },
                }
            }
            assert_eq!(
                pending_syncs.calls(),
                1,
                "certification and finalize used multiple section syncs"
            );

            // Abort first voter.
            handle.abort();

            // Second run: replay should process Artifact::Certification from journal.
            let certify_calls: Arc<Mutex<Vec<View>>> = Arc::new(Mutex::new(Vec::new()));
            let certify_tracker = certify_calls.clone();
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(
                    move |round, _| {
                        certify_tracker.lock().push(round.view());
                        true
                    },
                )),
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app_restarted"), app_cfg);
            app_actor.start();

            let replay_reporter = mocks::reporter::Reporter::new(
                context.child("reporter_restarted"),
                reporter_cfg,
            );

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: replay_reporter.clone(),
                partition,
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Wait for both replay notifications. Certification advances exactly one view.
            let mut replayed_certified = false;
            let mut advanced = false;
            while !(replayed_certified && advanced) {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. } if view == target_view => {
                            assert!(success, "replayed certification should be successful");
                            replayed_certified = true;
                        }
                        _ => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update {
                            current, ..
                        } = msg.unwrap()
                            && current >= target_view.next() {
                                assert_eq!(current, target_view.next());
                                advanced = true;
                            }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("timed out waiting for restarted voter to advance past view {target_view}");
                    },
                }
            }

            // The voter should NOT have called certify on the automaton for
            // target_view (it was replayed from journal).
            {
                let certified = certify_calls.lock();
                assert!(
                    !certified.contains(&target_view),
                    "voter should not re-certify view {target_view} during replay (observed: {certified:?})"
                );
            }

            let finalizes = replay_reporter.finalizes.lock();
            let signers = finalizes
                .get(&target_view)
                .and_then(|payloads| payloads.get(&proposal.payload))
                .expect("coalesced finalize should replay after restart");
            assert!(signers.contains(&me));
        });
    }

    #[test_traced]
    fn test_successful_certification_replayed_after_restart() {
        successful_certification_replayed_after_restart(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        successful_certification_replayed_after_restart(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        successful_certification_replayed_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        successful_certification_replayed_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        successful_certification_replayed_after_restart(ed25519::fixture);
        successful_certification_replayed_after_restart(secp256r1::fixture);
    }

    /// Tests that a failed certification (certify returns false) is correctly replayed
    /// from the journal after a restart. The replayed failure should trigger a timeout
    /// for the view (not re-certify or advance).
    fn failed_certification_replayed_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"failed_cert_replay".to_vec();
        let partition = "failed_cert_replay".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(20));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let epoch = Epoch::new(333);

            // First run: certify fails (returns false).
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Custom(Box::new(|_, _| false)),
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("voter"), voter_cfg);
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Advance to follower view 3.
            let target_view = View::new(3);
            let parent_payload = advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Send proposal + payload.
            let proposal = Proposal::new(
                Round::new(epoch, target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"failed_cert_replay_payload"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, parent_payload, 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());

            // Send notarization to trigger certification.
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            // Wait for failed certification result to be reported to resolver.
            loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == target_view =>
                        {
                            assert!(!success, "expected failed certification");
                            break;
                        }
                        _ => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { .. } = msg.unwrap() {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("timed out waiting for failed certification in first run");
                    },
                }
            }

            // Let the journal sync.
            context.sleep(Duration::from_millis(50)).await;
            while let Some(msg) = batcher_receiver.recv().now_or_never().flatten() {
                if let batcher::Message::Update { .. } = msg {}
            }

            // Abort first voter.
            handle.abort();

            // Second run: replay should process Artifact::Certification(false) from journal.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app_restarted"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(5),
                certification_timeout: Duration::from_secs(5),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // The replayed failed certification should be reported to resolver
            // and the voter should NOT advance past target_view.
            let mut replayed_certified = false;
            loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certified { view, success, .. }
                            if view == target_view =>
                        {
                            assert!(!success, "replayed certification should be a failure");
                            replayed_certified = true;
                        }
                        _ => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap() {
                            // After replay, should be at target_view (not past it).
                            if current == target_view && replayed_certified {
                                break;
                            }
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        if replayed_certified {
                            break;
                        }
                        panic!("timed out waiting for replayed failed certification");
                    },
                }
            }

            assert!(
                replayed_certified,
                "resolver should receive Certified(false) during replay for view {target_view}"
            );
        });
    }

    #[test_traced]
    fn test_failed_certification_replayed_after_restart() {
        failed_certification_replayed_after_restart(bls12381_threshold_vrf::fixture::<MinPk, _>);
        failed_certification_replayed_after_restart(bls12381_threshold_vrf::fixture::<MinSig, _>);
        failed_certification_replayed_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        failed_certification_replayed_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        failed_certification_replayed_after_restart(ed25519::fixture);
        failed_certification_replayed_after_restart(secp256r1::fixture);
    }

    /// Tests that nullify votes and nullification certificates are correctly
    /// replayed from the journal after a restart.
    ///
    /// 1. First run: follower times out, votes nullify, receives nullification
    ///    certificate. All persisted to journal.
    /// 2. Abort the voter.
    /// 3. Second run: voter replays journal and processes Artifact::Nullify and
    ///    Artifact::Nullification entries. The resolver receives the nullification
    ///    and the voter re-enters the same view (since it was never finalized).
    fn nullify_and_nullification_replayed_after_restart<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"nullify_nullification_replay".to_vec();
        let partition = "nullify_nullification_replay".to_string();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());
            let epoch = Epoch::new(333);
            let pending_syncs = PendingSyncs::default();
            let voter_context = DelayedSyncContext {
                inner: context.child("voter"),
                pending: pending_syncs.clone(),
            };

            // First run: trigger timeout and nullification.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: partition.clone(),
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(100),
                certification_timeout: Duration::from_secs(100),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&voter_context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(voter_context, voter_cfg);
            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();
            let handle = voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Advance to follower view 3.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Gate the first-attempt nullify's journal sync.
            pending_syncs.arm();
            mailbox.timeout(Round::new(epoch, target_view), TimeoutReason::LeaderTimeout);
            while pending_syncs.lock().is_empty() {
                reschedule().await;
            }
            let deferred = next_pending_sync(&pending_syncs);
            deferred
                .blocked
                .await
                .expect("gated nullify section sync was dropped");

            while let Some(msg) = batcher_receiver.recv().now_or_never().flatten() {
                assert!(
                    !matches!(
                        msg,
                        batcher::Message::Constructed(Vote::Nullify(ref nullify))
                            if nullify.view() == target_view
                    ),
                    "nullify reached the batcher before the section sync completed"
                );
            }

            deferred.release.send(Ok(())).unwrap();

            // Wait for the durable timeout-driven nullify vote.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(n))
                            if n.view() == target_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected nullify vote for view {target_view}");
                    },
                }
            }

            // Send a nullification certificate for this view.
            let (_, nullification) =
                build_nullification(&schemes, Round::new(epoch, target_view), quorum);
            mailbox.resolved(Certificate::Nullification(nullification));

            // Wait for the voter to process the nullification (advances to next view).
            loop {
                select! {
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > target_view
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("timed out waiting for view advance after nullification");
                    },
                }
            }

            // Let journal sync.
            context.sleep(Duration::from_millis(50)).await;
            while let Some(msg) = batcher_receiver.recv().now_or_never().flatten() {
                if let batcher::Message::Update { .. } = msg {}
            }

            // Abort first voter.
            handle.abort();

            // Second run: replay should process Artifact::Nullify and
            // Artifact::Nullification from journal.
            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app_restarted"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition,
                epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(epoch)),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(1),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, _mailbox) = Actor::new(context.child("voter_restarted"), voter_cfg);
            let (resolver_sender, mut resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(8));
            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(8));
            let (vote_sender, _) = oracle
                .control(me.clone())
                .register(2, TEST_QUOTA)
                .await
                .unwrap();
            let (cert_sender, _) = oracle
                .control(me.clone())
                .register(3, TEST_QUOTA)
                .await
                .unwrap();
            voter.start(
                batcher::Mailbox::new(batcher_sender),
                resolver::Mailbox::new(resolver_sender),
                vote_sender,
                cert_sender,
            );

            // Verify: resolver receives the replayed nullification.
            let mut replayed_nullification = false;
            loop {
                select! {
                    msg = resolver_receiver.recv() => match msg.unwrap() {
                        MailboxMessage::Certificate {
                            certificate: Certificate::Nullification(n),
                            ..
                        } if n.view() == target_view => {
                            replayed_nullification = true;
                        }
                        _ => {}
                    },
                    msg = batcher_receiver.recv() => {
                        if let batcher::Message::Update { current, .. } = msg.unwrap()
                            && current > target_view
                            && replayed_nullification
                        {
                            break;
                        }
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        if replayed_nullification {
                            break;
                        }
                        panic!("timed out waiting for nullification replay");
                    },
                }
            }

            assert!(
                replayed_nullification,
                "resolver should receive nullification during replay for view {target_view}"
            );
        });
    }

    #[test_traced]
    fn test_nullify_and_nullification_replayed_after_restart() {
        nullify_and_nullification_replayed_after_restart(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        );
        nullify_and_nullification_replayed_after_restart(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        nullify_and_nullification_replayed_after_restart(bls12381_multisig::fixture::<MinPk, _>);
        nullify_and_nullification_replayed_after_restart(bls12381_multisig::fixture::<MinSig, _>);
        nullify_and_nullification_replayed_after_restart(ed25519::fixture);
        nullify_and_nullification_replayed_after_restart(secp256r1::fixture);
    }

    /// Tests that when the batcher signals a timeout reason on view update,
    /// the voter immediately triggers a timeout for the current view.
    ///
    /// This covers the path where `batcher.update()` returns `Some(TimeoutReason)`
    /// (e.g., because the leader is inactive or has already nullified the view).
    fn batcher_update_triggers_timeout<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
    {
        let n = 5;
        let quorum = quorum(n);
        let namespace = b"batcher_update_timeout".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let oracle =
                start_test_network_with_peers(context.child("network"), participants.clone(), true)
                    .await;

            let me = participants[0].clone();
            let elector = RoundRobin::<Sha256>::default();
            let reporter_cfg = mocks::reporter::Config {
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
                elector: elector.clone(),
            };
            let reporter = mocks::reporter::Reporter::new(context.child("reporter"), reporter_cfg);
            let relay = Arc::new(mocks::relay::Relay::<Sha256Digest, _>::new());

            let app_cfg = mocks::application::Config::<Sha256, _> {
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
                certify_latency: (1.0, 0.0),
                should_certify: mocks::application::Certifier::Always,
            };
            let (app_actor, application) =
                mocks::application::Application::new(context.child("app"), app_cfg);
            app_actor.start();

            let voter_cfg = Config {
                scheme: schemes[0].clone(),
                elector: elector.clone().build(schemes[0].participants()),
                blocker: oracle.control(me.clone()),
                automaton: application.clone(),
                relay: application.clone(),
                reporter,
                partition: format!("batcher_timeout_test_{me}"),
                epoch: Epoch::new(333),
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(Epoch::new(333))),
                mailbox_size: NZUsize!(128),
                leader_timeout: Duration::from_secs(100),
                certification_timeout: Duration::from_secs(100),
                timeout_retry: Duration::from_mins(60),
                skip_budget: u64::MAX,
                view_retention: ViewDelta::new(10),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let (voter, mut mailbox) = Actor::new(context.child("actor"), voter_cfg);

            let (resolver_sender, _resolver_receiver) =
                mailbox::new(context.child("resolver_mailbox"), NZUsize!(10));
            let resolver = resolver::Mailbox::new(resolver_sender);

            let (batcher_sender, mut batcher_receiver) =
                mailbox::new(context.child("batcher_mailbox"), NZUsize!(1024));
            let batcher = batcher::Mailbox::new(batcher_sender);

            let (vote_sender, _vote_receiver) = oracle
                .control(me.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            let (certificate_sender, _certificate_receiver) = oracle
                .control(me.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            voter.start(batcher, resolver, vote_sender, certificate_sender);

            // Consume initial Update.
            if let batcher::Message::Update { .. } = batcher_receiver.recv().await.unwrap() {}

            // Advance to follower view 3 using finalization.
            let target_view = View::new(3);
            advance_to_view(
                &mut mailbox,
                &mut batcher_receiver,
                &schemes,
                quorum,
                target_view,
            )
            .await;

            // Certify view 3 to advance to view 4.
            let proposal = Proposal::new(
                Round::new(Epoch::new(333), target_view),
                target_view.previous().unwrap(),
                Sha256::hash(&[b"batcher_timeout_view3"]),
            );
            let leader = participants[1].clone();
            let contents = (proposal.round, Sha256::hash(&[b"genesis"]), 0u64).encode();
            relay.broadcast(&leader, Recipients::All, (proposal.payload, contents));
            mailbox.proposal(proposal.clone());
            let (_, notarization) = build_notarization(&schemes, &proposal, quorum);
            mailbox.resolved(Certificate::Notarization(notarization));

            // Wait for the Update for view 4 and simulate the batcher signaling that
            // the leader should be skipped.
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Update { current, .. } if current > target_view => {
                            // Signal leader inactivity to trigger the timeout path.
                            mailbox.timeout(
                                Round::new(Epoch::new(333), current),
                                TimeoutReason::Inactivity,
                            );
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!("expected Update for view > {target_view}");
                    },
                }
            }

            // The voter should emit a nullify vote for view 4 quickly (not
            // after the 100s leader timeout) because the batcher signaled
            // immediate timeout.
            let next_view = target_view.next();
            loop {
                select! {
                    msg = batcher_receiver.recv() => match msg.unwrap() {
                        batcher::Message::Constructed(Vote::Nullify(nullify))
                            if nullify.view() == next_view =>
                        {
                            break;
                        }
                        batcher::Message::Update { .. } => {}
                        _ => {}
                    },
                    _ = context.sleep(Duration::from_secs(5)) => {
                        panic!(
                            "expected nullify for view {next_view} triggered by batcher timeout"
                        );
                    },
                }
            }
        });
    }

    #[test_traced]
    fn test_batcher_update_triggers_timeout() {
        batcher_update_triggers_timeout(bls12381_threshold_vrf::fixture::<MinPk, _>);
        batcher_update_triggers_timeout(bls12381_threshold_vrf::fixture::<MinSig, _>);
        batcher_update_triggers_timeout(bls12381_multisig::fixture::<MinPk, _>);
        batcher_update_triggers_timeout(bls12381_multisig::fixture::<MinSig, _>);
        batcher_update_triggers_timeout(ed25519::fixture);
        batcher_update_triggers_timeout(secp256r1::fixture);
    }
}
