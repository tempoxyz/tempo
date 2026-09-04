//! Tempo mailbox certification against real marshal archives.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy_consensus::Header;
use alloy_primitives::B256;
use clap::Parser as _;
use commonware_actor::{Feedback, mailbox};
use commonware_consensus::{
    Automaton as _, CertifiableAutomaton as _, Relay as _, Reporter as _,
    marshal::{
        self,
        core::{self, Buffer},
        resolver::handler,
        standard::Standard,
    },
    simplex::{Plan, types::Context},
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{certificate::ConstantProvider, ed25519::PublicKey};
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_resolver::{Fetch, Resolver, TargetedResolver};
use commonware_runtime::{
    Blob as _, Handle, Runner as _, Spawner as _, Storage as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{archive::prunable, translator::TwoCap};
use commonware_utils::{
    Acknowledgement as _, NZU16, NZU64, NZUsize, acknowledgement::Exact, channel::oneshot,
    vec::NonEmptyVec,
};
use reth_node_core::primitives::SealedBlock;
use tempo_primitives::{TempoConsensusContext, TempoHeader};

use super::{
    durability::{Durability, publish_verification},
    ingress::{Mailbox, Message},
};
use crate::{
    alias,
    consensus::{Digest, block::Block},
    storage,
    test_utils::dkg_fixture,
};

fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}
fn block(view: u64) -> Block {
    Block::from_execution_block_unchecked(
        SealedBlock::seal_slow(tempo_primitives::Block {
            header: TempoHeader {
                inner: Header {
                    number: view,
                    ..Default::default()
                },
                consensus_context: Some(TempoConsensusContext {
                    epoch: 0,
                    view,
                    parent_view: view.saturating_sub(1),
                    proposer: tempo_primitives::ed25519::PublicKey::from_seed(42),
                }),
                ..Default::default()
            },
            body: Default::default(),
        }),
        None,
    )
}

#[derive(Clone)]
struct LocalResolver {
    _handler: handler::Handler<Digest>,
}
impl Resolver for LocalResolver {
    type Key = handler::Key<Digest>;
    type Subscriber = handler::Annotation;
    fn fetch<F: Into<Fetch<Self::Key, Self::Subscriber>> + Send>(&mut self, _: F) -> Feedback {
        Feedback::Ok
    }
    fn fetch_all<F: Into<Fetch<Self::Key, Self::Subscriber>> + Send>(
        &mut self,
        _: Vec<F>,
    ) -> Feedback {
        Feedback::Ok
    }
    fn retain(
        &mut self,
        _: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        Feedback::Ok
    }
}
impl TargetedResolver for LocalResolver {
    type PublicKey = PublicKey;
    fn fetch_targeted(
        &mut self,
        _: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        _: NonEmptyVec<PublicKey>,
    ) -> Feedback {
        Feedback::Ok
    }
    fn fetch_all_targeted<F: Into<Fetch<Self::Key, Self::Subscriber>> + Send>(
        &mut self,
        _: Vec<(F, NonEmptyVec<PublicKey>)>,
    ) -> Feedback {
        Feedback::Ok
    }
}

#[derive(Clone, Default)]
struct RecordingBuffer(Arc<Mutex<Vec<Digest>>>);
impl Buffer<Standard<Block>> for RecordingBuffer {
    type PublicKey = PublicKey;
    async fn find_by_digest(&self, _: Digest) -> Option<Arc<Block>> {
        None
    }
    async fn find_by_commitment(&self, _: Digest) -> Option<Arc<Block>> {
        None
    }
    fn subscribe_by_digest(&self, _: Digest) -> Option<oneshot::Receiver<Arc<Block>>> {
        None
    }
    fn subscribe_by_commitment(&self, _: Digest) -> Option<oneshot::Receiver<Arc<Block>>> {
        None
    }
    fn finalized(&self, _: Digest) {}
    fn send(&self, _: Round, block: Arc<Block>, _: Recipients<PublicKey>) {
        self.0.lock().unwrap().push(block.digest());
    }
}

struct Harness {
    mailbox: Mailbox,
    receiver: mailbox::Receiver<Message>,
    marshal: alias::marshal::Mailbox,
    actor: Handle<()>,
    buffer: RecordingBuffer,
}

#[derive(clap::Parser)]
struct HarnessArgs {
    #[arg(long)]
    #[allow(dead_code)]
    dev: bool,
    #[arg(long)]
    #[allow(dead_code)]
    follow: Option<String>,
    #[command(flatten)]
    consensus: crate::args::Args,
}

async fn setup(mut context: deterministic::Context, enabled: bool) -> Harness {
    let mut cli = vec!["test", "--dev"];
    if enabled {
        cli.push("--consensus.inline-durability");
    }
    let config = HarnessArgs::try_parse_from(cli).unwrap().consensus;
    let fixture = dkg_fixture(&mut context, Epoch::zero());
    let page_cache = CacheRef::from_pooler(&context, NZU16!(4096), NZUsize!(64));
    let finalizations =
        storage::init_finalizations_archive(&context, "inline-test", page_cache.clone())
            .await
            .unwrap();
    let blocks = prunable::Archive::<TwoCap, _, Digest, Block>::init(
        context.child("blocks"),
        prunable::Config {
            translator: TwoCap,
            key_partition: "inline-test-block-key".into(),
            key_page_cache: page_cache.clone(),
            value_partition: "inline-test-block-value".into(),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(16),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        },
    )
    .await
    .unwrap();
    let (actor, marshal, _) = core::Actor::<_, Standard<Block>, _, _, _, _, _, Exact>::init(
        context.child("marshal"),
        finalizations,
        blocks,
        marshal::Config {
            provider: ConstantProvider::new(fixture.schemes[0].clone()),
            epocher: FixedEpocher::new(NZU64!(100)),
            start: marshal::Start::Genesis(block(0)),
            mailbox_size: NZUsize!(32),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(8),
            block_codec_config: (),
            partition_prefix: "inline-test".into(),
            prunable_items_per_section: NZU64!(16),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache,
            strategy: Sequential,
        },
    )
    .await;
    let durability = config
        .inline_durability
        .then(|| Durability::new(marshal.clone()));
    let (sender, receiver) = mailbox::new(context.child("application"), NZUsize!(32));
    let mailbox = Mailbox::from_sender(sender, durability);
    let (requests, handler) = handler::init(context.child("resolver"), NZUsize!(32));
    let buffer = RecordingBuffer::default();
    let actor = actor.start(
        mailbox.clone(),
        buffer.clone(),
        (requests, LocalResolver { _handler: handler }),
    );
    Harness {
        mailbox,
        receiver,
        marshal,
        actor,
        buffer,
    }
}

async fn run_certify(harness: &mut Harness) {
    let Message::Certify(request) = harness.receiver.recv().await.unwrap() else {
        panic!("expected certification");
    };
    harness
        .mailbox
        .durability
        .as_ref()
        .unwrap()
        .certify(request.round, request.payload, request.response)
        .await;
}

#[test]
fn enabled_proposal_relay_certification_is_durable_after_restart() {
    let (digest, checkpoint) = deterministic::Runner::timed(Duration::from_secs(30))
        .start_and_recover(|context| async move {
            let mut harness = setup(context.child("first"), true).await;
            // Keep an unrelated unsynced write as a negative recovery control.
            let (unsynced, _) = context
                .open("inline-unsynced-control", b"blob")
                .await
                .unwrap();
            unsynced.write_at(0, b"not durable").await.unwrap();
            let candidate = block(1);
            let digest = candidate.digest();
            let durability = harness.mailbox.durability.clone().unwrap();
            let (tx, rx) = oneshot::channel();
            let _stage = context.spawn(move |_| async move {
                durability
                    .gates
                    .stage(round(1), digest, Arc::new(candidate), tx, "tempo test")
                    .await;
            });
            assert_eq!(rx.await.unwrap(), digest);
            assert!(harness.marshal.get_verified(round(1)).await.is_none());
            assert!(
                harness
                    .mailbox
                    .broadcast(digest, Plan::Propose { round: round(1) })
                    .accepted()
            );
            let certified = harness.mailbox.certify(round(1), digest).await;
            run_certify(&mut harness).await;
            assert!(certified.await.unwrap());
            assert_eq!(*harness.buffer.0.lock().unwrap(), vec![digest]);
            // Checkpoint immediately after certify: do not await the stage or make
            // another archive request that could hide a premature certification.
            digest
        });
    deterministic::Runner::from(checkpoint).start(|context| async move {
        let (_, length) = context
            .open("inline-unsynced-control", b"blob")
            .await
            .unwrap();
        assert_eq!(length, 0, "the recovery harness must discard unsynced data");
        let mut restarted = setup(context.child("restart"), true).await;
        let recovered = restarted.marshal.get_verified(round(1)).await.unwrap();
        assert_eq!(recovered.digest(), digest);
        assert!(super::durability::recovered_proposal(recovered.clone(), true).is_err());
        assert_eq!(
            super::durability::recovered_proposal(recovered, false)
                .unwrap()
                .digest(),
            digest
        );
        // No in-memory gate survives a restart: certify must fetch the persisted round.
        let certified = restarted.mailbox.certify(round(1), digest).await;
        run_certify(&mut restarted).await;
        assert!(certified.await.unwrap());
        restarted.actor.abort();
    });
}

#[test]
fn passive_reporter_acknowledges_only_its_own_block_dispatch() {
    for enabled in [false, true] {
        deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
            let mut harness = setup(context, enabled).await;
            let (ack, mut waiter) = Exact::handle();
            let execution_ack = ack.clone();
            harness
                .mailbox
                .report(marshal::Update::Block(Arc::new(block(0)), ack));
            assert!(
                futures::poll!(&mut waiter).is_pending(),
                "the passive observer must not release execution's acknowledgement"
            );
            execution_ack.acknowledge();
            assert!(
                waiter.await.is_ok(),
                "dropping the observer's clone would cancel the entire dispatch"
            );
            harness.actor.abort();
        });
    }
}

#[test]
fn disabled_adapter_certifies_immediately_and_keeps_old_relay_path() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let mut harness = setup(context, false).await;
        let digest = Digest(B256::repeat_byte(1));
        assert!(
            harness
                .mailbox
                .certify(round(1), digest)
                .await
                .await
                .unwrap()
        );
        assert!(harness.receiver.try_recv().is_err());
        harness
            .mailbox
            .broadcast(digest, Plan::Propose { round: round(1) });
        assert!(matches!(
            harness.receiver.recv().await.unwrap(),
            Message::Broadcast(_)
        ));
        assert!(harness.buffer.0.lock().unwrap().is_empty());
        harness.actor.abort();
    });
}

fn request_context(view: u64) -> Context<Digest, PublicKey> {
    Context {
        round: round(view),
        parent: (View::zero(), block(0).digest()),
        leader: tempo_primitives::ed25519::PublicKey::from_seed(42).to_inner(),
    }
}

#[test]
fn enabled_verifier_preserves_rejection_and_recovers_cancelled_work() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let mut harness = setup(context, true).await;
        for cancelled in [false, true] {
            let view = if cancelled { 2 } else { 1 };
            let candidate = block(view);
            let digest = candidate.digest();
            // Availability is not a verdict: a cached block must not override live rejection.
            assert!(harness.marshal.verified(round(view), candidate).await);
            let verify = harness.mailbox.verify(request_context(view), digest).await;
            let Message::Verify(request) = harness.receiver.recv().await.unwrap() else {
                panic!("expected verify");
            };
            assert!(
                request.durable.is_some(),
                "enabled ingress must register its gate before dispatch"
            );
            if cancelled {
                drop(verify);
                drop(request);
            } else {
                publish_verification(false, request.response, request.durable.unwrap(), async {
                    panic!("rejected block must not be stored")
                })
                .await;
                assert!(!verify.await.unwrap());
            }
            let certify = harness.mailbox.certify(round(view), digest).await;
            run_certify(&mut harness).await;
            assert_eq!(certify.await.unwrap(), cancelled);
        }
        harness.actor.abort();
    });
}

#[test]
fn cancelled_proposal_and_finalized_tip_release_staged_gates() {
    deterministic::Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let mut harness = setup(context.child("marshal"), true).await;
        let response = harness.mailbox.propose(request_context(1)).await;
        drop(response);
        let Message::Propose(request) = harness.receiver.recv().await.unwrap() else {
            panic!("expected proposal");
        };
        assert!(request.response.is_closed());
        drop(request);
        assert!(harness.marshal.get_verified(round(1)).await.is_none());

        // Proposals can be staged but never relayed when consensus changes view.
        // Every finalized tip must release both registries and their awaiting tasks.
        let durability = harness.mailbox.durability.clone().unwrap();
        let mut tasks = Vec::new();
        for view in 2..34 {
            let candidate = block(view);
            let digest = candidate.digest();
            let (tx, rx) = oneshot::channel();
            tasks.push(context.child("stage").spawn({
                let gates = durability.gates.clone();
                move |_| async move {
                    gates
                        .stage(
                            round(view),
                            digest,
                            Arc::new(candidate),
                            tx,
                            "abandoned proposal",
                        )
                        .await;
                }
            }));
            assert_eq!(rx.await.unwrap(), digest);
        }
        harness.mailbox.report(marshal::Update::Tip(
            round(33),
            Height::new(33),
            block(33).digest(),
        ));
        for task in tasks {
            task.await.unwrap();
        }
        for view in 2..34 {
            assert!(
                durability
                    .gates
                    .take(round(view), block(view).digest())
                    .is_none()
            );
            assert!(
                durability
                    .gates
                    .take_staged(round(view), block(view).digest())
                    .is_none()
            );
            assert!(harness.marshal.get_verified(round(view)).await.is_none());
        }
        harness.actor.abort();
    });
}
