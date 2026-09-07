//! Standalone `tempo/1` actor tests.
//!
//! The tests drive the actor through its transport channels. Stub certificate
//! and peer-control services avoid starting a driver or marshal.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{B256, B512, Bytes};
use commonware_consensus::{
    Reporter as _,
    marshal::Update,
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use parking_lot::Mutex;
use tempo_node::gossip::{self, Frame, PeerControl, PeerEvent, TransportSender};
use tokio::sync::{mpsc, oneshot};

use super::{Certificate, CertificateError, CertificateMailbox, Marshal};
use crate::{
    consensus::Digest,
    follow::test_utils::{EPOCH_LENGTH, make_block},
    test_utils::{DkgFixture, dkg_fixture, make_certificate},
};

const WAIT_ATTEMPTS: usize = 200;

async fn wait_until<T: commonware_runtime::Clock>(context: &T, mut cond: impl FnMut() -> bool) {
    for _ in 0..WAIT_ATTEMPTS {
        if cond() {
            return;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    assert!(cond(), "condition was not met before the test deadline");
}

fn peer(byte: u8) -> B512 {
    B512::with_last_byte(byte)
}

fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

fn metric(context: &impl commonware_runtime::Metrics, name: &str) -> i64 {
    let prefix = format!("{name} ");
    context
        .encode()
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("metric `{name}` was not registered"))
}

/// Records verification requests and returns outcomes chosen by each test.
#[derive(Clone)]
struct StubSink {
    inner: Arc<StubSinkInner>,
}

struct StubSinkInner {
    requests: Mutex<Vec<Round>>,
    answers: Mutex<VecDeque<eyre::Result<(), CertificateError>>>,
    fallback: Mutex<Option<eyre::Result<(), CertificateError>>>,
    /// Requests held open while a test changes other actor state.
    held: Mutex<Vec<oneshot::Sender<eyre::Result<(), CertificateError>>>>,
}

impl StubSink {
    fn new() -> Self {
        Self {
            inner: Arc::new(StubSinkInner {
                requests: Mutex::new(Vec::new()),
                answers: Mutex::new(VecDeque::new()),
                fallback: Mutex::new(None),
                held: Mutex::new(Vec::new()),
            }),
        }
    }

    fn answer(&self, result: eyre::Result<(), CertificateError>) {
        self.inner.answers.lock().push_back(result);
    }

    fn always(&self, result: eyre::Result<(), CertificateError>) {
        *self.inner.fallback.lock() = Some(result);
    }

    fn requests(&self) -> Vec<Round> {
        self.inner.requests.lock().clone()
    }

    fn release(&self, result: eyre::Result<(), CertificateError>) {
        let sender = self
            .inner
            .held
            .lock()
            .pop()
            .expect("a request should be awaiting a judgement");
        let _ = sender.send(result);
    }
}

impl CertificateMailbox for StubSink {
    fn process_certificate(
        &self,
        certificate: Certificate,
    ) -> oneshot::Receiver<eyre::Result<(), CertificateError>> {
        let (sender, receiver) = oneshot::channel();
        self.inner.requests.lock().push(certificate.round());

        let answer = self
            .inner
            .answers
            .lock()
            .pop_front()
            .or_else(|| *self.inner.fallback.lock());
        match answer {
            Some(answer) => {
                let _ = sender.send(answer);
            }
            // Keep it open so a test can answer once it has done something else.
            None => self.inner.held.lock().push(sender),
        }

        receiver
    }
}

#[derive(Clone, Default)]
struct StubMarshal {
    finalizations: Arc<Mutex<HashMap<u64, Certificate>>>,
}

impl StubMarshal {
    fn insert(&self, height: Height, certificate: Certificate) {
        self.finalizations.lock().insert(height.get(), certificate);
    }
}

impl Marshal for StubMarshal {
    async fn get_finalization(&self, height: Height) -> Option<Certificate> {
        self.finalizations.lock().get(&height.get()).cloned()
    }
}

#[derive(Clone, Default)]
struct StubPeerControl {
    penalized: Arc<Mutex<Vec<B512>>>,
}

impl StubPeerControl {
    fn penalized(&self) -> Vec<B512> {
        self.penalized.lock().clone()
    }
}

impl PeerControl for StubPeerControl {
    fn penalize(&self, peer: B512) {
        self.penalized.lock().push(peer);
    }
}

struct Rig {
    control: mpsc::UnboundedSender<PeerEvent>,
    frames: mpsc::Sender<Frame>,
    mailbox: super::Mailbox,
    marshal: StubMarshal,
    sink: StubSink,
    peer_control: StubPeerControl,
    routes: Arc<Mutex<HashMap<B512, mpsc::Sender<Bytes>>>>,
    outbound: HashMap<B512, mpsc::Receiver<Bytes>>,
    seen: HashMap<B512, Vec<Bytes>>,
    fixture: DkgFixture,
}

impl Rig {
    fn connect(&mut self, peer: B512) {
        let (outbound, receiver) = mpsc::channel(8);
        self.routes.lock().insert(peer, outbound);
        self.outbound.insert(peer, receiver);
        self.control
            .send(PeerEvent::Up(peer))
            .expect("actor is running");
    }

    fn disconnect(&self, peer: B512) {
        self.routes.lock().remove(&peer);
        self.control
            .send(PeerEvent::Down(peer))
            .expect("actor is running");
    }

    fn exit_epoch(&mut self, epoch: Epoch) {
        let boundary = FixedEpocher::new(EPOCH_LENGTH)
            .last(epoch)
            .expect("fixed epoch strategy supports every epoch");
        let (acknowledgement, _acknowledged) = Exact::handle();
        let _ = self.mailbox.report(Update::Block(
            make_block(boundary.get(), None).into(),
            acknowledgement,
        ));
    }

    /// Builds a frame carrying a real certificate over a synthetic block.
    fn frame(&self, view: u64) -> Bytes {
        gossip::wire::encode(&self.certificate(view))
            .freeze()
            .into()
    }

    fn certificate(&self, view: u64) -> Certificate {
        make_certificate(
            Digest(B256::with_last_byte(view as u8)),
            Epoch::zero(),
            view,
            &self.fixture.schemes,
        )
    }

    fn publish(&mut self, view: u64) {
        self.tip(view);
    }

    fn tip(&mut self, view: u64) {
        let height = Height::new(view);
        self.marshal.insert(height, self.certificate(view));
        let _ = self.mailbox.report(Update::Tip(
            round(view),
            height,
            Digest(B256::with_last_byte(view as u8)),
        ));
    }

    async fn send(&self, peer: B512, frame: Bytes) {
        self.frames
            .send(Frame { peer, frame })
            .await
            .expect("actor is running");
    }

    /// Returns all frames relayed to a peer so far.
    ///
    /// Results are kept after each read so a wait loop cannot consume frames
    /// before an assertion checks them.
    fn relayed(&mut self, peer: B512) -> Vec<Bytes> {
        let receiver = self.outbound.get_mut(&peer).expect("connected peer");
        let seen = self.seen.entry(peer).or_default();
        while let Ok(frame) = receiver.try_recv() {
            seen.push(frame);
        }
        seen.clone()
    }
}

/// A rate high enough that tests do not reach the verify limit.
const UNLIMITED_VERIFY_RATE: NonZeroU32 = NonZeroU32::new(1_000).expect("test rate is non-zero");

fn start(context: &mut deterministic::Context) -> Rig {
    start_with(context, UNLIMITED_VERIFY_RATE)
}

fn start_with_verify_rate(context: &mut deterministic::Context, verify_rate: u32) -> Rig {
    start_with(
        context,
        NonZeroU32::new(verify_rate).expect("test rate is non-zero"),
    )
}

fn start_with(context: &mut deterministic::Context, verify_rate: NonZeroU32) -> Rig {
    let fixture = dkg_fixture(context, Epoch::zero());

    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (frames_tx, frames_rx) = mpsc::channel(64);
    let routes = Arc::new(Mutex::new(HashMap::<B512, mpsc::Sender<Bytes>>::new()));
    let sender = TransportSender::new({
        let routes = Arc::clone(&routes);
        move |peer, frame| {
            let Some(outbound) = routes.lock().get(&peer).cloned() else {
                return Err(mpsc::error::TrySendError::Closed(frame));
            };
            outbound.try_send(frame)
        }
    });
    let transport = gossip::TransportHandle {
        control: control_rx,
        frames: frames_rx,
        sender,
    };

    let sink = StubSink::new();
    let marshal = StubMarshal::default();
    let peer_control = StubPeerControl::default();
    let (actor, mailbox) = super::init(
        context.child("gossip"),
        super::actor::Config {
            verify_rate,
            transport,
            epoch_strategy: FixedEpocher::new(EPOCH_LENGTH),
            finalized_floor: Height::zero(),
            peer_control: peer_control.clone(),
            driver: sink.clone(),
            marshal: marshal.clone(),
        },
    );
    actor.start();

    Rig {
        control: control_tx,
        frames: frames_tx,
        mailbox,
        marshal,
        sink,
        peer_control,
        routes,
        outbound: HashMap::new(),
        seen: HashMap::new(),
        fixture,
    }
}

/// Peers negotiate only the protocol version. The envelope and certificate
/// layout must therefore stay readable for the lifetime of `tempo/1`.
#[test]
fn full_frame_layout_is_frozen() {
    let frame = alloy_primitives::hex::decode(
        "000001000000000000000000000000000000000000000000000000000000000000000001893a6fba4f0630edd4f1f610258f9b3a1e1fbf9c1abefaea77a62bfd27b0dea1d448c4b4b992fa094bf96c8789b49cfa8565f0bc98152e274fd6d0e3b85955736432cdca1a52201ff244bf69a65b566ffbcf642a53a23e66b4d9bd6819dd95cc",
    )
    .expect("golden frame is valid hex");
    let certificate: Certificate =
        gossip::wire::decode(&frame).expect("golden finalization frame still decodes");

    assert_eq!(certificate.round(), round(1));
    assert_eq!(
        gossip::wire::encode(&certificate).as_ref(),
        frame.as_slice(),
    );
}

/// The actor must verify a claimed round before it can trust it. A peer may
/// claim a very high round, but that must not block certificates from other peers.
#[test_traced]
fn scheduling_is_fair_across_peers() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));
        rig.connect(peer(2));

        // One peer claims a much higher round than the other.
        let liar = rig.frame(1_000_000);
        let honest = rig.frame(5);
        rig.send(peer(1), liar).await;
        rig.send(peer(2), honest).await;

        wait_until(&context, || rig.sink.requests().len() >= 2).await;

        let mut requested = rig.sink.requests();
        requested.sort_unstable();
        assert_eq!(requested, [round(5), round(1_000_000)]);
    });
}

/// Rate-limit misses and attacker-controlled slot churn must not move later
/// arrivals ahead of a peer that is already waiting for verification.
#[test_traced]
fn rate_limited_churn_preserves_admission_order() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.connect(peer(3));

        // Spend the initial burst so the remaining slots accumulate behind the
        // same rate-limit deadline.
        rig.send(peer(3), rig.frame(1)).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;

        rig.send(peer(1), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_slots") == 1).await;
        rig.send(peer(2), rig.frame(20)).await;
        wait_until(&context, || metric(&context, "gossip_slots") == 2).await;

        rig.send(peer(1), rig.frame(11)).await;
        context.sleep(Duration::from_millis(10)).await;

        for view in 21..=23 {
            rig.disconnect(peer(2));
            wait_until(&context, || metric(&context, "gossip_slots") == 1).await;
            rig.connect(peer(2));
            rig.send(peer(2), rig.frame(view)).await;
            wait_until(&context, || metric(&context, "gossip_slots") == 2).await;
        }

        assert_eq!(rig.sink.requests(), vec![round(1)]);
        assert_eq!(
            metric(&context, "gossip_shed_total"),
            1,
            "frames do not retry dispatch before the budget wakeup",
        );

        context.sleep(Duration::from_secs(2)).await;
        wait_until(&context, || rig.sink.requests().len() >= 2).await;
        assert_eq!(rig.sink.requests()[1], round(11));
    });
}

/// A terminal outcome applies to the exact frame bytes and settles every copy.
/// A key based on the block would let a forged certificate suppress a valid
/// certificate for the same block.
#[test_traced]
fn terminal_outcome_settles_frame_for_every_peer() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        // Hold the first judgment open so both peers retain the same frame in
        // their own slots.
        let shared = rig.frame(7);
        rig.send(peer(1), shared.clone()).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;
        rig.send(peer(2), shared).await;
        wait_until(&context, || metric(&context, "gossip_slots") == 2).await;

        rig.sink.release(Err(CertificateError::Invalid));
        wait_until(&context, || rig.peer_control.penalized().len() == 2).await;

        assert_eq!(
            rig.sink.requests().len(),
            1,
            "the same bytes are only judged once",
        );
        let mut penalized = rig.peer_control.penalized();
        penalized.sort_unstable();
        assert_eq!(penalized, vec![peer(1), peer(2)]);
        assert_eq!(metric(&context, "gossip_slots"), 0);
    });
}

/// A live peer can only advance its claimed round. Replaying the same round or
/// an older one does not consume another driver judgment.
#[test_traced]
fn inbound_rounds_are_strictly_increasing_per_peer() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));

        rig.send(peer(1), rig.frame(10)).await;
        wait_until(&context, || rig.peer_control.penalized().len() == 1).await;
        rig.send(peer(1), rig.frame(10)).await;
        rig.send(peer(1), rig.frame(9)).await;
        wait_until(&context, || {
            metric(&context, "gossip_dropped_replay_total") == 2
        })
        .await;

        assert_eq!(rig.sink.requests(), vec![round(10)]);

        rig.send(peer(1), rig.frame(11)).await;
        wait_until(&context, || rig.sink.requests().len() == 2).await;
        assert_eq!(rig.sink.requests(), vec![round(10), round(11)]);
    });
}

/// A certificate settled by the driver is not propagated until marshal reports
/// that its block and certificate are durable.
#[test_traced]
fn settled_certificate_is_not_optimistically_relayed() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Ok(()));

        let frame = rig.frame(9);
        rig.send(peer(1), frame).await;
        wait_until(&context, || !rig.sink.requests().is_empty()).await;
        context.sleep(Duration::from_millis(10)).await;

        assert!(rig.relayed(peer(1)).is_empty());
        assert!(rig.relayed(peer(2)).is_empty());
    });
}

/// Frames received after the transport reports its logical peer down are ignored.
#[test_traced]
fn disconnected_peer_is_ignored() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));
        rig.disconnect(peer(1));

        let disconnected = rig.frame(3);
        rig.send(peer(1), disconnected).await;
        context.sleep(Duration::from_millis(30)).await;
        assert!(
            rig.sink.requests().is_empty(),
            "a frame from the disconnected peer is ignored",
        );

        rig.connect(peer(1));
        let current = rig.frame(4);
        rig.send(peer(1), current).await;
        wait_until(&context, || !rig.sink.requests().is_empty()).await;
    });
}

/// Quarantine is sticky until marshal processes the required boundary. Time
/// and replacement offers cannot cause another verification or peer penalty.
#[test_traced]
fn certificate_awaiting_scheme_is_held_without_retrying() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));
        rig.sink.always(Err(CertificateError::Invalid));

        let frame = rig.frame(11);
        rig.send(peer(1), frame).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.send(peer(1), rig.frame(12)).await;
        rig.send(peer(1), rig.frame(13)).await;
        wait_until(&context, || {
            metric(&context, "gossip_dropped_locked_replacement_total") == 2
        })
        .await;

        context.sleep(Duration::from_secs(3)).await;
        assert_eq!(rig.sink.requests().len(), 1, "no retry loop");
        assert!(
            rig.peer_control.penalized().is_empty(),
            "this is not the sender's fault",
        );

        // A scheme for an earlier epoch cannot verify it, so it stays held.
        rig.exit_epoch(Epoch::new(2));
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(rig.sink.requests().len(), 1, "still held");
        assert_eq!(metric(&context, "gossip_quarantined"), 1);

        // The scheme it was waiting for releases it.
        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || rig.sink.requests().len() == 2).await;
        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;
        assert_eq!(rig.peer_control.penalized(), vec![peer(1)]);
        assert_eq!(metric(&context, "gossip_quarantined"), 0);
    });
}

/// A boundary block may race with an in-flight driver judgement. Retaining the
/// processed epoch ensures an earlier update is not lost.
#[test_traced]
fn boundary_processed_during_judgement_is_not_missed() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        rig.send(peer(1), rig.frame(11)).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;

        rig.exit_epoch(Epoch::new(3));
        rig.sink.answer(Err(CertificateError::Invalid));
        rig.sink.release(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        wait_until(&context, || rig.sink.requests().len() == 2).await;
        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;
        assert_eq!(rig.peer_control.penalized(), vec![peer(1)]);
        assert_eq!(metric(&context, "gossip_quarantined"), 0);
    });
}

/// Every certificate that fails an installed scheme is reported to reth.
#[test_traced]
fn repeated_invalid_certificates_are_penalized() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));

        let first = rig.frame(21);
        rig.send(peer(1), first).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;

        let second = rig.frame(22);
        rig.send(peer(1), second).await;
        wait_until(&context, || rig.peer_control.penalized().len() == 2).await;

        assert_eq!(rig.peer_control.penalized().len(), 2);
    });
}

/// A malformed frame never reaches the driver, and its sender is penalized.
#[test_traced]
fn malformed_frames_are_penalized_without_reaching_the_driver() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        rig.send(peer(1), Bytes::from_static(&[0x00, 0xff])).await;
        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;

        assert!(rig.sink.requests().is_empty());
    });
}

/// Slot locking applies only after decoding. A quarantined peer cannot hide
/// malformed protocol data behind its existing certificate.
#[test_traced]
fn malformed_frame_from_a_quarantined_peer_is_penalized() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        rig.send(peer(1), rig.frame(11)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.send(peer(1), Bytes::from_static(&[0x00, 0xff])).await;
        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;

        assert_eq!(rig.sink.requests(), vec![round(11)]);
        assert_eq!(metric(&context, "gossip_quarantined"), 1);
    });
}

/// Once judgment begins, a higher-round offer cannot replace the attributed
/// frame or become a second verification request.
#[test_traced]
fn higher_round_cannot_replace_a_slot_being_judged() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        // Hold the judgment open while the peer offers a replacement.
        let verified = rig.frame(70);
        let replacement = rig.frame(71);
        rig.send(peer(1), verified.clone()).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;
        rig.send(peer(1), replacement.clone()).await;
        wait_until(&context, || {
            metric(&context, "gossip_dropped_locked_replacement_total") == 1
        })
        .await;

        rig.sink.release(Ok(()));

        context.sleep(Duration::from_millis(10)).await;
        assert!(rig.relayed(peer(2)).is_empty());
        assert_eq!(rig.sink.requests(), vec![round(70)]);
    });
}

/// A rate-limited slot has not consumed verification work, so the peer may
/// still replace it with a more useful certificate.
#[test_traced]
fn higher_round_replaces_a_ready_slot() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));

        rig.send(peer(1), rig.frame(90)).await;
        wait_until(&context, || rig.peer_control.penalized().len() == 1).await;

        rig.send(peer(1), rig.frame(91)).await;
        context.sleep(Duration::from_millis(100)).await;
        rig.send(peer(1), rig.frame(92)).await;
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(rig.sink.requests(), vec![round(90)]);

        context.sleep(Duration::from_secs(2)).await;
        assert_eq!(rig.sink.requests(), vec![round(90), round(92)]);
    });
}

/// Once the latest verified round passes a quarantined certificate, processing
/// its boundary only removes it. The actor does not spend another verification
/// to rediscover that it is stale.
#[test_traced]
fn stale_quarantine_is_pruned_without_reverification() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        rig.send(peer(1), rig.frame(11)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.tip(11);
        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;

        assert_eq!(rig.sink.requests(), vec![round(11)]);
        assert!(rig.peer_control.penalized().is_empty());
    });
}

/// A relevant boundary releases a live certificate through the
/// normal admission path. A durable marshal tip can publish and prune it while
/// its judgment is pending.
#[test_traced]
fn durable_tip_supersedes_pending_quarantine_retry() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        let frame = rig.frame(11);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || rig.sink.requests().len() == 2).await;
        rig.tip(11);
        rig.sink.release(Ok(()));

        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(2)), vec![frame]);
        assert!(rig.relayed(peer(1)).is_empty());
        assert_eq!(metric(&context, "gossip_latest_verified_view"), 11);
        assert!(rig.peer_control.penalized().is_empty());
        assert_eq!(metric(&context, "gossip_quarantined"), 0);
    });
}

/// Progress from the first useful retry settles lower quarantines before their
/// boundaries are processed, avoiding retrospective verification work.
#[test_traced]
fn successful_retry_prunes_lower_quarantines() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(5),
        }));
        rig.send(peer(1), rig.frame(9)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));
        rig.send(peer(2), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;

        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || rig.sink.requests().len() == 3).await;
        rig.sink.release(Ok(()));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;

        rig.exit_epoch(Epoch::new(4));
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(rig.sink.requests(), vec![round(9), round(10), round(10)],);
    });
}

/// If a live retry fails the newly installed scheme, only the source of that
/// retry is penalized. Other quarantined peers are not reverified for blame.
#[test_traced]
fn failed_retry_penalizes_only_its_source() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));
        rig.send(peer(1), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(5),
        }));
        rig.send(peer(2), rig.frame(20)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;

        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || rig.sink.requests().len() == 3).await;
        rig.sink.release(Err(CertificateError::Invalid));
        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;

        assert_eq!(rig.peer_control.penalized(), vec![peer(1)]);
        assert_eq!(metric(&context, "gossip_quarantined"), 1);
        assert_eq!(rig.sink.requests().len(), 3);
    });
}

/// Quarantine belongs to a live logical connection. Disconnect drops it, and
/// reconnecting the same peer starts with an empty slot.
#[test_traced]
fn disconnect_discards_quarantine() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        let frame = rig.frame(11);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.disconnect(peer(1));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;
        rig.exit_epoch(Epoch::new(3));
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(rig.sink.requests().len(), 1);

        rig.connect(peer(1));
        rig.sink.answer(Err(CertificateError::Invalid));
        rig.send(peer(1), frame).await;
        wait_until(&context, || rig.sink.requests().len() == 2).await;
    });
}

/// Released quarantines re-enter the same global rate limiter as fresh
/// candidates; processing a boundary cannot trigger a verification burst.
#[test_traced]
fn released_quarantines_share_the_global_verify_limit() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));

        rig.send(peer(1), rig.frame(11)).await;
        rig.send(peer(2), rig.frame(12)).await;
        context.sleep(Duration::from_secs(2)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;
        assert_eq!(rig.sink.requests().len(), 2);

        rig.sink.always(Err(CertificateError::Invalid));
        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || rig.sink.requests().len() == 3).await;
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            rig.sink.requests().len(),
            3,
            "only one retry used the burst"
        );

        context.sleep(Duration::from_secs(2)).await;
        assert_eq!(rig.sink.requests().len(), 4);
    });
}

/// A quarantine has already consumed a turn. When it becomes ready again, it
/// must wait behind a slot that remained ready while the scheme was unavailable.
#[test_traced]
fn released_quarantine_rejoins_behind_ready_slot() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.sink.answer(Err(CertificateError::NeedsScheme {
            epoch: Epoch::new(4),
        }));
        rig.sink.always(Err(CertificateError::Invalid));

        rig.send(peer(1), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.send(peer(2), rig.frame(20)).await;
        wait_until(&context, || metric(&context, "gossip_slots") == 2).await;
        rig.exit_epoch(Epoch::new(3));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;

        assert_eq!(rig.sink.requests(), vec![round(10)]);

        context.sleep(Duration::from_secs(2)).await;
        wait_until(&context, || rig.sink.requests().len() >= 2).await;
        assert_eq!(rig.sink.requests()[1], round(20));
    });
}

/// A rate-limited candidate stays in its slot. The actor must schedule its own
/// wakeup because no other message is guaranteed to arrive.
#[test_traced]
fn shed_candidate_is_retried_when_budget_replenishes() {
    deterministic::Runner::default().start(|mut context| async move {
        // One judgement per second, and the first frame consumes the burst.
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.sink.always(Err(CertificateError::Invalid));
        rig.connect(peer(1));

        let first = rig.frame(90);
        rig.send(peer(1), first).await;
        wait_until(&context, || rig.sink.requests().len() == 1).await;

        // The second is rate limited, and no new message wakes the loop.
        let second = rig.frame(91);
        rig.send(peer(1), second).await;
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            rig.sink.requests().len(),
            1,
            "shed while the budget is spent"
        );

        // Only the actor's own wake-up can pick it back up.
        context.sleep(Duration::from_secs(2)).await;
        assert_eq!(
            rig.sink.requests().len(),
            2,
            "the shed candidate was retried once the budget replenished",
        );
    });
}

/// A settled certificate is propagated once marshal reports its durable tip.
#[test_traced]
fn settled_certificate_is_published_after_tip() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Ok(()));

        let frame = rig.frame(50);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || !rig.sink.requests().is_empty()).await;
        assert!(rig.relayed(peer(2)).is_empty());

        rig.publish(50);
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(2)), vec![frame]);
        assert!(rig.relayed(peer(1)).is_empty());
    });
}

/// Local publication must not wait behind unauthenticated traffic. Sending the
/// same frame on both paths shows the order: publication records it before the
/// peer copy can consume verification work.
#[test_traced]
fn local_publication_takes_priority_over_peer_traffic() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));
        context.sleep(Duration::from_millis(1)).await;

        let frame = rig.frame(51);
        rig.frames
            .try_send(Frame {
                peer: peer(1),
                frame: frame.clone(),
            })
            .expect("frame queue has capacity");
        rig.publish(51);

        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert!(
            rig.sink.requests().is_empty(),
            "the peer copy must not get ahead of local publication",
        );
    });
}

/// A settled peer certificate waits for durable publication, which still skips
/// a peer that claimed a newer round.
#[test_traced]
fn durable_publication_skips_peer_with_newer_claim() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Ok(()));
        let claimed = rig.frame(63);
        rig.send(peer(1), claimed).await;

        wait_until(&context, || !rig.sink.requests().is_empty()).await;
        context.sleep(Duration::from_millis(10)).await;
        assert!(
            rig.relayed(peer(2)).is_empty(),
            "a settled frame must wait for durable publication",
        );

        let published = rig.frame(62);
        rig.publish(62);
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(2)), vec![published]);
        assert!(
            rig.relayed(peer(1)).is_empty(),
            "the source peer already claimed a newer round",
        );
    });
}

/// A stored certificate is offered to each peer that has not claimed the same
/// round or a later one.
#[test_traced]
fn publishing_an_unseen_frame_reaches_every_peer() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        let frame = rig.frame(60);
        rig.publish(60);

        wait_until(&context, || !rig.relayed(peer(1)).is_empty()).await;
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(1)), vec![frame.clone()]);
        assert_eq!(rig.relayed(peer(2)), vec![frame]);
    });
}

/// A publication remains useful after its first send. A peer that connects
/// later receives the newest certificate with a locally stored block.
#[test_traced]
fn new_peer_receives_latest_publication() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        rig.publish(63);
        wait_until(&context, || !rig.relayed(peer(1)).is_empty()).await;

        let latest = rig.frame(64);
        rig.publish(64);
        wait_until(&context, || rig.relayed(peer(1)).len() == 2).await;

        rig.connect(peer(2));
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(2)), vec![latest]);
    });
}

/// A full outbound queue does not mark the peer as having seen a publication.
/// Publishing the same stored certificate again retries that peer.
#[test_traced]
fn failed_publication_can_be_retried() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        for view in 1..=8 {
            rig.publish(view);
        }
        let latest = rig.frame(9);
        rig.publish(9);

        context.sleep(Duration::from_millis(20)).await;
        assert_eq!(rig.relayed(peer(1)).len(), 8, "the queue filled");

        rig.publish(9);
        wait_until(&context, || rig.relayed(peer(1)).len() == 9).await;
        assert_eq!(rig.relayed(peer(1)).last(), Some(&latest));
    });
}
