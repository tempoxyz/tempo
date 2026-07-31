//! Standalone `tempo/1` actor tests.
//!
//! The tests drive the actor through its transport channels. Stub certificate
//! and peer-control services avoid starting a driver, marshal, or scheme
//! provider.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{B256, B512, Bytes};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic};
use parking_lot::Mutex;
use tempo_node::gossip::{self, Frame, PeerControl, PeerEvent, TransportSender};
use tokio::sync::{mpsc, oneshot};

use super::{CertSink, Certificate, Outcome};
use crate::{
    consensus::Digest,
    follow::FollowerProgress,
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
    answers: Mutex<VecDeque<Outcome>>,
    fallback: Mutex<Option<Outcome>>,
    /// Requests held open while a test changes other actor state.
    held: Mutex<Vec<oneshot::Sender<Outcome>>>,
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

    fn answer(&self, outcome: Outcome) {
        self.inner.answers.lock().push_back(outcome);
    }

    fn always(&self, outcome: Outcome) {
        *self.inner.fallback.lock() = Some(outcome);
    }

    fn requests(&self) -> Vec<Round> {
        self.inner.requests.lock().clone()
    }

    fn release(&self, outcome: Outcome) {
        let sender = self
            .inner
            .held
            .lock()
            .pop()
            .expect("a request should be awaiting a judgement");
        let _ = sender.send(outcome);
    }
}

impl CertSink for StubSink {
    fn verify_and_apply(&self, certificate: Certificate) -> oneshot::Receiver<Outcome> {
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
    sink: StubSink,
    peer_control: StubPeerControl,
    progress: FollowerProgress,
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

    /// Builds a frame carrying a real certificate over a synthetic block.
    fn frame(&self, view: u64) -> Bytes {
        let certificate = make_certificate(
            Digest(B256::with_last_byte(view as u8)),
            Epoch::zero(),
            view,
            &self.fixture.schemes,
        );
        gossip::wire::encode(&certificate.encode()).freeze().into()
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
const UNLIMITED_VERIFY_RATE: u32 = 1_000;

fn start(context: &mut deterministic::Context) -> Rig {
    start_with(context, UNLIMITED_VERIFY_RATE, true)
}

fn start_with_verify_rate(context: &mut deterministic::Context, verify_rate: u32) -> Rig {
    start_with(context, verify_rate, true)
}

fn start_without_forwarding(context: &mut deterministic::Context) -> Rig {
    start_with(context, UNLIMITED_VERIFY_RATE, false)
}

fn start_with(context: &mut deterministic::Context, verify_rate: u32, relay: bool) -> Rig {
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
    let peer_control = StubPeerControl::default();
    let progress = FollowerProgress::new();
    let (mailbox, receiver) = super::channel();
    let actor = super::init(
        context.child("gossip"),
        super::ActorConfig {
            verify_rate,
            recent_frames: 64,
            relay,
            transport,
            mailbox: receiver,
            peer_control: Arc::new(peer_control.clone()),
            sink: sink.clone(),
            progress: Some(progress.clone()),
        },
    );
    actor.start();

    Rig {
        control: control_tx,
        frames: frames_tx,
        mailbox,
        sink,
        peer_control,
        progress,
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
    let payload = gossip::wire::decode(&frame).expect("golden frame uses the tempo/1 envelope");
    let certificate = Certificate::decode(payload).expect("golden certificate still decodes");

    assert_eq!(certificate.round(), round(1));
    assert_eq!(
        gossip::wire::encode(&certificate.encode()).as_ref(),
        frame.as_slice(),
    );
}

/// The actor must verify a claimed round before it can trust it. A peer may
/// claim a very high round, but that must not block certificates from other peers.
#[test_traced]
fn scheduling_is_fair_across_peers() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Outcome::Invalid);
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

/// A terminal outcome applies to the exact frame bytes and settles every copy.
/// A key based on the block would let a forged certificate suppress a valid
/// certificate for the same block.
#[test_traced]
fn terminal_outcome_settles_frame_for_every_peer() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Outcome::Invalid);
        rig.connect(peer(1));
        rig.connect(peer(2));

        // Both peers relay the very same certificate.
        let shared = rig.frame(7);
        rig.send(peer(1), shared.clone()).await;
        rig.send(peer(2), shared).await;

        wait_until(&context, || !rig.sink.requests().is_empty()).await;
        context.sleep(Duration::from_millis(30)).await;

        assert_eq!(
            rig.sink.requests().len(),
            1,
            "the same bytes are only judged once",
        );
        assert_eq!(
            rig.peer_control.penalized().len(),
            1,
            "only the judged source is penalized",
        );
    });
}

/// Relaying lets a follower learn the tip when its upstream is unavailable. The
/// source peer does not need the certificate back.
#[test_traced]
fn admitted_certificate_is_relayed_excluding_its_source() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Outcome::Admitted);

        let frame = rig.frame(9);
        rig.send(peer(1), frame).await;
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;

        assert!(
            rig.relayed(peer(1)).is_empty(),
            "the sender does not need it back",
        );
    });
}

/// Frames received after the transport reports its logical peer down are ignored.
#[test_traced]
fn disconnected_peer_is_ignored() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.sink.always(Outcome::Invalid);
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

/// Quarantine is sticky until a relevant authenticated boundary arrives. Time
/// and replacement offers cannot cause another verification or peer penalty.
#[test_traced]
fn certificate_awaiting_scheme_is_held_without_retrying() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });
        rig.sink.always(Outcome::Invalid);

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
        rig.progress.boundary_scheme_installed(Epoch::new(3));
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(rig.sink.requests().len(), 1, "still held");
        assert_eq!(metric(&context, "gossip_quarantined"), 1);

        // The scheme it was waiting for releases it.
        rig.progress.boundary_scheme_installed(Epoch::new(4));
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
        rig.sink.always(Outcome::Invalid);
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

/// A transport-level protocol breach penalizes the logical peer before its
/// connections are reported down.
#[test_traced]
fn protocol_breaches_are_penalized() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.control
            .send(PeerEvent::ProtocolBreach(peer(1)))
            .expect("actor is running");
        rig.disconnect(peer(1));

        wait_until(&context, || !rig.peer_control.penalized().is_empty()).await;

        assert_eq!(rig.peer_control.penalized(), vec![peer(1)]);
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
        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });

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

        rig.sink.release(Outcome::Admitted);

        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        let relayed = rig.relayed(peer(2));
        assert_eq!(
            relayed,
            vec![verified],
            "only the judged bytes may be relayed",
        );
        assert!(!relayed.contains(&replacement));
        assert_eq!(rig.sink.requests(), vec![round(70)]);
    });
}

/// A rate-limited slot has not consumed verification work, so the peer may
/// still replace it with a more useful certificate.
#[test_traced]
fn higher_round_replaces_a_ready_slot() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.sink.always(Outcome::Invalid);
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

/// Once the watermark passes a quarantined certificate, a boundary event only
/// removes it. The actor does not spend another verification to rediscover that
/// it is stale.
#[test_traced]
fn stale_quarantine_is_pruned_without_reverification() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });

        rig.send(peer(1), rig.frame(11)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.progress.advance(round(11));
        rig.progress.boundary_scheme_installed(Epoch::new(4));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;

        assert_eq!(rig.sink.requests(), vec![round(11)]);
        assert!(rig.peer_control.penalized().is_empty());
    });
}

/// A relevant boundary releases a live certificate through the normal
/// admission path. The real driver advances progress before returning
/// `Admitted`, which the stub mirrors before completing its held response.
#[test_traced]
fn successful_quarantine_retry_is_relayed() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });

        let frame = rig.frame(11);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.progress.boundary_scheme_installed(Epoch::new(4));
        wait_until(&context, || rig.sink.requests().len() == 2).await;
        rig.progress.advance(round(11));
        rig.sink.release(Outcome::Admitted);

        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert_eq!(rig.relayed(peer(2)), vec![frame]);
        assert!(rig.relayed(peer(1)).is_empty());
        assert_eq!(rig.progress.watermark(), round(11));
        assert!(rig.peer_control.penalized().is_empty());
        assert_eq!(metric(&context, "gossip_quarantined"), 0);
    });
}

/// Progress from the first useful retry settles lower quarantines before their
/// schemes arrive, avoiding retrospective verification work.
#[test_traced]
fn successful_retry_prunes_lower_quarantines() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(5),
        });
        rig.send(peer(1), rig.frame(9)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });
        rig.send(peer(2), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;

        rig.progress.boundary_scheme_installed(Epoch::new(4));
        wait_until(&context, || rig.sink.requests().len() == 3).await;
        rig.progress.advance(round(10));
        rig.sink.release(Outcome::Admitted);
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;

        rig.progress.boundary_scheme_installed(Epoch::new(5));
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

        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });
        rig.send(peer(1), rig.frame(10)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(5),
        });
        rig.send(peer(2), rig.frame(20)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;

        rig.progress.boundary_scheme_installed(Epoch::new(4));
        wait_until(&context, || rig.sink.requests().len() == 3).await;
        rig.sink.release(Outcome::Invalid);
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
        rig.sink.answer(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });

        let frame = rig.frame(11);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 1).await;

        rig.disconnect(peer(1));
        wait_until(&context, || metric(&context, "gossip_quarantined") == 0).await;
        rig.progress.boundary_scheme_installed(Epoch::new(4));
        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(rig.sink.requests().len(), 1);

        rig.connect(peer(1));
        rig.sink.answer(Outcome::Invalid);
        rig.send(peer(1), frame).await;
        wait_until(&context, || rig.sink.requests().len() == 2).await;
    });
}

/// Released quarantines re-enter the same global rate limiter as fresh
/// candidates; a boundary event cannot trigger a verification burst.
#[test_traced]
fn released_quarantines_share_the_global_verify_limit() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.connect(peer(1));
        rig.connect(peer(2));
        rig.sink.always(Outcome::NeedsScheme {
            epoch: Epoch::new(4),
        });

        rig.send(peer(1), rig.frame(11)).await;
        rig.send(peer(2), rig.frame(12)).await;
        context.sleep(Duration::from_secs(2)).await;
        wait_until(&context, || metric(&context, "gossip_quarantined") == 2).await;
        assert_eq!(rig.sink.requests().len(), 2);

        rig.progress.boundary_scheme_installed(Epoch::new(4));
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

/// A rate-limited candidate stays in its slot. The actor must schedule its own
/// wakeup because no other message is guaranteed to arrive.
#[test_traced]
fn shed_candidate_is_retried_when_budget_replenishes() {
    deterministic::Runner::default().start(|mut context| async move {
        // One judgement per second, and the first frame consumes the burst.
        let mut rig = start_with_verify_rate(&mut context, 1);
        rig.sink.always(Outcome::Invalid);
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

/// A certificate the node already relayed on the way in is not sent a second
/// time when its block later lands and the feed offers it again.
#[test_traced]
fn publishing_a_frame_already_relayed_is_suppressed() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Outcome::Admitted);

        let frame = rig.frame(50);
        rig.send(peer(1), frame.clone()).await;
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        let after_ingest = rig.relayed(peer(2)).len();

        rig.mailbox.publish(round(50), frame);
        context.sleep(Duration::from_millis(20)).await;
        assert_eq!(
            rig.relayed(peer(2)).len(),
            after_ingest,
            "already relayed on the way in",
        );
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
        rig.mailbox.publish(round(51), frame);

        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
        assert!(
            rig.sink.requests().is_empty(),
            "the peer copy must not get ahead of local publication",
        );
    });
}

/// Publishing makes a stored certificate available to peers. The setting that
/// controls forwarding of peer traffic must not disable local publication.
#[test_traced]
fn publishing_is_not_governed_by_forwarding() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_without_forwarding(&mut context);
        rig.connect(peer(1));

        rig.mailbox.publish(round(61), rig.frame(61));

        wait_until(&context, || !rig.relayed(peer(1)).is_empty()).await;
    });
}

/// With forwarding off, a peer's verified certificate is not forwarded. Local
/// publication still reaches eligible peers, but skips a peer that claimed a
/// newer round.
#[test_traced]
fn verified_frame_is_not_forwarded_when_forwarding_is_off() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start_without_forwarding(&mut context);
        rig.connect(peer(1));
        rig.connect(peer(2));

        rig.sink.answer(Outcome::Admitted);
        let claimed = rig.frame(63);
        rig.send(peer(1), claimed).await;

        wait_until(&context, || !rig.sink.requests().is_empty()).await;
        context.sleep(Duration::from_millis(10)).await;
        assert!(
            rig.relayed(peer(2)).is_empty(),
            "a verified frame must not be forwarded with relay off",
        );

        let published = rig.frame(62);
        rig.mailbox.publish(round(62), published.clone());
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
        rig.mailbox.publish(round(60), frame);

        wait_until(&context, || !rig.relayed(peer(1)).is_empty()).await;
        wait_until(&context, || !rig.relayed(peer(2)).is_empty()).await;
    });
}

/// A publication remains useful after its first send. A peer that connects
/// later receives the newest certificate with a locally stored block.
#[test_traced]
fn new_peer_receives_latest_publication() {
    deterministic::Runner::default().start(|mut context| async move {
        let mut rig = start(&mut context);
        rig.connect(peer(1));

        let first = rig.frame(63);
        rig.mailbox.publish(round(63), first);
        wait_until(&context, || !rig.relayed(peer(1)).is_empty()).await;

        let latest = rig.frame(64);
        rig.mailbox.publish(round(64), latest.clone());
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
            rig.mailbox.publish(round(view), rig.frame(view));
        }
        let latest = rig.frame(9);
        rig.mailbox.publish(round(9), latest.clone());

        context.sleep(Duration::from_millis(20)).await;
        assert_eq!(rig.relayed(peer(1)).len(), 8, "the queue filled");

        rig.mailbox.publish(round(9), latest.clone());
        wait_until(&context, || rig.relayed(peer(1)).len() == 9).await;
        assert_eq!(rig.relayed(peer(1)).last(), Some(&latest));
    });
}
