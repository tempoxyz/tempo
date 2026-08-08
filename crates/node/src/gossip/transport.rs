//! Peer-keyed transport for `tempo/1`.
//!
//! Consensus sees one logical connection per [`PeerId`]. It receives lifecycle
//! events and inbound frames keyed only by the peer, and sends outbound frames
//! the same way. Physical connection identities are not part of this interface.
//!
//! Normally, that logical connection is backed by one RLPx connection. As a
//! short-lived edge case, reth can expose both sides of a duplicate-connection
//! race before it selects the survivor. The coordinator hides this window by
//! accepting at most two equivalent physical connections: inbound frames from
//! either use the same peer ID, while outbound frames are offered to both. Reth
//! remains responsible for selecting and closing the duplicate.
//!
//! Reth polls each physical [`Connection`] from its RLPx session task. The
//! transport limits frame size and inbound rate per connection but otherwise
//! treats frames as opaque bytes. It reports byte-level protocol violations;
//! consensus decodes certificates, removes replays, enforces fairness, verifies
//! certificates, and reports invalid certificates.
//!
//! Outbound buffering keeps only the latest frame for a logical peer. This is
//! safe while `tempo/1` carries only finalization certificates because a newer
//! certificate supersedes an older one.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Instant,
};

use alloy_primitives::{
    Bytes,
    bytes::{BufMut as _, BytesMut},
};
use futures::{Stream, StreamExt as _};
use reth_ethereum::{
    network::{
        api::{Direction, PeerId},
        eth_wire::{
            capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol,
        },
        protocol::{
            ConnectionHandler, IntoRlpxSubProtocol as _, OnNotSupported, ProtocolHandler,
            RlpxSubProtocol,
        },
    },
    tasks::TaskExecutor,
};
use reth_metrics::{Metrics, metrics::Counter};
use reth_tracing::tracing::warn;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_stream::wrappers::WatchStream;

use super::{PeerControl, wire};

const MAX_CONNECTIONS_PER_PEER: usize = 2;

/// Events for the consensus-facing logical peer.
///
/// The coordinator emits [`PeerEvent::Up`] when it accepts the first physical
/// connection for a peer. A transient duplicate connection joins the same
/// logical peer and does not produce another `Up`. [`PeerEvent::Down`] follows
/// when the last physical connection disappears or when the coordinator removes
/// the logical peer after a protocol breach.
///
/// These events use an unbounded channel because losing lifecycle events would
/// leave stale peer state.
#[derive(Debug)]
pub enum PeerEvent {
    /// The logical peer became available for inbound and outbound traffic.
    Up(PeerId),
    /// The logical peer no longer has an accepted physical connection.
    Down(PeerId),
}

/// An inbound frame that passed the transport's guards.
#[derive(Debug)]
pub struct Frame {
    /// Peer that sent it.
    pub peer: PeerId,
    /// Original frame bytes, kept so the frame can be relayed without encoding it again.
    pub frame: Bytes,
}

type SendResult = Result<(), mpsc::error::TrySendError<Bytes>>;
type SendFrame = dyn Fn(PeerId, Bytes) -> SendResult + Send + Sync;

/// Allows sending frames to the specified peers.
#[derive(Clone)]
pub struct TransportSender {
    send: Arc<SendFrame>,
}

impl TransportSender {
    /// Creates a sender backed by a peer-routing function.
    pub fn new<F>(send: F) -> Self
    where
        F: Fn(PeerId, Bytes) -> SendResult + Send + Sync + 'static,
    {
        Self {
            send: Arc::new(send),
        }
    }

    /// Queues a frame for `peer`.
    ///
    /// Success means the coordinator queue accepted the frame. It does not
    /// acknowledge delivery because the peer may disconnect before the frame is
    /// routed. Once routed, current and replacement connections can observe it
    /// until a newer frame replaces it.
    pub fn try_send(&self, peer: PeerId, frame: Bytes) -> SendResult {
        (self.send)(peer, frame)
    }
}

impl fmt::Debug for TransportSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportSender").finish_non_exhaustive()
    }
}

/// Transport configuration.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Whether inbound frames are sent to consensus.
    ///
    /// Validators publish but do not ingest. They already receive certificates
    /// from an authenticated validator network. Accepting the same data from a
    /// permissionless network would add risk and unnecessary consensus work.
    pub ingest: bool,
    /// Frames per second accepted from a single connection.
    pub peer_frame_rate: u32,
    /// Depth of the shared inbound queue to the consensus layer.
    pub frame_queue: usize,
    /// Depth of the outbound queue to the transport coordinator.
    pub route_queue: usize,
}

/// The consensus-facing, peer-keyed view of the transport.
///
/// This interface intentionally exposes no physical connection identity.
#[derive(Debug)]
pub struct TransportHandle {
    /// Logical peer lifecycle events.
    pub control: mpsc::UnboundedReceiver<PeerEvent>,
    /// Inbound frames.
    pub frames: mpsc::Receiver<Frame>,
    /// Peer-keyed outbound routing.
    pub sender: TransportSender,
}

/// Creates the protocol and the consensus-facing end of its transport.
pub fn init(config: Config, tasks: &TaskExecutor) -> (GossipProtocol, TransportHandle) {
    let (protocol, coordinator, transport) = build(config);
    tasks.spawn_critical_task("tempo gossip coordinator", coordinator.run());
    (protocol, transport)
}

fn build(config: Config) -> (GossipProtocol, TransportCoordinator, TransportHandle) {
    let (peer_events_tx, peer_events_rx) = mpsc::unbounded_channel();
    let (frames_tx, frames_rx) = mpsc::channel(config.frame_queue);
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let (outbound_tx, outbound_rx) = mpsc::channel(config.route_queue);
    let metrics = Arc::new(GossipMetrics::default());

    let shared = Arc::new(Shared {
        commands: commands_tx,
        frames: frames_tx,
        config,
        next_connection: AtomicU64::new(0),
        metrics: Arc::clone(&metrics),
    });
    let sender = TransportSender::new({
        move |peer, frame| match outbound_tx.try_send(OutboundFrame { peer, frame }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(outbound)) => {
                Err(mpsc::error::TrySendError::Full(outbound.frame))
            }
            Err(mpsc::error::TrySendError::Closed(outbound)) => {
                Err(mpsc::error::TrySendError::Closed(outbound.frame))
            }
        }
    });
    let protocol = GossipProtocol { shared };
    let coordinator = TransportCoordinator {
        commands: commands_rx,
        outbound: outbound_rx,
        peers: HashMap::new(),
        peer_events: peer_events_tx,
        metrics,
    };
    let transport = TransportHandle {
        control: peer_events_rx,
        frames: frames_rx,
        sender,
    };

    (protocol, coordinator, transport)
}

#[derive(Debug)]
struct Shared {
    commands: mpsc::UnboundedSender<ConnectionCommand>,
    frames: mpsc::Sender<Frame>,
    config: Config,
    next_connection: AtomicU64,
    metrics: Arc<GossipMetrics>,
}

/// The `tempo/1` protocol before it is installed into Reth's network.
///
/// Reth clones node definitions while it assembles their components, so this
/// value contains only shared transport state. [`Self::install`] binds it to
/// the network before Reth can create a `tempo/1` connection.
#[derive(Debug, Clone)]
pub struct GossipProtocol {
    shared: Arc<Shared>,
}

impl GossipProtocol {
    pub(crate) fn install(self, network: impl PeerControl) -> RlpxSubProtocol {
        self.into_handler(network).into_rlpx_sub_protocol()
    }

    fn into_handler(self, peer_control: impl PeerControl) -> GossipProtocolHandler {
        GossipProtocolHandler {
            shared: self.shared,
            peer_control: Arc::new(peer_control),
        }
    }
}

impl Shared {
    fn connection<S>(
        self: &Arc<Self>,
        peer: PeerId,
        conn: S,
        peer_control: Arc<dyn PeerControl>,
    ) -> Connection<S> {
        let id = self.next_connection_id();
        let (registration_tx, registration_rx) = oneshot::channel();
        let _ = self.commands.send(ConnectionCommand::Register {
            peer,
            id,
            registration: registration_tx,
        });

        Connection {
            peer,
            id,
            state: ConnectionState::Registering(registration_rx),
            admission: Admission::new(self.config.peer_frame_rate, Instant::now()),
            shared: Arc::clone(self),
            peer_control,
            conn,
            outbound: None,
        }
    }

    fn next_connection_id(&self) -> ConnectionId {
        ConnectionId(self.next_connection.fetch_add(1, Ordering::Relaxed))
    }
}

/// Implements the logical peer abstraction over physical connections.
///
/// A peer normally has one connection. The second slot exists only for reth's
/// transient duplicate-reconciliation edge case. Both slots are equivalent:
/// outbound frames are offered to both, [`PeerEvent::Up`] is emitted for the
/// first, and [`PeerEvent::Down`] for the last. Any further connection is
/// rejected.
#[derive(Debug)]
struct TransportCoordinator {
    commands: mpsc::UnboundedReceiver<ConnectionCommand>,
    outbound: mpsc::Receiver<OutboundFrame>,
    peers: HashMap<PeerId, PeerConnections>,
    peer_events: mpsc::UnboundedSender<PeerEvent>,
    metrics: Arc<GossipMetrics>,
}

impl TransportCoordinator {
    async fn run(mut self) {
        loop {
            tokio::select! {
                Some(command) = self.commands.recv() => {
                    self.on_command(command).await
                },
                Some(outbound) = self.outbound.recv() => self.on_outbound(outbound),
                else => {
                    // Critical tasks report panics, not normal completion. Keep
                    // this unexpected teardown visible until executor shutdown.
                    warn!("Gossip transport coordinator inputs closed; waiting for shutdown");
                    std::future::pending::<()>().await;
                }
            }
        }
    }

    async fn on_command(&mut self, command: ConnectionCommand) {
        match command {
            ConnectionCommand::Register {
                peer,
                id,
                registration,
            } => self.register(peer, id, registration),
            ConnectionCommand::Unregister { peer, id } => self.unregister(peer, id),
            ConnectionCommand::ProtocolBreach {
                peer,
                id,
                peer_control,
            } => self.protocol_breach(peer, id, peer_control).await,
        }
    }

    fn register(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        registration: oneshot::Sender<Registration>,
    ) {
        let outbound = match self.peers.entry(peer) {
            Entry::Vacant(entry) => {
                let connections = entry.insert(PeerConnections::new(id));
                let outbound = connections.outbound.subscribe();

                // The actor prioritizes lifecycle events over frames. Enqueueing `Up`
                // before accepting registration ensures it creates peer state before
                // this connection can forward inbound bytes.
                let _ = self.peer_events.send(PeerEvent::Up(peer));

                outbound
            }
            Entry::Occupied(mut entry) => {
                let connections = entry.get_mut();
                if connections.ids.len() >= MAX_CONNECTIONS_PER_PEER {
                    self.metrics.rejected_excess_connections.increment(1);
                    let _ = registration.send(Registration::Rejected);
                    return;
                }

                connections.ids.push(id);
                connections.outbound.subscribe()
            }
        };

        if registration.send(Registration::Accepted(outbound)).is_err() {
            self.unregister(peer, id);
        }
    }

    fn unregister(&mut self, peer: PeerId, id: ConnectionId) {
        let empty = {
            let Some(known) = self.peers.get_mut(&peer) else {
                return;
            };
            let Some(index) = known.ids.iter().position(|known| *known == id) else {
                return;
            };
            known.ids.swap_remove(index);
            known.ids.is_empty()
        };

        if empty {
            self.peers.remove(&peer);
            let _ = self.peer_events.send(PeerEvent::Down(peer));
        }
    }

    fn on_outbound(&mut self, outbound: OutboundFrame) {
        let Some(peer) = self.peers.get(&outbound.peer) else {
            return;
        };
        peer.outbound.send_replace(Some(outbound.frame));
    }

    async fn protocol_breach(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        peer_control: Arc<dyn PeerControl>,
    ) {
        let Some(connections) = self.peers.get(&peer) else {
            return;
        };
        if !connections.ids.contains(&id) {
            return;
        }

        peer_control.protocol_breach(peer).await;

        // Removes the PeerConnections which drops the `outbound` stream. This serves as a signal
        // for the associated connections to shutdown.
        let _ = self.peers.remove(&peer);
        let _ = self.peer_events.send(PeerEvent::Down(peer));
    }
}

enum ConnectionCommand {
    Register {
        peer: PeerId,
        id: ConnectionId,
        registration: oneshot::Sender<Registration>,
    },
    Unregister {
        peer: PeerId,
        id: ConnectionId,
    },
    ProtocolBreach {
        peer: PeerId,
        id: ConnectionId,
        peer_control: Arc<dyn PeerControl>,
    },
}

#[derive(Debug)]
struct OutboundFrame {
    peer: PeerId,
    frame: Bytes,
}

#[derive(Debug)]
struct PeerConnections {
    ids: Vec<ConnectionId>,
    outbound: watch::Sender<Option<Bytes>>,
}

impl PeerConnections {
    fn new(id: ConnectionId) -> Self {
        let (outbound, _) = watch::channel(None);
        Self {
            ids: vec![id],
            outbound,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionId(u64);

#[derive(Debug)]
enum ConnectionState {
    Registering(oneshot::Receiver<Registration>),
    Active,
    Breached,
    Rejected,
}

#[derive(Debug)]
enum Registration {
    Accepted(watch::Receiver<Option<Bytes>>),
    Rejected,
}

enum InboundAction {
    Continue,
    WaitForShutdown,
    Close,
}

/// Offers `tempo/1` on every connection.
#[derive(Clone)]
struct GossipProtocolHandler {
    shared: Arc<Shared>,
    peer_control: Arc<dyn PeerControl>,
}

impl fmt::Debug for GossipProtocolHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GossipProtocolHandler")
            .field("shared", &self.shared)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for GossipProtocolHandler {
    type ConnectionHandler = Self;

    fn on_incoming(&self, _socket_addr: SocketAddr) -> Option<Self::ConnectionHandler> {
        Some(self.clone())
    }

    fn on_outgoing(
        &self,
        _socket_addr: SocketAddr,
        _peer_id: PeerId,
    ) -> Option<Self::ConnectionHandler> {
        Some(self.clone())
    }
}

impl ConnectionHandler for GossipProtocolHandler {
    type Connection = Connection;

    fn protocol(&self) -> Protocol {
        wire::protocol()
    }

    fn on_unsupported_by_peer(
        self,
        _supported: &SharedCapabilities,
        _direction: Direction,
        _peer_id: PeerId,
    ) -> OnNotSupported {
        // Keep `eth` sessions with peers that do not support `tempo/1`.
        OnNotSupported::KeepAlive
    }

    fn into_connection(
        self,
        _direction: Direction,
        peer_id: PeerId,
        conn: ProtocolConnection,
    ) -> Self::Connection {
        self.shared.connection(peer_id, conn, self.peer_control)
    }
}

/// A physical `tempo/1` connection polled by reth.
///
/// Its underlying stream remains unpolled until the coordinator accepts its
/// registration. Registration rejection or a protocol breach ends this
/// satellite stream and therefore the containing RLPx connection.
pub struct Connection<S = ProtocolConnection> {
    peer: PeerId,
    id: ConnectionId,
    state: ConnectionState,
    shared: Arc<Shared>,
    peer_control: Arc<dyn PeerControl>,
    conn: S,
    // Dropping the sender closes every physical connection for the logical peer.
    outbound: Option<WatchStream<Option<Bytes>>>,
    admission: Admission,
}

impl<S> Connection<S> {
    fn poll_registration(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // The coordinator owns admission to the logical peer. Do not poll the
        // underlying protocol stream before it accepts this physical connection;
        // rejection must close RLPx without processing any frames from it.
        if let ConnectionState::Registering(registration) = &mut self.state {
            self.state = match ready!(Pin::new(registration).poll(cx)) {
                Ok(Registration::Accepted(outbound)) => {
                    self.outbound = Some(WatchStream::new(outbound));
                    ConnectionState::Active
                }
                Ok(Registration::Rejected) | Err(_) => ConnectionState::Rejected,
            };
        }

        Poll::Ready(())
    }

    fn protocol_breach(&mut self) -> InboundAction {
        self.shared.metrics.dropped_oversized.increment(1);
        let command = ConnectionCommand::ProtocolBreach {
            peer: self.peer,
            id: self.id,
            peer_control: Arc::clone(&self.peer_control),
        };

        match self.shared.commands.send(command) {
            Ok(()) => {
                self.state = ConnectionState::Breached;
                InboundAction::WaitForShutdown
            }
            Err(_) => {
                self.state = ConnectionState::Rejected;
                InboundAction::Close
            }
        }
    }

    fn on_inbound(&mut self, frame: BytesMut) -> InboundAction {
        self.shared.metrics.frames_received.increment(1);

        if frame.len() > wire::MAX_FRAME_BYTES {
            return self.protocol_breach();
        }

        if !self.admission.allow(Instant::now()) {
            self.shared.metrics.dropped_admission.increment(1);
            return InboundAction::Continue;
        }

        if !self.shared.config.ingest {
            self.shared.metrics.dropped_not_ingesting.increment(1);
            return InboundAction::Continue;
        }

        // This queue is lossy. A newer certificate also proves finality for
        // earlier blocks, so dropping one frame does not block progress.
        if self
            .shared
            .frames
            .try_send(Frame {
                peer: self.peer,
                frame: frame.freeze().into(),
            })
            .is_err()
        {
            self.shared.metrics.dropped_channel_full.increment(1);
        }

        InboundAction::Continue
    }

    fn poll_active(&mut self, cx: &mut Context<'_>) -> Poll<Option<BytesMut>>
    where
        S: Stream<Item = BytesMut> + Unpin,
    {
        // Check the outbound relay before each inbound frame so a peer that sends
        // continuously cannot starve locally produced certificates.
        loop {
            if let Some(outbound) = self.outbound.as_mut() {
                match outbound.poll_next_unpin(cx) {
                    Poll::Ready(Some(Some(frame))) => {
                        let mut out = BytesMut::with_capacity(frame.len());
                        out.put_slice(&frame);
                        return Poll::Ready(Some(out));
                    }
                    Poll::Ready(Some(None)) => continue,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => {}
                }
            }

            let Some(frame) = ready!(self.conn.poll_next_unpin(cx)) else {
                return Poll::Ready(None);
            };
            match self.on_inbound(frame) {
                InboundAction::Continue => {}
                InboundAction::WaitForShutdown => return self.poll_breached(cx),
                InboundAction::Close => return Poll::Ready(None),
            }
        }
    }

    fn poll_breached(&mut self, cx: &mut Context<'_>) -> Poll<Option<BytesMut>> {
        // The coordinator drops this relay only after Reth acknowledges the
        // penalty. Ignore any queued values and keep polling until closure so the
        // connection remains alive, with a registered waker, in the meantime.
        let outbound = self
            .outbound
            .as_mut()
            .expect("a breached connection must have completed registration");

        loop {
            match ready!(outbound.poll_next_unpin(cx)) {
                Some(_) => {}
                None => return Poll::Ready(None),
            }
        }
    }
}

impl<S> Stream for Connection<S>
where
    S: Stream<Item = BytesMut> + Unpin,
{
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();

        // Reth treats this stream as the lifetime of the installed `tempo/1`
        // satellite, not only as a source of outbound frames. Yielding a frame
        // forwards it to the peer, while remaining pending keeps the RLPx session
        // alive as we wait for more work. Once the stream ends, Reth considers the
        // satellite closed and tears down the entire containing RLPx connection,
        // including its other negotiated subprotocols.
        //
        // After a protocol breach, returning `None` must wait until Reth processes
        // the penalty. Ending the stream sooner could remove an unknown inbound
        // peer before its ban is recorded.
        if matches!(me.state, ConnectionState::Registering(_)) {
            ready!(me.poll_registration(cx));
        }

        match me.state {
            ConnectionState::Active => me.poll_active(cx),
            ConnectionState::Breached => me.poll_breached(cx),
            ConnectionState::Rejected => Poll::Ready(None),
            ConnectionState::Registering(_) => unreachable!(),
        }
    }
}

impl<S> Drop for Connection<S> {
    fn drop(&mut self) {
        let _ = self.shared.commands.send(ConnectionCommand::Unregister {
            peer: self.peer,
            id: self.id,
        });
    }
}

/// Per-connection token bucket.
///
/// This protects the channel to consensus from floods. It does not enforce
/// fairness across peers. Consensus does that by keeping one pending frame per
/// peer and using a deterministic clock.
#[derive(Debug)]
struct Admission {
    tokens: f64,
    capacity: f64,
    per_second: f64,
    updated: Instant,
}

impl Admission {
    fn new(per_second: u32, now: Instant) -> Self {
        let capacity = f64::from(per_second.max(1));
        Self {
            tokens: capacity,
            capacity,
            per_second: capacity,
            updated: now,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.updated = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "tempo_gossip")]
struct GossipMetrics {
    /// tempo/1 frames received from peers.
    frames_received: Counter,
    /// tempo/1 frames dropped because this node does not ingest gossip.
    dropped_not_ingesting: Counter,
    /// tempo/1 frames dropped for exceeding the maximum frame size.
    dropped_oversized: Counter,
    /// tempo/1 frames dropped by the per-connection rate limit.
    dropped_admission: Counter,
    /// tempo/1 frames dropped because the queue to the consensus layer was full.
    dropped_channel_full: Counter,
    /// RLPx connections rejected after a peer reached its tempo/1 connection cap.
    rejected_excess_connections: Counter,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::gossip::NoPeerControl;
    use futures::{
        future::{BoxFuture, poll_fn},
        stream,
    };

    use super::*;

    fn test_config() -> Config {
        Config {
            ingest: true,
            peer_frame_rate: 8,
            frame_queue: 8,
            route_queue: 8,
        }
    }

    #[derive(Clone)]
    struct StubPeerControl {
        breaches: mpsc::UnboundedSender<(PeerId, oneshot::Sender<()>)>,
    }

    impl PeerControl for StubPeerControl {
        fn penalize(&self, _peer: PeerId) {}

        fn protocol_breach(&self, peer: PeerId) -> BoxFuture<'_, ()> {
            let (release, released) = oneshot::channel();
            let _ = self.breaches.send((peer, release));
            Box::pin(async move {
                let _ = released.await;
            })
        }
    }

    fn build_with_peer_control(
        config: Config,
        peer_control: impl PeerControl,
    ) -> (GossipProtocolHandler, TransportCoordinator, TransportHandle) {
        let (protocol, coordinator, transport) = build(config);
        (protocol.into_handler(peer_control), coordinator, transport)
    }

    fn spawn_coordinator(coordinator: TransportCoordinator) -> tokio::task::JoinHandle<()> {
        tokio::spawn(coordinator.run())
    }

    fn connection<S>(handler: &GossipProtocolHandler, peer: PeerId, conn: S) -> Connection<S> {
        handler
            .shared
            .connection(peer, conn, Arc::clone(&handler.peer_control))
    }

    async fn register<S>(connection: &mut Connection<S>) -> bool {
        poll_fn(|cx| connection.poll_registration(cx)).await;
        matches!(connection.state, ConnectionState::Active)
    }

    async fn next_outbound<S>(connection: &mut Connection<S>) -> Bytes {
        loop {
            if let Some(frame) = connection
                .outbound
                .as_mut()
                .expect("registered connection")
                .next()
                .await
                .expect("logical peer is registered")
            {
                return frame;
            }
        }
    }

    #[tokio::test]
    async fn connection_waits_for_registration_before_polling_frames() {
        let (handler, mut coordinator, mut transport) =
            build_with_peer_control(test_config(), NoPeerControl);
        let peer = PeerId::with_last_byte(0);
        let inbound = BytesMut::from(&b"inbound"[..]);
        let mut connection = connection(&handler, peer, stream::iter([inbound.clone()]));

        assert!(futures::poll!(connection.next()).is_pending());
        assert!(matches!(
            transport.frames.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let command = coordinator.commands.recv().await.unwrap();
        coordinator.on_command(command).await;
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Up(known)) if known == peer)
        );

        assert!(connection.next().await.is_none());
        let received = transport.frames.recv().await.unwrap();
        assert_eq!(received.peer, peer);
        assert_eq!(received.frame.as_ref(), inbound.as_ref());
    }

    #[tokio::test]
    async fn duplicate_connections_share_one_peer_lifecycle() {
        let (handler, coordinator, mut transport) =
            build_with_peer_control(test_config(), NoPeerControl);
        let _coordinator = spawn_coordinator(coordinator);
        let peer = PeerId::with_last_byte(1);

        let mut first = connection(&handler, peer, stream::pending::<BytesMut>());
        assert!(register(&mut first).await);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Up(known)) if known == peer)
        );

        let mut second = connection(&handler, peer, stream::pending::<BytesMut>());
        assert!(register(&mut second).await);
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let mut rejected = connection(&handler, peer, stream::pending::<BytesMut>());
        assert!(!register(&mut rejected).await);
        assert!(rejected.next().await.is_none());

        drop(second);
        let mut replacement = connection(&handler, peer, stream::pending::<BytesMut>());
        assert!(register(&mut replacement).await);
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(replacement);

        drop(first);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Down(known)) if known == peer)
        );
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn duplicate_connections_are_equivalent_routes() {
        let (handler, coordinator, mut transport) =
            build_with_peer_control(test_config(), NoPeerControl);
        let _coordinator = spawn_coordinator(coordinator);
        let peer = PeerId::with_last_byte(2);
        let mut first = connection(&handler, peer, stream::pending::<BytesMut>());
        let mut second = connection(&handler, peer, stream::pending::<BytesMut>());
        assert!(register(&mut first).await);
        assert!(register(&mut second).await);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Up(known)) if known == peer)
        );

        let outbound = Bytes::from_static(b"outbound");
        transport.sender.try_send(peer, outbound.clone()).unwrap();
        assert_eq!(next_outbound(&mut first).await, outbound);
        assert_eq!(next_outbound(&mut second).await, outbound);

        let from_first = BytesMut::from(&b"from-first"[..]);
        let from_second = BytesMut::from(&b"from-second"[..]);
        assert!(matches!(
            first.on_inbound(from_first.clone()),
            InboundAction::Continue
        ));
        assert!(matches!(
            second.on_inbound(from_second.clone()),
            InboundAction::Continue
        ));
        assert_eq!(
            transport.frames.try_recv().unwrap().frame.as_ref(),
            from_first.as_ref()
        );
        assert_eq!(
            transport.frames.try_recv().unwrap().frame.as_ref(),
            from_second.as_ref()
        );

        drop(first);
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let remaining = Bytes::from_static(b"remaining");
        transport.sender.try_send(peer, remaining.clone()).unwrap();
        assert_eq!(next_outbound(&mut second).await, remaining);

        drop(second);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Down(known)) if known == peer)
        );
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn slow_and_replacement_connections_receive_latest_frame() {
        let (handler, mut coordinator, mut transport) =
            build_with_peer_control(test_config(), NoPeerControl);
        let peer = PeerId::with_last_byte(3);
        let mut first = connection(&handler, peer, stream::pending::<BytesMut>());
        let command = coordinator.commands.recv().await.unwrap();
        coordinator.on_command(command).await;
        assert!(register(&mut first).await);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Up(known)) if known == peer)
        );

        transport
            .sender
            .try_send(peer, Bytes::from_static(b"stale"))
            .unwrap();
        let outbound = coordinator.outbound.recv().await.unwrap();
        coordinator.on_outbound(outbound);

        let latest = Bytes::from_static(b"latest");
        transport.sender.try_send(peer, latest.clone()).unwrap();
        let outbound = coordinator.outbound.recv().await.unwrap();
        coordinator.on_outbound(outbound);

        let mut second = connection(&handler, peer, stream::pending::<BytesMut>());
        let command = coordinator.commands.recv().await.unwrap();
        coordinator.on_command(command).await;
        assert!(register(&mut second).await);

        assert_eq!(next_outbound(&mut first).await, latest);
        assert_eq!(next_outbound(&mut second).await, latest);

        drop(first);
        drop(second);
        for _ in 0..2 {
            let command = coordinator.commands.recv().await.unwrap();
            coordinator.on_command(command).await;
        }
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Down(known)) if known == peer)
        );
    }

    #[tokio::test]
    async fn oversized_frame_is_penalized_before_connections_close() {
        let mut config = test_config();
        config.ingest = false;
        let (breaches, mut reported_breaches) = mpsc::unbounded_channel();
        let (handler, coordinator, mut transport) =
            build_with_peer_control(config, StubPeerControl { breaches });
        let _coordinator = spawn_coordinator(coordinator);
        let peer = PeerId::with_last_byte(4);
        let oversized = BytesMut::from(&vec![0; wire::MAX_FRAME_BYTES + 1][..]);
        let mut first = connection(&handler, peer, stream::iter([oversized]));
        let mut second = connection(&handler, peer, stream::pending::<BytesMut>());

        assert!(register(&mut first).await);
        assert!(register(&mut second).await);
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Up(known)) if known == peer)
        );

        assert!(futures::poll!(first.next()).is_pending());
        let (reported, release) = reported_breaches.recv().await.unwrap();
        assert_eq!(reported, peer);
        assert!(futures::poll!(first.next()).is_pending());
        assert!(futures::poll!(second.next()).is_pending());
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        release.send(()).unwrap();
        assert!(first.next().await.is_none());
        assert!(
            matches!(transport.control.recv().await, Some(PeerEvent::Down(known)) if known == peer)
        );
        assert!(second.next().await.is_none());
        assert!(matches!(
            transport.frames.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn admission_allows_a_burst_then_throttles() {
        let start = Instant::now();
        let mut admission = Admission::new(4, start);

        for _ in 0..4 {
            assert!(admission.allow(start));
        }
        assert!(!admission.allow(start));
    }

    #[test]
    fn admission_refills_over_time() {
        let start = Instant::now();
        let mut admission = Admission::new(4, start);
        for _ in 0..4 {
            assert!(admission.allow(start));
        }

        let later = start + Duration::from_millis(250);
        assert!(admission.allow(later));
        assert!(!admission.allow(later));
    }

    #[test]
    fn admission_does_not_accumulate_beyond_capacity() {
        let start = Instant::now();
        let mut admission = Admission::new(2, start);

        let much_later = start + Duration::from_secs(60);
        assert!(admission.allow(much_later));
        assert!(admission.allow(much_later));
        assert!(!admission.allow(much_later));
    }

    #[test]
    fn admission_rate_of_zero_still_permits_progress() {
        let start = Instant::now();
        let mut admission = Admission::new(0, start);
        assert!(admission.allow(start));
    }
}
