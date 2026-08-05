//! Per-connection transport for `tempo/1`.
//!
//! The transport passes bytes between reth and consensus. It limits frame size
//! and inbound rate for each connection. Consensus decodes frames, removes
//! duplicates, enforces fairness, verifies certificates, and manages peer
//! reputation.
//!
//! Reth polls [`Connection`] on its own task, so only framing runs on that
//! runtime. The transport does not inspect payloads or use consensus types.
//! This lets it stay in the node crate.

use std::{
    collections::{HashMap, hash_map::Entry},
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
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
use reth_ethereum::network::{
    api::{Direction, PeerId},
    eth_wire::{capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol},
    protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler},
};
use reth_metrics::{Metrics, metrics::Counter};
use tokio::sync::mpsc;

use super::wire;

const MAX_CONNECTIONS_PER_PEER: usize = 2;

/// Logical peer lifecycle events.
///
/// These events use an unbounded channel so backpressure cannot drop them.
/// Losing [`PeerEvent::Up`] would prevent relay to that peer. Losing
/// [`PeerEvent::Down`] would leave stale peer state in consensus.
#[derive(Debug)]
pub enum PeerEvent {
    /// The first `tempo/1` connection to a peer opened.
    Up(PeerId),
    /// The last `tempo/1` connection to a peer ended.
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

/// Sends a frame through every current transport connection for a peer.
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
    /// Returns success when at least one connection accepts the frame. If none
    /// accept it, returns `Full` when any route is full and `Closed` otherwise.
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
    /// Depth of each connection's outbound relay queue.
    pub outbound_queue: usize,
}

/// The consensus layer's end of the transport.
#[derive(Debug)]
pub struct TransportHandle {
    /// Logical peer lifecycle events.
    pub control: mpsc::UnboundedReceiver<PeerEvent>,
    /// Inbound frames.
    pub frames: mpsc::Receiver<Frame>,
    /// Peer-keyed outbound routing.
    pub sender: TransportSender,
}

/// Creates the protocol handler for reth and the transport handle for consensus.
pub fn init(config: Config) -> (GossipProtocolHandler, TransportHandle) {
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (frames_tx, frames_rx) = mpsc::channel(config.frame_queue);

    let shared = Arc::new(Shared {
        control: control_tx,
        frames: frames_tx,
        config,
        next_connection: AtomicU64::new(0),
        connections: Mutex::new(HashMap::new()),
        metrics: GossipMetrics::default(),
    });
    let sender = TransportSender::new({
        let shared = Arc::clone(&shared);
        move |peer, frame| shared.try_send(peer, frame)
    });
    let protocol_handler = GossipProtocolHandler { shared };
    let transport = TransportHandle {
        control: control_rx,
        frames: frames_rx,
        sender,
    };

    (protocol_handler, transport)
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

#[derive(Debug)]
struct Shared {
    control: mpsc::UnboundedSender<PeerEvent>,
    frames: mpsc::Sender<Frame>,
    config: Config,
    next_connection: AtomicU64,
    // Reth can briefly construct both sides of a duplicate-connection race, and
    // either side may survive its reconciliation. Both slots are equivalent and
    // removing either one does not change the logical peer lifecycle.
    connections: Mutex<HashMap<PeerId, Vec<ConnectionSlot>>>,
    metrics: GossipMetrics,
}

impl Shared {
    fn connection<S>(self: Arc<Self>, peer: PeerId, conn: S) -> Connection<S> {
        let id = self.next_connection_id();
        let (outbound_tx, outbound_rx) = mpsc::channel(self.config.outbound_queue);
        let mut connections = self
            .connections
            .lock()
            .expect("gossip connection mutex poisoned");

        let admitted = match connections.entry(peer) {
            Entry::Vacant(entry) => {
                entry.insert(vec![ConnectionSlot {
                    id,
                    outbound: outbound_tx,
                }]);
                let _ = self.control.send(PeerEvent::Up(peer));
                true
            }
            Entry::Occupied(mut entry) if entry.get().len() < MAX_CONNECTIONS_PER_PEER => {
                entry.get_mut().push(ConnectionSlot {
                    id,
                    outbound: outbound_tx,
                });
                true
            }
            Entry::Occupied(_) => {
                self.metrics.rejected_excess_connections.increment(1);
                false
            }
        };
        drop(connections);

        Connection {
            peer,
            id: admitted.then_some(id),
            admission: Admission::new(self.config.peer_frame_rate, Instant::now()),
            shared: self,
            conn,
            outbound: admitted.then_some(outbound_rx),
        }
    }

    fn next_connection_id(&self) -> ConnectionId {
        ConnectionId(self.next_connection.fetch_add(1, Ordering::Relaxed))
    }

    fn remove_connection(&self, peer: PeerId, id: ConnectionId) {
        let mut connections = self
            .connections
            .lock()
            .expect("gossip connection mutex poisoned");
        let empty = {
            let Some(known) = connections.get_mut(&peer) else {
                return;
            };
            let Some(index) = known.iter().position(|slot| slot.id == id) else {
                return;
            };
            known.swap_remove(index);
            known.is_empty()
        };

        if empty {
            connections.remove(&peer);
            let _ = self.control.send(PeerEvent::Down(peer));
        }
    }

    fn try_send(&self, peer: PeerId, frame: Bytes) -> SendResult {
        let connections = self
            .connections
            .lock()
            .expect("gossip connection mutex poisoned");
        let Some(slots) = connections.get(&peer) else {
            return Err(mpsc::error::TrySendError::Closed(frame));
        };

        // The connection cap bounds this critical section to two non-blocking
        // sends. Keeping the registry locked avoids cloning senders and gives
        // the fanout one stable set of routes.
        let mut sent = false;
        let mut full = false;
        for slot in slots {
            match slot.outbound.try_send(frame.clone()) {
                Ok(()) => sent = true,
                Err(mpsc::error::TrySendError::Full(_)) => full = true,
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
        }

        if sent {
            Ok(())
        } else if full {
            Err(mpsc::error::TrySendError::Full(frame))
        } else {
            Err(mpsc::error::TrySendError::Closed(frame))
        }
    }
}

#[derive(Debug)]
struct ConnectionSlot {
    id: ConnectionId,
    outbound: mpsc::Sender<Bytes>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionId(u64);

/// Offers `tempo/1` on every connection.
#[derive(Debug, Clone)]
pub struct GossipProtocolHandler {
    shared: Arc<Shared>,
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
        self.shared.connection(peer_id, conn)
    }
}

/// A single `tempo/1` connection, polled by reth.
#[derive(Debug)]
pub struct Connection<S = ProtocolConnection> {
    peer: PeerId,
    id: Option<ConnectionId>,
    shared: Arc<Shared>,
    conn: S,
    // Set to `None` when all outbound senders close. Inbound remains active.
    outbound: Option<mpsc::Receiver<Bytes>>,
    admission: Admission,
}

impl<S> Connection<S> {
    fn on_inbound(&mut self, frame: BytesMut) {
        self.shared.metrics.frames_received.increment(1);

        if !self.shared.config.ingest {
            self.shared.metrics.dropped_not_ingesting.increment(1);
            return;
        }

        if frame.len() > wire::MAX_FRAME_BYTES {
            self.shared.metrics.dropped_oversized.increment(1);
            return;
        }

        if !self.admission.allow(Instant::now()) {
            self.shared.metrics.dropped_admission.increment(1);
            return;
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
    }
}

impl<S> Stream for Connection<S>
where
    S: Stream<Item = BytesMut> + Unpin,
{
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();

        // Ending any installed satellite protocol ends the containing RLPx
        // connection. This bounds simultaneous connections for one peer before
        // reth finishes its own duplicate reconciliation.
        if me.id.is_none() {
            return Poll::Ready(None);
        }

        loop {
            // Prefer outbound relay so inbound traffic cannot starve it.
            if let Some(outbound) = me.outbound.as_mut() {
                match outbound.poll_recv(cx) {
                    Poll::Ready(Some(frame)) => {
                        let mut out = BytesMut::with_capacity(frame.len());
                        out.put_slice(&frame);
                        return Poll::Ready(Some(out));
                    }
                    // Keep the connection alive and continue to read inbound frames.
                    Poll::Ready(None) => me.outbound = None,
                    Poll::Pending => {}
                }
            }

            let Some(frame) = ready!(me.conn.poll_next_unpin(cx)) else {
                return Poll::Ready(None);
            };
            me.on_inbound(frame);
        }
    }
}

impl<S> Drop for Connection<S> {
    fn drop(&mut self) {
        if let Some(id) = self.id {
            self.shared.remove_connection(self.peer, id);
        }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::stream;

    use super::*;

    fn test_config() -> Config {
        Config {
            ingest: true,
            peer_frame_rate: 8,
            frame_queue: 8,
            outbound_queue: 8,
        }
    }

    #[test]
    fn duplicate_connections_share_one_peer_lifecycle() {
        let (handler, mut transport) = init(test_config());
        let peer = PeerId::with_last_byte(1);
        let shared = Arc::clone(&handler.shared);

        let first = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        assert!(matches!(transport.control.try_recv(), Ok(PeerEvent::Up(known)) if known == peer));

        let second = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let mut rejected = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        assert!(futures::executor::block_on(rejected.next()).is_none());

        drop(second);
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let replacement = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        drop(replacement);

        drop(first);
        assert!(
            matches!(transport.control.try_recv(), Ok(PeerEvent::Down(known)) if known == peer)
        );
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn duplicate_connections_are_equivalent_routes() {
        let (handler, mut transport) = init(test_config());
        let peer = PeerId::with_last_byte(2);
        let shared = Arc::clone(&handler.shared);
        let mut first = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        let mut second = shared.connection(peer, stream::pending::<BytesMut>());
        assert!(matches!(transport.control.try_recv(), Ok(PeerEvent::Up(known)) if known == peer));

        let outbound = Bytes::from_static(b"outbound");
        transport.sender.try_send(peer, outbound.clone()).unwrap();
        assert_eq!(
            first.outbound.as_mut().unwrap().try_recv(),
            Ok(outbound.clone())
        );
        assert_eq!(second.outbound.as_mut().unwrap().try_recv(), Ok(outbound));

        let from_first = BytesMut::from(&b"from-first"[..]);
        let from_second = BytesMut::from(&b"from-second"[..]);
        first.on_inbound(from_first.clone());
        second.on_inbound(from_second.clone());
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
        assert_eq!(second.outbound.as_mut().unwrap().try_recv(), Ok(remaining));

        drop(second);
        assert!(
            matches!(transport.control.try_recv(), Ok(PeerEvent::Down(known)) if known == peer)
        );
        assert!(matches!(
            transport.control.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn outbound_send_succeeds_if_any_connection_accepts() {
        let mut config = test_config();
        config.outbound_queue = 1;
        let (handler, transport) = init(config);
        let peer = PeerId::with_last_byte(3);
        let shared = Arc::clone(&handler.shared);
        let mut first = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());
        let mut second = Arc::clone(&shared).connection(peer, stream::pending::<BytesMut>());

        let blocked = Bytes::from_static(b"blocked");
        shared.connections.lock().unwrap().get(&peer).unwrap()[0]
            .outbound
            .try_send(blocked.clone())
            .unwrap();
        let delivered = Bytes::from_static(b"delivered");
        assert_eq!(transport.sender.try_send(peer, delivered.clone()), Ok(()));
        assert_eq!(first.outbound.as_mut().unwrap().try_recv(), Ok(blocked));
        assert_eq!(second.outbound.as_mut().unwrap().try_recv(), Ok(delivered));

        for (slot, frame) in shared
            .connections
            .lock()
            .unwrap()
            .get(&peer)
            .unwrap()
            .iter()
            .zip([b"first-full".as_slice(), b"second-full".as_slice()])
        {
            slot.outbound
                .try_send(Bytes::copy_from_slice(frame))
                .unwrap();
        }
        let full = Bytes::from_static(b"full");
        assert!(matches!(
            transport.sender.try_send(peer, full),
            Err(mpsc::error::TrySendError::Full(frame)) if frame == Bytes::from_static(b"full")
        ));

        drop(first);
        drop(second);
        let closed = Bytes::from_static(b"closed");
        assert!(matches!(
            transport.sender.try_send(peer, closed),
            Err(mpsc::error::TrySendError::Closed(frame)) if frame == Bytes::from_static(b"closed")
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
