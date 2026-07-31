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
use reth_ethereum::network::{
    api::{Direction, PeerId},
    eth_wire::{capability::SharedCapabilities, multiplex::ProtocolConnection, protocol::Protocol},
    protocol::{ConnectionHandler, OnNotSupported, ProtocolHandler},
};
use reth_metrics::{Metrics, metrics::Counter};
use tokio::sync::mpsc;

use super::wire;

/// Session lifecycle events.
///
/// These events use an unbounded channel so backpressure cannot drop them.
/// Losing [`SessionEvent::Up`] would prevent relay to that peer. Losing
/// [`SessionEvent::Down`] would leave stale peer state in consensus.
#[derive(Debug)]
pub enum SessionEvent {
    /// A session negotiated `tempo/1`.
    Up {
        /// Remote peer.
        peer: PeerId,
        /// Session number used to ignore events from an older session with the
        /// same peer.
        generation: u64,
        /// Queue for frames to send to this peer.
        outbound: mpsc::Sender<Bytes>,
    },
    /// A session ended.
    Down {
        /// Remote peer.
        peer: PeerId,
        /// Session that ended.
        generation: u64,
    },
}

/// An inbound frame that passed the transport's guards.
#[derive(Debug)]
pub struct Frame {
    /// Peer that sent it.
    pub peer: PeerId,
    /// Session it arrived on.
    pub generation: u64,
    /// Original frame bytes, kept so the frame can be relayed without encoding it again.
    pub frame: Bytes,
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
    /// Depth of each peer's outbound relay queue.
    pub outbound_queue: usize,
}

/// The consensus layer's end of the transport.
///
/// Each [`SessionEvent::Up`] carries the outbound sender for that session.
#[derive(Debug)]
pub struct TransportHandle {
    /// Session lifecycle events.
    pub control: mpsc::UnboundedReceiver<SessionEvent>,
    /// Inbound frames.
    pub frames: mpsc::Receiver<Frame>,
}

/// Creates the protocol handler for reth and the transport handle for consensus.
pub fn init(config: Config) -> (GossipProtocolHandler, TransportHandle) {
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (frames_tx, frames_rx) = mpsc::channel(config.frame_queue);

    let protocol_handler = GossipProtocolHandler {
        shared: Arc::new(Shared {
            control: control_tx,
            frames: frames_tx,
            config,
            generations: AtomicU64::new(0),
            metrics: GossipMetrics::default(),
        }),
    };
    let transport = TransportHandle {
        control: control_rx,
        frames: frames_rx,
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
}

#[derive(Debug)]
struct Shared {
    control: mpsc::UnboundedSender<SessionEvent>,
    frames: mpsc::Sender<Frame>,
    config: Config,
    generations: AtomicU64,
    metrics: GossipMetrics,
}

/// Offers `tempo/1` on every session.
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
        let generation = self.shared.generations.fetch_add(1, Ordering::Relaxed);
        let (outbound_tx, outbound_rx) = mpsc::channel(self.shared.config.outbound_queue);

        let _ = self.shared.control.send(SessionEvent::Up {
            peer: peer_id,
            generation,
            outbound: outbound_tx,
        });

        Connection {
            peer: peer_id,
            generation,
            admission: Admission::new(self.shared.config.peer_frame_rate, Instant::now()),
            shared: self.shared,
            conn,
            outbound: Some(outbound_rx),
        }
    }
}

/// A single `tempo/1` session, polled by reth.
#[derive(Debug)]
pub struct Connection {
    peer: PeerId,
    generation: u64,
    shared: Arc<Shared>,
    conn: ProtocolConnection,
    // Set to `None` when all outbound senders close. Inbound remains active.
    outbound: Option<mpsc::Receiver<Bytes>>,
    admission: Admission,
}

impl Connection {
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
                generation: self.generation,
                frame: frame.freeze().into(),
            })
            .is_err()
        {
            self.shared.metrics.dropped_channel_full.increment(1);
        }
    }
}

impl Stream for Connection {
    type Item = BytesMut;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            // Prefer outbound relay so inbound traffic cannot starve it.
            if let Some(outbound) = this.outbound.as_mut() {
                match outbound.poll_recv(cx) {
                    Poll::Ready(Some(frame)) => {
                        let mut out = BytesMut::with_capacity(frame.len());
                        out.put_slice(&frame);
                        return Poll::Ready(Some(out));
                    }
                    // Keep the session alive and continue to read inbound frames.
                    Poll::Ready(None) => this.outbound = None,
                    Poll::Pending => {}
                }
            }

            let Some(frame) = ready!(this.conn.poll_next_unpin(cx)) else {
                return Poll::Ready(None);
            };
            this.on_inbound(frame);
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let _ = self.shared.control.send(SessionEvent::Down {
            peer: self.peer,
            generation: self.generation,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

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
