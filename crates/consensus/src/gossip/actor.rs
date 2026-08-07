//! The `tempo/1` actor.
//!
//! The actor admits, schedules, and relays gossiped certificates. The driver
//! judges them because it owns the epoch schemes. The actor uses the runtime
//! clock so its scheduling and rate limits work in deterministic tests.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroU32,
    sync::Arc,
};

use alloy_primitives::{B256, Bytes, keccak256};
use commonware_consensus::{
    Epochable as _,
    types::{Epoch, Round},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Quota, RateLimiter, Spawner, spawn_cell,
};
use futures::{
    FutureExt as _, StreamExt as _,
    stream::{self, BoxStream},
};
use tempo_node::gossip::{Frame, PeerControl, PeerEvent, TransportHandle, TransportSender, wire};
use tokio::{select, sync::mpsc};
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::debug;

use super::{CertSink, Certificate, Outcome, ingress::Message, metrics::Metrics};
use crate::{follow::FollowerProgress, utils::OptionFuture};

/// Hash of the exact frame bytes used to track settled or published frames.
///
/// Different certificates can name the same block. A key based on the block
/// would let a forged certificate suppress a valid certificate for that block.
type FrameId = B256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Ready,
    Judging,
    NeedsScheme(Epoch),
}

/// A peer's current candidate or quarantined certificate.
struct Slot {
    round: Round,
    certificate: Certificate,
    frame: Bytes,
    id: FrameId,
    state: SlotState,
}

struct Peer {
    /// Highest round this peer claimed or this node accepted for outbound routing.
    seen_round: Option<Round>,
}

impl Peer {
    fn observe(&mut self, round: Round) {
        self.seen_round = Some(self.seen_round.map_or(round, |seen| seen.max(round)));
    }

    /// Offers a certificate if the peer has not seen its round or a later one.
    ///
    /// Returns `true` when the coordinator queue accepts the frame. Delivery to
    /// physical connections is best effort and is not reported here. A failed
    /// enqueue does not advance `seen_round`, so a later call can try again.
    fn offer(
        &mut self,
        sender: &TransportSender,
        peer: PeerKey,
        round: Round,
        frame: &Bytes,
    ) -> Result<bool, mpsc::error::TrySendError<Bytes>> {
        if self.seen_round.is_some_and(|seen| seen >= round) {
            return Ok(false);
        }

        sender.try_send(peer, frame.clone())?;
        self.observe(round);
        Ok(true)
    }
}

/// Latest certificate with a block stored locally.
struct Published {
    round: Round,
    frame: Bytes,
}

/// A certificate the driver is judging.
struct Pending {
    peer: PeerKey,
    round: Round,
    id: FrameId,
    /// Exact bytes are retained outside the slot so a disconnect cannot erase
    /// the evidence or change what a completed judgment relays.
    frame: Bytes,
}

type PeerKey = alloy_primitives::B512;
type BoundarySchemeStream = BoxStream<'static, Result<Epoch, BroadcastStreamRecvError>>;

/// Returns authenticated boundary-scheme notifications or a stream that remains pending.
///
/// The pending tail keeps the actor's select branch dormant if the source is
/// absent or closes.
fn boundary_scheme_stream(progress: Option<&FollowerProgress>) -> BoundarySchemeStream {
    match progress {
        Some(progress) => BroadcastStream::new(progress.boundary_schemes())
            .chain(stream::pending())
            .boxed(),
        None => stream::pending().boxed(),
    }
}

/// Inputs and limits for the `tempo/1` actor.
pub(crate) struct Config<K> {
    /// Maximum driver judgements per second across all peers.
    ///
    /// Each signature check runs on the driver task, which also acknowledges
    /// blocks to marshal. This limit bounds how much a flood can delay block
    /// import. Initialization treats zero as one.
    pub(crate) verify_rate: u32,
    /// Frames remembered as already settled or published.
    pub(crate) recent_frames: usize,
    /// Whether to forward certificates verified from a peer.
    ///
    /// Does not govern publishing: a certificate this node stored itself is
    /// offered regardless.
    pub(crate) relay: bool,
    /// The consensus layer's end of the `tempo/1` transport.
    pub(crate) transport: TransportHandle,
    /// Certificates published after the feed confirms their blocks are stored.
    pub(crate) mailbox: mpsc::UnboundedReceiver<Message>,
    /// Reputation control for peers that misbehave.
    pub(crate) peer_control: Arc<dyn PeerControl>,
    /// Judges certificates. A publish-only node uses a sink with no outcome.
    pub(crate) sink: K,
    /// The follower's progress, when this node follows one.
    ///
    /// A publish-only node has no progress because it does not ingest or judge
    /// certificates.
    pub(crate) progress: Option<FollowerProgress>,
}

pub(crate) fn init<TContext, K>(context: TContext, config: Config<K>) -> Actor<TContext, K>
where
    TContext: Clock + RuntimeMetrics + Spawner,
{
    let metrics = Metrics::init(&context);
    let quota =
        Quota::per_second(NonZeroU32::new(config.verify_rate.max(1)).expect("clamped above zero"));
    let recent = SettledFrames::with_capacity(config.recent_frames);
    let boundary_schemes = boundary_scheme_stream(config.progress.as_ref());

    let limiter_context = context.child("verify_limiter");

    Actor {
        verify_limiter: RateLimiter::direct_with_clock(quota, limiter_context),
        context: ContextCell::new(context),
        config,
        peers: HashMap::new(),
        slots: HashMap::new(),
        settled_frames: recent,
        latest: None,
        pending: OptionFuture::none(),
        budget_wakeup: OptionFuture::none(),
        boundary_schemes,
        cursor: 0,
        slots_pruned_through: Round::zero(),
        metrics,
    }
}

pub(crate) struct Actor<TContext: Clock, K> {
    context: ContextCell<TContext>,
    config: Config<K>,

    peers: HashMap<PeerKey, Peer>,
    slots: HashMap<PeerKey, Slot>,
    settled_frames: SettledFrames,
    latest: Option<Published>,

    pending: OptionFuture<futures::future::BoxFuture<'static, (Pending, Option<Outcome>)>>,
    budget_wakeup: OptionFuture<futures::future::BoxFuture<'static, ()>>,

    boundary_schemes: BoundarySchemeStream,

    /// Round-robin position used to share the verify budget between peers.
    cursor: usize,

    /// Last watermark applied to every slot. New frames are checked against the
    /// live watermark before insertion, so unchanged progress needs no rescan.
    slots_pruned_through: Round,

    verify_limiter: RateLimiter<TContext>,
    metrics: Metrics,
}

impl<TContext, K> Actor<TContext, K>
where
    TContext: Clock + RuntimeMetrics + Spawner + Send + 'static,
    K: CertSink,
{
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        loop {
            self.try_dispatch();

            // Biased order keeps incoming peer frames last. A flood cannot delay
            // driver results, control changes, publications, or scheme updates.
            select! {
                biased;

                (pending, result) = &mut self.pending => {
                    self.pending = OptionFuture::none();
                    self.on_judged(pending, result).await;
                }

                Some(event) = self.config.transport.control.recv() => self.on_peer(event),

                Some(message) = self.config.mailbox.recv() => self.on_message(message),

                Some(scheme) = self.boundary_schemes.next() => match scheme {
                    Ok(epoch) => self.release_quarantines(epoch),
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        debug!(skipped, "boundary scheme notifications lagged");
                    }
                },

                _ = (&mut self.budget_wakeup).fuse() => {
                    self.budget_wakeup = OptionFuture::none();
                }

                Some(frame) = self.config.transport.frames.recv() => self.on_frame(frame),
            }
        }
    }

    fn on_peer(&mut self, event: PeerEvent) {
        match event {
            PeerEvent::Up(peer) => {
                if self.peers.contains_key(&peer) {
                    return;
                }

                let mut state = Peer { seen_round: None };

                if let Some(latest) = &self.latest {
                    match state.offer(
                        &self.config.transport.sender,
                        peer,
                        latest.round,
                        &latest.frame,
                    ) {
                        Ok(true) => {
                            self.metrics.relayed.inc();
                        }
                        Ok(false) => {}
                        Err(_) => {
                            self.metrics.relay_dropped.inc();
                        }
                    }
                }

                self.peers.insert(peer, state);
                self.metrics.peers.set(self.peers.len() as i64);
            }
            PeerEvent::Down(peer) => {
                if self.peers.remove(&peer).is_some() {
                    self.slots.remove(&peer);
                    self.metrics.peers.set(self.peers.len() as i64);
                    self.update_slot_metrics();
                }
            }
            PeerEvent::ProtocolBreach(peer) => self.penalize(peer),
        }
    }

    fn on_frame(&mut self, frame: Frame) {
        let Frame { peer, frame } = frame;

        if !self.peers.contains_key(&peer) {
            self.metrics.dropped_disconnected_peer.inc();
            return;
        }

        let id = keccak256(&frame);
        if let Some(round) = self.settled_frames.round(&id) {
            self.peers
                .get_mut(&peer)
                .expect("peer was checked above")
                .observe(round);
            self.metrics.dropped_replay.inc();
            return;
        }

        let Some(certificate) = decode(&frame) else {
            self.metrics.dropped_malformed.inc();
            self.penalize(peer);
            return;
        };

        let round = certificate.round();
        self.peers
            .get_mut(&peer)
            .expect("peer was checked above")
            .observe(round);

        if round <= self.watermark() {
            self.metrics.dropped_stale.inc();
            return;
        }

        // A peer may improve a candidate that has not consumed verification
        // work. However, once judgment starts replacing is not allowed to
        // make the peer on the hook in case the certificate turns out to be
        // forged. Should that happen the peer gets penalized.
        let replace = match self.slots.get(&peer) {
            None => true,
            Some(current) if current.state == SlotState::Ready => round > current.round,
            Some(_) => {
                self.metrics.dropped_locked_replacement.inc();
                false
            }
        };
        if !replace {
            return;
        }

        self.slots.insert(
            peer,
            Slot {
                round,
                certificate,
                frame,
                id,
                state: SlotState::Ready,
            },
        );
        self.update_slot_metrics();
    }

    fn on_message(&mut self, message: Message) {
        match message {
            Message::Publish { round, frame } => {
                // Keep one publication for the latest round. Repeating that round
                // retries only peers whose coordinator enqueue failed because
                // `offer` skips attempts accepted by the coordinator. Reuse the
                // cached bytes so another frame for the same round cannot replace
                // what we advertised.
                if let Some(latest) = &self.latest {
                    if latest.round > round {
                        return;
                    }
                    if latest.round == round {
                        let frame = latest.frame.clone();
                        self.relay(round, &frame, None);
                        return;
                    }
                }

                let id = keccak256(&frame);
                self.settled_frames.insert(id, round);
                self.forget(id);
                self.latest = Some(Published {
                    round,
                    frame: frame.clone(),
                });
                self.relay(round, &frame, None);
            }
        }
    }

    /// Releases live quarantines covered by an authenticated boundary scheme.
    fn release_quarantines(&mut self, installed: Epoch) {
        // Progress may make a quarantine stale while it waits. Prune before
        // changing states so metrics and release logs describe only live retries.
        // Dispatch repeats this guard, but an unchanged watermark does not rescan slots.
        self.prune_stale_slots();

        for (peer, slot) in &mut self.slots {
            let SlotState::NeedsScheme(required) = slot.state else {
                continue;
            };
            if required <= installed {
                debug!(
                    %peer,
                    %required,
                    %installed,
                    round = %slot.round,
                    digest = %slot.certificate.proposal.payload,
                    "releasing quarantined certificate after boundary scheme installation",
                );
                slot.state = SlotState::Ready;
            }
        }
        self.metrics.boundary_scheme_events.inc();
        self.update_slot_metrics();
    }

    /// Removes slots at or below the driver's watermark.
    ///
    /// Selection also checks the watermark, so this is bounded cleanup and not
    /// a correctness requirement.
    fn prune_stale_slots(&mut self) {
        let watermark = self.watermark();
        self.metrics
            .watermark_epoch
            .set(watermark.epoch().get() as i64);
        self.metrics
            .watermark_view
            .set(watermark.view().get() as i64);
        if watermark <= self.slots_pruned_through {
            return;
        }

        self.slots_pruned_through = watermark;
        self.slots.retain(|_, slot| slot.round > watermark);
        self.update_slot_metrics();
    }

    /// Starts the next fair judgement if the budget allows it.
    ///
    /// The actor selects a candidate before it spends a rate-limit token. Other
    /// events must not consume the verify budget. If no token is available, the
    /// actor schedules a wakeup because the waiting slot produces no new event.
    fn try_dispatch(&mut self) {
        if !self.pending.is_none() {
            return;
        }

        self.prune_stale_slots();

        let Some(peer) = self.next_candidate() else {
            return;
        };

        if let Err(not_until) = self.verify_limiter.check() {
            self.metrics.shed.inc();
            let wait = not_until.wait_time_from(self.context.current());
            self.budget_wakeup.replace(self.context.sleep(wait).boxed());
            return;
        }

        let (pending, certificate) = {
            let slot = self.slots.get_mut(&peer).expect("selected peer has a slot");
            debug_assert_eq!(slot.state, SlotState::Ready);
            slot.state = SlotState::Judging;

            (
                Pending {
                    peer,
                    round: slot.round,
                    id: slot.id,
                    frame: slot.frame.clone(),
                },
                slot.certificate.clone(),
            )
        };
        let receiver = self.config.sink.verify_and_apply(certificate);

        self.pending
            .replace(async move { (pending, receiver.await.ok()) }.boxed());
        self.metrics.dispatched.inc();
    }

    /// Picks the next peer in round-robin order.
    ///
    /// The actor does not select the highest round because the value is not yet
    /// verified. A peer could claim a large round and starve all other peers.
    fn next_candidate(&mut self) -> Option<PeerKey> {
        if self.slots.is_empty() {
            return None;
        }

        let watermark = self.watermark();
        let peers: Vec<PeerKey> = self.slots.keys().copied().collect();
        let start = self.cursor % peers.len();

        for offset in 0..peers.len() {
            let index = (start + offset) % peers.len();
            let peer = peers[index];
            let slot = &self.slots[&peer];

            if slot.round > watermark && slot.state == SlotState::Ready {
                self.cursor = index + 1;
                return Some(peer);
            }
        }

        None
    }

    async fn on_judged(&mut self, pending: Pending, result: Option<Outcome>) {
        let Some(result) = result else {
            // No result will arrive. Settle the frame so the actor does not send
            // the same slot again on every loop and consume the full budget.
            debug!("no judgement for certificate; treating it as settled");
            self.metrics.unanswered.inc();
            self.settled_frames.insert(pending.id, pending.round);
            self.forget(pending.id);
            return;
        };

        match result {
            Outcome::Admitted => {
                self.settled_frames.insert(pending.id, pending.round);
                self.metrics.admitted.inc();
                self.forward(pending.round, &pending.frame, pending.peer);
                self.forget(pending.id);
            }
            Outcome::Stale => {
                self.settled_frames.insert(pending.id, pending.round);
                self.metrics.stale.inc();
                self.forget(pending.id);
            }
            Outcome::Invalid => {
                self.settled_frames.insert(pending.id, pending.round);
                self.metrics.invalid.inc();
                self.forget(pending.id);
                self.penalize(pending.peer);
            }
            Outcome::NeedsScheme { epoch } => {
                // `NeedsScheme` is provisional.
                //
                // This means that we cannot get a definitive judgement for the pending certificate.
                // We might be lacking the scheme for the epoch the certificate requires or perhaps
                // the certificate is forged.
                //
                // Because of that, we do not forget it nor settle it, we are going to quarantine it
                // until the scheme for the epoch is installed.
                //
                // Once the scheme is installed, the pending certificate will be released and can be
                // settled, potentially punishing the peer if forgery is detected.
                self.metrics.needs_scheme.inc();
                self.quarantine(&pending, epoch);
            }
        }

        self.prune_stale_slots();
    }

    /// Forwards a verified certificate when peer forwarding is enabled.
    ///
    /// Local publications do not use this flag. Publishing a stored certificate
    /// is what makes it available to the network.
    fn forward(&mut self, round: Round, frame: &Bytes, from: PeerKey) {
        if !self.config.relay {
            return;
        }

        self.relay(round, frame, Some(from));
    }

    /// Highest applied follower round, or zero on a publish-only node.
    fn watermark(&self) -> Round {
        self.config
            .progress
            .as_ref()
            .map_or_else(Round::zero, FollowerProgress::watermark)
    }

    fn relay(&mut self, round: Round, frame: &Bytes, exclude: Option<PeerKey>) {
        let mut sent = 0u64;
        let mut full = 0u64;
        for (peer, state) in &mut self.peers {
            if Some(*peer) == exclude {
                continue;
            }
            match state.offer(&self.config.transport.sender, *peer, round, frame) {
                Ok(true) => sent += 1,
                Ok(false) => {}
                Err(_) => full += 1,
            }
        }

        self.metrics.relayed.inc_by(sent);
        self.metrics.relay_dropped.inc_by(full);
    }

    /// Removes every slot that holds the same frame bytes.
    ///
    /// A terminal judgement settles all identical copies. A missing scheme is
    /// not terminal, so that outcome does not call this method.
    fn forget(&mut self, id: FrameId) {
        self.slots.retain(|_, slot| slot.id != id);
        self.update_slot_metrics();
    }

    fn quarantine(&mut self, pending: &Pending, required: Epoch) {
        let Some(slot) = self.slots.get_mut(&pending.peer) else {
            return;
        };
        if slot.id != pending.id || slot.state != SlotState::Judging {
            return;
        }

        debug!(
            peer = %pending.peer,
            %required,
            certificate_epoch = %slot.certificate.epoch(),
            round = %pending.round,
            digest = %slot.certificate.proposal.payload,
            "quarantining certificate until an authenticated boundary installs its scheme",
        );
        slot.state = SlotState::NeedsScheme(required);
        self.update_slot_metrics();
    }

    fn update_slot_metrics(&self) {
        self.metrics.slots.set(self.slots.len() as i64);
        // The peer count is bounded and thus does not pose a performance concern here.
        let quarantined_cnt = self
            .slots
            .values()
            .filter(|slot| matches!(slot.state, SlotState::NeedsScheme(_)))
            .count() as i64;
        self.metrics.quarantined.set(quarantined_cnt);
    }

    fn penalize(&mut self, peer: PeerKey) {
        self.config.peer_control.penalize(peer);
        self.metrics.penalties.inc();
    }
}

fn decode(frame: &Bytes) -> Option<Certificate> {
    let payload = wire::decode(frame).ok()?;
    commonware_codec::DecodeExt::decode(payload).ok()
}

/// Bounded cache of settled or published frames and their rounds.
struct SettledFrames {
    seen: HashMap<FrameId, Round>,
    order: VecDeque<FrameId>,
    capacity: usize,
}

impl SettledFrames {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    fn round(&self, id: &FrameId) -> Option<Round> {
        self.seen.get(id).copied()
    }

    fn insert(&mut self, id: FrameId, round: Round) {
        if self.seen.insert(id, round).is_some() {
            return;
        }

        self.order.push_back(id);
        if self.order.len() > self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
    }
}
