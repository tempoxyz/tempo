//! The `tempo/1` actor.
//!
//! The actor admits and schedules peer certificates for driver judgment, then
//! publishes certificates after marshal confirms they are durable. It uses the
//! runtime clock so scheduling and rate limits work in deterministic tests.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroU32,
    sync::Arc,
};

use alloy_primitives::{B256, Bytes, keccak256};
use commonware_codec::Encode as _;
use commonware_consensus::{
    Epochable as _,
    types::{Epoch, Round},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Quota, RateLimiter, Spawner, spawn_cell,
};
use futures::FutureExt as _;
use tempo_node::gossip::{Frame, PeerControl, PeerEvent, TransportHandle, TransportSender, wire};
use tokio::{select, sync::mpsc};
use tracing::debug;

use super::{
    Certificate, CertificateError, CertificateMailbox, Marshal, ingress::Message, metrics::Metrics,
};
use crate::utils::OptionFuture;

/// Hash of the exact frame bytes used to track settled or published frames.
///
/// Different certificates can name the same block. A key based on the block
/// would let a forged certificate suppress a valid certificate for that block.
type FrameId = B256;

/// A slot's position in the ready queue.
///
/// Stable admission order prevents peer churn from repeatedly overtaking and
/// starving a candidate when verification capacity is exhausted. The actor
/// dispatches the smallest ticket first. New slots and released quarantines join
/// the back of the queue, while replacements and rate-limit waits preserve their
/// position.
type ReadyTicket = u128;

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
    id: FrameId,
    state: SlotState,
    ready_ticket: ReadyTicket,
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
}

type PeerKey = alloy_primitives::B512;

/// Inputs and limits for the `tempo/1` actor.
pub(crate) struct Config<K, M = crate::alias::marshal::Mailbox> {
    /// Maximum driver judgements per second across all peers.
    ///
    /// Each signature check runs on the driver task, which also acknowledges
    /// blocks to marshal. This limit bounds how much a flood can delay block
    /// import. Initialization treats zero as one.
    pub(crate) verify_rate: u32,
    /// Frames remembered as already settled or published.
    pub(crate) recent_frames: usize,
    /// The consensus layer's end of the `tempo/1` transport.
    pub(crate) transport: TransportHandle,
    /// Marshal notifications that trigger durable publication and scheme retries.
    pub(crate) mailbox: mpsc::UnboundedReceiver<Message>,
    /// Reputation control for peers that misbehave.
    pub(crate) peer_control: Arc<dyn PeerControl>,
    /// Driver capability that verifies and processes peer certificates.
    pub(crate) driver: K,
    /// Retrieves certificates after marshal announces their persisted tips.
    pub(crate) marshal: M,
}

pub(crate) fn init<TContext, K, M>(context: TContext, config: Config<K, M>) -> Actor<TContext, K, M>
where
    TContext: Clock + RuntimeMetrics + Spawner,
{
    let metrics = Metrics::init(&context);
    let quota =
        Quota::per_second(NonZeroU32::new(config.verify_rate.max(1)).expect("clamped above zero"));
    let recent = SettledFrames::with_capacity(config.recent_frames);
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
        latest_verified_round: Round::zero(),
        next_ready_ticket: 0,
        metrics,
    }
}

pub(crate) struct Actor<TContext: Clock, K, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    config: Config<K, M>,

    /// Active logical `tempo/1` peers.
    ///
    /// Publication scans every entry, so the actor relies on the RLPx network's
    /// peer limit to keep this map small.
    peers: HashMap<PeerKey, Peer>,
    /// At most one certificate slot per active peer.
    ///
    /// Scheduling and cleanup scan every entry. This map is no larger than
    /// `peers` and relies on the same peer limit.
    slots: HashMap<PeerKey, Slot>,
    settled_frames: SettledFrames,
    latest: Option<Published>,

    pending: OptionFuture<
        futures::future::BoxFuture<'static, (Pending, Option<eyre::Result<(), CertificateError>>)>,
    >,
    budget_wakeup: OptionFuture<futures::future::BoxFuture<'static, ()>>,

    /// Highest verified round learned from driver judgment or a durable marshal tip.
    latest_verified_round: Round,

    /// Next available ticket to assign to a slot.
    next_ready_ticket: ReadyTicket,

    verify_limiter: RateLimiter<TContext>,
    metrics: Metrics,
}

impl<TContext, K, M> Actor<TContext, K, M>
where
    TContext: Clock + RuntimeMetrics + Spawner + Send + 'static,
    K: CertificateMailbox,
    M: Marshal,
{
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        loop {
            // Biased order keeps incoming peer frames last. A flood cannot delay
            // driver results, budget wakeups, control changes, publications, or
            // scheme updates.
            select! {
                biased;

                (pending, result) = &mut self.pending => {
                    self.pending = OptionFuture::none();
                    self.on_judged(pending, result);
                    self.try_dispatch();
                }

                _ = (&mut self.budget_wakeup).fuse() => {
                    self.budget_wakeup = OptionFuture::none();
                    self.try_dispatch();
                }

                Some(event) = self.config.transport.control.recv() => self.on_peer(event),

                Some(message) = self.config.mailbox.recv() => self.on_message(message).await,

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

        if round <= self.latest_verified_round {
            self.metrics.dropped_stale.inc();
            return;
        }

        // A higher-round replacement keeps the slot's ticket because the ticket
        // tracks how long the peer has waited, not the age of the certificate.
        //
        // Once verification starts, the certificate is locked until it is
        // settled or removed. This prevents a peer from replacing a quarantined
        // certificate before the missing scheme arrives and verification can retry.
        if let Some(current) = self.slots.get_mut(&peer) {
            if current.state != SlotState::Ready {
                self.metrics.dropped_locked_replacement.inc();
                return;
            }
            if round <= current.round {
                return;
            }

            current.round = round;
            current.certificate = certificate;
            current.id = id;
            self.update_slot_metrics();
            self.try_dispatch();
            return;
        }

        let ready_ticket = self.issue_ready_ticket();
        self.slots.insert(
            peer,
            Slot {
                round,
                certificate,
                id,
                state: SlotState::Ready,
                ready_ticket,
            },
        );
        self.update_slot_metrics();
        self.try_dispatch();
    }

    async fn on_message(&mut self, message: Message) {
        match message {
            Message::BoundarySchemeInstalled { epoch } => self.release_quarantines(epoch),
            Message::FinalizedTip { round, height } => {
                let Some(certificate) = self.config.marshal.get_finalization(height).await else {
                    debug!(%height, "finalized tip is missing its persisted certificate");
                    return;
                };
                self.advance_latest_verified_round(round);
                let frame = wire::encode(&certificate.encode()).freeze().into();
                self.publish(round, frame);
            }
        }
    }

    fn publish(&mut self, round: Round, frame: Bytes) {
        // Keep one publication for the latest round. Repeating that round
        // retries only peers whose coordinator enqueue failed because `offer`
        // skips attempts accepted by the coordinator. Reuse the cached bytes so
        // another frame for the same round cannot replace what we advertised.
        if let Some(latest) = &self.latest {
            if latest.round > round {
                return;
            }
            if latest.round == round {
                let frame = latest.frame.clone();
                self.relay(round, &frame);
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
        self.relay(round, &frame);
    }

    /// Releases live quarantines covered by an authenticated boundary scheme.
    fn release_quarantines(&mut self, installed: Epoch) {
        let mut releasable: Vec<(ReadyTicket, PeerKey, Epoch)> = self
            .slots
            .iter()
            .filter_map(|(peer, slot)| match slot.state {
                SlotState::NeedsScheme(epoch) if epoch <= installed => {
                    Some((slot.ready_ticket, *peer, epoch))
                }
                _ => None,
            })
            .collect();
        releasable.sort_unstable_by_key(|(ticket, peer, _)| (*ticket, *peer));
        let released = !releasable.is_empty();

        for (_, peer, epoch) in releasable {
            let ready_ticket = self.issue_ready_ticket();
            let slot = self
                .slots
                .get_mut(&peer)
                .expect("selected quarantine has a slot");

            debug!(
                %peer,
                %epoch,
                %installed,
                round = %slot.round,
                digest = %slot.certificate.proposal.payload,
                "releasing quarantined certificate after boundary scheme installation",
            );
            slot.state = SlotState::Ready;
            slot.ready_ticket = ready_ticket;
        }
        self.metrics.boundary_scheme_events.inc();
        self.update_slot_metrics();
        if released {
            self.try_dispatch();
        }
    }

    /// Advances verified progress and removes slots that it makes stale.
    fn advance_latest_verified_round(&mut self, round: Round) {
        if round <= self.latest_verified_round {
            return;
        }

        self.latest_verified_round = round;
        self.metrics
            .latest_verified_epoch
            .set(round.epoch().get() as i64);
        self.metrics
            .latest_verified_view
            .set(round.view().get() as i64);

        self.slots.retain(|_, slot| slot.round > round);
        self.update_slot_metrics();
    }

    /// Starts the next fair judgement if the budget allows it.
    ///
    /// This runs only when ready work changes or dispatch capacity becomes
    /// available, keeping the linear candidate scan off unrelated frame paths.
    ///
    /// A rate-limit miss leaves ready order unchanged. Since a waiting slot emits
    /// no event, a wakeup retries it when the budget replenishes.
    fn try_dispatch(&mut self) {
        if !self.pending.is_none() || !self.budget_wakeup.is_none() {
            return;
        }

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
                },
                slot.certificate.clone(),
            )
        };

        let receiver = self.config.driver.process_certificate(certificate);
        self.pending
            .replace(async move { (pending, receiver.await.ok()) }.boxed());

        self.metrics.dispatched.inc();
    }

    /// Picks the ready peer that has waited longest.
    ///
    /// The actor does not select the highest round because the value is not yet
    /// verified. A peer could claim a large round and starve all other peers.
    fn next_candidate(&self) -> Option<PeerKey> {
        self.slots
            .iter()
            .filter_map(|(peer, slot)| {
                (slot.state == SlotState::Ready).then_some((slot.ready_ticket, *peer))
            })
            .min()
            .map(|(_, peer)| peer)
    }

    fn issue_ready_ticket(&mut self) -> ReadyTicket {
        let ticket = self.next_ready_ticket;
        self.next_ready_ticket = self
            .next_ready_ticket
            .checked_add(1)
            .expect("ready ticket space exhausted");
        ticket
    }

    fn on_judged(&mut self, pending: Pending, result: Option<eyre::Result<(), CertificateError>>) {
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
            Ok(()) => {
                self.advance_latest_verified_round(pending.round);
                self.settled_frames.insert(pending.id, pending.round);
                self.metrics.settled.inc();
                self.forget(pending.id);
            }
            Err(CertificateError::Invalid) => {
                self.settled_frames.insert(pending.id, pending.round);
                self.metrics.invalid.inc();
                self.forget(pending.id);
                self.penalize(pending.peer);
            }
            Err(CertificateError::NeedsScheme { epoch }) => {
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
    }

    fn relay(&mut self, round: Round, frame: &Bytes) {
        let mut sent = 0u64;
        let mut full = 0u64;
        for (peer, state) in &mut self.peers {
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
        // The peer count is bounded and thus does not pose a performance concern here.
        let quarantined_cnt = self
            .slots
            .values()
            .filter(|slot| matches!(slot.state, SlotState::NeedsScheme(_)))
            .count() as i64;

        self.metrics.slots.set(self.slots.len() as i64);
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
