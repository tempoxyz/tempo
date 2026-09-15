//! The `tempo/1` actor.
//!
//! The actor publishes certificates after marshal confirms they are durable. In
//! follow mode, it also admits and schedules peer certificates for verification.
//! It uses the runtime clock so scheduling and rate limits work in deterministic
//! tests.

use std::{collections::HashMap, num::NonZeroU32};

use alloy_primitives::{B256, Bytes, keccak256};
use commonware_consensus::{
    Epochable as _,
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round},
};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Quota, RateLimiter, Spawner, spawn_cell,
};
use futures::{FutureExt as _, future::BoxFuture};
use tempo_node::gossip::{Frame, PeerControl, PeerEvent, TransportHandle, TransportSender, wire};
use tokio::{select, sync::mpsc};
use tracing::debug;

use super::{
    Certificate, CertificateError, CertificateMailbox, Marshal, ingress::Message, metrics::Metrics,
};
use crate::utils::OptionFuture;

/// Hash of the exact frame bytes used to match duplicate peer slots.
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
    certificate: Certificate,
    id: FrameId,
    state: SlotState,
    ready_ticket: ReadyTicket,
}

struct Peer {
    /// Highest round this peer claimed or this node accepted for outbound routing.
    seen_round: Option<Round>,
    /// Pending inbound certificate work, kept until it settles or the peer disconnects.
    slot: Option<Slot>,
}

impl Peer {
    fn has_seen(&self, round: Round) -> bool {
        self.seen_round.is_some_and(|seen| seen >= round)
    }

    fn observe(&mut self, round: Round) {
        debug_assert!(!self.has_seen(round));
        self.seen_round = Some(round);
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
        if self.has_seen(round) {
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

type PendingJudgement = (Pending, Option<eyre::Result<(), CertificateError>>);

type PeerKey = alloy_primitives::B512;

/// Inputs and limits for the `tempo/1` actor.
pub(crate) struct Config<K, P, M = crate::alias::marshal::Mailbox> {
    /// Maximum inbound certificate judgements per second across all peers.
    ///
    /// In follow mode, each signature check runs on the driver task, which also
    /// acknowledges blocks to marshal. This limit bounds how much a flood can
    /// delay block import.
    pub(crate) verify_rate: NonZeroU32,
    /// The consensus layer's end of the `tempo/1` transport.
    pub(crate) transport: TransportHandle,
    /// Epoch layout used to interpret gap-free marshal block updates.
    pub(crate) epoch_strategy: FixedEpocher,
    /// Finalized height processed before marshal starts reporting updates.
    pub(crate) finalized_floor: Height,
    /// Reputation control for peers that misbehave.
    pub(crate) peer_control: P,
    /// Capability used to verify and process inbound peer certificates.
    pub(crate) driver: K,
    /// Retrieves certificates after marshal announces their persisted tips.
    pub(crate) marshal: M,
}

pub(super) fn init<TContext, K, P, M>(
    context: TContext,
    config: Config<K, P, M>,
    mailbox: mpsc::UnboundedReceiver<Message>,
) -> Actor<TContext, K, P, M>
where
    TContext: Clock + RuntimeMetrics + Spawner,
{
    let metrics = Metrics::init(&context);
    let quota = Quota::per_second(config.verify_rate);
    let limiter_context = context.child("verify_limiter");
    let info = config
        .epoch_strategy
        .containing(config.finalized_floor)
        .expect("fixed epoch strategy supports every height");
    let latest_processed_epoch = if info.last() == config.finalized_floor {
        info.epoch().next()
    } else {
        info.epoch()
    };

    Actor {
        verify_limiter: RateLimiter::direct_with_clock(quota, limiter_context),
        context: ContextCell::new(context),
        config,
        mailbox,
        latest_processed_epoch,
        peers: HashMap::new(),
        latest: None,
        pending: OptionFuture::none(),
        budget_wakeup: OptionFuture::none(),
        latest_verified_round: Round::zero(),
        next_ready_ticket: 0,
        metrics,
    }
}

pub(crate) struct Actor<TContext: Clock, K, P, M = crate::alias::marshal::Mailbox> {
    context: ContextCell<TContext>,
    config: Config<K, P, M>,
    mailbox: mpsc::UnboundedReceiver<Message>,

    /// Active logical `tempo/1` peers and their certificate slots.
    ///
    /// Publication and scheduling scan every entry, so the actor relies on the
    /// RLPx network's peer limit to keep this map small.
    peers: HashMap<PeerKey, Peer>,
    latest: Option<Published>,

    pending: OptionFuture<BoxFuture<'static, PendingJudgement>>,
    budget_wakeup: OptionFuture<futures::future::BoxFuture<'static, ()>>,

    /// Highest verified round learned from driver judgment or a durable marshal tip.
    latest_verified_round: Round,
    /// Highest epoch whose scheme is available from processed boundary blocks.
    latest_processed_epoch: Epoch,
    /// Next available ticket to assign to a slot.
    next_ready_ticket: ReadyTicket,

    verify_limiter: RateLimiter<TContext>,
    metrics: Metrics,
}

impl<TContext, K, P, M> Actor<TContext, K, P, M>
where
    TContext: Clock + RuntimeMetrics + Spawner + Send + 'static,
    K: CertificateMailbox,
    P: PeerControl,
    M: Marshal,
{
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        loop {
            // Biased order keeps incoming peer frames last. A flood cannot delay
            // driver results, budget wakeups, control changes, publications, or
            // marshal progress updates.
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

                Some(message) = self.mailbox.recv() => self.on_message(message).await,

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

                let mut state = Peer {
                    seen_round: None,
                    slot: None,
                };

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

        let Some(certificate) = decode(&frame) else {
            self.metrics.dropped_malformed.inc();
            self.penalize(peer);
            return;
        };

        let round = certificate.round();
        let state = self.peers.get_mut(&peer).expect("peer was checked above");
        if state.has_seen(round) {
            self.metrics.dropped_replay.inc();
            return;
        }
        state.observe(round);

        if round <= self.latest_verified_round {
            self.metrics.dropped_stale.inc();
            return;
        }

        let id = keccak256(&frame);

        // A higher-round replacement keeps the slot's ticket because the ticket
        // tracks how long the peer has waited, not the age of the certificate.
        //
        // Once verification starts, the certificate is locked until it is
        // settled or removed. This prevents a peer from replacing a quarantined
        // certificate before the missing scheme arrives and verification can retry.
        let state = self.peers.get_mut(&peer).expect("peer was checked above");
        let inserted = match state.slot.as_mut() {
            Some(current) => {
                if current.state != SlotState::Ready {
                    self.metrics.dropped_locked_replacement.inc();
                    return;
                }

                current.certificate = certificate;
                current.id = id;
                false
            }
            None => {
                let ready_ticket = Self::issue_ready_ticket(&mut self.next_ready_ticket);
                state.slot = Some(Slot {
                    certificate,
                    id,
                    state: SlotState::Ready,
                    ready_ticket,
                });
                true
            }
        };

        if inserted {
            self.update_slot_metrics();
        }
        self.try_dispatch();
    }

    async fn on_message(&mut self, message: Message) {
        match message {
            Message::FinalizedTip { round, height } => {
                let Some(certificate) = self.config.marshal.get_finalization(height).await else {
                    debug!(%height, "finalized tip is missing its persisted certificate");
                    return;
                };
                debug_assert_eq!(round, certificate.proposal.round);
                self.advance_latest_verified_round(round);
                let frame = wire::encode(&certificate).freeze().into();
                self.publish(round, frame);
            }
            Message::FinalizedBlock { height } => {
                let info = self
                    .config
                    .epoch_strategy
                    .containing(height)
                    .expect("fixed epoch strategy supports every height");
                if info.last() == height {
                    let installed = info.epoch().next();
                    if installed > self.latest_processed_epoch {
                        self.latest_processed_epoch = installed;
                        self.release_quarantines(installed);
                    }
                }
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

        self.latest = Some(Published {
            round,
            frame: frame.clone(),
        });
        self.relay(round, &frame);
    }

    /// Releases live quarantines covered by a processed epoch boundary.
    fn release_quarantines(&mut self, available: Epoch) {
        let mut releasable: Vec<(ReadyTicket, PeerKey, Epoch)> = self
            .peers
            .iter()
            .filter_map(|(peer, state)| {
                let slot = state.slot.as_ref()?;
                match slot.state {
                    SlotState::NeedsScheme(epoch) if epoch <= available => {
                        Some((slot.ready_ticket, *peer, epoch))
                    }
                    _ => None,
                }
            })
            .collect();
        releasable.sort_unstable_by_key(|(ticket, peer, _)| (*ticket, *peer));
        let released = !releasable.is_empty();

        for (_, peer, epoch) in releasable {
            let ready_ticket = Self::issue_ready_ticket(&mut self.next_ready_ticket);
            let slot = self
                .peers
                .get_mut(&peer)
                .and_then(|state| state.slot.as_mut())
                .expect("selected quarantine has a slot");

            debug!(
                %peer,
                %epoch,
                %available,
                round = %slot.certificate.round(),
                digest = %slot.certificate.proposal.payload,
                "releasing quarantined certificate after processing its epoch boundary",
            );
            slot.state = SlotState::Ready;
            slot.ready_ticket = ready_ticket;
        }
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

        // Verified progress settles pending work from every peer at this round or below.
        for state in self.peers.values_mut() {
            if state
                .slot
                .as_ref()
                .is_some_and(|slot| slot.certificate.round() <= round)
            {
                state.slot = None;
            }
        }
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
            let slot = self
                .peers
                .get_mut(&peer)
                .and_then(|state| state.slot.as_mut())
                .expect("selected peer has a slot");
            debug_assert_eq!(slot.state, SlotState::Ready);
            slot.state = SlotState::Judging;
            let round = slot.certificate.round();

            (
                Pending {
                    peer,
                    round,
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
        self.peers
            .iter()
            .filter_map(|(peer, state)| {
                let slot = state.slot.as_ref()?;
                (slot.state == SlotState::Ready).then_some((slot.ready_ticket, *peer))
            })
            .min()
            .map(|(_, peer)| peer)
    }

    fn issue_ready_ticket(next_ready_ticket: &mut ReadyTicket) -> ReadyTicket {
        let ticket = *next_ready_ticket;
        *next_ready_ticket = ticket.checked_add(1).expect("ready ticket space exhausted");
        ticket
    }

    fn on_judged(&mut self, pending: Pending, result: Option<eyre::Result<(), CertificateError>>) {
        let Some(result) = result else {
            // No result will arrive. Settle the frame so the actor does not send
            // the same slot again on every loop and consume the full budget.
            debug!("no judgement for certificate; treating it as settled");
            self.metrics.unanswered.inc();
            let _peers = self.remove_frame_slots(pending.id);
            return;
        };

        match result {
            Ok(()) => {
                self.advance_latest_verified_round(pending.round);
                self.metrics.settled.inc();
            }
            Err(CertificateError::Invalid) => {
                self.metrics.invalid.inc();
                for peer in self.remove_frame_slots(pending.id) {
                    self.penalize(peer);
                }
            }
            Err(CertificateError::NeedsScheme { epoch }) => {
                // A missing scheme is provisional because the sender may be
                // honest after an identity rotation. A boundary update can race
                // with this judgement, so check the retained watermark after
                // quarantining instead of relying only on the update.
                self.metrics.needs_scheme.inc();
                self.quarantine(&pending, epoch);
                self.release_quarantines(self.latest_processed_epoch);
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

    /// Removes every slot that holds the same frame bytes and returns the owning peers.
    ///
    /// A terminal judgement settles all identical copies. A missing scheme is
    /// not terminal, so that outcome does not call this method.
    fn remove_frame_slots(&mut self, id: FrameId) -> Vec<PeerKey> {
        let mut removed = Vec::new();
        for (peer, state) in &mut self.peers {
            if state.slot.as_ref().is_some_and(|slot| slot.id == id) {
                state.slot = None;
                removed.push(*peer);
            }
        }
        self.update_slot_metrics();
        removed
    }

    fn quarantine(&mut self, pending: &Pending, required: Epoch) {
        let Some(slot) = self
            .peers
            .get_mut(&pending.peer)
            .and_then(|state| state.slot.as_mut())
        else {
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
            "quarantining certificate until marshal processes its epoch boundary",
        );
        slot.state = SlotState::NeedsScheme(required);
        self.update_slot_metrics();
    }

    fn update_slot_metrics(&self) {
        let mut slots = 0;
        let mut quarantined = 0;
        for slot in self.peers.values().filter_map(|state| state.slot.as_ref()) {
            slots += 1;
            if matches!(slot.state, SlotState::NeedsScheme(_)) {
                quarantined += 1;
            }
        }

        self.metrics.slots.set(slots);
        self.metrics.quarantined.set(quarantined);
    }

    fn penalize(&mut self, peer: PeerKey) {
        self.config.peer_control.penalize(peer);
        self.metrics.penalties.inc();
    }
}

fn decode(frame: &Bytes) -> Option<Certificate> {
    wire::decode(frame).ok()
}
