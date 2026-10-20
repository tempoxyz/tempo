//! Typed node-facing ports and single-owner coordinator for the backfill protocol.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Recipients, Sender as _, authenticated::lookup};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::{
    EncodedBlock, LeadershipSchedule, P2pPeerId, PeerTip,
    capabilities::{ANNOUNCEMENT_INTERVAL, LOCAL_CAPABILITIES_VERSION, PeerCapabilities},
    protocol::{RequestFrame, ResponseFrame},
    routing::{RoutingMembership, RoutingPolicy},
};

/// Hard limit for one backfill response generation.
const BACKFILL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Maximum time a peer may remain silent while holding a backfill reservation.
///
/// Commonware sender admission does not indicate whether a peer is connected. Each accepted block
/// refreshes this timeout, so active responses remain reserved while offline peers are retried.
const BACKFILL_RESPONSE_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(5);
const BACKFILL_BEHIND_COOLDOWN: Duration = Duration::from_secs(30);

type CommonwareSender = lookup::Sender<PublicKey, commonware_runtime::tokio::Context>;
type CommonwareReceiver = lookup::Receiver<PublicKey>;

/// Commands sent by node tasks to the backfill coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillCommand {
    /// Ask eligible peers for canonical blocks beginning at `start`.
    Request { start: u64 },
    /// Return one canonical block to the peer that requested it.
    SendBlock {
        peer: P2pPeerId,
        request_id: u64,
        block: EncodedBlock,
    },
    /// Finish one response page and advertise the responder's snapshot tip.
    Complete {
        peer: P2pPeerId,
        request_id: u64,
        tip: PeerTip,
    },
}

/// A process-lifetime request for canonical blocks from a node's provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillRequest {
    pub peer: P2pPeerId,
    pub request_id: u64,
    pub start: u64,
}

/// A response accepted for the active follower generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackfillResponse {
    Block { peer: P2pPeerId, block: Vec<u8> },
    Completed { peer: P2pPeerId, tip: PeerTip },
}

/// Bounded node-facing channels for backfill commands, serving requests, and responses.
pub struct BackfillPorts {
    pub commands: mpsc::Sender<BackfillCommand>,
    pub requests: mpsc::Receiver<BackfillRequest>,
    pub responses: mpsc::Receiver<BackfillResponse>,
}

/// Channels handed from the P2P runtime to the single backfill coordinator.
pub(crate) struct BackfillRuntimeChannels<Rq = CommonwareReceiver, Rs = CommonwareReceiver> {
    pub(crate) request_sender: CommonwareSender,
    pub(crate) request_receiver: Rq,
    pub(crate) response_sender: CommonwareSender,
    pub(crate) response_receiver: Rs,
    pub(crate) commands: mpsc::Receiver<BackfillCommand>,
    pub(crate) requests: mpsc::Sender<BackfillRequest>,
    pub(crate) responses: mpsc::Sender<BackfillResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    LeaderOnly,
    Fallback,
}

#[derive(Debug, Clone, Copy)]
struct OutstandingBackfill {
    request_id: u64,
    start: u64,
    sent_at: Instant,
    last_progress_at: Instant,
    kind: RequestKind,
}

impl OutstandingBackfill {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.sent_at) >= BACKFILL_RESPONSE_TIMEOUT
            || now.duration_since(self.last_progress_at) >= BACKFILL_RESPONSE_INACTIVITY_TIMEOUT
    }
}

#[derive(Debug, Default)]
struct BackfillJob {
    next_request_id: u64,
    outstanding: HashMap<PublicKey, OutstandingBackfill>,
    behind_until: HashMap<PublicKey, Instant>,
}

impl BackfillJob {
    fn begin_request(
        &mut self,
        peers: &[PublicKey],
        start: u64,
        kind: RequestKind,
        now: Instant,
    ) -> Option<(u64, Vec<PublicKey>)> {
        self.behind_until.retain(|_, until| now < *until);
        let request_peers = peers
            .iter()
            .filter(|peer| {
                self.outstanding
                    .get(*peer)
                    .is_none_or(|request| request.expired(now))
                    && !self.is_behind(peer, now)
            })
            .cloned()
            .collect::<Vec<_>>();
        if request_peers.is_empty() {
            return None;
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        for peer in &request_peers {
            self.outstanding.insert(
                peer.clone(),
                OutstandingBackfill {
                    request_id,
                    start,
                    sent_at: now,
                    last_progress_at: now,
                    kind,
                },
            );
        }
        Some((request_id, request_peers))
    }

    fn finish_send(&mut self, request_id: u64, admitted: &[PublicKey]) {
        self.outstanding
            .retain(|peer, request| request.request_id != request_id || admitted.contains(peer));
    }

    fn accepts(&self, peer: &PublicKey, request_id: u64, now: Instant) -> bool {
        self.outstanding
            .get(peer)
            .is_some_and(|request| request.request_id == request_id && !request.expired(now))
    }

    fn record_response(&mut self, peer: &PublicKey, request_id: u64, now: Instant) -> bool {
        let Some(request) = self.outstanding.get_mut(peer) else {
            return false;
        };
        if request.request_id != request_id || request.expired(now) {
            return false;
        }
        request.last_progress_at = now;
        true
    }

    fn is_unresponsive(&self, peer: &PublicKey, now: Instant) -> bool {
        self.outstanding
            .get(peer)
            .is_some_and(|request| request.expired(now))
    }

    fn should_wait_for_leader(&self, peer: &PublicKey, now: Instant) -> bool {
        // Keep the leader exclusive while its response page is active. Each block refreshes the
        // inactivity timeout; a silent leader yields to the fallback peers after one timeout.
        self.outstanding
            .get(peer)
            .is_some_and(|request| request.kind == RequestKind::LeaderOnly && !request.expired(now))
    }

    fn is_behind(&self, peer: &PublicKey, now: Instant) -> bool {
        self.behind_until
            .get(peer)
            .is_some_and(|until| now < *until)
    }

    fn mark_behind(&mut self, peer: PublicKey, now: Instant) {
        self.behind_until
            .insert(peer, now + BACKFILL_BEHIND_COOLDOWN);
    }

    fn complete(&mut self, peer: &PublicKey, request_id: u64, now: Instant) -> Option<u64> {
        if !self.accepts(peer, request_id, now) {
            return None;
        }
        self.outstanding.remove(peer).map(|request| request.start)
    }
}

/// Owns every outstanding backfill request and the two Commonware backfill protocols.
pub(crate) struct BackfillCoordinator<Rq = CommonwareReceiver, Rs = CommonwareReceiver> {
    local: PublicKey,
    membership: RoutingMembership,
    leadership: LeadershipSchedule,
    request_sender: CommonwareSender,
    request_receiver: Rq,
    response_sender: CommonwareSender,
    response_receiver: Rs,
    commands: mpsc::Receiver<BackfillCommand>,
    requests: mpsc::Sender<BackfillRequest>,
    responses: mpsc::Sender<BackfillResponse>,
    job: BackfillJob,
    capabilities: PeerCapabilities,
}

impl<Rq, Rs> BackfillCoordinator<Rq, Rs>
where
    Rq: commonware_p2p::Receiver<PublicKey = PublicKey>,
    Rs: commonware_p2p::Receiver<PublicKey = PublicKey>,
{
    pub(crate) fn new(
        local: PublicKey,
        membership: RoutingMembership,
        leadership: LeadershipSchedule,
        capabilities: PeerCapabilities,
        channels: BackfillRuntimeChannels<Rq, Rs>,
    ) -> Self {
        Self {
            local,
            membership,
            leadership,
            request_sender: channels.request_sender,
            request_receiver: channels.request_receiver,
            response_sender: channels.response_sender,
            response_receiver: channels.response_receiver,
            commands: channels.commands,
            requests: channels.requests,
            responses: channels.responses,
            job: BackfillJob::default(),
            capabilities,
        }
    }

    pub(crate) async fn run(mut self) -> eyre::Result<()> {
        let mut announcements = tokio::time::interval(ANNOUNCEMENT_INTERVAL);
        announcements.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = announcements.tick() => {
                    let frame = ResponseFrame::Capabilities(LOCAL_CAPABILITIES_VERSION).encode().expect("fixed-size announcement");
                    let _ = self.response_sender.send(
                        Recipients::Some(self.membership.other_peers(&self.local)), frame, false,
                    );
                }
                command = self.commands.recv() => {
                    let command = command.ok_or_else(|| eyre::eyre!("backfill command channel closed unexpectedly"))?;
                    self.handle_command(command).await?;
                }
                result = self.request_receiver.recv() => {
                    let (peer, bytes) = result.map_err(|err| eyre::eyre!("backfill request receive failed: {err}"))?;
                    self.handle_request(peer, bytes.as_ref()).await?;
                }
                result = self.response_receiver.recv() => {
                    let (peer, bytes) = result.map_err(|err| eyre::eyre!("backfill response receive failed: {err}"))?;
                    self.handle_response(peer, bytes.as_ref()).await?;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: BackfillCommand) -> eyre::Result<()> {
        match command {
            BackfillCommand::Request { start } => self.request_blocks(start).await,
            BackfillCommand::SendBlock {
                peer,
                request_id,
                block,
            } => {
                let is_remote_member =
                    RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
                        .is_remote_member(&peer);
                if !is_remote_member {
                    warn!(target: "zone::p2p", %peer, "Ignoring backfill block addressed to an unknown peer");
                    return Ok(());
                }
                let block = if self.capabilities.supports_witnesses(&peer, Instant::now()) {
                    block.encode()
                } else {
                    block.block
                };
                let frame = match (ResponseFrame::Block { request_id, block }).encode() {
                    Ok(frame) => frame,
                    Err(err) => {
                        error!(target: "zone::p2p", %peer, %err, "Backfill block exceeds the P2P response frame size limit");
                        return Ok(());
                    }
                };
                let _ = self
                    .response_sender
                    .send(Recipients::Some(vec![peer]), frame, true);
                Ok(())
            }
            BackfillCommand::Complete {
                peer,
                request_id,
                tip,
            } => {
                let is_remote_member =
                    RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
                        .is_remote_member(&peer);
                if !is_remote_member {
                    warn!(target: "zone::p2p", %peer, "Ignoring backfill completion addressed to an unknown peer");
                    return Ok(());
                }
                let frame = ResponseFrame::Complete { request_id, tip }
                    .encode()
                    .expect("completion frames have a fixed size");
                let _ = self
                    .response_sender
                    .send(Recipients::Some(vec![peer]), frame, true);
                Ok(())
            }
        }
    }

    async fn request_blocks(&mut self, start: u64) -> eyre::Result<()> {
        let policy = RoutingPolicy::new(&self.local, &self.membership, &self.leadership);
        let (candidates, leader) = (
            policy.backfill_candidates(),
            policy.preferred_backfill_leader(),
        );
        let now = Instant::now();
        let leader_first = match &leader {
            Some(leader) => candidates.contains(leader) && !self.job.is_unresponsive(leader, now),
            None => false,
        };
        let mut attempts = Vec::with_capacity(2);
        if let Some(leader) = leader.as_ref().filter(|_| leader_first) {
            attempts.push(vec![leader.clone()]);
        }
        attempts.push(candidates);

        // When a usable leader exists, `attempts` contains a leader-only pass followed
        // by a pass over all eligible peers. If there's no leader, then go to the peers directly.
        // The job prevents a peer from receiving duplicate requests while an earlier response
        // is still in flight.
        for (attempt, sources) in attempts.into_iter().enumerate() {
            let kind = if leader_first && attempt == 0 {
                RequestKind::LeaderOnly
            } else {
                RequestKind::Fallback
            };

            // Reserve eligible peers and assign a request ID. Peers with a live outstanding
            // request are skipped, so each peer has at most one active request.
            let request = self.job.begin_request(&sources, start, kind, now);
            let Some((request_id, request_peers)) = request else {
                debug!(target: "zone::p2p", start, sources = sources.len(), leader_only = kind == RequestKind::LeaderOnly, "Skipping block backfill request because all eligible peers already have outstanding responses");
                if kind == RequestKind::LeaderOnly
                    && leader
                        .as_ref()
                        .is_some_and(|leader| self.job.should_wait_for_leader(leader, now))
                {
                    debug!(target: "zone::p2p", start, "Keeping the backfill leader as the sole source while its request is still pending");
                    break;
                }
                continue;
            };

            // Send the request to the selected peers.
            let request_frame = RequestFrame { request_id, start }.encode().to_vec();
            let admitted = self.request_sender.send(
                Recipients::Some(request_peers.clone()),
                request_frame,
                true,
            );

            self.job.finish_send(request_id, &admitted);
            if admitted.is_empty() {
                debug!(target: "zone::p2p", request_id, start, requested = request_peers.len(), leader_only = kind == RequestKind::LeaderOnly, "Block backfill request was not admitted for any peer");
                // Try the next attempt, if one was constructed.
                continue;
            }

            // Record requests sent through the all-peers path. This path is used when no
            // leader-only request is available (or when the attempt didn't reach a peer).
            if kind == RequestKind::Fallback {
                metrics::counter!("zone_p2p_backfill_requests_without_leader_total").increment(1);
            }
            debug!(target: "zone::p2p", request_id, start, admitted = admitted.len(), requested = request_peers.len(), sources = sources.len(), leader_only = kind == RequestKind::LeaderOnly, "Submitted block backfill request");
            break;
        }
        Ok(())
    }

    async fn handle_request(&mut self, peer: PublicKey, bytes: &[u8]) -> eyre::Result<()> {
        let request = match RequestFrame::decode(bytes) {
            Ok(request) => request,
            Err(err) => {
                warn!(target: "zone::p2p", %peer, size = bytes.len(), %err, "Ignoring malformed backfill request");
                return Ok(());
            }
        };
        let is_remote_member = RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
            .is_remote_member(&peer);
        if !is_remote_member {
            warn!(target: "zone::p2p", %peer, "Ignoring backfill request from ineligible peer");
            return Ok(());
        }
        self.requests
            .send(BackfillRequest {
                peer,
                request_id: request.request_id,
                start: request.start,
            })
            .await
            .map_err(|_| eyre::eyre!("backfill request event channel closed"))
    }

    async fn handle_response(&mut self, peer: PublicKey, bytes: &[u8]) -> eyre::Result<()> {
        let frame = match ResponseFrame::decode(bytes) {
            Ok(frame) => frame,
            Err(err) => {
                warn!(target: "zone::p2p", %peer, size = bytes.len(), %err, "Ignoring malformed backfill response");
                return Ok(());
            }
        };
        if let ResponseFrame::Capabilities(version) = frame {
            // Capability advertisements are independent of leadership and outstanding requests.
            if RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
                .is_remote_member(&peer)
            {
                self.capabilities.announce(peer, version, Instant::now());
            }
            return Ok(());
        }
        let may_accept = RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
            .may_accept_backfill_response(&peer);
        if !may_accept {
            warn!(target: "zone::p2p", %peer, "Ignoring backfill response from ineligible peer");
            return Ok(());
        }
        let received_at = Instant::now();
        match frame {
            ResponseFrame::Capabilities(_) => unreachable!("handled before backfill routing"),
            ResponseFrame::Block { request_id, block } => {
                if !self.job.record_response(&peer, request_id, received_at) {
                    warn!(target: "zone::p2p", %peer, request_id, "Ignoring unsolicited or stale backfill block");
                    return Ok(());
                }
                self.responses
                    .send(BackfillResponse::Block { peer, block })
                    .await
                    .map_err(|_| eyre::eyre!("backfill response event channel closed"))?;
            }
            ResponseFrame::Complete { request_id, tip } => {
                let Some(requested_start) = self.job.complete(&peer, request_id, received_at)
                else {
                    warn!(target: "zone::p2p", %peer, request_id, "Ignoring unsolicited or stale backfill completion");
                    return Ok(());
                };
                if tip.zone_height.saturating_add(1) < requested_start {
                    warn!(target: "zone::p2p", %peer, request_id, requested_start, tip_height = tip.zone_height, "Backfill peer is behind the requested range; trying other eligible peers");
                    self.job.mark_behind(peer, received_at);
                    self.request_blocks(requested_start).await?;
                    return Ok(());
                }
                self.responses
                    .send(BackfillResponse::Completed { peer, tip })
                    .await
                    .map_err(|_| eyre::eyre!("backfill response event channel closed"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        BACKFILL_BEHIND_COOLDOWN, BACKFILL_RESPONSE_INACTIVITY_TIMEOUT, BackfillJob, RequestKind,
    };
    use crate::protocol::{PeerTip, ResponseFrame};
    use alloy_primitives::B256;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    fn peer(seed: u64) -> crate::P2pPeerId {
        PrivateKey::from_seed(seed).public_key()
    }

    fn tip() -> PeerTip {
        PeerTip {
            zone_height: 7,
            zone_hash: B256::repeat_byte(0x11),
            tempo_block_number: 13,
            tempo_block_hash: B256::repeat_byte(0x22),
        }
    }

    #[test]
    fn leader_request_expires_and_replacement_uses_wrapped_ids() {
        let leader = peer(1);
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (first, peers) = job
            .begin_request(
                std::slice::from_ref(&leader),
                7,
                RequestKind::LeaderOnly,
                now,
            )
            .unwrap();
        job.finish_send(first, &peers);
        let before_timeout = now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT / 2;
        let at_timeout = now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT;
        assert!(!job.is_unresponsive(&leader, before_timeout));
        assert!(job.accepts(&leader, first, before_timeout));
        assert!(job.should_wait_for_leader(&leader, before_timeout));
        assert!(job.is_unresponsive(&leader, at_timeout));
        assert_eq!(job.complete(&leader, first, at_timeout), None);
        let (replacement, peers) = job
            .begin_request(
                std::slice::from_ref(&leader),
                8,
                RequestKind::LeaderOnly,
                at_timeout,
            )
            .unwrap();
        job.finish_send(replacement, &peers);
        assert_ne!(replacement, first);
        assert!(!job.accepts(&leader, first, at_timeout));
        assert_eq!(job.complete(&leader, first, at_timeout), None);
        assert!(job.accepts(&leader, replacement, at_timeout));
        assert_eq!(job.complete(&leader, replacement, at_timeout), Some(8));
    }

    #[test]
    fn behind_peer_is_bypassed_until_its_cooldown_expires() {
        let leader = peer(1);
        let alternate = peer(2);
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (request_id, peers) = job
            .begin_request(
                std::slice::from_ref(&leader),
                11,
                RequestKind::LeaderOnly,
                now,
            )
            .unwrap();
        job.finish_send(request_id, &peers);

        assert_eq!(job.complete(&leader, request_id, now), Some(11));
        job.mark_behind(leader.clone(), now);

        let (_, peers) = job
            .begin_request(
                &[leader.clone(), alternate.clone()],
                11,
                RequestKind::Fallback,
                now,
            )
            .unwrap();
        assert_eq!(peers, vec![alternate]);

        assert!(
            job.begin_request(
                std::slice::from_ref(&leader),
                11,
                RequestKind::LeaderOnly,
                now + BACKFILL_BEHIND_COOLDOWN
            )
            .is_some()
        );
    }

    #[test]
    fn malformed_completion_does_not_consume_outstanding_request() {
        let peer = peer(1);
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (request_id, peers) = job
            .begin_request(std::slice::from_ref(&peer), 7, RequestKind::Fallback, now)
            .unwrap();
        job.finish_send(request_id, &peers);

        let mut malformed = vec![1];
        malformed.extend_from_slice(&request_id.to_be_bytes());
        malformed.extend_from_slice(&[0; PeerTip::ENCODED_LEN - 1]);
        assert!(ResponseFrame::decode(&malformed).is_err());
        assert!(job.accepts(&peer, request_id, now));
        assert_eq!(job.complete(&peer, request_id, now), Some(7));
        assert_eq!(
            ResponseFrame::decode(
                &ResponseFrame::Complete {
                    request_id,
                    tip: tip()
                }
                .encode()
                .unwrap()
            ),
            Ok(ResponseFrame::Complete {
                request_id,
                tip: tip()
            })
        );
    }

    #[test]
    fn leader_only_retry_does_not_fan_out_when_next_page_starts_before_timeout() {
        let leader = peer(1);
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (request_id, peers) = job
            .begin_request(
                std::slice::from_ref(&leader),
                7,
                RequestKind::LeaderOnly,
                now,
            )
            .unwrap();
        job.finish_send(request_id, &peers);

        let responded_at = now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT / 2;
        assert!(job.record_response(&leader, request_id, responded_at));

        let retry_at =
            now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT / 4;
        // A partial response can advance the follower to the next page before the leader sends
        // the completion for this one. Progress refreshes the leader reservation, so it still
        // covers a retry after the original send would have timed out.
        assert!(job.should_wait_for_leader(&leader, retry_at));
        assert!(
            job.begin_request(
                std::slice::from_ref(&leader),
                8,
                RequestKind::LeaderOnly,
                retry_at,
            )
            .is_none()
        );
        assert!(job.should_wait_for_leader(&leader, retry_at));

        let stalled_at = responded_at + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT;
        assert!(job.is_unresponsive(&leader, stalled_at));
        assert!(!job.should_wait_for_leader(&leader, stalled_at));
    }

    #[test]
    fn fallback_retries_only_peers_silent_for_timeout() {
        let active = peer(1);
        let silent = peer(2);
        let candidates = [active.clone(), silent.clone()];
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (first, peers) = job
            .begin_request(&candidates, 7, RequestKind::Fallback, now)
            .unwrap();
        job.finish_send(first, &peers);

        let responded_at = now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT / 2;
        assert!(job.record_response(&active, first, responded_at));

        let retry_at = now + BACKFILL_RESPONSE_INACTIVITY_TIMEOUT;
        let (replacement, peers) = job
            .begin_request(&candidates, 7, RequestKind::Fallback, retry_at)
            .unwrap();
        assert_eq!(peers, vec![silent.clone()]);
        job.finish_send(replacement, &peers);
        assert!(job.accepts(&active, first, retry_at));
        assert!(!job.accepts(&silent, first, retry_at));
        assert!(job.accepts(&silent, replacement, retry_at));
    }

    #[test]
    fn completed_fallback_page_reuses_backup_for_next_page() {
        let leader = peer(1);
        let backup = peer(2);
        let candidates = [leader.clone(), backup.clone()];
        let now = std::time::Instant::now();
        let mut job = BackfillJob::default();
        let (page_one, peers) = job
            .begin_request(&candidates, 7, RequestKind::Fallback, now)
            .unwrap();
        job.finish_send(page_one, &peers);
        assert_eq!(job.complete(&backup, page_one, now), Some(7));

        let retry_at = now + Duration::from_secs(1);
        assert!(!job.should_wait_for_leader(&leader, retry_at));
        let (page_two, peers) = job
            .begin_request(&candidates, 8, RequestKind::Fallback, retry_at)
            .unwrap();
        assert_eq!(peers, vec![backup.clone()]);
        assert_eq!(job.complete(&backup, page_two, retry_at), Some(8));
    }
}
