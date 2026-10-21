//! Typed node-facing ports and single-owner coordinator for deposit allowlist requests, which
//! RPC-only members relay to every quorum member.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Recipients, Sender as _, authenticated::lookup};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, MissedTickBehavior},
};
use tracing::{debug, warn};

use crate::{
    LeadershipSchedule, P2pPeerId,
    network::{
        ALLOWLIST_FRAME_BURST, ALLOWLIST_FRAMES_PER_SECOND, MAX_ALLOWLIST_MESSAGE_SIZE,
        MAX_ALLOWLIST_PAYLOAD_SIZE,
    },
    protocol::AllowlistFrame,
    routing::{RoutingMembership, RoutingPolicy},
};

/// How long a request waits for every quorum member before returning.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How often a request is resent to the quorum members that have not answered it.
const RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Answers kept for each relayer, so a resent request gets the original answer instead of being
/// handled again. Covers more requests than one relayer keeps in flight at once.
const ANSWERS_PER_RELAYER: usize = 8;
const PORT_BACKLOG: usize = 16;
/// Interval between paced request frames, matching the channel quota's rate.
const FRAME_INTERVAL: Duration =
    Duration::from_nanos(1_000_000_000 / ALLOWLIST_FRAMES_PER_SECOND as u64);
/// Paced frames that may be sent back to back. Half the quota's burst, leaving room for frames
/// that arrive bunched together.
const PACED_BURST: u32 = ALLOWLIST_FRAME_BURST / 2;

type CommonwareSender = lookup::Sender<PublicKey, commonware_runtime::tokio::Context>;
type CommonwareReceiver = lookup::Receiver<PublicKey>;
type Reply = oneshot::Sender<Result<AllowlistResponses, AllowlistRequestError>>;

/// Node-facing deposit allowlist channels.
pub struct AllowlistPorts {
    /// Relays requests to every quorum member. Only RPC-only members can relay.
    pub client: AllowlistClient,
    /// Requests relayed by RPC-only members, delivered on quorum members.
    pub requests: mpsc::Receiver<AllowlistRequest>,
}

/// Relays allowlist requests from an RPC-only member to every quorum member.
#[derive(Clone)]
pub struct AllowlistClient {
    calls: mpsc::Sender<Call>,
}

impl AllowlistClient {
    /// Send `payload` to every quorum member, resending it to members that have not answered,
    /// and return the answers once all have answered or the 10 s timeout passes. Dropping the
    /// future stops the resends.
    pub async fn request(
        &self,
        payload: Vec<u8>,
    ) -> Result<AllowlistResponses, AllowlistRequestError> {
        let (reply, response) = oneshot::channel();
        self.calls
            .send(Call { payload, reply })
            .await
            .map_err(|_| AllowlistRequestError::Stopped)?;
        response.await.map_err(|_| AllowlistRequestError::Stopped)?
    }
}

/// Quorum members' answers to one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistResponses {
    pub answers: Vec<(P2pPeerId, Vec<u8>)>,
    /// Quorum members that did not answer before the timeout.
    pub unanswered: Vec<P2pPeerId>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistRequestError {
    #[error("only RPC-only members relay allowlist requests")]
    NotRelayer,
    #[error("request is {0} bytes; the limit is {MAX_ALLOWLIST_PAYLOAD_SIZE}")]
    TooLarge(usize),
    #[error("P2P runtime stopped")]
    Stopped,
}

/// A request relayed by an RPC-only member, answered with [`Self::respond`].
#[derive(Debug)]
pub struct AllowlistRequest {
    pub peer: P2pPeerId,
    pub payload: Vec<u8>,
    id: u64,
    answers: mpsc::Sender<Answer>,
}

impl AllowlistRequest {
    /// Answer the relayer. An answer over [`MAX_ALLOWLIST_PAYLOAD_SIZE`] is dropped, and the
    /// relayer reports this member as unanswered.
    pub async fn respond(self, payload: Vec<u8>) {
        let answer = Answer {
            peer: self.peer,
            id: self.id,
            payload,
        };
        let _ = self.answers.send(answer).await;
    }
}

pub(crate) struct Call {
    payload: Vec<u8>,
    reply: Reply,
}

#[derive(Debug)]
struct Answer {
    peer: PublicKey,
    id: u64,
    payload: Vec<u8>,
}

/// Coordinator ends of the [`AllowlistPorts`] channels.
pub(crate) struct AllowlistNodeChannels {
    calls: mpsc::Receiver<Call>,
    requests: mpsc::Sender<AllowlistRequest>,
}

pub(crate) fn allowlist_ports() -> (AllowlistPorts, AllowlistNodeChannels) {
    let (calls, calls_rx) = mpsc::channel(PORT_BACKLOG);
    let (requests_tx, requests) = mpsc::channel(PORT_BACKLOG);
    (
        AllowlistPorts {
            client: AllowlistClient { calls },
            requests,
        },
        AllowlistNodeChannels {
            calls: calls_rx,
            requests: requests_tx,
        },
    )
}

/// A relayed request still waiting for some quorum members.
struct Outstanding {
    frame: Vec<u8>,
    answers: Vec<(PublicKey, Vec<u8>)>,
    unanswered: Vec<PublicKey>,
    deadline: Instant,
    last_sent: Instant,
    reply: Reply,
}

impl Outstanding {
    fn finish(self) {
        let _ = self.reply.send(Ok(AllowlistResponses {
            answers: self.answers,
            unanswered: self.unanswered,
        }));
    }
}

/// A request a relayer sent recently.
#[derive(Debug)]
struct AnsweredRequest {
    id: u64,
    /// The encoded answer frame, once the node has answered.
    answer: Option<Vec<u8>>,
    /// When the request may be forgotten: the relayer stops resending it by then.
    expires_at: Instant,
}

/// Requests each relayer sent recently, oldest first.
#[derive(Debug, Default)]
struct Answered(HashMap<PublicKey, VecDeque<AnsweredRequest>>);

impl Answered {
    fn get(&self, peer: &PublicKey, id: u64) -> Option<&Option<Vec<u8>>> {
        self.0
            .get(peer)?
            .iter()
            .find_map(|request| (request.id == id).then_some(&request.answer))
    }

    fn insert_pending(&mut self, peer: PublicKey, id: u64, now: Instant) {
        let requests = self.0.entry(peer).or_default();
        if requests.len() == ANSWERS_PER_RELAYER {
            requests.pop_front();
        }
        requests.push_back(AnsweredRequest {
            id,
            answer: None,
            expires_at: now + REQUEST_TIMEOUT,
        });
    }

    fn complete(&mut self, peer: &PublicKey, id: u64, frame: &[u8]) {
        if let Some(request) = self
            .0
            .get_mut(peer)
            .and_then(|requests| requests.iter_mut().find(|request| request.id == id))
        {
            request.answer = Some(frame.to_vec());
        }
    }

    /// Forget requests the relayer no longer resends, so answers such as full snapshots are not
    /// kept for the life of the process.
    fn expire(&mut self, now: Instant) {
        self.0.retain(|_, requests| {
            requests.retain(|request| request.expires_at > now);
            !requests.is_empty()
        });
    }
}

/// Paces request frames to the allowlist channel quota. A receiver enforces the quota by pausing
/// every channel from the sender, which would also delay blocks and transactions.
#[derive(Debug)]
struct Pacer {
    available: u32,
    refilled_at: Instant,
}

impl Pacer {
    fn new(now: Instant) -> Self {
        Self {
            available: PACED_BURST,
            refilled_at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let earned =
            now.saturating_duration_since(self.refilled_at).as_nanos() / FRAME_INTERVAL.as_nanos();
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.available = self.available.saturating_add(earned).min(PACED_BURST);
        self.refilled_at = if self.available == PACED_BURST {
            now
        } else {
            self.refilled_at + FRAME_INTERVAL * earned
        };
    }

    /// When the next frame may be sent; in the past if one may be sent now.
    fn ready_at(&mut self, now: Instant) -> Instant {
        self.refill(now);
        if self.available > 0 {
            now
        } else {
            self.refilled_at + FRAME_INTERVAL
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        let available = self.available > 0;
        self.available -= u32::from(available);
        available
    }
}

/// Owns the allowlist channel: relays the node's requests and serves relayed ones.
pub(crate) struct AllowlistCoordinator<B, R = CommonwareReceiver> {
    local: PublicKey,
    membership: RoutingMembership,
    leadership: LeadershipSchedule,
    blocker: B,
    sender: CommonwareSender,
    receiver: R,
    calls: mpsc::Receiver<Call>,
    requests: mpsc::Sender<AllowlistRequest>,
    answers_tx: mpsc::Sender<Answer>,
    answers: mpsc::Receiver<Answer>,
    next_id: u64,
    /// Stable IDs break ties when requests were last sent at the same time.
    outstanding: BTreeMap<u64, Outstanding>,
    pacer: Pacer,
    answered: Answered,
}

impl<B, R> AllowlistCoordinator<B, R>
where
    B: commonware_p2p::Blocker<PublicKey = PublicKey>,
    R: commonware_p2p::Receiver<PublicKey = PublicKey>,
{
    pub(crate) fn new(
        local: PublicKey,
        membership: RoutingMembership,
        leadership: LeadershipSchedule,
        blocker: B,
        (sender, receiver): (CommonwareSender, R),
        node: AllowlistNodeChannels,
    ) -> Self {
        let (answers_tx, answers) = mpsc::channel(PORT_BACKLOG);
        // Seeded from the clock so a quorum member's cached answer from before a restart cannot
        // match a new request.
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos() as u64);
        Self {
            local,
            membership,
            leadership,
            blocker,
            sender,
            receiver,
            calls: node.calls,
            requests: node.requests,
            answers_tx,
            answers,
            next_id,
            outstanding: BTreeMap::new(),
            pacer: Pacer::new(Instant::now()),
            answered: Answered::default(),
        }
    }

    pub(crate) async fn run(mut self) -> eyre::Result<()> {
        let mut retry = tokio::time::interval(RETRY_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            // New requests wait while the pacer has no frame to spare.
            let ready_at = self.prepare_calls();
            let ready = ready_at <= Instant::now();
            tokio::select! {
                _ = retry.tick() => {}
                () = tokio::time::sleep_until(ready_at), if !ready => {}
                Some(call) = self.calls.recv(), if ready => self.start(call),
                Some(answer) = self.answers.recv() => self.answer(answer),
                result = self.receiver.recv() => {
                    let (peer, bytes) = result
                        .map_err(|err| eyre::eyre!("allowlist channel receive failed: {err}"))?;
                    self.receive(peer, bytes.as_ref());
                }
            }
        }
    }

    /// Service due resends before allowing a new call to spend a pacing token.
    fn prepare_calls(&mut self) -> Instant {
        self.retry();
        self.pacer.ready_at(Instant::now())
    }

    fn policy(&self) -> RoutingPolicy<'_> {
        RoutingPolicy::new(&self.local, &self.membership, &self.leadership)
    }

    fn start(&mut self, Call { payload, reply }: Call) {
        let policy = self.policy();
        if !policy.may_relay_allowlist_update() {
            let _ = reply.send(Err(AllowlistRequestError::NotRelayer));
            return;
        }
        if payload.len() > MAX_ALLOWLIST_PAYLOAD_SIZE {
            let _ = reply.send(Err(AllowlistRequestError::TooLarge(payload.len())));
            return;
        }
        let unanswered = policy.allowlist_update_recipients();
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let frame = AllowlistFrame::Request { id, payload }.encode();
        // Without a frame to spare, the next retry sends it.
        if self.pacer.try_take(Instant::now()) {
            send_frame(&mut self.sender, unanswered.clone(), frame.clone());
        }
        let request = Outstanding {
            frame,
            answers: Vec::with_capacity(unanswered.len()),
            unanswered,
            deadline: Instant::now() + REQUEST_TIMEOUT,
            last_sent: Instant::now(),
            reply,
        };
        if request.unanswered.is_empty() {
            request.finish();
        } else {
            self.outstanding.insert(id, request);
        }
    }

    /// Resend outstanding requests to the members that have not answered, as far as the pacer
    /// allows, return the ones past their deadline, and drop the ones whose caller is gone. Also
    /// forgets served requests that have expired.
    fn retry(&mut self) {
        let now = Instant::now();
        self.answered.expire(now);
        let finished = self
            .outstanding
            .iter()
            .filter(|(_, request)| request.reply.is_closed() || now >= request.deadline)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in finished {
            if let Some(request) = self.outstanding.remove(&id) {
                request.finish();
            }
        }
        // Rotate retries by the last send, so unanswered reads cannot repeatedly consume
        // every paced frame ahead of a later write.
        let mut requests = self.outstanding.iter_mut().collect::<Vec<_>>();
        requests.sort_by_key(|(id, request)| (request.last_sent, **id));
        for (_, request) in requests {
            if now < request.last_sent + RETRY_INTERVAL || !self.pacer.try_take(now) {
                break;
            }
            send_frame(
                &mut self.sender,
                request.unanswered.clone(),
                request.frame.clone(),
            );
            request.last_sent = now;
        }
    }

    fn receive(&mut self, peer: PublicKey, bytes: &[u8]) {
        if bytes.len() > MAX_ALLOWLIST_MESSAGE_SIZE {
            commonware_p2p::block!(
                self.blocker,
                peer,
                allowlist_frame_size_bytes = bytes.len(),
                max_allowlist_frame_size_bytes = MAX_ALLOWLIST_MESSAGE_SIZE,
                "Blocking peer for oversized allowlist frame"
            );
            return;
        }
        let policy = self.policy();
        match AllowlistFrame::decode(bytes) {
            Ok(AllowlistFrame::Request { id, payload })
                if policy.may_accept_allowlist_update(&peer) =>
            {
                self.serve(peer, id, payload)
            }
            Ok(AllowlistFrame::Response { id, payload })
                if policy.may_accept_allowlist_ack(&peer) =>
            {
                self.record(peer, id, payload)
            }
            Ok(_) => {
                metrics::counter!("zone_p2p_role_invalid_messages_dropped_total").increment(1);
                warn!(target: "zone::p2p", %peer, "Ignoring allowlist frame from role-invalid peer");
            }
            Err(err) => {
                warn!(target: "zone::p2p", %peer, %err, "Ignoring malformed allowlist frame");
            }
        }
    }

    /// Hand a relayed request to the node once, and resend the answer for a repeated one.
    fn serve(&mut self, peer: PublicKey, id: u64, payload: Vec<u8>) {
        match self.answered.get(&peer, id) {
            Some(Some(frame)) => send_frame(&mut self.sender, vec![peer], frame.clone()),
            // The node is still answering it.
            Some(None) => {}
            None => {
                let request = AllowlistRequest {
                    peer: peer.clone(),
                    payload,
                    id,
                    answers: self.answers_tx.clone(),
                };
                if self.requests.try_send(request).is_ok() {
                    self.answered.insert_pending(peer, id, Instant::now());
                } else {
                    // The relayer resends it.
                    metrics::counter!("zone_p2p_allowlist_frames_dropped_total").increment(1);
                    debug!(target: "zone::p2p", %peer, id, "Dropping allowlist request the node is not ready for");
                }
            }
        }
    }

    fn answer(&mut self, Answer { peer, id, payload }: Answer) {
        let frame = AllowlistFrame::Response { id, payload }.encode();
        if frame.len() > MAX_ALLOWLIST_MESSAGE_SIZE {
            // Left pending, so resends are ignored and the relayer times out on this member.
            metrics::counter!("zone_p2p_allowlist_frames_dropped_total").increment(1);
            warn!(target: "zone::p2p", %peer, id, allowlist_frame_size_bytes = frame.len(), max_allowlist_frame_size_bytes = MAX_ALLOWLIST_MESSAGE_SIZE, "Dropping oversized allowlist answer");
            return;
        }
        self.answered.complete(&peer, id, &frame);
        send_frame(&mut self.sender, vec![peer], frame);
    }

    fn record(&mut self, peer: PublicKey, id: u64, payload: Vec<u8>) {
        let Some(request) = self.outstanding.get_mut(&id) else {
            debug!(target: "zone::p2p", %peer, id, "Ignoring allowlist answer for a finished request");
            return;
        };
        let Some(index) = request.unanswered.iter().position(|member| *member == peer) else {
            return;
        };
        request.unanswered.swap_remove(index);
        request.answers.push((peer, payload));
        if request.unanswered.is_empty()
            && let Some(request) = self.outstanding.remove(&id)
        {
            request.finish();
        }
    }
}

/// Send `frame` to `peers` at low priority, keeping admin traffic behind block replication. The
/// relayer resends a frame that is not admitted or is delayed past its retry interval.
fn send_frame(sender: &mut CommonwareSender, peers: Vec<PublicKey>, frame: Vec<u8>) {
    if peers.is_empty() {
        return;
    }
    let requested = peers.len();
    let admitted = sender.send(Recipients::Some(peers), frame, false).len();
    if admitted < requested {
        metrics::counter!("zone_p2p_allowlist_frames_dropped_total")
            .increment((requested - admitted) as u64);
        debug!(target: "zone::p2p", requested, admitted, "Allowlist frame was not admitted for every peer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use commonware_runtime::Runner as _;

    use crate::{P2pNetworkId, ZoneManifest, network};

    #[test]
    fn due_retries_take_tokens_before_queued_calls_and_rotate() {
        commonware_runtime::tokio::Runner::new(Default::default()).start(|context| async move {
            let keys = [1, 2, 3, 4].map(PrivateKey::from_seed);
            let mut input = format!("leader_ed25519_public_key = \"{}\"\n", keys[0].public_key());
            for (index, key) in keys.iter().enumerate() {
                input.push_str(&format!(
                    "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\naddress = \"127.0.0.1:{}\"\nrpc_only = {}\n",
                    key.public_key(), 9200 + index, index == 3,
                ));
                if index != 3 {
                    input.push_str(&format!("secp256k1_address = \"0x{:040x}\"\n", index + 1));
                }
            }
            let manifest = ZoneManifest::parse(&input).unwrap();
            let leadership = manifest.leadership_schedule();
            leadership.publish(manifest.bootstrap_leadership()).unwrap();
            let (mut network, blocker, _) = network::instantiate(
                &context, &manifest, 1, keys[3].clone(), "127.0.0.1:9203".parse().unwrap(),
                false, P2pNetworkId::new(1, alloy_primitives::Address::repeat_byte(1)),
            ).unwrap();
            let channel = network.register(network::ALLOWLIST_CHANNEL, network::allowlist_quota());
            let (ports, node) = allowlist_ports();
            let mut coordinator = AllowlistCoordinator::new(
                keys[3].public_key(), RoutingMembership::from_manifest(&manifest), leadership,
                blocker, channel, node,
            );
            let now = Instant::now();
            let old = now - RETRY_INTERVAL;
            let mut replies = Vec::new();
            // Four unanswered reads and a later write all need retransmission.
            for id in 0..5 {
                let (reply, response) = oneshot::channel();
                replies.push(response);
                coordinator.outstanding.insert(id, Outstanding {
                    frame: AllowlistFrame::Request { id, payload: vec![] }.encode(),
                    answers: vec![], unanswered: vec![keys[0].public_key()],
                    deadline: now + REQUEST_TIMEOUT, last_sent: old, reply,
                });
            }
            // New read calls are always available to consume fresh pacing tokens.
            for _ in 0..PORT_BACKLOG {
                let (reply, response) = oneshot::channel();
                replies.push(response);
                ports.client.calls.try_send(Call { payload: vec![], reply }).unwrap();
            }
            // Each iteration earns one token. All five outstanding requests, including the
            // last write, must get a resend before any queued call can consume that token.
            for id in 0..5 {
                coordinator.pacer.available = 0;
                coordinator.pacer.refilled_at = Instant::now() - FRAME_INTERVAL;
                let ready_at = coordinator.prepare_calls();
                assert!(coordinator.outstanding[&id].last_sent >= now);
                assert!(ready_at > Instant::now(), "new calls must wait for the next token");
                assert_eq!(coordinator.calls.len(), PORT_BACKLOG);
            }
            // Before the next retry is due, a fresh token is available to new calls.
            coordinator.pacer.available = 0;
            coordinator.pacer.refilled_at = Instant::now() - FRAME_INTERVAL;
            assert!(coordinator.prepare_calls() <= Instant::now());
            assert!(coordinator.pacer.try_take(Instant::now()));
            drop(replies);
        });
    }

    #[test]
    fn pacer_holds_frames_to_the_channel_rate() {
        let start = Instant::now();
        let mut pacer = Pacer::new(start);
        for _ in 0..PACED_BURST {
            assert!(pacer.try_take(start));
        }
        assert!(!pacer.try_take(start));
        assert_eq!(pacer.ready_at(start), start + FRAME_INTERVAL);
        assert!(!pacer.try_take(start + FRAME_INTERVAL - Duration::from_nanos(1)));
        assert!(pacer.try_take(start + FRAME_INTERVAL));
        assert!(!pacer.try_take(start + FRAME_INTERVAL));
        // Idle time refills at most a burst.
        let later = start + FRAME_INTERVAL * 100;
        for _ in 0..PACED_BURST {
            assert!(pacer.try_take(later));
        }
        assert!(!pacer.try_take(later));
        // Partial progress toward the next frame carries over.
        let partial = later + FRAME_INTERVAL / 2;
        assert!(!pacer.try_take(partial));
        assert!(pacer.try_take(later + FRAME_INTERVAL));
    }

    #[test]
    fn answered_keeps_each_relayers_recent_requests() {
        let relayer = PrivateKey::from_seed(1).public_key();
        let other = PrivateKey::from_seed(2).public_key();
        let mut answered = Answered::default();
        let now = Instant::now();

        answered.insert_pending(relayer.clone(), 7, now);
        assert_eq!(answered.get(&relayer, 7), Some(&None));
        assert_eq!(answered.get(&other, 7), None);
        answered.complete(&relayer, 7, b"answer");
        assert_eq!(answered.get(&relayer, 7), Some(&Some(b"answer".to_vec())));
        // An answer for a request that was never handed to the node is not cached.
        answered.complete(&relayer, 8, b"stray");
        assert_eq!(answered.get(&relayer, 8), None);

        for id in 100..100 + ANSWERS_PER_RELAYER as u64 {
            answered.insert_pending(relayer.clone(), id, now);
        }
        assert_eq!(answered.get(&relayer, 7), None);
        assert_eq!(answered.get(&relayer, 100), Some(&None));
    }

    #[test]
    fn answered_forgets_requests_the_relayer_stopped_resending() {
        let relayer = PrivateKey::from_seed(1).public_key();
        let mut answered = Answered::default();
        let start = Instant::now();
        answered.insert_pending(relayer.clone(), 1, start);
        answered.complete(&relayer, 1, b"snapshot");
        answered.insert_pending(relayer.clone(), 2, start + Duration::from_secs(1));

        answered.expire(start + REQUEST_TIMEOUT - Duration::from_nanos(1));
        assert_eq!(answered.get(&relayer, 1), Some(&Some(b"snapshot".to_vec())));
        answered.expire(start + REQUEST_TIMEOUT);
        assert_eq!(answered.get(&relayer, 1), None);
        assert_eq!(answered.get(&relayer, 2), Some(&None));
        answered.expire(start + Duration::from_secs(1) + REQUEST_TIMEOUT);
        assert!(answered.0.is_empty());
    }
}
