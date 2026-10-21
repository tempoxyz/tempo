//! Typed node-facing ports and single-owner coordinator for deposit allowlist requests, which
//! RPC-only members relay to every quorum member.

use std::{
    collections::{HashMap, VecDeque},
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
    network::{MAX_ALLOWLIST_MESSAGE_SIZE, MAX_ALLOWLIST_PAYLOAD_SIZE},
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

/// A relayed request's ID and, once the node has answered, the encoded answer frame.
type AnsweredRequest = (u64, Option<Vec<u8>>);

/// Requests each relayer sent recently, oldest first.
#[derive(Debug, Default)]
struct Answered(HashMap<PublicKey, VecDeque<AnsweredRequest>>);

impl Answered {
    fn get(&self, peer: &PublicKey, id: u64) -> Option<&Option<Vec<u8>>> {
        self.0
            .get(peer)?
            .iter()
            .find_map(|(seen, answer)| (*seen == id).then_some(answer))
    }

    fn insert_pending(&mut self, peer: PublicKey, id: u64) {
        let requests = self.0.entry(peer).or_default();
        if requests.len() == ANSWERS_PER_RELAYER {
            requests.pop_front();
        }
        requests.push_back((id, None));
    }

    fn complete(&mut self, peer: &PublicKey, id: u64, frame: &[u8]) {
        if let Some((_, answer)) = self
            .0
            .get_mut(peer)
            .and_then(|requests| requests.iter_mut().find(|(seen, _)| *seen == id))
        {
            *answer = Some(frame.to_vec());
        }
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
    outstanding: HashMap<u64, Outstanding>,
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
            outstanding: HashMap::new(),
            answered: Answered::default(),
        }
    }

    pub(crate) async fn run(mut self) -> eyre::Result<()> {
        let mut retry = tokio::time::interval(RETRY_INTERVAL);
        retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = retry.tick() => self.retry(),
                Some(call) = self.calls.recv() => self.start(call),
                Some(answer) = self.answers.recv() => self.answer(answer),
                result = self.receiver.recv() => {
                    let (peer, bytes) = result
                        .map_err(|err| eyre::eyre!("allowlist channel receive failed: {err}"))?;
                    self.receive(peer, bytes.as_ref());
                }
            }
        }
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
        send_frame(&mut self.sender, unanswered.clone(), frame.clone());
        let request = Outstanding {
            frame,
            answers: Vec::with_capacity(unanswered.len()),
            unanswered,
            deadline: Instant::now() + REQUEST_TIMEOUT,
            reply,
        };
        if request.unanswered.is_empty() {
            request.finish();
        } else {
            self.outstanding.insert(id, request);
        }
    }

    /// Resend outstanding requests to the members that have not answered, return the ones past
    /// their deadline, and drop the ones whose caller is gone.
    fn retry(&mut self) {
        let now = Instant::now();
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
        for request in self.outstanding.values() {
            send_frame(
                &mut self.sender,
                request.unanswered.clone(),
                request.frame.clone(),
            );
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
                    self.answered.insert_pending(peer, id);
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
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::*;

    #[test]
    fn answered_keeps_each_relayers_recent_requests() {
        let relayer = PrivateKey::from_seed(1).public_key();
        let other = PrivateKey::from_seed(2).public_key();
        let mut answered = Answered::default();

        answered.insert_pending(relayer.clone(), 7);
        assert_eq!(answered.get(&relayer, 7), Some(&None));
        assert_eq!(answered.get(&other, 7), None);
        answered.complete(&relayer, 7, b"answer");
        assert_eq!(answered.get(&relayer, 7), Some(&Some(b"answer".to_vec())));
        // An answer for a request that was never handed to the node is not cached.
        answered.complete(&relayer, 8, b"stray");
        assert_eq!(answered.get(&relayer, 8), None);

        for id in 100..100 + ANSWERS_PER_RELAYER as u64 {
            answered.insert_pending(relayer.clone(), id);
        }
        assert_eq!(answered.get(&relayer, 7), None);
        assert_eq!(answered.get(&relayer, 100), Some(&None));
    }
}
