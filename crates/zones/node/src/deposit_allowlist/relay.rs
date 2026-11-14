//! Relays `zoneAdmin` allowlist requests from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist and no admin key. It
//! checks each write's admin signature and deadline, then sends the request unchanged to every
//! quorum member, which checks it again, applies it to its own persisted list, and answers. The
//! call returns only after every member answered, so a success means every sequencer will enforce
//! the change on its next block. [`zone_p2p::AllowlistClient`] owns delivery: request IDs,
//! resends, the timeout, and answering resent requests without handling them twice.
//!
//! [`mirror_leader`] keeps every RPC-only node's [`AllowlistMirror`] in step with the leader's
//! list, with or without the admin, so the node rejects transfers the list does not admit on
//! submission instead of forwarding them. Reads need no signature.

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Address, Bytes};
use jsonrpsee::{
    core::RpcResult,
    types::{
        ErrorObjectOwned,
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    },
};
use reth_tasks::TaskExecutor;
use reth_transaction_pool::TransactionPool;
use serde::{Deserialize, Serialize};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{Instrument, debug, info, warn};
use zone_p2p::{
    AllowlistClient, AllowlistRequest, AllowlistResponses, LeadershipSchedule, P2pPeerId,
};

use super::{
    AllowlistMirror, AllowlistPolicy, DepositAllowlist, DepositAllowlistAdmin,
    DepositAllowlistApiServer, DepositAllowlistError, DepositAllowlistSnapshot,
    DepositAllowlistStatus, SequencerAllowlistStatus, SignedWrite, Write, evict_unlisted_transfers,
};

/// Reads relayed at once. Reads need no signature, so they have their own limit and cannot keep
/// writes from being relayed.
const MAX_CONCURRENT_READS: usize = 4;

/// How long an RPC-only node waits between checks of the leader's allowlist. Writes this node
/// relays refresh its copy immediately; writes relayed through another node show up here within
/// this delay.
const MIRROR_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// How long to wait instead while the leader reports no written list, so Zones that never enable
/// the allowlist are not polled every second. The first write this node relays still refreshes
/// at once.
const IDLE_MIRROR_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// An allowlist request relayed to every sequencer.
#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Write(SignedWrite),
    Get,
    Status,
}

/// A sequencer's answer to a relayed request.
type Answer = Result<Response, DepositAllowlistError>;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Response {
    /// The write is persisted, leaving the list at this status.
    Applied(DepositAllowlistStatus),
    /// The list, answering `Get`.
    Snapshot(DepositAllowlistSnapshot),
    /// The list's status, answering `Status`.
    Status(DepositAllowlistStatus),
}

type RelayResult = RpcResult<Vec<(P2pPeerId, Response)>>;

/// Why a sequencer gave no response to a relayed request.
#[derive(Debug)]
enum Failure {
    /// The sequencer rejected the request.
    Rejected(DepositAllowlistError),
    /// The sequencer's answer did not decode.
    Malformed(serde_json::Error),
    /// The sequencer did not answer before the relay timeout.
    Unanswered,
}

/// Each sequencer's outcome for one relayed request.
struct Answers(Vec<(P2pPeerId, Result<Response, Failure>)>);

impl Answers {
    /// Every sequencer's response, or an error naming the sequencers that rejected the request or
    /// did not answer.
    fn into_responses(self) -> RelayResult {
        let mut responses = Vec::with_capacity(self.0.len());
        let mut errors = Vec::new();
        let mut unanswered = Vec::new();
        // Invalid params only when every sequencer that failed rejected the request itself.
        let mut code = INVALID_PARAMS_CODE;
        for (peer, outcome) in self.0 {
            match outcome {
                Ok(response) => responses.push((peer, response)),
                Err(Failure::Rejected(error)) => {
                    if error.code() != INVALID_PARAMS_CODE {
                        code = INTERNAL_ERROR_CODE;
                    }
                    errors.push(format!("{peer}: {error}"));
                }
                Err(Failure::Malformed(err)) => {
                    code = INTERNAL_ERROR_CODE;
                    errors.push(format!("{peer}: malformed answer: {err}"));
                }
                Err(Failure::Unanswered) => {
                    code = INTERNAL_ERROR_CODE;
                    unanswered.push(peer.to_string());
                }
            }
        }
        if !unanswered.is_empty() {
            errors.push(format!(
                "no acknowledgement from sequencers {}",
                unanswered.join(", ")
            ));
        }
        if errors.is_empty() {
            Ok(responses)
        } else {
            Err(ErrorObjectOwned::owned(code, errors.join("; "), None::<()>))
        }
    }

    /// The outcome of `peer`, `None` if the request did not go to it.
    fn outcome_of(self, peer: &P2pPeerId) -> Option<Result<Response, Failure>> {
        self.0
            .into_iter()
            .find_map(|(answered, outcome)| (answered == *peer).then_some(outcome))
    }
}

/// `zoneAdmin` API on an RPC-only node, relaying requests to every sequencer.
#[derive(Clone)]
pub(crate) struct AllowlistRelay {
    /// Rejects writes the sequencers would reject before they use P2P bandwidth.
    admin: DepositAllowlistAdmin,
    client: AllowlistClient,
    /// This node's copy of the sequencers' list, refreshed after every write it relays.
    mirror: AllowlistMirror,
    executor: TaskExecutor,
    /// Held by the one write in flight, so every sequencer receives this node's writes in the
    /// same order.
    write: Arc<Semaphore>,
    reads: Arc<Semaphore>,
}

impl AllowlistRelay {
    pub(crate) fn new(
        client: AllowlistClient,
        admin: DepositAllowlistAdmin,
        mirror: AllowlistMirror,
        executor: TaskExecutor,
    ) -> Self {
        Self {
            admin,
            client,
            mirror,
            executor,
            write: Arc::new(Semaphore::new(1)),
            reads: Arc::new(Semaphore::new(MAX_CONCURRENT_READS)),
        }
    }

    /// Send `request` to every sequencer and return each one's response, or an error naming the
    /// sequencers that rejected it or did not answer.
    async fn relay(&self, request: &Request) -> RelayResult {
        answers(&self.client, None, request).await?.into_responses()
    }

    /// Relay `request` in a free `lane` slot, failing fast with `Busy` when there is none. The
    /// relay runs to completion even if the caller disconnects, keeping the slot until every
    /// sequencer answered or timed out: a cancelled read cannot free its slot early, and the next
    /// write cannot overtake this one.
    async fn relay_in(&self, lane: &Arc<Semaphore>, request: Request) -> RelayResult {
        let permit = lane
            .clone()
            .try_acquire_owned()
            .map_err(|_| DepositAllowlistError::Busy)?;
        let relay = self.clone();
        let (reply, response) = oneshot::channel();
        self.executor.spawn_task(async move {
            let result = relay.relay(&request).await;
            drop(permit);
            // A disconnected RPC caller no longer needs the result.
            if reply.send(result).is_err() {
                tracing::debug!(target: "zone::allowlist", "Allowlist caller disconnected before relay completed");
            }
        }.in_current_span());
        response
            .await
            .map_err(|err| relay_error(format!("allowlist relay task stopped: {err}")))?
    }

    async fn relay_read(&self, request: Request) -> RelayResult {
        self.relay_in(&self.reads, request).await
    }

    async fn relay_write(&self, write: SignedWrite) -> RpcResult<()> {
        self.admin.authorize(&write)?;
        let result = self.relay_in(&self.write, Request::Write(write)).await;
        // Some sequencers may have applied a write that failed elsewhere.
        self.mirror.request_refresh();
        let responses = result?;
        let unexpected = responses
            .into_iter()
            .filter(|(_, response)| !matches!(response, Response::Applied(_)))
            .map(|(peer, _)| peer.to_string())
            .collect::<Vec<_>>();
        if unexpected.is_empty() {
            Ok(())
        } else {
            Err(relay_error(format!(
                "unexpected write acknowledgement from {}",
                unexpected.join(", ")
            )))
        }
    }
}

impl DepositAllowlistApiServer for AllowlistRelay {
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.relay_write(SignedWrite {
            write: Write::Set { addresses, allowed },
            nonce,
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, allowed, "Relayed deposit allowlist update to every sequencer");
        Ok(())
    }

    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let count = addresses.len();
        self.relay_write(SignedWrite {
            write: Write::Replace { addresses },
            nonce,
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", count, "Relayed deposit allowlist replacement to every sequencer");
        Ok(())
    }

    async fn replace_deposit_allowlist_groups(
        &self,
        policy: AllowlistPolicy,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        let (groups, routers) = (policy.groups.len(), policy.routers.len());
        self.relay_write(SignedWrite {
            write: Write::ReplaceGroups { policy },
            nonce,
            deadline,
            signature,
        })
        .await?;
        info!(target: "zone::allowlist", groups, routers, "Relayed deposit allowlist groups to every sequencer");
        Ok(())
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<DepositAllowlistSnapshot> {
        let mut snapshots = Vec::new();
        for (peer, response) in self.relay_read(Request::Get).await? {
            let Response::Snapshot(snapshot) = response else {
                return Err(relay_error(format!(
                    "unexpected read acknowledgement from {peer}"
                )));
            };
            snapshots.push((peer, snapshot));
        }
        let Some((_, first)) = snapshots.first() else {
            return Err(relay_error("no sequencers to read from".to_owned()));
        };
        if snapshots.iter().all(|(_, snapshot)| {
            (snapshot.status.initialized, snapshot.status.list_hash)
                == (first.status.initialized, first.status.list_hash)
        }) {
            return Ok(first.clone());
        }
        let statuses = snapshots
            .iter()
            .map(|(peer, snapshot)| {
                let status = snapshot.status;
                if status.initialized {
                    format!(
                        "{peer}: nonce {}, {} entries, hash {}",
                        status.nonce, status.count, status.list_hash
                    )
                } else {
                    format!("{peer}: uninitialized")
                }
            })
            .collect::<Vec<_>>();
        Err(relay_error(format!(
            "sequencer allowlists differ; {}",
            statuses.join("; ")
        )))
    }

    async fn get_deposit_allowlist_status(&self) -> RpcResult<Vec<SequencerAllowlistStatus>> {
        self.relay_read(Request::Status)
            .await?
            .into_iter()
            .map(|(peer, response)| match response {
                Response::Status(status) => Ok(SequencerAllowlistStatus {
                    sequencer: Some(peer.to_string()),
                    status,
                }),
                _ => Err(relay_error(format!(
                    "unexpected status acknowledgement from {peer}"
                ))),
            })
            .collect()
    }
}

/// Answer requests relayed to this sequencer, applying writes to its list.
pub(crate) async fn apply_relayed_requests(
    allowlist: Option<DepositAllowlist>,
    mut requests: mpsc::Receiver<AllowlistRequest>,
) {
    while let Some(request) = requests.recv().await {
        let peer = request.peer.clone();
        let answer = match (
            &allowlist,
            serde_json::from_slice::<Request>(&request.payload),
        ) {
            (_, Err(err)) => {
                warn!(target: "zone::allowlist", %peer, %err, "Rejected malformed allowlist request");
                Err(DepositAllowlistError::Internal(format!(
                    "malformed allowlist request: {err}"
                )))
            }
            (None, Ok(_)) => Err(DepositAllowlistError::Disabled),
            (Some(allowlist), Ok(Request::Get)) => Ok(Response::Snapshot(allowlist.snapshot())),
            (Some(allowlist), Ok(Request::Status)) => Ok(Response::Status(allowlist.status())),
            (Some(allowlist), Ok(Request::Write(write))) => {
                let result = allowlist.apply_signed_blocking(write).await;
                match &result {
                    Ok(()) => {
                        info!(target: "zone::allowlist", %peer, "Applied relayed deposit allowlist update")
                    }
                    Err(error) => {
                        warn!(target: "zone::allowlist", %peer, %error, "Rejected relayed deposit allowlist update")
                    }
                }
                result.map(|()| Response::Applied(allowlist.status()))
            }
        };
        match serde_json::to_vec(&answer) {
            Ok(answer) => request.respond(answer).await,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Failed to encode allowlist answer");
            }
        }
    }
}

/// Send `request` to `sequencer`, or to every sequencer when it is `None`, and collect their
/// answers.
async fn answers(
    client: &AllowlistClient,
    sequencer: Option<&P2pPeerId>,
    request: &Request,
) -> RpcResult<Answers> {
    let payload = serde_json::to_vec(request)
        .map_err(|err| relay_error(format!("failed to encode request: {err}")))?;
    let AllowlistResponses {
        answers,
        unanswered,
    } = client
        .request(sequencer.cloned(), payload)
        .await
        .map_err(|err| relay_error(err.to_string()))?;
    let answered = answers.into_iter().map(|(peer, answer)| {
        let outcome = match serde_json::from_slice::<Answer>(&answer) {
            Ok(answer) => answer.map_err(Failure::Rejected),
            Err(err) => Err(Failure::Malformed(err)),
        };
        (peer, outcome)
    });
    let unanswered = unanswered
        .into_iter()
        .map(|peer| (peer, Err(Failure::Unanswered)));
    Ok(Answers(answered.chain(unanswered).collect()))
}

/// Keep `mirror` in step with the list of the leader `leadership` names, reading it through
/// `client`, and remove pooled transactions the new copy rejects. Runs on every RPC-only node
/// until the node shuts down.
pub(crate) async fn mirror_leader<P>(
    client: AllowlistClient,
    leadership: LeadershipSchedule,
    mirror: AllowlistMirror,
    pool: P,
) where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    let mut delay = Duration::ZERO;
    loop {
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = mirror.refresh_requested() => {}
        }
        let refreshed = refresh_mirror(&client, &leadership, &mirror).await;
        delay = match refreshed {
            Ok(Refreshed::Unlisted { .. }) => IDLE_MIRROR_REFRESH_INTERVAL,
            _ => MIRROR_REFRESH_INTERVAL,
        };
        match refreshed {
            Ok(Refreshed::Listed { changed: true }) => {
                let evicted = evict_unlisted_transfers(&pool, &mirror);
                let status = mirror.status();
                info!(
                    target: "zone::allowlist",
                    nonce = status.map(|status| status.nonce),
                    count = status.map(|status| status.count),
                    evicted,
                    "Updated mirrored transfer allowlist"
                );
            }
            Ok(Refreshed::Unlisted { cleared: true }) => {
                info!(target: "zone::allowlist", "Leader has no written transfer allowlist, admitting every transfer");
            }
            Ok(_) => {}
            // Only a stopped P2P runtime fails the request, and that shuts the node down.
            Err(error) => {
                debug!(target: "zone::allowlist", %error, "Failed to refresh mirrored transfer allowlist");
            }
        }
    }
}

/// What a mirror refresh learned from the leader.
#[derive(Debug, PartialEq, Eq)]
enum Refreshed {
    /// The leader reported a written list, and the copy now matches it.
    Listed {
        /// Whether the copy's version changed.
        changed: bool,
    },
    /// The leader runs without the allowlist or has not written its list, so the copy is cleared.
    Unlisted {
        /// Whether the mirror held a copy before.
        cleared: bool,
    },
    /// The leader is unknown or did not answer properly, so the copy is kept.
    Unanswered,
}

/// Copy the list of the leader `leadership` routes transactions to, the only sequencer that
/// enforces it, into `mirror`, asking only the leader.
async fn refresh_mirror(
    client: &AllowlistClient,
    leadership: &LeadershipSchedule,
    mirror: &AllowlistMirror,
) -> RpcResult<Refreshed> {
    let Some(leader) = leadership.next_anchor_record().map(|record| record.leader) else {
        return Ok(Refreshed::Unanswered);
    };
    let status = match answers(client, Some(&leader), &Request::Status)
        .await?
        .outcome_of(&leader)
    {
        Some(Ok(Response::Status(status))) if status.initialized => status,
        // An uninitialized list admits everyone, like no list at all.
        Some(Ok(Response::Status(_)))
        | Some(Err(Failure::Rejected(DepositAllowlistError::Disabled))) => {
            return Ok(Refreshed::Unlisted {
                cleared: mirror.clear(),
            });
        }
        outcome => {
            debug!(target: "zone::allowlist", %leader, ?outcome, "Leader did not report its allowlist status");
            return Ok(Refreshed::Unanswered);
        }
    };
    if mirror.status() == Some(status) {
        return Ok(Refreshed::Listed { changed: false });
    }
    match answers(client, Some(&leader), &Request::Get)
        .await?
        .outcome_of(&leader)
    {
        Some(Ok(Response::Snapshot(snapshot))) => Ok(Refreshed::Listed {
            changed: mirror.replace(snapshot),
        }),
        outcome => {
            debug!(target: "zone::allowlist", %leader, ?outcome, "Leader did not return its allowlist");
            Ok(Refreshed::Unanswered)
        }
    }
}

fn relay_error(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, message, None::<()>)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{net::TcpListener, time::Duration};

    use alloy::signers::{SignerSync as _, local::PrivateKeySigner};
    use commonware_codec::Encode as _;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
    use zone_p2p::{
        MAX_ALLOWLIST_PAYLOAD_SIZE, P2pConfig, P2pHandleParts, P2pNetworkId, spawn_p2p,
    };

    use zone_payload::TransferAllowlist as _;

    use crate::deposit_allowlist::{
        AllowlistGroup, AllowlistRouter, MAX_DEPOSIT_ALLOWLIST_LEN, MAX_GROUP_ID_LEN, MAX_GROUPS,
        MAX_ROUTERS, Policy, status_of,
    };
    use zone_payload::Movement;

    struct RelayFixture {
        relay: AllowlistRelay,
        /// The RPC-only node's leadership schedule, naming `node-0` as leader.
        leadership: LeadershipSchedule,
        peers: Vec<P2pHandleParts>,
        _dir: tempfile::TempDir,
    }

    impl RelayFixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let keys = [31, 32, 33, 34].map(PrivateKey::from_seed);
            let listeners: [_; 4] =
                std::array::from_fn(|_| TcpListener::bind("127.0.0.1:0").unwrap());
            let addresses = listeners
                .each_ref()
                .map(|listener| listener.local_addr().unwrap());
            let signer: PrivateKeySigner = format!("0x{:064x}", 31).parse().unwrap();
            let manifest_path = dir.path().join("manifest.toml");
            let mut manifest =
                format!("leader_ed25519_public_key = \"{}\"\n", keys[0].public_key());
            for (index, key) in keys.iter().enumerate() {
                manifest.push_str(&format!(
                    "\n[[nodes]]\nname = \"node-{index}\"\ned25519_public_key = \"{}\"\naddress = \"{}\"\nrpc_only = {}\n",
                    key.public_key(), addresses[index], index == 3,
                ));
                if index != 3 {
                    let signer: PrivateKeySigner =
                        format!("0x{:064x}", 31 + index).parse().unwrap();
                    manifest.push_str(&format!("secp256k1_address = \"{}\"\n", signer.address()));
                }
            }
            std::fs::write(&manifest_path, manifest).unwrap();
            drop(listeners);
            let mut leadership = None;
            let peers = keys
                .into_iter()
                .enumerate()
                .map(|(index, key)| {
                    let key_path = dir.path().join(format!("ed-{index}.key"));
                    std::fs::write(&key_path, const_hex::encode(key.encode())).unwrap();
                    let secp_path = dir.path().join(format!("secp-{index}.key"));
                    std::fs::write(&secp_path, format!("0x{:064x}", 31 + index)).unwrap();
                    let config = P2pConfig::load(
                        &manifest_path,
                        &key_path,
                        (index != 3).then_some(&secp_path),
                        addresses[index],
                        false,
                        1,
                        None,
                    )
                    .unwrap();
                    config
                        .leadership()
                        .publish(config.manifest().bootstrap_leadership())
                        .unwrap();
                    if index == 3 {
                        leadership = Some(config.leadership());
                    }
                    spawn_p2p(config, P2pNetworkId::new(1, Address::repeat_byte(1)))
                        .unwrap()
                        .into_parts()
                })
                .collect::<Vec<_>>();
            let relay = AllowlistRelay::new(
                peers[3].allowlist.client.clone(),
                DepositAllowlistAdmin {
                    address: signer.address(),
                    zone_chain_id: 1,
                },
                AllowlistMirror::default(),
                TaskExecutor::test(),
            );
            Self {
                relay,
                leadership: leadership.unwrap(),
                peers,
                _dir: dir,
            }
        }

        fn refresh_mirror(&self) -> tokio::task::JoinHandle<RpcResult<Refreshed>> {
            let (client, leadership, mirror) = (
                self.relay.client.clone(),
                self.leadership.clone(),
                self.relay.mirror.clone(),
            );
            tokio::spawn(async move { refresh_mirror(&client, &leadership, &mirror).await })
        }

        /// The next request at each of the three sequencers.
        async fn receive(&mut self) -> Vec<AllowlistRequest> {
            let mut requests = Vec::new();
            for index in 0..3 {
                requests.push(self.receive_at(index).await);
            }
            requests
        }

        async fn receive_at(&mut self, index: usize) -> AllowlistRequest {
            tokio::time::timeout(
                Duration::from_secs(10),
                self.peers[index].allowlist.requests.recv(),
            )
            .await
            .expect("sequencer did not receive request")
            .unwrap()
        }
    }

    impl Drop for RelayFixture {
        fn drop(&mut self) {
            for peer in &self.peers {
                peer.shutdown.cancel();
            }
        }
    }

    #[tokio::test]
    async fn cancelled_reads_keep_their_slots_until_completion() {
        let mut fixture = RelayFixture::new();
        let mut requests = Vec::new();
        for _ in 0..MAX_CONCURRENT_READS {
            let relay = fixture.relay.clone();
            let read = tokio::spawn(async move { relay.relay_read(Request::Get).await });
            requests.extend(fixture.receive().await);
            read.abort();
            assert!(read.await.unwrap_err().is_cancelled());
        }
        assert_eq!(fixture.relay.reads.available_permits(), 0);
        assert_eq!(
            fixture.relay.relay_read(Request::Status).await.unwrap_err(),
            ErrorObjectOwned::from(DepositAllowlistError::Busy),
        );

        let relay = fixture.relay.clone();
        let signer: PrivateKeySigner = format!("0x{:064x}", 31).parse().unwrap();
        let mut write = SignedWrite {
            write: Write::Replace { addresses: vec![] },
            nonce: 1,
            deadline: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 60,
            signature: Bytes::new(),
        };
        write.signature = Bytes::from(
            signer
                .sign_hash_sync(&write.signing_hash(&relay.admin.domain()))
                .unwrap()
                .as_bytes(),
        );
        let write = tokio::spawn(async move { relay.relay_write(write).await });
        for request in fixture.receive().await {
            request
                .respond(
                    serde_json::to_vec(&Answer::Ok(Response::Applied(status_of(None)))).unwrap(),
                )
                .await;
        }
        tokio::time::timeout(Duration::from_secs(10), write)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        for request in requests {
            request
                .respond(ok(Response::Snapshot(DepositAllowlistSnapshot {
                    status: status_of(None),
                    policy: Policy::default(),
                })))
                .await;
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while fixture.relay.reads.available_permits() != MAX_CONCURRENT_READS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed reads did not release their slots");

        // A missing acknowledgement also releases the read slot after the transport timeout.
        let relay = fixture.relay.clone();
        let call = tokio::spawn(async move { relay.relay_read(Request::Status).await });
        let unanswered = fixture.receive().await;
        let error = tokio::time::timeout(Duration::from_secs(12), call)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), jsonrpsee::types::error::INTERNAL_ERROR_CODE);
        assert!(
            error
                .message()
                .contains("no acknowledgement from sequencers")
        );
        assert_eq!(
            fixture.relay.reads.available_permits(),
            MAX_CONCURRENT_READS
        );
        drop(unanswered);
    }

    #[tokio::test]
    async fn relay_preserves_sequencer_error_codes() {
        let mut fixture = RelayFixture::new();
        for error in [
            DepositAllowlistError::StaleNonce {
                nonce: 1,
                applied: 2,
            },
            DepositAllowlistError::Uninitialized,
            DepositAllowlistError::TooLarge {
                len: MAX_DEPOSIT_ALLOWLIST_LEN + 1,
            },
            DepositAllowlistError::Persist("disk full".to_owned()),
            DepositAllowlistError::Disabled,
            DepositAllowlistError::Internal("failed".to_owned()),
        ] {
            let expected = ErrorObjectOwned::from(error.clone());
            let relay = fixture.relay.clone();
            let call = tokio::spawn(async move { relay.relay_read(Request::Status).await });
            for request in fixture.receive().await {
                request
                    .respond(serde_json::to_vec(&Answer::Err(error.clone())).unwrap())
                    .await;
            }
            let result = tokio::time::timeout(Duration::from_secs(10), call)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert_eq!(result.code(), expected.code());
            assert!(result.message().contains(expected.message()), "{result}");
        }
        // An internal error wins over caller errors, regardless of response order.
        let relay = fixture.relay.clone();
        let call = tokio::spawn(async move { relay.relay_read(Request::Status).await });
        for (index, request) in fixture.receive().await.into_iter().enumerate() {
            let error = if index == 1 {
                DepositAllowlistError::Persist("disk full".to_owned())
            } else {
                DepositAllowlistError::Uninitialized
            };
            request
                .respond(serde_json::to_vec(&Answer::Err(error)).unwrap())
                .await;
        }
        let error = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), jsonrpsee::types::error::INTERNAL_ERROR_CODE);
        assert!(error.message().contains("disk full"));
        assert!(error.message().contains("uninitialized"));

        let relay = fixture.relay.clone();
        let call = tokio::spawn(async move { relay.relay_read(Request::Status).await });
        for request in fixture.receive().await {
            request.respond(b"malformed".to_vec()).await;
        }
        let error = tokio::time::timeout(Duration::from_secs(10), call)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), jsonrpsee::types::error::INTERNAL_ERROR_CODE);
        assert!(error.message().contains("malformed answer"));
    }

    fn status(nonce: u64) -> DepositAllowlistStatus {
        DepositAllowlistStatus {
            initialized: true,
            nonce,
            list_hash: alloy_primitives::B256::with_last_byte(u8::try_from(nonce).unwrap()),
            count: 1,
        }
    }

    /// A policy whose only group is the default group holding `addresses`.
    fn default_group(addresses: Vec<Address>) -> Policy {
        let mut policy = Policy::default();
        policy.default_group().members = addresses.into_iter().collect();
        policy
    }

    /// Whether `mirror` admits a transfer from `address` to itself.
    fn admits(mirror: &AllowlistMirror, address: Address) -> bool {
        mirror.admits(&[Movement::Transfer {
            spender: None,
            from: address,
            to: address,
        }])
    }

    /// A written list of `nonce` holding only `address`.
    fn listed(nonce: u64, address: Address) -> Response {
        Response::Snapshot(DepositAllowlistSnapshot {
            status: status(nonce),
            policy: default_group(vec![address]),
        })
    }

    fn ok(response: Response) -> Vec<u8> {
        serde_json::to_vec(&Answer::Ok(response)).unwrap()
    }

    fn disabled() -> Vec<u8> {
        serde_json::to_vec(&Answer::Err(DepositAllowlistError::Disabled)).unwrap()
    }

    /// Bytes no sequencer sends, standing in for one that did not answer properly.
    fn malformed() -> Vec<u8> {
        b"not json".to_vec()
    }

    fn uninitialized() -> Vec<u8> {
        ok(Response::Status(DepositAllowlistStatus {
            initialized: false,
            nonce: 0,
            list_hash: alloy_primitives::B256::ZERO,
            count: 0,
        }))
    }

    impl RelayFixture {
        /// Answer the next request at sequencer `index` with `answer`.
        async fn answer_at(&mut self, index: usize, answer: Vec<u8>) {
            self.receive_at(index).await.respond(answer).await;
        }
    }

    async fn refreshed(refresh: tokio::task::JoinHandle<RpcResult<Refreshed>>) -> Refreshed {
        tokio::time::timeout(Duration::from_secs(10), refresh)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn mirror_copies_the_leaders_list() {
        let mut fixture = RelayFixture::new();
        let (old, new) = (Address::repeat_byte(1), Address::repeat_byte(2));

        let refresh = fixture.refresh_mirror();
        fixture.answer_at(0, ok(Response::Status(status(1)))).await;
        fixture.answer_at(0, ok(listed(1, old))).await;
        assert_eq!(
            refreshed(refresh).await,
            Refreshed::Listed { changed: true }
        );
        assert_eq!(fixture.relay.mirror.status(), Some(status(1)));
        assert!(admits(&fixture.relay.mirror, old));
        assert!(!admits(&fixture.relay.mirror, new));
        // Only the leader is asked.
        for peer in &mut fixture.peers[1..3] {
            assert!(peer.allowlist.requests.try_recv().is_err());
        }

        // An unchanged version is not fetched again.
        let refresh = fixture.refresh_mirror();
        fixture.answer_at(0, ok(Response::Status(status(1)))).await;
        assert_eq!(
            refreshed(refresh).await,
            Refreshed::Listed { changed: false }
        );

        // A leader that does not answer properly leaves the copy as it is.
        let refresh = fixture.refresh_mirror();
        fixture.answer_at(0, malformed()).await;
        assert_eq!(refreshed(refresh).await, Refreshed::Unanswered);
        let refresh = fixture.refresh_mirror();
        fixture.answer_at(0, ok(Response::Status(status(3)))).await;
        fixture.answer_at(0, malformed()).await;
        assert_eq!(refreshed(refresh).await, Refreshed::Unanswered);
        assert_eq!(fixture.relay.mirror.status(), Some(status(1)));

        // The copy moves back with the leader, e.g. after the admin rebuilt its list.
        let refresh = fixture.refresh_mirror();
        fixture.answer_at(0, ok(Response::Status(status(0)))).await;
        fixture.answer_at(0, ok(listed(0, new))).await;
        assert_eq!(
            refreshed(refresh).await,
            Refreshed::Listed { changed: true }
        );
        assert_eq!(fixture.relay.mirror.status(), Some(status(0)));
        assert!(admits(&fixture.relay.mirror, new));

        // An uninitialized list or a leader without the allowlist clears the copy.
        for answer in [uninitialized(), disabled()] {
            fixture.relay.mirror.replace(DepositAllowlistSnapshot {
                status: status(0),
                policy: default_group(vec![new]),
            });
            let refresh = fixture.refresh_mirror();
            fixture.answer_at(0, answer.clone()).await;
            assert_eq!(
                refreshed(refresh).await,
                Refreshed::Unlisted { cleared: true }
            );
            assert_eq!(fixture.relay.mirror.status(), None);
            assert!(admits(&fixture.relay.mirror, old) && admits(&fixture.relay.mirror, new));
            let refresh = fixture.refresh_mirror();
            fixture.answer_at(0, answer).await;
            assert_eq!(
                refreshed(refresh).await,
                Refreshed::Unlisted { cleared: false }
            );
        }
    }

    #[tokio::test]
    async fn mirror_follows_a_new_leader() {
        let mut fixture = RelayFixture::new();
        let (old, new) = (Address::repeat_byte(1), Address::repeat_byte(2));
        assert!(fixture.relay.mirror.replace(DepositAllowlistSnapshot {
            status: status(1),
            policy: default_group(vec![old]),
        }));
        fixture
            .leadership
            .publish(zone_p2p::LeadershipState::new(
                1,
                PrivateKey::from_seed(32).public_key(),
                10,
            ))
            .unwrap();

        let refresh = fixture.refresh_mirror();
        fixture.answer_at(1, ok(Response::Status(status(2)))).await;
        fixture.answer_at(1, ok(listed(2, new))).await;
        assert_eq!(
            refreshed(refresh).await,
            Refreshed::Listed { changed: true }
        );
        assert_eq!(fixture.relay.mirror.status(), Some(status(2)));
        assert!(admits(&fixture.relay.mirror, new));
    }

    fn full_list() -> Vec<Address> {
        (0..MAX_DEPOSIT_ALLOWLIST_LEN)
            .map(|index| Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes()))
            .collect()
    }

    /// The largest policies the limits allow: every entry a membership, or as many entries as
    /// possible routes. Both hold the most groups and routers, with the longest group IDs.
    fn largest_policies() -> [AllowlistPolicy; 2] {
        let ids = (0..MAX_GROUPS)
            .map(|index| format!("{index:0>MAX_GROUP_ID_LEN$}"))
            .collect::<Vec<_>>();
        let addresses = full_list();
        let members = |members: &[Address]| {
            ids.iter()
                .enumerate()
                .map(|(index, id)| AllowlistGroup {
                    id: id.clone(),
                    members: if index == 0 { members.to_vec() } else { vec![] },
                    depositors: vec![],
                    transfers: true,
                })
                .collect::<Vec<_>>()
        };
        let routers = |groups: &[String]| {
            addresses[..MAX_ROUTERS]
                .iter()
                .map(|router| AllowlistRouter {
                    router: *router,
                    groups: groups.to_vec(),
                })
                .collect::<Vec<_>>()
        };
        let routes = MAX_GROUPS * MAX_ROUTERS;
        [
            AllowlistPolicy {
                groups: members(&addresses),
                routers: routers(&[]),
            },
            AllowlistPolicy {
                groups: members(&addresses[..MAX_DEPOSIT_ALLOWLIST_LEN - routes]),
                routers: routers(&ids),
            },
        ]
    }

    #[test]
    fn the_largest_lists_fit_in_one_frame_both_ways() {
        for policy in largest_policies() {
            let policy = Policy::try_from(policy).unwrap();
            policy.check_limits().unwrap();
            assert_eq!(policy.len(), MAX_DEPOSIT_ALLOWLIST_LEN);
            let answer =
                serde_json::to_vec(&Answer::Ok(Response::Snapshot(DepositAllowlistSnapshot {
                    status: DepositAllowlistStatus {
                        initialized: true,
                        nonce: u64::MAX,
                        list_hash: alloy_primitives::B256::repeat_byte(0xff),
                        count: policy.len(),
                    },
                    policy: policy.clone(),
                })))
                .unwrap();
            assert!(
                answer.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE,
                "{}",
                answer.len()
            );

            let replace = serde_json::to_vec(&Request::Write(SignedWrite {
                write: Write::ReplaceGroups {
                    policy: policy.into(),
                },
                nonce: u64::MAX,
                deadline: u64::MAX,
                signature: Bytes::from([0xff; 65]),
            }))
            .unwrap();
            assert!(
                replace.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE,
                "{}",
                replace.len()
            );
        }
    }
}
