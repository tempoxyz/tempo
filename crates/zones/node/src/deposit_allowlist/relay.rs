//! Relays `zoneAdmin` allowlist requests from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist and no admin key. It
//! checks each write's admin signature and deadline, then sends the request unchanged to every
//! quorum member, which checks it again, applies it to its own persisted list, and answers. The
//! call returns only after every member answered, so a success means every sequencer will enforce
//! the change on its next block. [`zone_p2p::AllowlistClient`] owns delivery: request IDs,
//! resends, the timeout, and answering resent requests without handling them twice.
//!
//! [`mirror_sequencers`] keeps every RPC-only node's [`AllowlistMirror`] in step with the
//! sequencers, with or without the admin, so the node rejects transfers between unlisted accounts
//! on submission instead of forwarding them. Reads need no signature.

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
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    time::MissedTickBehavior,
};
use tracing::{Instrument, debug, info, warn};
use zone_p2p::{AllowlistClient, AllowlistRequest, AllowlistResponses, P2pPeerId};

use super::{
    AllowlistMirror, DepositAllowlist, DepositAllowlistAdmin, DepositAllowlistApiServer,
    DepositAllowlistError, DepositAllowlistSnapshot, DepositAllowlistStatus,
    SequencerAllowlistStatus, SignedWrite, Write, evict_unlisted_transfers,
};

/// Reads relayed at once. Reads need no signature, so they have their own limit and cannot keep
/// writes from being relayed.
const MAX_CONCURRENT_READS: usize = 4;

/// How often an RPC-only node checks whether the sequencers' allowlist changed. Writes this node
/// relays refresh its copy immediately; writes relayed through another node show up here within
/// this interval.
const MIRROR_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

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

/// The sequencers' answers to one relayed request.
struct Answers {
    /// Responses of the sequencers that accepted the request.
    responses: Vec<(P2pPeerId, Response)>,
    /// Whether every sequencer answered, with a response or by reporting that it runs without the
    /// allowlist.
    complete: bool,
    /// Names the sequencers that rejected the request or did not answer, if any did.
    error: Option<ErrorObjectOwned>,
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
        let answers = answers(&self.client, request).await?;
        match answers.error {
            None => Ok(answers.responses),
            Some(error) => Err(error),
        }
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

#[jsonrpsee::core::async_trait]
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
                        "{peer}: nonce {}, {} addresses, hash {}",
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

/// Send `request` to every sequencer and collect their answers.
async fn answers(client: &AllowlistClient, request: &Request) -> RpcResult<Answers> {
    let payload = serde_json::to_vec(request)
        .map_err(|err| relay_error(format!("failed to encode request: {err}")))?;
    let AllowlistResponses {
        answers,
        unanswered,
    } = client
        .request(payload)
        .await
        .map_err(|err| relay_error(err.to_string()))?;
    let mut responses = Vec::with_capacity(answers.len());
    let mut complete = unanswered.is_empty();
    let mut errors = Vec::new();
    // Invalid params only when every sequencer that failed rejected the request itself.
    let mut code = INVALID_PARAMS_CODE;
    for (peer, answer) in answers {
        match serde_json::from_slice::<Answer>(&answer) {
            Ok(Ok(response)) => responses.push((peer, response)),
            Ok(Err(error)) => {
                complete &= matches!(error, DepositAllowlistError::Disabled);
                if error.code() != INVALID_PARAMS_CODE {
                    code = INTERNAL_ERROR_CODE;
                }
                errors.push(format!("{peer}: {error}"));
            }
            Err(err) => {
                complete = false;
                code = INTERNAL_ERROR_CODE;
                errors.push(format!("{peer}: malformed answer: {err}"));
            }
        }
    }
    if !unanswered.is_empty() {
        let unanswered = unanswered
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        code = INTERNAL_ERROR_CODE;
        errors.push(format!(
            "no acknowledgement from sequencers {}",
            unanswered.join(", ")
        ));
    }
    let error =
        (!errors.is_empty()).then(|| ErrorObjectOwned::owned(code, errors.join("; "), None::<()>));
    Ok(Answers {
        responses,
        complete,
        error,
    })
}

/// Keep `mirror` in step with the sequencers' lists, reading them through `client`, and remove
/// pooled transactions the new copy rejects. Runs on every RPC-only node until the
/// node shuts down.
pub(crate) async fn mirror_sequencers<P>(client: AllowlistClient, mirror: AllowlistMirror, pool: P)
where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    let mut interval = tokio::time::interval(MIRROR_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            () = mirror.refresh_requested() => {}
        }
        match refresh_mirror(&client, &mirror).await {
            Ok(false) => {}
            Ok(true) => {
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
            Err(error) => {
                warn!(target: "zone::allowlist", %error, "Failed to refresh mirrored transfer allowlist");
            }
        }
    }
}

/// Bring `mirror` in line with the newest written list held by the sequencers that answer.
/// Returns whether the copy changed.
///
/// A newer list is taken from any sequencer, so one offline sequencer does not leave this node
/// behind. The copy moves back, to an older list or to none when no sequencer holds a written
/// list (for example after `--deposits.allowlist` is turned off), only when every sequencer
/// answered, so a lagging sequencer that alone answers cannot roll it back.
async fn refresh_mirror(client: &AllowlistClient, mirror: &AllowlistMirror) -> RpcResult<bool> {
    let statuses = answers(client, &Request::Status).await?;
    if let Some(error) = &statuses.error {
        debug!(target: "zone::allowlist", %error, "Some sequencers did not report their allowlist status");
    }
    let follow_back = statuses.complete;
    // An uninitialized list admits everyone, like a sequencer without the allowlist.
    let Some(newest) = statuses
        .responses
        .into_iter()
        .filter_map(|(_, response)| match response {
            Response::Status(status) if status.initialized => Some(status),
            _ => None,
        })
        .max_by_key(|status| status.nonce)
    else {
        return Ok(follow_back && mirror.clear());
    };
    let fetch = mirror
        .status()
        .is_none_or(|current| current != newest && (follow_back || newest.nonce > current.nonce));
    if !fetch {
        return Ok(false);
    }
    let snapshots = answers(client, &Request::Get).await?;
    if let Some(error) = &snapshots.error {
        debug!(target: "zone::allowlist", %error, "Some sequencers did not return their allowlist");
    }
    // The sequencers that answer this round may lag behind those that reported `newest`.
    let Some(snapshot) = snapshots
        .responses
        .into_iter()
        .filter_map(|(_, response)| match response {
            Response::Snapshot(snapshot) if snapshot.status.initialized => Some(snapshot),
            _ => None,
        })
        .max_by_key(|snapshot| snapshot.status.nonce)
        .filter(|snapshot| snapshot.status.nonce >= newest.nonce)
    else {
        return Ok(false);
    };
    Ok(mirror.replace(snapshot))
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

    use crate::deposit_allowlist::{MAX_DEPOSIT_ALLOWLIST_LEN, status_of};

    struct RelayFixture {
        relay: AllowlistRelay,
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
                peers,
                _dir: dir,
            }
        }

        fn refresh_mirror(&self) -> tokio::task::JoinHandle<RpcResult<bool>> {
            let (client, mirror) = (self.relay.client.clone(), self.relay.mirror.clone());
            tokio::spawn(async move { refresh_mirror(&client, &mirror).await })
        }

        async fn receive(&mut self) -> Vec<AllowlistRequest> {
            let mut requests = Vec::new();
            for peer in &mut self.peers[..3] {
                requests.push(
                    tokio::time::timeout(Duration::from_secs(10), peer.allowlist.requests.recv())
                        .await
                        .expect("sequencer did not receive request")
                        .unwrap(),
                );
            }
            requests
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
        write.signature = Bytes::copy_from_slice(
            &signer
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
                .respond(serde_json::to_vec(&Answer::Ok(snapshot(vec![]))).unwrap())
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

    /// A written list of `nonce` holding only `address`.
    fn listed(nonce: u64, address: Address) -> Response {
        Response::Snapshot(DepositAllowlistSnapshot {
            status: status(nonce),
            addresses: vec![address],
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
        /// Answer the next request at the three sequencers with `answers`, in order.
        async fn answer(&mut self, answers: [Vec<u8>; 3]) {
            for (request, answer) in self.receive().await.into_iter().zip(answers) {
                request.respond(answer).await;
            }
        }
    }

    async fn changed(refresh: tokio::task::JoinHandle<RpcResult<bool>>) -> bool {
        tokio::time::timeout(Duration::from_secs(10), refresh)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn mirror_takes_the_newest_list_from_the_sequencers_that_answer() {
        let mut fixture = RelayFixture::new();
        let (old, new) = (Address::repeat_byte(1), Address::repeat_byte(2));

        let refresh = fixture.refresh_mirror();
        fixture
            .answer([
                ok(Response::Status(status(1))),
                ok(Response::Status(status(2))),
                malformed(),
            ])
            .await;
        fixture
            .answer([ok(listed(1, old)), ok(listed(2, new)), malformed()])
            .await;
        assert!(changed(refresh).await);
        assert_eq!(fixture.relay.mirror.status(), Some(status(2)));
        assert!(fixture.relay.mirror.allows_all(&[new]));
        assert!(!fixture.relay.mirror.allows_all(&[old]));

        // An unchanged version is not fetched again. While a sequencer does not answer, neither
        // an older list nor the lack of one moves the copy back.
        for answers in [
            [
                ok(Response::Status(status(1))),
                ok(Response::Status(status(2))),
                disabled(),
            ],
            [ok(Response::Status(status(1))), malformed(), malformed()],
            [disabled(), uninitialized(), malformed()],
        ] {
            let refresh = fixture.refresh_mirror();
            fixture.answer(answers).await;
            assert!(!changed(refresh).await);
            assert_eq!(fixture.relay.mirror.status(), Some(status(2)));
        }
    }

    #[tokio::test]
    async fn mirror_follows_the_sequencers_back_once_every_one_answers() {
        let mut fixture = RelayFixture::new();
        let (old, new) = (Address::repeat_byte(1), Address::repeat_byte(2));
        assert!(fixture.relay.mirror.replace(DepositAllowlistSnapshot {
            status: status(2),
            addresses: vec![new],
        }));

        // Every sequencer holds an older list, e.g. after the admin rebuilt them.
        let refresh = fixture.refresh_mirror();
        fixture
            .answer([
                ok(Response::Status(status(1))),
                ok(Response::Status(status(1))),
                disabled(),
            ])
            .await;
        fixture
            .answer([ok(listed(1, old)), ok(listed(1, old)), disabled()])
            .await;
        assert!(changed(refresh).await);
        assert_eq!(fixture.relay.mirror.status(), Some(status(1)));

        // Every sequencer runs without the allowlist or has not written it.
        let refresh = fixture.refresh_mirror();
        fixture
            .answer([disabled(), disabled(), uninitialized()])
            .await;
        assert!(changed(refresh).await);
        assert_eq!(fixture.relay.mirror.status(), None);
        assert!(fixture.relay.mirror.allows_all(&[new]));
    }

    fn full_list() -> Vec<Address> {
        (0..MAX_DEPOSIT_ALLOWLIST_LEN)
            .map(|index| Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes()))
            .collect()
    }

    fn snapshot(addresses: Vec<Address>) -> Response {
        Response::Snapshot(DepositAllowlistSnapshot {
            status: DepositAllowlistStatus {
                initialized: true,
                nonce: u64::MAX,
                list_hash: alloy_primitives::B256::repeat_byte(0xff),
                count: addresses.len(),
            },
            addresses,
        })
    }

    #[test]
    fn a_full_list_fits_in_one_frame_both_ways() {
        let addresses = full_list();
        let answer = serde_json::to_vec(&Answer::Ok(snapshot(addresses.clone()))).unwrap();
        assert!(
            answer.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE,
            "{}",
            answer.len()
        );

        let replace = serde_json::to_vec(&Request::Write(SignedWrite {
            write: Write::Replace { addresses },
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
