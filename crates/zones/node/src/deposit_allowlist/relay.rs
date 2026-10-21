//! Relays `zoneAdmin` allowlist requests from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist and no admin key. It
//! checks each write's admin signature and deadline, then sends the request unchanged to every
//! quorum member, which checks it again, applies it to its own persisted list, and answers. The
//! call returns only after every member answered, so a success means every sequencer will enforce
//! the change on its next block. [`zone_p2p::AllowlistClient`] owns delivery: request IDs,
//! resends, the timeout, and answering resent requests without handling them twice.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes};
use jsonrpsee::{
    core::RpcResult,
    types::{
        ErrorObjectOwned,
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    },
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};
use zone_p2p::{AllowlistClient, AllowlistRequest, AllowlistResponses, P2pPeerId};

use super::{
    DepositAllowlist, DepositAllowlistAdmin, DepositAllowlistApiServer, DepositAllowlistError,
    DepositAllowlistSnapshot, DepositAllowlistStatus, SequencerAllowlistStatus, SignedWrite, Write,
};

/// Reads relayed at once. Reads need no signature, so they have their own limit and cannot keep
/// writes from being relayed.
const MAX_CONCURRENT_READS: usize = 4;

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

/// `zoneAdmin` API on an RPC-only node, relaying requests to every sequencer.
#[derive(Clone)]
pub(crate) struct AllowlistRelay {
    /// Rejects writes the sequencers would reject before they use P2P bandwidth.
    admin: DepositAllowlistAdmin,
    client: AllowlistClient,
    /// Held by the one write in flight, so every sequencer receives this node's writes in the
    /// same order.
    write: Arc<Semaphore>,
    reads: Arc<Semaphore>,
}

impl AllowlistRelay {
    pub(crate) fn new(client: AllowlistClient, admin: DepositAllowlistAdmin) -> Self {
        Self {
            admin,
            client,
            write: Arc::new(Semaphore::new(1)),
            reads: Arc::new(Semaphore::new(MAX_CONCURRENT_READS)),
        }
    }

    /// Send `request` to every sequencer and return each one's response, or an error naming the
    /// sequencers that rejected it or did not answer.
    async fn relay(&self, request: &Request) -> RelayResult {
        let payload = serde_json::to_vec(request)
            .map_err(|err| relay_error(format!("failed to encode request: {err}")))?;
        let AllowlistResponses {
            answers,
            unanswered,
        } = self
            .client
            .request(payload)
            .await
            .map_err(|err| relay_error(err.to_string()))?;
        let mut responses = Vec::with_capacity(answers.len());
        let mut errors = Vec::new();
        // Invalid params only when every sequencer that failed rejected the request itself.
        let mut code = INVALID_PARAMS_CODE;
        for (peer, answer) in answers {
            match serde_json::from_slice::<Answer>(&answer) {
                Ok(Ok(response)) => responses.push((peer, response)),
                Ok(Err(error)) => {
                    if error.code() != INVALID_PARAMS_CODE {
                        code = INTERNAL_ERROR_CODE;
                    }
                    errors.push(format!("{peer}: {error}"));
                }
                Err(err) => {
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
        if errors.is_empty() {
            Ok(responses)
        } else {
            Err(ErrorObjectOwned::owned(code, errors.join("; "), None::<()>))
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
        tokio::spawn(async move {
            let _permit = permit;
            relay.relay(&request).await
        })
        .await
        .map_err(|err| relay_error(format!("allowlist relay task failed: {err}")))?
    }

    async fn relay_read(&self, request: Request) -> RelayResult {
        self.relay_in(&self.reads, request).await
    }

    async fn relay_write(&self, write: SignedWrite) -> RpcResult<()> {
        self.admin.authorize(&write)?;
        let responses = self.relay_in(&self.write, Request::Write(write)).await?;
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

fn relay_error(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, message, None::<()>)
}

#[cfg(test)]
mod tests {
    use zone_p2p::MAX_ALLOWLIST_PAYLOAD_SIZE;

    use super::*;
    use crate::deposit_allowlist::MAX_DEPOSIT_ALLOWLIST_LEN;

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
