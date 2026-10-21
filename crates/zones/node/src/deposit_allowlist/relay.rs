//! Relays `zoneAdmin` allowlist requests from an RPC-only node to every sequencer over P2P.
//!
//! The RPC-only node serves the operator-facing RPC but holds no allowlist and no admin key. It
//! checks each write's admin signature and deadline, then sends the request unchanged to every
//! quorum member, which checks it again, applies it to its own persisted list, and acknowledges
//! it. The call returns only after
//! every member acknowledged, so a success means every sequencer will enforce the change on its
//! next block.

use std::{collections::HashMap, time::Duration};

use alloy_primitives::{Address, Bytes};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use serde::{Deserialize, Serialize};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use tracing::{debug, info, warn};
use zone_p2p::{MAX_ALLOWLIST_PAYLOAD_SIZE, P2pCommand, P2pEvent, P2pPeerId};

use super::{
    DepositAllowlist, DepositAllowlistAdmin, DepositAllowlistApiServer, DepositAllowlistError,
    DepositAllowlistSnapshot, DepositAllowlistStatus, SequencerAllowlistStatus, SignedWrite, Write,
};

/// How long a relayed request waits for every sequencer before failing.
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);
/// How often an unacknowledged request is resent to the sequencers still missing.
const RELAY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Requests waiting behind the one in flight; more fail fast so clients cannot pile up work.
const MAX_QUEUED_RELAYS: usize = 4;

/// An allowlist request relayed over P2P, tagged so acknowledgements match their request.
#[derive(Debug, Serialize, Deserialize)]
struct Update {
    id: u64,
    request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Write(SignedWrite),
    Get,
    Status,
}

/// A sequencer's result for one relayed request, or the reason it was rejected.
#[derive(Debug, Serialize, Deserialize)]
struct Ack {
    id: u64,
    result: Result<Response, DepositAllowlistError>,
}

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

/// `zoneAdmin` API on an RPC-only node, relaying requests to the sequencers it lists.
#[derive(Clone)]
pub(crate) struct AllowlistRelay {
    /// Rejects writes the sequencers would reject before they use P2P bandwidth.
    admin: DepositAllowlistAdmin,
    /// Requests for [`run_relay`], which relays one at a time.
    calls: mpsc::Sender<(Request, oneshot::Sender<RelayResult>)>,
}

impl AllowlistRelay {
    /// Create a relay to `sequencers` and the worker task that serves it, reading
    /// acknowledgements from `events`.
    pub(crate) fn new(
        sequencers: Vec<P2pPeerId>,
        commands: mpsc::Sender<P2pCommand>,
        events: mpsc::Receiver<P2pEvent>,
        admin: DepositAllowlistAdmin,
    ) -> (Self, impl Future<Output = ()> + Send + 'static) {
        let (calls, queued) = mpsc::channel(MAX_QUEUED_RELAYS);
        (
            Self { admin, calls },
            run_relay(sequencers, commands, queued, events),
        )
    }

    /// Queue `request` and return each sequencer's result once all have answered. Fails fast
    /// when the queue is full.
    async fn relay(&self, request: Request) -> RelayResult {
        let (reply, result) = oneshot::channel();
        self.calls
            .try_send((request, reply))
            .map_err(|err| match err {
                TrySendError::Full(_) => DepositAllowlistError::Busy.into(),
                TrySendError::Closed(_) => relay_error("allowlist relay stopped".to_owned()),
            })?;
        result
            .await
            .map_err(|_| relay_error("allowlist relay stopped".to_owned()))?
    }

    async fn relay_write(&self, write: SignedWrite) -> RpcResult<()> {
        self.admin.authorize(&write)?;
        let unexpected = self
            .relay(Request::Write(write))
            .await?
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

/// Relay queued requests one at a time, so every sequencer receives writes in the same order.
async fn run_relay(
    sequencers: Vec<P2pPeerId>,
    commands: mpsc::Sender<P2pCommand>,
    mut calls: mpsc::Receiver<(Request, oneshot::Sender<RelayResult>)>,
    mut events: mpsc::Receiver<P2pEvent>,
) {
    // Starts at a random value so a sequencer's late acknowledgement for a request from before a
    // restart cannot match a new request.
    let mut next_id: u64 = rand::random();
    while let Some((request, reply)) = calls.recv().await {
        if reply.is_closed() {
            continue;
        }
        next_id = next_id.wrapping_add(1);
        let result = relay_one(next_id, request, &sequencers, &commands, &mut events).await;
        let _ = reply.send(result);
    }
}

/// Send `request` to every sequencer, resending to those that have not acknowledged it, and
/// return each one's result once all have answered.
async fn relay_one(
    id: u64,
    request: Request,
    sequencers: &[P2pPeerId],
    commands: &mpsc::Sender<P2pCommand>,
    events: &mut mpsc::Receiver<P2pEvent>,
) -> RelayResult {
    let update = serde_json::to_vec(&Update { id, request })
        .map_err(|err| relay_error(format!("failed to encode request: {err}")))?;
    if update.len() > MAX_ALLOWLIST_PAYLOAD_SIZE {
        return Err(relay_error(format!(
            "request encodes to {} bytes; the relay limit is {MAX_ALLOWLIST_PAYLOAD_SIZE}",
            update.len()
        )));
    }
    let mut missing = sequencers.to_vec();
    let mut results = Vec::with_capacity(missing.len());
    let mut errors = Vec::new();
    let deadline = tokio::time::Instant::now() + RELAY_TIMEOUT;
    let mut retry = tokio::time::interval(RELAY_RETRY_INTERVAL);
    while !missing.is_empty() {
        tokio::select! {
            _ = retry.tick() => {
                for peer in &missing {
                    commands
                        .send(P2pCommand::SendAllowlistUpdate { peer: peer.clone(), update: update.clone() })
                        .await
                        .map_err(|_| relay_error("P2P command channel closed".to_owned()))?;
                }
            }
            event = events.recv() => {
                let Some(event) = event else {
                    return Err(relay_error("allowlist acknowledgement stream closed".to_owned()));
                };
                let Some((peer, ack)) = decode_ack(event) else { continue };
                if ack.id != id {
                    debug!(target: "zone::allowlist", %peer, id = ack.id, "Ignoring allowlist acknowledgement for a finished request");
                    continue;
                }
                if let Some(index) = missing.iter().position(|missing| *missing == peer) {
                    missing.swap_remove(index);
                    match ack.result {
                        Ok(response) => results.push((peer, response)),
                        Err(error) => errors.push(format!("{peer}: {error}")),
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                let missing = missing.iter().map(ToString::to_string).collect::<Vec<_>>();
                errors.push(format!("no acknowledgement from sequencers {}", missing.join(", ")));
                break;
            }
        }
    }
    if errors.is_empty() {
        Ok(results)
    } else {
        Err(relay_error(errors.join("; ")))
    }
}

fn decode_ack(event: P2pEvent) -> Option<(P2pPeerId, Ack)> {
    let P2pEvent::AllowlistAckReceived { peer, ack } = event else {
        return None;
    };
    match serde_json::from_slice(&ack) {
        Ok(ack) => Some((peer, ack)),
        Err(err) => {
            warn!(target: "zone::allowlist", %peer, %err, "Ignoring malformed allowlist acknowledgement");
            None
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
        for (peer, response) in self.relay(Request::Get).await? {
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
        self.relay(Request::Status)
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

/// Apply relayed requests on a sequencer and acknowledge each one to its relayer.
///
/// A relayer resends a request until it is acknowledged, so the last acknowledgement sent to
/// each relayer is kept and resent for a repeated request instead of handling it again.
pub(crate) async fn apply_relayed_updates(
    allowlist: Option<DepositAllowlist>,
    mut events: mpsc::Receiver<P2pEvent>,
    commands: mpsc::Sender<P2pCommand>,
) {
    // Keyed by relayer, which routing limits to the manifest's RPC-only members.
    let mut last_acks: HashMap<P2pPeerId, (u64, Vec<u8>)> = HashMap::new();
    while let Some(event) = events.recv().await {
        let P2pEvent::AllowlistUpdateReceived { peer, update } = event else {
            continue;
        };
        let update: Update = match serde_json::from_slice(&update) {
            Ok(update) => update,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Ignoring malformed allowlist update");
                continue;
            }
        };
        if let Some((id, ack)) = last_acks.get(&peer)
            && *id == update.id
        {
            let (peer, ack) = (peer.clone(), ack.clone());
            if commands
                .send(P2pCommand::SendAllowlistAck { peer, ack })
                .await
                .is_err()
            {
                return;
            }
            continue;
        }
        let result = match (&allowlist, update.request) {
            (None, _) => Err(DepositAllowlistError::Disabled),
            (Some(allowlist), Request::Get) => Ok(Response::Snapshot(allowlist.snapshot())),
            (Some(allowlist), Request::Status) => Ok(Response::Status(allowlist.status())),
            (Some(allowlist), Request::Write(write)) => {
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
        let ack = match encode_ack(update.id, result) {
            Ok(ack) => ack,
            Err(err) => {
                warn!(target: "zone::allowlist", %peer, %err, "Failed to encode allowlist acknowledgement");
                continue;
            }
        };
        last_acks.insert(peer.clone(), (update.id, ack.clone()));
        if commands
            .send(P2pCommand::SendAllowlistAck { peer, ack })
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Encode an acknowledgement, replacing a result too large for one frame with an error so the
/// relayer is never blocked for an oversized frame.
fn encode_ack(
    id: u64,
    result: Result<Response, DepositAllowlistError>,
) -> serde_json::Result<Vec<u8>> {
    let ack = serde_json::to_vec(&Ack { id, result })?;
    if ack.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE {
        return Ok(ack);
    }
    serde_json::to_vec(&Ack {
        id,
        result: Err(DepositAllowlistError::Internal(format!(
            "acknowledgement encodes to {} bytes; the relay limit is {MAX_ALLOWLIST_PAYLOAD_SIZE}",
            ack.len()
        ))),
    })
}

fn relay_error(message: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        jsonrpsee::types::error::INTERNAL_ERROR_CODE,
        message,
        None::<()>,
    )
}

#[cfg(test)]
mod tests {
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
        let ack = encode_ack(u64::MAX, Ok(snapshot(addresses.clone()))).unwrap();
        let ack: Ack = serde_json::from_slice(&ack).unwrap();
        assert_eq!(ack.result, Ok(snapshot(addresses.clone())));

        let replace = serde_json::to_vec(&Update {
            id: u64::MAX,
            request: Request::Write(SignedWrite {
                write: Write::Replace { addresses },
                nonce: u64::MAX,
                deadline: u64::MAX,
                signature: Bytes::from([0xff; 65]),
            }),
        })
        .unwrap();
        assert!(
            replace.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE,
            "{}",
            replace.len()
        );
    }

    #[test]
    fn oversized_ack_becomes_an_error() {
        let mut addresses = full_list();
        addresses.extend(full_list());
        let ack = encode_ack(7, Ok(snapshot(addresses))).unwrap();
        assert!(ack.len() <= MAX_ALLOWLIST_PAYLOAD_SIZE);
        let ack: Ack = serde_json::from_slice(&ack).unwrap();
        assert_eq!(ack.id, 7);
        assert!(matches!(
            ack.result,
            Err(DepositAllowlistError::Internal(_))
        ));
    }
}
