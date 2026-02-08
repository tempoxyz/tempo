//! RPC-based resolver for follow mode.
//!
//! Owns a persistent WebSocket connection to the upstream node with transparent
//! reconnection.  Used directly by the driver for event streaming and
//! block/finalization fetches, and implements [`Resolver`] for marshal's
//! gap-repair machinery.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use alloy_network::primitives::HeaderResponse as _;
use alloy_rpc_types_eth::Block as AlloyRpcBlock;
use bytes::Bytes;
use commonware_codec::{Encode, ReadExt as _};
use commonware_consensus::{
    marshal::ingress::handler,
    simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_resolver::Resolver;
use commonware_utils::{
    channel::{mpsc, oneshot},
    vec::NonEmptyVec,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::client::Subscription;
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use reth_node_core::primitives::SealedBlock;
use tempo_alloy::rpc::TempoHeaderResponse;
use tempo_node::rpc::consensus::{Event, TempoConsensusApiClient};
use tempo_primitives::TempoTxEnvelope;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, warn, warn_span};

use crate::consensus::{Digest, block::Block};

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur during RPC operations.
#[derive(Debug)]
pub enum RpcError {
    NotFound(String),
    Rpc(String),
    Decode(String),
    Validation(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) => write!(f, "not found: {s}"),
            Self::Rpc(s) => write!(f, "RPC error: {s}"),
            Self::Decode(s) => write!(f, "decode error: {s}"),
            Self::Validation(s) => write!(f, "validation error: {s}"),
        }
    }
}

impl std::error::Error for RpcError {}

pub type RpcResult<T> = Result<T, RpcError>;

// ── RpcResolver ─────────────────────────────────────────────────────────────

type TempoRpcBlock =
    AlloyRpcBlock<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

type Request = handler::Request<Block>;
type Message = handler::Message<Block>;

const RECONNECT_BASE_MS: u64 = 500;
const RECONNECT_MAX_MS: u64 = 30_000;

pub struct RpcResolver {
    url: String,
    client: RwLock<Option<Arc<WsClient>>>,
    sender: mpsc::Sender<Message>,
    pending: Arc<Mutex<HashSet<Request>>>,
}

impl Clone for RpcResolver {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            client: RwLock::new(None),
            sender: self.sender.clone(),
            pending: self.pending.clone(),
        }
    }
}

impl RpcResolver {
    pub fn new(url: String, sender: mpsc::Sender<Message>) -> Self {
        Self {
            url,
            client: RwLock::new(None),
            sender,
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    // ── Connection management ───────────────────────────────────────────

    async fn client(&self) -> RpcResult<Arc<WsClient>> {
        {
            let guard = self.client.read().await;
            if let Some(c) = guard.as_ref() {
                if c.is_connected() {
                    return Ok(c.clone());
                }
            }
        }
        self.reconnect().await
    }

    async fn reconnect(&self) -> RpcResult<Arc<WsClient>> {
        let mut guard = self.client.write().await;
        if let Some(c) = guard.as_ref() {
            if c.is_connected() {
                return Ok(c.clone());
            }
        }

        let mut attempts: u32 = 0;
        loop {
            match WsClientBuilder::default().build(&self.url).await {
                Ok(c) => {
                    let c = Arc::new(c);
                    *guard = Some(c.clone());
                    if attempts > 0 {
                        debug!(attempts, "reconnected to upstream WebSocket");
                    }
                    return Ok(c);
                }
                Err(e) => {
                    attempts += 1;
                    let delay_ms =
                        (RECONNECT_BASE_MS * 2u64.pow(attempts.min(6))).min(RECONNECT_MAX_MS);

                    warn_span!("follow").in_scope(|| {
                        warn!(
                            error = %e,
                            attempt = attempts,
                            retry_in_ms = delay_ms,
                            "failed to connect to upstream WebSocket"
                        );
                    });

                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    // ── Public fetch helpers (used by driver) ───────────────────────────

    pub async fn subscribe_events(&self) -> RpcResult<Subscription<Event>> {
        let client = self.client().await?;
        client
            .subscribe_events()
            .await
            .map_err(|e| RpcError::Rpc(e.to_string()))
    }

    pub async fn fetch_finalization(
        &self,
        height: u64,
    ) -> RpcResult<Option<tempo_node::rpc::consensus::CertifiedBlock>> {
        let client = self.client().await?;
        client
            .get_finalization(tempo_node::rpc::consensus::Query::Height(height))
            .await
            .map_err(|e| RpcError::Rpc(e.to_string()))
    }

    pub async fn fetch_latest_finalization(
        &self,
    ) -> RpcResult<Option<tempo_node::rpc::consensus::CertifiedBlock>> {
        let client = self.client().await?;
        client
            .get_finalization(tempo_node::rpc::consensus::Query::Latest)
            .await
            .map_err(|e| RpcError::Rpc(e.to_string()))
    }

    pub async fn fetch_block(&self, height: u64) -> RpcResult<Option<Block>> {
        let client = self.client().await?;
        let rpc_block: Option<TempoRpcBlock> = client
            .request(
                "eth_getBlockByNumber",
                rpc_params![format!("0x{:x}", height), true],
            )
            .await
            .map_err(|e| RpcError::Rpc(e.to_string()))?;
        let Some(rpc_block) = rpc_block else {
            return Ok(None);
        };
        let block_hash = rpc_block.header.hash();
        let consensus_block = rpc_block
            .into_consensus_block()
            .map_header(|h| h.inner.inner)
            .map_transactions(|tx: alloy_rpc_types_eth::Transaction<TempoTxEnvelope>| {
                tx.into_inner()
            });
        let sealed = SealedBlock::seal_slow(consensus_block);
        if sealed.hash() != block_hash {
            return Err(RpcError::Validation(format!(
                "block hash mismatch at height {height}: expected {block_hash}, got {}",
                sealed.hash()
            )));
        }
        Ok(Some(Block::from_execution_block(sealed)))
    }

    pub async fn fetch_block_by_hash(&self, hash: alloy_primitives::B256) -> RpcResult<Option<Block>> {
        let client = self.client().await?;
        let rpc_block: Option<TempoRpcBlock> = client
            .request(
                "eth_getBlockByHash",
                rpc_params![hash, true],
            )
            .await
            .map_err(|e| RpcError::Rpc(e.to_string()))?;
        let Some(rpc_block) = rpc_block else {
            return Ok(None);
        };
        let block_hash = rpc_block.header.hash();
        let consensus_block = rpc_block
            .into_consensus_block()
            .map_header(|h| h.inner.inner)
            .map_transactions(|tx: alloy_rpc_types_eth::Transaction<TempoTxEnvelope>| {
                tx.into_inner()
            });
        let sealed = SealedBlock::seal_slow(consensus_block);
        if sealed.hash() != block_hash {
            return Err(RpcError::Validation(format!(
                "block hash mismatch: expected {block_hash}, got {}",
                sealed.hash()
            )));
        }
        Ok(Some(Block::from_execution_block(sealed)))
    }

    // ── Resolver internals (gap-repair delivery to marshal) ─────────────

    fn spawn_fetch(&self, key: Request) {
        let resolver = self.clone();
        let key_clone = key.clone();

        tokio::spawn(async move {
            {
                let p = resolver.pending.lock().await;
                if !p.contains(&key_clone) {
                    return;
                }
            }

            let result = match &key_clone {
                handler::Request::Finalized { height } => {
                    resolver.resolve_finalized(height.clone()).await
                }
                handler::Request::Block(commitment) => {
                    resolver.resolve_block(*commitment).await
                }
                other => {
                    warn_span!("follow")
                        .in_scope(|| warn!(?other, "unexpected resolver request type"));
                    return;
                }
            };

            {
                let p = resolver.pending.lock().await;
                if !p.contains(&key_clone) {
                    return;
                }
            }

            match result {
                Ok(Some(value)) => {
                    let (response_tx, response_rx) = oneshot::channel();
                    if resolver
                        .sender
                        .send(Message::Deliver {
                            key: key_clone.clone(),
                            value,
                            response: response_tx,
                        })
                        .await
                        .is_ok()
                    {
                        if let Ok(true) = response_rx.await {
                            resolver.pending.lock().await.remove(&key_clone);
                        }
                    }
                }
                Ok(None) => {
                    debug!(?key_clone, "data not yet available from upstream");
                }
                Err(e) => {
                    warn!(?key_clone, error = %e, "failed to fetch from upstream");
                }
            }
        });
    }

    async fn resolve_finalized(
        &self,
        height: commonware_consensus::types::Height,
    ) -> eyre::Result<Option<Bytes>> {
        let h = height.get();
        let certified = match self.fetch_finalization(h).await {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(None),
            Err(e) => return Err(eyre::eyre!("{e}")),
        };
        let block = match self.fetch_block(h).await {
            Ok(Some(b)) => b,
            Ok(None) => return Err(eyre::eyre!("block {h} not found but finalization exists")),
            Err(e) => return Err(eyre::eyre!("{e}")),
        };
        let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
            .map_err(|e| eyre::eyre!("failed to decode certificate hex: {e}"))?;
        let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
            Finalization::read(&mut &cert_bytes[..])
                .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))?;
        Ok(Some((finalization, block).encode()))
    }

    async fn resolve_block(&self, commitment: Digest) -> eyre::Result<Option<Bytes>> {
        let block = match self.fetch_block_by_hash(commitment.0).await {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(None),
            Err(e) => return Err(eyre::eyre!("{e}")),
        };
        Ok(Some(block.encode()))
    }
}

// ── Resolver trait impl ─────────────────────────────────────────────────────

impl Resolver for RpcResolver {
    type Key = Request;
    type PublicKey = PublicKey;

    async fn fetch(&mut self, key: Self::Key) {
        self.pending.lock().await.insert(key.clone());
        self.spawn_fetch(key);
    }

    async fn fetch_all(&mut self, keys: Vec<Self::Key>) {
        let mut pending = self.pending.lock().await;
        for key in &keys {
            pending.insert(key.clone());
        }
        drop(pending);
        for key in keys {
            self.spawn_fetch(key);
        }
    }

    async fn fetch_targeted(&mut self, key: Self::Key, _targets: NonEmptyVec<Self::PublicKey>) {
        Resolver::fetch(self, key).await;
    }

    async fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) {
        let keys: Vec<Self::Key> = requests.into_iter().map(|(k, _)| k).collect();
        self.fetch_all(keys).await;
    }

    async fn cancel(&mut self, key: Self::Key) {
        self.pending.lock().await.remove(&key);
    }

    async fn clear(&mut self) {
        self.pending.lock().await.clear();
    }

    async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
        self.pending.lock().await.retain(|k| predicate(k));
    }
}
