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
use eyre::WrapErr as _;
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

// ── RpcResolver ─────────────────────────────────────────────────────────────

type TempoRpcBlock =
    AlloyRpcBlock<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

type Request = handler::Request<Block>;
type Message = handler::Message<Block>;

const RECONNECT_BASE_MS: u64 = 500;
const RECONNECT_MAX_MS: u64 = 30_000;

pub(crate) struct RpcResolver {
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
    pub(crate) fn new(url: String, sender: mpsc::Sender<Message>) -> Self {
        Self {
            url,
            client: RwLock::new(None),
            sender,
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    // ── Connection management ───────────────────────────────────────────

    async fn client(&self) -> eyre::Result<Arc<WsClient>> {
        {
            let guard = self.client.read().await;
            if let Some(c) = guard.as_ref()
                && c.is_connected()
            {
                return Ok(c.clone());
            }
        }
        self.reconnect().await
    }

    async fn reconnect(&self) -> eyre::Result<Arc<WsClient>> {
        let mut guard = self.client.write().await;
        if let Some(c) = guard.as_ref()
            && c.is_connected()
        {
            return Ok(c.clone());
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

    pub(crate) async fn subscribe_events(&self) -> eyre::Result<Subscription<Event>> {
        let client = self.client().await?;
        client.subscribe_events().await.wrap_err("rpc error")
    }

    pub(crate) async fn fetch_finalization(
        &self,
        height: u64,
    ) -> eyre::Result<Option<tempo_node::rpc::consensus::CertifiedBlock>> {
        let client = self.client().await?;
        client
            .get_finalization(tempo_node::rpc::consensus::Query::Height(height))
            .await
            .wrap_err("rpc error")
    }

    pub(crate) async fn fetch_latest_finalization(
        &self,
    ) -> eyre::Result<Option<tempo_node::rpc::consensus::CertifiedBlock>> {
        let client = self.client().await?;
        client
            .get_finalization(tempo_node::rpc::consensus::Query::Latest)
            .await
            .wrap_err("rpc error")
    }

    pub(crate) async fn fetch_block(&self, height: u64) -> eyre::Result<Option<Block>> {
        let client = self.client().await?;
        let rpc_block: Option<TempoRpcBlock> = client
            .request(
                "eth_getBlockByNumber",
                rpc_params![format!("0x{:x}", height), true],
            )
            .await
            .wrap_err("rpc error")?;
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
        eyre::ensure!(
            sealed.hash() == block_hash,
            "block hash mismatch at height {height}: expected {block_hash}, got {}",
            sealed.hash()
        );
        Ok(Some(Block::from_execution_block(sealed)))
    }

    pub(crate) async fn fetch_block_by_hash(
        &self,
        hash: alloy_primitives::B256,
    ) -> eyre::Result<Option<Block>> {
        let client = self.client().await?;
        let rpc_block: Option<TempoRpcBlock> = client
            .request("eth_getBlockByHash", rpc_params![hash, true])
            .await
            .wrap_err("rpc error")?;
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
        eyre::ensure!(
            sealed.hash() == block_hash,
            "block hash mismatch: expected {block_hash}, got {}",
            sealed.hash()
        );
        Ok(Some(Block::from_execution_block(sealed)))
    }

    // ── Resolver internals (gap-repair delivery to marshal) ─────────────

    fn spawn_fetch(&self, key: Request) {
        let resolver = self.clone();
        let key_clone = key;

        tokio::spawn(async move {
            {
                let p = resolver.pending.lock().await;
                if !p.contains(&key_clone) {
                    return;
                }
            }

            let result = match &key_clone {
                handler::Request::Finalized { height } => resolver.resolve_finalized(*height).await,
                handler::Request::Block(commitment) => resolver.resolve_block(*commitment).await,
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
                        && let Ok(true) = response_rx.await
                    {
                        resolver.pending.lock().await.remove(&key_clone);
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
        let Some(certified) = self.fetch_finalization(h).await? else {
            return Ok(None);
        };
        let block = self
            .fetch_block(h)
            .await?
            .ok_or_else(|| eyre::eyre!("block {h} not found but finalization exists"))?;
        let cert_bytes = alloy_primitives::hex::decode(&certified.certificate)
            .wrap_err("failed to decode certificate hex")?;
        let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
            Finalization::read(&mut &cert_bytes[..])
                .map_err(|e| eyre::eyre!("failed to decode finalization: {e:?}"))?;
        Ok(Some((finalization, block).encode()))
    }

    async fn resolve_block(&self, commitment: Digest) -> eyre::Result<Option<Bytes>> {
        let Some(block) = self.fetch_block_by_hash(commitment.0).await? else {
            return Ok(None);
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
