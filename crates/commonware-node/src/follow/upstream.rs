//! Upstream node abstraction for follow mode.
//!
//! Defines the [`UpstreamNode`] trait that captures the operations the follow
//! engine needs from an upstream node, and provides two implementations:
//!
//! - [`WsUpstream`]: WebSocket RPC for production use.
//! - [`LocalUpstream`]: Direct access for testing network I/O.

use std::{sync::Arc, time::Duration};

use alloy_network::primitives::HeaderResponse as _;
use alloy_rpc_types_eth::Block as AlloyRpcBlock;
use eyre::WrapErr as _;
use futures::stream::{BoxStream, StreamExt as _};
use jsonrpsee::{
    core::client::ClientT,
    rpc_params,
    ws_client::{WsClient, WsClientBuilder},
};
use reth_node_core::primitives::SealedBlock;
use reth_primitives_traits::Block as _;
use reth_provider::{BlockReader as _, BlockSource};
use tempo_alloy::rpc::TempoHeaderResponse;
use tempo_node::{
    TempoFullNode,
    rpc::consensus::{CertifiedBlock, ConsensusFeed as _, Event, Query, TempoConsensusApiClient},
};
use tempo_primitives::TempoTxEnvelope;
use tokio::sync::Mutex;
use tracing::{debug, warn, warn_span};

use crate::{consensus::block::Block, feed::FeedStateHandle};

type TempoRpcBlock =
    AlloyRpcBlock<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

const RECONNECT_BASE_MS: u64 = 500;
const RECONNECT_MAX_MS: u64 = 30_000;

/// Abstraction over the upstream node that a follower syncs from.
///
/// In production this is backed by a WebSocket RPC connection ([`WsUpstream`]).
/// In tests it can be backed by in-process direct access to another node's
/// feed state and execution provider.
pub trait UpstreamNode: Send + Sync + 'static {
    fn subscribe_events(
        &self,
    ) -> impl std::future::Future<Output = eyre::Result<BoxStream<'static, eyre::Result<Event>>>> + Send;

    fn get_finalization(
        &self,
        query: Query,
    ) -> impl std::future::Future<Output = eyre::Result<Option<CertifiedBlock>>> + Send;

    fn get_block_by_number(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send;

    fn get_block_by_hash(
        &self,
        hash: alloy_primitives::B256,
    ) -> impl std::future::Future<Output = eyre::Result<Option<Block>>> + Send;

    fn get_block_and_finalization_by_number(
        &self,
        height: u64,
    ) -> impl std::future::Future<Output = eyre::Result<Option<(Block, CertifiedBlock)>>> + Send;
}

/// WebSocket-based upstream node for production use.
///
/// Owns a persistent WebSocket connection to the upstream node with
/// transparent reconnection.
pub struct WsUpstream {
    url: String,
    client: Mutex<Option<Arc<WsClient>>>,
}

impl WsUpstream {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: Mutex::new(None),
        }
    }

    async fn client(&self) -> eyre::Result<Arc<WsClient>> {
        let mut guard = self.client.lock().await;
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
                    guard.replace(c.clone());
                    if attempts > 0 {
                        debug!(attempts, "reconnected to upstream WebSocket");
                    }

                    return Ok(c);
                }
                Err(e) => {
                    attempts += 1;
                    let delay_ms =
                        (RECONNECT_BASE_MS * 2u64.pow(attempts.min(6))).min(RECONNECT_MAX_MS);

                    warn_span!("follow_ws_upstream").in_scope(|| {
                        warn!(
                            error = %e,
                            attempt = attempts,
                            retry_in_ms = delay_ms,
                            "failed to connect to upstream"
                        );
                    });

                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    fn convert_rpc_block(rpc_block: TempoRpcBlock, height_label: &str) -> eyre::Result<Block> {
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
            "block hash mismatch at {height_label}: expected {block_hash}, got {}",
            sealed.hash()
        );

        Ok(Block::from_execution_block(sealed))
    }
}

impl UpstreamNode for WsUpstream {
    async fn subscribe_events(&self) -> eyre::Result<BoxStream<'static, eyre::Result<Event>>> {
        let client = self.client().await?;
        let sub = client.subscribe_events().await.wrap_err("rpc error")?;
        Ok(sub
            .map(|item| item.map_err(|e| eyre::eyre!("subscription error: {e}")))
            .boxed())
    }

    async fn get_finalization(&self, query: Query) -> eyre::Result<Option<CertifiedBlock>> {
        let client = self.client().await?;
        client.get_finalization(query).await.wrap_err("rpc error")
    }

    async fn get_block_by_number(&self, height: u64) -> eyre::Result<Option<Block>> {
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

        Self::convert_rpc_block(rpc_block, &format!("height {height}")).map(Some)
    }

    async fn get_block_by_hash(&self, hash: alloy_primitives::B256) -> eyre::Result<Option<Block>> {
        let client = self.client().await?;
        let rpc_block: Option<TempoRpcBlock> = client
            .request("eth_getBlockByHash", rpc_params![hash, true])
            .await
            .wrap_err("rpc error")?;

        let Some(rpc_block) = rpc_block else {
            return Ok(None);
        };

        Self::convert_rpc_block(rpc_block, &format!("hash {hash}")).map(Some)
    }

    async fn get_block_and_finalization_by_number(
        &self,
        height: u64,
    ) -> eyre::Result<Option<(Block, CertifiedBlock)>> {
        let finalization = self.get_finalization(Query::Height(height)).await?;
        let block = self.get_block_by_number(height).await?;

        match block.zip(finalization) {
            None => Ok(None),
            Some((block, finalization)) => {
                eyre::ensure!(
                    block.block_hash() == finalization.digest,
                    "block and finalizationhash mismatch at height {height}",
                );

                Ok(Some((block, finalization)))
            }
        }
    }
}

/// Upstream backed by direct access to state.
///
/// Avoids WebSocket I/O, allowing the follow engine to run in a
/// deterministic runtime for testing.
pub struct LocalUpstream {
    feed: FeedStateHandle,
    execution_node: TempoFullNode,
}

impl LocalUpstream {
    pub fn new(feed: FeedStateHandle, execution_node: TempoFullNode) -> Self {
        Self {
            feed,
            execution_node,
        }
    }
}

impl UpstreamNode for LocalUpstream {
    async fn subscribe_events(&self) -> eyre::Result<BoxStream<'static, eyre::Result<Event>>> {
        let rx = self
            .feed
            .subscribe()
            .await
            .ok_or_else(|| eyre::eyre!("feed not ready for subscription"))?;

        let stream = futures::stream::unfold(rx, |mut rx| async {
            match rx.recv().await {
                Ok(event) => Some((Ok(event), rx)),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    Some((Err(eyre::eyre!("lagged by {n} events")), rx))
                }
            }
        })
        .boxed();

        Ok(stream)
    }

    async fn get_finalization(&self, query: Query) -> eyre::Result<Option<CertifiedBlock>> {
        Ok(self.feed.get_finalization(query).await)
    }

    async fn get_block_by_number(&self, height: u64) -> eyre::Result<Option<Block>> {
        let block = self
            .execution_node
            .provider
            .block_by_number(height)
            .map_err(|e| eyre::eyre!("provider error: {e}"))?
            .map(|b| Block::from_execution_block(b.seal()));

        Ok(block)
    }

    async fn get_block_by_hash(&self, hash: alloy_primitives::B256) -> eyre::Result<Option<Block>> {
        let block = self
            .execution_node
            .provider
            .find_block_by_hash(hash, BlockSource::Any)
            .map_err(|e| eyre::eyre!("provider error: {e}"))?
            .map(|b| Block::from_execution_block(b.seal()));

        Ok(block)
    }

    async fn get_block_and_finalization_by_number(
        &self,
        height: u64,
    ) -> eyre::Result<Option<(Block, CertifiedBlock)>> {
        let finalization = self.get_finalization(Query::Height(height)).await?;
        let block = self.get_block_by_number(height).await?;
        match block.zip(finalization) {
            None => Ok(None),
            Some((block, finalization)) => {
                eyre::ensure!(
                    block.block_hash() == finalization.digest,
                    "block and finalization hash mismatch at height {height}",
                );

                Ok(Some((block, finalization)))
            }
        }
    }
}
