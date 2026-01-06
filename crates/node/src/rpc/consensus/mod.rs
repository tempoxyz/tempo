//! Consensus namespace RPC implementation.
//!
//! Provides query methods and subscriptions for consensus data:
//! - `consensus_getNotarization(query)` - Get notarization by view from in-memory cache
//! - `consensus_getFinalization(query)` - Get finalization by height from marshal archive
//! - `consensus_getLatest()` - Get the current consensus state snapshot
//! - `consensus_subscribe()` - Subscribe to consensus events stream

pub mod types;

use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{
        ErrorObject,
        error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    },
};

pub use types::{CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query, QueryError};

/// Consensus namespace RPC trait.
#[rpc(server, namespace = "consensus")]
pub trait TempoConsensusApi {
    /// Get notarization by view query.
    ///
    /// Use `"latest"` to get the most recent notarization, or `{"view": N}` for a specific view.
    /// Returns an error if `{"height": N}` is used (height queries only work for finalizations).
    #[method(name = "getNotarization")]
    async fn get_notarization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>>;

    /// Get finalization by height query.
    ///
    /// Use `"latest"` to get the most recent finalization, or `{"height": N}` for a specific height.
    /// Returns an error if `{"view": N}` is used (view queries only work for notarizations).
    #[method(name = "getFinalization")]
    async fn get_finalization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>>;

    /// Get the current consensus state snapshot.
    ///
    /// Returns the latest finalized block and all cached notarizations.
    #[method(name = "getLatest")]
    async fn get_latest(&self) -> RpcResult<ConsensusState>;

    /// Subscribe to all consensus events (Notarized, Finalized, Nullified).
    #[subscription(name = "subscribe" => "event", unsubscribe = "unsubscribe", item = Event)]
    async fn subscribe(&self) -> jsonrpsee::core::SubscriptionResult;
}

/// Tempo consensus RPC implementation.
#[derive(Debug, Clone)]
pub struct TempoConsensusRpc<I> {
    consensus_feed: I,
}

impl<I: ConsensusFeed> TempoConsensusRpc<I> {
    /// Create a new consensus RPC handler.
    pub fn new(consensus_feed: I) -> Self {
        Self { consensus_feed }
    }
}

#[async_trait::async_trait]
impl<I: ConsensusFeed> TempoConsensusApiServer for TempoConsensusRpc<I> {
    async fn get_notarization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>> {
        self.consensus_feed
            .get_notarization(query)
            .await
            .map_err(|e| ErrorObject::owned(INVALID_PARAMS_CODE, e.to_string(), None::<()>))
    }

    async fn get_finalization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>> {
        self.consensus_feed
            .get_finalization(query)
            .await
            .map_err(|e| ErrorObject::owned(INVALID_PARAMS_CODE, e.to_string(), None::<()>))
    }

    async fn get_latest(&self) -> RpcResult<ConsensusState> {
        Ok(self.consensus_feed.get_latest().await)
    }

    async fn subscribe(
        &self,
        pending: jsonrpsee::PendingSubscriptionSink,
    ) -> jsonrpsee::core::SubscriptionResult {
        let sink = pending.accept().await?;
        let mut rx = self.consensus_feed.subscribe().await.ok_or_else(|| {
            ErrorObject::owned(INTERNAL_ERROR_CODE, "Failed to subscribe", None::<()>)
        })?;

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let msg = jsonrpsee::SubscriptionMessage::new(
                            sink.method_name(),
                            sink.subscription_id().clone(),
                            &event,
                        )
                        .expect("Event should be serializable");
                        if sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });

        Ok(())
    }
}
