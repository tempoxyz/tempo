//! Consensus namespace RPC implementation.
//!
//! Provides query methods and subscriptions for consensus data:
//! - `consensus_getFinalization(query)` - Get finalization by height from marshal archive
//! - `consensus_getLatest()` - Get the current consensus state snapshot
//! - `consensus_subscribe()` - Subscribe to consensus events stream

pub mod types;

use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{ErrorObject, error::INTERNAL_ERROR_CODE},
};

pub use types::{CertifiedBlock, ConsensusFeed, ConsensusState, Event, Query};

/// Consensus namespace RPC trait.
#[rpc(server, namespace = "consensus")]
pub trait TempoConsensusApi {
    /// Get finalization by height query.
    ///
    /// Use `"latest"` to get the most recent finalization, or `{"height": N}` for a specific height.
    #[method(name = "getFinalization")]
    async fn get_finalization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>>;

    /// Get the current consensus state snapshot.
    ///
    /// Returns the latest finalized block and the latest notarized block (if not yet finalized).
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
    async fn get_finalization(&self, query: Query) -> RpcResult<Option<CertifiedBlock>> {
        Ok(self.consensus_feed.get_finalization(query).await)
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
