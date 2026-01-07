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

pub use types::{
    CertifiedBlock, ConsensusFeed, ConsensusState, Event, IdentityProofError, IdentityTransition,
    IdentityTransitionResponse, Query, TransitionProofData,
};

/// Consensus namespace RPC trait.
#[rpc(server, client, namespace = "consensus")]
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
    async fn subscribe_events(&self) -> jsonrpsee::core::SubscriptionResult;

    /// Get identity transition proofs (full DKG events).
    ///
    /// Each proof contains the block header with the new DKG outcome, and a BLS certificate from the OLD
    /// network identity that signs the block.
    ///
    /// - `from_epoch`: Optional epoch to start searching from (defaults to latest finalized)
    /// - `full = false` (default): Returns only the most recent transition
    /// - `full = true`: Returns all transitions from the starting epoch back to genesis
    #[method(name = "getIdentityTransitionProof")]
    async fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: Option<bool>,
    ) -> RpcResult<IdentityTransitionResponse>;
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

    async fn subscribe_events(
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

    async fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: Option<bool>,
    ) -> RpcResult<IdentityTransitionResponse> {
        self.consensus_feed
            .get_identity_transition_proof(from_epoch, full.unwrap_or(false))
            .await
            .map_err(|e| ErrorObject::owned(INTERNAL_ERROR_CODE, e.to_string(), None::<()>))
    }
}
