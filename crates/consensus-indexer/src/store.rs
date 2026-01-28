use tempo_node::rpc::consensus::{
    ConsensusFeed, ConsensusState, Event, IdentityProofError, IdentityTransitionResponse, Query,
};
use tokio::sync::broadcast;

use crate::{db::ConsensusDb, state::ConsensusCache};

#[derive(Clone, Debug)]
pub struct ConsensusStore {
    db: ConsensusDb,
    events_tx: broadcast::Sender<Event>,
    cache: ConsensusCache,
}

impl ConsensusStore {
    pub fn new(
        db: ConsensusDb,
        events_tx: broadcast::Sender<Event>,
        cache: ConsensusCache,
    ) -> Self {
        Self {
            db,
            events_tx,
            cache,
        }
    }

    pub fn events_tx(&self) -> broadcast::Sender<Event> {
        self.events_tx.clone()
    }

    pub fn cache(&self) -> &ConsensusCache {
        &self.cache
    }
}

impl ConsensusFeed for ConsensusStore {
    async fn get_finalization(
        &self,
        query: Query,
    ) -> Option<tempo_node::rpc::consensus::CertifiedBlock> {
        self.db.get_finalization(query).await.ok().flatten()
    }

    async fn get_latest(&self) -> ConsensusState {
        let mut snapshot = self.cache.snapshot().await;
        if snapshot.finalized.is_none()
            && let Ok(finalized) = self.db.latest_finalized().await
        {
            snapshot.finalized = finalized;
        }
        snapshot
    }

    async fn subscribe(&self) -> Option<broadcast::Receiver<Event>> {
        Some(self.events_tx.subscribe())
    }

    async fn get_identity_transition_proof(
        &self,
        from_epoch: Option<u64>,
        full: bool,
    ) -> Result<IdentityTransitionResponse, IdentityProofError> {
        self.db
            .get_identity_transition_proof(from_epoch, full)
            .await
            .map_err(|_| IdentityProofError::NotReady)
    }
}
