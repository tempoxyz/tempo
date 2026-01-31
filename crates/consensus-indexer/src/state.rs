use tempo_node::rpc::consensus::{CertifiedBlock, ConsensusState};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Default)]
pub struct ConsensusCache {
    state: std::sync::Arc<RwLock<ConsensusState>>,
}

impl ConsensusCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn snapshot(&self) -> ConsensusState {
        self.state.read().await.clone()
    }

    pub async fn update_notarized(&self, block: CertifiedBlock) {
        let mut state = self.state.write().await;
        let finalized_height = state.finalized.as_ref().and_then(|b| b.height);
        let should_update_finalized = finalized_height
            .zip(block.height)
            .map(|(finalized, candidate)| finalized < candidate)
            .unwrap_or(finalized_height.is_none());

        let should_update_view = state.notarized.as_ref().is_none_or(|n| n.view < block.view);

        if should_update_finalized && should_update_view {
            state.notarized = Some(block);
        }
    }

    pub async fn update_finalized(&self, block: CertifiedBlock) {
        let mut state = self.state.write().await;
        let should_update = state
            .finalized
            .as_ref()
            .is_none_or(|f| f.height < block.height);

        if should_update {
            if state
                .notarized
                .as_ref()
                .is_some_and(|n| n.view <= block.view)
            {
                state.notarized = None;
            }
            state.finalized = Some(block);
        }
    }
}
