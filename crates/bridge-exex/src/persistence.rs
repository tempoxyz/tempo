//! Persistence layer for bridge state.
//!
//! Tracks signed deposits, pending burns, and enables recovery on restart.

use alloy::primitives::{Address, B256};
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Persistent state for the bridge sidecar
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeState {
    /// Deposits we have signed (request_id -> signature tx hash)
    pub signed_deposits: HashMap<B256, SignedDeposit>,

    /// Deposits that are fully finalized
    pub finalized_deposits: HashSet<B256>,

    /// Burns we have processed
    pub processed_burns: HashMap<B256, ProcessedBurn>,

    /// Last processed block for each origin chain
    pub origin_chain_blocks: HashMap<u64, u64>,

    /// Last processed Tempo block
    pub last_tempo_block: u64,
}

/// Record of a signed deposit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDeposit {
    pub request_id: B256,
    pub origin_chain_id: u64,
    pub origin_tx_hash: B256,
    pub tempo_recipient: Address,
    pub amount: u64,
    pub signature_tx_hash: B256,
    pub signed_at: u64,
}

/// Record of a processed burn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedBurn {
    pub burn_id: B256,
    pub origin_chain_id: u64,
    pub origin_recipient: Address,
    pub amount: u64,
    pub tempo_block_number: u64,
    pub unlock_tx_hash: Option<B256>,
    pub processed_at: u64,
}

/// Thread-safe bridge state manager
pub struct StateManager {
    state: Arc<RwLock<BridgeState>>,
    path: Option<std::path::PathBuf>,
}

impl StateManager {
    /// Create a new in-memory state manager
    pub fn new_in_memory() -> Self {
        Self {
            state: Arc::new(RwLock::new(BridgeState::default())),
            path: None,
        }
    }

    /// Create a state manager that persists to disk
    pub fn new_persistent(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let state = if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            serde_json::from_str(&contents)?
        } else {
            BridgeState::default()
        };

        Ok(Self {
            state: Arc::new(RwLock::new(state)),
            path: Some(path),
        })
    }

    /// Save state to disk (if persistent)
    pub async fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            let state = self.state.read().await;
            let contents = serde_json::to_string_pretty(&*state)?;

            // Write atomically
            let temp_path = path.with_extension("json.tmp");
            std::fs::write(&temp_path, contents)?;
            std::fs::rename(temp_path, path)?;

            debug!("Saved bridge state to {:?}", path);
        }
        Ok(())
    }

    /// Check if we have already signed a deposit
    pub async fn has_signed_deposit(&self, request_id: &B256) -> bool {
        self.state
            .read()
            .await
            .signed_deposits
            .contains_key(request_id)
    }

    /// Record that we signed a deposit
    pub async fn record_signed_deposit(&self, deposit: SignedDeposit) -> Result<()> {
        let request_id = deposit.request_id;
        {
            let mut state = self.state.write().await;
            state.signed_deposits.insert(request_id, deposit);
        }
        self.save().await?;
        info!(%request_id, "Recorded signed deposit");
        Ok(())
    }

    /// Mark a deposit as finalized
    pub async fn mark_deposit_finalized(&self, request_id: B256) -> Result<()> {
        {
            let mut state = self.state.write().await;
            state.finalized_deposits.insert(request_id);
        }
        self.save().await?;
        info!(%request_id, "Marked deposit as finalized");
        Ok(())
    }

    /// Check if a deposit is finalized
    pub async fn is_deposit_finalized(&self, request_id: &B256) -> bool {
        self.state
            .read()
            .await
            .finalized_deposits
            .contains(request_id)
    }

    /// Check if we have processed a burn
    pub async fn has_processed_burn(&self, burn_id: &B256) -> bool {
        self.state
            .read()
            .await
            .processed_burns
            .contains_key(burn_id)
    }

    /// Record a processed burn
    pub async fn record_processed_burn(&self, burn: ProcessedBurn) -> Result<()> {
        let burn_id = burn.burn_id;
        {
            let mut state = self.state.write().await;
            state.processed_burns.insert(burn_id, burn);
        }
        self.save().await?;
        info!(%burn_id, "Recorded processed burn");
        Ok(())
    }

    /// Update last processed block for an origin chain
    pub async fn update_origin_chain_block(&self, chain_id: u64, block: u64) -> Result<()> {
        {
            let mut state = self.state.write().await;
            state.origin_chain_blocks.insert(chain_id, block);
        }
        self.save().await
    }

    /// Get last processed block for an origin chain
    pub async fn get_origin_chain_block(&self, chain_id: u64) -> Option<u64> {
        self.state
            .read()
            .await
            .origin_chain_blocks
            .get(&chain_id)
            .copied()
    }

    /// Update last processed Tempo block
    pub async fn update_tempo_block(&self, block: u64) -> Result<()> {
        {
            let mut state = self.state.write().await;
            state.last_tempo_block = block;
        }
        self.save().await
    }

    /// Get last processed Tempo block
    pub async fn get_tempo_block(&self) -> u64 {
        self.state.read().await.last_tempo_block
    }

    /// Get pending (unsigned) deposits that need signing
    /// In production, this would query from on-chain state
    pub async fn get_pending_deposits(&self) -> Vec<B256> {
        let state = self.state.read().await;
        state
            .signed_deposits
            .iter()
            .filter(|(id, _)| !state.finalized_deposits.contains(*id))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get stats about the bridge state
    pub async fn get_stats(&self) -> BridgeStats {
        let state = self.state.read().await;
        BridgeStats {
            signed_deposits: state.signed_deposits.len(),
            finalized_deposits: state.finalized_deposits.len(),
            processed_burns: state.processed_burns.len(),
            last_tempo_block: state.last_tempo_block,
        }
    }

    /// Remove a signed deposit (e.g., due to reorg invalidation)
    pub async fn remove_signed_deposit(&self, request_id: &B256) -> Result<bool> {
        let removed = {
            let mut state = self.state.write().await;
            state.signed_deposits.remove(request_id).is_some()
        };
        if removed {
            self.save().await?;
            info!(%request_id, "Removed signed deposit (invalidated)");
        }
        Ok(removed)
    }

    /// Get a signed deposit by request ID
    pub async fn get_signed_deposit(&self, request_id: &B256) -> Option<SignedDeposit> {
        self.state
            .read()
            .await
            .signed_deposits
            .get(request_id)
            .cloned()
    }
}

/// Statistics about the bridge state
#[derive(Debug, Clone)]
pub struct BridgeStats {
    pub signed_deposits: usize,
    pub finalized_deposits: usize,
    pub processed_burns: usize,
    pub last_tempo_block: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_state() {
        let manager = StateManager::new_in_memory();

        let request_id = B256::repeat_byte(0x42);
        assert!(!manager.has_signed_deposit(&request_id).await);

        manager
            .record_signed_deposit(SignedDeposit {
                request_id,
                origin_chain_id: 1,
                origin_tx_hash: B256::ZERO,
                tempo_recipient: Address::ZERO,
                amount: 1000000,
                signature_tx_hash: B256::repeat_byte(0x11),
                signed_at: 12345,
            })
            .await
            .unwrap();

        assert!(manager.has_signed_deposit(&request_id).await);
        assert!(!manager.is_deposit_finalized(&request_id).await);

        manager.mark_deposit_finalized(request_id).await.unwrap();
        assert!(manager.is_deposit_finalized(&request_id).await);
    }

    #[tokio::test]
    async fn test_persistent_state() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("bridge-state.json");

        let request_id = B256::repeat_byte(0x42);

        // Create and save state
        {
            let manager = StateManager::new_persistent(&path).unwrap();
            manager
                .record_signed_deposit(SignedDeposit {
                    request_id,
                    origin_chain_id: 1,
                    origin_tx_hash: B256::ZERO,
                    tempo_recipient: Address::ZERO,
                    amount: 1000000,
                    signature_tx_hash: B256::repeat_byte(0x11),
                    signed_at: 12345,
                })
                .await
                .unwrap();
        }

        // Reload and verify
        {
            let manager = StateManager::new_persistent(&path).unwrap();
            assert!(manager.has_signed_deposit(&request_id).await);
        }
    }
}
