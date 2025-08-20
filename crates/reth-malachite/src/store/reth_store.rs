//! RethStore implementation that uses reth's database infrastructure for persistent storage.

use crate::{Value, ValueId, context::MalachiteContext, height::Height};
use eyre::Result;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_types::{CommitCertificate, Round};
use reth_db_api::{
    cursor::{DbCursorRO, DbCursorRW},
    transaction::{DbTx, DbTxMut},
};
use reth_provider::{DBProvider, DatabaseProviderFactory};
use std::sync::Arc;
use tempo_telemetry_util::error_field;
use thiserror::Error;
use tracing::{debug, error, trace};

use super::{
    BlockStore,
    tables::{
        BlockKey, Blocks, ConsensusState, DecidedValue, DecidedValues, HeightKey, ProposalKey,
        StoredBlock, StoredProposal, UndecidedProposals,
    },
};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] reth_db_api::DatabaseError),

    #[error("Provider error: {0}")]
    Provider(#[from] reth_provider::ProviderError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Value not found")]
    NotFound,

    #[error("Other error: {0}")]
    Other(String),
}

/// Store implementation that uses reth's database for persistence
#[derive(Clone)]
pub struct RethStore<Provider> {
    /// Provider for database access
    provider: Arc<Provider>,
}

impl<Provider> RethStore<Provider>
where
    Provider: DatabaseProviderFactory + Send + Sync,
    Provider::Provider: Send,
    Provider::ProviderRW: Send,
{
    /// Create a new RethStore with the given provider
    pub fn new(provider: Arc<Provider>) -> Self {
        Self { provider }
    }

    /// Get a database provider for read operations
    fn provider(&self) -> Result<Provider::Provider, StoreError> {
        Ok(self.provider.database_provider_ro()?)
    }

    /// Get a database provider for write operations
    fn provider_rw(&self) -> Result<Provider::ProviderRW, StoreError> {
        Ok(self.provider.database_provider_rw()?)
    }

    /// Returns the maximum decided value height
    pub async fn max_decided_value_height(&self) -> Option<Height> {
        match self.provider() {
            Ok(provider) => {
                let tx = provider.tx_ref();
                match tx.cursor_read::<DecidedValues>() {
                    Ok(mut cursor) => match cursor.last() {
                        Ok(Some((key, _))) => Some(key.into()),
                        Ok(None) => None,
                        Err(e) => {
                            error!(error = error_field(&e), "Failed to read max height");
                            None
                        }
                    },
                    Err(e) => {
                        error!(error = error_field(&e), "Failed to open cursor");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error = error_field(&e), "Failed to get provider");
                None
            }
        }
    }

    /// Returns the minimum decided value height
    pub async fn min_decided_value_height(&self) -> Option<Height> {
        match self.provider() {
            Ok(provider) => {
                let tx = provider.tx_ref();
                match tx.cursor_read::<DecidedValues>() {
                    Ok(mut cursor) => match cursor.first() {
                        Ok(Some((key, _))) => Some(key.into()),
                        Ok(None) => None,
                        Err(e) => {
                            error!(error = error_field(&e), "Failed to read min height");
                            None
                        }
                    },
                    Err(e) => {
                        error!(error = error_field(&e), "Failed to open cursor");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error = error_field(&e), "Failed to get provider");
                None
            }
        }
    }

    /// Get a decided value by height
    pub async fn get_decided_value(
        &self,
        height: Height,
    ) -> Result<Option<DecidedValue>, StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();
        let key = HeightKey::from(height);

        trace!("Getting decided value for height {}", height.0);

        match tx.get::<DecidedValues>(key)? {
            Some(value) => {
                debug!("Found decided value for height {}", height.0);
                Ok(Some(value))
            }
            None => {
                trace!("No decided value found for height {}", height.0);
                Ok(None)
            }
        }
    }

    /// Store a decided value with its certificate
    pub async fn store_decided_value(
        &self,
        certificate: &CommitCertificate<MalachiteContext>,
        value: Value,
    ) -> Result<(), StoreError> {
        let mut provider_rw = self.provider_rw()?;

        let height = certificate.height;
        let key = HeightKey::from(height);
        let decided_value = DecidedValue {
            value,
            certificate: certificate.clone(),
        };

        debug!("Storing decided value for height {}", height.0);

        // Get a write cursor for the table
        {
            let tx = provider_rw.tx_mut();
            tx.put::<DecidedValues>(key, decided_value)?;
        }

        // Commit the transaction
        provider_rw.commit()?;

        Ok(())
    }

    /// Get undecided proposals for a height and round
    pub async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>, StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();

        trace!(
            "Getting undecided proposals for height {} round {}",
            height.0,
            round.as_u32().unwrap_or(0)
        );

        let mut proposals = Vec::new();
        let mut cursor = tx.cursor_read::<UndecidedProposals>()?;

        // Iterate through all proposals and filter by height and round
        let walker = cursor.walk(None)?;
        let round_u32 = round.as_u32().unwrap_or(0);
        for entry in walker {
            let (key, stored) = entry?;
            if key.height == height.0 && key.round == round_u32 {
                proposals.push(stored.proposal);
            }
            // Since keys are ordered, we can break early if we've passed our height
            if key.height > height.0 {
                break;
            }
        }

        debug!(
            "Found {} undecided proposals for height {} round {}",
            proposals.len(),
            height.0,
            round.as_u32().unwrap_or(0)
        );

        Ok(proposals)
    }

    /// Store an undecided proposal
    pub async fn store_undecided_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
    ) -> Result<(), StoreError> {
        let mut provider_rw = self.provider_rw()?;

        let value_id = proposal.value.id();
        let key = ProposalKey::new(proposal.height, proposal.round, &value_id);
        let stored = StoredProposal {
            proposal: proposal.clone(),
        };

        debug!(
            "Storing undecided proposal for height {} round {} with value_id {:?} (B256: {})",
            proposal.height.0,
            proposal.round.as_u32().unwrap_or(0),
            value_id,
            value_id.as_b256()
        );

        {
            let tx = provider_rw.tx_mut();
            tx.put::<UndecidedProposals>(key, stored)?;
        }

        provider_rw.commit()?;

        Ok(())
    }

    /// Get an undecided proposal by height, round, and value ID
    pub async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>, StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();

        let key = ProposalKey::new(height, round, &value_id);

        debug!(
            "Getting undecided proposal for height {} round {} value_id {:?} (B256: {})",
            height.0,
            round.as_u32().unwrap_or(0),
            value_id,
            value_id.as_b256()
        );

        match tx.get::<UndecidedProposals>(key)? {
            Some(stored) => {
                debug!("Found undecided proposal");
                Ok(Some(stored.proposal))
            }
            None => {
                trace!("No undecided proposal found");
                Ok(None)
            }
        }
    }

    /// Get an undecided proposal by value ID (searches all heights and rounds)
    pub async fn get_undecided_proposal_by_value_id(
        &self,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>, StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();

        trace!(
            "Searching for undecided proposal by value_id {:?}",
            value_id
        );

        let mut cursor = tx.cursor_read::<UndecidedProposals>()?;
        let walker = cursor.walk(None)?;

        for entry in walker {
            let (_, stored) = entry?;
            if stored.proposal.value.id() == value_id {
                debug!("Found undecided proposal by value_id");
                return Ok(Some(stored.proposal));
            }
        }

        trace!("No undecided proposal found by value_id");
        Ok(None)
    }

    /// Prune old data from the store
    pub async fn prune(
        &self,
        current_height: Height,
        retain_height: Height,
    ) -> Result<(), StoreError> {
        let mut provider_rw = self.provider_rw()?;

        debug!(
            "Pruning store: current_height={}, retain_height={}",
            current_height.0, retain_height.0
        );

        // Prune undecided proposals up to current height
        {
            let tx = provider_rw.tx_mut();
            let mut cursor = tx.cursor_write::<UndecidedProposals>()?;
            let walker = cursor.walk(None)?;

            let mut keys_to_delete = Vec::new();
            for entry in walker {
                let (key, _) = entry?;
                if key.height <= current_height.0 {
                    keys_to_delete.push(key);
                } else {
                    break; // Keys are ordered, so we can stop here
                }
            }

            for key in keys_to_delete {
                cursor.seek_exact(key)?;
                cursor.delete_current()?;
            }
        }

        // Prune decided values below retain height
        {
            let tx = provider_rw.tx_mut();
            let mut cursor = tx.cursor_write::<DecidedValues>()?;
            let walker = cursor.walk(None)?;

            let mut keys_to_delete = Vec::new();
            for entry in walker {
                let (key, _) = entry?;
                if key.0 < retain_height.0 {
                    keys_to_delete.push(key);
                } else {
                    break; // Keys are ordered, so we can stop here
                }
            }

            for key in keys_to_delete {
                cursor.seek_exact(key)?;
                cursor.delete_current()?;
            }
        }

        provider_rw.commit()?;

        debug!("Pruning completed");
        Ok(())
    }

    /// Store arbitrary consensus state data
    pub async fn set_consensus_state(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), StoreError>
    where
        Provider::ProviderRW: Send,
    {
        let mut provider_rw = self.provider_rw()?;

        {
            let tx = provider_rw.tx_mut();
            tx.put::<ConsensusState>(key, value)?;
        }

        provider_rw.commit()?;

        Ok(())
    }

    /// Get arbitrary consensus state data
    pub async fn get_consensus_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();

        Ok(tx.get::<ConsensusState>(key.to_vec())?)
    }

    /// Delete consensus state data
    pub async fn delete_consensus_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>
    where
        Provider::ProviderRW: Send,
    {
        let mut provider_rw = self.provider_rw()?;

        let value = {
            let tx = provider_rw.tx_ref();
            tx.get::<ConsensusState>(key.to_vec())?
        };

        if value.is_some() {
            {
                let tx = provider_rw.tx_mut();
                tx.delete::<ConsensusState>(key.to_vec(), None)?;
            }
            provider_rw.commit()?;
        }

        Ok(value)
    }

    /// Check if a consensus state key exists
    pub async fn contains_consensus_state(&self, key: &[u8]) -> bool {
        matches!(self.get_consensus_state(key).await, Ok(Some(_)))
    }

    /// Verify that all consensus tables exist in the database
    pub async fn verify_tables(&self) -> Result<(), StoreError> {
        let provider = self.provider()?;
        let tx = provider.tx_ref();

        // Try to create cursors for each table to verify they exist
        let _decided_values_cursor = tx
            .cursor_read::<DecidedValues>()
            .map_err(|e| StoreError::Other(format!("DecidedValues table not found: {e:?}")))?;

        let _undecided_proposals_cursor = tx
            .cursor_read::<UndecidedProposals>()
            .map_err(|e| StoreError::Other(format!("UndecidedProposals table not found: {e:?}")))?;

        let _consensus_state_cursor = tx
            .cursor_read::<ConsensusState>()
            .map_err(|e| StoreError::Other(format!("ConsensusState table not found: {e:?}")))?;

        let _blocks_cursor = tx
            .cursor_read::<Blocks>()
            .map_err(|e| StoreError::Other(format!("Blocks table not found: {e:?}")))?;

        debug!("All consensus tables verified successfully");
        Ok(())
    }
}

impl<Provider> BlockStore for RethStore<Provider>
where
    Provider: DatabaseProviderFactory + Send + Sync,
    Provider::Provider: Send,
    Provider::ProviderRW: Send,
{
    fn store_block(&self, block: reth_ethereum_primitives::Block) -> Result<()> {
        let hash = block.header.hash_slow();
        debug!("Storing block with hash: {}", hash);

        let mut provider = self.provider_rw()?;

        let key = BlockKey::from(hash);
        let stored_block = StoredBlock { block };

        provider.tx_mut().put::<Blocks>(key, stored_block)?;

        provider.commit()?;

        debug!("Successfully stored block with hash: {}", hash);
        Ok(())
    }

    fn get_block(
        &self,
        hash: &alloy_primitives::B256,
    ) -> Result<Option<reth_ethereum_primitives::Block>> {
        trace!("Getting block with hash: {}", hash);

        let provider = self.provider()?;
        let key = BlockKey::from(*hash);

        let result = provider.tx_ref().get::<Blocks>(key)?;

        Ok(result.map(|stored| stored.block))
    }

    fn has_block(&self, hash: &alloy_primitives::B256) -> Result<bool> {
        trace!("Checking if block exists with hash: {}", hash);

        let provider = self.provider()?;
        let key = BlockKey::from(*hash);

        let mut cursor = provider.tx_ref().cursor_read::<Blocks>()?;
        Ok(cursor.seek_exact(key)?.is_some())
    }

    fn remove_block(&self, hash: &alloy_primitives::B256) -> Result<()> {
        debug!("Removing block with hash: {}", hash);

        let mut provider = self.provider_rw()?;
        let key = BlockKey::from(*hash);

        let mut cursor = provider.tx_mut().cursor_write::<Blocks>()?;

        if cursor.seek_exact(key)?.is_some() {
            cursor.delete_current()?;
            provider.commit()?;
            debug!("Successfully removed block with hash: {}", hash);
        } else {
            trace!("Block not found for removal: {}", hash);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    // TODO: Add unit tests once we have test utilities for creating a test database
}
