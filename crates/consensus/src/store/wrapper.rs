//! Store wrapper for easier integration with the State module.

use super::{BlockStore, RethStore};
use crate::{Value, ValueId, context::MalachiteContext, height::Height};
use alloy_primitives::B256;
use eyre::Result;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_types::{CommitCertificate, Round};
use reth_provider::DatabaseProviderFactory;
use std::sync::Arc;

/// A wrapper around RethStore that hides the generic parameter
#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn StoreOps + Send + Sync>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish()
    }
}

impl Store {
    /// Create a new Store from any provider that implements DatabaseProviderFactory
    pub fn new<P>(provider: Arc<P>) -> Self
    where
        P: DatabaseProviderFactory + Send + Sync + 'static,
        P::Provider: Send,
        P::ProviderRW: Send,
    {
        Self {
            inner: Arc::new(RethStore::new(provider)),
        }
    }

    /// Returns the maximum decided value height
    pub async fn max_decided_value_height(&self) -> Option<Height> {
        self.inner.max_decided_value_height().await
    }

    /// Get a decided value by height
    pub async fn get_decided_value(&self, height: Height) -> Result<Option<super::DecidedValue>> {
        self.inner.get_decided_value(height).await
    }

    /// Store a decided value with its certificate
    pub async fn store_decided_value(
        &self,
        certificate: CommitCertificate<MalachiteContext>,
        value: Value,
    ) -> Result<()> {
        self.inner.store_decided_value(&certificate, value).await
    }

    /// Get undecided proposals for a height and round
    pub async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>> {
        self.inner.get_undecided_proposals(height, round).await
    }

    /// Store an undecided proposal along with its block
    pub async fn store_undecided_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
        block: reth_primitives::Block,
    ) -> Result<()> {
        // Store the block first
        self.inner.store_block(block).await?;
        // Then store the proposal that references it
        self.inner.store_undecided_proposal(proposal).await
    }

    /// Get an undecided proposal by height, round, and value ID
    pub async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        self.inner
            .get_undecided_proposal(height, round, value_id)
            .await
    }

    /// Verify that all consensus tables exist in the database
    pub async fn verify_tables(&self) -> Result<()> {
        self.inner.verify_tables().await
    }

    /// Store a block indexed by its hash
    pub async fn store_block(&self, block: reth_primitives::Block) -> Result<()> {
        self.inner.store_block(block).await
    }

    /// Get a block by its hash
    pub async fn get_block(&self, hash: &B256) -> Result<Option<reth_primitives::Block>> {
        self.inner.get_block(hash).await
    }

    /// Check if a block exists by its hash
    pub async fn has_block(&self, hash: &B256) -> Result<bool> {
        self.inner.has_block(hash).await
    }

    /// Remove a block by its hash
    pub async fn remove_block(&self, hash: &B256) -> Result<()> {
        self.inner.remove_block(hash).await
    }
}

/// Internal trait to encapsulate storage operations needed by State.
///
/// This trait defines the storage API that State requires to manage the blockchain state.
/// It serves as an abstraction boundary between State's business logic and the underlying
/// storage implementation (RethStore).
///
/// API boundaries:
/// - **Consensus -> State**: High-level operations like commit(), get_decided_value()
/// - **State -> Store**: Low-level storage operations defined in this trait
/// - **Store -> RethStore**: Implementation details using reth's database
#[async_trait::async_trait]
trait StoreOps {
    // Core storage operations used by State:

    /// Store a decided (committed) value with its commit certificate
    async fn store_decided_value(
        &self,
        certificate: &CommitCertificate<MalachiteContext>,
        value: Value,
    ) -> Result<()>;

    /// Retrieve a decided value at a specific height
    async fn get_decided_value(&self, height: Height) -> Result<Option<super::DecidedValue>>;

    /// Store a proposal that hasn't been decided yet
    async fn store_undecided_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
    ) -> Result<()>;

    /// Retrieve a specific undecided proposal
    async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>>;

    /// Verify that all required database tables exist
    async fn verify_tables(&self) -> Result<()>;

    // Additional operations that may be needed as State evolves:

    /// Get the highest height with a decided value
    async fn max_decided_value_height(&self) -> Option<Height>;

    /// Get all proposals for a given height and round
    async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>>;

    // Block storage operations:

    /// Store a block by its hash
    async fn store_block(&self, block: reth_primitives::Block) -> Result<()>;

    /// Get a block by its hash
    async fn get_block(
        &self,
        hash: &alloy_primitives::B256,
    ) -> Result<Option<reth_primitives::Block>>;

    /// Check if a block exists
    async fn has_block(&self, hash: &alloy_primitives::B256) -> Result<bool>;

    /// Remove a block by its hash
    async fn remove_block(&self, hash: &alloy_primitives::B256) -> Result<()>;
}

#[async_trait::async_trait]
impl<P> StoreOps for RethStore<P>
where
    P: DatabaseProviderFactory + Send + Sync,
    P::Provider: Send,
    P::ProviderRW: Send,
{
    async fn max_decided_value_height(&self) -> Option<Height> {
        self.max_decided_value_height().await
    }

    async fn get_decided_value(&self, height: Height) -> Result<Option<super::DecidedValue>> {
        self.get_decided_value(height).await.map_err(Into::into)
    }

    async fn store_decided_value(
        &self,
        certificate: &CommitCertificate<MalachiteContext>,
        value: Value,
    ) -> Result<()> {
        self.store_decided_value(certificate, value)
            .await
            .map_err(Into::into)
    }

    async fn get_undecided_proposals(
        &self,
        height: Height,
        round: Round,
    ) -> Result<Vec<ProposedValue<MalachiteContext>>> {
        self.get_undecided_proposals(height, round)
            .await
            .map_err(Into::into)
    }

    async fn store_undecided_proposal(
        &self,
        proposal: ProposedValue<MalachiteContext>,
    ) -> Result<()> {
        self.store_undecided_proposal(proposal)
            .await
            .map_err(Into::into)
    }

    async fn get_undecided_proposal(
        &self,
        height: Height,
        round: Round,
        value_id: ValueId,
    ) -> Result<Option<ProposedValue<MalachiteContext>>> {
        self.get_undecided_proposal(height, round, value_id)
            .await
            .map_err(Into::into)
    }

    async fn verify_tables(&self) -> Result<()> {
        self.verify_tables().await.map_err(Into::into)
    }

    async fn store_block(&self, block: reth_primitives::Block) -> Result<()> {
        BlockStore::store_block(self, block)
    }

    async fn get_block(&self, hash: &B256) -> Result<Option<reth_primitives::Block>> {
        BlockStore::get_block(self, hash)
    }

    async fn has_block(&self, hash: &B256) -> Result<bool> {
        BlockStore::has_block(self, hash)
    }

    async fn remove_block(&self, hash: &B256) -> Result<()> {
        BlockStore::remove_block(self, hash)
    }
}
