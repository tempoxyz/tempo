//! Persistence of accumulators alongside the block batches that produced them.

use crate::store::LthashStore;
use alloy_eips::eip1898::BlockNumHash;
use reth_chain_state::ExecutedBlock;
use reth_engine_tree::persistence::PersistenceHook;
use reth_errors::ProviderResult;
use reth_provider::{ProviderFactory, providers::ProviderNodeTypes};
use reth_storage_api::DatabaseProviderFactory;
use std::sync::Arc;

/// Persists lthash accumulators together with the block batches that produced them.
#[derive(Debug)]
pub struct LthashPersistenceHook {
    store: Arc<LthashStore>,
}

impl LthashPersistenceHook {
    /// Creates a hook flushing and pruning the given store.
    pub const fn new(store: Arc<LthashStore>) -> Self {
        Self { store }
    }
}

impl<N: ProviderNodeTypes> PersistenceHook<N> for LthashPersistenceHook {
    fn save_blocks(
        &self,
        provider: &<ProviderFactory<N> as DatabaseProviderFactory>::ProviderRW,
        blocks: &[ExecutedBlock<N::Primitives>],
    ) -> ProviderResult<()> {
        self.store.persist(provider.tx_ref(), blocks)
    }

    fn remove_blocks(
        &self,
        provider: &<ProviderFactory<N> as DatabaseProviderFactory>::ProviderRW,
        blocks: &[BlockNumHash],
    ) -> ProviderResult<()> {
        self.store.unwind(provider.tx_ref(), blocks)
    }
}
