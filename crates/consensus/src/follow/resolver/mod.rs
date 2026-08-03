//! Resolver for follow mode.
//!
//! Implements [`commonware_resolver::Resolver`] for marshal's gap-repair machinery. Checks the
//! local execution provider first and falls back to the upstream abstraction.

use std::{future::Future, time::Duration};

use commonware_consensus::{marshal::resolver::handler, types::Height};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::mpsc;
use reth_ethereum::provider::db::DatabaseEnv;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_primitives_traits::NodePrimitives;
use reth_provider::{
    BlockReader as _, BlockSource,
    providers::{BlockchainProvider, ProviderNodeTypes},
};
use tempo_node::{node::TempoNode, rpc::consensus::CertifiedBlock};
use tempo_primitives::Block as TempoBlock;

use crate::consensus::{Block, Digest};

mod actor;
mod ingress;

#[cfg(test)]
mod test;

pub(crate) use actor::Resolver;
pub(crate) use ingress::Mailbox;

pub(crate) struct Config<
    P = BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
    U = super::upstream::Mailbox,
> {
    /// For reading blocks locally from the execution layer.
    pub(super) execution_provider: P,
    /// For reading blocks and certificates from the connected node.
    pub(super) upstream: U,
    pub(super) mailbox_size: usize,
    pub(super) upstream_request_timeout: Duration,
}

pub(crate) fn try_init<TContext, P, U>(
    context: TContext,
    config: Config<P, U>,
) -> (
    Resolver<TContext, P, U>,
    Mailbox,
    mpsc::Receiver<handler::Message<Digest>>,
)
where
    TContext: Clock + Metrics + Spawner,
    P: BlockProvider + Clone + 'static,
    U: Upstream + Clone + 'static,
{
    actor::try_init(context, config)
}

/// Local execution-layer block lookup needed by the resolver.
pub(crate) trait BlockProvider: Send + Sync {
    fn block_by_hash(&self, digest: Digest) -> eyre::Result<Option<Block>>;
}

/// Upstream reads needed by the resolver.
pub(crate) trait Upstream: Send + Sync {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send + 'static;
    fn get_finalization(
        &self,
        h: Height,
    ) -> impl Future<Output = Option<CertifiedBlock>> + Send + 'static;
}

impl<N> BlockProvider for BlockchainProvider<N>
where
    N: ProviderNodeTypes,
    N::Primitives: NodePrimitives<Block = TempoBlock>,
{
    fn block_by_hash(&self, digest: Digest) -> eyre::Result<Option<Block>> {
        self.find_sealed_or_recovered_block(digest.0, BlockSource::Any)
            .map_err(eyre::Report::new)
            .map(|block| block.map(|block| Block::from_execution_block_unchecked(block, None)))
    }
}

impl Upstream for super::upstream::Mailbox {
    fn get_block(&self, digest: Digest) -> impl Future<Output = Option<Block>> + Send + 'static {
        let upstream = self.clone();
        async move { upstream.get_block(digest).await }
    }

    fn get_finalization(
        &self,
        height: Height,
    ) -> impl Future<Output = Option<CertifiedBlock>> + Send + 'static {
        let upstream = self.clone();
        async move { upstream.get_finalization(height).await }
    }
}
