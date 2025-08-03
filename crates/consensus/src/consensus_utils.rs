use reth_chainspec::ChainSpec;
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_execution_types::BlockExecutionResult;
use reth_node_builder::{components::ConsensusBuilder, Block, BuilderContext, FullNodeTypes};
use reth_primitives::{SealedBlock, SealedHeader};
use std::sync::Arc;

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct MalachiteConsensus {
    chain_spec: Arc<ChainSpec>,
}

impl MalachiteConsensus {
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self { chain_spec }
    }
}

impl<H> HeaderValidator<H> for MalachiteConsensus {
    fn validate_header(&self, _header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        // For now, return Ok - implement validation logic here
        Ok(())
    }

    fn validate_header_against_parent(
        &self,
        _header: &SealedHeader<H>,
        _parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        // For now, return Ok - implement validation logic here
        Ok(())
    }
}

impl<B> Consensus<B> for MalachiteConsensus
where
    B: Block,
{
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        _body: &B::Body,
        _header: &SealedHeader<B::Header>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn validate_block_pre_execution(&self, _block: &SealedBlock<B>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<N> FullConsensus<N> for MalachiteConsensus
where
    N: reth_primitives_traits::NodePrimitives,
{
    fn validate_block_post_execution(
        &self,
        _block: &reth_primitives_traits::RecoveredBlock<N::Block>,
        _result: &BlockExecutionResult<N::Receipt>,
    ) -> Result<(), ConsensusError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct MalachiteConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for MalachiteConsensusBuilder
where
    Node: FullNodeTypes<Types: reth_node_builder::NodeTypes<ChainSpec = ChainSpec>>,
{
    type Consensus = Arc<MalachiteConsensus>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(Arc::new(MalachiteConsensus::new(ctx.chain_spec())))
    }
}

impl MalachiteConsensusBuilder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MalachiteConsensusBuilder {
    fn default() -> Self {
        Self::new()
    }
}
