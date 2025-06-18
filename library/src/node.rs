use tokio::sync::{broadcast, mpsc};
use tracing::warn;

use crate::consensus::MalachiteConsensusBuilder;
use crate::state::State;

use reth::payload::{PayloadBuilderHandle, PayloadServiceCommand};
use reth::transaction_pool::TransactionPool;
use reth_chainspec::ChainSpec;
use reth_node_builder::components::{BasicPayloadServiceBuilder, PayloadServiceBuilder};
use reth_node_builder::{BuilderContext, BuiltPayload, ConfigureEvm};
use reth_node_builder::{
    FullNodeTypes, Node, NodeComponentsBuilder, NodeTypes, components::ComponentsBuilder,
};
use reth_node_ethereum::node::{EthereumAddOns, EthereumNetworkBuilder, EthereumPoolBuilder};
use reth_primitives::{Block as RethBlock, SealedBlock};
use reth_trie_db::MerklePatriciaTrie;

/// Type configuration for a regular Malachite node.
#[derive(Debug, Clone)]
pub struct MalachiteNode {}

impl MalachiteNode {
    /// Create a new MalachiteNode
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MalachitePayloadServiceBuilder;

impl<Node, Pool, Evm> PayloadServiceBuilder<Node, Pool, Evm> for MalachitePayloadServiceBuilder
where
    Node: FullNodeTypes<Types = MalachiteNode>,
    Pool: TransactionPool,
    Evm: ConfigureEvm,
{
    async fn spawn_payload_builder_service(
        self,
        ctx: &BuilderContext<Node>,
        _pool: Pool,
        _evm_config: Evm,
    ) -> eyre::Result<PayloadBuilderHandle<<Node::Types as NodeTypes>::Payload>> {
        let (tx, mut rx) = mpsc::unbounded_channel();

        ctx.task_executor()
            .spawn_critical("payload builder", async move {
                let mut subscriptions = Vec::new();

                while let Some(message) = rx.recv().await {
                    match message {
                        PayloadServiceCommand::Subscribe(tx) => {
                            let (events_tx, events_rx) = broadcast::channel(100);
                            // Retain senders to make sure that channels are not getting closed
                            subscriptions.push(events_tx);
                            let _ = tx.send(events_rx);
                        }
                        message => warn!(?message, "Malachite payload service received a message"),
                    }
                }
            });

        Ok(PayloadBuilderHandle::new(tx))
    }
}

impl NodeTypes for MalachiteNode {
    type Primitives = reth_ethereum_primitives::EthPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = reth_provider::EthStorage;
    type Payload = reth_node_ethereum::EthEngineTypes;
}

impl<N> Node<N> for MalachiteNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        BasicPayloadServiceBuilder<reth_node_ethereum::EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        reth_node_ethereum::EthereumExecutorBuilder,
        MalachiteConsensusBuilder,
    >;

    type AddOns = EthereumAddOns<
        reth_node_builder::NodeAdapter<
            N,
            <Self::ComponentsBuilder as NodeComponentsBuilder<N>>::Components,
        >,
    >;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(EthereumPoolBuilder::default())
            .executor(reth_node_ethereum::EthereumExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(MalachiteConsensusBuilder::new())
    }

    fn add_ons(&self) -> Self::AddOns {
        EthereumAddOns::default()
    }
}
