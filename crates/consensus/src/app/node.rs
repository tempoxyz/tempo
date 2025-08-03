//! Reth node configuration for Malachite consensus.
//!
//! This module defines the node types and builders needed to configure a Reth node
//! that uses Malachite consensus instead of the default consensus mechanisms. It
//! integrates Malachite consensus into Reth's component architecture.
//!
//! # Components
//!
//! - [`RethNode`]: Node type configuration with Malachite consensus
//! - [`MalachitePayloadServiceBuilder`]: Custom payload builder for Malachite
//!
//! The configuration uses standard Ethereum components for most functionality
//! (transaction pool, networking, execution) but replaces the consensus layer
//! with Malachite.

use crate::consensus_utils::MalachiteConsensusBuilder;
use reth::{
    payload::{PayloadBuilderHandle, PayloadServiceCommand},
    transaction_pool::TransactionPool,
};
use reth_chainspec::ChainSpec;
use reth_node_builder::{
    BuilderContext, ConfigureEvm, FullNodeTypes, Node, NodeComponentsBuilder, NodeTypes,
    components::{BasicPayloadServiceBuilder, ComponentsBuilder, PayloadServiceBuilder},
};
use reth_node_ethereum::node::{
    EthereumAddOns, EthereumEngineValidatorBuilder, EthereumEthApiBuilder, EthereumNetworkBuilder,
    EthereumPoolBuilder,
};
use reth_trie_db::MerklePatriciaTrie;
use tokio::sync::{broadcast, mpsc};
use tracing::warn;

/// Type configuration for a regular Reth node.
#[derive(Debug, Clone, Default)]
pub struct RethNode {}

impl RethNode {
    /// Create a new RethNode
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MalachitePayloadServiceBuilder;

impl<Node, Pool, Evm> PayloadServiceBuilder<Node, Pool, Evm> for MalachitePayloadServiceBuilder
where
    Node: FullNodeTypes<Types = RethNode>,
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

impl NodeTypes for RethNode {
    type Primitives = reth_ethereum_primitives::EthPrimitives;
    type ChainSpec = ChainSpec;
    type StateCommitment = MerklePatriciaTrie;
    type Storage = reth_provider::EthStorage;
    type Payload = reth_node_ethereum::EthEngineTypes;
}

impl<N> Node<N> for RethNode
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
        EthereumEthApiBuilder,
        EthereumEngineValidatorBuilder,
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
