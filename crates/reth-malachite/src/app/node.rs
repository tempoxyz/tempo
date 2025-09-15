//! Reth node configuration for Malachite consensus.
//!
//! This module defines the node types and builders needed to configure a Reth node
//! that uses Malachite consensus instead of the default consensus mechanisms. It
//! integrates Malachite consensus into Reth's component architecture.
//!
//! # Components
//!
//! - [`TempoNode`]: Node type configuration with Malachite consensus & Tempo EVM
//! - [`MalachitePayloadServiceBuilder`]: Custom payload builder for Malachite
//!
//! The configuration uses standard Ethereum components for most functionality
//! (transaction pool, networking, execution) but replaces the consensus layer
//! with Malachite.
use reth::{
    payload::{PayloadBuilderHandle, PayloadServiceCommand},
    transaction_pool::TransactionPool,
};
use reth_chainspec::ChainSpec;
use reth_node_builder::{
    BuilderContext, ConfigureEvm, FullNodeTypes, NodeTypes, PayloadBuilderConfig,
    components::{ExecutorBuilder, PayloadServiceBuilder},
};
use reth_node_ethereum::EthEvmConfig;

use tempo_evm::evm::TempoEvmFactory;
use tokio::sync::{broadcast, mpsc};
use tracing::warn;

/// Type configuration for a Tempo reth node.
#[derive(Debug, Clone, Default)]
pub struct TempoNode {}

impl TempoNode {
    /// Create a new TempNode
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MalachitePayloadServiceBuilder;

impl<Node, Pool, Evm> PayloadServiceBuilder<Node, Pool, Evm> for MalachitePayloadServiceBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
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

impl NodeTypes for TempoNode {
    type Primitives = reth_ethereum_primitives::EthPrimitives;
    type ChainSpec = ChainSpec;
    type Storage = reth_provider::EthStorage;
    type Payload = reth_node_ethereum::EthEngineTypes;
}

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoExecutorBuilder;

impl<N: FullNodeTypes<Types = TempoNode>> ExecutorBuilder<N> for TempoExecutorBuilder {
    type EVM = EthEvmConfig<ChainSpec, TempoEvmFactory>;

    async fn build_evm(self, ctx: &BuilderContext<N>) -> eyre::Result<Self::EVM> {
        Ok(
            EthEvmConfig::new_with_evm_factory(
                ctx.chain_spec().clone(),
                TempoEvmFactory::default(),
            )
            .with_extra_data(ctx.payload_builder_config().extra_data_bytes()),
        )
    }
}
