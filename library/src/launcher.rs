use reth_node_builder::{
    FullNodeTypes, NodeBuilderWithComponents, NodeHandle, LaunchNode,
    NodeComponentsBuilder, NodeAddOns, NodeAdapter, LaunchContext,
    rpc::RethRpcAddOns, NodeTypesWithDB,
};
use reth_node_core::dirs::{ChainPath, DataDirPath};
use reth_provider::providers::BlockchainProvider;
use reth_tasks::TaskExecutor;

#[derive(Debug)]
pub struct MalachiteNodeLauncher {
    /// The task executor for the node.
    pub ctx: LaunchContext,
}

impl MalachiteNodeLauncher {
    /// Create a new instance of the default node launcher.
    pub const fn new(task_executor: TaskExecutor, data_dir: ChainPath<DataDirPath>) -> Self {
        Self {
            ctx: LaunchContext::new(task_executor, data_dir),
        }
    }
}

impl<T, CB, AO> LaunchNode<NodeBuilderWithComponents<T, CB, AO>> for MalachiteNodeLauncher
where
    T: FullNodeTypes<Provider = BlockchainProvider<<T as FullNodeTypes>::DB>>,
    T::DB: NodeTypesWithDB,
    CB: NodeComponentsBuilder<T>,
    AO: NodeAddOns<NodeAdapter<T, CB::Components>> + RethRpcAddOns<NodeAdapter<T, CB::Components>>,
{
    type Node = NodeHandle<NodeAdapter<T, CB::Components>, AO>;

    async fn launch_node(
        self,
        target: NodeBuilderWithComponents<T, CB, AO>,
    ) -> eyre::Result<Self::Node> {
        // Use the standard launch implementation
        todo!()
    }
}
