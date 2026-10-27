//! Non-generic launch entrypoint for [`TempoNode`].
//!
//! Launching a reth node monomorphizes the entire node stack for the concrete node types.
//! Routing every launch through the non-generic [`launch`] makes that happen once, in this
//! crate, instead of once per crate that launches a node (the binary and each test harness).

use std::future::IntoFuture;

use futures::future::BoxFuture;
use reth_db::DatabaseEnv;
use reth_node_builder::{
    Node, NodeBuilderWithComponents, NodeHandleFor, RethFullAdapter, WithLaunchContext,
};
use tempo_node::node::TempoNode;

type TempoAdapter = RethFullAdapter<DatabaseEnv, TempoNode>;

/// A node builder configured with [`TempoNode`] components and add-ons, ready to launch.
pub type TempoLaunchBuilder = WithLaunchContext<
    NodeBuilderWithComponents<
        TempoAdapter,
        <TempoNode as Node<TempoAdapter>>::ComponentsBuilder,
        <TempoNode as Node<TempoAdapter>>::AddOns,
    >,
>;

/// Handle to a launched [`TempoNode`].
pub type TempoNodeHandle = NodeHandleFor<TempoNode>;

/// Launches the node with reth's debug capabilities, which are inert unless configured.
pub fn launch(builder: TempoLaunchBuilder) -> BoxFuture<'static, eyre::Result<TempoNodeHandle>> {
    builder.launch_with_debug_capabilities().into_future()
}
