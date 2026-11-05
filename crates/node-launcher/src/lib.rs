//! Non-generic launch entrypoint for [`TempoNode`].
//!
//! Launching a reth node monomorphizes the entire node stack for the concrete node types.
//! Routing every launch through the non-generic [`launch`] makes that happen once, in this
//! crate, instead of once per crate that launches a node (the binary and each test harness).

use std::sync::Arc;

use futures::future::BoxFuture;
use reth_db::DatabaseEnv;
use reth_node_builder::{
    DebugNodeLauncher, Node, NodeBuilderWithComponents, NodeHandleFor, RethFullAdapter,
    WithLaunchContext,
};
use reth_provider::StateBackend;
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
///
/// With `state_backend`, reth reads current state from it instead of the hashed state tables and
/// stops writing those tables and the state tries; the node's state-root strategy must keep the
/// backend in step through its persistence hook.
pub fn launch(
    builder: TempoLaunchBuilder,
    state_backend: Option<Arc<dyn StateBackend>>,
) -> BoxFuture<'static, eyre::Result<TempoNodeHandle>> {
    let mut engine = builder.engine_api_launcher();
    if let Some(backend) = state_backend {
        engine = engine.with_state_backend(backend);
    }
    Box::pin(builder.launch_with(DebugNodeLauncher::new(engine)))
}
