//! The environment to launch tempo execution nodes in.
use std::{path::Path, sync::Arc};

use eyre::WrapErr as _;
use reth_db::mdbx::DatabaseArguments;
use reth_ethereum::tasks::{TaskExecutor, TaskManager};
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_node_core::{
    args::{DatadirArgs, RpcServerArgs},
    exit::NodeExitFuture,
};
use reth_rpc_builder::RpcModuleSelection;
use tempfile::TempDir;
use tempo_chainspec::TempoChainSpec;
use tempo_node::{TempoFullNode, node::TempoNode};

/// An execution runtime wrapping a thread running a [`tokio::runtime::Runtime`].
///
/// This is needed to spawn tempo execution nodes, which require a tokio runtime.
///
/// The commonware itself is launched in their
/// [`commonware_runtime::deterministic`] and so this extra effort is necessary.
pub struct ExecutionRuntime {
    // The tokio runtime launched on a different thread.
    rt: std::thread::JoinHandle<()>,

    // Base directory where all reth databases will be initialized.
    _tempdir: TempDir,

    // Channel to request the runtime to launch new execution nodes.
    to_runtime: tokio::sync::mpsc::UnboundedSender<Message>,
}

impl ExecutionRuntime {
    /// Constructs a new execution runtime to launch execution nodes.
    pub fn new() -> Self {
        let tempdir = tempfile::Builder::new()
            // TODO(janis): cargo manifest prefix?
            .prefix("tempo_e2e_test")
            .tempdir()
            .expect("must be able to create a temp directory run tun tests");

        let (to_runtime, mut from_handle) = tokio::sync::mpsc::unbounded_channel();

        let datadir = tempdir.path().to_path_buf();
        let rt = std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new()
                .expect("must be able to initialize a runtime to run execution/reth nodes");
            rt.block_on(async move {
                let task_manager = TaskManager::current();
                while let Some(msg) = from_handle.recv().await {
                    match msg {
                        Message::SpawnNode { name, response } => {
                            let node =
                                launch_execution_node(task_manager.executor(), datadir.join(name))
                                    .await
                                    .expect("must be able to launch execution nodes");
                            response.send(node).expect(
                                "receiver must hold the return channel until the node is returned",
                            );
                        }
                        Message::Stop => {
                            break;
                        }
                    }
                }
            })
        });

        Self {
            rt,
            _tempdir: tempdir,
            to_runtime,
        }
    }

    /// Returns a handle to this runtime.
    ///
    /// Can be used to spawn nodes.
    pub fn handle(&self) -> ExecutionRuntimeHandle {
        ExecutionRuntimeHandle {
            to_runtime: self.to_runtime.clone(),
        }
    }

    /// Requests a new execution node and blocks until its returned.
    pub async fn spawn_node(&self, name: &str) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.await.wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }

    /// Requests a new execution node and blocks until its returned.
    pub fn spawn_node_blocking(&self, name: &str) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.blocking_recv().wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }

    /// Instructs the runtime to stop and exit.
    pub fn stop(self) -> eyre::Result<()> {
        self.to_runtime
            .send(Message::Stop)
            .wrap_err("the execution runtime went away")?;
        match self.rt.join() {
            Ok(()) => Ok(()),
            Err(e) => std::panic::resume_unwind(e),
        }
    }
}

impl Default for ExecutionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// A handle to the execution runtime.
///
/// Can be used to spawn nodes.
pub struct ExecutionRuntimeHandle {
    to_runtime: tokio::sync::mpsc::UnboundedSender<Message>,
}

impl ExecutionRuntimeHandle {
    /// Requests a new execution node and blocks until its returned.
    pub async fn spawn_node(&self, name: &str) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.await.wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }

    /// Requests a new execution node and blocks until its returned.
    pub fn spawn_node_blocking(&self, name: &str) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.blocking_recv().wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }
}

/// An execution node spawned by the execution runtime.
///
/// This is essentially the same as [`reth_node_builder::NodeHandle`], but
/// avoids the type parameters.
pub struct ExecutionNode {
    pub node: TempoFullNode,
    pub _exit_fut: NodeExitFuture,
}

// TODO(janis): allow configuring this.
fn chainspec() -> Arc<TempoChainSpec> {
    tempo_chainspec::spec::ADAGIO.clone()
}

// TODO(janis): would be nicer if we could identify the node somehow?
impl std::fmt::Debug for ExecutionNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionNode")
            .field("node", &"<TempoFullNode>")
            .field("exit_fut", &"<NodeExitFuture>")
            .finish()
    }
}

/// Launches a tempo execution node.
///
/// Difference compared to starting the node through the binary:
///
/// 1. faucet is always disabled
/// 2. components are not provided (looking at the node command, the components
///    are not passed to it).
/// 3. consensus config is not necessary
pub async fn launch_execution_node<P: AsRef<Path>>(
    executor: TaskExecutor,
    datadir: P,
) -> eyre::Result<ExecutionNode> {
    let node_config = NodeConfig::new(chainspec())
        .with_unused_ports()
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        )
        .with_datadir_args(DatadirArgs {
            datadir: datadir.as_ref().to_path_buf().into(),
            ..DatadirArgs::default()
        });

    let database = Arc::new(
        reth_db::init_db(node_config.datadir().db(), DatabaseArguments::default())
            .wrap_err("failed initializing database")?
            .with_metrics(),
    );

    let node_handle = NodeBuilder::new(node_config)
        .with_database(database)
        .with_launch_context(executor)
        .node(TempoNode::default())
        .launch()
        .await
        .wrap_err("failed launching node")?;
    Ok(ExecutionNode {
        node: node_handle.node,
        _exit_fut: node_handle.node_exit_future,
    })
}

#[derive(Debug)]
enum Message {
    SpawnNode {
        name: String,
        response: tokio::sync::oneshot::Sender<ExecutionNode>,
    },
    Stop,
}
