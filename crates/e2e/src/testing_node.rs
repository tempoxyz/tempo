//! A testing node that can start and stop both consensus and execution layers.

use crate::execution_runtime::{self, ExecutionNode, ExecutionNodeConfig, ExecutionRuntimeHandle};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::simulated::{Control, Oracle, SocketManager};
use commonware_runtime::{Handle, deterministic::Context};
use reth_db::{
    init_db,
    mdbx::{DatabaseArguments, DatabaseEnv},
};
use reth_ethereum::provider::{
    ProviderFactory,
    providers::{BlockchainProvider, StaticFileProvider},
};
use reth_node_builder::NodeTypesWithDBAdapter;
use std::{path::PathBuf, sync::Arc};
use tempo_commonware_node::consensus;
use tempo_node::node::TempoNode;
use tracing::debug;

/// A testing node that can start and stop both consensus and execution layers.
pub struct TestingNode {
    /// Unique identifier for this node
    uid: String,
    /// Public key of the validator
    public_key: PublicKey,
    /// Simulated network oracle for test environments
    oracle: Oracle<PublicKey>,
    /// Consensus configuration used to start the consensus engine
    consensus_config: consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>>,
    /// Running consensus handle (None if consensus is stopped)
    consensus_handle: Option<Handle<eyre::Result<()>>>,
    /// Path to the execution node's data directory
    execution_node_datadir: PathBuf,
    /// Running execution node (None if execution is stopped)
    execution_node: Option<ExecutionNode>,
    /// Handle to the execution runtime for spawning new execution nodes
    execution_runtime: ExecutionRuntimeHandle,
    /// Configuration for the execution node
    execution_config: ExecutionNodeConfig,
}

impl TestingNode {
    /// Create a new TestingNode without spawning execution or starting consensus.
    ///
    /// Call `start()` to start both consensus and execution.
    pub fn new(
        uid: String,
        public_key: PublicKey,
        oracle: Oracle<PublicKey>,
        consensus_config: consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>>,
        execution_runtime: ExecutionRuntimeHandle,
        execution_config: ExecutionNodeConfig,
    ) -> Self {
        let execution_node_datadir = execution_runtime
            .nodes_dir()
            .join(execution_runtime::execution_node_name(&public_key));

        Self {
            uid,
            public_key,
            oracle,
            consensus_config,
            consensus_handle: None,
            execution_node: None,
            execution_node_datadir,
            execution_runtime,
            execution_config,
        }
    }

    /// Get the validator public key of this node.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Start both consensus and execution layers.
    ///
    ///
    /// # Panics
    /// Panics if either consensus or execution is already running.
    pub async fn start(&mut self) {
        self.start_execution().await;
        self.start_consensus().await;
    }

    /// Start the execution node and update consensus config to reference it.
    ///
    /// # Panics
    /// Panics if execution node is already running.
    async fn start_execution(&mut self) {
        assert!(
            self.execution_node.is_none(),
            "execution node is already running for {}",
            self.uid
        );

        let execution_node = self
            .execution_runtime
            .spawn_node(
                &execution_runtime::execution_node_name(&self.public_key),
                self.execution_config.clone(),
            )
            .await
            .expect("must be able to spawn execution node");

        // Update consensus config to point to the new execution node
        self.consensus_config.execution_node = execution_node.node.clone();
        self.execution_node = Some(execution_node);
        debug!(%self.uid, "started execution node for testing node");
    }

    /// Start the consensus engine with oracle registration.
    ///
    /// # Panics
    /// Panics if consensus is already running.
    async fn start_consensus(&mut self) {
        assert!(
            self.consensus_handle.is_none(),
            "consensus is already running for {}",
            self.uid
        );
        let engine = self
            .consensus_config
            .clone()
            .try_init()
            .await
            .expect("must be able to start the engine");

        let pending = self
            .oracle
            .control(self.public_key.clone())
            .register(0)
            .await
            .unwrap();
        let recovered = self
            .oracle
            .control(self.public_key.clone())
            .register(1)
            .await
            .unwrap();
        let resolver = self
            .oracle
            .control(self.public_key.clone())
            .register(2)
            .await
            .unwrap();
        let broadcast = self
            .oracle
            .control(self.public_key.clone())
            .register(3)
            .await
            .unwrap();
        let marshal = self
            .oracle
            .control(self.public_key.clone())
            .register(4)
            .await
            .unwrap();
        let dkg = self
            .oracle
            .control(self.public_key.clone())
            .register(5)
            .await
            .unwrap();
        let boundary_certs = self
            .oracle
            .control(self.public_key.clone())
            .register(6)
            .await
            .unwrap();
        let subblocks = self
            .oracle
            .control(self.public_key.clone())
            .register(7)
            .await
            .unwrap();

        let consensus_handle = engine.start(
            pending,
            recovered,
            resolver,
            broadcast,
            marshal,
            dkg,
            boundary_certs,
            subblocks,
        );

        self.consensus_handle = Some(consensus_handle);
        debug!(%self.uid, "started consensus for testing node");
    }

    /// Stop both consensus and execution layers.
    ///
    /// # Panics
    /// Panics if either consensus or execution is not running.
    pub async fn stop(&mut self) {
        self.stop_consensus();
        self.stop_execution().await
    }

    /// Stop only the consensus engine.
    ///
    /// # Panics
    /// Panics if consensus is not running.
    fn stop_consensus(&mut self) {
        let handle = self
            .consensus_handle
            .take()
            .unwrap_or_else(|| panic!("consensus is not running for {}, cannot stop", self.uid));
        handle.abort();
        debug!(%self.uid, "stopped consensus for testing node");
    }

    /// Stop only the execution node.
    ///
    /// This triggers a critical task failure which will cause the execution node's
    /// executor to shutdown.
    ///
    /// # Panics
    /// Panics if execution node is not running.
    async fn stop_execution(&mut self) {
        let execution_node = self.execution_node.take().unwrap_or_else(|| {
            panic!(
                "execution node is not running for {}, cannot stop",
                self.uid
            )
        });
        execution_node.shutdown().await
    }

    /// Check if both consensus and execution are running
    pub fn is_running(&self) -> bool {
        self.consensus_handle.is_some() && self.execution_node.is_some()
    }

    /// Check if consensus is running
    pub fn is_consensus_running(&self) -> bool {
        self.consensus_handle.is_some()
    }

    /// Check if execution is running
    pub fn is_execution_running(&self) -> bool {
        self.execution_node.is_some()
    }

    /// Get a reference to the running execution node.
    ///
    /// # Panics
    /// Panics if the execution node is not running.
    pub fn execution(&self) -> &tempo_node::TempoFullNode {
        &self
            .execution_node
            .as_ref()
            .expect("execution node is not running")
            .node
    }

    /// Get a reference to the running consensus handle.
    ///
    /// # Panics
    /// Panics if the consensus engine is not running.
    pub fn consensus(&self) -> &Handle<eyre::Result<()>> {
        self.consensus_handle
            .as_ref()
            .expect("consensus is not running")
    }

    /// Get a blockchain provider for the execution node.
    ///
    /// If the execution node is running, returns the provider from the running node.
    /// If the execution node is stopped, opens a new provider to its storage.
    ///
    /// # Panics
    /// Panics if unable to open the database or static files.
    pub fn execution_provider(
        &self,
    ) -> BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, Arc<DatabaseEnv>>> {
        // If execution node is running, return its provider
        if let Some(execution_node) = &self.execution_node {
            return execution_node.node.provider.clone();
        }

        // Otherwise, open a read-only provider to the database
        let db_path = self.execution_node_datadir.join("db");
        let database = Arc::new(
            init_db(&db_path, DatabaseArguments::default())
                .expect("failed to open execution node database")
                .with_metrics(),
        );

        let static_file_provider =
            StaticFileProvider::read_only(self.execution_node_datadir.join("static_files"), true)
                .expect("failed to open static files");

        let provider_factory = ProviderFactory::<NodeTypesWithDBAdapter<TempoNode, _>>::new(
            database,
            execution_runtime::chainspec(),
            static_file_provider,
        )
        .expect("failed to create provider factory");

        BlockchainProvider::new(provider_factory).expect("failed to create blockchain provider")
    }
}

#[cfg(test)]
mod tests {
    use crate::{ExecutionRuntime, Setup, setup_validators};
    use alloy::providers::{Provider, ProviderBuilder};
    use commonware_p2p::simulated::Link;
    use commonware_runtime::{
        Clock, Runner as _,
        deterministic::{Config, Runner},
    };
    use std::time::Duration;

    #[tokio::test]
    async fn test_stop_shuts_down_everything() {
        let _ = tempo_eyre::install();

        let runner = Runner::from(Config::default().with_seed(0));
        let (tx_started, rx_started) = tokio::sync::oneshot::channel();
        let (tx_stopped, rx_stopped) = tokio::sync::oneshot::channel();

        std::thread::spawn(move || {
            runner.start(|context| async move {
                let execution_runtime = ExecutionRuntime::new();

                let setup = Setup {
                    how_many_signers: 1,
                    seed: 0,
                    linkage: Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::from_millis(1),
                        success_rate: 1.0,
                    },
                    epoch_length: 100,
                    connect_execution_layer_nodes: false,
                };

                let (mut nodes, _oracle) =
                    setup_validators(context.clone(), &execution_runtime, setup).await;

                let mut node = nodes.pop().unwrap();
                node.start().await;

                // Get the RPC HTTP address while running
                let rpc_addr = node
                    .execution()
                    .rpc_server_handles
                    .rpc
                    .http_local_addr()
                    .expect("http rpc server should be running");

                // Signal that node is started
                let _ = tx_started.send(rpc_addr);

                // Wait for signal to stop
                let _ = rx_stopped.blocking_recv();

                // Stop the node
                node.stop().await;
                assert!(!node.is_running(), "node should not be running after stop");
                assert!(
                    !node.is_consensus_running(),
                    "consensus should not be running after stop"
                );
                assert!(
                    !node.is_execution_running(),
                    "execution should not be running after stop"
                );

                // Keep execution runtime alive so we can verify RPC is actually stopped
                loop {
                    context.sleep(Duration::from_secs(1)).await;
                }
            });
        });

        let rpc_addr = rx_started.await.unwrap();
        let rpc_url = format!("http://{rpc_addr}");

        // Verify RPC is accessible while running
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());

        let block_number = provider.get_block_number().await;
        assert!(
            block_number.is_ok(),
            "RPC should be accessible while running"
        );

        // Signal to stop the node
        let _ = tx_stopped.send(());

        // Wait for shutdown to complete
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify RPC is no longer accessible after stopping
        let result =
            tokio::time::timeout(Duration::from_millis(500), provider.get_block_number()).await;

        assert!(
            result.is_err() || result.unwrap().is_err(),
            "RPC should not be accessible after stopping"
        );
    }
}
