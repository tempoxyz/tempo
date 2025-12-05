//! A testing node that can start and stop both consensus and execution layers.

use crate::execution_runtime::{self, ExecutionNode, ExecutionNodeConfig, ExecutionRuntimeHandle};
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::simulated::{Control, Oracle, SocketManager};
use commonware_runtime::{Handle, deterministic::Context};
use reth_db::{DatabaseEnv, mdbx::DatabaseArguments, open_db_read_only};
use reth_ethereum::{
    provider::{
        DatabaseProviderFactory, ProviderFactory,
        providers::{BlockchainProvider, StaticFileProvider},
    },
    storage::BlockNumReader,
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
    /// Database instance for the execution node
    execution_database: Option<Arc<DatabaseEnv>>,
    /// Last block number in database when stopped (used for restart verification)
    last_db_block_on_stop: Option<u64>,
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
            execution_database: None,
            last_db_block_on_stop: None,
        }
    }

    /// Get the validator public key of this node.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the unique identifier of this node.
    pub fn uid(&self) -> &str {
        &self.uid
    }

    /// Get a reference to the consensus config.
    pub fn consensus_config(
        &self,
    ) -> &consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>> {
        &self.consensus_config
    }

    /// Get a mutable reference to the consensus config.
    pub fn consensus_config_mut(
        &mut self,
    ) -> &mut consensus::Builder<Control<PublicKey>, Context, SocketManager<PublicKey>> {
        &mut self.consensus_config
    }

    /// Get a reference to the oracle.
    pub fn oracle(&self) -> &Oracle<PublicKey> {
        &self.oracle
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

        // Create database if not exists
        if self.execution_database.is_none() {
            let db_path = self.execution_node_datadir.join("db");
            self.execution_database = Some(Arc::new(
                reth_db::init_db(db_path, DatabaseArguments::default())
                    .expect("failed to init database")
                    .with_metrics(),
            ));
        }

        let execution_node = self
            .execution_runtime
            .spawn_node(
                &execution_runtime::execution_node_name(&self.public_key),
                self.execution_config.clone(),
                self.execution_database.as_ref().unwrap().clone(),
            )
            .await
            .expect("must be able to spawn execution node");

        // verify database persistence on restart
        if let Some(expected_block) = self.last_db_block_on_stop {
            let current_db_block = execution_node
                .node
                .provider
                .database_provider_ro()
                .expect("failed to get database provider")
                .last_block_number()
                .expect("failed to get last block number from database");

            assert!(current_db_block >= expected_block,);
        }

        // Update consensus config to point to the new execution node
        self.consensus_config = self
            .consensus_config
            .clone()
            .with_execution_node(execution_node.node.clone());
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
        self.stop_consensus().await;
        self.stop_execution().await
    }

    /// Stop only the consensus engine.
    ///
    /// # Panics
    /// Panics if consensus is not running.
    async fn stop_consensus(&mut self) {
        let handle = self.consensus_handle.take().expect(format!(
            "consensus is not running for {}, cannot stop",
            self.uid
        ));
        handle.abort();

        // Wait for the consensus handle to actually finish
        let _ = handle.await;

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

        let last_db_block = execution_node
            .node
            .provider
            .database_provider_ro()
            .expect("failed to get database provider")
            .last_block_number()
            .expect("failed to get last block number from database");
        self.last_db_block_on_stop = Some(last_db_block);

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
    /// # Panics
    /// Panics if the execution node is not running.
    pub fn execution_provider(
        &self,
    ) -> BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, Arc<DatabaseEnv>>> {
        self.execution().provider.clone()
    }

    /// Get a blockchain provider for when the execution node is down.
    ///
    /// This provider MUST BE DROPPED before starting the node again.
    pub fn execution_provider_offline(
        &self,
    ) -> BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, Arc<DatabaseEnv>>> {
        // Open a read-only provider to the database
        // Note: MDBX allows multiple readers, so this is safe even if another process
        // has the database open for reading
        let database = Arc::new(
            open_db_read_only(
                self.execution_node_datadir.join("db"),
                DatabaseArguments::default(),
            )
            .expect("failed to open execution node database")
            .with_metrics(),
        );

        let static_file_provider =
            StaticFileProvider::read_only(self.execution_node_datadir.join("static_files"), true)
                .expect("failed to open static files");

        let provider_factory = ProviderFactory::<NodeTypesWithDBAdapter<TempoNode, _>>::new(
            database,
            execution_runtime::chainspec_arc(),
            static_file_provider,
        )
        .expect("failed to create provider factory");

        BlockchainProvider::new(provider_factory).expect("failed to create blockchain provider")
    }
}

#[cfg(test)]
mod tests {
    use crate::{Setup, setup_validators};
    use alloy::providers::{Provider, ProviderBuilder};
    use commonware_p2p::simulated::Link;
    use commonware_runtime::{
        Runner as _,
        deterministic::{Config, Runner},
    };
    use std::time::Duration;
    use tokio::sync::{oneshot, oneshot::Sender};

    enum Message {
        Stop(Sender<()>),
        Start(Sender<std::net::SocketAddr>),
    }

    /// Start node and verify RPC is accessible
    async fn start_and_verify(tx_msg: &tokio::sync::mpsc::UnboundedSender<Message>) -> String {
        let (tx_rpc_addr, rx_rpc_addr) = oneshot::channel();
        let _ = tx_msg.send(Message::Start(tx_rpc_addr));
        let rpc_addr = rx_rpc_addr.await.unwrap();
        let rpc_url = format!("http://{rpc_addr}");

        // Verify RPC is accessible
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
        let block_number = provider.get_block_number().await;
        assert!(block_number.is_ok(), "RPC should be accessible after start");

        rpc_url
    }

    #[tokio::test]
    async fn test_restart() {
        // Ensures that the node can be stopped completely and brought up inside a test.
        let _ = tempo_eyre::install();

        let runner = Runner::from(Config::default().with_seed(0));
        let (tx_msg, mut rx_msg) = tokio::sync::mpsc::unbounded_channel::<Message>();

        std::thread::spawn(move || {
            runner.start(|context| async move {
                let setup = Setup {
                    how_many_signers: 1,
                    how_many_verifiers: 0,
                    seed: 0,
                    linkage: Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::from_millis(1),
                        success_rate: 1.0,
                    },
                    epoch_length: 100,
                    connect_execution_layer_nodes: false,
                    allegretto_in_seconds: None,
                };

                let (mut nodes, _execution_runtime) =
                    setup_validators(context.clone(), setup).await;

                let mut node = nodes.pop().unwrap();

                loop {
                    match rx_msg.blocking_recv() {
                        Some(Message::Stop(tx_stopped)) => {
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

                            let _ = tx_stopped.send(());
                        }
                        Some(Message::Start(tx_rpc_addr)) => {
                            node.start().await;
                            assert!(node.is_running(), "node should be running after start");

                            // Get the RPC HTTP address while running
                            let rpc_addr = node
                                .execution()
                                .rpc_server_handles
                                .rpc
                                .http_local_addr()
                                .expect("http rpc server should be running");

                            let _ = tx_rpc_addr.send(rpc_addr);
                        }
                        None => {
                            break;
                        }
                    }
                }
            });
        });

        // Start the node initially
        let rpc_url = start_and_verify(&tx_msg).await;

        // Signal to stop the node
        let (tx_stopped, rx_stopped) = oneshot::channel();
        let _ = tx_msg.send(Message::Stop(tx_stopped));
        rx_stopped.await.unwrap();

        // Verify RPC is no longer accessible after stopping
        let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
        let result =
            tokio::time::timeout(Duration::from_millis(500), provider.get_block_number()).await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "RPC should not be accessible after stopping"
        );

        // Start the node again
        start_and_verify(&tx_msg).await;
    }
}
