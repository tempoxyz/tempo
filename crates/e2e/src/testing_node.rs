//! A testing node that can start and stop both consensus and execution layers.

use crate::execution_runtime::{self, ExecutionNode, ExecutionNodeConfig, ExecutionRuntimeHandle};
use alloy_primitives::Address;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::simulated::{Control, Oracle, SocketManager};
use commonware_runtime::{Handle, Metrics as _, deterministic::Context};
use reth_db::{Database, DatabaseEnv, mdbx::DatabaseArguments, open_db_read_only};
use reth_ethereum::{
    provider::{
        DatabaseProviderFactory, ProviderFactory,
        providers::{BlockchainProvider, RocksDBProvider, StaticFileProvider},
    },
    storage::BlockNumReader,
};
use reth_node_builder::NodeTypesWithDBAdapter;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tempo_commonware_node::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, RESOLVER_CHANNEL_IDENT,
    RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
    consensus,
};
use tempo_node::node::TempoNode;
use tracing::{debug, instrument};

/// A testing node that can start and stop both consensus and execution layers.
pub struct TestingNode<TClock>
where
    TClock: commonware_runtime::Clock,
{
    /// Unique identifier for this node
    pub uid: String,
    /// Public key of the validator
    pub public_key: PublicKey,
    /// Simulated network oracle for test environments
    pub oracle: Oracle<PublicKey, TClock>,
    /// Consensus configuration used to start the consensus engine
    pub consensus_config:
        consensus::Builder<Control<PublicKey, TClock>, SocketManager<PublicKey, TClock>>,
    /// Running consensus handle (None if consensus is stopped)
    pub consensus_handle: Option<Handle<eyre::Result<()>>>,
    /// Path to the execution node's data directory
    pub execution_node_datadir: PathBuf,
    /// Running execution node (None if execution is stopped)
    pub execution_node: Option<ExecutionNode>,
    /// Handle to the execution runtime for spawning new execution nodes
    pub execution_runtime: ExecutionRuntimeHandle,
    /// Configuration for the execution node
    pub execution_config: ExecutionNodeConfig,
    /// Database instance for the execution node
    pub execution_database: Option<DatabaseEnv>,
    /// The execution node name assigned at initialization. Important when
    /// constructing the datadir at which to find the node.
    pub execution_node_name: String,
    /// Last block number in database when stopped (used for restart verification)
    pub last_db_block_on_stop: Option<u64>,
    /// Network address of the node. Used for execution the validator-config
    /// addValidator contract call.
    pub network_address: SocketAddr,
    /// The chain address of the node. Used for executing validator-config smart
    /// contract calls.
    pub chain_address: Address,

    n_starts: u32,
}

impl<TClock> TestingNode<TClock>
where
    TClock: commonware_runtime::Clock,
{
    /// Create a new TestingNode without spawning execution or starting consensus.
    ///
    /// Call `start()` to start both consensus and execution.
    // FIXME: replace this by a `Config` to make this more digestible.
    #[expect(clippy::too_many_arguments, reason = "quickly threw this together")]
    pub fn new(
        uid: String,
        public_key: PublicKey,
        oracle: Oracle<PublicKey, TClock>,
        consensus_config: consensus::Builder<
            Control<PublicKey, TClock>,
            SocketManager<PublicKey, TClock>,
        >,
        execution_runtime: ExecutionRuntimeHandle,
        execution_config: ExecutionNodeConfig,
        network_address: SocketAddr,
        chain_address: Address,
    ) -> Self {
        let execution_node_datadir = execution_runtime
            .nodes_dir()
            .join(execution_runtime::execution_node_name(&public_key));

        let execution_node_name = execution_runtime::execution_node_name(&public_key);
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
            execution_node_name,
            execution_database: None,
            last_db_block_on_stop: None,
            network_address,
            chain_address,

            n_starts: 0,
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
    ) -> &consensus::Builder<Control<PublicKey, TClock>, SocketManager<PublicKey, TClock>> {
        &self.consensus_config
    }

    /// Get a mutable reference to the consensus config.
    pub fn consensus_config_mut(
        &mut self,
    ) -> &mut consensus::Builder<Control<PublicKey, TClock>, SocketManager<PublicKey, TClock>> {
        &mut self.consensus_config
    }

    /// Get a reference to the oracle.
    pub fn oracle(&self) -> &Oracle<PublicKey, TClock> {
        &self.oracle
    }

    /// Start both consensus and execution layers.
    ///
    ///
    /// # Panics
    /// Panics if either consensus or execution is already running.
    pub async fn start(&mut self, context: &Context) {
        self.start_execution().await;
        self.start_consensus(context).await;
        self.n_starts += 1;
    }

    /// Start the execution node and update consensus config to reference it.
    ///
    /// # Panics
    /// Panics if execution node is already running.
    #[instrument(skip_all, fields(last_db_block = self.last_db_block_on_stop))]
    async fn start_execution(&mut self) {
        assert!(
            self.execution_node.is_none(),
            "execution node is already running for {}",
            self.uid
        );

        // Create database if not exists
        if self.execution_database.is_none() {
            let db_path = self.execution_node_datadir.join("db");
            self.execution_database = Some(
                reth_db::init_db(db_path, DatabaseArguments::default())
                    .expect("failed to init database")
                    .with_metrics(),
            );
        }

        let execution_node = self
            .execution_runtime
            .spawn_node(
                &self.execution_node_name,
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
    async fn start_consensus(&mut self, context: &Context) {
        assert!(
            self.consensus_handle.is_none(),
            "consensus is already running for {}",
            self.uid
        );
        let engine = self
            .consensus_config
            .clone()
            .try_init(context.with_label(&format!("{}_{}", self.uid, self.n_starts)))
            .await
            .expect("must be able to start the engine");

        let votes = self
            .oracle
            .control(self.public_key.clone())
            .register(VOTES_CHANNEL_IDENT, VOTES_LIMIT)
            .await
            .unwrap();
        let certificates = self
            .oracle
            .control(self.public_key.clone())
            .register(CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT)
            .await
            .unwrap();
        let resolver = self
            .oracle
            .control(self.public_key.clone())
            .register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT)
            .await
            .unwrap();
        let broadcast = self
            .oracle
            .control(self.public_key.clone())
            .register(BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT)
            .await
            .unwrap();
        let marshal = self
            .oracle
            .control(self.public_key.clone())
            .register(MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT)
            .await
            .unwrap();
        let dkg = self
            .oracle
            .control(self.public_key.clone())
            .register(DKG_CHANNEL_IDENT, DKG_LIMIT)
            .await
            .unwrap();
        let subblocks = self
            .oracle
            .control(self.public_key.clone())
            .register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT)
            .await
            .unwrap();

        let consensus_handle = engine.start(
            votes,
            certificates,
            resolver,
            broadcast,
            marshal,
            dkg,
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
    #[instrument(skip_all)]
    async fn stop_consensus(&mut self) {
        let handle = self
            .consensus_handle
            .take()
            .unwrap_or_else(|| panic!("consensus is not running for {}, cannot stop", self.uid));
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
    #[instrument(skip_all)]
    async fn stop_execution(&mut self) {
        debug!(%self.uid, "stopping execution node for testing node");
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
        tracing::debug!(
            last_db_block,
            "storing last block block number to verify restart"
        );
        self.last_db_block_on_stop = Some(last_db_block);

        execution_node.shutdown().await;

        // Acquire a RW transaction and immediately drop it. This blocks until any
        // pending write transaction completes, ensuring all database writes are
        // fully flushed. Without this, a pending write could still be in-flight
        // after shutdown returns, leading to database/static-file inconsistencies
        // when the node restarts.
        drop(
            self.execution_database
                .as_ref()
                .expect("database should exist")
                .tx_mut()
                .expect("failed to acquire rw transaction"),
        );

        debug!(%self.uid, "stopped execution node for testing node");
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
    ) -> BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>> {
        self.execution().provider.clone()
    }

    /// Get a blockchain provider for when the execution node is down.
    ///
    /// This provider MUST BE DROPPED before starting the node again.
    pub fn execution_provider_offline(
        &self,
    ) -> BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>> {
        // Open a read-only provider to the database
        // Note: MDBX allows multiple readers, so this is safe even if another process
        // has the database open for reading
        let database = open_db_read_only(
            self.execution_node_datadir.join("db"),
            DatabaseArguments::default(),
        )
        .expect("failed to open execution node database")
        .with_metrics();

        let static_file_provider =
            StaticFileProvider::read_only(self.execution_node_datadir.join("static_files"), true)
                .expect("failed to open static files");

        let rocksdb = RocksDBProvider::builder(self.execution_node_datadir.join("rocksdb"))
            .build()
            .unwrap();

        let provider_factory = ProviderFactory::<NodeTypesWithDBAdapter<TempoNode, _>>::new(
            database,
            Arc::new(execution_runtime::chainspec()),
            static_file_provider,
            rocksdb,
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
    async fn just_restart() {
        // Ensures that the node can be stopped completely and brought up inside a test.
        let _ = tempo_eyre::install();

        let runner = Runner::from(Config::default().with_seed(0));
        let (tx_msg, mut rx_msg) = tokio::sync::mpsc::unbounded_channel::<Message>();

        std::thread::spawn(move || {
            runner.start(|mut context| async move {
                let setup = Setup::new()
                    .how_many_signers(1)
                    .linkage(Link {
                        latency: Duration::from_millis(10),
                        jitter: Duration::from_millis(1),
                        success_rate: 1.0,
                    })
                    .epoch_length(100);

                let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;

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
                            node.start(&context).await;
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
