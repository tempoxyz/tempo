//! The environment to launch tempo execution nodes in.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use alloy::{
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
    transports::http::reqwest::Url,
};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256};
use commonware_codec::Encode;
use commonware_cryptography::ed25519::PublicKey;
use eyre::WrapErr as _;
use futures::StreamExt;
use reth_db::mdbx::DatabaseEnv;
use reth_ethereum::{
    network::{
        Peers,
        api::{
            NetworkEventListenerProvider, PeersInfo,
            events::{NetworkEvent, PeerEvent},
        },
    },
    tasks::TaskManager,
};
use reth_network_peers::{NodeRecord, TrustedPeer};
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_node_core::{
    args::{DatadirArgs, PayloadBuilderArgs, RpcServerArgs},
    exit::NodeExitFuture,
};
use reth_rpc_builder::RpcModuleSelection;
use secp256k1::SecretKey;
use std::net::TcpListener;
use tempfile::TempDir;
use tempo_chainspec::TempoChainSpec;
use tempo_commonware_node_config::PublicPolynomial;
use tempo_node::{TempoFullNode, node::TempoNode};
use tempo_precompiles::{VALIDATOR_CONFIG_ADDRESS, validator_config::IValidatorConfig};

const ADMIN_INDEX: u32 = 0;
const VALIDATOR_START_INDEX: u32 = 1;

/// Same mnemonic as used in the imported test-genesis and in the `tempo-node` integration tests.
pub const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// Configuration for launching an execution node.
#[derive(Clone, Debug)]
pub struct ExecutionNodeConfig {
    /// Network secret key for the node's identity.
    pub secret_key: B256,
    /// List of trusted peer enode URLs to connect to.
    pub trusted_peers: Vec<String>,
    /// Port for the network service.
    pub port: u16,
}

impl ExecutionNodeConfig {
    /// Create a default generator for building multiple execution node configs.
    pub fn generator() -> ExecutionNodeConfigGenerator {
        ExecutionNodeConfigGenerator::default()
    }
}

/// Generator for creating multiple execution node configurations.
#[derive(Default)]
pub struct ExecutionNodeConfigGenerator {
    count: u32,
    connect_peers: bool,
}

impl ExecutionNodeConfigGenerator {
    /// Set the number of nodes to generate.
    pub fn with_count(mut self, count: u32) -> Self {
        self.count = count;
        self
    }

    /// Set whether to enable peer connections between all generated nodes.
    pub fn with_peers(mut self, connect: bool) -> Self {
        self.connect_peers = connect;
        self
    }

    /// Generate the execution node configurations.
    pub fn generate(self) -> Vec<ExecutionNodeConfig> {
        if !self.connect_peers {
            // No peer connections needed, use port 0 (OS will assign)
            return (0..self.count)
                .map(|_| ExecutionNodeConfig {
                    secret_key: B256::random(),
                    trusted_peers: vec![],
                    port: 0,
                })
                .collect();
        }

        // Reserve ports by binding to them for peer connections
        let ports: Vec<u16> = (0..self.count)
            .map(|_| {
                // This should work, but there's a chance that it results in flaky tests
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let port = listener
                    .local_addr()
                    .expect("failed to get local addr")
                    .port();
                drop(listener);
                port
            })
            .collect();

        let mut configs: Vec<ExecutionNodeConfig> = ports
            .into_iter()
            .map(|port| ExecutionNodeConfig {
                secret_key: B256::random(),
                trusted_peers: vec![],
                port,
            })
            .collect();

        let enode_urls: Vec<String> = configs
            .iter()
            .map(|config| {
                let secret_key =
                    SecretKey::from_slice(config.secret_key.as_slice()).expect("valid secret key");
                let addr = format!("127.0.0.1:{}", config.port)
                    .parse()
                    .expect("valid socket address");
                NodeRecord::from_secret_key(addr, &secret_key).to_string()
            })
            .collect();

        for (i, config) in configs.iter_mut().enumerate() {
            for (j, enode_url) in enode_urls.iter().enumerate() {
                if i != j {
                    config.trusted_peers.push(enode_url.clone());
                }
            }
        }

        configs
    }
}

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
    /// Constructs a new execution runtime to launch execution nodes using the default chainspec.
    pub fn new() -> Self {
        Self::with_chain_spec(chainspec())
    }

    /// Constructs a new execution runtime to launch execution nodes.
    pub fn with_chain_spec(chain_spec: TempoChainSpec) -> Self {
        let tempdir = tempfile::Builder::new()
            // TODO(janis): cargo manifest prefix?
            .prefix("tempo_e2e_test")
            .tempdir()
            .expect("must be able to create a temp directory run tun tests");

        let (to_runtime, mut from_handle) = tokio::sync::mpsc::unbounded_channel();

        let datadir = tempdir.path().to_path_buf();
        let rt = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new()
                .expect("must be able to initialize a runtime to run execution/reth nodes");
            let wallet = MnemonicBuilder::from_phrase(crate::execution_runtime::TEST_MNEMONIC)
                .build()
                .unwrap();
            rt.block_on(async move {
                while let Some(msg) = from_handle.recv().await {
                    // create a new task manager for the new node instance
                    let task_manager = TaskManager::current();
                    match msg {
                        Message::AddValidator(add_validator) => {
                            let AddValidator {
                                http_url,
                                address,
                                public_key,
                                addr,
                                response,
                            } = *add_validator;
                            let provider = ProviderBuilder::new()
                                .wallet(wallet.clone())
                                .connect_http(http_url);
                            let validator_config =
                                IValidatorConfig::new(VALIDATOR_CONFIG_ADDRESS, provider);
                            let receipt = validator_config
                                .addValidator(
                                    address,
                                    public_key.encode().as_ref().try_into().unwrap(),
                                    true,
                                    addr.to_string(),
                                    addr.to_string(),
                                )
                                .send()
                                .await
                                .unwrap()
                                .get_receipt()
                                .await
                                .unwrap();
                            let _ = response.send(receipt);
                        }
                        Message::ChangeValidatorStatus(change_validator_status) => {
                            let ChangeValidatorStatus {
                                http_url,
                                active,
                                address,
                                response,
                            } = *change_validator_status;
                            let provider = ProviderBuilder::new()
                                .wallet(wallet.clone())
                                .connect_http(http_url);
                            let validator_config =
                                IValidatorConfig::new(VALIDATOR_CONFIG_ADDRESS, provider);
                            let receipt = validator_config
                                .changeValidatorStatus(address, active)
                                .send()
                                .await
                                .unwrap()
                                .get_receipt()
                                .await
                                .unwrap();
                            let _ = response.send(receipt);
                        }
                        Message::SpawnNode {
                            name,
                            config,
                            database,
                            response,
                        } => {
                            let node = launch_execution_node(
                                task_manager,
                                chain_spec.clone(),
                                datadir.join(name),
                                config,
                                database,
                            )
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
            nodes_dir: self._tempdir.path().to_path_buf(),
        }
    }

    pub async fn add_validator(
        &self,
        http_url: Url,
        address: Address,
        public_key: PublicKey,
        addr: SocketAddr,
    ) -> eyre::Result<TransactionReceipt> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(
                AddValidator {
                    http_url,
                    address,
                    public_key,
                    addr,
                    response: tx,
                }
                .into(),
            )
            .wrap_err("the execution runtime went away")?;
        rx.await
            .wrap_err("the execution runtime dropped the response channel before sending a receipt")
    }

    pub async fn change_validator_status(
        &self,
        http_url: Url,
        address: Address,
        active: bool,
    ) -> eyre::Result<TransactionReceipt> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(
                ChangeValidatorStatus {
                    address,
                    active,
                    http_url,
                    response: tx,
                }
                .into(),
            )
            .wrap_err("the execution runtime went away")?;
        rx.await
            .wrap_err("the execution runtime dropped the response channel before sending a receipt")
    }

    pub async fn remove_validator(
        &self,
        http_url: Url,
        address: Address,
        public_key: PublicKey,
        addr: SocketAddr,
    ) -> eyre::Result<TransactionReceipt> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(
                AddValidator {
                    http_url,
                    address,
                    public_key,
                    addr,
                    response: tx,
                }
                .into(),
            )
            .wrap_err("the execution runtime went away")?;
        rx.await
            .wrap_err("the execution runtime dropped the response channel before sending a receipt")
    }

    /// Requests a new execution node and blocks until its returned.
    pub async fn spawn_node(
        &self,
        name: &str,
        config: ExecutionNodeConfig,
        database: Arc<DatabaseEnv>,
    ) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                config,
                database,
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.await.wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }

    /// Requests a new execution node and blocks until its returned.
    pub fn spawn_node_blocking(
        &self,
        name: &str,
        config: ExecutionNodeConfig,
        database: Arc<DatabaseEnv>,
    ) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                config,
                database,
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
#[derive(Clone)]
pub struct ExecutionRuntimeHandle {
    to_runtime: tokio::sync::mpsc::UnboundedSender<Message>,
    nodes_dir: PathBuf,
}

impl ExecutionRuntimeHandle {
    /// Returns the base directory where execution node data is stored.
    pub fn nodes_dir(&self) -> &Path {
        &self.nodes_dir
    }

    /// Requests a new execution node and blocks until its returned.
    pub async fn spawn_node(
        &self,
        name: &str,
        config: ExecutionNodeConfig,
        database: Arc<DatabaseEnv>,
    ) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                config,
                database,
                response: tx,
            })
            .wrap_err("the execution runtime went away")?;
        rx.await.wrap_err(
            "the execution runtime dropped the response channel before sending an execution node",
        )
    }

    /// Requests a new execution node and blocks until its returned.
    pub fn spawn_node_blocking(
        &self,
        name: &str,
        config: ExecutionNodeConfig,
        database: Arc<DatabaseEnv>,
    ) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(Message::SpawnNode {
                name: name.to_string(),
                config,
                database,
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
    /// All handles to interact with the launched node instances and services.
    pub node: TempoFullNode,
    /// The [`TaskManager`] that drives the node's services.
    pub task_manager: TaskManager,
    /// The exist future that resolves when the node's engine future resolves.
    pub exit_fut: NodeExitFuture,
}

impl ExecutionNode {
    /// Connect peers bidirectionally.
    pub async fn connect_peer(&self, other: &Self) {
        let self_record = self.node.network.local_node_record();
        let other_record = other.node.network.local_node_record();
        let mut events = self.node.network.event_listener();

        self.node
            .network
            .add_trusted_peer(other_record.id, other_record.tcp_addr());

        match events.next().await {
            Some(NetworkEvent::Peer(PeerEvent::PeerAdded(_))) => (),
            ev => panic!("Expected a peer added event, got: {ev:?}"),
        }

        match events.next().await {
            Some(NetworkEvent::ActivePeerSession { .. }) => (),
            ev => panic!("Expected an active peer session event, got: {ev:?}"),
        }

        tracing::debug!(
            "Connected peers: {:?} -> {:?}",
            self_record.id,
            other_record.id
        );
    }

    /// Shuts down the node and awaits until the node is terminated.
    pub async fn shutdown(self) {
        let _ = self.node.rpc_server_handle().clone().stop();
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        let _ = self.exit_fut.await;
    }
}

/// Returns the chainspec used for e2e tests.
///
/// TODO(janis): allow configuring this.
pub fn chainspec() -> TempoChainSpec {
    TempoChainSpec::from_genesis(genesis())
}

/// Returns the chainspec used for e2e tests as Arc.
pub fn chainspec_arc() -> Arc<TempoChainSpec> {
    Arc::new(chainspec())
}

/// Generate execution node name from public key.
pub fn execution_node_name(public_key: &PublicKey) -> String {
    format!("{}-{}", crate::EXECUTION_NODE_PREFIX, public_key)
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

pub fn genesis() -> Genesis {
    serde_json::from_str(include_str!(
        "../../node/tests/assets/test-genesis-moderato.json"
    ))
    .unwrap()
}

pub fn insert_allegretto(mut genesis: Genesis, timestamp: u64) -> Genesis {
    genesis
        .config
        .extra_fields
        .insert_value("allegrettoTime".to_string(), timestamp)
        .unwrap();
    genesis
}

pub fn insert_epoch_length(mut genesis: Genesis, epoch_length: u64) -> Genesis {
    genesis
        .config
        .extra_fields
        .insert_value("epochLength".to_string(), epoch_length)
        .unwrap();
    genesis
}

pub fn insert_validators(
    mut genesis: Genesis,
    validators: tempo_commonware_node_config::Peers,
) -> Genesis {
    genesis
        .config
        .extra_fields
        .insert_value("validators".to_string(), validators)
        .unwrap();
    genesis
}

pub fn insert_public_polynomial(
    mut genesis: Genesis,
    public_polynomial: PublicPolynomial,
) -> Genesis {
    genesis
        .config
        .extra_fields
        .insert_value("publicPolynomial".to_string(), public_polynomial)
        .unwrap();
    genesis
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
    task_manager: TaskManager,
    chain_spec: TempoChainSpec,
    datadir: P,
    config: ExecutionNodeConfig,
    database: Arc<DatabaseEnv>,
) -> eyre::Result<ExecutionNode> {
    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        )
        .with_datadir_args(DatadirArgs {
            datadir: datadir.as_ref().to_path_buf().into(),
            ..DatadirArgs::default()
        })
        .with_payload_builder(PayloadBuilderArgs {
            interval: Duration::from_millis(100),
            ..Default::default()
        })
        .apply(|mut c| {
            c.network.discovery.disable_discovery = true;
            c.network.trusted_peers = config
                .trusted_peers
                .into_iter()
                .map(|s| TrustedPeer::from_str(&s).expect("invalid trusted peer enode"))
                .collect();
            c.network.port = config.port;
            c.network.p2p_secret_key_hex = Some(config.secret_key);
            c
        });

    let node_handle = NodeBuilder::new(node_config)
        .with_database(database)
        .with_launch_context(task_manager.executor())
        .node(TempoNode::default())
        .launch()
        .await
        .wrap_err("failed launching node")?;

    Ok(ExecutionNode {
        node: node_handle.node,
        task_manager,
        exit_fut: node_handle.node_exit_future,
    })
}

#[derive(Debug)]
enum Message {
    AddValidator(Box<AddValidator>),
    ChangeValidatorStatus(Box<ChangeValidatorStatus>),
    SpawnNode {
        name: String,
        config: ExecutionNodeConfig,
        database: Arc<DatabaseEnv>,
        response: tokio::sync::oneshot::Sender<ExecutionNode>,
    },
    Stop,
}

impl From<AddValidator> for Message {
    fn from(value: AddValidator) -> Self {
        Self::AddValidator(value.into())
    }
}

impl From<ChangeValidatorStatus> for Message {
    fn from(value: ChangeValidatorStatus) -> Self {
        Self::ChangeValidatorStatus(value.into())
    }
}

#[derive(Debug)]
struct AddValidator {
    /// URL of the node to send this to.
    http_url: Url,
    address: Address,
    public_key: PublicKey,
    addr: SocketAddr,
    response: tokio::sync::oneshot::Sender<TransactionReceipt>,
}

#[derive(Debug)]
struct ChangeValidatorStatus {
    /// URL of the node to send this to.
    http_url: Url,
    address: Address,
    active: bool,
    response: tokio::sync::oneshot::Sender<TransactionReceipt>,
}

pub fn admin() -> Address {
    address(ADMIN_INDEX)
}

pub fn validator(idx: u32) -> Address {
    address(VALIDATOR_START_INDEX + idx)
}

pub fn address(index: u32) -> Address {
    secret_key_to_address(MnemonicBuilder::from_phrase_nth(TEST_MNEMONIC, index).credential())
}
