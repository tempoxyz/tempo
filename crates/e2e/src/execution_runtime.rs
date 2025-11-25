//! The environment to launch tempo execution nodes in.
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use alloy::{
    providers::ProviderBuilder,
    rpc::types::TransactionReceipt,
    signers::{
        local::{MnemonicBuilder, coins_bip39::English},
        utils::secret_key_to_address,
    },
    transports::http::reqwest::Url,
};
use alloy_genesis::Genesis;
use alloy_primitives::Address;
use commonware_codec::Encode;
use commonware_cryptography::ed25519::PublicKey;
use eyre::WrapErr as _;
use futures::StreamExt;
use reth_db::mdbx::DatabaseArguments;
use reth_ethereum::{
    network::{
        Peers,
        api::{
            NetworkEventListenerProvider, PeersInfo,
            events::{NetworkEvent, PeerEvent},
        },
    },
    tasks::{TaskExecutor, TaskManager},
};
use reth_evm::{
    EvmEnv, EvmFactory,
    revm::database::{CacheDB, EmptyDB},
};
use reth_node_builder::{NodeBuilder, NodeConfig};
use reth_node_core::{
    args::{DatadirArgs, PayloadBuilderArgs, RpcServerArgs},
    exit::NodeExitFuture,
};
use reth_rpc_builder::RpcModuleSelection;
use tempfile::TempDir;
use tempo_chainspec::TempoChainSpec;
use tempo_commonware_node_config::PublicPolynomial;
use tempo_evm::{TempoEvmFactory, evm::TempoEvm};
use tempo_node::{TempoFullNode, node::TempoNode};
use tempo_precompiles::{VALIDATOR_CONFIG_ADDRESS, validator_config::IValidatorConfig};

const ADMIN_INDEX: u32 = 0;
const VALIDATOR_START_INDEX: u32 = 1;

/// Same mnemonic as used in the imported test-genesis and in the `tempo-node` integration tests.
pub const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

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
    pub fn with_chain_spec(chain_spec: TempoChainSpec) -> Self {
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
            let wallet = MnemonicBuilder::from_phrase(crate::execution_runtime::TEST_MNEMONIC)
                .build()
                .unwrap();
            rt.block_on(async move {
                let task_manager = TaskManager::current();
                while let Some(msg) = from_handle.recv().await {
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
                        Message::SpawnNode(spawn_node) => {
                            let SpawnNode { name, response } = *spawn_node;
                            let node = launch_execution_node(
                                task_manager.executor(),
                                chain_spec.clone(),
                                datadir.join(name),
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
    pub async fn spawn_node(&self, name: &str) -> eyre::Result<ExecutionNode> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.to_runtime
            .send(
                SpawnNode {
                    name: name.to_string(),
                    response: tx,
                }
                .into(),
            )
            .wrap_err("the execution runtime went away")?;
        rx.await.wrap_err(
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

/// An execution node spawned by the execution runtime.
///
/// This is essentially the same as [`reth_node_builder::NodeHandle`], but
/// avoids the type parameters.
pub struct ExecutionNode {
    pub node: TempoFullNode,
    pub _exit_fut: NodeExitFuture,
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

// TODO(janis): allow configuring this.
pub fn chainspec() -> TempoChainSpec {
    TempoChainSpec::from_genesis(genesis())
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
    executor: TaskExecutor,
    chain_spec: TempoChainSpec,
    datadir: P,
) -> eyre::Result<ExecutionNode> {
    let node_config = NodeConfig::new(Arc::new(chain_spec))
        .with_rpc(
            RpcServerArgs::default()
                .with_unused_ports()
                .with_http()
                .with_http_api(RpcModuleSelection::All),
        )
        .with_unused_ports()
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
            c
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
    AddValidator(Box<AddValidator>),
    ChangeValidatorStatus(Box<ChangeValidatorStatus>),
    SpawnNode(Box<SpawnNode>),
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

impl From<SpawnNode> for Message {
    fn from(value: SpawnNode) -> Self {
        Self::SpawnNode(value.into())
    }
}

#[derive(Debug)]
struct SpawnNode {
    name: String,
    response: tokio::sync::oneshot::Sender<ExecutionNode>,
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
    let signer = MnemonicBuilder::<English>::default()
        .phrase(TEST_MNEMONIC)
        .index(index)
        .unwrap()
        .build()
        .unwrap();
    secret_key_to_address(signer.credential())
}

fn setup_tempo_evm() -> TempoEvm<CacheDB<EmptyDB>> {
    let db = CacheDB::default();
    let env = EvmEnv::default();
    let factory = TempoEvmFactory::default();
    factory.create_evm(db, env)
}
