use alloy::{
    providers::{Provider, ProviderBuilder},
    rpc,
    transports::http::reqwest::Url,
};
use alloy_primitives::U160;
use commonware_cryptography::Signer as _;
use eyre::WrapErr as _;
use rand::SeedableRng as _;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    time::Duration,
};
use tempfile::TempDir;
use tempo_commonware_node_cryptography::PrivateKey;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::{task::JoinHandle, time::sleep};

const CONSENSUS_P2P_PORT: u16 = 8_000;
const EXECUTION_RPC_PORT: u16 = 8_545;
const EXECUTION_P2P_PORT: u16 = 30_303;

const CONSENSUS_CONFIG: &str = "/tmp/consensus.toml";

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_recovery() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let validators = run_validators(3).await;

    // let (validator0, validator1, _validator2) = start_network().await?;
    //
    // let provider = validator0.provider();
    // ensure_block_production(provider.clone()).await?;
    //
    // // Stop a validator and ensure blocks are still being produced
    // validator1.stop().await?;
    // ensure_block_production(provider.clone()).await?;
    //
    // // Restart validator 1
    // let _validator0 = TempoValidator::new(Config {
    //     validator_id: "validator-0",
    //     consensus_config: "consensus-config-0.toml",
    //     consensus_p2p_port: 8000,
    //     execution_rpc_port: 8545,
    //     execution_p2p_port: 30304,
    // })
    // .await?;
    // ensure_block_production(provider.clone()).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_majority_network_failure() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (validator0, validator1, validator2) = start_network().await?;

    let provider = validator0.provider();
    ensure_block_production(provider.clone()).await?;

    validator1.stop().await?;
    validator2.stop().await?;

    let last_block = provider.get_block_number().await?;
    for _ in 0..5 {
        sleep(Duration::from_secs(1)).await;
        let current_block = provider.get_block_number().await?;
        assert_eq!(current_block, last_block);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_proposal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (validator0, validator1, validator2) = start_network().await?;

    // TODO: Submit invalid proposals (malformed txs, invalid state transitions, etc.)
    // TODO: Assert nodes reject invalid proposals without halting the network
    // TODO: Assert valid block production continues
    // TODO: Assert block produced contains all valid txs from mempool

    Ok(())
}

struct Config {
    validator_id: &'static str,
    consensus_config: &'static str,
    consensus_p2p_port: u16,
    execution_rpc_port: u16,
    execution_p2p_port: u16,
}

struct TempoValidator {
    container: ContainerAsync<GenericImage>,
    config: Config,
    rpc_url: Url,
    host_consensus_p2p_port: u16,
    host_execution_rpc_port: u16,
    host_execution_p2p_port: u16,
    _temp_dir: TempDir,
}

impl TempoValidator {
    async fn new(
        config @ Config {
            validator_id,
            consensus_config,
            consensus_p2p_port,
            execution_rpc_port,
            execution_p2p_port,
        }: Config,
    ) -> eyre::Result<Self> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/assets")
            .join(consensus_config);

        let temp_dir =
            TempDir::new().map_err(|e| eyre::eyre!("Failed to create temp directory: {}", e))?;
        let config_in_temp = temp_dir.path().join("consensus-config.toml");
        std::fs::copy(&config_path, &config_in_temp)
            .map_err(|e| eyre::eyre!("Failed to copy consensus config: {}", e))?;

        let container_discovery_port = get_available_port()?;
        let container_auth_port = get_available_port()?;

        let image = GenericImage::new("tempo-commonware", "latest")
            .with_wait_for(WaitFor::message_on_stdout("RPC HTTP server started"))
            .with_exposed_port(ContainerPort::Tcp(consensus_p2p_port))
            .with_exposed_port(ContainerPort::Tcp(execution_rpc_port))
            .with_exposed_port(ContainerPort::Tcp(execution_p2p_port))
            .with_env_var("RUST_LOG", "debug")
            .with_mount(testcontainers::core::Mount::bind_mount(
                config_in_temp.to_string_lossy(),
                "/tmp/consensus-config.toml",
            ))
            .with_cmd(vec![
                "node".to_string(),
                "--consensus-config".to_string(),
                "/tmp/consensus-config.toml".to_string(),
                "--datadir".to_string(),
                format!("/tmp/{}-data", validator_id),
                "--port".to_string(),
                execution_p2p_port.to_string(),
                "--http".to_string(),
                "--http.addr".to_string(),
                "0.0.0.0".to_string(),
                "--http.port".to_string(),
                execution_rpc_port.to_string(),
                "--http.api".to_string(),
                "all".to_string(),
                "--discovery.port".to_string(),
                container_discovery_port.to_string(),
                "--authrpc.port".to_string(),
                container_auth_port.to_string(),
            ]);

        let container = image.start().await?;

        let host_consensus_p2p_port = container
            .get_host_port_ipv4(consensus_p2p_port)
            .await
            .wrap_err_with(|| {
                format!(
                    "failed getting host port for in-container consensus p2p `{consensus_p2p_port}`"
                )
            })?;

        let host_execution_rpc_port = container
            .get_host_port_ipv4(execution_rpc_port)
            .await
            .map_err(|e| eyre::eyre!("Failed to get host port for RPC: {}", e))?;

        let host_execution_p2p_port = container
            .get_host_port_ipv4(execution_p2p_port)
            .await
            .map_err(|e| eyre::eyre!("Failed to get host port for P2P: {}", e))?;

        let rpc_url: Url = format!("http://127.0.0.1:{host_execution_rpc_port}").parse()?;

        let validator = Self {
            container,
            config,
            rpc_url,
            host_consensus_p2p_port,
            host_execution_rpc_port,
            host_execution_p2p_port,
            _temp_dir: temp_dir,
        };

        Ok(validator)
    }

    async fn wait_for_ready(&self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new().connect_http(self.rpc_url.clone());
        for _ in 0..5 {
            match provider.get_block_number().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::debug!("Waiting for node to be ready: {}", e);
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
        Err(eyre::eyre!("Node not ready"))
    }

    async fn stop(self) -> eyre::Result<()> {
        self.container
            .stop()
            .await
            .map_err(|e| eyre::eyre!("Failed to stop validator container: {}", e))?;
        Ok(())
    }

    fn provider(&self) -> impl Provider + Clone {
        ProviderBuilder::new().connect_http(self.rpc_url.clone())
    }

    // fn get_ports(&self) -> (u16, u16) {
    //     (self.host_rpc_port, self.host_p2p_port)
    // }

    fn get_rpc_url(&self) -> &Url {
        &self.rpc_url
    }
}

struct TxGenerator {
    handle: JoinHandle<eyre::Result<()>>,
}

impl TxGenerator {
    async fn new(
        _providers: Vec<impl Provider + Clone + Send + 'static>,
        _tps: u32,
    ) -> eyre::Result<Self> {
        let handle = tokio::spawn(async move {
            // TODO: Implement transaction generation with governor rate limiter
            // TODO: Use providers to send transactions at specified TPS
            loop {
                sleep(Duration::from_millis(100)).await;
            }
        });

        Ok(Self { handle })
    }
}

impl Drop for TxGenerator {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn get_available_port() -> eyre::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

async fn start_network() -> eyre::Result<(TempoValidator, TempoValidator, TempoValidator)> {
    let validator0 = TempoValidator::new(Config {
        validator_id: "validator-0",
        consensus_config: "consensus-config-0.toml",
        consensus_p2p_port: 8000,
        execution_rpc_port: 8545,
        execution_p2p_port: 30304,
    })
    .await?;

    let validator1 = TempoValidator::new(Config {
        validator_id: "validator-1",
        consensus_config: "consensus-config-1.toml",
        consensus_p2p_port: 8001,
        execution_rpc_port: 8546,
        execution_p2p_port: 30305,
    })
    .await?;

    let validator2 = TempoValidator::new(Config {
        validator_id: "validator-2",
        consensus_config: "consensus-config-2.toml",
        consensus_p2p_port: 8002,
        execution_rpc_port: 8547,
        execution_p2p_port: 30306,
    })
    .await?;
    // Wait for all validators to be ready
    validator0.wait_for_ready().await?;
    validator1.wait_for_ready().await?;
    validator2.wait_for_ready().await?;

    Ok((validator0, validator1, validator2))
}

async fn ensure_block_production(provider: impl Provider) -> eyre::Result<()> {
    let mut last_block = provider.get_block_number().await?;
    for _ in 0..3 {
        sleep(Duration::from_secs(1)).await;
        let current_block = provider.get_block_number().await?;
        assert!(current_block > last_block);
        last_block = current_block;
    }
    Ok(())
}

struct Validator {
    container: ContainerAsync<GenericImage>,
    config: tempo_commonware_node_config::Config,
    execution_rpc_addr: SocketAddr,
}

struct Validators {
    bootstrapper: Validator,
    peers: Vec<Validator>,
    _tmp: TempDir,
}

/// Creates the configuration for `amount` validators.
async fn run_validators(amount: usize) -> Validators {
    let mut all_configs = create_pre_configs(amount).into_iter();

    let ephemeral_out =
        TempDir::new().expect("must be able to create a temp direcetory for tests to work");
    let bootstrapper_toml = ephemeral_out.path().join("bootstrapper.toml");

    let bootstrapper_cfg = all_configs.next().unwrap();

    std::fs::write(
        &bootstrapper_toml,
        &toml::to_string_pretty(&bootstrapper_cfg).expect("must be able to turn config to toml"),
    )
    .expect("must be able to write bootstrapper config to temp test directory");

    let image = GenericImage::new("tempo-commonware", "latest")
        .with_wait_for(WaitFor::message_on_stdout("RPC HTTP server started"))
        .with_exposed_port(ContainerPort::Tcp(CONSENSUS_P2P_PORT))
        .with_exposed_port(ContainerPort::Tcp(EXECUTION_RPC_PORT))
        .with_exposed_port(ContainerPort::Tcp(EXECUTION_P2P_PORT))
        .with_env_var("RUST_LOG", "debug")
        .with_mount(testcontainers::core::Mount::bind_mount(
            bootstrapper_toml.to_string_lossy(),
            CONSENSUS_CONFIG,
        ))
        .with_cmd(vec![
            "node",
            "--consensus-config",
            CONSENSUS_CONFIG,
            "--datadir",
            "/tmp/data",
            "--port",
            EXECUTION_P2P_PORT.to_string().as_str(),
            "--http",
            "--http.addr",
            "0.0.0.0",
            "--http.port",
            EXECUTION_RPC_PORT.to_string().as_str(),
            "--http.api",
            "all",
        ]);

    let container = image
        .start()
        .await
        .expect("must be able to run bootstrapper node");

    let host = container.get_host().await;

    dbg!(&host.expect("could not get host"));

    let bootstrapper_addr = match container
        .get_host()
        .await
        .expect("boostrapper must have a host")
    {
        url::Host::Ipv4(addr) => addr,
        url::Host::Domain(domain) if domain == "localhost" => Ipv4Addr::LOCALHOST,
        _ => panic!("can't deal with non-ipv4 hosts for now"),
    };
    let bootstrapper_consensus_p2p_port = container
        .get_host_port_ipv4(CONSENSUS_P2P_PORT)
        .await
        .expect("bootstrapper consensus p2p must have a port");
    let bootstrapper_execution_rpc_port = container
        .get_host_port_ipv4(EXECUTION_RPC_PORT)
        .await
        .expect("bootstrapper rpc must have a port");

    let bootstrapper = Validator {
        container,
        config: bootstrapper_cfg,
        execution_rpc_addr: SocketAddr::new(
            IpAddr::V4(bootstrapper_addr),
            bootstrapper_execution_rpc_port,
        ),
    };

    // Consume the rest of the configs
    let mut peers = vec![];
    for (i, mut config) in all_configs.enumerate() {
        // XXX: here we set the bootstrapper so that we can find the node.
        let entry = config
            .peers
            .get_mut(&bootstrapper.config.signer.public_key())
            .expect("the bootstrapper must have an entry in the peers table");
        *entry = SocketAddr::new(
            IpAddr::V4(bootstrapper_addr),
            bootstrapper_consensus_p2p_port,
        )
        .to_string();

        let peer_toml = ephemeral_out.path().join(format!("peer-{i}.toml"));
        std::fs::write(
            &peer_toml,
            &toml::to_string_pretty(&config).expect("must be able to turn config to toml"),
        )
        .expect("must be able to write peer config to temp test directory");

        let image = GenericImage::new("tempo-commonware", "latest")
            .with_wait_for(WaitFor::message_on_stdout("RPC HTTP server started"))
            .with_exposed_port(ContainerPort::Tcp(CONSENSUS_P2P_PORT))
            .with_exposed_port(ContainerPort::Tcp(EXECUTION_RPC_PORT))
            .with_exposed_port(ContainerPort::Tcp(EXECUTION_P2P_PORT))
            .with_env_var("RUST_LOG", "debug")
            .with_mount(testcontainers::core::Mount::bind_mount(
                peer_toml.to_string_lossy(),
                CONSENSUS_CONFIG,
            ))
            .with_cmd(vec![
                "node",
                "--consensus-config",
                CONSENSUS_CONFIG,
                "--datadir",
                "/tmp/data",
                "--port",
                EXECUTION_P2P_PORT.to_string().as_str(),
                "--http",
                "--http.addr",
                "0.0.0.0",
                "--http.port",
                EXECUTION_RPC_PORT.to_string().as_str(),
                "--http.api",
                "all",
            ]);

        let container = image.start().await.expect("must be able to run peer node");

        let host_addr = match container
            .get_host()
            .await
            .expect("boostrapper must have a host")
        {
            url::Host::Ipv4(addr) => addr,
            url::Host::Domain(domain) if domain == "localhost" => Ipv4Addr::LOCALHOST,
            _ => panic!("can't deal with non-ipv4 hosts for now"),
        };

        let execution_rpc_port = container
            .get_host_port_ipv4(EXECUTION_RPC_PORT)
            .await
            .expect("peer rpc must have a port");
        let peer = Validator {
            container,
            config,
            execution_rpc_addr: SocketAddr::new(IpAddr::V4(host_addr), execution_rpc_port),
        };
        peers.push(peer);
    }

    Validators {
        bootstrapper,
        peers,
        _tmp: ephemeral_out,
    }
}

/// Creates a bunch of "raw" configs that are still lacking peers information.
fn create_pre_configs(peers: usize) -> Vec<tempo_commonware_node_config::Config> {
    use commonware_cryptography::PrivateKeyExt as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);

    let threshold = commonware_utils::quorum(peers as u32);
    let (polynomial, shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        tempo_commonware_node_cryptography::BlsScheme,
    >(&mut rng, None, peers as u32, threshold);

    let mut all_configs = vec![];
    let mut bootstrapper = None;
    for share in shares {
        let signer = PrivateKey::from_rng(&mut rng);
        // XXX: the first peer always becomes the bootstrapper.
        let bootstrappers = vec![bootstrapper.get_or_insert(signer.public_key()).clone()].into();

        all_configs.push(tempo_commonware_node_config::Config {
            signer,
            share,
            polynomial: polynomial.clone(),
            listen_port: CONSENSUS_P2P_PORT,
            metrics_port: None,
            p2p: Default::default(),
            storage_directory: "/tmp/consensus".into(),
            worker_threads: 3,
            // this will be updated after we have collected all peers
            peers: Default::default(),
            bootstrappers,
            message_backlog: 16384,
            mailbox_size: 16384,
            deque_size: 10,
            fee_recipient: alloy_primitives::Address::from(U160::ZERO),
            timeouts: Default::default(),
        });
    }
    // XXX: Bit silly workaround; we need all public keys to identify the peers, but
    // the IP address will be set later once it is known.
    let peers = all_configs
        .iter()
        .map(|cfg| {
            (
                cfg.signer.public_key(),
                "0.0.0.0:{CONSENSUS_P2P_PORT}".to_string(),
            )
        })
        .collect::<indexmap::IndexMap<_, _>>();
    all_configs
        .iter_mut()
        .for_each(|cfg| cfg.peers = peers.clone());
    all_configs
}
