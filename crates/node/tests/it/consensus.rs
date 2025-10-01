use alloy::{
    providers::{Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
use std::{net::TcpListener, time::Duration};
use tempfile::TempDir;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::{task::JoinHandle, time::sleep};

fn get_available_port() -> eyre::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_recovery() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start a single validator node
    let validator = TempoValidator::new("validator-1".to_string(), "consensus-config.toml").await?;
    validator.wait_for_ready().await?;

    println!(
        "Validator started successfully at RPC URL: {}",
        validator.rpc_url
    );

    // TODO: Set up 3+ validator nodes
    // TODO: Stop one validator node
    // TODO: Assert network continues block production with remaining validators
    // TODO: Restart the stopped node
    // TODO: Assert node re-syncs to tip and resumes participation
    // TODO: Assert block production continues as normal

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_majority_network_failure() -> eyre::Result<()> {
    // reth_tracing::init_test_tracing();

    // TODO: Set up 3+ validator nodes
    // TODO: Stop 2/3rds of validator nodes
    // TODO: Assert network halts (no new blocks produced)
    // TODO: Restart stopped validators
    // TODO: Assert network recovers and resumes from last finalized block

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_invalid_proposal() -> eyre::Result<()> {
    // reth_tracing::init_test_tracing();

    // TODO: Set up validator network
    // TODO: Submit invalid proposals (malformed txs, invalid state transitions, etc.)
    // TODO: Assert nodes reject invalid proposals without halting the network
    // TODO: Assert valid block production continues
    // TODO: Assert block produced contains all valid txs from mempool

    Ok(())
}

struct TempoValidator {
    container: ContainerAsync<GenericImage>,
    rpc_url: Url,
    validator_id: String,
    container_rpc_port: u16,
    container_p2p_port: u16,
    host_rpc_port: u16,
    host_p2p_port: u16,
    _temp_dir: TempDir,
}

impl TempoValidator {
    async fn new(validator_id: String, consensus_config: &str) -> eyre::Result<Self> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/assets")
            .join(consensus_config);

        let temp_dir =
            TempDir::new().map_err(|e| eyre::eyre!("Failed to create temp directory: {}", e))?;
        let config_in_temp = temp_dir.path().join("consensus-config.toml");
        std::fs::copy(&config_path, &config_in_temp)
            .map_err(|e| eyre::eyre!("Failed to copy consensus config: {}", e))?;

        let container_rpc_port = get_available_port()?;
        let container_p2p_port = get_available_port()?;
        let container_discovery_port = get_available_port()?;
        let container_auth_port = get_available_port()?;

        let image = GenericImage::new("tempo-commonware", "latest")
            .with_wait_for(WaitFor::message_on_stdout("RPC HTTP server started"))
            .with_exposed_port(ContainerPort::Tcp(container_rpc_port))
            .with_exposed_port(ContainerPort::Tcp(container_p2p_port))
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
                container_p2p_port.to_string(),
                "--http".to_string(),
                "--http.addr".to_string(),
                "0.0.0.0".to_string(),
                "--http.port".to_string(),
                container_rpc_port.to_string(),
                "--http.api".to_string(),
                "all".to_string(),
                "--discovery.port".to_string(),
                container_discovery_port.to_string(),
                "--authrpc.port".to_string(),
                container_auth_port.to_string(),
            ]);

        let container = image.start().await?;
        let host_rpc_port = container
            .get_host_port_ipv4(container_rpc_port)
            .await
            .map_err(|e| eyre::eyre!("Failed to get host port for RPC: {}", e))?;

        let host_p2p_port = container
            .get_host_port_ipv4(container_p2p_port)
            .await
            .map_err(|e| eyre::eyre!("Failed to get host port for P2P: {}", e))?;

        let rpc_url: Url = format!("http://127.0.0.1:{}", host_rpc_port).parse()?;

        let validator = Self {
            container,
            rpc_url,
            validator_id,
            container_rpc_port,
            container_p2p_port,
            host_rpc_port,
            host_p2p_port,
            _temp_dir: temp_dir,
        };

        Ok(validator)
    }

    async fn wait_for_ready(&self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new().connect_http(self.rpc_url.clone());
        for _ in 0..30 {
            match provider.get_block_number().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::debug!("Waiting for node to be ready: {}", e);
                }
            }
            sleep(Duration::from_secs(2)).await;
        }
        Err(eyre::eyre!("Node not ready after 60 seconds"))
    }

    async fn stop(self) -> eyre::Result<()> {
        self.container
            .stop()
            .await
            .map_err(|e| eyre::eyre!("Failed to stop validator container: {}", e))?;
        Ok(())
    }

    fn provider(&self) -> impl Provider {
        ProviderBuilder::new().connect_http(self.rpc_url.clone())
    }

    fn get_ports(&self) -> (u16, u16) {
        (self.host_rpc_port, self.host_p2p_port)
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
