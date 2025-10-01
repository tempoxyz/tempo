use alloy::{
    providers::{Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
use std::time::Duration;
use tempfile::TempDir;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{ContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::{task::JoinHandle, time::sleep};

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_recovery() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start a single validator node
    let validator = TempoValidator::new(
        "validator-1".to_string(),
        8545,
        30305,
        "consensus-config.toml",
    )
    .await?;
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
    rpc_port: u16,
    p2p_port: u16,
    _temp_dir: TempDir,
}

impl TempoValidator {
    async fn new(
        validator_id: String,
        rpc_port: u16,
        p2p_port: u16,
        consensus_config: &str,
    ) -> eyre::Result<Self> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/assets")
            .join(consensus_config);

        let temp_dir =
            TempDir::new().map_err(|e| eyre::eyre!("Failed to create temp directory: {}", e))?;
        let datadir = temp_dir.path().to_string_lossy();

        // Copy consensus config to temp directory for mounting
        let config_in_temp = temp_dir.path().join("consensus-config.toml");
        std::fs::copy(&config_path, &config_in_temp)
            .map_err(|e| eyre::eyre!("Failed to copy consensus config: {}", e))?;

        // Create a Docker image for the tempo node
        let image = GenericImage::new("tempo-commonware", "latest")
            .with_wait_for(WaitFor::message_on_stdout("RPC Server Started"))
            .with_exposed_port(ContainerPort::Tcp(8545)) // Default RPC port
            .with_exposed_port(ContainerPort::Tcp(30303)) // Default P2P port
            .with_exposed_port(ContainerPort::Tcp(8546)) // Default metrics port
            .with_env_var("RUST_LOG", "debug")
            .with_cmd(vec![
                "node".to_string(),
                "--consensus-config".to_string(),
                "/tmp/consensus-config.toml".to_string(),
                "--datadir".to_string(),
                format!("/tmp/{}-data", validator_id),
                "--port".to_string(),
                "30303".to_string(),
                "--http".to_string(),
                "--http.addr".to_string(),
                "0.0.0.0".to_string(),
                "--http.port".to_string(),
                "8545".to_string(),
                "--http.api".to_string(),
                "all".to_string(),
                "--discovery.port".to_string(),
                "30306".to_string(),
                "--authrpc.port".to_string(),
                "8558".to_string(),
            ]);

        println!(
            "Starting container for validator {} with RPC port {} and P2P port {}",
            validator_id, rpc_port, p2p_port
        );

        let container = image.start().await?;
        let host_rpc_port = container
            .get_host_port_ipv4(8545)
            .await
            .map_err(|e| eyre::eyre!("Failed to get host port for RPC: {}", e))?;

        let rpc_url: Url = format!("http://127.0.0.1:{}", host_rpc_port).parse()?;

        let validator = Self {
            container,
            rpc_url,
            validator_id,
            rpc_port,
            p2p_port,
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
        (self.rpc_port, self.p2p_port)
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
