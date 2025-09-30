use alloy::{
    providers::{Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
use std::{process::Stdio, time::Duration};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::sleep,
};

#[tokio::test(flavor = "multi_thread")]
async fn test_validator_recovery() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // Start a single validator node
    let validator = TempoValidator::new("validator-1".to_string(), 8545, 30303).await?;
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
    process: Child,
    rpc_url: Url,
    validator_id: String,
    rpc_port: u16,
    p2p_port: u16,
}

impl TempoValidator {
    async fn new(validator_id: String, rpc_port: u16, p2p_port: u16) -> eyre::Result<Self> {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/assets/consensus-config.toml");

        let datadir = format!("/tmp/tempo-test-{}", validator_id);

        let mut cmd = Command::new("cargo");
        cmd.args(&[
            "run",
            "--bin",
            "tempo-commonware",
            "--",
            "node",
            "--consensus-config",
        ])
        .arg(&config_path)
        .args(&["--datadir", &datadir])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        let process = cmd
            .spawn()
            .map_err(|e| eyre::eyre!("Failed to start tempo-commonware process: {}", e))?;

        let rpc_url: Url = "http://127.0.0.1:8545".parse()?;

        let validator = Self {
            process,
            rpc_url,
            validator_id,
            rpc_port,
            p2p_port,
        };

        Ok(validator)
    }

    async fn wait_for_ready(&self) -> eyre::Result<()> {
        let provider = ProviderBuilder::new().connect_http(self.rpc_url.clone());
        for _ in 0..3 {
            match provider.get_block_number().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    tracing::error!("Failed to connect to provider and get block number: {}", e);
                }
            }
            sleep(Duration::from_secs(1)).await;
        }

        Err(eyre::eyre!("Node not ready after 3 attempts"))
    }

    async fn stop(mut self) -> eyre::Result<()> {
        self.process
            .kill()
            .await
            .map_err(|e| eyre::eyre!("Failed to stop validator process: {}", e))?;
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
