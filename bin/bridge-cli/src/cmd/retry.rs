use alloy::{
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::{Context, Result};
use std::path::PathBuf;
use tempo_bridge_exex::{BridgeConfig, TempoClient};

#[derive(Parser, Debug)]
pub struct RetryArgs {
    /// Request ID or burn ID to retry
    #[arg(required = true)]
    id: String,

    /// Path to bridge config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Tempo RPC URL (overrides config)
    #[arg(long)]
    tempo_rpc: Option<String>,

    /// Path to private key file for signing
    #[arg(long)]
    key_path: Option<PathBuf>,

    /// Retry type: deposit or burn
    #[arg(long, default_value = "deposit")]
    r#type: String,

    /// Dry run (don't submit transaction)
    #[arg(long)]
    dry_run: bool,
}

impl RetryArgs {
    pub async fn run(self) -> Result<()> {
        let id: B256 = self.id.parse().context("Invalid ID format")?;

        let config = if let Some(config_path) = &self.config {
            BridgeConfig::load(config_path)?
        } else {
            BridgeConfig::default_test_config()
        };

        let tempo_rpc = self
            .tempo_rpc
            .or(config.tempo_rpc_url.clone())
            .unwrap_or_else(|| "http://localhost:8551".to_string());

        println!("Retrying {} {}", self.r#type, id);
        println!();

        if self.dry_run {
            println!("Dry run mode - no transaction will be submitted");
            println!();

            // Check current status
            let provider = ProviderBuilder::new().connect(&tempo_rpc).await?;
            let block = provider.get_block_number().await?;
            println!("Current Tempo block: {block}");
            println!("Would retry {} with ID: {}", self.r#type, id);
            return Ok(());
        }

        // Need a signer to submit transactions
        let key_path = self
            .key_path
            .or(config.validator_key_path.as_ref().map(PathBuf::from))
            .ok_or_else(|| eyre::eyre!("No key path provided"))?;

        let key_hex = std::fs::read_to_string(&key_path)
            .context("Failed to read key file")?
            .trim()
            .to_string();
        let signer: PrivateKeySigner = key_hex.parse().context("Invalid private key")?;

        let client = TempoClient::new(&tempo_rpc, signer).await?;

        match self.r#type.as_str() {
            "deposit" => {
                println!("Attempting to finalize deposit...");
                match client.try_finalize_deposit(id).await? {
                    Some(tx_hash) => {
                        println!("Deposit finalized successfully!");
                        println!("Transaction hash: {tx_hash}");
                    }
                    None => {
                        println!("Deposit already finalized or threshold not yet reached.");
                    }
                }
            }
            "burn" => {
                println!(
                    "Burn retry not implemented - use `bridge unlock` to manually unlock with proof"
                );
            }
            other => {
                eyre::bail!("Unknown retry type: {other}. Use 'deposit' or 'burn'");
            }
        }

        Ok(())
    }
}
