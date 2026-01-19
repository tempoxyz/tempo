use alloy::providers::{Provider, ProviderBuilder};
use clap::Parser;
use eyre::Result;
use std::path::PathBuf;
use tempo_bridge_exex::{BridgeConfig, StateManager};

#[derive(Parser, Debug)]
pub struct StatusArgs {
    /// Path to bridge config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Path to bridge state file
    #[arg(short, long, default_value = "bridge-state.json")]
    state: PathBuf,

    /// Tempo RPC URL (overrides config)
    #[arg(long)]
    tempo_rpc: Option<String>,
}

impl StatusArgs {
    pub async fn run(self) -> Result<()> {
        let config = if let Some(config_path) = &self.config {
            BridgeConfig::load(config_path)?
        } else {
            BridgeConfig::default_test_config()
        };

        let tempo_rpc = self
            .tempo_rpc
            .or(config.tempo_rpc_url.clone())
            .unwrap_or_else(|| "http://localhost:8551".to_string());

        println!("Bridge Status");
        println!("=============");
        println!();

        // Load persisted state if available
        if self.state.exists() {
            let state_manager = StateManager::new_persistent(&self.state)?;
            let stats = state_manager.get_stats().await;

            println!("Local State:");
            println!("  Signed deposits:    {}", stats.signed_deposits);
            println!("  Finalized deposits: {}", stats.finalized_deposits);
            println!("  Processed burns:    {}", stats.processed_burns);
            println!("  Last Tempo block:   {}", stats.last_tempo_block);
            println!();
        } else {
            println!("Local State: No state file found at {:?}", self.state);
            println!();
        }

        // Get on-chain status
        println!("On-Chain Status:");
        match ProviderBuilder::new().connect(&tempo_rpc).await {
            Ok(provider) => {
                let block = provider.get_block_number().await?;
                println!("  Tempo chain block:  {block}");
                println!("  RPC URL:            {tempo_rpc}");
            }
            Err(e) => {
                println!("  Error connecting to Tempo RPC: {e}");
            }
        }

        println!();
        println!("Origin Chains:");
        for (name, chain_config) in &config.chains {
            print!("  {name} (chain_id: {}): ", chain_config.chain_id);
            match ProviderBuilder::new().connect(&chain_config.rpc_url).await {
                Ok(provider) => match provider.get_block_number().await {
                    Ok(block) => println!("block {block}"),
                    Err(e) => println!("error: {e}"),
                },
                Err(e) => println!("connection error: {e}"),
            }
        }

        Ok(())
    }
}
