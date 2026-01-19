use alloy::{
    primitives::{Address, B256, Bytes},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::{Context, Result};
use std::path::PathBuf;
use tempo_bridge_exex::{BridgeConfig, OriginClient};

#[derive(Parser, Debug)]
pub struct UnlockArgs {
    /// Burn ID to unlock
    #[arg(required = true)]
    burn_id: String,

    /// Path to proof file (JSON format)
    #[arg(long, required = true)]
    proof: PathBuf,

    /// Path to bridge config file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Origin chain name (must match config)
    #[arg(long, required = true)]
    chain: String,

    /// Path to private key file for signing
    #[arg(long)]
    key_path: Option<PathBuf>,

    /// Recipient address on origin chain
    #[arg(long)]
    recipient: Option<String>,

    /// Amount to unlock (in token base units)
    #[arg(long)]
    amount: Option<u64>,

    /// Dry run (don't submit transaction)
    #[arg(long)]
    dry_run: bool,
}

#[derive(serde::Deserialize)]
struct UnlockProof {
    recipient: Address,
    amount: u64,
    proof: String,
    origin_block_number: u64,
}

impl UnlockArgs {
    pub async fn run(self) -> Result<()> {
        let burn_id: B256 = self.burn_id.parse().context("Invalid burn ID format")?;

        let config = if let Some(config_path) = &self.config {
            BridgeConfig::load(config_path)?
        } else {
            BridgeConfig::default_test_config()
        };

        let chain_config = config
            .chains
            .get(&self.chain)
            .ok_or_else(|| eyre::eyre!("Chain '{}' not found in config", self.chain))?;

        // Read proof file
        let proof_contents =
            std::fs::read_to_string(&self.proof).context("Failed to read proof file")?;
        let proof_data: UnlockProof =
            serde_json::from_str(&proof_contents).context("Invalid proof format")?;

        let recipient = self
            .recipient
            .map(|r| r.parse())
            .transpose()
            .context("Invalid recipient address")?
            .unwrap_or(proof_data.recipient);

        let amount = self.amount.unwrap_or(proof_data.amount);
        let proof_bytes: Bytes = proof_data.proof.parse().context("Invalid proof hex")?;

        println!("Manual Unlock");
        println!("=============");
        println!();
        println!("Burn ID:     {burn_id}");
        println!("Chain:       {} ({})", self.chain, chain_config.chain_id);
        println!("Recipient:   {recipient}");
        println!("Amount:      {amount}");
        println!("Escrow:      {}", chain_config.escrow_address);
        println!();

        if self.dry_run {
            println!("Dry run mode - no transaction will be submitted");
            return Ok(());
        }

        let key_path = self
            .key_path
            .or(config.validator_key_path.as_ref().map(PathBuf::from))
            .ok_or_else(|| eyre::eyre!("No key path provided"))?;

        let key_hex = std::fs::read_to_string(&key_path)
            .context("Failed to read key file")?
            .trim()
            .to_string();
        let signer: PrivateKeySigner = key_hex.parse().context("Invalid private key")?;

        let light_client_address = chain_config.light_client_address.unwrap_or(Address::ZERO);

        let client = OriginClient::new(
            self.chain.clone(),
            chain_config.chain_id,
            &chain_config.rpc_url,
            signer,
            light_client_address,
            chain_config.escrow_address,
        )
        .await?;

        println!("Submitting unlock transaction...");

        let tx_hash = client
            .unlock_with_proof(
                burn_id,
                recipient,
                amount,
                proof_bytes,
                proof_data.origin_block_number,
            )
            .await?;

        if tx_hash.is_zero() {
            println!("Burn already unlocked.");
        } else {
            println!("Unlock successful!");
            println!("Transaction hash: {tx_hash}");
        }

        Ok(())
    }
}
