use std::{collections::BTreeMap, fs, path::PathBuf};
use clap::Parser;
use alloy::signers::{local::MnemonicBuilder, utils::secret_key_to_address};
use alloy_signer_local::coins_bip39::English;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use simple_tqdm::ParTqdm;

#[derive(Debug, Serialize, Deserialize)]
struct AccountBalance {
    balance: String,
}

/// Generate genesis allocation file for testing
#[derive(Parser, Debug)]
pub struct GenesisArgs {
    /// Number of accounts to generate
    #[arg(short, long, default_value = "50000")]
    pub accounts: u32,
    
    /// Output file path
    #[arg(short, long, default_value = "genesis.json")]
    pub output: PathBuf,
    
    /// Mnemonic to use for account generation
    #[arg(short, long, default_value = "test test test test test test test test test test test junk")]
    pub mnemonic: String,
    
    /// Balance for each account (in hex)
    #[arg(short, long, default_value = "0xD3C21BCECCEDA1000000")]
    pub balance: String,
}

impl GenesisArgs {
    pub async fn run(self) -> eyre::Result<()> {
        generate_genesis_alloc(self.accounts, &self.output, &self.mnemonic, &self.balance)
            .map_err(|e| eyre::eyre!("Failed to generate genesis alloc: {}", e))
    }
}

fn generate_genesis_alloc(
    num_accounts: u32, 
    output_path: &PathBuf, 
    mnemonic: &str, 
    balance: &str
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating {num_accounts} accounts...");

    let genesis_alloc: BTreeMap<String, AccountBalance> = (0..num_accounts)
        .into_par_iter()
        .tqdm()
        .map(|worker_id| {
            let signer = MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(worker_id)
                .unwrap()
                .build()
                .unwrap();

            let address = secret_key_to_address(signer.credential());

            (
                format!("{address:?}"),
                AccountBalance {
                    balance: balance.to_string(),
                },
            )
        })
        .collect();

    let json = serde_json::to_string_pretty(&genesis_alloc)?;
    fs::write(output_path, json)?;

    println!("\nSuccessfully generated {num_accounts} accounts!");
    println!("Accounts saved to: {}", output_path.display());

    Ok(())
}
