use alloy::{
    genesis::GenesisAccount,
    primitives::{Address, U256},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_signer_local::coins_bip39::English;
use clap::Parser;
use rayon::prelude::*;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use serde::{Deserialize, Serialize};
use simple_tqdm::ParTqdm;
use std::{collections::BTreeMap, fs, path::PathBuf};

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
    #[arg(short, long)]
    pub output: PathBuf,

    /// Mnemonic to use for account generation
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,

    /// Balance for each account (in hex)
    #[arg(short, long, default_value = "0xD3C21BCECCEDA1000000")]
    pub balance: String,

    /// Chain ID for the genesis block
    #[arg(short = 'c', long, default_value = "1337")]
    pub chain_id: u64,
}

impl GenesisArgs {
    pub async fn run(self) -> eyre::Result<()> {
        let chain_spec = ChainSpecBuilder::mainnet()
            .chain(Chain::from(self.chain_id))
            .homestead_activated()
            .constantinople_activated()
            .byzantium_activated()
            .petersburg_activated()
            .istanbul_activated()
            .berlin_activated()
            .london_activated()
            .shanghai_activated()
            .cancun_activated()
            .prague_activated()
            .build();

        generate_genesis_alloc(
            self.accounts,
            &self.output,
            &self.mnemonic,
            &self.balance,
            &chain_spec,
        )
        .map_err(|e| eyre::eyre!("Failed to generate genesis alloc: {}", e))
    }
}

fn generate_genesis_alloc(
    num_accounts: u32,
    output_path: &PathBuf,
    mnemonic: &str,
    balance: &str,
    chain_spec: &ChainSpec,
) -> eyre::Result<()> {
    println!("Generating {num_accounts} accounts...");

    let accounts: BTreeMap<Address, GenesisAccount> = (0..num_accounts)
        .into_par_iter()
        .tqdm()
        .map(|worker_id| -> eyre::Result<(Address, GenesisAccount)> {
            let signer = MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(worker_id)
                .map_err(|e| eyre::eyre!("Failed to build signer: {}", e))?
                .build()
                .map_err(|e| eyre::eyre!("Failed to build signer: {}", e))?;

            let address = secret_key_to_address(signer.credential());
            let balance_u256 = U256::from_str_radix(&balance[2..], 16)
                .map_err(|e| eyre::eyre!("Invalid balance format: {}", e))?;

            Ok((
                address,
                GenesisAccount {
                    balance: balance_u256,
                    ..Default::default()
                },
            ))
        })
        .collect::<eyre::Result<BTreeMap<Address, GenesisAccount>>>()?;

    let mut genesis = chain_spec.genesis.clone();
    genesis.alloc = accounts;

    let json = serde_json::to_string_pretty(&genesis)?;
    fs::write(output_path, json)?;

    Ok(())
}
