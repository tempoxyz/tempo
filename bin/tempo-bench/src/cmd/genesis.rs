use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, U256},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_signer_local::coins_bip39::English;
use clap::Parser;
use rayon::prelude::*;
use reth_chainspec::{Chain, ChainSpec, ChainSpecBuilder};
use serde::{Deserialize, Serialize};
use simple_tqdm::ParTqdm;
use std::{collections::BTreeMap, fs, path::PathBuf, u64};

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

    /// Balance for each account
    #[arg(short, long, default_value = "0xD3C21BCECCEDA1000000")]
    pub balance: U256,

    /// Chain ID
    #[arg(long, short, default_value = "1337")]
    pub chain_id: u64,
}

impl GenesisArgs {
    pub async fn run(self) -> eyre::Result<()> {
        let mut chain_spec = ChainSpecBuilder::mainnet()
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

        println!("Generating {:?} accounts...", self.accounts);

        let accounts: BTreeMap<Address, GenesisAccount> = (0..self.accounts)
            .into_par_iter()
            .tqdm()
            .map(|worker_id| -> eyre::Result<(Address, GenesisAccount)> {
                let signer = MnemonicBuilder::<English>::default()
                    .phrase(self.mnemonic.clone())
                    .index(worker_id)?
                    .build()?;
                let address = secret_key_to_address(signer.credential());

                Ok((
                    address,
                    GenesisAccount {
                        balance: self.balance,
                        ..Default::default()
                    },
                ))
            })
            .collect::<eyre::Result<BTreeMap<Address, GenesisAccount>>>()?;

        chain_spec.genesis.alloc = accounts;
        chain_spec.genesis.gas_limit = u64::MAX;

        let json = serde_json::to_string_pretty(&chain_spec.genesis)?;
        fs::write(self.output, json)?;

        Ok(())
    }
}
