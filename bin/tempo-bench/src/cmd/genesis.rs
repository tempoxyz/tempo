use alloy::{
    genesis::{ChainConfig, Genesis, GenesisAccount},
    primitives::{Address, Bytes, U256, address},
    signers::{local::MnemonicBuilder, utils::secret_key_to_address},
};
use alloy_signer_local::coins_bip39::English;
use clap::Parser;
use rayon::prelude::*;
use simple_tqdm::ParTqdm;
use std::{collections::BTreeMap, fs, path::PathBuf};

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
        println!("Generating {:?} accounts...", self.accounts);

        let alloc: BTreeMap<Address, GenesisAccount> = (0..self.accounts)
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

        let chain_config = ChainConfig {
            chain_id: self.chain_id,
            homestead_block: Some(0),
            eip150_block: Some(0),
            eip155_block: Some(0),
            eip158_block: Some(0),
            byzantium_block: Some(0),
            constantinople_block: Some(0),
            petersburg_block: Some(0),
            istanbul_block: Some(0),
            berlin_block: Some(0),
            london_block: Some(0),
            merge_netsplit_block: Some(0),
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            terminal_total_difficulty: Some(U256::from(0)),
            terminal_total_difficulty_passed: true,
            deposit_contract_address: Some(address!("0x00000000219ab540356cBB839Cbe05303d7705Fa")),
            ..Default::default()
        };

        let mut genesis = Genesis::default()
            .with_gas_limit(0xfffffffffff)
            .with_nonce(0x42)
            .with_extra_data(Bytes::from_static(b"tempo-genesis"))
            .with_coinbase(Address::ZERO);

        genesis.alloc = alloc;
        genesis.config = chain_config;

        let json = serde_json::to_string_pretty(&genesis)?;
        fs::write(self.output, json)?;

        Ok(())
    }
}
