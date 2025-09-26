use alloy::{
    consensus::SignableTransaction,
    network::TxSignerSync,
    primitives::{Address, TxHash, TxKind, U128, U256, hex},
    providers::{Provider, ProviderBuilder},
    rpc::client::ClientBuilder,
    sol_types::SolCall,
    transports::http::reqwest::Url,
};
use alloy_consensus::TxLegacy;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use clap::Parser;
use eyre::WrapErr;
// use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use rayon::prelude::*;
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_precompiles::contracts::ITIP20;
use tokio::time::{Instant, interval, sleep};

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct TPSArgs {
    /// Target RPC URLs
    #[arg(short, long, default_value = "http://127.0.0.1:8545")]
    pub urls: Vec<Url>,

    /// Target transactions per second
    #[arg(long, default_value = "5000")]
    pub tps: u64,

    /// Duration to run benchmark in seconds
    #[arg(long, default_value = "30")]
    pub duration: u64,

    /// Number of accounts to generate
    #[arg(long, default_value = "1000")]
    pub accounts: u32,

    /// Mnemonic for account generation
    #[arg(
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,

    /// Contract address of token to be transferred
    #[arg(long, default_value = "0x2000000000000000000000000000000000000001")]
    pub token_address: Address,

    /// Chain ID
    #[arg(long, default_value = "1337")]
    pub chain_id: u64,

    /// Gas limit for each transaction
    #[arg(long, default_value = "100000000000")]
    pub gas_limit: u64,

    /// Number of concurrent connections
    #[arg(long, default_value = "100")]
    pub connections: usize,
}

impl TPSArgs {
    pub async fn run(self) -> eyre::Result<()> {
        let core_ids =
            core_affinity::get_core_ids().ok_or_else(|| eyre::eyre!("Failed to get core IDs"))?;
        println!("Detected {} cores for parallel processing", core_ids.len());

        rayon::ThreadPoolBuilder::new()
            .num_threads(core_ids.len())
            .build_global()?;

        let transactions = self.generate_transactions().await?;
        println!("[*] Pre-generated {} transactions", transactions.len());

        // // Send transactions at specified rate
        // self.send_transactions(transactions).await?;

        Ok(())
    }

    async fn generate_transactions(&self) -> eyre::Result<Vec<Vec<u8>>> {
        println!("Generating {} accounts...", self.accounts);
        let signers: Vec<PrivateKeySigner> = (0..self.accounts)
            .into_par_iter()
            .map(|i| {
                MnemonicBuilder::<English>::default()
                    .phrase(&self.mnemonic)
                    .index(i)
                    .unwrap()
                    .build()
                    .unwrap()
            })
            .collect();

        let provider = ProviderBuilder::new().connect_http(self.urls[0].clone());

        let mut nonces = Vec::with_capacity(signers.len());
        for signer in signers.iter() {
            let address = signer.address();
            let nonce = provider.get_transaction_count(address).await?;
            nonces.push(nonce);
        }
        let signers_with_nonces: Vec<_> = signers.into_iter().zip(nonces).collect();
        let num_txs = self.tps * self.duration;
        let txs_per_signer = num_txs / self.accounts as u64;

        println!(
            "[*] Generating {} transactions per signer...",
            txs_per_signer
        );

        // Generate transactions for each signer
        let mut transactions = Vec::with_capacity(num_txs as usize);

        for (signer, nonce) in signers_with_nonces.iter() {
            for tx_index in 0..txs_per_signer {
                let transfer_call = ITIP20::transferCall {
                    to: Address::random(),
                    amount: U256::ONE,
                }
                .abi_encode();

                let tx = TxLegacy {
                    chain_id: Some(self.chain_id),
                    nonce: *nonce + tx_index,
                    gas_price: TEMPO_BASE_FEE as u128,
                    gas_limit: self.gas_limit,
                    to: TxKind::Call(self.token_address),
                    value: U256::ZERO,
                    input: transfer_call.into(),
                };

                let encoded_tx = self.sign_and_encode_tx(signer, tx);
                transactions.push(encoded_tx);
            }
        }

        Ok(transactions)
    }

    fn sign_and_encode_tx(&self, signer: &PrivateKeySigner, mut tx: TxLegacy) -> Vec<u8> {
        let signature = signer.sign_transaction_sync(&mut tx).unwrap();
        let mut payload = Vec::new();
        tx.into_signed(signature).eip2718_encode(&mut payload);
        payload
    }
}
