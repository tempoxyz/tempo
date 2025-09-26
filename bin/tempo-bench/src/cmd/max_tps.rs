use alloy::{
    network::TxSignerSync,
    primitives::{Address, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::SolCall,
    transports::http::reqwest::Url,
};
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_signer_local::{LocalSigner, MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use clap::Parser;
use core_affinity::CoreId;
use governor::{Quota, RateLimiter};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rlimit::Resource;
use simple_tqdm::ParTqdm;
use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;

sol! {
    interface ERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct MaxTPSArgs {
    /// Target transactions per second
    #[arg(short, long)]
    pub tps: u64,

    /// Test duration in seconds
    #[arg(short, long, default_value = "30")]
    pub duration: u64,

    /// Number of accounts for pre-generation
    #[arg(short, long, default_value = "100")]
    pub accounts: u64,

    /// Number of workers to send transactions
    #[arg(short, long, default_value = "10")]
    pub workers: usize,

    /// Mnemonic for generating accounts
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    pub mnemonic: String,

    /// Chain ID
    #[arg(long, default_value = "1337")]
    pub chain_id: u64,

    /// Token address
    #[arg(long, default_value = "0x20c0000000000000000000000000000000000000")]
    pub token_address: Address,

    /// Target URLs for network connections
    #[arg(long, default_values_t = vec!["http://localhost:8545".to_string()])]
    pub target_urls: Vec<String>,

    /// Total network connections
    #[arg(long, default_value = "100")]
    pub total_connections: u64,

    #[arg(long)]
    pub disable_thread_pinning: bool,

    /// File descriptor limit to set
    #[arg(long)]
    pub fd_limit: Option<u64>,
}

impl MaxTPSArgs {
    pub async fn run(self) -> eyre::Result<()> {
        // Set file descriptor limit if provided
        if let Some(fd_limit) = self.fd_limit {
            increase_nofile_limit(fd_limit)?;
        }

        let target_urls = self
            .target_urls
            .iter()
            .map(|url| url.as_str().parse().expect("Could not parse Url"))
            .collect();

        // TODO: check that contract is deployed

        // Generate all transactions
        let total_txs = self.tps * self.duration;
        let transactions = Arc::new(generate_transactions(
            total_txs,
            self.accounts,
            &self.mnemonic,
            self.chain_id,
            self.token_address,
        ));

        // Create shared transaction counter and monitoring
        let tx_counter = Arc::new(AtomicU64::new(0));

        // Spawn monitoring thread for TPS tracking
        let _monitor_handle = monitor_tps(tx_counter.clone());

        // Spawn workers and send transactions
        send_transactions(
            transactions,
            self.workers,
            self.total_connections,
            target_urls,
            self.tps,
            self.disable_thread_pinning,
            tx_counter,
        )?;

        // Wait for all sender threads to finish
        std::thread::sleep(Duration::from_secs(self.duration + 5));
        println!("Finished sending transactions");

        Ok(())
    }
}

fn send_transactions(
    transactions: Arc<Vec<Vec<u8>>>,
    num_workers: usize,
    num_connections: u64,
    target_urls: Vec<Url>,
    tps: u64,
    disable_thread_pinning: bool,
    tx_counter: Arc<AtomicU64>,
) -> eyre::Result<()> {
    // Get available cores
    let core_ids =
        core_affinity::get_core_ids().ok_or_else(|| eyre::eyre!("Failed to get core IDs"))?;
    println!("Detected {} effective cores.", core_ids.len());

    let num_sender_threads = num_workers.min(core_ids.len());
    let chunk_size = transactions.len().div_ceil(num_sender_threads);

    // Create a shared rate limiter for all threads
    let rate_limiter = Arc::new(RateLimiter::direct(Quota::per_second(
        NonZeroU32::new(tps as u32).unwrap(),
    )));

    for thread_id in 0..num_sender_threads {
        if !disable_thread_pinning {
            let core_id = core_ids[thread_id % core_ids.len()];
            pin_thread(core_id);
        }

        // Segment transactions
        let rate_limiter = rate_limiter.clone();
        let transactions = transactions.clone();
        let target_urls = target_urls.to_vec();
        let tx_counter = tx_counter.clone();
        let start = thread_id * chunk_size;
        let end = (start + chunk_size).min(transactions.len());

        // Spawn thread and send transactions over specifed duration
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");

            rt.block_on(async {
                // Create multiple connections for this thread
                let mut providers = Vec::new();
                for i in 0..num_connections {
                    let url = &target_urls[(i as usize) % target_urls.len()];
                    let provider = ProviderBuilder::new().connect_http(url.clone());
                    providers.push(provider);
                }

                let mut batch_count = 0;
                for (i, tx_bytes) in transactions[start..end].iter().enumerate() {
                    rate_limiter.until_ready().await;
                    let provider = &providers[i % providers.len()];
                    if let Err(e) = provider.send_raw_transaction(tx_bytes).await {
                        eprintln!("Failed to send transaction: {}", e);
                    }

                    batch_count += 1;
                    if batch_count >= 1000 {
                        tx_counter.fetch_add(batch_count, Ordering::Relaxed);
                        batch_count = 0;
                    }
                }
            });
        });
    }

    Ok(())
}

fn generate_transactions(
    total_txs: u64,
    num_accounts: u64,
    mnemonic: &str,
    chain_id: u64,
    token_address: Address,
) -> Vec<Vec<u8>> {
    println!("Generating {num_accounts} accounts...");
    let signers: Vec<PrivateKeySigner> = (0..num_accounts as u32)
        .into_par_iter()
        .tqdm()
        .map(|i| {
            MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(i)
                .unwrap()
                .build()
                .unwrap()
        })
        .collect();

    // TODO: fund all accounts
    println!("Generating {total_txs} txs...");

    let txs_per_sender = total_txs / num_accounts;
    let params: Vec<(LocalSigner<_>, u64)> = signers
        .into_iter()
        .flat_map(|signer| (0..txs_per_sender).map(move |nonce| (signer.clone(), nonce)))
        .collect();

    let transactions: Vec<Vec<u8>> = params
        .into_par_iter()
        .tqdm()
        .map(|(signer, nonce)| {
            let mut tx = TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: TEMPO_BASE_FEE as u128,
                gas_limit: 300000,
                to: TxKind::Call(token_address),
                value: U256::ZERO,
                input: ERC20::transferCall {
                    to: Address::random(),
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
            };

            let signature = signer.sign_transaction_sync(&mut tx).unwrap();
            let mut payload = Vec::new();
            tx.into_signed(signature).eip2718_encode(&mut payload);
            payload
        })
        .collect();

    println!("Generated {} transactions", transactions.len());
    transactions
}

pub fn increase_nofile_limit(min_limit: u64) -> eyre::Result<u64> {
    let (soft, hard) = Resource::NOFILE.get()?;
    println!("[*] At startup, file descriptor limit:      soft = {soft}, hard = {hard}");

    if hard < min_limit {
        panic!(
            "[!] File descriptor hard limit is too low. Please increase it to at least {min_limit}."
        );
    }

    if soft != hard {
        Resource::NOFILE.set(hard, hard)?; // Just max things out to give us plenty of overhead.
        let (soft, hard) = Resource::NOFILE.get()?;
        println!("[+] After increasing file descriptor limit: soft = {soft}, hard = {hard}");
    }

    Ok(soft)
}

/// Pin the current thread to the given core ID if enabled.
/// Panics if the thread fails to pin.
pub fn pin_thread(core_id: CoreId) {
    if !core_affinity::set_for_current(core_id) {
        panic!(
            "[!] Failed to pin thread to core {}. Try disabling thread_pinning in your config.",
            core_id.id
        );
    }
}

fn monitor_tps(tx_counter: Arc<AtomicU64>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_count = 0u64;
        loop {
            let current_count = tx_counter.load(Ordering::Relaxed);
            let tps = current_count - last_count;
            last_count = current_count;

            println!("TPS Sent: {tps}, Total Txs Sent: {current_count}");
            thread::sleep(Duration::from_secs(1));
        }
    })
}
