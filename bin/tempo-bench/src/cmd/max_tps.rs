mod dex;
mod tip20;

use tempo_alloy::TempoNetwork;

use alloy::{
    consensus::BlockHeader,
    eips::{BlockNumberOrTag::Latest, Decodable2718},
    network::ReceiptResponse,
    primitives::{Address, BlockNumber, U256},
    providers::{PendingTransactionBuilder, Provider, ProviderBuilder},
    sol_types::SolEvent,
    transports::http::reqwest::Url,
};
use alloy_consensus::{EthereumTxEnvelope, TxEip4844};
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use clap::Parser;
use core_affinity::CoreId;
use eyre::{Context, OptionExt, ensure};
use futures::{StreamExt, TryStreamExt, future::BoxFuture, stream};
use governor::{Quota, RateLimiter};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressIterator};
use rand::{random, seq::IndexedRandom};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rlimit::Resource;
use serde::Serialize;
use std::{
    fs::File,
    io::BufWriter,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tempo_chainspec::spec::TEMPO_BASE_FEE;
use tempo_contracts::precompiles::{
    IRolesAuth, IStablecoinExchange::IStablecoinExchangeInstance, ITIP20, ITIP20::ITIP20Instance,
    ITIP20Factory, STABLECOIN_EXCHANGE_ADDRESS, TIP20_FACTORY_ADDRESS,
};
use tempo_precompiles::{
    stablecoin_exchange::MIN_ORDER_AMOUNT,
    tip20::{ISSUER_ROLE, token_id_to_address},
};
use tokio::time::timeout;

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct MaxTpsArgs {
    /// Target transactions per second
    #[arg(short, long)]
    tps: u64,

    /// Test duration in seconds
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Number of accounts for pre-generation
    #[arg(short, long, default_value = "100")]
    accounts: u64,

    /// Number of workers to send transactions
    #[arg(short, long, default_value = "10")]
    workers: usize,

    /// Mnemonic for generating accounts
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    #[arg(short, long, default_value = "0")]
    from_mnemonic_index: u32,

    /// Token address used when creating TIP20 transfer calldata
    #[arg(long, default_value = "0x20c0000000000000000000000000000000000000")]
    token_address: Address,

    /// Target URLs for network connections
    #[arg(long, default_values_t = vec!["http://localhost:8545".to_string()])]
    target_urls: Vec<String>,

    /// Total network connections
    /// A limit of the maximum amount of concurrent requests, prevents issues with too many
    /// connections open at once.
    #[arg(long, default_value = "100")]
    total_connections: u64,

    /// Disable binding worker threads to specific CPU cores, letting the OS scheduler handle placement.
    #[arg(long)]
    disable_thread_pinning: bool,

    /// File descriptor limit to set
    #[arg(long)]
    fd_limit: Option<u64>,

    /// Node commit SHA for metadata
    #[arg(long)]
    node_commit_sha: Option<String>,

    /// Build profile for metadata (e.g., "release", "debug", "maxperf")
    #[arg(long)]
    build_profile: Option<String>,

    /// Benchmark mode for metadata (e.g., "max_tps", "stress_test")
    #[arg(long)]
    benchmark_mode: Option<String>,

    /// A number of transaction to send, before waiting for their receipts, that should be likely
    /// safe.
    ///
    /// Large amount of transactions in a block will result in system transaction OutOfGas error.
    /// Large amount of transactions sent very quickly can overflow the txpool.
    #[arg(long, default_value = "10000")]
    max_concurrent_transactions: usize,

    /// A weight that determines the likelihood of generating a TIP-20 transfer transaction.
    #[arg(long, default_value = "0.8")]
    tip20_weight: f64,

    /// A weight that determines the likelihood of generating a DEX place transaction.
    #[arg(long, default_value = "0.01")]
    place_order_weight: f64,

    /// A weight that determines the likelihood of generating a DEX swapExactAmountIn transaction.
    #[arg(long, default_value = "0.19")]
    swap_weight: f64,

    /// An amount of receipts to wait for after sending all the transactions.
    #[arg(long, default_value = "100")]
    sample_size: usize,
}

impl MaxTpsArgs {
    const WEIGHT_PRECISION: f64 = 1000.0;

    pub async fn run(self) -> eyre::Result<()> {
        // Set file descriptor limit if provided
        if let Some(fd_limit) = self.fd_limit {
            increase_nofile_limit(fd_limit).context("Failed to increase nofile limit")?;
        }

        let tip20_weight = (self.tip20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let place_order_weight = (self.place_order_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let swap_weight = (self.swap_weight * Self::WEIGHT_PRECISION).trunc() as u64;

        let target_urls: Vec<Url> = self
            .target_urls
            .iter()
            .map(|s| {
                s.parse::<Url>()
                    .wrap_err_with(|| format!("failed to parse `{s}` as URL"))
            })
            .collect::<eyre::Result<Vec<_>>>()
            .wrap_err("failed parsing input target URLs")?;

        // Generate all transactions
        let total_txs = self.tps * self.duration;
        let transactions = Arc::new(
            generate_transactions(GenerateTransactionsInput {
                total_txs,
                num_accounts: self.accounts,
                mnemonic: &self.mnemonic,
                rpc_url: target_urls[0].clone(),
                from_mnemonic_index: self.from_mnemonic_index,
                max_concurrent_requests: self.total_connections as usize,
                max_concurrent_transactions: self.max_concurrent_transactions,
                tip20_weight,
                place_order_weight,
                swap_weight,
            })
            .await
            .context("Failed to generate transactions")?,
        );

        // Get first block height before sending transactions
        let provider = ProviderBuilder::new().connect_http(target_urls[0].clone());
        let start_block = provider
            .get_block(Latest.into())
            .await?
            .ok_or_eyre("failed to fetch start block")?;
        let start_block_number = start_block.header.number;

        // Create shared transaction counter and monitoring
        let tx_counter = Arc::new(AtomicU64::new(0));

        // Spawn monitoring thread for TPS tracking
        let _monitor_handle = monitor_tps(tx_counter.clone(), total_txs);

        // Spawn workers and send transactions
        send_transactions(
            transactions.clone(),
            self.workers,
            self.total_connections,
            target_urls.clone(),
            self.tps,
            self.disable_thread_pinning,
            tx_counter,
        )
        .context("Failed to send transactions")?;

        // Graceful period of 1 second for `monitor_tps` to print out last statement
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut rng = rand::rng();
        let sample_size = transactions.len().min(self.sample_size);
        let mut end_block_number = start_block_number;
        println!("Collecting a sample of {sample_size} receipts");
        let progress = ProgressBar::new(sample_size as u64);
        progress.tick();

        for transaction in transactions.choose_multiple(&mut rng, sample_size) {
            let tx = EthereumTxEnvelope::<TxEip4844>::decode_2718_exact(transaction.as_slice())
                .expect("should be serialized as EIP-2718");
            let tx_hash = *tx.hash();
            let receipt = PendingTransactionBuilder::new(provider.root().clone(), tx_hash)
                .get_receipt()
                .await?;
            progress.inc(1);

            if let Some(block_number) = receipt.block_number
                && block_number > end_block_number
            {
                end_block_number = block_number;
            }
        }
        progress.force_draw();

        generate_report(
            &target_urls[0].clone(),
            start_block_number,
            end_block_number,
            &self,
        )
        .await?;

        Ok(())
    }
}

fn send_transactions(
    transactions: Arc<Vec<Vec<u8>>>,
    num_workers: usize,
    _num_connections: u64,
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

    let handles: Vec<_> = (0..num_sender_threads)
        .map(|thread_id| {
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

            // Spawn thread and send transactions over specified duration
            thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to build tokio runtime");

                rt.block_on(async {
                    // TODO: Send txs from multiple senders
                    // Create multiple connections for this thread
                    // let mut providers = Vec::new();
                    // for i in 0..num_connections {
                    //     println!("{i:?}");
                    //     let url = &target_urls[(i as usize) % target_urls.len()];
                    //     let provider = ProviderBuilder::new().connect_http(url.clone());
                    //     providers.push(provider);
                    // }

                    let provider = ProviderBuilder::new().connect_http(target_urls[0].clone());
                    for tx_bytes in transactions[start..end].iter() {
                        rate_limiter.until_ready().await;

                        match timeout(
                            Duration::from_secs(1),
                            provider.send_raw_transaction(tx_bytes),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                tx_counter.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(Err(e)) => eprintln!("Failed to send transaction: {e}"),
                            Err(_) => eprintln!("Tx send timed out"),
                        }
                    }
                });
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

async fn generate_transactions(input: GenerateTransactionsInput<'_>) -> eyre::Result<Vec<Vec<u8>>> {
    let GenerateTransactionsInput {
        total_txs,
        num_accounts,
        mnemonic,
        from_mnemonic_index,
        rpc_url,
        max_concurrent_requests,
        max_concurrent_transactions,
        tip20_weight,
        place_order_weight,
        swap_weight,
    } = input;
    println!("Generating {num_accounts} accounts...");

    let signers: Vec<PrivateKeySigner> = (from_mnemonic_index
        ..(from_mnemonic_index + num_accounts as u32))
        .into_par_iter()
        .progress()
        .map(|i| -> eyre::Result<PrivateKeySigner> {
            let signer = MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(i)?
                .build()?;
            Ok(signer)
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    let txs_per_sender = total_txs / num_accounts;
    ensure!(
        txs_per_sender > 0,
        "txs per sender is 0, increase tps or decrease senders"
    );

    let (exchange, quote, user_tokens) = dex::setup(
        rpc_url.clone(),
        mnemonic,
        signers.clone(),
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    let accounts = signers.len();
    // Fetch current nonces for all accounts
    let provider = ProviderBuilder::new().connect_http(rpc_url);

    println!("Fetching nonces for {accounts} accounts...");

    let mut futures = Vec::new();
    let mut params = Vec::new();
    for signer in signers {
        let address = signer.address();
        let current_nonce = provider.get_transaction_count(address);
        futures.push(async move { (signer, current_nonce.await) });
    }

    let mut iter = stream::iter(futures).buffer_unordered(max_concurrent_requests);
    while let Some((signer, nonce)) = iter.next().await {
        let nonce = nonce.context("Failed to get transaction count")?;
        for i in 0..txs_per_sender {
            params.push((signer.clone(), nonce + i));
        }
    }

    let user_tokens_count = user_tokens.len();

    println!(
        "Pregenerating {} transactions",
        txs_per_sender as usize * accounts,
    );

    let transfers = Arc::new(AtomicUsize::new(0));
    let swaps = Arc::new(AtomicUsize::new(0));
    let orders = Arc::new(AtomicUsize::new(0));
    let transactions: Vec<_> = stream::iter(params.into_iter().progress())
        .then(async |(signer, nonce)| {
            #[expect(clippy::type_complexity)]
            let tx_factories: [(Box<dyn Fn() -> BoxFuture<'static, _>>, u64); 3] = [
                (
                    Box::new(|| {
                        transfers.fetch_add(1, Ordering::Relaxed);
                        Box::pin(tip20::transfer(
                            signer.clone(),
                            nonce,
                            user_tokens[random::<u16>() as usize % user_tokens_count].clone(),
                        ))
                    }),
                    tip20_weight,
                ),
                (
                    Box::new(|| {
                        swaps.fetch_add(1, Ordering::Relaxed);
                        Box::pin(dex::swap_in(
                            exchange.clone(),
                            signer.clone(),
                            nonce,
                            *user_tokens[random::<u16>() as usize % user_tokens_count].address(),
                            quote,
                        ))
                    }),
                    swap_weight,
                ),
                (
                    Box::new(|| {
                        orders.fetch_add(1, Ordering::Relaxed);
                        Box::pin(dex::place(
                            exchange.clone(),
                            signer.clone(),
                            nonce,
                            *user_tokens[random::<u16>() as usize % user_tokens_count].address(),
                        ))
                    }),
                    place_order_weight,
                ),
            ];
            let mut rng = rand::rng();
            let tx = tx_factories
                .choose_weighted(&mut rng, |item| item.1)
                .map(|item| &item.0)?;
            tx().await
        })
        .try_collect::<Vec<_>>()
        .await?;

    println!(
        "Generated {} transactions [{} transfers, {} swaps, {} orders]",
        transactions.len(),
        transfers.load(Ordering::Relaxed),
        swaps.load(Ordering::Relaxed),
        orders.load(Ordering::Relaxed)
    );

    Ok(transactions)
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

#[derive(Serialize)]
struct BenchmarkedBlock {
    number: BlockNumber,
    tx_count: usize,
    ok_count: usize,
    err_count: usize,
    gas_used: u64,
    timestamp: u64,
    latency_ms: Option<u64>,
}

#[derive(Serialize)]
struct BenchmarkMetadata {
    target_tps: u64,
    run_duration_secs: u64,
    num_accounts: u64,
    num_workers: usize,
    chain_id: u64,
    total_connections: u64,
    start_block: BlockNumber,
    end_block: BlockNumber,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    tip20_weight: f64,
    place_order_weight: f64,
    swap_weight: f64,
}

#[derive(Serialize)]
struct BenchmarkReport {
    metadata: BenchmarkMetadata,
    blocks: Vec<BenchmarkedBlock>,
}

pub async fn generate_report(
    rpc_url: &Url,
    start_block: BlockNumber,
    end_block: BlockNumber,
    args: &MaxTpsArgs,
) -> eyre::Result<()> {
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.clone());

    let mut last_block_timestamp: Option<u64> = None;

    let mut benchmarked_blocks = Vec::new();

    for number in start_block..=end_block {
        let block = provider
            .get_block(number.into())
            .await?
            .expect("we should always have this block number");
        let receipts = provider
            .get_block_receipts(number.into())
            .await?
            .expect("there should always be at least one receipt");
        let timestamp = block.header.timestamp_millis();

        let latency_ms = last_block_timestamp.map(|last| timestamp - last);
        let (ok_count, err_count) =
            receipts
                .iter()
                .fold((0, 0), |(successes, failures), receipt| {
                    if receipt.status() {
                        (successes + 1, failures)
                    } else {
                        (successes, failures + 1)
                    }
                });

        benchmarked_blocks.push(BenchmarkedBlock {
            number,
            tx_count: receipts.len(),
            ok_count,
            err_count,
            gas_used: block.header.gas_used(),
            timestamp: block.header.timestamp_millis(),
            latency_ms,
        });

        last_block_timestamp = Some(timestamp);
    }

    let metadata = BenchmarkMetadata {
        target_tps: args.tps,
        run_duration_secs: args.duration,
        num_accounts: args.accounts,
        num_workers: args.workers,
        chain_id: provider.get_chain_id().await?,
        total_connections: args.total_connections,
        start_block,
        end_block,
        node_commit_sha: args.node_commit_sha.clone(),
        build_profile: args.build_profile.clone(),
        mode: args.benchmark_mode.clone(),
        tip20_weight: args.tip20_weight,
        place_order_weight: args.place_order_weight,
        swap_weight: args.swap_weight,
    };

    let report = BenchmarkReport {
        metadata,
        blocks: benchmarked_blocks,
    };

    let file = File::create("report.json")?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &report)?;

    println!("Report written to report.json");

    Ok(())
}

fn monitor_tps(tx_counter: Arc<AtomicU64>, target_count: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_count = 0u64;
        loop {
            let current_count = tx_counter.load(Ordering::Relaxed);
            let tps = current_count - last_count;
            last_count = current_count;

            println!("TPS Sent: {tps}, Total Txs Sent: {current_count}");
            thread::sleep(Duration::from_secs(1));

            if current_count == target_count {
                break;
            }
        }
    })
}

async fn join_all<
    T: Future<Output = alloy::contract::Result<PendingTransactionBuilder<TempoNetwork>>>,
>(
    futures: impl IntoIterator<Item = T>,
    tx_count: &ProgressBar,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<()> {
    let mut buf: Vec<Vec<T>> = Vec::new();

    for future in futures {
        match buf.last_mut() {
            Some(buf) if buf.len() < max_concurrent_transactions => buf.push(future),
            _ => buf.push(vec![future]),
        }
    }

    for buf in buf {
        let mut receipts = Vec::new();
        let mut iter = stream::iter(buf)
            .map(|receipt| async { eyre::Ok(receipt.await?) })
            .buffer_unordered(max_concurrent_requests);
        while let Some(receipt) = iter.next().await {
            tx_count.inc(1);
            receipts.push(receipt);
        }
        let mut iter = stream::iter(
            receipts
                .into_iter()
                .map(|receipt| async { eyre::Ok(receipt?.get_receipt().await?) }),
        )
        .buffer_unordered(max_concurrent_requests);
        while let Some(receipt) = iter.next().await {
            assert!(receipt?.status());
        }
    }

    Ok(())
}

struct GenerateTransactionsInput<'input> {
    total_txs: u64,
    num_accounts: u64,
    mnemonic: &'input str,
    rpc_url: Url,
    from_mnemonic_index: u32,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
    tip20_weight: u64,
    place_order_weight: u64,
    swap_weight: u64,
}
