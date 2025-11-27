mod dex;

use itertools::Itertools;
use reth_tracing::{
    RethTracer, Tracer,
    tracing::{error, info, warn},
};
use tempo_alloy::TempoNetwork;

use alloy::{
    consensus::BlockHeader,
    eips::BlockNumberOrTag::Latest,
    network::ReceiptResponse,
    primitives::{Address, B256, BlockNumber, U256},
    providers::{DynProvider, PendingTransactionBuilder, Provider, ProviderBuilder},
    transports::http::reqwest::Url,
};
use alloy_signer_local::{
    MnemonicBuilder, PrivateKeySigner,
    coins_bip39::{English, Mnemonic, MnemonicError},
};
use clap::Parser;
use eyre::{Context, OptionExt, ensure};
use futures::{StreamExt, TryStreamExt, future::BoxFuture, stream};
use governor::{Quota, RateLimiter, state::StreamRateLimitExt};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressIterator};
use rand::{
    random, random_range,
    seq::{IndexedRandom, SliceRandom},
};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rlimit::Resource;
use serde::Serialize;
use std::{
    fs::File,
    io::BufWriter,
    num::NonZeroU32,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tempo_contracts::precompiles::{
    IFeeManager::IFeeManagerInstance,
    IRolesAuth,
    IStablecoinExchange::IStablecoinExchangeInstance,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory, STABLECOIN_EXCHANGE_ADDRESS, TIP20_FACTORY_ADDRESS,
};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO, TIP_FEE_MANAGER_ADDRESS,
    stablecoin_exchange::{MAX_TICK, MIN_ORDER_AMOUNT, MIN_TICK},
    tip20::{ISSUER_ROLE, token_id_to_address},
};
use tokio::time::{sleep, timeout};

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct MaxTpsArgs {
    /// Target transactions per second
    #[arg(short, long)]
    tps: u64,

    /// Test duration in seconds
    #[arg(short, long, default_value_t = 30)]
    duration: u64,

    /// Number of accounts for pre-generation
    #[arg(short, long, default_value_t = 100)]
    accounts: u64,

    /// Mnemonic for generating accounts
    #[arg(short, long, default_value = "random")]
    mnemonic: MnemonicArg,

    #[arg(short, long, default_value_t = 0)]
    from_mnemonic_index: u32,

    #[arg(long, default_value_t = DEFAULT_FEE_TOKEN_PRE_ALLEGRETTO)]
    fee_token: Address,

    /// Target URLs for network connections
    #[arg(long, default_values_t = vec!["http://localhost:8545".parse::<Url>().unwrap()])]
    target_urls: Vec<Url>,

    /// A limit of the maximum number of concurrent requests, prevents issues with too many
    /// connections open at once.
    #[arg(long, default_value_t = 100)]
    max_concurrent_requests: usize,

    /// A number of transaction to send, before waiting for their receipts, that should be likely
    /// safe.
    ///
    /// Large amount of transactions in a block will result in system transaction OutOfGas error.
    #[arg(long, default_value_t = 10000)]
    max_concurrent_transactions: usize,

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

    /// A weight that determines the likelihood of generating a TIP-20 transfer transaction.
    #[arg(long, default_value_t = 0.8)]
    tip20_weight: f64,

    /// A weight that determines the likelihood of generating a DEX place transaction.
    #[arg(long, default_value_t = 0.01)]
    place_order_weight: f64,

    /// A weight that determines the likelihood of generating a DEX swapExactAmountIn transaction.
    #[arg(long, default_value_t = 0.19)]
    swap_weight: f64,

    /// An amount of receipts to wait for after sending all the transactions.
    #[arg(long, default_value_t = 100)]
    sample_size: usize,

    /// Fund accounts from the faucet before running the benchmark.
    ///
    /// Calls tempo_fundAddress for each account.
    #[arg(long)]
    faucet: bool,
}

impl MaxTpsArgs {
    const WEIGHT_PRECISION: f64 = 1000.0;

    pub async fn run(self) -> eyre::Result<()> {
        RethTracer::new().init()?;

        // Set file descriptor limit if provided
        if let Some(fd_limit) = self.fd_limit {
            increase_nofile_limit(fd_limit).context("Failed to increase nofile limit")?;
        }

        let target_url = self.target_urls[0].clone();
        if self.target_urls.len() > 1 {
            warn!("Multiple target URLs provided, but only the first one will be used")
        }

        let tip20_weight = (self.tip20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let place_order_weight = (self.place_order_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let swap_weight = (self.swap_weight * Self::WEIGHT_PRECISION).trunc() as u64;

        info!(accounts = self.accounts, "Creating signers and providers");
        let mnemonic = self.mnemonic.resolve();
        let signer_providers = (self.from_mnemonic_index
            ..(self.from_mnemonic_index + self.accounts as u32))
            .into_par_iter()
            .progress()
            .map(|i| {
                let signer = MnemonicBuilder::<English>::from_phrase_nth(&mnemonic, i);
                let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                    .wallet(signer.clone())
                    .with_cached_nonce_management()
                    .connect_http(target_url.clone())
                    .erased();
                Ok((signer, provider))
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        // Fund accounts from faucet if requested
        if self.faucet {
            let provider = ProviderBuilder::new().connect_http(target_url.clone());
            fund_accounts(
                &provider,
                &signer_providers
                    .iter()
                    .map(|(signer, _)| signer.address())
                    .collect::<Vec<_>>(),
                self.max_concurrent_requests,
                self.max_concurrent_transactions,
            )
            .await
            .context("Failed to fund accounts from faucet")?;
        }

        info!(fee_token = %self.fee_token, "Setting default fee token");
        join_all(
            signer_providers
                .iter()
                .map(async |(_, provider)| {
                    IFeeManagerInstance::new(TIP_FEE_MANAGER_ADDRESS, provider.clone())
                        .setUserToken(self.fee_token)
                        .send()
                        .await
                })
                .progress(),
            self.max_concurrent_requests,
            self.max_concurrent_transactions,
        )
        .await
        .context("Failed to set default fee token")?;

        // Generate all transactions
        let total_txs = self.tps * self.duration;
        let transactions = generate_transactions(GenerateTransactionsInput {
            total_txs,
            num_accounts: self.accounts,
            signer_providers,
            max_concurrent_requests: self.max_concurrent_requests,
            max_concurrent_transactions: self.max_concurrent_transactions,
            tip20_weight,
            place_order_weight,
            swap_weight,
        })
        .await
        .context("Failed to generate transactions")?;

        // Get first block height before sending transactions
        let provider = ProviderBuilder::new().connect_http(target_url.clone());
        let start_block = provider
            .get_block(Latest.into())
            .await?
            .ok_or_eyre("failed to fetch start block")?;
        let start_block_number = start_block.header.number;

        // Create shared transaction counter and monitoring
        let tx_counter = Arc::new(AtomicU64::new(0));

        // Spawn monitoring thread for TPS tracking
        let _monitor_handle = monitor_tps(tx_counter.clone(), total_txs);

        // Send transactions
        let mut pending_txs = send_transactions(
            transactions,
            self.max_concurrent_requests,
            self.tps,
            tx_counter,
            sleep(Duration::from_secs(self.duration)),
        )
        .await;

        // Graceful period of 1 second for `monitor_tps` to print out last statement
        tokio::time::sleep(Duration::from_secs(1)).await;

        let sample_size = pending_txs.len().min(self.sample_size);
        info!(sample_size, "Collecting a sample of receipts");
        let end_block_number = stream::iter(
            (0..sample_size)
                .map(|_| {
                    let idx = random_range(0..pending_txs.len());
                    pending_txs.remove(idx)
                })
                .progress(),
        )
        .map(async |pending_tx| {
            pending_tx
                .get_receipt()
                .await
                .map(|receipt| receipt.block_number)
        })
        .buffered(self.max_concurrent_requests)
        .try_collect::<Vec<_>>()
        .await?
        .last()
        .copied()
        .flatten()
        .unwrap_or(start_block_number);

        generate_report(&target_url, start_block_number, end_block_number, &self).await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
enum MnemonicArg {
    Mnemonic(String),
    Random,
}

impl FromStr for MnemonicArg {
    type Err = MnemonicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "random" => Ok(MnemonicArg::Random),
            mnemonic => Ok(MnemonicArg::Mnemonic(
                Mnemonic::<English>::from_str(mnemonic)?.to_phrase(),
            )),
        }
    }
}

impl MnemonicArg {
    fn resolve(&self) -> String {
        match self {
            MnemonicArg::Mnemonic(mnemonic) => mnemonic.clone(),
            MnemonicArg::Random => Mnemonic::<English>::new(&mut rand_08::thread_rng()).to_phrase(),
        }
    }
}

/// Awaits pending transactions with up to `tps` per second and `max_concurrent_requests` simultaneous in-flight requests. Stops when `deadline` future resolves.
async fn send_transactions(
    transactions: Vec<
        BoxFuture<'static, alloy::contract::Result<PendingTransactionBuilder<TempoNetwork>>>,
    >,
    max_concurrent_requests: usize,
    tps: u64,
    tx_counter: Arc<AtomicU64>,
    deadline: impl Future<Output = ()>,
) -> Vec<PendingTransactionBuilder<TempoNetwork>> {
    info!(
        transactions = transactions.len(),
        max_concurrent_requests, tps, "Sending transactions"
    );

    // Create a shared rate limiter for all threads
    let rate_limiter = RateLimiter::direct(Quota::per_second(NonZeroU32::new(tps as u32).unwrap()));

    stream::iter(transactions)
        .ratelimit_stream(&rate_limiter)
        .map(|transaction| timeout(Duration::from_secs(1), transaction))
        .buffer_unordered(max_concurrent_requests)
        .filter_map(|result| async {
            match result {
                Ok(Ok(pending_tx)) => {
                    tx_counter.fetch_add(1, Ordering::Relaxed);
                    Some(pending_tx)
                }
                Ok(Err(err)) => {
                    error!(?err, "Failed to send transaction");
                    None
                }
                Err(_) => {
                    error!("Transaction sending timed out");
                    None
                }
            }
        })
        .take_until(deadline)
        .collect()
        .await
}

async fn generate_transactions(
    input: GenerateTransactionsInput,
) -> eyre::Result<
    Vec<BoxFuture<'static, alloy::contract::Result<PendingTransactionBuilder<TempoNetwork>>>>,
> {
    let GenerateTransactionsInput {
        total_txs,
        num_accounts,
        signer_providers,
        max_concurrent_requests,
        max_concurrent_transactions,
        tip20_weight,
        place_order_weight,
        swap_weight,
    } = input;

    let txs_per_sender = total_txs / num_accounts;
    ensure!(
        txs_per_sender > 0,
        "txs per sender is 0, increase tps or decrease senders"
    );

    let (quote, user_tokens) = dex::setup(
        &signer_providers,
        2,
        max_concurrent_requests,
        max_concurrent_transactions,
    )
    .await?;

    info!(transactions = total_txs, "Generating transactions");

    let mut params = signer_providers
        .into_iter()
        .flat_map(|(_, provider)| std::iter::repeat_n(provider, txs_per_sender as usize))
        .zip(std::iter::repeat_with(|| user_tokens.choose(&mut rand::rng()).copied()).flatten())
        .collect::<Vec<_>>();
    params.shuffle(&mut rand::rng());

    const TX_TYPES: usize = 3;
    let tx_weights: [u64; TX_TYPES] = [tip20_weight, swap_weight, place_order_weight];

    let transfers = Arc::new(AtomicUsize::new(0));
    let swaps = Arc::new(AtomicUsize::new(0));
    let orders = Arc::new(AtomicUsize::new(0));
    let transactions: Vec<_> = params
        .into_par_iter()
        .map(|(provider, token)| -> eyre::Result<BoxFuture<'static, _>> {
            // TODO: can be improved with an enum per transaction type
            let tx_index = tx_weights
                .iter()
                .enumerate()
                .collect::<Vec<_>>()
                .choose_weighted(&mut rand::rng(), |(_, weight)| *weight)?
                .0;

            let tx: BoxFuture<'static, _> = match tx_index {
                0 => {
                    transfers.fetch_add(1, Ordering::Relaxed);
                    let provider = provider.clone();
                    Box::pin(async move {
                        let token = ITIP20Instance::new(token, provider);

                        // Transfer minimum possible amount
                        let tx = token.transfer(Address::random(), U256::ONE);
                        tx.send().await
                    })
                }
                1 => {
                    swaps.fetch_add(1, Ordering::Relaxed);
                    let provider = provider.clone();
                    Box::pin(async move {
                        let exchange =
                            IStablecoinExchangeInstance::new(STABLECOIN_EXCHANGE_ADDRESS, provider);

                        // Swap minimum possible amount
                        let tx = exchange.quoteSwapExactAmountIn(token, quote, 1);

                        tx.send().await
                    })
                }
                2 => {
                    orders.fetch_add(1, Ordering::Relaxed);
                    let provider = provider.clone();
                    Box::pin(async move {
                        let exchange =
                            IStablecoinExchangeInstance::new(STABLECOIN_EXCHANGE_ADDRESS, provider);

                        // Place an order at exactly the dust limit
                        let tick =
                            (random::<u16>() % (MAX_TICK - MIN_TICK) as u16) as i16 + MIN_TICK;
                        let tx = exchange.place(token, MIN_ORDER_AMOUNT, true, tick);

                        tx.send().await
                    })
                }
                _ => unreachable!("Only {TX_TYPES} transaction types are supported"),
            };

            Ok(tx)
        })
        .progress_count(total_txs)
        .collect::<eyre::Result<Vec<_>>>()?;

    info!(
        transactions = transactions.len(),
        transfers = transfers.load(Ordering::Relaxed),
        swaps = swaps.load(Ordering::Relaxed),
        orders = orders.load(Ordering::Relaxed),
        "Generated transactions",
    );

    Ok(transactions)
}

/// Funds accounts from the faucet using `temp_fundAddress` RPC.
async fn fund_accounts(
    provider: &impl Provider,
    addresses: &[Address],
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<()> {
    info!(accounts = addresses.len(), "Funding accounts from faucet");
    let progress = ProgressBar::new(addresses.len() as u64);

    let chunks = addresses
        .iter()
        .map(|address| {
            let address = *address;
            provider.raw_request::<_, Vec<B256>>("tempo_fundAddress".into(), (address,))
        })
        .chunks(max_concurrent_transactions);

    for chunk in chunks.into_iter() {
        let tx_hashes = stream::iter(chunk)
            .buffer_unordered(max_concurrent_requests)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .inspect(|_| progress.inc(1))
            .flatten()
            .map(async |hash| {
                Ok(
                    PendingTransactionBuilder::new(provider.root().clone(), hash)
                        .get_receipt()
                        .await?,
                )
            });
        assert_receipts(tx_hashes, max_concurrent_requests)
            .await
            .expect("Failed to fund accounts");
    }
    Ok(())
}

pub fn increase_nofile_limit(min_limit: u64) -> eyre::Result<u64> {
    let (soft, hard) = Resource::NOFILE.get()?;
    info!(soft, hard, "File descriptor limit at startup");

    if hard < min_limit {
        panic!(
            "File descriptor hard limit is too low. Please increase it to at least {min_limit}."
        );
    }

    if soft != hard {
        Resource::NOFILE.set(hard, hard)?; // Just max things out to give us plenty of overhead.
        let (soft, hard) = Resource::NOFILE.get()?;
        info!(soft, hard, "After increasing file descriptor limit");
    }

    Ok(soft)
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
    chain_id: u64,
    max_concurrent_requests: usize,
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
        chain_id: provider.get_chain_id().await?,
        max_concurrent_requests: args.max_concurrent_requests,
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

    info!("Report written to report.json");

    Ok(())
}

fn monitor_tps(tx_counter: Arc<AtomicU64>, target_count: u64) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_count = 0u64;
        loop {
            let current_count = tx_counter.load(Ordering::Relaxed);
            let tps = current_count - last_count;
            last_count = current_count;

            info!(tps, total = current_count, "Status");
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
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
) -> eyre::Result<()> {
    let chunks = futures.into_iter().chunks(max_concurrent_transactions);

    for chunk in chunks.into_iter() {
        // Send transactions and collect pending builders
        let pending_txs = stream::iter(chunk)
            .buffer_unordered(max_concurrent_requests)
            .try_collect::<Vec<_>>()
            .await?;

        // Fetch receipts and assert status
        assert_receipts(
            pending_txs
                .into_iter()
                .map(|tx| async move { Ok(tx.get_receipt().await?) }),
            max_concurrent_requests,
        )
        .await?;
    }

    Ok(())
}

async fn assert_receipts<R: ReceiptResponse, F: Future<Output = eyre::Result<R>>>(
    receipts: impl IntoIterator<Item = F>,
    max_concurrent_requests: usize,
) -> eyre::Result<()> {
    stream::iter(receipts.into_iter())
        .buffer_unordered(max_concurrent_requests)
        .try_for_each(async |receipt| {
            eyre::ensure!(
                receipt.status(),
                "Transaction {} failed",
                receipt.transaction_hash()
            );
            Ok(())
        })
        .await
}

struct GenerateTransactionsInput {
    total_txs: u64,
    num_accounts: u64,
    signer_providers: Vec<(PrivateKeySigner, DynProvider<TempoNetwork>)>,
    max_concurrent_requests: usize,
    max_concurrent_transactions: usize,
    tip20_weight: u64,
    place_order_weight: u64,
    swap_weight: u64,
}
