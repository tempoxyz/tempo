mod dex;
mod erc20;

use alloy_consensus::Transaction;
use itertools::Itertools;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use reth_tracing::{
    RethTracer, Tracer,
    tracing::{debug, error, info},
};
use tempo_alloy::{
    TempoNetwork, primitives::TempoTxEnvelope, provider::ext::TempoProviderBuilderExt,
};

use alloy::{
    consensus::BlockHeader,
    eips::Encodable2718,
    network::{ReceiptResponse, TransactionBuilder, TxSignerSync},
    primitives::{Address, B256, BlockNumber, U256},
    providers::{
        DynProvider, PendingTransactionBuilder, PendingTransactionError, Provider, ProviderBuilder,
        SendableTx, WatchTxError, fillers::TxFiller,
    },
    rpc::client::NoParams,
    signers::local::{
        PrivateKeySigner,
        coins_bip39::{English, Mnemonic, MnemonicError},
    },
    transports::http::reqwest::Url,
};
use clap::Parser;
use eyre::{Context, OptionExt, ensure};
use futures::{
    FutureExt, StreamExt, TryStreamExt,
    future::BoxFuture,
    stream::{self},
};
use governor::{Quota, RateLimiter, state::StreamRateLimitExt};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressIterator};
use rand::{random_range, seq::IndexedRandom};
use rlimit::Resource;
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs::File,
    io::BufWriter,
    num::{NonZeroU32, NonZeroU64},
    str::FromStr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
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
    stablecoin_exchange::{MAX_TICK, MIN_ORDER_AMOUNT, MIN_TICK, TICK_SPACING},
    tip20::{ISSUER_ROLE, token_id_to_address},
};
use tokio::{
    select,
    time::{Sleep, interval, sleep},
};
use tokio_util::sync::CancellationToken;

use crate::cmd::signer_providers::SignerProviderManager;

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
    #[arg(short, long, default_value_t = NonZeroU64::new(100).unwrap())]
    accounts: NonZeroU64,

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

    /// A weight that determines the likelihood of generating an ERC-20 transfer transaction.
    #[arg(long, default_value_t = 0.0)]
    erc20_weight: f64,

    /// An amount of receipts to wait for after sending all the transactions.
    #[arg(long, default_value_t = 100)]
    sample_size: usize,

    /// Fund accounts from the faucet before running the benchmark.
    ///
    /// Calls tempo_fundAddress for each account.
    #[arg(long)]
    faucet: bool,

    /// Clear the transaction pool before running the benchmark.
    ///
    /// Calls admin_clearTxpool.
    #[arg(long)]
    clear_txpool: bool,

    /// Disable 2D nonces
    #[arg(long)]
    disable_2d_nonces: bool,
}

impl MaxTpsArgs {
    const WEIGHT_PRECISION: f64 = 1000.0;

    pub async fn run(self) -> eyre::Result<()> {
        RethTracer::new().init()?;

        let accounts = self.accounts.get();

        // Set file descriptor limit if provided
        if let Some(fd_limit) = self.fd_limit {
            increase_nofile_limit(fd_limit).context("Failed to increase nofile limit")?;
        }

        let signer_provider_factory = Box::new(|signer, target_url, cached_nonce_manager| {
            ProviderBuilder::default()
                .fetch_chain_id()
                .with_gas_estimation()
                .with_nonce_management(cached_nonce_manager)
                .wallet(signer)
                .connect_http(target_url)
                .erased()
        });

        if self.disable_2d_nonces {
            info!(
                accounts = self.accounts,
                "Creating signers (with standard nonces)"
            );
            let signer_provider_manager = SignerProviderManager::new(
                self.mnemonic.resolve(),
                self.from_mnemonic_index,
                accounts,
                self.target_urls.clone(),
                Box::new(|target_url, cached_nonce_manager| {
                    ProviderBuilder::default()
                        .fetch_chain_id()
                        .with_gas_estimation()
                        .with_nonce_management(cached_nonce_manager)
                        .connect_http(target_url)
                }),
                signer_provider_factory,
            );
            self.run_with_manager(signer_provider_manager).await
        } else {
            info!(
                accounts = self.accounts,
                "Creating signers (with 2D nonces)"
            );
            let signer_provider_manager = SignerProviderManager::new(
                self.mnemonic.resolve(),
                self.from_mnemonic_index,
                accounts,
                self.target_urls.clone(),
                Box::new(|target_url, _cached_nonce_manager| {
                    ProviderBuilder::new_with_network::<TempoNetwork>()
                        .with_random_2d_nonces()
                        .connect_http(target_url)
                }),
                signer_provider_factory,
            );
            self.run_with_manager(signer_provider_manager).await
        }
    }

    async fn run_with_manager<F: TxFiller<TempoNetwork> + 'static>(
        self,
        signer_provider_manager: SignerProviderManager<F>,
    ) -> eyre::Result<()> {
        let accounts = self.accounts.get();
        let signer_providers = signer_provider_manager.signer_providers();

        if self.clear_txpool {
            for (target_url, provider) in signer_provider_manager.target_url_providers() {
                let transactions: u64 = provider
                    .raw_request("admin_clearTxpool".into(), NoParams::default())
                    .await
                    .context(
                        format!("Failed to clear transaction pool for {target_url}. Is `admin_clearTxpool` RPC method available?"),
                    )?;
                info!(%target_url, transactions, "Cleared transaction pool");
            }
        }

        // Grab first provider to call some RPC methods
        let provider = signer_providers[0].1.clone();

        // Fund accounts from faucet if requested
        if self.faucet {
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

        // Setup DEX
        let user_tokens = 2;
        info!(user_tokens, "Setting up DEX");
        let (quote_token, user_tokens) = dex::setup(
            signer_providers,
            user_tokens,
            self.max_concurrent_requests,
            self.max_concurrent_transactions,
        )
        .await?;

        // Setup ERC-20 tokens if erc20_weight > 0
        let erc20_tokens = if self.erc20_weight > 0.0 {
            let num_erc20_tokens = 2;
            info!(num_erc20_tokens, "Setting up ERC-20 tokens");
            erc20::setup(
                signer_providers,
                num_erc20_tokens,
                self.max_concurrent_requests,
                self.max_concurrent_transactions,
            )
            .await?
        } else {
            Vec::new()
        };

        // Generate all transactions
        let total_txs = self.tps * self.duration;
        let tip20_weight = (self.tip20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let place_order_weight = (self.place_order_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let swap_weight = (self.swap_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let erc20_weight = (self.erc20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let transactions = generate_transactions(GenerateTransactionsInput {
            total_txs,
            accounts,
            signer_provider_manager: signer_provider_manager.clone(),
            max_concurrent_requests: self.max_concurrent_requests,
            tip20_weight,
            place_order_weight,
            swap_weight,
            erc20_weight,
            quote_token,
            user_tokens,
            erc20_tokens,
        })
        .await
        .context("Failed to generate transactions")?;

        // Send transactions
        let mut pending_txs = send_transactions(
            transactions,
            signer_provider_manager.clone(),
            self.max_concurrent_requests,
            self.tps,
            sleep(Duration::from_secs(self.duration)),
        )
        .await;
        let end_block_number = provider.get_block_number().await?;

        info!("Retrieving first block number from sent transactions");
        let start_block_number = loop {
            if let Some(first_tx) = pending_txs.pop_front() {
                debug!(hash = %first_tx.tx_hash(), "Retrieving transaction receipt for first block number");
                if let Ok(first_tx_receipt) = first_tx
                    .with_timeout(Some(Duration::from_secs(5)))
                    .get_receipt()
                    .await
                {
                    break first_tx_receipt.block_number;
                }
            } else {
                break None;
            }
        };
        let Some(start_block_number) = start_block_number else {
            eyre::bail!("Failed to retrieve start block number")
        };

        // Collect a sample of receipts and print the stats
        let sample_size = pending_txs.len().min(self.sample_size);
        let successful = Arc::new(AtomicUsize::new(0));
        let timeout = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        info!(sample_size, "Collecting a sample of receipts");
        stream::iter(0..sample_size)
            .map(|_| {
                let idx = random_range(0..pending_txs.len());
                pending_txs.remove(idx).expect("index is in range")
            })
            .map(|pending_tx| {
                let hash = *pending_tx.tx_hash();
                pending_tx
                    .with_timeout(Some(Duration::from_secs(5)))
                    .get_receipt()
                    .map(move |result| (hash, result))
            })
            .buffered(self.max_concurrent_requests)
            .for_each(async |(hash, result)| match result {
                Ok(_) => {
                    successful.fetch_add(1, Ordering::Relaxed);
                }
                Err(PendingTransactionError::TxWatcher(WatchTxError::Timeout)) => {
                    timeout.fetch_add(1, Ordering::Relaxed);
                    error!(?hash, "Transaction receipt retrieval timed out");
                }
                Err(err) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    error!(?hash, "Transaction receipt retrieval failed: {}", err);
                }
            })
            .await;
        info!(
            successful = successful.load(Ordering::Relaxed),
            timeout = timeout.load(Ordering::Relaxed),
            failed = failed.load(Ordering::Relaxed),
            "Collected a sample of receipts"
        );

        generate_report(provider, start_block_number, end_block_number, &self).await?;

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
async fn send_transactions<F: TxFiller<TempoNetwork> + 'static>(
    transactions: Vec<Vec<u8>>,
    signer_provider_manager: SignerProviderManager<F>,
    max_concurrent_requests: usize,
    tps: u64,
    deadline: Sleep,
) -> VecDeque<PendingTransactionBuilder<TempoNetwork>> {
    info!(
        transactions = transactions.len(),
        max_concurrent_requests, tps, "Sending transactions"
    );

    // Create shared transaction counter and monitoring
    let tx_counter = Arc::new(AtomicUsize::new(0));

    // Spawn monitoring task for TPS reporting
    let cancel = CancellationToken::new();
    let _drop_guard = cancel.clone().drop_guard();
    tokio::spawn(monitor_tps(
        tx_counter.clone(),
        transactions.len(),
        cancel.clone(),
    ));

    // Create a rate limiter
    let rate_limiter = RateLimiter::direct(Quota::per_second(NonZeroU32::new(tps as u32).unwrap()));

    let failed = Arc::new(AtomicUsize::new(0));
    let timeout = Arc::new(AtomicUsize::new(0));
    let transactions = stream::iter(transactions)
        .ratelimit_stream(&rate_limiter)
        .zip(stream::repeat_with(|| {
            signer_provider_manager.random_unsigned_provider()
        }))
        .map(|(bytes, provider)| async move {
            tokio::time::timeout(
                Duration::from_secs(1),
                provider.send_raw_transaction(&bytes),
            )
            .await
        })
        .buffer_unordered(max_concurrent_requests)
        .filter_map(|result| async {
            match result {
                Ok(Ok(pending_tx)) => {
                    tx_counter.fetch_add(1, Ordering::Relaxed);
                    Some(pending_tx)
                }
                Ok(Err(err)) => {
                    failed.fetch_add(1, Ordering::Relaxed);
                    debug!(?err, "Failed to send transaction");
                    None
                }
                Err(_) => {
                    timeout.fetch_add(1, Ordering::Relaxed);
                    debug!("Transaction sending timed out");
                    None
                }
            }
        })
        .take_until(deadline)
        .collect()
        .await;

    info!(
        success = tx_counter.load(Ordering::Relaxed),
        failed = failed.load(Ordering::Relaxed),
        timeout = timeout.load(Ordering::Relaxed),
        "Finished sending transactions"
    );

    transactions
}

async fn generate_transactions<F: TxFiller<TempoNetwork> + 'static>(
    input: GenerateTransactionsInput<F>,
) -> eyre::Result<Vec<Vec<u8>>> {
    let GenerateTransactionsInput {
        total_txs,
        accounts,
        signer_provider_manager,
        max_concurrent_requests,
        tip20_weight,
        place_order_weight,
        swap_weight,
        erc20_weight,
        quote_token,
        user_tokens,
        erc20_tokens,
    } = input;

    let txs_per_sender = total_txs / accounts;
    ensure!(
        txs_per_sender > 0,
        "txs per sender is 0, increase tps or decrease senders"
    );

    info!(transactions = total_txs, "Generating transactions");

    const TX_TYPES: usize = 4;
    // Weights for random sampling for each transaction type
    let tx_weights: [u64; TX_TYPES] = [tip20_weight, swap_weight, place_order_weight, erc20_weight];
    // Cached gas estimates for each transaction type
    let gas_estimates: [Arc<OnceLock<(u128, u128, u64)>>; TX_TYPES] = Default::default();

    // Counters for number of transactions of each type
    let transfers = Arc::new(AtomicUsize::new(0));
    let swaps = Arc::new(AtomicUsize::new(0));
    let orders = Arc::new(AtomicUsize::new(0));
    let erc20_transfers = Arc::new(AtomicUsize::new(0));

    let builders = ProgressBar::new(total_txs)
        .wrap_stream(stream::iter(
            std::iter::repeat_with(|| signer_provider_manager.random_unsigned_provider())
                .take(total_txs as usize),
        ))
        .map(async |provider| {
            let token = user_tokens.choose(&mut rand::rng()).copied().unwrap();

            // TODO: can be improved with an enum per transaction type
            let tx_index = tx_weights
                .iter()
                .enumerate()
                .collect::<Vec<_>>()
                .choose_weighted(&mut rand::rng(), |(_, weight)| *weight)?
                .0;

            let mut tx = match tx_index {
                0 => {
                    transfers.fetch_add(1, Ordering::Relaxed);
                    let token = ITIP20Instance::new(token, provider.clone());

                    // Transfer minimum possible amount
                    token
                        .transfer(Address::random(), U256::ONE)
                        .into_transaction_request()
                }
                1 => {
                    swaps.fetch_add(1, Ordering::Relaxed);
                    let exchange = IStablecoinExchangeInstance::new(
                        STABLECOIN_EXCHANGE_ADDRESS,
                        provider.clone(),
                    );

                    // Swap minimum possible amount
                    exchange
                        .quoteSwapExactAmountIn(token, quote_token, 1)
                        .into_transaction_request()
                }
                2 => {
                    orders.fetch_add(1, Ordering::Relaxed);
                    let exchange = IStablecoinExchangeInstance::new(
                        STABLECOIN_EXCHANGE_ADDRESS,
                        provider.clone(),
                    );

                    // Place an order at a random tick that's a multiple of `TICK_SPACING`
                    let tick =
                        rand::random_range(MIN_TICK / TICK_SPACING..=MAX_TICK / TICK_SPACING)
                            * TICK_SPACING;
                    exchange
                        .place(token, MIN_ORDER_AMOUNT, true, tick)
                        .into_transaction_request()
                }
                3 => {
                    erc20_transfers.fetch_add(1, Ordering::Relaxed);
                    let token_address = erc20_tokens.choose(&mut rand::rng()).copied().unwrap();
                    let token = erc20::MockERC20::new(token_address, provider.clone());

                    // Transfer minimum possible amount
                    token
                        .transfer(Address::random(), U256::ONE)
                        .into_transaction_request()
                }
                _ => unreachable!("Only {TX_TYPES} transaction types are supported"),
            };

            // Get a random signer and set it as the sender of the transaction.
            let signer = signer_provider_manager.random_signer();
            tx.inner.set_from(signer.address());

            let gas = &gas_estimates[tx_index];
            // If we already filled the gas fields once for that transaction type, use it.
            // This will skip the gas filler.
            if let Some((max_fee_per_gas, max_priority_fee_per_gas, gas_limit)) = gas.get() {
                tx.inner.set_max_fee_per_gas(*max_fee_per_gas);
                tx.inner
                    .set_max_priority_fee_per_gas(*max_priority_fee_per_gas);
                tx.inner.set_gas_limit(*gas_limit);
            }

            // Fill the rest of transaction. In case we already filled the gas fields,
            // it will only fill the chain ID and nonce that are efficiently cached inside
            // the fillers.
            let tx = provider.fill(tx).await?;

            // If we never filled the gas fields for that transaction type, cache the estimated
            // gas.
            if gas.get().is_none() {
                let _ = gas.set(match &tx {
                    SendableTx::Builder(builder) => (
                        builder
                            .max_fee_per_gas()
                            .ok_or_eyre("max fee per gas should be filled")?,
                        builder
                            .max_priority_fee_per_gas()
                            .ok_or_eyre("max priority fee per gas should be filled")?,
                        builder
                            .gas_limit()
                            .ok_or_eyre("gas limit should be filled")?,
                    ),
                    SendableTx::Envelope(envelope) => (
                        envelope.max_fee_per_gas(),
                        envelope
                            .max_priority_fee_per_gas()
                            .ok_or_eyre("max priority fee per gas should be filled")?,
                        envelope.gas_limit(),
                    ),
                });
            }

            eyre::Ok((tx.try_into_request()?, signer))
        })
        .buffer_unordered(max_concurrent_requests)
        .try_collect::<Vec<_>>()
        .await?;
    info!(
        transactions = builders.len(),
        transfers = transfers.load(Ordering::Relaxed),
        swaps = swaps.load(Ordering::Relaxed),
        orders = orders.load(Ordering::Relaxed),
        "Generated transactions",
    );

    info!(transactions = builders.len(), "Signing transactions");
    // Sign transactions in parallel using signers directly, so it doesn't require async
    let transactions = builders
        .into_par_iter()
        .progress()
        .map(|(tx, signer)| -> eyre::Result<TempoTxEnvelope> {
            let mut tx = tx.build_unsigned()?;
            let sig = signer.sign_transaction_sync(tx.as_dyn_signable_mut())?;
            Ok(tx.into_envelope(sig))
        })
        .map(|result| result.map(|tx| tx.encoded_2718()))
        .collect::<eyre::Result<Vec<_>>>()?;

    Ok(transactions)
}

/// Funds accounts from the faucet using `temp_fundAddress` RPC.
async fn fund_accounts(
    provider: &DynProvider<TempoNetwork>,
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
    accounts: u64,
    chain_id: u64,
    total_connections: usize,
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
    provider: DynProvider<TempoNetwork>,
    start_block: BlockNumber,
    end_block: BlockNumber,
    args: &MaxTpsArgs,
) -> eyre::Result<()> {
    info!(start_block, end_block, "Generating report");

    let mut last_block_timestamp: Option<u64> = None;

    let mut benchmarked_blocks = Vec::new();

    for number in start_block..=end_block {
        let block = provider
            .get_block(number.into())
            .await?
            .ok_or_eyre("Block {number} not found")?;
        let receipts = provider
            .get_block_receipts(number.into())
            .await?
            .ok_or_eyre("Receipts for block {number} not found")?;
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
        accounts: args.accounts.get(),
        chain_id: provider.get_chain_id().await?,
        total_connections: args.max_concurrent_requests,
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

    let path = "report.json";
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &report)?;

    info!(path, "Generated report");

    Ok(())
}

async fn monitor_tps(tx_counter: Arc<AtomicUsize>, target_count: usize, token: CancellationToken) {
    let mut last_count = 0;
    let mut ticker = interval(Duration::from_secs(1));

    loop {
        select! {
            _ = ticker.tick() => {
                let current_count = tx_counter.load(Ordering::Relaxed);
                let tps = current_count - last_count;
                last_count = current_count;

                info!(tps, total = current_count, "Status");
                thread::sleep(Duration::from_secs(1));

                if current_count == target_count {
                    break;
                }
            }
            _ = token.cancelled() => {
                break;
            }
        }
    }
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
        .try_for_each(|receipt| assert_receipt(receipt))
        .await
}

async fn assert_receipt<R: ReceiptResponse>(receipt: R) -> eyre::Result<()> {
    eyre::ensure!(
        receipt.status(),
        "Transaction {} failed",
        receipt.transaction_hash()
    );
    Ok(())
}

struct GenerateTransactionsInput<F: TxFiller<TempoNetwork>> {
    total_txs: u64,
    accounts: u64,
    signer_provider_manager: SignerProviderManager<F>,
    max_concurrent_requests: usize,
    tip20_weight: u64,
    place_order_weight: u64,
    swap_weight: u64,
    erc20_weight: u64,
    quote_token: Address,
    user_tokens: Vec<Address>,
    erc20_tokens: Vec<Address>,
}
