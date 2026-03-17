mod dex;
mod erc20;
mod mpp;
pub(crate) mod scenario;

use alloy_consensus::Transaction;
use itertools::Itertools;
use reth_tracing::{
    RethTracer, Tracer,
    tracing::{debug, error, info, warn},
};
use tempo_alloy::{
    TempoNetwork, fillers::ExpiringNonceFiller, provider::ext::TempoProviderBuilderExt,
};

use alloy::{
    consensus::BlockHeader,
    eips::Encodable2718,
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder, TxSignerSync},
    primitives::{Address, B256, BlockNumber, U256},
    providers::{
        DynProvider, PendingTransactionBuilder, PendingTransactionError, Provider, ProviderBuilder,
        SendableTx, WatchTxError, fillers::TxFiller,
    },
    rpc::client::NoParams,
    signers::local::{
        Secp256k1Signer,
        coins_bip39::{English, Mnemonic, MnemonicError},
    },
    transports::http::reqwest::Url,
};
use clap::Parser;
use eyre::{Context, OptionExt};
use futures::{
    FutureExt, Stream, StreamExt, TryStreamExt,
    future::BoxFuture,
    stream::{self},
};
use indicatif::{ProgressBar, ProgressIterator};
use rand::{random_range, seq::IndexedRandom};
use rlimit::Resource;
use serde::Serialize;
use std::{
    collections::VecDeque,
    fs::File,
    io::BufWriter,
    num::NonZeroU64,
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_contracts::precompiles::{
    IFeeManager::IFeeManagerInstance,
    IRolesAuth,
    IStablecoinDEX::IStablecoinDEXInstance,
    ITIP20::{self, ITIP20Instance},
    ITIP20Factory, STABLECOIN_DEX_ADDRESS, TIP20_FACTORY_ADDRESS,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    stablecoin_dex::{MAX_TICK, MIN_ORDER_AMOUNT, MIN_TICK, TICK_SPACING},
    tip_fee_manager::DEFAULT_FEE_TOKEN,
    tip20::ISSUER_ROLE,
};
use tokio::{select, time::interval};
use tokio_util::sync::CancellationToken;

use crate::cmd::signer_providers::SignerProviderManager;

use self::scenario::{LoadProfile, Scenario};

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct MaxTpsArgs {
    /// Predefined stress test scenario. Sets a load profile plus defaults for accounts,
    /// weights, and concurrency. Mutually exclusive with `--profile`.
    #[arg(long, value_enum, conflicts_with = "profile")]
    scenario: Option<Scenario>,

    /// Custom load profile (YAML file defining phases with TPS ramps).
    /// Mutually exclusive with `--scenario`.
    #[arg(long, conflicts_with = "scenario")]
    profile: Option<PathBuf>,

    /// Target TPS. When used with `--scenario`/`--profile`, creates a single constant-TPS
    /// phase that overrides the profile. When used alone (no scenario/profile), also
    /// requires `--duration`.
    #[arg(short, long)]
    tps: Option<u64>,

    /// Test duration in seconds. Used with `--tps` to create a simple constant-TPS profile.
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

    #[arg(long, default_value_t = DEFAULT_FEE_TOKEN)]
    fee_token: Address,

    /// Target URLs for network connections (comma-separated or multiple --target-urls)
    #[arg(long, value_delimiter = ',', action = clap::ArgAction::Append, default_values_t = vec!["http://localhost:8545".parse::<Url>().unwrap()])]
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
    #[arg(long, default_value_t = 1.0)]
    tip20_weight: f64,

    /// A weight that determines the likelihood of generating a DEX place transaction.
    #[arg(long, default_value_t = 0.0)]
    place_order_weight: f64,

    /// A weight that determines the likelihood of generating a DEX swapExactAmountIn transaction.
    #[arg(long, default_value_t = 0.0)]
    swap_weight: f64,

    /// A weight that determines the likelihood of generating an ERC-20 transfer transaction.
    #[arg(long, default_value_t = 0.0)]
    erc20_weight: f64,

    /// A weight that determines the likelihood of generating an MPP channel open+close
    /// transaction. Requires `--mpp-contract-address`.
    #[arg(long, default_value_t = 0.0)]
    mpp_weight: f64,

    /// Address of a deployed TempoStreamChannel contract. Required when `--mpp-weight` > 0.
    #[arg(long, default_value = "0x33b901018174ddabe4841042ab76ba85d4e24f25")]
    mpp_contract_address: Option<Address>,

    /// Send transfers to existing signer accounts instead of random new addresses.
    ///
    /// When enabled, TIP-20 and ERC-20 transfers are sent to the bench's own signer addresses
    /// (which already exist on-chain), avoiding cold SSTORE for account creation. This tests
    /// pure transfer throughput without state growth.
    #[arg(long)]
    existing_recipients: bool,

    /// An amount of receipts to wait for after sending all the transactions.
    #[arg(long, default_value_t = 100)]
    sample_size: usize,

    /// Fund accounts from the faucet before running the benchmark.
    ///
    /// Calls tempo_fundAddress for each account.
    #[arg(long)]
    faucet: bool,

    /// URL for the faucet service. If not provided, uses the first target URL.
    #[arg(long)]
    faucet_url: Option<Url>,

    /// Clear the transaction pool before running the benchmark.
    ///
    /// Calls admin_clearTxpool.
    #[arg(long)]
    clear_txpool: bool,

    /// Use 2D nonces instead of expiring nonces.
    ///
    /// By default, tempo-bench uses expiring nonces ([TIP-1009]) which use a circular buffer
    /// for replay protection, avoiding state bloat. Use this flag to switch to 2D nonces
    /// which store nonce state per (address, nonce_key) pair.
    ///
    /// [TIP-1009]: <https://docs.tempo.xyz/protocol/tips/tip-1009>
    #[arg(long)]
    use_2d_nonces: bool,

    /// Use standard sequential nonces instead of expiring nonces.
    ///
    /// This disables both expiring nonces and 2D nonces, using traditional sequential
    /// nonce management.
    #[arg(long)]
    use_standard_nonces: bool,
}

impl MaxTpsArgs {
    const WEIGHT_PRECISION: f64 = 1000.0;

    /// Apply scenario overrides to fields that were left at their CLI defaults.
    fn apply_scenario_overrides(&mut self) {
        let Some(scenario) = self.scenario else {
            return;
        };

        let o = scenario.overrides();

        if self.accounts.get() == 100
            && let Some(v) = o.accounts
        {
            self.accounts = NonZeroU64::new(v).unwrap_or(self.accounts);
        }
        if self.max_concurrent_requests == 100
            && let Some(v) = o.max_concurrent_requests
        {
            self.max_concurrent_requests = v;
        }
        if self.tip20_weight == 1.0
            && let Some(v) = o.tip20_weight
        {
            self.tip20_weight = v;
        }
        if self.erc20_weight == 0.0
            && let Some(v) = o.erc20_weight
        {
            self.erc20_weight = v;
        }
        if self.mpp_weight == 0.0
            && let Some(v) = o.mpp_weight
        {
            self.mpp_weight = v;
        }
        if self.place_order_weight == 0.0
            && let Some(v) = o.place_order_weight
        {
            self.place_order_weight = v;
        }
        if self.swap_weight == 0.0
            && let Some(v) = o.swap_weight
        {
            self.swap_weight = v;
        }
        if !self.existing_recipients
            && let Some(v) = o.existing_recipients
        {
            self.existing_recipients = v;
        }
        if self.benchmark_mode.is_none() {
            self.benchmark_mode = o.benchmark_mode;
        }
    }

    /// Resolve the load profile from CLI args.
    ///
    /// Priority: `--tps` override > `--profile` file > `--scenario` preset > bare `--tps --duration`.
    fn resolve_profile(&self) -> eyre::Result<LoadProfile> {
        // If --tps is given, it always creates a simple constant profile
        if let Some(tps) = self.tps {
            eyre::ensure!(tps > 0, "--tps must be > 0");
            return Ok(LoadProfile {
                phases: vec![scenario::Phase {
                    name: "constant".into(),
                    target_tps: tps,
                    duration: Duration::from_secs(self.duration),
                    ramp: false,
                    burst: None,
                }],
            });
        }

        // --profile <file>
        if let Some(ref path) = self.profile {
            return LoadProfile::from_file(path);
        }

        // --scenario <name>
        if let Some(scenario) = self.scenario {
            return Ok(scenario.profile());
        }

        eyre::bail!("one of --tps, --scenario, or --profile is required")
    }

    pub async fn run(mut self) -> eyre::Result<()> {
        RethTracer::new().init()?;

        self.apply_scenario_overrides();
        let profile = self.resolve_profile()?;

        info!(
            phases = profile.phases.len(),
            total_duration_secs = profile.total_duration().as_secs(),
            expected_txs = profile.expected_total_txs(),
            max_tps = profile.max_tps(),
            tip20 = self.tip20_weight,
            erc20 = self.erc20_weight,
            mpp = self.mpp_weight,
            existing_recipients = self.existing_recipients,
            "Load profile resolved"
        );
        for (i, phase) in profile.phases.iter().enumerate() {
            info!(
                phase = i,
                name = %phase.name,
                target_tps = phase.target_tps,
                duration_secs = phase.duration.as_secs(),
                ramp = phase.ramp,
                "  Phase"
            );
        }

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
                .wallet(EthereumWallet::from(signer))
                .connect_http(target_url)
                .erased()
        });

        if self.use_2d_nonces {
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
            self.run_with_manager(signer_provider_manager, profile)
                .await
        } else if self.use_standard_nonces {
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
            self.run_with_manager(signer_provider_manager, profile)
                .await
        } else {
            // Default: Use expiring nonces (TIP-1009)
            // Use the default 25-second expiry window (protocol max is 30s).
            let expiry_secs = ExpiringNonceFiller::DEFAULT_EXPIRY_SECS;
            info!(
                accounts = self.accounts,
                expiry_secs, "Creating signers (with expiring nonces - TIP-1009)"
            );
            let signer_provider_manager = SignerProviderManager::new(
                self.mnemonic.resolve(),
                self.from_mnemonic_index,
                accounts,
                self.target_urls.clone(),
                Box::new(move |target_url, _cached_nonce_manager| {
                    ProviderBuilder::default()
                        .filler(ExpiringNonceFiller::with_expiry_secs(expiry_secs))
                        .with_gas_estimation()
                        .fetch_chain_id()
                        .connect_http(target_url)
                }),
                signer_provider_factory,
            );
            self.run_with_manager(signer_provider_manager, profile)
                .await
        }
    }

    async fn run_with_manager<F: TxFiller<TempoNetwork> + 'static>(
        self,
        signer_provider_manager: SignerProviderManager<F>,
        profile: LoadProfile,
    ) -> eyre::Result<()> {
        // Validate required addresses before sending any transactions
        eyre::ensure!(
            self.mpp_weight == 0.0 || self.mpp_contract_address.is_some(),
            "--mpp-contract-address is required when --mpp-weight > 0"
        );

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
            let faucet_provider: DynProvider<TempoNetwork> =
                if let Some(ref faucet_url) = self.faucet_url {
                    info!(%faucet_url, "Using custom faucet URL");
                    ProviderBuilder::new_with_network::<TempoNetwork>()
                        .connect_http(faucet_url.clone())
                        .erased()
                } else {
                    provider.clone()
                };
            fund_accounts(
                &faucet_provider,
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

        // Setup DEX tokens, pairs, and liquidity only if any DEX transaction type has non-zero
        // weight. Otherwise, use the fee token for TIP-20 transfers directly.
        let (quote_token, user_tokens) = if self.place_order_weight > 0.0 || self.swap_weight > 0.0
        {
            let user_tokens = 2;
            info!(user_tokens, "Setting up DEX");
            let (quote_token, user_tokens) = dex::setup(
                signer_providers,
                user_tokens,
                self.max_concurrent_requests,
                self.max_concurrent_transactions,
            )
            .await?;
            (Some(quote_token), user_tokens)
        } else {
            info!(fee_token = %self.fee_token, "Using fee token for TIP-20 transfers");
            (None, vec![self.fee_token])
        };

        let erc20_tokens = if self.erc20_weight > 0.0 {
            let num_erc20_tokens = 1;
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

        let mpp_contract_address = if self.mpp_weight > 0.0 {
            let addr = self.mpp_contract_address.expect("validated above");
            mpp::setup(
                signer_providers,
                addr,
                self.fee_token,
                self.max_concurrent_requests,
                self.max_concurrent_transactions,
            )
            .await?;
            Some(addr)
        } else {
            None
        };

        let tip20_weight = (self.tip20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let place_order_weight = (self.place_order_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let swap_weight = (self.swap_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let erc20_weight = (self.erc20_weight * Self::WEIGHT_PRECISION).trunc() as u64;
        let mpp_weight = (self.mpp_weight * Self::WEIGHT_PRECISION).trunc() as u64;

        let recipients = if self.existing_recipients {
            let addrs: Vec<Address> = signer_providers
                .iter()
                .map(|(signer, _)| signer.address())
                .collect();
            info!(
                recipients = addrs.len(),
                "Using existing signer addresses as recipients"
            );
            Some(addrs)
        } else {
            None
        };

        let use_expiring_nonces = !self.use_2d_nonces && !self.use_standard_nonces;
        let expiry_secs = if use_expiring_nonces {
            Some(ExpiringNonceFiller::DEFAULT_EXPIRY_SECS)
        } else {
            None
        };

        let chain_id = provider.get_chain_id().await?;

        let gen_input = GenerateTransactionsInput {
            tip20_weight,
            place_order_weight,
            swap_weight,
            erc20_weight,
            mpp_weight,
            quote_token,
            user_tokens,
            erc20_tokens,
            mpp_contract_address,
            chain_id,
            recipients,
            expiry_secs,
        };

        let total_duration = profile.total_duration();
        let expected_txs = profile.expected_total_txs();
        let pregen_buffer = (profile.max_tps() as usize).clamp(100, 5_000);

        let providers_with_urls = signer_provider_manager.unsigned_providers_with_urls();
        let num_urls = providers_with_urls.len();

        info!(
            expected_txs,
            pregen_buffer,
            num_urls,
            per_url_concurrency = self.max_concurrent_requests,
            total_duration_secs = total_duration.as_secs(),
            "Generating and sending transactions"
        );

        let counters = TransactionCounters::default();
        let cancel_token = CancellationToken::new();

        // Start TPS monitor
        tokio::spawn(monitor_tps_profiled(
            counters.clone(),
            profile.clone(),
            cancel_token.clone(),
        ));

        let start_block_number = provider.get_block_number().await?;

        // Pre-generate a buffer of signed transaction bytes from the infinite generator stream
        let mut tx_stream =
            generate_transactions(signer_provider_manager.clone(), gen_input, counters.clone())
                .buffer_unordered(pregen_buffer)
                .filter_map(|result| async {
                    match result {
                        Ok(bytes) => Some(bytes),
                        Err(e) => {
                            debug!(?e, "Transaction generation failed");
                            None
                        }
                    }
                })
                .boxed();

        // Credit-based pacer: dispatches transactions according to the load profile
        let start = Instant::now();
        let mut credit = 0.0f64;
        let mut last_elapsed = Duration::ZERO;
        let mut last_phase: Option<String> = None;
        let mut pending_txs: VecDeque<PendingTransactionBuilder<TempoNetwork>> = VecDeque::new();
        let tick = Duration::from_millis(50);

        // Per-URL in-flight tracking with round-robin distribution
        let mut in_flight_per_url = vec![0usize; num_urls];
        let mut rr_index = 0usize;

        // Channel for collecting send results
        let (result_tx, mut result_rx) =
            tokio::sync::mpsc::channel::<SendResult>(self.max_concurrent_requests * num_urls * 2);

        loop {
            let elapsed = start.elapsed();
            if elapsed >= total_duration {
                break;
            }

            // Log phase transitions
            if let Some(current_phase) = profile.phase_at(elapsed) {
                let current = current_phase.to_string();
                if last_phase.as_deref() != Some(current_phase) {
                    let current_tps = profile.tps_at(elapsed);
                    let total_in_flight: usize = in_flight_per_url.iter().sum();
                    info!(
                        phase = %current,
                        target_tps = current_tps as u64,
                        total_in_flight,
                        elapsed_secs = elapsed.as_secs(),
                        "Phase transition"
                    );
                    last_phase = Some(current);
                }
            }

            // Refill credit based on elapsed time
            credit += profile.tx_budget_between(last_elapsed, elapsed);
            last_elapsed = elapsed;

            // Drain completed send results
            while let Ok(result) = result_rx.try_recv() {
                match result {
                    SendResult::Success(url_idx, pending_tx) => {
                        in_flight_per_url[url_idx] -= 1;
                        counters.sent.fetch_add(1, Ordering::Relaxed);
                        counters.success.fetch_add(1, Ordering::Relaxed);
                        pending_txs.push_back(pending_tx);
                    }
                    SendResult::Failed(url_idx) => {
                        in_flight_per_url[url_idx] -= 1;
                        counters.sent.fetch_add(1, Ordering::Relaxed);
                        counters.failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            // Dispatch transactions up to available credit and per-URL concurrency
            let total_capacity: usize = in_flight_per_url
                .iter()
                .map(|&f| self.max_concurrent_requests.saturating_sub(f))
                .sum();
            let to_send = (credit.floor() as usize).min(total_capacity);

            for _ in 0..to_send {
                // Find next URL with available capacity via round-robin
                let mut found = false;
                for _ in 0..num_urls {
                    let idx = rr_index % num_urls;
                    rr_index += 1;
                    if in_flight_per_url[idx] < self.max_concurrent_requests {
                        // Pull a pre-generated tx from the buffer
                        let Some(bytes) = tx_stream.next().await else {
                            warn!("Transaction generator exhausted");
                            break;
                        };

                        credit -= 1.0;
                        in_flight_per_url[idx] += 1;

                        let provider = providers_with_urls[idx].1.clone();
                        let result_tx = result_tx.clone();
                        tokio::spawn(async move {
                            let result = tokio::time::timeout(
                                Duration::from_secs(1),
                                provider.send_raw_transaction(&bytes),
                            )
                            .await;

                            let send_result = match result {
                                Ok(Ok(pending_tx)) => SendResult::Success(idx, pending_tx),
                                _ => SendResult::Failed(idx),
                            };
                            let _ = result_tx.send(send_result).await;
                        });
                        found = true;
                        break;
                    }
                }
                if !found {
                    break;
                }
            }

            tokio::time::sleep(tick).await;
        }

        // Drain remaining in-flight results
        drop(result_tx);
        while let Some(result) = result_rx.recv().await {
            match result {
                SendResult::Success(_, pending_tx) => {
                    counters.sent.fetch_add(1, Ordering::Relaxed);
                    counters.success.fetch_add(1, Ordering::Relaxed);
                    pending_txs.push_back(pending_tx);
                }
                SendResult::Failed(_) => {
                    counters.sent.fetch_add(1, Ordering::Relaxed);
                    counters.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        cancel_token.cancel();

        info!(
            tip20_transfers = counters.tip20_transfers.load(Ordering::Relaxed),
            swaps = counters.swaps.load(Ordering::Relaxed),
            orders = counters.orders.load(Ordering::Relaxed),
            erc20_transfers = counters.erc20_transfers.load(Ordering::Relaxed),
            mpp_open_close = counters.mpp_open_close.load(Ordering::Relaxed),
            success = counters.success.load(Ordering::Relaxed),
            failed = counters.failed.load(Ordering::Relaxed),
            "Finished sending transactions"
        );

        let end_block_number = provider.get_block_number().await?;

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

        generate_report(
            provider,
            start_block_number,
            end_block_number,
            &self,
            &profile,
        )
        .await?;

        Ok(())
    }
}

/// Result of a single transaction send attempt.
/// The `usize` is the URL index for per-URL in-flight tracking.
enum SendResult {
    Success(usize, PendingTransactionBuilder<TempoNetwork>),
    Failed(usize),
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

#[derive(Clone, Default)]
struct TransactionCounters {
    /// Per-type generation counters
    tip20_transfers: Arc<AtomicUsize>,
    swaps: Arc<AtomicUsize>,
    orders: Arc<AtomicUsize>,
    erc20_transfers: Arc<AtomicUsize>,
    mpp_open_close: Arc<AtomicUsize>,
    /// Sending counters
    sent: Arc<AtomicUsize>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct GenerateTransactionsInput {
    tip20_weight: u64,
    place_order_weight: u64,
    swap_weight: u64,
    erc20_weight: u64,
    mpp_weight: u64,
    quote_token: Option<Address>,
    user_tokens: Vec<Address>,
    erc20_tokens: Vec<Address>,
    mpp_contract_address: Option<Address>,
    chain_id: u64,
    /// When set, transfers go to these existing addresses instead of `Address::random()`.
    recipients: Option<Vec<Address>>,
    /// When `Some`, sets `valid_before` on each transaction right before signing
    /// to keep it fresh for expiring nonces.
    expiry_secs: Option<u64>,
}

/// Returns an infinite stream of futures, each generating, signing, and encoding one transaction.
fn generate_transactions<F: TxFiller<TempoNetwork> + 'static>(
    signer_provider_manager: SignerProviderManager<F>,
    input: GenerateTransactionsInput,
    counters: TransactionCounters,
) -> impl Stream<Item = impl Future<Output = eyre::Result<Vec<u8>>>> {
    let GenerateTransactionsInput {
        tip20_weight,
        place_order_weight,
        swap_weight,
        erc20_weight,
        mpp_weight,
        quote_token,
        user_tokens,
        erc20_tokens,
        mpp_contract_address,
        chain_id,
        recipients,
        expiry_secs,
    } = input;

    const TX_TYPES: usize = 5;
    // Weights for random sampling for each transaction type
    let tx_weights: [u64; TX_TYPES] = [
        tip20_weight,
        swap_weight,
        place_order_weight,
        erc20_weight,
        mpp_weight,
    ];
    // Cached gas estimates for each transaction type
    let gas_estimates: [Arc<OnceLock<(u128, u128, u64)>>; TX_TYPES] = Default::default();
    // Global tx counter used to bump priority fee, ensuring unique tx hashes
    // when using expiring nonces (which share nonce=0).
    let tx_id = Arc::new(AtomicUsize::new(0));

    stream::repeat_with(move || {
        let signer_provider_manager = signer_provider_manager.clone();
        let gas_estimates = gas_estimates.clone();
        let tx_id = tx_id.clone();
        let recipients = recipients.clone();
        let user_tokens = user_tokens.clone();
        let erc20_tokens = erc20_tokens.clone();
        let counters = counters.clone();

        async move {
            let provider = signer_provider_manager.random_unsigned_provider();
            let signer = signer_provider_manager.random_signer();
            let token = user_tokens.choose(&mut rand::rng()).copied().unwrap();

            // TODO: can be improved with an enum per transaction type
            let tx_index = tx_weights
                .iter()
                .enumerate()
                .collect::<Vec<_>>()
                .choose_weighted(&mut rand::rng(), |(_, weight)| *weight)?
                .0;

            let recipient = match &recipients {
                Some(addrs) => *addrs.choose(&mut rand::rng()).unwrap(),
                None => Address::random(),
            };

            let mut tx = match tx_index {
                0 => {
                    counters.tip20_transfers.fetch_add(1, Ordering::Relaxed);
                    let token = ITIP20Instance::new(token, provider.clone());

                    // Transfer minimum possible amount
                    token
                        .transfer(recipient, U256::ONE)
                        .into_transaction_request()
                }
                1 => {
                    counters.swaps.fetch_add(1, Ordering::Relaxed);
                    let exchange =
                        IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

                    // Swap minimum possible amount
                    let quote_token =
                        quote_token.expect("quote_token must be set when swap_weight > 0");
                    exchange
                        .quoteSwapExactAmountIn(token, quote_token, 1)
                        .into_transaction_request()
                }
                2 => {
                    counters.orders.fetch_add(1, Ordering::Relaxed);
                    let exchange =
                        IStablecoinDEXInstance::new(STABLECOIN_DEX_ADDRESS, provider.clone());

                    // Place an order at a random tick that's a multiple of `TICK_SPACING`
                    let tick = random_range(MIN_TICK / TICK_SPACING..=MAX_TICK / TICK_SPACING)
                        * TICK_SPACING;
                    exchange
                        .place(token, MIN_ORDER_AMOUNT, true, tick)
                        .into_transaction_request()
                }
                3 => {
                    counters.erc20_transfers.fetch_add(1, Ordering::Relaxed);
                    let token_address = erc20_tokens.choose(&mut rand::rng()).copied().unwrap();
                    let token = erc20::MockERC20::new(token_address, provider.clone());

                    // Transfer minimum possible amount
                    token
                        .transfer(recipient, U256::ONE)
                        .into_transaction_request()
                }
                4 => {
                    counters.mpp_open_close.fetch_add(1, Ordering::Relaxed);
                    let contract = mpp_contract_address
                        .expect("mpp_channel_address must be set when mpp_weight > 0");

                    // Single Tempo tx with two calls: open a channel, then close it.
                    // Signer is both payer and payee, so close succeeds immediately.
                    let salt = B256::random();
                    let payer = signer.address();
                    let channel_id = mpp::compute_channel_id(
                        payer,
                        payer,
                        token,
                        salt,
                        Address::ZERO,
                        contract,
                        chain_id,
                    );
                    mpp::build_open_and_close(contract, payer, token, salt, channel_id)
                }
                _ => unreachable!("Only {TX_TYPES} transaction types are supported"),
            };

            // Get a random signer and set it as the sender of the transaction.
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
            let filled = provider.fill(tx).await?;

            // If we never filled the gas fields for that transaction type, cache the estimated
            // gas.
            if gas.get().is_none() {
                let _ = gas.set(match &filled {
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

            let mut req = filled.try_into_request()?;

            // Bump priority fee by a unique counter to ensure unique tx hashes
            // when using expiring nonces (which share nonce=0).
            let id = tx_id.fetch_add(1, Ordering::Relaxed) as u128;
            if let Some(fee) = req.max_priority_fee_per_gas() {
                req.inner.set_max_priority_fee_per_gas(fee + id);
            }
            if let Some(fee) = req.max_fee_per_gas() {
                req.inner.set_max_fee_per_gas(fee + id);
            }

            // Set valid_before right before signing to keep it fresh (expiring nonces only)
            if let Some(expiry_secs) = expiry_secs {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                req.set_valid_before(now + expiry_secs);
            }

            // Sign and encode
            let mut unsigned = req.build_unsigned()?;
            let sig = signer.sign_transaction_sync(unsigned.as_dyn_signable_mut())?;
            eyre::Ok(unsigned.into_envelope(sig).encoded_2718())
        }
    })
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
struct ProfilePhaseMetadata {
    name: String,
    target_tps: u64,
    duration_secs: u64,
    ramp: bool,
}

#[derive(Serialize)]
struct BenchmarkMetadata {
    max_tps: u64,
    expected_total_txs: u64,
    total_duration_secs: u64,
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
    erc20_weight: f64,
    mpp_weight: f64,
    phases: Vec<ProfilePhaseMetadata>,
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
    profile: &LoadProfile,
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

    let phases = profile
        .phases
        .iter()
        .map(|p| ProfilePhaseMetadata {
            name: p.name.clone(),
            target_tps: p.target_tps,
            duration_secs: p.duration.as_secs(),
            ramp: p.ramp,
        })
        .collect();

    let metadata = BenchmarkMetadata {
        max_tps: profile.max_tps(),
        expected_total_txs: profile.expected_total_txs(),
        total_duration_secs: profile.total_duration().as_secs(),
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
        erc20_weight: args.erc20_weight,
        mpp_weight: args.mpp_weight,
        phases,
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

async fn monitor_tps_profiled(
    counters: TransactionCounters,
    profile: LoadProfile,
    token: CancellationToken,
) {
    let mut last_count = 0;
    let mut ticker = interval(Duration::from_secs(1));
    let start = Instant::now();

    loop {
        select! {
            _ = ticker.tick() => {
                let elapsed = start.elapsed();
                let current_count = counters.sent.load(Ordering::Relaxed);
                let actual_tps = current_count - last_count;
                last_count = current_count;

                let target_tps = profile.tps_at(elapsed) as u64;
                let phase = profile.phase_at(elapsed).unwrap_or("done");

                info!(
                    actual_tps,
                    target_tps,
                    total = current_count,
                    phase,
                    elapsed_secs = elapsed.as_secs(),
                    "Status"
                );

                if elapsed >= profile.total_duration() {
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
    stream::iter(receipts)
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
