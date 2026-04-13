use alloy::{
    consensus::transaction::TxHashRef,
    network::EthereumWallet,
    primitives::{
        Address, U256, address,
        private::{
            rand,
            rand::{RngCore, SeedableRng, rngs::StdRng},
        },
    },
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::TransactionRequest,
    signers::local::MnemonicBuilder,
};
use clap::{Parser, ValueEnum};
use eyre::{Context, Result};
use futures::StreamExt;
use rand_distr::{Distribution, Exp, Zipf};
use reqwest::Url;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_alloy::{
    TempoNetwork,
    primitives::{TempoHeader, TempoTxEnvelope},
    rpc::TempoTransactionRequest,
};
use tempo_precompiles::{TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::IFeeManager, tip20::ITIP20};
use tempo_telemetry_util::error_field;
use tokio::{signal, sync::Mutex};
use tracing::{debug, error, info, warn};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PaymentLaneScenario {
    PaymentsOnly,
    NonPaymentOnly,
    MixedLoad,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct PaymentLaneBenchArgs {
    #[arg(
        short,
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,

    #[arg(short, long, required = true)]
    rpc_url: Url,

    #[arg(long, required = true)]
    ws_url: Url,

    #[arg(long, default_value_t = 10)]
    wallet_count: usize,

    #[arg(long, default_value_t = 10)]
    average_tps: usize,

    #[arg(long, default_value_t = 60)]
    duration_secs: u64,

    #[arg(long, value_enum, default_value_t = PaymentLaneScenario::MixedLoad)]
    scenario: PaymentLaneScenario,

    #[arg(long, default_values_t = vec![address!("0x20C0000000000000000000000000000000000000")])]
    fee_token_addresses: Vec<Address>,

    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Default, Debug)]
struct BenchStats {
    submitted_payment_txs: u64,
    submitted_non_payment_txs: u64,
    observed_blocks: u64,
    observed_payment_txs: u64,
    observed_non_payment_txs: u64,
    observed_system_txs: u64,
    blocks_with_payment_txs: u64,
    blocks_with_non_payment_txs: u64,
    payment_latencies_secs: Vec<f64>,
    non_payment_latencies_secs: Vec<f64>,
}

impl BenchStats {
    fn record_block(&mut self, payment_txs: u64, non_payment_txs: u64, system_txs: u64) {
        self.observed_blocks += 1;
        self.observed_payment_txs += payment_txs;
        self.observed_non_payment_txs += non_payment_txs;
        self.observed_system_txs += system_txs;
        if payment_txs > 0 {
            self.blocks_with_payment_txs += 1;
        }
        if non_payment_txs > 0 {
            self.blocks_with_non_payment_txs += 1;
        }
    }
}

impl PaymentLaneBenchArgs {
    pub async fn run(self) -> Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(BenchStats::default()));

        let load_task = tokio::spawn(load_worker(
            self.mnemonic.clone(),
            self.rpc_url.clone(),
            self.wallet_count,
            self.average_tps,
            self.fee_token_addresses.clone(),
            self.scenario,
            self.seed,
            stop.clone(),
            stats.clone(),
        ));

        let monitor_task = tokio::spawn(monitor_worker(
            self.ws_url.clone(),
            stop.clone(),
            stats.clone(),
        ));

        let duration = tokio::time::sleep(Duration::from_secs(self.duration_secs));
        tokio::pin!(duration);

        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .context("failed to install SIGTERM handler")?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .context("failed to install SIGINT handler")?;

        tokio::select! {
            _ = &mut duration => info!("benchmark duration elapsed"),
            _ = sigterm.recv() => info!("received SIGTERM, stopping benchmark"),
            _ = sigint.recv() => info!("received SIGINT, stopping benchmark"),
        }

        stop.store(true, Ordering::Relaxed);

        let (load_result, monitor_result) = tokio::join!(load_task, monitor_task);
        if let Err(err) = load_result {
            error!(err = %err, "load worker task exited unexpectedly");
        }
        if let Err(err) = monitor_result {
            error!(err = %err, "monitor worker task exited unexpectedly");
        }

        let stats = stats.lock().await;
        report_summary(&stats, self.duration_secs, self.scenario);
        Ok(())
    }
}

async fn load_worker(
    mnemonic: String,
    rpc_url: Url,
    wallet_count: usize,
    average_tps: usize,
    fee_token_addresses: Vec<Address>,
    scenario: PaymentLaneScenario,
    seed: Option<u64>,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<BenchStats>>,
) -> Result<()> {
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::seed_from_u64(rand::rng().next_u64()),
    };

    let mut wallet = EthereumWallet::default();
    let mut addresses = Vec::new();
    for index in 0..wallet_count {
        let signer = MnemonicBuilder::from_phrase_nth(&mnemonic, index as u32);
        addresses.push(signer.address());
        wallet.register_signer(signer);
    }

    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(wallet)
        .connect_http(rpc_url.clone());

    if !matches!(scenario, PaymentLaneScenario::NonPaymentOnly) {
        let fee_token_zipf = Zipf::new(fee_token_addresses.len() as f64, 1.4)?;
        info!("setting fee tokens for benchmark wallets");
        for address in &addresses {
            let fee_token_address =
                zipf_vec_sample(&mut rng, fee_token_zipf, &fee_token_addresses)?;
            let fee_manager = IFeeManager::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
            if let Err(e) = fee_manager
                .setUserToken(*fee_token_address)
                .from(*address)
                .send()
                .await
            {
                warn!(
                    address = %address,
                    fee_token = %fee_token_address,
                    err = error_field(&e),
                    "failed to set fee token for benchmark wallet"
                );
            }
        }
    }

    let exp = Exp::new(average_tps as f64)?;
    let wallet_zipf = Zipf::new(wallet_count as f64, 1.4)?;
    let fee_token_zipf = Zipf::new(fee_token_addresses.len() as f64, 1.4)?;

    while !stop.load(Ordering::Relaxed) {
        let sender = *zipf_vec_sample(&mut rng, wallet_zipf, &addresses)?;
        let mut recipient = *zipf_vec_sample(&mut rng, wallet_zipf, &addresses)?;
        if recipient == sender {
            recipient = addresses[(addresses.len() + 1) % addresses.len()];
        }

        let tx_kind = match scenario {
            PaymentLaneScenario::PaymentsOnly => TxKind::Payment,
            PaymentLaneScenario::NonPaymentOnly => TxKind::NonPayment,
            PaymentLaneScenario::MixedLoad => {
                if rng.next_u32().is_multiple_of(2) {
                    TxKind::Payment
                } else {
                    TxKind::NonPayment
                }
            }
        };

        match tx_kind {
            TxKind::Payment => {
                let token_address =
                    *zipf_vec_sample(&mut rng, fee_token_zipf, &fee_token_addresses)?;
                let token = ITIP20::new(token_address, provider.clone());
                match token
                    .transfer(recipient, U256::from(10_u64))
                    .from(sender)
                    .send()
                    .await
                {
                    Ok(_) => {
                        stats.lock().await.submitted_payment_txs += 1;
                    }
                    Err(e) => {
                        warn!(
                            sender = %sender,
                            recipient = %recipient,
                            token = %token_address,
                            err = error_field(&e),
                            "failed to submit payment transaction"
                        );
                    }
                }
            }
            TxKind::NonPayment => {
                let request = TempoTransactionRequest {
                    inner: TransactionRequest::default()
                        .from(sender)
                        .to(recipient)
                        .value(U256::ZERO),
                    ..Default::default()
                };
                match provider.send_transaction(request).await {
                    Ok(_) => {
                        stats.lock().await.submitted_non_payment_txs += 1;
                    }
                    Err(e) => {
                        warn!(
                            sender = %sender,
                            recipient = %recipient,
                            err = error_field(&e),
                            "failed to submit non-payment transaction"
                        );
                    }
                }
            }
        }

        let delay = exp.sample(&mut rng);
        debug!(
            delay_secs = delay,
            "sleeping until next benchmark transaction"
        );
        tokio::time::sleep(Duration::from_secs_f64(delay)).await;
    }

    Ok(())
}

async fn monitor_worker(
    ws_url: Url,
    stop: Arc<AtomicBool>,
    stats: Arc<Mutex<BenchStats>>,
) -> Result<()> {
    let mut provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_ws(WsConnect::new(ws_url.to_string()))
        .await
        .context("failed to connect websocket provider")?;

    let mut pending_txs_sub = provider
        .subscribe_pending_transactions()
        .await
        .context("failed to subscribe to pending transactions")?;

    let mut block_subscription = provider
        .subscribe_full_blocks()
        .channel_size(1000)
        .into_stream()
        .await
        .context("failed to create block stream")?;

    let mut pending_seen_at: HashMap<alloy::primitives::B256, u128> = HashMap::new();
    let mut pending_stream = pending_txs_sub.into_stream();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        tokio::select! {
            maybe_hash = pending_stream.next() => {
                match maybe_hash {
                    Some(hash) => { pending_seen_at.entry(hash).or_insert_with(now_millis); }
                    None => {
                        warn!("pending transaction stream ended; reconnecting");
                        provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                            .connect_ws(WsConnect::new(ws_url.to_string()))
                            .await
                            .context("failed to reconnect websocket provider")?;
                        pending_txs_sub = provider
                            .subscribe_pending_transactions()
                            .await
                            .context("failed to resubscribe to pending transactions")?;
                        pending_stream = pending_txs_sub.into_stream();
                    }
                }
            }
            maybe_block = block_subscription.next() => {
                if let Some(Ok(block)) = maybe_block {
                    on_mined_block(
                        block.header.inner.into_consensus(),
                        block.transactions.txns(),
                        &mut pending_seen_at,
                        &stats,
                    ).await;
                }
            }
        }
    }

    Ok(())
}

async fn on_mined_block<'a>(
    header: TempoHeader,
    transactions: impl Iterator<Item = &'a alloy::rpc::types::Transaction<TempoTxEnvelope>>,
    pending_seen_at: &mut HashMap<alloy::primitives::B256, u128>,
    stats: &Arc<Mutex<BenchStats>>,
) {
    let mut payment_txs = 0_u64;
    let mut non_payment_txs = 0_u64;
    let mut system_txs = 0_u64;
    let landing_millis = header.timestamp_millis() as u128;

    let mut stats = stats.lock().await;

    for tx in transactions {
        if tx.inner.is_system_tx() {
            system_txs += 1;
            continue;
        }

        let latency = pending_seen_at
            .remove(tx.inner.tx_hash())
            .map(|seen_at| latency_seconds(seen_at, landing_millis));

        if tx.inner.is_payment_v2() {
            payment_txs += 1;
            if let Some(latency) = latency {
                stats.payment_latencies_secs.push(latency);
            }
        } else {
            non_payment_txs += 1;
            if let Some(latency) = latency {
                stats.non_payment_latencies_secs.push(latency);
            }
        }
    }

    stats.record_block(payment_txs, non_payment_txs, system_txs);
}

fn report_summary(stats: &BenchStats, duration_secs: u64, scenario: PaymentLaneScenario) {
    let payment_p50 = percentile(&stats.payment_latencies_secs, 0.50);
    let payment_p95 = percentile(&stats.payment_latencies_secs, 0.95);
    let non_payment_p50 = percentile(&stats.non_payment_latencies_secs, 0.50);
    let non_payment_p95 = percentile(&stats.non_payment_latencies_secs, 0.95);

    info!(
        scenario = ?scenario,
        duration_secs,
        submitted_payment_txs = stats.submitted_payment_txs,
        submitted_non_payment_txs = stats.submitted_non_payment_txs,
        observed_blocks = stats.observed_blocks,
        observed_payment_txs = stats.observed_payment_txs,
        observed_non_payment_txs = stats.observed_non_payment_txs,
        observed_system_txs = stats.observed_system_txs,
        blocks_with_payment_txs = stats.blocks_with_payment_txs,
        blocks_with_non_payment_txs = stats.blocks_with_non_payment_txs,
        payment_p50_secs = payment_p50,
        payment_p95_secs = payment_p95,
        non_payment_p50_secs = non_payment_p50,
        non_payment_p95_secs = non_payment_p95,
        "payment lane benchmark summary"
    );

    println!("scenario: {:?}", scenario);
    println!("duration_secs: {}", duration_secs);
    println!("submitted_payment_txs: {}", stats.submitted_payment_txs);
    println!(
        "submitted_non_payment_txs: {}",
        stats.submitted_non_payment_txs
    );
    println!("observed_blocks: {}", stats.observed_blocks);
    println!("observed_payment_txs: {}", stats.observed_payment_txs);
    println!(
        "observed_non_payment_txs: {}",
        stats.observed_non_payment_txs
    );
    println!("observed_system_txs: {}", stats.observed_system_txs);
    println!("blocks_with_payment_txs: {}", stats.blocks_with_payment_txs);
    println!(
        "blocks_with_non_payment_txs: {}",
        stats.blocks_with_non_payment_txs
    );
    println!("payment_latency_p50_secs: {:.4}", payment_p50);
    println!("payment_latency_p95_secs: {:.4}", payment_p95);
    println!("non_payment_latency_p50_secs: {:.4}", non_payment_p50);
    println!("non_payment_latency_p95_secs: {:.4}", non_payment_p95);
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index]
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn latency_seconds(seen_at_millis: u128, landing_millis: u128) -> f64 {
    landing_millis.saturating_sub(seen_at_millis) as f64 / 1000.0
}

fn zipf_vec_sample<'a, T>(rng: &mut StdRng, zipf: Zipf<f64>, items: &'a [T]) -> Result<&'a T> {
    let index = zipf.sample(rng) as u32 - 1;
    items
        .get(index as usize)
        .ok_or_else(|| eyre::eyre!("zipf out of bounds"))
}

#[derive(Clone, Copy)]
enum TxKind {
    Payment,
    NonPayment,
}
