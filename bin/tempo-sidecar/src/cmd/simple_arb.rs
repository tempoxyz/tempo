use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{Filter, Log},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use clap::Parser;
use eyre::Context;
use itertools::Itertools;
use metrics::{counter, describe_counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt as _, Route, Server, get, listener::TcpListener};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    tip_fee_manager::ITIPFeeAMM::{self, Burn, ITIPFeeAMMInstance, Mint, RebalanceSwap},
    tip20_factory::ITIP20Factory,
};
use tempo_telemetry_util::error_field;
use tracing::{debug, error, info, instrument};

use crate::monitor;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct SimpleArbArgs {
    /// RPC endpoint for the node
    #[arg(short, long, required = true)]
    rpc_url: String,

    /// Private key of the tx sender
    #[arg(short, long, required = true)]
    private_key: String,

    /// Interval between checking pools for rebalancing. This should be set to the block time.
    #[arg(long, default_value_t = 2)]
    poll_interval: u64,

    /// Interval between full pool sweeps in seconds. Set to 0 to disable the fallback sweep.
    #[arg(long, default_value_t = 30)]
    full_rescan_interval: u64,

    /// Prometheus port for metrics
    #[arg(long, default_value_t = 8000)]
    metrics_port: u64,
}

#[instrument(skip(provider))]
async fn fetch_all_tokens<P: Provider>(provider: P) -> eyre::Result<HashSet<Address>> {
    let filter = Filter::new()
        .address(TIP20_FACTORY_ADDRESS)
        .event_signature(ITIP20Factory::TokenCreated::SIGNATURE_HASH);

    let logs = provider.get_logs(&filter).await?;

    let tokens: HashSet<Address> = logs
        .iter()
        .filter_map(|log| {
            log.log_decode::<ITIP20Factory::TokenCreated>()
                .ok()
                .map(|event| event.inner.token)
        })
        .collect();

    info!(token_count = tokens.len(), "Fetched TIP-20 tokens");

    Ok(tokens)
}

fn all_pairs(tokens: &HashSet<Address>) -> HashSet<(Address, Address)> {
    let mut pairs = HashSet::new();
    for pair in tokens.iter().permutations(2) {
        let (token_a, token_b) = (*pair[0], *pair[1]);
        pairs.insert((token_a, token_b));
    }
    pairs
}

struct ArbState {
    tokens: HashSet<Address>,
    pairs: HashSet<(Address, Address)>,
    dirty_pairs: HashSet<(Address, Address)>,
    last_processed_block: u64,
}

#[instrument(skip(provider))]
async fn init_state<P: Provider + Clone>(provider: P) -> eyre::Result<ArbState> {
    let tokens = fetch_all_tokens(provider.clone()).await?;
    let pairs = all_pairs(&tokens);
    let last_processed_block = provider.get_block_number().await?;

    info!(
        token_count = tokens.len(),
        pair_count = pairs.len(),
        last_processed_block,
        "Initialized arb state"
    );

    Ok(ArbState {
        tokens,
        dirty_pairs: pairs.clone(),
        pairs,
        last_processed_block,
    })
}

fn pair_from_fee_amm_log(log: &Log) -> Option<(Address, Address)> {
    let signature = *log.topics().first()?;
    if signature == Mint::SIGNATURE_HASH || signature == Burn::SIGNATURE_HASH {
        return Some((
            Address::from_word(*log.topics().get(2)?),
            Address::from_word(*log.topics().get(3)?),
        ));
    }

    if signature == RebalanceSwap::SIGNATURE_HASH {
        return Some((
            Address::from_word(*log.topics().get(1)?),
            Address::from_word(*log.topics().get(2)?),
        ));
    }

    None
}

#[instrument(skip(provider, state))]
async fn sync_state<P: Provider>(provider: P, state: &mut ArbState) -> eyre::Result<()> {
    let current_block = provider.get_block_number().await?;
    if current_block <= state.last_processed_block {
        return Ok(());
    }

    let from_block = state.last_processed_block + 1;

    let token_logs = provider
        .get_logs(
            &Filter::new()
                .address(TIP20_FACTORY_ADDRESS)
                .event_signature(ITIP20Factory::TokenCreated::SIGNATURE_HASH)
                .from_block(from_block)
                .to_block(current_block),
        )
        .await?;

    for log in token_logs {
        if let Ok(event) = log.log_decode::<ITIP20Factory::TokenCreated>() {
            let token = event.inner.token;
            if state.tokens.insert(token) {
                for existing in state.tokens.iter().copied().filter(|addr| *addr != token) {
                    state.pairs.insert((token, existing));
                    state.pairs.insert((existing, token));
                }
                info!(token = %token, pair_count = state.pairs.len(), "Discovered new TIP-20 token");
            }
        }
    }

    let pool_logs = provider
        .get_logs(
            &Filter::new()
                .address(TIP_FEE_MANAGER_ADDRESS)
                .from_block(from_block)
                .to_block(current_block),
        )
        .await?;

    let mut dirty_pairs_discovered = 0;
    for log in pool_logs {
        if let Some(pair) = pair_from_fee_amm_log(&log) {
            state.pairs.insert(pair);
            if state.dirty_pairs.insert(pair) {
                dirty_pairs_discovered += 1;
            }
        }
    }

    if dirty_pairs_discovered > 0 {
        counter!("tempo_arb_bot_dirty_pairs_discovered").increment(dirty_pairs_discovered as u64);
    }
    gauge!("tempo_arb_bot_dirty_pairs").set(state.dirty_pairs.len() as f64);
    state.last_processed_block = current_block;

    Ok(())
}

#[instrument(skip(provider))]
async fn rebalance_pair<P: Provider + Clone>(
    provider: P,
    pair: (Address, Address),
    signer_address: Address,
    poll_interval: u64,
) {
    let fee_amm: ITIPFeeAMMInstance<_, _> = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let pool = match fee_amm.getPool(pair.0, pair.1).call().await {
        Ok(pool) => pool,
        Err(e) => {
            error!(
                token_a = %pair.0,
                token_b = %pair.1,
                err = error_field(&e),
                "Failed to fetch pool"
            );
            counter!("tempo_arb_bot_failed_transactions", "error" => "fetch_pool").increment(1);
            return;
        }
    };

    if pool.reserveUserToken == 0 {
        return;
    }

    match fee_amm
        .rebalanceSwap(
            pair.0,
            pair.1,
            U256::from(pool.reserveUserToken),
            signer_address,
        )
        .send()
        .await
    {
        Ok(tx) => {
            match tokio::time::timeout(Duration::from_secs(poll_interval * 2), tx.get_receipt())
                .await
            {
                Ok(Ok(_)) => {
                    debug!(token_a = %pair.0, token_b = %pair.1, "Rebalance receipt received");
                    counter!("tempo_arb_bot_successful_transactions").increment(1);
                }
                Ok(Err(e)) => {
                    error!(
                        token_a = %pair.0,
                        token_b = %pair.1,
                        err = error_field(&e),
                        "Failed to get rebalance receipt"
                    );
                    counter!("tempo_arb_bot_failed_transactions", "error" => "fetch_receipt")
                        .increment(1);
                }
                Err(_) => {
                    error!(token_a = %pair.0, token_b = %pair.1, "Timeout waiting for tx receipt");
                    counter!("tempo_arb_bot_failed_transactions", "error" => "receipt_timeout")
                        .increment(1);
                }
            }
        }
        Err(e) => {
            error!(
                token_a = %pair.0,
                token_b = %pair.1,
                amount = %pool.reserveUserToken,
                err = error_field(&e),
                "Failed to send rebalance transaction"
            );
            counter!("tempo_arb_bot_failed_transactions", "error" => "tx_send").increment(1);
        }
    }
}

impl SimpleArbArgs {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        let builder = PrometheusBuilder::new();
        let metrics_handle = builder
            .install_recorder()
            .context("failed to install recorder")?;

        describe_counter!(
            "tempo_arb_bot_successful_transactions",
            "Number of successful transactions executed by the arb bot"
        );
        describe_counter!(
            "tempo_arb_bot_failed_transactions",
            "Number of failed transactions executed by the arb bot"
        );
        describe_counter!(
            "tempo_arb_bot_full_sweeps",
            "Number of fallback full sweeps executed by the arb bot"
        );
        describe_counter!(
            "tempo_arb_bot_dirty_pairs_discovered",
            "Number of dirty pools discovered from incremental scans"
        );

        let app = Route::new().at(
            "/metrics",
            get(monitor::prometheus_metrics).data(metrics_handle.clone()),
        );

        let addr = format!("0.0.0.0:{}", self.metrics_port);

        tokio::spawn(async move {
            Server::new(TcpListener::bind(addr))
                .run(app)
                .await
                .context("failed to run poem server")
        });

        let signer = PrivateKeySigner::from_slice(
            &hex::decode(&self.private_key).context("failed to decode private key")?,
        )
        .context("failed to parse private key")?;

        let signer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.rpc_url.parse().context("failed to parse RPC URL")?);

        let mut state = init_state(provider.clone()).await?;
        let mut last_full_sweep = Instant::now();

        loop {
            if let Err(e) = sync_state(provider.clone(), &mut state).await {
                error!(
                    err = error_field(&e),
                    "Failed to sync dirty pools from logs"
                );
            }

            if self.full_rescan_interval > 0
                && last_full_sweep.elapsed() >= Duration::from_secs(self.full_rescan_interval)
            {
                // `execute_fee_swap` updates pool reserves without emitting an AMM event, so the
                // fallback sweep keeps the bot eventually consistent even when log scanning misses
                // those reserve changes.
                state.dirty_pairs.extend(state.pairs.iter().copied());
                counter!("tempo_arb_bot_full_sweeps").increment(1);
                last_full_sweep = Instant::now();
                info!(
                    pair_count = state.pairs.len(),
                    "Scheduled fallback full sweep"
                );
            }

            let dirty_pairs: Vec<_> = state.dirty_pairs.drain().collect();
            gauge!("tempo_arb_bot_dirty_pairs").set(dirty_pairs.len() as f64);

            if dirty_pairs.is_empty() {
                debug!("No dirty pools discovered in this interval");
            } else {
                info!(
                    dirty_pair_count = dirty_pairs.len(),
                    "Rebalancing dirty pools"
                );
                for pair in dirty_pairs {
                    rebalance_pair(provider.clone(), pair, signer_address, self.poll_interval)
                        .await;
                }
            }

            tokio::time::sleep(Duration::from_secs(self.poll_interval)).await;
        }
    }
}
