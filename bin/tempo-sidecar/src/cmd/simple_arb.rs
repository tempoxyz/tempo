use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::Context;
use itertools::Itertools;
use metrics::{counter, describe_counter};
use metrics_exporter_prometheus::PrometheusBuilder;
use poem::{EndpointExt as _, Route, Server, get, listener::TcpListener};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{collections::HashSet, time::Duration};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    tip_fee_manager::ITIPFeeAMM::{self, ITIPFeeAMMInstance},
    tip20::token_id_to_address,
    tip20_factory::ITIP20Factory,
};
use tempo_telemetry_util::error_field;
use tracing::{debug, error, info, instrument};

use crate::monitor;

/// Duration in seconds to mute a token after an InsufficientBalance error
const TOKEN_MUTE_DURATION_SECS: u64 = 300; // 5 minutes

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

    /// Prometheus port for metrics
    #[arg(long, default_value_t = 8000)]
    metrics_port: u64,

    /// Token address to include (can be specified multiple times, if not provided all tokens will be fetched)
    #[arg(long)]
    token: Vec<String>,
}

#[derive(PartialEq, Eq, Hash)]
struct Pair {
    pub token_a: Address,
    pub token_b: Address,
}

#[instrument(skip(provider))]
async fn fetch_all_pairs<P: Provider>(
    provider: P,
    token_filter: Option<Vec<Address>>,
) -> eyre::Result<HashSet<Pair>> {
    let tokens = if let Some(filter) = token_filter {
        filter
    } else {
        let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider);
        let last_token_id = tip20_factory.tokenIdCounter().call().await?.to::<u64>();

        (0..last_token_id)
            .map(token_id_to_address)
            .collect::<Vec<_>>()
    };

    let mut pairs = HashSet::new();
    for pair in tokens.iter().permutations(2) {
        let (token_a, token_b) = (*pair[0], *pair[1]);
        pairs.insert(Pair { token_a, token_b });
    }

    info!(
        token_count = tokens.len(),
        pair_count = pairs.len(),
        "Fetched token pairs"
    );

    Ok(pairs)
}

async fn initial_rebalance<P: Provider>(
    fee_amm: &ITIPFeeAMMInstance<P>,
    pairs: &HashSet<Pair>,
    signer_address: &Address,
) -> eyre::Result<()> {
    for pair in pairs.iter() {
        // Get current pool state
        let pool = fee_amm
            .getPool(pair.token_a, pair.token_b)
            .call()
            .await
            .wrap_err_with(|| {
                format!(
                    "failed to fetch pool for tokens {}, {}",
                    pair.token_a, pair.token_b
                )
            })?;

        if pool.reserveUserToken > 0
            && let Err(e) = fee_amm
                .rebalanceSwap(
                    pair.token_a,
                    pair.token_b,
                    U256::from(pool.reserveUserToken),
                    *signer_address,
                )
                .send()
                .await
        {
            error!(
                token_a = %pair.token_a,
                token_b = %pair.token_b,
                amount = %pool.reserveUserToken,
                err = error_field(&e),
                "Failed to send initial rebalance transaction"
            );
        }
    }
    Ok(())
}

async fn continue_rebalancing<P: Provider>(
    fee_amm: &ITIPFeeAMMInstance<P>,
    pairs: &HashSet<Pair>,
    signer_address: &Address,
    poll_interval: u64,
) -> eyre::Result<()> {
    // if there was insufficient balance for a token it's added to muted map so rebalances will be skipped until stored timestamp
    let mut muted: HashMap<Address, u64> = HashMap::new();

    // NOTE: currently this is a very simple approach that checks all pools every `n`
    // milliseconds. While this should ensure pools are always balanced within a few blocks,
    // this can be updated to listen to events and only rebalance pools that have been swapped.
    loop {
        let mut pools_to_rebalance = 0;
        let mut errors = 0;

        // Clean up expired muted entries
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        muted.retain(|_, &mut unmute_time| unmute_time > current_time);

        for pair in pairs.iter() {
            // Check if token is muted
            if let Some(&unmute_time) = muted.get(&pair.token_b) {
                if unmute_time > current_time {
                    debug!(
                        token = %pair.token_b,
                        unmute_time = unmute_time,
                        "Skipping muted token"
                    );
                    continue;
                }
            }

            // Get current pool state
            let pool = fee_amm
                .getPool(pair.token_a, pair.token_b)
                .call()
                .await
                .wrap_err_with(|| {
                    format!(
                        "failed to fetch pool for tokens {:?}, {:?}",
                        pair.token_a, pair.token_b
                    )
                })?;

            if pool.reserveUserToken > 0 {
                pools_to_rebalance += 1;
                let mut pending_txs = vec![];

                match fee_amm
                    .rebalanceSwap(
                        pair.token_a,
                        pair.token_b,
                        U256::from(pool.reserveUserToken),
                        *signer_address,
                    )
                    .send()
                    .await
                {
                    Ok(tx) => {
                        pending_txs.push(tx);
                    }

                    Err(e) => {
                        errors += 1;
                        let error_msg = format!("{:?}", e);

                        error!(
                            token_a = %pair.token_a,
                            token_b = %pair.token_b,
                            amount = %pool.reserveUserToken,
                            err = error_field(&e),
                            "Failed to send rebalance transaction"
                        );

                        counter!("tempo_arb_bot_failed_transactions", "error" => "tx_send")
                            .increment(1);

                        // If this is an InsufficientBalance error, add token to muted list
                        if error_msg.contains("InsufficientBalance") {
                            let unmute_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                                + TOKEN_MUTE_DURATION_SECS;

                            muted.insert(pair.token_b, unmute_time);

                            info!(
                                token = %pair.token_b,
                                unmute_time = unmute_time,
                                "Token muted due to InsufficientBalance error"
                            );
                        }
                    }
                }

                // Await all receipts with timeout
                for tx in pending_txs {
                    match tokio::time::timeout(
                        Duration::from_secs(poll_interval * 2),
                        tx.get_receipt(),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            debug!("Tx receipt received successfully");
                            counter!("tempo_arb_bot_successful_transactions").increment(1);
                        }
                        Ok(Err(e)) => {
                            error!(err = error_field(&e), "Failed to get tx receipt");
                            counter!("tempo_arb_bot_failed_transactions", "error" => "fetch_receipt")
                                    .increment(1);
                        }
                        Err(_) => {
                            error!("Timeout waiting for tx receipt");
                            counter!("tempo_arb_bot_failed_transactions", "error" => "receipt_timeout")
                                    .increment(1);
                        }
                    }
                }
            }
        }
        debug!(
            "Found {} pools to rebalance, failed times: {}",
            pools_to_rebalance, errors
        );

        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
        debug!("Polling interval elapsed, checking pools for rebalancing");
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

        let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

        // Parse token addresses if provided
        let token_filter = if !self.token.is_empty() {
            let tokens = self
                .token
                .iter()
                .map(|s| s.parse::<Address>())
                .collect::<Result<Vec<_>, _>>()
                .context("failed to parse token addresses")?;
            Some(tokens)
        } else {
            None
        };

        info!("Fetching all pairs...");
        let pairs = fetch_all_pairs(provider.clone(), token_filter).await?;

        info!("Rebalancing initial pools...");
        initial_rebalance(&fee_amm, &pairs, &signer_address).await?;
        info!("Starting to rebalance pools periodically");
        continue_rebalancing(&fee_amm, &pairs, &signer_address, self.poll_interval).await?;
        Ok(())
    }
}
