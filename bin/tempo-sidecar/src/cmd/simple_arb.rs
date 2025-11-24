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
use std::{collections::HashSet, time::Duration};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS, tip_fee_manager::ITIPFeeAMM,
    tip20::token_id_to_address, tip20_factory::ITIP20Factory,
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

    /// Prometheus port for metrics
    #[arg(long, default_value_t = 8000)]
    metrics_port: u64,
}

#[instrument(skip(provider))]
async fn fetch_all_pairs<P: Provider>(provider: P) -> eyre::Result<HashSet<(Address, Address)>> {
    let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider);
    let last_token_id = tip20_factory.tokenIdCounter().call().await?.to::<u64>();

    let tokens = (0..last_token_id)
        .map(token_id_to_address)
        .collect::<Vec<_>>();

    let mut pairs = HashSet::new();
    for pair in tokens.iter().permutations(2) {
        let (token_a, token_b) = (*pair[0], *pair[1]);
        pairs.insert((token_a, token_b));
    }

    info!(
        token_count = tokens.len(),
        pair_count = pairs.len(),
        "Fetched token pairs"
    );

    Ok(pairs)
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

        info!("Fetching all pairs...");
        let pairs = fetch_all_pairs(provider.clone()).await?;

        info!("Rebalancing initial pools...");
        for pair in pairs.iter() {
            // Get current pool state
            let pool = fee_amm
                .getPool(pair.0, pair.1)
                .call()
                .await
                .wrap_err_with(|| {
                    format!("failed to fetch pool for tokens {}, {}", pair.0, pair.1)
                })?;

            if pool.reserveUserToken > 0
                && let Err(e) = fee_amm
                    .rebalanceSwap(
                        pair.0,
                        pair.1,
                        U256::from(pool.reserveUserToken),
                        signer_address,
                    )
                    .send()
                    .await
            {
                error!(
                    token_a = %pair.0,
                    token_b = %pair.1,
                    amount = %pool.reserveUserToken,
                    err = error_field(&e),
                    "Failed to send initial rebalance transaction"
                );
            }
        }

        // NOTE: currently this is a very simple approach that checks all pools every `n`
        // milliseconds. While this should ensure pools are always balanced within a few blocks,
        // this can be updated to listen to events and only rebalance pools that have been swapped.
        loop {
            for pair in pairs.iter() {
                // Get current pool state
                let pool = fee_amm
                    .getPool(pair.0, pair.1)
                    .call()
                    .await
                    .wrap_err_with(|| {
                        format!("failed to fetch pool for tokens {:?}, {:?}", pair.0, pair.1)
                    })?;

                if pool.reserveUserToken > 0 {
                    let mut pending_txs = vec![];

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
                            pending_txs.push(tx);
                        }

                        Err(e) => {
                            error!(
                                token_a = %pair.0,
                                token_b = %pair.1,
                                amount = %pool.reserveUserToken,
                                err = error_field(&e),
                                "Failed to send rebalance transaction"
                            );

                            counter!("tempo_arb_bot_failed_transactions", "error" => "tx_send")
                                .increment(1);
                        }
                    }

                    // Await all receipts with timeout
                    for tx in pending_txs {
                        match tokio::time::timeout(
                            Duration::from_secs(self.poll_interval * 2),
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

            tokio::time::sleep(Duration::from_secs(self.poll_interval)).await;
            debug!("Polling interval elapsed, checking pools for rebalancing");
        }
    }
}
