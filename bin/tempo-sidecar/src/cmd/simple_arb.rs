use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::Context;
use futures::StreamExt;
use itertools::Itertools;
use std::{collections::HashSet, time::Duration};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20Factory,
        ITIPFeeAMM::{self},
        token_id_to_address,
    },
};
use tempo_telemetry_util::error_field;
use tracing::{debug, error, info, instrument};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct SimpleArbArgs {
    #[arg(short, long, required = true)]
    rpc_url: String,

    #[arg(short, long, required = true)]
    private_key: String,

    #[arg(long, default_value_t = 200)]
    poll_interval_ms: u64,
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
                        "Failed to send rebalance transaction"
                    );
                }
            }

            tokio::time::sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }
    }
}
