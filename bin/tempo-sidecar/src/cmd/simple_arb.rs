use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, U256, uint},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use dashmap::DashMap;
use eyre::Context;
use futures::StreamExt;
use itertools::Itertools;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    contracts::{ITIP20Factory, ITIPFeeAMM, ITIPFeeAMM::Pool, token_id_to_address},
};
use tempo_telemetry_util::error_field;
use tracing::{debug, error, info, instrument, warn};

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
async fn fetch_all_tokens<P: Provider + Clone>(provider: P) -> eyre::Result<HashSet<Address>> {
    let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider);
    let last_token_id = tip20_factory.tokenIdCounter().call().await?.to::<u64>();

    let tokens = (0..last_token_id)
        .map(token_id_to_address)
        .collect::<HashSet<_>>();

    info!(count = tokens.len(), "Fetched tokens");

    Ok(tokens)
}

#[instrument(skip(provider, tokens))]
async fn fetch_all_pools<P: Provider + Clone>(
    provider: P,
    tokens: &HashSet<Address>,
) -> eyre::Result<DashMap<(Address, Address), Pool>> {
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);
    let pools = DashMap::new();
    let token_vec: Vec<Address> = tokens.iter().copied().collect();

    for token_combo in token_vec.iter().permutations(2) {
        let (&token_a, &token_b) = (token_combo[0], token_combo[1]);

        if let Ok(pool) = fee_amm.getPool(token_a, token_b).call().await {
            #[warn(clippy::collapsible_if)]
            if pool.reserveUserToken > 0 || pool.reserveValidatorToken > 0 {
                pools.insert((token_a, token_b), pool);
                debug!(
                    %token_a,
                    %token_b,
                    "Found pool",
                );
            }
        }
    }

    info!(count = pools.len(), "Fetched pools");

    Ok(pools)
}

#[instrument(skip(provider, pools))]
async fn rebalance_pool<P: Provider + Clone>(
    provider: P,
    signer: Arc<EthereumWallet>,
    token_a: Address,
    token_b: Address,
    pools: &DashMap<(Address, Address), Pool>,
) -> eyre::Result<()> {
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

    // Get current pool state
    let pool = fee_amm
        .getPool(token_a, token_b)
        .call()
        .await
        .wrap_err_with(|| format!("failed to fetch pool for tokens {token_a}, {token_b}"))?;

    // Simple rebalancing strategy: if reserves are imbalanced, perform rebalance
    let user_reserve = U256::from(pool.reserveUserToken);
    let validator_reserve = U256::from(pool.reserveValidatorToken);

    if user_reserve.is_zero() && validator_reserve.is_zero() {
        debug!("Pool has zero reserves, skipping rebalance");
        return Ok(());
    }

    let total_reserve = user_reserve + validator_reserve;
    let user_ratio = user_reserve * uint!(100_U256) / total_reserve;
    let threshold = uint!(60_U256); // If user reserves > 60% of total, rebalance

    if user_ratio > threshold {
        info!(
            %user_ratio,
            "Rebalancing pool"
        );

        // Calculate amount to rebalance - take half of the excess
        let excess = user_reserve.saturating_sub(validator_reserve);
        let amount_out = excess / uint!(2_U256);

        if !amount_out.is_zero() {
            let to_address = signer.default_signer().address();

            match fee_amm
                .rebalanceSwap(token_a, token_b, amount_out, to_address)
                .send()
                .await
            {
                Ok(tx) => {
                    info!(
                        tx_hash = tx.tx_hash().to_string(),
                        "Rebalance transaction sent",
                    );

                    // Update local pool state
                    let updated_pool = fee_amm
                        .getPool(token_a, token_b)
                        .call()
                        .await
                        .wrap_err_with(|| {
                            format!("failed to fetch pool for tokens {token_a},{token_b}")
                        })?;
                    pools.insert((token_a, token_b), updated_pool);
                }
                Err(e) => {
                    error!(
                        err = error_field(&e),
                        "Failed to send rebalance transaction"
                    );
                }
            }
        }
    } else {
        debug!(
            %user_ratio,
            "Pool balance within threshold, no rebalance needed",
        );
    }

    Ok(())
}

#[instrument(skip(provider, signer, pools))]
async fn listen_for_feeswaps<P: Provider + Clone>(
    provider: P,
    signer: Arc<EthereumWallet>,
    pools: Arc<DashMap<(Address, Address), Pool>>,
    poll_interval: Duration,
) -> eyre::Result<()> {
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());

    let mut filter = fee_amm
        .FeeSwap_filter()
        .watch()
        .await
        .context("failed to initialize fee swap filter")?;
    filter.poller.set_poll_interval(poll_interval);
    let mut stream = filter.into_stream();

    info!("Starting to listen for FeeSwap events...");

    while let Some(log_result) = stream.next().await {
        match log_result {
            Ok((log, _)) => {
                info!(
                    user_token = %log.userToken,
                    validator_token = %log.validatorToken,
                    amount_in = %log.amountIn,
                    amount_out = %log.amountOut,
                    "Fee swap detected",
                );

                if let Err(e) = rebalance_pool(
                    provider.clone(),
                    signer.clone(),
                    log.userToken,
                    log.validatorToken,
                    &pools,
                )
                .await
                {
                    error!(
                        user_token = %log.userToken,
                        validator_token = %log.validatorToken,
                        e = error_field(&e),
                        "Failed to rebalance pool"
                    );
                }
            }
            Err(e) => {
                warn!("Error receiving FeeSwap event: {e}");
            }
        }
    }

    Ok(())
}

async fn check_and_rebalance_all_pools<P: Provider + Clone>(
    provider: P,
    signer: Arc<EthereumWallet>,
    pools: &DashMap<(Address, Address), Pool>,
) -> eyre::Result<()> {
    info!("Checking all pools for imbalances...");

    let mut rebalanced_count = 0;
    for entry in pools.iter() {
        let ((token_a, token_b), _) = entry.pair();

        if let Err(e) =
            rebalance_pool(provider.clone(), signer.clone(), *token_a, *token_b, pools).await
        {
            warn!(
                %token_a,
                %token_b,
                error = error_field(&e),
                "Failed to check/rebalance pool"
            );
        } else {
            rebalanced_count += 1;
        }
    }

    info!("Initial rebalance check completed for {rebalanced_count} pools");
    Ok(())
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
        let wallet = EthereumWallet::from(signer);
        let wallet = Arc::new(wallet);
        let poll_interval = Duration::from_millis(self.poll_interval_ms);

        let provider = ProviderBuilder::new()
            .wallet(wallet.clone())
            .connect_http(self.rpc_url.parse().context("failed to parse RPC URL")?);

        info!("Fetching all tokens...");
        let tokens = fetch_all_tokens(provider.clone()).await?;

        info!("Fetching all pools...");
        let pools = fetch_all_pools(provider.clone(), &tokens).await?;
        let pools = Arc::new(pools);

        info!("Checking existing pools for imbalances...");
        check_and_rebalance_all_pools(provider.clone(), wallet.clone(), &pools).await?;

        info!("Starting event listener...");
        listen_for_feeswaps(provider, wallet, pools, poll_interval).await?;

        Ok(())
    }
}
