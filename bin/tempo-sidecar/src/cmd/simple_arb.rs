use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use dashmap::DashMap;
use futures::StreamExt;
use std::{
    collections::HashSet,
    sync::Arc,
    time::Duration,
};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS, TIP20_FACTORY_ADDRESS,
    contracts::{
        ITIP20Factory, ITIPFeeAMM,
        ITIPFeeAMM::Pool,
        token_id_to_address,
    },
};
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

#[instrument(skip(signer))]
async fn fetch_all_tokens(rpc_url: &str, signer: Arc<EthereumWallet>) -> eyre::Result<HashSet<Address>> {
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .on_http(rpc_url.parse()?);

    let tip20_factory = ITIP20Factory::new(TIP20_FACTORY_ADDRESS, provider);
    let last_token_id = tip20_factory.tokenIdCounter().call().await?.to::<u64>();

    let tokens = (0..last_token_id)
        .map(token_id_to_address)
        .collect::<HashSet<_>>();

    info!("Fetched {} tokens", tokens.len());
    Ok(tokens)
}

#[instrument(skip(signer, tokens))]
async fn fetch_all_pools(
    rpc_url: &str,
    signer: Arc<EthereumWallet>,
    tokens: &HashSet<Address>
) -> eyre::Result<DashMap<(Address, Address), Pool>> {
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .on_http(rpc_url.parse()?);

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);
    let pools = DashMap::new();
    let token_vec: Vec<Address> = tokens.iter().copied().collect();

    for (i, &token_a) in token_vec.iter().enumerate() {
        for &token_b in token_vec.iter().skip(i + 1) {
            if let Ok(pool) = fee_amm.getPool(token_a, token_b).call().await {
                if pool.reserveUserToken > 0 || pool.reserveValidatorToken > 0 {
                    pools.insert((token_a, token_b), pool);
                    debug!("Found pool: {:?} <-> {:?}", token_a, token_b);
                }
            }
        }
    }

    info!("Fetched {} pools", pools.len());
    Ok(pools)
}

#[instrument(skip(signer, pools))]
async fn rebalance_pool(
    rpc_url: &str,
    signer: Arc<EthereumWallet>,
    token_a: Address,
    token_b: Address,
    pools: &DashMap<(Address, Address), Pool>
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .on_http(rpc_url.parse()?);

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

    // Get current pool state
    let pool = fee_amm.getPool(token_a, token_b).call().await?;

    // Simple rebalancing strategy: if reserves are imbalanced, perform rebalance
    let user_reserve = U256::from(pool.reserveUserToken);
    let validator_reserve = U256::from(pool.reserveValidatorToken);

    if user_reserve == U256::ZERO && validator_reserve == U256::ZERO {
        debug!("Pool has zero reserves, skipping rebalance");
        return Ok(());
    }

    // Calculate if rebalance is needed - check if user reserves are significantly higher
    let total_reserve = user_reserve + validator_reserve;
    if total_reserve == U256::ZERO {
        debug!("Total reserves are zero, skipping rebalance");
        return Ok(());
    }

    let user_ratio = user_reserve * U256::from(100) / total_reserve;
    let threshold = U256::from(60); // If user reserves > 60% of total, rebalance

    if user_ratio > threshold {
        info!("Rebalancing pool {:?}<->{:?}, user ratio: {}%", token_a, token_b, user_ratio);

        // Calculate amount to rebalance - take half of the excess
        let excess = user_reserve.saturating_sub(validator_reserve);
        let amount_out = excess / U256::from(2);

        if amount_out > U256::ZERO {
            let to_address = signer.default_signer().address();

            match fee_amm.rebalanceSwap(token_a, token_b, amount_out, to_address).send().await {
                Ok(tx_hash) => {
                    info!("Rebalance transaction sent: {:?}", tx_hash.tx_hash());

                    // Update local pool state
                    let updated_pool = fee_amm.getPool(token_a, token_b).call().await?;
                    pools.insert((token_a, token_b), updated_pool);
                }
                Err(e) => {
                    error!("Failed to send rebalance transaction: {}", e);
                }
            }
        }
    } else {
        debug!("Pool balance within threshold (user ratio: {}%), no rebalance needed", user_ratio);
    }

    Ok(())
}

#[instrument(skip(signer, pools))]
async fn listen_for_feeswaps(
    rpc_url: &str,
    signer: Arc<EthereumWallet>,
    pools: Arc<DashMap<(Address, Address), Pool>>,
    poll_interval: Duration,
) -> eyre::Result<()> {
    let provider = ProviderBuilder::new()
        .wallet(signer.clone())
        .on_http(rpc_url.parse()?);

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);

    let mut filter = fee_amm.FeeSwap_filter().watch().await?;
    filter.poller.set_poll_interval(poll_interval);
    let mut stream = filter.into_stream();

    info!("Starting to listen for FeeSwap events...");

    while let Some(log_result) = stream.next().await {
        match log_result {
            Ok((log, _)) => {
                info!(
                    "FeeSwap detected - User Token: {:?}, Validator Token: {:?}, Amount In: {}, Amount Out: {}",
                    log.userToken, log.validatorToken, log.amountIn, log.amountOut
                );

                if let Err(e) = rebalance_pool(
                    rpc_url,
                    signer.clone(),
                    log.userToken,
                    log.validatorToken,
                    &pools
                ).await {
                    error!("Failed to rebalance pool {:?}<->{:?}: {}", log.userToken, log.validatorToken, e);
                }
            }
            Err(e) => {
                warn!("Error receiving FeeSwap event: {}", e);
            }
        }
    }

    Ok(())
}

async fn run_simple_arb(rpc_url: String, private_key: String, poll_interval_ms: u64) -> eyre::Result<()> {
    info!("Starting Simple Arbitrage Bot...");

    let signer = PrivateKeySigner::from_slice(&hex::decode(&private_key)?)?;
    let wallet = EthereumWallet::from(signer);
    let wallet = Arc::new(wallet);
    let poll_interval = Duration::from_millis(poll_interval_ms);

    // Phase 1: Fetch all tokens
    info!("Fetching all tokens...");
    let tokens = fetch_all_tokens(&rpc_url, wallet.clone()).await?;

    // Phase 2: Fetch all pools
    info!("Fetching all pools...");
    let pools = fetch_all_pools(&rpc_url, wallet.clone(), &tokens).await?;
    let pools = Arc::new(pools);

    // Phase 3: Listen for feeswap events and rebalance
    info!("Starting event listener...");
    listen_for_feeswaps(&rpc_url, wallet, pools, poll_interval).await?;

    Ok(())
}

impl SimpleArbArgs {
    pub async fn run(self) -> eyre::Result<()> {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();

        run_simple_arb(self.rpc_url, self.private_key, self.poll_interval_ms).await
    }
}