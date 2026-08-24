//! Bootstrap support for the built-in Tempo development chain.

use std::time::Duration;

use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, U256, address, b256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use eyre::{Context, Result, bail, eyre};
use tempo_alloy::{TempoNetwork, fillers::FeeTokenFiller};
use tempo_contracts::precompiles::{IStablecoinDEX, ITIP20, ITIPFeeAMM};
use tempo_faucet::args::FaucetArgs;
use tempo_precompiles::{PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tokio::time::{sleep, timeout};

/// Well-known first development key used only for local bootstrap transactions.
const DEV_PRIVATE_KEY: B256 =
    b256!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
/// Amount of each canonical token, in base units, issued by one faucet request.
const FAUCET_AMOUNT: u128 = 1_000_000_000_000_000;
/// Validator-token liquidity, in base units, seeded into each fee AMM pool.
const FEE_LIQUIDITY: u128 = 1_000_000_000;
/// Fee-pool validator reserve below which bootstrap restores liquidity.
const MIN_FEE_RESERVE: u128 = 100_000_000;
/// Liquidity, in base units, seeded on each side of every DEX market.
const DEX_LIQUIDITY: u128 = 100_000_000_000;
/// Canonical development tokens: pathUSD, AlphaUSD, BetaUSD, and ThetaUSD.
const TOKENS: [Address; 4] = [
    address!("0x20c0000000000000000000000000000000000000"),
    address!("0x20c0000000000000000000000000000000000001"),
    address!("0x20c0000000000000000000000000000000000002"),
    address!("0x20c0000000000000000000000000000000000003"),
];

const MIN_RECEIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns the canonical faucet configuration installed by `--dev`.
pub(crate) fn faucet_args(rpc_url: String) -> FaucetArgs {
    FaucetArgs {
        enabled: true,
        private_key: Some(DEV_PRIVATE_KEY),
        amount: Some(U256::from(FAUCET_AMOUNT)),
        token_addresses: Some(TOKENS.to_vec()),
        node_address: rpc_url,
    }
}

/// Seeds the canonical Fee AMM pools and Stablecoin DEX markets if needed.
pub(crate) async fn bootstrap(rpc_url: &str, block_time: Option<Duration>) -> Result<()> {
    let signer = PrivateKeySigner::from_bytes(&DEV_PRIVATE_KEY)?;
    let admin = signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .filler(FeeTokenFiller::new(PATH_USD_ADDRESS))
        .wallet(signer)
        .connect_http(rpc_url.parse()?);

    wait_for_rpc(&provider).await?;

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider.clone());
    let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider.clone());
    let mut missing_fee_pools = Vec::new();
    let mut missing_orders = Vec::new();

    for token in TOKENS.into_iter().skip(1) {
        let pool = fee_amm.getPool(token, PATH_USD_ADDRESS).call().await?;
        if fee_pool_needs_repair(pool.reserveValidatorToken) {
            missing_fee_pools.push(token);
        }

        for is_bid in [true, false] {
            let has_liquidity = dex
                .getTickLevel(token, 0, is_bid)
                .call()
                .await
                .is_ok_and(|level| level.totalLiquidity > 0);
            if !has_liquidity {
                missing_orders.push((token, is_bid));
            }
        }
    }

    if missing_fee_pools.is_empty() && missing_orders.is_empty() {
        return Ok(());
    }

    for token in TOKENS {
        let hash = *ITIP20::new(token, provider.clone())
            .mint(admin, U256::from(FAUCET_AMOUNT))
            .send()
            .await
            .wrap_err_with(|| format!("failed to fund dev bootstrap account with {token}"))?
            .tx_hash();
        wait_for_receipt(&provider, hash, block_time).await?;
    }

    for token in missing_fee_pools {
        let hash = *fee_amm
            .mint(token, PATH_USD_ADDRESS, U256::from(FEE_LIQUIDITY), admin)
            .send()
            .await?
            .tx_hash();
        wait_for_receipt(&provider, hash, block_time).await?;

        let pool = fee_amm.getPool(token, PATH_USD_ADDRESS).call().await?;
        if fee_pool_needs_repair(pool.reserveValidatorToken) {
            bail!("fee liquidity for {token} remains below the minimum reserve");
        }
    }

    if !missing_orders.is_empty() {
        for token in TOKENS {
            let hash = *ITIP20::new(token, provider.clone())
                .approve(STABLECOIN_DEX_ADDRESS, U256::MAX)
                .send()
                .await?
                .tx_hash();
            wait_for_receipt(&provider, hash, block_time).await?;
        }

        for (token, is_bid) in missing_orders {
            let hash = *dex
                .place(token, DEX_LIQUIDITY, is_bid, 0)
                .send()
                .await?
                .tx_hash();
            wait_for_receipt(&provider, hash, block_time).await?;
        }
    }

    Ok(())
}

/// Waits until the RPC is reachable and the canonical liquidity is present.
pub async fn wait_until_ready(rpc_url: &str, seeded: bool) -> Result<()> {
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse()?);
    wait_for_rpc(&provider).await?;
    if !seeded {
        return Ok(());
    }

    for _ in 0..240 {
        if is_seeded(&provider).await {
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
    Err(eyre!("timed out waiting for Tempo dev bootstrap"))
}

async fn is_seeded(provider: &impl Provider<TempoNetwork>) -> bool {
    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, provider);
    let dex = IStablecoinDEX::new(STABLECOIN_DEX_ADDRESS, provider);
    for token in TOKENS.into_iter().skip(1) {
        let Ok(pool) = fee_amm.getPool(token, PATH_USD_ADDRESS).call().await else {
            return false;
        };
        if fee_pool_needs_repair(pool.reserveValidatorToken) {
            return false;
        }
        for is_bid in [true, false] {
            if !dex
                .getTickLevel(token, 0, is_bid)
                .call()
                .await
                .is_ok_and(|level| level.totalLiquidity > 0)
            {
                return false;
            }
        }
    }
    true
}

async fn wait_for_rpc(provider: &impl Provider<TempoNetwork>) -> Result<()> {
    for _ in 0..120 {
        if matches!(provider.get_chain_id().await, Ok(1337)) {
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
    Err(eyre!("timed out waiting for Tempo dev RPC"))
}

fn fee_pool_needs_repair(reserve: u128) -> bool {
    reserve < MIN_FEE_RESERVE
}

fn receipt_timeout(block_time: Option<Duration>) -> Duration {
    block_time
        .map(|interval| MIN_RECEIPT_TIMEOUT.max(interval.saturating_mul(4)))
        .unwrap_or(MIN_RECEIPT_TIMEOUT)
}

async fn wait_for_receipt(
    provider: &impl Provider<TempoNetwork>,
    hash: B256,
    block_time: Option<Duration>,
) -> Result<()> {
    match timeout(receipt_timeout(block_time), async {
        loop {
            if let Some(receipt) = provider.get_transaction_receipt(hash).await? {
                if receipt.status() {
                    return Ok(());
                }
                bail!("bootstrap transaction {hash} failed");
            }
            sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(eyre!("timed out waiting for bootstrap transaction {hash}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depleted_fee_pools_are_repaired_before_bootstrap() {
        for (reserve, needs_repair) in [
            (0, true),
            (MIN_FEE_RESERVE - 1, true),
            (MIN_FEE_RESERVE, false),
            (FEE_LIQUIDITY, false),
        ] {
            assert_eq!(fee_pool_needs_repair(reserve), needs_repair);
        }
    }

    #[test]
    fn receipt_timeout_accounts_for_slow_blocks() {
        assert_eq!(receipt_timeout(None), MIN_RECEIPT_TIMEOUT);
        assert_eq!(
            receipt_timeout(Some(Duration::from_secs(10))),
            Duration::from_secs(40)
        );
    }
}
