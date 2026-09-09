//! Entrypoint for the batteries-included Tempo localnet container.

use std::{path::Path, process::ExitStatus, str::FromStr, time::Duration};

use alloy::{
    network::ReceiptResponse,
    primitives::{Address, B256, U256, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use reth_cli_util::{parse_duration_from_secs_or_ms, parsers::format_duration_as_secs_or_ms};
use tempo_alloy::{TempoNetwork, fillers::FeeTokenFiller};
use tempo_contracts::precompiles::{IStablecoinDEX, ITIP20, ITIPFeeAMM};
use tempo_precompiles::{PATH_USD_ADDRESS, STABLECOIN_DEX_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tokio::{
    process::{Child, Command},
    time::{sleep, timeout},
};

/// Loopback RPC endpoint used by the bootstrapper and container health check.
const RPC_URL: &str = "http://127.0.0.1:8545";
/// Marker written only after the selected localnet bootstrap has completed.
const READY_FILE: &str = "/tmp/tempo-localnet-ready";
/// Well-known first Anvil development key used only for local bootstrap transactions.
const DEV_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Amount of each canonical token, in base units, issued by one faucet request.
const FAUCET_AMOUNT: u128 = 1_000_000_000_000_000;
/// Validator-token liquidity, in base units, seeded into each fee AMM pool.
const FEE_LIQUIDITY: u128 = 1_000_000_000;
/// Fee-pool validator reserve below which bootstrap restores liquidity.
const MIN_FEE_RESERVE: u128 = 100_000_000;
/// Liquidity, in base units, seeded on each side of every DEX market.
const DEX_LIQUIDITY: u128 = 100_000_000_000;
/// Maximum interval that keeps faucet expiring nonces safe.
const MAX_BLOCK_TIME: Duration = Duration::from_secs(5);
/// Maximum time allowed for all RPC readiness and liquidity setup.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
/// Minimum time allowed for one transaction to receive a receipt.
const MIN_RECEIPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace period kept below Docker's default 10-second stop timeout.
const CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(8);
/// Canonical localnet tokens: pathUSD, AlphaUSD, BetaUSD, and ThetaUSD.
const TOKENS: [Address; 4] = [
    address!("0x20c0000000000000000000000000000000000000"),
    address!("0x20c0000000000000000000000000000000000001"),
    address!("0x20c0000000000000000000000000000000000002"),
    address!("0x20c0000000000000000000000000000000000003"),
];

#[derive(Debug, Parser)]
#[command(
    name = "tempo-localnet",
    about = "Run a fully bootstrapped Tempo development network"
)]
struct Args {
    /// Start only the node, without the faucet or liquidity bootstrap.
    #[arg(long)]
    bare: bool,

    /// Interval between blocks, for example 200ms or 1s.
    #[arg(long, default_value = "1s", value_parser = parse_block_time)]
    block_time: Duration,

    /// Check whether the localnet finished bootstrapping.
    #[arg(long, hide = true)]
    health: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.health {
        return health().await;
    }

    let _ = tokio::fs::remove_file(READY_FILE).await;
    let node_binary = std::env::current_exe()
        .wrap_err("failed to locate tempo-localnet")?
        .with_file_name("tempo");
    let mut child = Command::new(node_binary)
        .args(node_args(&args))
        .kill_on_drop(true)
        .spawn()
        .wrap_err("failed to start Tempo node")?;

    let setup = timeout(BOOTSTRAP_TIMEOUT, bootstrap(args.bare, args.block_time));
    tokio::pin!(setup);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    tokio::select! {
        result = &mut setup => result.wrap_err("localnet bootstrap timed out")??,
        status = child.wait() => return node_exit(status?),
        _ = &mut shutdown => return stop_child(&mut child).await,
    }

    tokio::fs::write(READY_FILE, b"ready\n")
        .await
        .wrap_err("failed to write localnet readiness marker")?;
    eprintln!(
        "Tempo localnet ready at {RPC_URL} ({})",
        if args.bare { "bare" } else { "full" }
    );

    tokio::select! {
        status = child.wait() => node_exit(status?),
        _ = &mut shutdown => stop_child(&mut child).await,
    }
}

fn parse_block_time(value: &str) -> std::result::Result<Duration, String> {
    let duration = parse_duration_from_secs_or_ms(value)
        .map_err(|_| format!("invalid block interval: {value}"))?;
    if duration.is_zero() {
        return Err("block interval must be greater than zero".into());
    }
    if duration > MAX_BLOCK_TIME {
        return Err(format!(
            "block interval must not exceed {}",
            format_duration_as_secs_or_ms(MAX_BLOCK_TIME)
        ));
    }
    Ok(duration)
}

fn node_args(args: &Args) -> Vec<String> {
    let mut values = vec![
        "node".into(),
        "--dev".into(),
        "--dev.block-time".into(),
        format_duration_as_secs_or_ms(args.block_time),
        "--datadir".into(),
        "/data".into(),
        "--tempo.bootnodes-endpoint".into(),
        "none".into(),
        "--disable-discovery".into(),
        "--no-persist-peers".into(),
        "--http".into(),
        "--http.addr".into(),
        "0.0.0.0".into(),
        "--http.port".into(),
        "8545".into(),
        "--http.api".into(),
        "all".into(),
        "--http.corsdomain".into(),
        "*".into(),
        "--builder.gaslimit".into(),
        "3000000000".into(),
    ];

    if !args.bare {
        values.extend([
            "--faucet.enabled".into(),
            "--faucet.private-key".into(),
            DEV_PRIVATE_KEY.into(),
            "--faucet.amount".into(),
            FAUCET_AMOUNT.to_string(),
            "--faucet.node-address".into(),
            RPC_URL.into(),
            "--faucet.address".into(),
        ]);
        values.extend(TOKENS.map(|token| token.to_string()));
    }

    values
}

async fn bootstrap(bare: bool, block_time: Duration) -> Result<()> {
    let signer = PrivateKeySigner::from_str(DEV_PRIVATE_KEY)?;
    let admin = signer.address();
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .filler(FeeTokenFiller::new(PATH_USD_ADDRESS))
        .wallet(signer)
        .connect_http(RPC_URL.parse()?);

    wait_for_rpc(&provider).await?;
    if bare {
        return Ok(());
    }

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

    let hashes: Vec<B256> = provider
        .raw_request("tempo_fundAddress".into(), [admin])
        .await
        .wrap_err("failed to fund the localnet bootstrap account")?;
    for hash in hashes {
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

fn fee_pool_needs_repair(reserve: u128) -> bool {
    reserve < MIN_FEE_RESERVE
}

async fn wait_for_rpc(provider: &impl Provider<TempoNetwork>) -> Result<()> {
    for _ in 0..120 {
        if matches!(provider.get_chain_id().await, Ok(1337)) {
            return Ok(());
        }
        sleep(Duration::from_millis(500)).await;
    }
    Err(eyre!("timed out waiting for Tempo localnet RPC"))
}

fn receipt_timeout(block_time: Duration) -> Duration {
    MIN_RECEIPT_TIMEOUT.max(block_time.saturating_mul(4))
}

async fn wait_for_receipt(
    provider: &impl Provider<TempoNetwork>,
    hash: B256,
    block_time: Duration,
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

async fn health() -> Result<()> {
    if !Path::new(READY_FILE).is_file() {
        bail!("localnet bootstrap is not complete");
    }
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(RPC_URL.parse()?);
    if provider.get_chain_id().await? != 1337 {
        bail!("unexpected localnet chain ID");
    }
    Ok(())
}

fn node_exit(status: ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(eyre!("Tempo node exited with {status}"))
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut interrupt = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn stop_child(child: &mut Child) -> Result<()> {
    let Some(id) = child.id() else {
        return Ok(());
    };

    #[cfg(unix)]
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(id as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .wrap_err("failed to stop Tempo node")?;

    #[cfg(not(unix))]
    child.start_kill().wrap_err("failed to stop Tempo node")?;

    match timeout(CHILD_STOP_TIMEOUT, child.wait()).await {
        Ok(status) => {
            status?;
            Ok(())
        }
        Err(_) => {
            child.start_kill().wrap_err("failed to kill Tempo node")?;
            child.wait().await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_mode_enables_faucet_for_all_canonical_tokens() {
        let args = node_args(&Args {
            bare: false,
            block_time: Duration::from_millis(200),
            health: false,
        });

        assert!(args.windows(2).any(|v| v == ["--dev.block-time", "200ms"]));
        assert!(args.iter().any(|value| value == "--faucet.enabled"));
        assert!(
            args.windows(2)
                .any(|v| v == ["--tempo.bootnodes-endpoint", "none"])
        );
        assert!(args.iter().any(|value| value == "--disable-discovery"));
        assert!(args.iter().any(|value| value == "--no-persist-peers"));
        assert!(
            !args
                .iter()
                .any(|value| value == "--engine.disable-precompile-cache")
        );
        for token in TOKENS {
            assert!(args.iter().any(|value| value == &token.to_string()));
        }
    }

    #[test]
    fn bare_mode_omits_bootstrap_arguments() {
        let args = node_args(&Args {
            bare: true,
            block_time: Duration::from_secs(1),
            health: false,
        });

        assert!(!args.iter().any(|value| value.starts_with("--faucet")));
        assert!(args.windows(2).any(|v| v == ["--datadir", "/data"]));
    }

    #[test]
    fn block_time_is_bounded_for_expiring_faucet_nonces() {
        for value in ["1ms", "200ms", "1s", "5s"] {
            assert!(parse_block_time(value).is_ok(), "{value} should be valid");
        }
        for value in ["0", "0ms", "5001ms", "6s", "invalid"] {
            assert!(
                parse_block_time(value).is_err(),
                "{value} should be rejected"
            );
        }
    }

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
}
