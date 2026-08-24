//! Entrypoint for the batteries-included Tempo localnet container.

use std::{path::Path, process::ExitStatus, time::Duration};

use alloy::providers::{Provider, ProviderBuilder};
use clap::Parser;
use eyre::{Context, Result, bail, eyre};
use reth_cli_util::{parse_duration_from_secs_or_ms, parsers::format_duration_as_secs_or_ms};
use tempo_alloy::TempoNetwork;
use tokio::{
    process::{Child, Command},
    time::timeout,
};

/// Loopback RPC endpoint used by the bootstrapper and container health check.
const RPC_URL: &str = "http://127.0.0.1:8545";
/// Marker written only after the selected localnet bootstrap has completed.
const READY_FILE: &str = "/tmp/tempo-localnet-ready";
/// Maximum interval that keeps faucet expiring nonces safe.
const MAX_BLOCK_TIME: Duration = Duration::from_secs(5);
/// Maximum time allowed for all RPC readiness and liquidity setup.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
/// Grace period kept below Docker's default 10-second stop timeout.
const CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(8);
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

    let setup = timeout(
        BOOTSTRAP_TIMEOUT,
        tempo::dev::wait_until_ready(RPC_URL, !args.bare),
    );
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

    if args.bare {
        values.push("--dev.no-bootstrap".into());
    }

    values
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
    fn full_mode_relies_on_dev_bootstrap() {
        let args = node_args(&Args {
            bare: false,
            block_time: Duration::from_millis(200),
            health: false,
        });

        assert!(args.windows(2).any(|v| v == ["--dev.block-time", "200ms"]));
        assert!(!args.iter().any(|value| value.starts_with("--faucet")));
        assert!(!args.iter().any(|value| value == "--dev.no-bootstrap"));
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
    }

    #[test]
    fn bare_mode_omits_bootstrap_arguments() {
        let args = node_args(&Args {
            bare: true,
            block_time: Duration::from_secs(1),
            health: false,
        });

        assert!(!args.iter().any(|value| value.starts_with("--faucet")));
        assert!(args.iter().any(|value| value == "--dev.no-bootstrap"));
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
}
