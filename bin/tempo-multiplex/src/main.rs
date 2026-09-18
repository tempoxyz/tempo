mod config;
mod rpc;

use axum::{Router, extract::DefaultBodyLimit, routing::post};
use clap::Parser;
use config::Config;
use eyre::WrapErr;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

#[derive(Parser)]
#[command(
    version,
    about = "Run legacy and current Tempo nodes behind one JSON-RPC endpoint"
)]
struct Args {
    /// JSON configuration containing both child commands and the verified cutover.
    #[arg(long)]
    config: PathBuf,
}

fn spawn(backend: &config::Backend) -> eyre::Result<Child> {
    Command::new(&backend.binary)
        .args(&backend.args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .wrap_err_with(|| format!("start {}", backend.binary.display()))
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let config: Config = serde_json::from_slice(&std::fs::read(&args.config)?)?;
    config.validate()?;
    let mut v1 = spawn(&config.v1)?;
    let mut v2 = spawn(&config.v2)?;
    let rpc = rpc::Rpc::new(&config)?;
    // Bind only after identity and checkpoint validation. A port accepting traffic means ready.
    tokio::select! {
        ready = tokio::time::timeout(Duration::from_secs(120), rpc.wait_ready()) => ready??,
        result = v1.wait() => eyre::bail!("v1 exited during startup: {result:?}"),
        result = v2.wait() => eyre::bail!("v2 exited during startup: {result:?}"),
        _ = shutdown() => return Ok(()),
    }
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    eprintln!(
        "tempo-multiplex ready at http://{}; v2 starts at block {}",
        config.listen, config.cutover_block
    );
    let app = Router::new()
        .route("/", post(rpc::handle))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(rpc);
    let result = tokio::select! {
        result = axum::serve(listener, app) => result.map_err(Into::into),
        result = v1.wait() => Err(eyre::eyre!("v1 exited: {result:?}")),
        result = v2.wait() => Err(eyre::eyre!("v2 exited: {result:?}")),
        _ = shutdown() => Ok(()),
    };
    // Dropping either child also kills it if the other fails to start or validation fails.
    let _ = v1.kill().await;
    let _ = v2.kill().await;
    result
}
