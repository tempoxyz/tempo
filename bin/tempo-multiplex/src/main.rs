mod config;
mod rpc;
mod version;

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

async fn stop_child(child: &mut Child) {
    #[cfg(unix)]
    if let Some(id) = child.id() {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(id as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        if tokio::time::timeout(Duration::from_secs(10), child.wait())
            .await
            .is_ok()
        {
            return;
        }
    }
    let _ = child.kill().await;
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    let config: Config = serde_json::from_slice(&std::fs::read(&args.config)?)?;
    config.validate()?;
    let (v1_sha, v2_sha) = tokio::try_join!(
        version::node_sha(&config.v1.binary),
        version::node_sha(&config.v2.binary)
    )?;
    let rpc = rpc::Rpc::new(&config, [v1_sha, v2_sha])?;
    let mut v1 = spawn(&config.v1)?;
    let mut v2 = match spawn(&config.v2) {
        Ok(child) => child,
        Err(error) => {
            stop_child(&mut v1).await;
            return Err(error);
        }
    };
    // Bind only after identity and checkpoint validation. A port accepting traffic means ready.
    let startup = tokio::select! {
        ready = tokio::time::timeout(Duration::from_secs(120), rpc.wait_ready()) => ready.map_err(eyre::Report::from).and_then(|ready| ready),
        result = v1.wait() => Err(eyre::eyre!("v1 exited during startup: {result:?}")),
        result = v2.wait() => Err(eyre::eyre!("v2 exited during startup: {result:?}")),
        _ = shutdown() => Err(eyre::eyre!("interrupted during startup")),
    };
    if let Err(error) = startup {
        tokio::join!(stop_child(&mut v1), stop_child(&mut v2));
        return Err(error);
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
    tokio::join!(stop_child(&mut v1), stop_child(&mut v2));
    result
}
