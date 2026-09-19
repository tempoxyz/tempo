use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempo_replay::{
    capture,
    config::Config,
    engine,
    journal::{Journal, SharedJournal, lock},
    metrics, profile, verify,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "Mirror finalized Tempo transaction traffic to verified independent shadow validators"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Capture only; never submits a transaction. Use --from-block for a new journal.
    Capture {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        from_block: Option<u64>,
        #[arg(long)]
        to_block: Option<u64>,
    },
    /// Summarize a captured interval for capacity and compatibility qualification.
    Profile {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        from_block: Option<u64>,
        #[arg(long)]
        to_block: Option<u64>,
    },
    /// Read-only deployment, identity, finality recovery and workload checks.
    Verify {
        #[arg(long)]
        config: PathBuf,
    },
    /// Mirror from a source height, catch up, then follow finalized traffic until stopped.
    Run {
        #[arg(long)]
        config: PathBuf,
        /// First source block to mirror (inclusive); defaults to fork checkpoint + 1.
        #[arg(long)]
        from_block: Option<u64>,
        /// Optional end height for a bounded replay; omitted for continuous live mirroring.
        #[arg(long)]
        to_block: Option<u64>,
        #[arg(long)]
        acknowledge_incident: bool,
    },
    /// Read durable counters and independent progress cursors, including while running.
    Status {
        #[arg(long)]
        journal: PathBuf,
    },
    /// Inspect every captured occurrence of a transaction hash.
    Inspect {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        tx: String,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tempo_replay=info".into()),
        )
        .json()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Profile {
            journal,
            output,
            from_block,
            to_block,
        } => {
            let j = Journal::read(&journal)?;
            let p = profile::profile(&j, from_block, to_block)?;
            write_json(&output, &p)?;
            println!("{}", serde_json::to_string_pretty(&p)?);
        }
        Command::Status { journal } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Journal::read(&journal)?.state)?
            );
        }
        Command::Inspect { journal, tx } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Journal::read(&journal)?.inspect(&tx)?)?
            );
        }
        Command::Verify { config } => {
            let c = Config::load(&config)?;
            let source = verify::source_rpc(&c)?;
            tokio::select! { r = verify::verify(&c, &source) => { let (_, report) = r?; println!("{}", serde_json::to_string_pretty(&report)?); }, _ = shutdown_signal() => {} }
        }
        Command::Capture {
            config,
            from_block,
            to_block,
        } => {
            let c = Config::load(&config)?;
            ensure!(
                from_block.is_some()
                    || c.checkpoint.is_some()
                    || c.journal.path.join("db").exists(),
                "new capture requires --from-block or a checkpoint"
            );
            let j = Arc::new(Mutex::new(Journal::open(&c, from_block)?));
            let source = verify::source_rpc(&c)?;
            ensure!(
                source.chain_id().await? == c.run.chain_id,
                "source chain id mismatch"
            );
            supervise(c.clone(), j.clone(), async move |stop| {
                capture::capture_loop(c, source, j, to_block, stop).await
            })
            .await?;
        }
        Command::Run {
            config,
            from_block,
            to_block,
            acknowledge_incident,
        } => {
            let c = Config::load(&config)?;
            c.replay()?;
            let j = Arc::new(Mutex::new(Journal::open_replay(&c, from_block, to_block)?));
            let first = c.checkpoint.as_ref().unwrap().source_height + 1;
            tracing::info!(
                from_block = first,
                to_block,
                continuous = to_block.is_none(),
                "starting traffic mirror; existing journal progress resumes automatically"
            );
            let source = verify::source_rpc(&c)?;
            supervise(c.clone(), j.clone(), async move |stop| {
                let capture_stop = stop.child_token();
                let capture_journal = j.clone(); let capture_config = c.clone(); let capture_source = source.clone();
                let mut capture_task = tokio::spawn(capture::capture_loop(capture_config, capture_source, capture_journal, None, capture_stop.clone()));
                let mut capture_joined = false;
                let replay_result = async {
                    let qualified = tokio::select! {
                        r = verify::verify_live(&c, &source) => {
                            let (q, report) = r?;
                            for warning in &report.warnings { tracing::warn!(message = %warning, "startup verification note"); }
                            lock(&j)?.put("meta/verification", &report)?;
                            q
                        },
                        r = &mut capture_task => { capture_joined = true; r??; anyhow::bail!("capture stopped during verification"); },
                        _ = stop.cancelled() => return Ok(()),
                    };
                    let mut replay_future = Box::pin(engine::replay(c, qualified, source, j.clone(), to_block, acknowledge_incident, stop.clone()));
                    tokio::select! {
                        r = &mut replay_future => r,
                        r = &mut capture_task => { capture_joined = true; stop.cancel(); let _ = replay_future.await; r??; Ok(()) },
                    }
                }.await;
                capture_stop.cancel();
                if !capture_joined { let capture_result = capture_task.await.context("capture task panicked")?; if replay_result.is_ok() { capture_result?; } }
                replay_result
            }).await?;
        }
    }
    Ok(())
}
async fn supervise<F, Fut>(c: Config, journal: SharedJournal, work: F) -> Result<()>
where
    F: FnOnce(CancellationToken) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let stop = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind(&c.metrics.listen)
        .await
        .context("bind metrics listener")?;
    let mut metrics_task = tokio::spawn(metrics::serve(
        listener,
        journal.clone(),
        c.metrics,
        stop.clone(),
    ));
    let mut future = Box::pin(work(stop.clone()));
    let mut metrics_joined = false;
    let result = tokio::select! {
        r = &mut future => r,
        _ = shutdown_signal() => { stop.cancel(); future.await },
        r = &mut metrics_task => { metrics_joined = true; stop.cancel(); let _ = future.await; match r { Ok(Ok(())) => Err(anyhow::anyhow!("metrics listener stopped")), Ok(Err(e)) => Err(e), Err(e) => Err(e.into()) } },
    };
    stop.cancel();
    if !metrics_joined {
        metrics_task.await.context("metrics task panicked")??;
    }
    lock(&journal)?.flush()?;
    result
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} };
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
fn write_json(path: &std::path::Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_from_height_is_continuous_by_default() {
        let cli = Cli::try_parse_from([
            "tempo-replay",
            "run",
            "--config",
            "mirror.toml",
            "--from-block",
            "101",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Run {
                from_block: Some(101),
                to_block: None,
                ..
            }
        ));
    }
    #[test]
    fn run_can_resume_without_repeating_the_height() {
        let cli = Cli::try_parse_from(["tempo-replay", "run", "--config", "mirror.toml"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Run {
                from_block: None,
                to_block: None,
                ..
            }
        ));
    }
}
