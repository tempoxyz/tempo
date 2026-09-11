//! Command-line entry point for the independent mirror, auditor, profiler, and inspector.

use alloy::primitives::B256;
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tempo_replay::{
    audit::{AuditReader, AuditStore, Auditor, Expectation, Incident},
    config::{Checkpoint, Config, Endpoint},
    mirror::{Mirror, MirrorOccurrence, MirrorReader, MirrorStore},
    profile,
    source::{TempoProvider, block_hash, chain_id, finalized_stream},
    state::{OccurrenceId, atomic_json},
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "Mirror, audit, and profile finalized Tempo traffic")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Mirror exact signed transactions from finalized source blocks.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        to_block: Option<u64>,
    },
    /// Independently compare finalized source and shadow execution.
    Audit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        to_block: Option<u64>,
    },
    /// Produce an immutable workload profile for an exact finalized source range.
    Profile {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        from_block: u64,
        #[arg(long)]
        to_block: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Correlate durable submission and audit evidence.
    Inspect {
        #[arg(long)]
        mirror_state: PathBuf,
        #[arg(long)]
        audit_state: PathBuf,
        #[arg(long, conflicts_with = "source_block")]
        tx: Option<B256>,
        #[arg(long, requires = "index", conflicts_with = "tx")]
        source_block: Option<u64>,
        #[arg(long, requires = "source_block")]
        index: Option<u32>,
    },
}

#[derive(Serialize)]
struct Inspection {
    mirror_cursor: u64,
    audit_source_cursor: u64,
    audit_target_cursor: u64,
    records: Vec<InspectionRecord>,
}

#[derive(Serialize)]
struct InspectionRecord {
    occurrence: OccurrenceId,
    mirror: Option<MirrorOccurrence>,
    audit: Option<Expectation>,
    incidents: Vec<Incident>,
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

    match Cli::parse().command {
        Command::Run { config, to_block } => {
            let config = Config::load(&config)?;
            let (target_config, checkpoint, run) = config.run()?;
            ensure_end(to_block, checkpoint.height)?;
            install_metrics(run.metrics)?;
            let (source, target) = connect_checked(&config, target_config, checkpoint).await?;
            let path = run.store.state.clone();
            let identity = checkpoint.identity(config.chain_id);
            let max_bytes = run.store.max_bytes();
            let min_free_bytes = run.store.min_free_bytes();
            let store = tokio::task::spawn_blocking(move || {
                MirrorStore::open(&path, identity, max_bytes, min_free_bytes)
            })
            .await??;
            let cursor = store.state().source_cursor;
            let finalized = finalized_stream(source.clone(), config.chain_id, cursor.hash).await?;
            let state = Mirror {
                source,
                target,
                finalized,
                store: Arc::new(Mutex::new(store)),
                concurrency: run.concurrency(),
                retries: run.retries(),
                retry_delay: Duration::from_millis(run.retry_delay_ms()),
                retain_completed_blocks: run.retain_completed_blocks(),
                to_block,
            }
            .run(shutdown_token())
            .await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Command::Audit { config, to_block } => {
            let config = Config::load(&config)?;
            let (target_config, checkpoint, audit) = config.audit()?;
            ensure_end(to_block, checkpoint.height)?;
            install_metrics(audit.metrics)?;
            let (source, target) = connect_checked(&config, target_config, checkpoint).await?;
            let path = audit.store.state.clone();
            let identity = checkpoint.identity(config.chain_id);
            let max_bytes = audit.store.max_bytes();
            let min_free_bytes = audit.store.min_free_bytes();
            let store = tokio::task::spawn_blocking(move || {
                AuditStore::open(&path, identity, max_bytes, min_free_bytes)
            })
            .await??;
            let source_cursor = store.source_cursor();
            let target_cursor = store.target_cursor();
            let source_finalized =
                finalized_stream(source.clone(), config.chain_id, source_cursor.hash).await?;
            let target_finalized =
                finalized_stream(target.clone(), config.chain_id, target_cursor.hash).await?;
            let summary = Auditor {
                source,
                target,
                source_finalized,
                target_finalized,
                store: Arc::new(Mutex::new(store)),
                source_to_block: to_block,
                missing_after_blocks: audit.missing_after_blocks(),
                missing_after: audit.missing_after(),
                retain_included_blocks: audit.retain_included_blocks(),
                finality_stall: audit.finality_stall(),
                chain_id: config.chain_id,
            }
            .run(shutdown_token())
            .await?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Profile {
            config,
            from_block,
            to_block,
            output,
        } => {
            ensure!(from_block <= to_block, "invalid profile range");
            ensure!(
                from_block > 0,
                "profiling must start after a checkpoint block"
            );
            let config = Config::load(&config)?;
            let source = config.source.connect()?;
            ensure!(
                chain_id(&source).await? == config.chain_id,
                "source chain id mismatch"
            );
            let start_after = block_hash(&source, from_block - 1).await?;
            let finalized = finalized_stream(source.clone(), config.chain_id, start_after).await?;
            let report = profile::WorkloadProfile::profile(
                config.chain_id,
                source,
                finalized,
                from_block,
                to_block,
            )
            .await?;
            atomic_json(&output, &report)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Inspect {
            mirror_state,
            audit_state,
            tx,
            source_block,
            index,
        } => {
            ensure!(
                tx.is_some() || source_block.is_some(),
                "provide --tx or --source-block/--index"
            );
            let inspection = tokio::task::spawn_blocking(move || {
                inspect(&mirror_state, &audit_state, tx, source_block.zip(index))
            })
            .await??;
            println!("{}", serde_json::to_string_pretty(&inspection)?);
        }
    }
    Ok(())
}

fn inspect(
    mirror_path: &std::path::Path,
    audit_path: &std::path::Path,
    hash: Option<B256>,
    occurrence: Option<(u64, u32)>,
) -> Result<Inspection> {
    let mirror = MirrorReader::open(mirror_path)?;
    let audit = AuditReader::open(audit_path)?;
    let mirror_cursor = mirror.state()?.source_cursor.height;
    let (audit_source, audit_target) = audit.cursors()?;
    let audit_source_cursor = audit_source.height;
    let audit_target_cursor = audit_target.height;

    let records = if let Some(hash) = hash {
        let mut records = BTreeMap::new();
        for (id, record) in mirror.by_hash(hash)? {
            records.entry(id).or_insert((None, None)).0 = Some(record);
        }
        for (id, record) in audit.by_hash(hash)? {
            records.entry(id).or_insert((None, None)).1 = Some(record);
        }
        records
            .into_iter()
            .map(|(id, (mirror, audit_record))| inspection_record(&audit, id, mirror, audit_record))
            .collect::<Result<_>>()?
    } else if let Some((source_height, source_index)) = occurrence {
        let id = OccurrenceId {
            source_height,
            source_index,
        };
        vec![inspection_record(
            &audit,
            id,
            mirror.occurrence(id)?,
            audit.occurrence(id)?,
        )?]
    } else {
        Vec::new()
    };
    Ok(Inspection {
        mirror_cursor,
        audit_source_cursor,
        audit_target_cursor,
        records,
    })
}

fn inspection_record(
    audit_reader: &AuditReader,
    occurrence: OccurrenceId,
    mirror: Option<MirrorOccurrence>,
    audit: Option<Expectation>,
) -> Result<InspectionRecord> {
    const INCIDENT_WINDOW_MS: u64 = 5 * 60 * 1_000;
    let observed_at = audit
        .as_ref()
        .map(|expectation| expectation.observed_at_ms)
        .or_else(|| {
            mirror
                .as_ref()
                .map(|occurrence| occurrence.submission.started_at_ms)
        });
    let incidents = observed_at.map_or_else(
        || Ok(Vec::new()),
        |center| {
            audit_reader.incidents(
                center.saturating_sub(INCIDENT_WINDOW_MS),
                center.saturating_add(INCIDENT_WINDOW_MS),
            )
        },
    )?;
    Ok(InspectionRecord {
        occurrence,
        mirror,
        audit,
        incidents,
    })
}

fn install_metrics(address: Option<std::net::SocketAddr>) -> Result<()> {
    if let Some(address) = address {
        PrometheusBuilder::new()
            .with_http_listener(address)
            .install()
            .context("install Prometheus exporter")?;
    }
    Ok(())
}

async fn connect_checked(
    config: &Config,
    target: &Endpoint,
    checkpoint: &Checkpoint,
) -> Result<(TempoProvider, TempoProvider)> {
    let source = config.source.connect()?;
    let target = target.connect()?;
    check_endpoint(
        &source,
        config.chain_id,
        checkpoint.height,
        checkpoint.source_hash,
        "source",
    )
    .await?;
    check_endpoint(
        &target,
        config.chain_id,
        checkpoint.height,
        checkpoint.target_hash,
        "target",
    )
    .await?;
    Ok((source, target))
}

fn ensure_end(to_block: Option<u64>, checkpoint_height: u64) -> Result<()> {
    ensure!(
        to_block.is_none_or(|height| height > checkpoint_height),
        "end block must follow the checkpoint"
    );
    Ok(())
}

async fn check_endpoint(
    provider: &TempoProvider,
    expected_chain_id: u64,
    checkpoint_height: u64,
    expected_checkpoint: B256,
    name: &str,
) -> Result<()> {
    ensure!(
        chain_id(provider).await? == expected_chain_id,
        "{name} chain id mismatch"
    );
    ensure!(
        block_hash(provider, checkpoint_height).await? == expected_checkpoint,
        "{name} checkpoint hash mismatch"
    );
    Ok(())
}

fn shutdown_token() -> CancellationToken {
    let stop = CancellationToken::new();
    let signal = stop.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        signal.cancel();
    });
    stop
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_flags_remain_stable() {
        assert!(Cli::try_parse_from(["tempo-replay", "run", "--config", "replay.toml"]).is_ok());
        assert!(Cli::try_parse_from(["tempo-replay", "audit", "--config", "replay.toml"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "tempo-replay",
                "inspect",
                "--mirror-state",
                "mirror",
                "--audit-state",
                "audit",
                "--tx",
                "0x0000000000000000000000000000000000000000000000000000000000000000",
            ])
            .is_ok()
        );
    }
}
