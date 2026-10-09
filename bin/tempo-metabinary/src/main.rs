use alloy_primitives::{B256, U64};
use clap::{Parser, Subcommand};
use eyre::{Context, OptionExt, Result, ensure};
use jsonrpsee::{core::client::ClientT, http_client::HttpClient};
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tempo_metabinary::{
    catalog::ReleaseEra,
    manifest::{Bootstrap, Manifest},
    process::{shutdown_children, shutdown_signal, spawn_bootstrap},
    workers::{DEFAULT_STARTUP_TIMEOUT_SECS, HistoricalWorkers, WorkerContext},
};
use tokio::process::Child;
use tracing::info;

#[derive(Debug, Parser)]
#[command(about = "Replay canonical block files through frozen Tempo execution eras")]
struct Cli {
    #[arg(long)]
    manifest: PathBuf,
    /// Time allowed for each checkpoint worker to become ready.
    #[arg(long, global = true, default_value_t = DEFAULT_STARTUP_TIMEOUT_SECS)]
    startup_timeout_secs: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Replay canonical block files from genesis through the historical eras.
    Bootstrap,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let manifest = Manifest::load(&cli.manifest)?;
    let mut import = None;
    let mut readers = None;
    let result = tokio::select! {
        result = bootstrap(
            &manifest,
            Duration::from_secs(cli.startup_timeout_secs),
            &mut import,
            &mut readers,
        ) => result,
        result = shutdown_signal() => result,
    };
    let shutdown = match readers {
        Some(readers) => readers.shutdown().await,
        None => Ok(()),
    };
    let shutdown = match import {
        Some(mut child) => shutdown.and(shutdown_children([("bootstrap", &mut child)]).await),
        None => shutdown,
    };
    result.and(shutdown)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Header {
    number: U64,
    hash: B256,
    parent_hash: B256,
    timestamp: U64,
}

async fn verify_successor(client: &HttpClient, checkpoint: &Bootstrap, start: u64) -> Result<()> {
    let first_number = checkpoint
        .terminal_block_number
        .checked_add(1)
        .ok_or_eyre("terminal block number overflows")?;
    let first: Option<Header> = client
        .request("eth_getBlockByNumber", (U64::from(first_number), false))
        .await?;
    let first = first.ok_or_eyre("successor header is missing after bootstrap")?;
    ensure!(
        first.parent_hash == checkpoint.terminal_block_hash,
        "successor does not extend the pinned handoff block"
    );
    ensure!(
        first.timestamp.to::<u64>() >= start,
        "bootstrap ended before the successor era boundary"
    );
    Ok(())
}

async fn verify_checkpoint(
    client: &HttpClient,
    checkpoint: &Bootstrap,
    start: u64,
    end: u64,
    exact_head: bool,
) -> Result<()> {
    let block: Option<Header> = client
        .request(
            "eth_getBlockByNumber",
            (U64::from(checkpoint.terminal_block_number), false),
        )
        .await?;
    let block = block.ok_or_eyre("bootstrap checkpoint is missing")?;
    ensure!(
        block.number.to::<u64>() == checkpoint.terminal_block_number,
        "bootstrap checkpoint is missing"
    );
    ensure!(
        block.hash == checkpoint.terminal_block_hash,
        "bootstrap canonical checkpoint hash mismatch"
    );
    ensure!(
        (start..end).contains(&block.timestamp.to::<u64>()),
        "bootstrap checkpoint is outside its era"
    );
    if exact_head {
        let head: Header = client
            .request("eth_getBlockByNumber", ("latest", false))
            .await?;
        ensure!(
            head.hash == block.hash,
            "bootstrap did not stop at its pinned checkpoint"
        );
    }
    Ok(())
}

async fn bootstrap(
    manifest: &Manifest,
    timeout: Duration,
    import: &mut Option<Child>,
    readers: &mut Option<Arc<HistoricalWorkers>>,
) -> Result<()> {
    let context = WorkerContext {
        chain: manifest.chain.clone(),
        datadir: manifest.datadir.clone(),
        static_files_path: None,
        rocksdb_path: None,
        rpc_config: None,
        chain_id: manifest.chain_id,
        genesis_hash: manifest.genesis_hash,
        startup_timeout: timeout,
    };
    for (index, eras) in manifest.eras.windows(2).enumerate() {
        let era = &eras[0];
        let checkpoint = era.bootstrap.as_ref().expect("validated bootstrap");
        info!(
            era = %era.name,
            block = checkpoint.terminal_block_number,
            "running bounded bootstrap"
        );
        let status = import
            .insert(spawn_bootstrap(manifest, era, checkpoint)?)
            .wait()
            .await
            .wrap_err_with(|| format!("waiting for {} bootstrap", era.name))?;
        // Clear only after reaping: cancellation retains ownership for shutdown.
        *import = None;
        ensure!(
            status.success(),
            "{} bootstrap exited with {status}",
            era.name
        );
        let workers = readers.insert(HistoricalWorkers::new(
            context.clone(),
            vec![ReleaseEra {
                name: era.name.clone(),
                start_timestamp: era.start_timestamp,
                binary: Some(era.binary.clone()),
                checkpoint: None,
            }],
        )?);
        let worker = workers.get(0).await?;
        verify_checkpoint(
            &worker.client,
            checkpoint,
            era.start_timestamp,
            eras[1].start_timestamp,
            true,
        )
        .await
        .wrap_err_with(|| format!("checking {} bootstrap", era.name))?;
        if index > 0 {
            let previous = manifest.eras[index - 1]
                .bootstrap
                .as_ref()
                .expect("validated bootstrap");
            verify_checkpoint(
                &worker.client,
                previous,
                manifest.eras[index - 1].start_timestamp,
                era.start_timestamp,
                false,
            )
            .await?;
            verify_successor(&worker.client, previous, era.start_timestamp).await?;
        }
        workers.shutdown().await?;
        *readers = None;
    }
    info!("historical bootstrap complete; start the live era with tempo node");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::{RpcModule, server::ServerBuilder};
    use serde_json::{Value, json};
    use std::sync::Mutex;

    fn hash(n: u64) -> String {
        format!("0x{n:064x}")
    }
    fn header(n: u64, timestamp: u64) -> Value {
        json!({
            "number": format!("0x{n:x}"),
            "hash": hash(n),
            "parentHash": hash(n.saturating_sub(1)),
            "timestamp": format!("0x{timestamp:x}")
        })
    }
    #[tokio::test]
    async fn bootstrap_validates_checkpoint_and_successor() {
        let headers = Arc::new(Mutex::new(json!({})));
        let mut module = RpcModule::from_arc(headers.clone());
        module
            .register_method("eth_getBlockByNumber", |params, headers, _| {
                let (number, _): (String, bool) = params.parse().unwrap();
                headers.lock().unwrap()[&number].clone()
            })
            .unwrap();
        let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
        let client = jsonrpsee::http_client::HttpClientBuilder::default()
            .build(format!("http://{}", server.local_addr().unwrap()))
            .unwrap();
        let _server = server.start(module);
        let checkpoint = Bootstrap {
            args: vec![],
            terminal_block_number: 2,
            terminal_block_hash: hash(2).parse().unwrap(),
        };
        for (block, head, exact, valid) in [
            (Value::Null, Value::Null, true, false),
            (header(2, 99), header(2, 99), true, true),
            (header(2, 99), header(3, 100), true, false),
            (header(2, 99), header(3, 100), false, true),
            (header(20, 99), Value::Null, false, false),
            (header(2, 100), Value::Null, false, false),
        ] {
            *headers.lock().unwrap() = json!({"0x2": block, "latest": head});
            let result = verify_checkpoint(&client, &checkpoint, 0, 100, exact).await;
            assert_eq!(result.is_ok(), valid, "{result:?}");
        }
        let mut wrong_parent = header(3, 100);
        wrong_parent["parentHash"] = json!(hash(42));
        for (block, valid) in [
            (Value::Null, false),
            (header(3, 99), false),
            (wrong_parent, false),
            (header(3, 100), true),
        ] {
            headers.lock().unwrap()["0x3"] = block;
            let result = verify_successor(&client, &checkpoint, 100).await;
            assert_eq!(result.is_ok(), valid, "{result:?}");
        }
    }
}
