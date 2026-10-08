use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use clap::{Args, Parser, Subcommand};
use eyre::{Context, Result, ensure};
use jsonrpsee::{
    core::client::ClientT,
    http_client::{HttpClient, HttpClientBuilder},
    ws_client::WsClientBuilder,
};
use serde_json::Value;
use tempo_metabinary::{
    handshake::{WorkerIdentity, wait_for_worker},
    manifest::{Bootstrap, Manifest},
    process::ProcessGroup,
    routing::{ExecutionInfo, Router, quantity},
    server::{self, ServerOptions},
};
use tracing::info;

#[derive(Debug, Parser)]
#[command(about = "Launch ordinary Tempo binaries and route execution RPCs by era")]
struct Cli {
    #[arg(long)]
    manifest: PathBuf,
    /// Time allowed for each worker to become ready.
    #[arg(long, global = true, default_value_t = 120)]
    startup_timeout_secs: u64,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve RPC with one live node and optional historical workers.
    Serve(Serve),
    /// Replay canonical block files from genesis through the historical eras.
    Bootstrap,
}

#[derive(Debug, Args)]
struct Serve {
    /// Start frozen read-only workers to serve historical execution RPCs.
    #[arg(long)]
    history: bool,
    #[arg(long, default_value = "127.0.0.1:8545")]
    listen: SocketAddr,
    /// Public namespaces. Private worker methods outside this list are never registered.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "eth,net,web3,tempo,token,consensus,rpc"
    )]
    api: Vec<String>,
    #[arg(long, default_value_t = 10_485_760)]
    max_request_bytes: u32,
    #[arg(long, default_value_t = 26_214_400)]
    max_response_bytes: u32,
    #[arg(long, default_value_t = 100)]
    max_connections: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let manifest = Arc::new(Manifest::load(&cli.manifest)?);
    let timeout = Duration::from_secs(cli.startup_timeout_secs);
    let mut processes = ProcessGroup::new();
    let result = tokio::select! {
        result = async {
            match cli.command {
                Command::Serve(options) => serve(manifest, options, timeout, &mut processes).await,
                Command::Bootstrap => bootstrap(&manifest, timeout, &mut processes).await,
            }
        } => result,
        result = shutdown_signal() => result,
    };
    let shutdown = processes.shutdown().await;
    result.and(shutdown)
}

fn client(port: u16, max_response: u32) -> Result<HttpClient> {
    Ok(HttpClientBuilder::default()
        .max_response_size(max_response)
        .request_timeout(Duration::from_secs(30))
        .build(format!("http://127.0.0.1:{port}"))?)
}

async fn ready(
    client: &HttpClient,
    manifest: &Manifest,
    index: usize,
    processes: &mut ProcessGroup,
    timeout: Duration,
    read_only: bool,
) -> Result<ExecutionInfo> {
    let era = &manifest.eras[index];
    let expected_pid = processes
        .worker_pid(&era.name)
        .expect("worker was launched");
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| eyre::eyre!("worker startup timeout exceeds the clock range"))?;
    wait_for_worker(
        client,
        WorkerIdentity {
            chain_id: &manifest.chain_id,
            genesis_hash: &manifest.genesis_hash,
            read_only,
        },
        expected_pid,
        deadline,
        || processes.check_alive(),
    )
    .await
    .wrap_err_with(|| format!("waiting for era {}", era.name))
}

async fn serve(
    manifest: Arc<Manifest>,
    options: Serve,
    timeout: Duration,
    processes: &mut ProcessGroup,
) -> Result<()> {
    let live = manifest.eras.len() - 1;
    let clients: Vec<_> = manifest
        .eras
        .iter()
        .map(|e| client(e.rpc_port, options.max_response_bytes))
        .collect::<Result<_>>()?;
    // Before starting a binary whose old execution may have been deleted, establish that storage
    // is already in its era or at the explicitly pinned predecessor handoff.
    if live > 0 {
        processes.spawn_reader(&manifest, live)?;
        ready(&clients[live], &manifest, live, processes, timeout, true).await?;
        let head: Value = clients[live]
            .request("eth_getBlockByNumber", ("latest", false))
            .await?;
        let in_live_era = quantity(&head["timestamp"])? >= manifest.live().start_timestamp;
        let predecessor = manifest.eras[live - 1].bootstrap.as_ref();
        let at_handoff = predecessor.is_some_and(|b| {
            head["hash"]
                .as_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&b.terminal_block_hash))
                && quantity(&head["number"]).ok() == Some(b.terminal_block_number)
        });
        ensure!(
            in_live_era || at_handoff,
            "database precedes the live era; run bootstrap or use a snapshot"
        );
        processes.shutdown().await?;
    }
    processes.spawn_live(&manifest)?;
    let live_info = ready(&clients[live], &manifest, live, processes, timeout, false).await?;
    if options.history {
        processes.spawn_history(&manifest)?;
    }
    let mut metadata = Vec::with_capacity(clients.len());
    for (index, client) in clients.iter().enumerate().take(live) {
        metadata.push(if options.history {
            Some(ready(client, &manifest, index, processes, timeout, true).await?)
        } else {
            None
        });
    }
    metadata.push(Some(live_info));
    let ws = if let Some(port) = manifest.live().ws_port {
        let expected_pid = processes
            .worker_pid(&manifest.live().name)
            .ok_or_else(|| eyre::eyre!("live worker exited before WebSocket handshake"))?;
        let ws = Arc::new(
            WsClientBuilder::default()
                .max_response_size(options.max_response_bytes)
                .build(format!("ws://127.0.0.1:{port}"))
                .await?,
        );
        let metadata: ExecutionInfo = ws
            .request("tempo_executionInfo", jsonrpsee::rpc_params![])
            .await?;
        metadata.validate(
            WorkerIdentity {
                chain_id: &manifest.chain_id,
                genesis_hash: &manifest.genesis_hash,
                read_only: false,
            },
            Some(expected_pid),
        )?;
        Some(ws)
    } else {
        None
    };
    let mut boundary_verified = verify_live_boundary(&clients[live], &manifest).await?;
    let router = Arc::new(Router::new(manifest.clone(), clients.clone(), metadata)?);
    let (address, handle) = server::start(
        router,
        ServerOptions {
            listen: options.listen,
            api: options.api,
            max_request_bytes: options.max_request_bytes,
            max_response_bytes: options.max_response_bytes,
            max_connections: options.max_connections,
        },
        ws,
    )
    .await?;
    info!(%address, "era RPC router ready");
    // The guard stops the server even when main cancels this future on a shutdown signal.
    let _stop_server = StopServer(handle.clone());
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = handle.clone().stopped() => return Ok(()),
            _ = tick.tick() => {
                processes.check_alive()?;
                if !boundary_verified { boundary_verified = verify_live_boundary(&clients[live], &manifest).await?; }
            }
        }
    }
}

struct StopServer(jsonrpsee::server::ServerHandle);
impl Drop for StopServer {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}

/// Check the first successor header as soon as it is available. Checkpoints are operator pins,
/// but a truncated bootstrap must never silently keep the writer running in an older era.
async fn verify_live_boundary(client: &HttpClient, manifest: &Manifest) -> Result<bool> {
    let live = manifest.eras.len() - 1;
    let Some(checkpoint) = live
        .checked_sub(1)
        .and_then(|index| manifest.eras[index].bootstrap.as_ref())
    else {
        return Ok(true);
    };
    let first_number = checkpoint
        .terminal_block_number
        .checked_add(1)
        .ok_or_else(|| eyre::eyre!("terminal block number overflows"))?;
    let first: Value = client
        .request(
            "eth_getBlockByNumber",
            (format!("0x{first_number:x}"), false),
        )
        .await?;
    if first.is_null() {
        return Ok(false);
    }
    ensure!(
        first["parentHash"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&checkpoint.terminal_block_hash)),
        "successor does not extend the pinned handoff block"
    );
    ensure!(
        quantity(&first["timestamp"])? >= manifest.live().start_timestamp,
        "bootstrap ended before the actual live era boundary"
    );
    Ok(true)
}

async fn verify_checkpoint(
    client: &HttpClient,
    checkpoint: &Bootstrap,
    start: u64,
    end: u64,
    exact_head: bool,
) -> Result<()> {
    let block: Value = client
        .request(
            "eth_getBlockByNumber",
            (format!("0x{:x}", checkpoint.terminal_block_number), false),
        )
        .await?;
    ensure!(
        quantity(&block["number"])? == checkpoint.terminal_block_number,
        "bootstrap checkpoint is missing"
    );
    ensure!(
        block["hash"]
            .as_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(&checkpoint.terminal_block_hash)),
        "bootstrap canonical checkpoint hash mismatch"
    );
    let timestamp = quantity(&block["timestamp"])?;
    ensure!(
        (start..end).contains(&timestamp),
        "bootstrap checkpoint is outside its era"
    );
    if exact_head {
        let head: Value = client
            .request("eth_getBlockByNumber", ("latest", false))
            .await?;
        ensure!(
            head["hash"] == block["hash"],
            "bootstrap did not stop at its pinned checkpoint"
        );
    }
    Ok(())
}

async fn bootstrap(
    manifest: &Manifest,
    timeout: Duration,
    processes: &mut ProcessGroup,
) -> Result<()> {
    manifest.validate_bootstrap()?;
    for index in 0..manifest.eras.len() - 1 {
        let era = &manifest.eras[index];
        let checkpoint = era.bootstrap.as_ref().expect("validated bootstrap");
        info!(era = %era.name, block = checkpoint.terminal_block_number, "running bounded bootstrap");
        processes.run_bootstrap(manifest, index).await?;
        processes.spawn_reader(manifest, index)?;
        let client = client(era.rpc_port, 25 * 1024 * 1024)?;
        ready(&client, manifest, index, processes, timeout, true).await?;
        verify_checkpoint(
            &client,
            checkpoint,
            era.start_timestamp,
            manifest.eras[index + 1].start_timestamp,
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
                &client,
                previous,
                manifest.eras[index - 1].start_timestamp,
                era.start_timestamp,
                false,
            )
            .await?;
            let first_number = previous
                .terminal_block_number
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("terminal block number overflows"))?;
            let first: Value = client
                .request(
                    "eth_getBlockByNumber",
                    (format!("0x{first_number:x}"), false),
                )
                .await?;
            ensure!(
                quantity(&first["timestamp"])? >= era.start_timestamp,
                "predecessor checkpoint ended before the actual era boundary"
            );
        }
        processes.shutdown().await?;
    }
    info!("historical bootstrap complete; serve will start the live era");
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result = tokio::signal::ctrl_c() => result?, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use jsonrpsee::{
        RpcModule,
        server::{ServerBuilder, ServerHandle},
    };
    use serde_json::json;
    use std::{collections::HashMap, sync::Mutex};
    use tempo_metabinary::manifest::Era;

    #[test]
    fn cli_validates_and_parses_archive_and_bootstrap_modes() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "tempo-metabinary",
            "--manifest",
            "eras.json",
            "serve",
            "--history",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Serve(Serve { history: true, .. })
        ));
        let cli = Cli::try_parse_from(["tempo-metabinary", "--manifest", "eras.json", "bootstrap"])
            .unwrap();
        assert!(matches!(cli.command, Command::Bootstrap));
    }

    fn hash(n: u64) -> String {
        format!("0x{n:064x}")
    }
    fn header(n: u64, timestamp: u64) -> Value {
        json!({"number":format!("0x{n:x}"), "hash":hash(n), "parentHash":hash(n.saturating_sub(1)), "timestamp":format!("0x{timestamp:x}")})
    }
    struct Storage {
        headers: Arc<Mutex<HashMap<String, Value>>>,
        client: HttpClient,
        server: ServerHandle,
    }
    impl Drop for Storage {
        fn drop(&mut self) {
            let _ = self.server.stop();
        }
    }
    impl Storage {
        async fn new() -> Self {
            let headers = Arc::new(Mutex::new(HashMap::<String, Value>::new()));
            let mut module = RpcModule::from_arc(headers.clone());
            module
                .register_method("eth_getBlockByNumber", |params, headers, _| {
                    let (number, _): (String, bool) = params.parse().unwrap();
                    headers
                        .lock()
                        .unwrap()
                        .get(&number)
                        .cloned()
                        .unwrap_or(Value::Null)
                })
                .unwrap();
            let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
            let client = super::client(server.local_addr().unwrap().port(), 10_000).unwrap();
            Self {
                headers,
                client,
                server: server.start(module),
            }
        }
        fn put(&self, id: &str, value: Value) {
            self.headers.lock().unwrap().insert(id.into(), value);
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            chain: "test".into(),
            datadir: "data".into(),
            chain_id: "0x1".into(),
            genesis_hash: hash(0),
            eras: vec![
                Era {
                    name: "old".into(),
                    start_timestamp: 0,
                    binary: "old".into(),
                    node_args: vec![],
                    rpc_port: 18545,
                    ws_port: None,
                    bootstrap: Some(Bootstrap {
                        args: vec!["import".into(), "blocks.rlp".into()],
                        terminal_block_number: 2,
                        terminal_block_hash: hash(2),
                    }),
                },
                Era {
                    name: "live".into(),
                    start_timestamp: 100,
                    binary: "live".into(),
                    node_args: vec![],
                    rpc_port: 18546,
                    ws_port: None,
                    bootstrap: None,
                },
            ],
        }
    }

    #[tokio::test]
    async fn bootstrap_requires_canonical_checkpoint_exact_head_and_era() {
        let storage = Storage::new().await;
        let manifest = manifest();
        let checkpoint = manifest.eras[0].bootstrap.as_ref().unwrap();
        assert!(
            verify_checkpoint(&storage.client, checkpoint, 0, 100, true)
                .await
                .is_err()
        );
        storage.put("0x2", header(2, 99));
        storage.put("latest", header(2, 99));
        verify_checkpoint(&storage.client, checkpoint, 0, 100, true)
            .await
            .unwrap();
        storage.put("latest", header(3, 100));
        assert!(
            verify_checkpoint(&storage.client, checkpoint, 0, 100, true)
                .await
                .is_err()
        );
        verify_checkpoint(&storage.client, checkpoint, 0, 100, false)
            .await
            .unwrap();
        storage.put("0x2", header(20, 99));
        assert!(
            verify_checkpoint(&storage.client, checkpoint, 0, 100, false)
                .await
                .is_err()
        );
        storage.put("0x2", header(2, 100));
        assert!(
            verify_checkpoint(&storage.client, checkpoint, 0, 100, false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn successor_verification_rejects_truncated_bootstrap_and_wrong_parent() {
        let storage = Storage::new().await;
        let manifest = manifest();
        assert!(
            !verify_live_boundary(&storage.client, &manifest)
                .await
                .unwrap()
        );
        storage.put("0x3", header(3, 99));
        assert!(
            verify_live_boundary(&storage.client, &manifest)
                .await
                .is_err()
        );
        let mut wrong_parent = header(3, 100);
        wrong_parent["parentHash"] = json!(hash(42));
        storage.put("0x3", wrong_parent);
        assert!(
            verify_live_boundary(&storage.client, &manifest)
                .await
                .is_err()
        );
        storage.put("0x3", header(3, 100));
        assert!(
            verify_live_boundary(&storage.client, &manifest)
                .await
                .unwrap()
        );
    }
}
