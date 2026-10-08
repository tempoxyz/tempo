//! Lazy, private historical RPC processes for an ordinary node.
//!
//! The node remains the only writer and keeps its normal public RPC transports. These workers
//! only open existing storage and are started when a historical execution request needs them.

use std::{collections::HashSet, net::TcpListener, path::PathBuf, sync::Arc, time::Duration};

use eyre::{Context, OptionExt, Result, bail, ensure};
use jsonrpsee::{
    core::{RpcResult, client::ClientT},
    http_client::{HttpClient, HttpClientBuilder},
    types::ErrorObjectOwned,
};
use serde_json::Value;
use tokio::{
    process::{Child, Command},
    sync::Mutex,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    catalog::ReleaseEra,
    handshake::{WorkerIdentity, wait_for_worker},
    manifest::{parse_quantity, validate_hash},
    process::{shutdown_children, spawn_child},
    routing::{ExecutionInfo, RpcParams, unsupported, upstream_error},
};

/// Resolved from the ordinary node's chain and data-directory configuration.
#[derive(Clone, Debug)]
pub struct WorkerContext {
    pub chain: String,
    pub datadir: PathBuf,
    pub static_files_path: Option<PathBuf>,
    pub rocksdb_path: Option<PathBuf>,
    /// Private execution configuration produced by the node, without duplicating its CLI.
    pub rpc_config: Option<PathBuf>,
    pub chain_id: String,
    pub genesis_hash: String,
    pub startup_timeout: Duration,
}

#[derive(Debug)]
pub struct HistoricalWorker {
    pub client: HttpClient,
    pub info: ExecutionInfo,
}

struct Process {
    child: Child,
    client: HttpClient,
    ready: Option<Arc<HistoricalWorker>>,
    deadline: Instant,
}

enum State {
    Dormant,
    Running(Box<Process>),
    Failed(String),
}

/// Clones share one process per era. Startup is serialized independently for each era.
///
/// A cancelled request leaves a starting child owned by its state, so another request can finish
/// the handshake. Explicit shutdown reaps every child; final drop kills children as a fallback.
pub struct HistoricalWorkers {
    context: WorkerContext,
    eras: Vec<ReleaseEra>,
    states: Vec<Mutex<State>>,
    shutdown: CancellationToken,
}

impl HistoricalWorkers {
    pub fn new(context: WorkerContext, eras: Vec<ReleaseEra>) -> Result<Arc<Self>> {
        ensure!(
            !context.chain.is_empty(),
            "historical worker chain must not be empty"
        );
        ensure!(
            !context.datadir.as_os_str().is_empty(),
            "historical worker datadir must not be empty"
        );
        parse_quantity(&context.chain_id).wrap_err("invalid historical worker chain ID")?;
        validate_hash(&context.genesis_hash).wrap_err("invalid historical worker genesis hash")?;
        ensure!(
            !context.startup_timeout.is_zero(),
            "historical worker startup timeout must be positive"
        );
        let mut names = HashSet::new();
        for era in &eras {
            ensure!(
                !era.name.is_empty() && names.insert(&era.name),
                "historical era names must be unique and nonempty"
            );
            ensure!(
                era.binary
                    .as_ref()
                    .is_some_and(|path| !path.as_os_str().is_empty()),
                "historical era {} has no executable",
                era.name
            );
        }
        let states = eras.iter().map(|_| Mutex::new(State::Dormant)).collect();
        Ok(Arc::new(Self {
            context,
            eras,
            states,
            shutdown: CancellationToken::new(),
        }))
    }

    pub async fn get(&self, index: usize) -> Result<Arc<HistoricalWorker>> {
        let era = self
            .eras
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown historical era {index}"))?;
        let mut state = self.states[index].lock().await;
        ensure!(
            !self.shutdown.is_cancelled(),
            "historical workers are shutting down"
        );
        if let State::Failed(error) = &*state {
            bail!("{error}");
        }
        let result = async {
            if matches!(*state, State::Dormant) {
                *state = State::Running(Box::new(spawn(&self.context, era)?));
            }
            let State::Running(process) = &mut *state else {
                unreachable!("spawned or failed")
            };
            if let Some(status) = process.child.try_wait()? {
                bail!("historical era {} exited with {status}", era.name);
            }
            if let Some(worker) = &process.ready {
                return Ok(worker.clone());
            }
            let worker = ready(self, era, process).await?;
            process.ready = Some(worker.clone());
            Ok(worker)
        }
        .await;
        match result {
            Ok(worker) => Ok(worker),
            Err(error) => {
                let message = format!("historical era {} unavailable: {error:#}", era.name);
                tracing::warn!(era = %era.name, %message, "Historical worker failed");
                let previous = std::mem::replace(&mut *state, State::Failed(message.clone()));
                if let State::Running(mut process) = previous {
                    // Keep this child owned while waiting. Cancellation falls back to kill_on_drop.
                    let _ = process.child.kill().await;
                }
                bail!("{message}");
            }
        }
    }

    pub async fn request(&self, index: usize, method: &str, params: RpcParams) -> RpcResult<Value> {
        let worker = self
            .get(index)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-32000, error.to_string(), None::<()>))?;
        if !worker.info.methods.iter().any(|name| name == method) {
            return Err(unsupported(format!(
                "{method} is unavailable in historical era {}",
                self.eras[index].name
            )));
        }
        worker
            .client
            .request(method, params)
            .await
            .map_err(upstream_error)
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.shutdown.cancel();
        let processes = futures::future::join_all(self.states.iter().zip(&self.eras).map(
            |(slot, era)| async {
                let mut state = slot.lock().await;
                match std::mem::replace(&mut *state, State::Dormant) {
                    State::Running(process) => Some((era.name.as_str(), process)),
                    _ => None,
                }
            },
        ))
        .await;
        let mut processes: Vec<_> = processes.into_iter().flatten().collect();
        shutdown_children(
            processes
                .iter_mut()
                .map(|(name, process)| (*name, &mut process.child)),
        )
        .await
    }
}

fn spawn(context: &WorkerContext, era: &ReleaseEra) -> Result<Process> {
    let deadline = Instant::now()
        .checked_add(context.startup_timeout)
        .ok_or_eyre("historical worker startup timeout exceeds the clock range")?;
    // Reserve a loopback port until immediately before spawn. The worker binds independently;
    // its PID handshake detects the small remaining bind race and prevents misrouting.
    let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = reservation.local_addr()?.port();
    let client = HttpClientBuilder::default()
        .max_request_size(u32::MAX)
        .max_response_size(u32::MAX)
        // Execution timeouts and public limits belong to the ordinary RPC implementation.
        .request_timeout(Duration::MAX)
        .build(format!("http://127.0.0.1:{port}"))?;
    let binary = era
        .binary
        .as_ref()
        .expect("validated historical executable");
    let mut command = Command::new(binary);
    command
        .args(["rpc-only", "--chain", &context.chain, "--datadir"])
        .arg(&context.datadir)
        .args(["--port", &port.to_string()]);
    if let Some(path) = &context.static_files_path {
        command.arg("--datadir.static-files").arg(path);
    }
    if let Some(path) = &context.rocksdb_path {
        command.arg("--datadir.rocksdb").arg(path);
    }
    if let Some(path) = &context.rpc_config {
        command.arg("--rpc-config").arg(path);
    }
    drop(reservation);
    let child =
        spawn_child(&mut command).wrap_err_with(|| format!("launching {}", binary.display()))?;
    Ok(Process {
        child,
        client,
        ready: None,
        deadline,
    })
}

async fn ready(
    workers: &HistoricalWorkers,
    era: &ReleaseEra,
    process: &mut Process,
) -> Result<Arc<HistoricalWorker>> {
    let pid = process
        .child
        .id()
        .ok_or_eyre("historical worker exited before handshake")?;
    let handshake = wait_for_worker(
        &process.client,
        WorkerIdentity {
            chain_id: &workers.context.chain_id,
            genesis_hash: &workers.context.genesis_hash,
            read_only: true,
        },
        pid,
        process.deadline,
        || {
            ensure!(
                !workers.shutdown.is_cancelled(),
                "historical workers are shutting down"
            );
            if let Some(status) = process.child.try_wait()? {
                bail!("historical worker exited with {status}");
            }
            Ok(())
        },
    );
    let info = tokio::select! {
        _ = workers.shutdown.cancelled() => { bail!("historical workers are shutting down"); },
        info = handshake => info?,
    };
    tracing::debug!(era = %era.name, pid, "Historical RPC worker ready");
    Ok(Arc::new(HistoricalWorker {
        client: process.client.clone(),
        info,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use jsonrpsee::{RpcModule, server::ServerBuilder};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    use crate::{handshake::EXECUTION_INFO_METHOD, process::tests::assert_reaped};

    /// Executed only as a child fixture, using this test binary as a real private RPC worker.
    #[tokio::test]
    #[ignore]
    async fn child_rpc_fixture() {
        let port: u16 = std::env::var("TEMPO_WORKER_TEST_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let mode = std::env::var("TEMPO_WORKER_TEST_MODE").unwrap_or_default();
        let delay = std::env::var("TEMPO_WORKER_TEST_DELAY_MS")
            .unwrap_or_default()
            .parse()
            .unwrap_or(0);
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let info = json!({
            "protocolVersion": 1 + u64::from(mode == "wrong-protocol"),
            "processId": std::process::id() + u32::from(mode == "wrong-pid"),
            "chainId": if mode == "wrong-chain" { "0x2" } else { "0x1" },
            "genesisHash": format!("0x{}", if mode == "wrong-genesis" { "11" } else { "00" }.repeat(32)),
            "readOnly": mode != "writer",
            "methods": match mode.as_str() {
                "too-many-methods" => vec!["eth_call".to_owned(); 1025],
                "long-method" => vec!["x".repeat(257)],
                _ => vec![EXECUTION_INFO_METHOD.into(), "eth_call".into()],
            }
        });
        let mut methods = RpcModule::new((info, mode == "stalled"));
        if mode != "missing-protocol" {
            methods
                .register_async_method(EXECUTION_INFO_METHOD, |_, info, _| async move {
                    if info.1 {
                        std::future::pending::<()>().await;
                    }
                    info.0.clone()
                })
                .unwrap();
        }
        methods
            .register_method("eth_call", |params, _, _| params.parse::<Value>())
            .unwrap();
        let server = ServerBuilder::default()
            .build((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        server.start(methods).stopped().await;
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        starts: PathBuf,
        workers: Arc<HistoricalWorkers>,
    }

    impl Fixture {
        fn new(mode: &str, delay_ms: u64) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let binary = directory.path().join("tempo-frozen");
            let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" >> \"$0.starts\"\n\
                 while [ \"$1\" != --port ]; do shift; done\n\
                 export TEMPO_WORKER_TEST_PORT=\"$2\" TEMPO_WORKER_TEST_MODE={mode} TEMPO_WORKER_TEST_DELAY_MS={delay_ms}\n\
                 exec {} --exact workers::tests::child_rpc_fixture --ignored --nocapture\n",
                quote(std::env::current_exe().unwrap().to_str().unwrap())
            );
            std::fs::write(&binary, script).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
            let workers = HistoricalWorkers::new(
                WorkerContext {
                    chain: "test-chain".into(),
                    datadir: directory.path().join("data with spaces"),
                    static_files_path: Some(directory.path().join("custom static files")),
                    rocksdb_path: Some(directory.path().join("custom rocksdb")),
                    rpc_config: None,
                    chain_id: "0x1".into(),
                    genesis_hash: format!("0x{}", "00".repeat(32)),
                    startup_timeout: Duration::from_secs(if mode == "stalled" { 2 } else { 5 }),
                },
                vec![ReleaseEra {
                    name: "frozen".into(),
                    start_timestamp: 0,
                    binary: Some(binary.clone()),
                }],
            )
            .unwrap();
            Self {
                _directory: directory,
                starts: binary.with_extension("starts"),
                workers,
            }
        }

        fn pids(&self) -> Vec<u32> {
            std::fs::read_to_string(&self.starts)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.parse().ok())
                .collect()
        }

        async fn spawned_pid(&self) -> u32 {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(pid) = self.pids().first() {
                        return *pid;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap()
        }
    }

    #[tokio::test]
    async fn starts_lazily_and_coalesces_concurrent_requests() {
        let fixture = Fixture::new("", 0);
        assert!(!fixture.starts.exists());
        let (first, second) = tokio::join!(fixture.workers.get(0), fixture.workers.get(0));
        let first = first.unwrap();
        second.unwrap();
        assert_eq!(fixture.pids(), [first.info.process_id]);
        let params = json!({"request": {"to": "0x1234"}, "blockId": "0x1"});
        assert_eq!(
            fixture
                .workers
                .request(0, "eth_call", RpcParams(params.clone()))
                .await
                .unwrap(),
            params
        );
        assert_eq!(
            fixture
                .workers
                .request(0, "debug_unknown", RpcParams(Value::Null))
                .await
                .unwrap_err()
                .code(),
            -32004
        );
        fixture.workers.shutdown().await.unwrap();
        assert_reaped(first.info.process_id);
        assert!(fixture.workers.get(0).await.is_err());
    }

    #[tokio::test]
    async fn rejects_identity_mismatch_and_reaps_failed_startup() {
        for mode in [
            "wrong-pid",
            "wrong-chain",
            "wrong-genesis",
            "writer",
            "wrong-protocol",
            "too-many-methods",
            "long-method",
            "missing-protocol",
            "stalled",
        ] {
            let fixture = Fixture::new(mode, 0);
            let timeout = fixture.workers.context.startup_timeout + Duration::from_secs(2);
            let error = tokio::time::timeout(timeout, fixture.workers.get(0))
                .await
                .expect(mode)
                .unwrap_err();
            if mode == "stalled" {
                assert!(error.to_string().contains("startup timed out"));
            }
            let pid = fixture.spawned_pid().await;
            assert_reaped(pid);
            assert!(fixture.workers.get(0).await.is_err());
            assert_eq!(fixture.pids(), [pid]);
            fixture.workers.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn interrupted_startup_keeps_the_child_owned() {
        for shutdown in [false, true] {
            let fixture = Fixture::new("", if shutdown { 60_000 } else { 400 });
            let workers = fixture.workers.clone();
            let request = tokio::spawn(async move { workers.get(0).await });
            let pid = fixture.spawned_pid().await;
            if shutdown {
                tokio::time::timeout(Duration::from_secs(2), fixture.workers.shutdown())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(request.await.unwrap().is_err());
            } else {
                request.abort();
                let _ = request.await;
                assert_eq!(fixture.workers.get(0).await.unwrap().info.process_id, pid);
                fixture.workers.shutdown().await.unwrap();
            }
            assert_reaped(pid);
        }
    }
}
