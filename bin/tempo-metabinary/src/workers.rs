//! Lazy, private historical RPC processes for an ordinary node.
//!
//! The node remains the only writer and keeps its normal public RPC transports. These workers
//! only open existing storage and are started when a historical execution request needs them.

use std::{
    collections::HashSet,
    net::TcpListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use eyre::{Context, Result, bail, ensure};
use jsonrpsee::{
    core::{RpcResult, client::ClientT},
    http_client::{HttpClient, HttpClientBuilder},
    types::ErrorObjectOwned,
};
use serde_json::Value;
use tokio::{
    process::{Child, Command},
    sync::{Mutex, Notify},
    time::Instant,
};

use crate::{
    handshake::{WorkerIdentity, wait_for_worker},
    manifest::parse_quantity,
    process::{shutdown_children, spawn_child},
    routing::{ExecutionInfo, RpcParams, upstream_error},
};

#[derive(Clone, Debug)]
pub struct WorkerEra {
    pub name: String,
    pub start_timestamp: u64,
    pub binary: PathBuf,
}

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
    /// Private transport limit. The node's existing server retains the public response limit.
    pub max_response_bytes: u32,
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
    Running(Process),
    Failed(String),
}

struct Inner {
    context: WorkerContext,
    eras: Vec<WorkerEra>,
    states: Vec<Mutex<State>>,
    closing: AtomicBool,
    shutdown: Notify,
}

/// Clones share one process per era. Startup is serialized independently for each era.
///
/// A cancelled request leaves a starting child owned by its state, so another request can finish
/// the handshake. Explicit shutdown reaps every child; final drop kills children as a fallback.
#[derive(Clone)]
pub struct HistoricalWorkers {
    inner: Arc<Inner>,
}

impl HistoricalWorkers {
    pub fn new(context: WorkerContext, eras: Vec<WorkerEra>) -> Result<Self> {
        ensure!(
            !context.chain.is_empty(),
            "historical worker chain must not be empty"
        );
        ensure!(
            !context.datadir.as_os_str().is_empty(),
            "historical worker datadir must not be empty"
        );
        parse_quantity(&context.chain_id).wrap_err("invalid historical worker chain ID")?;
        ensure!(
            context
                .genesis_hash
                .strip_prefix("0x")
                .is_some_and(|digits| digits.len() == 64
                    && digits.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "invalid historical worker genesis hash"
        );
        ensure!(
            !context.startup_timeout.is_zero(),
            "historical worker startup timeout must be positive"
        );
        let mut names = HashSet::new();
        for (index, era) in eras.iter().enumerate() {
            ensure!(
                !era.name.is_empty() && names.insert(&era.name),
                "historical era names must be unique and nonempty"
            );
            ensure!(
                !era.binary.as_os_str().is_empty(),
                "historical era {} has no executable",
                era.name
            );
            if index > 0 {
                ensure!(
                    eras[index - 1].start_timestamp < era.start_timestamp,
                    "historical era timestamps must strictly increase"
                );
            }
        }
        let states = eras.iter().map(|_| Mutex::new(State::Dormant)).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                context,
                eras,
                states,
                closing: AtomicBool::new(false),
                shutdown: Notify::new(),
            }),
        })
    }

    pub async fn get(&self, index: usize) -> Result<Arc<HistoricalWorker>> {
        let era = self
            .inner
            .eras
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown historical era {index}"))?;
        let mut state = self.inner.states[index].lock().await;
        ensure!(
            !self.inner.closing.load(Ordering::Acquire),
            "historical workers are shutting down"
        );
        if let State::Failed(error) = &*state {
            bail!("{error}");
        }
        if matches!(*state, State::Dormant) {
            match spawn(&self.inner.context, era) {
                Ok(process) => *state = State::Running(process),
                Err(error) => {
                    let message = format!("starting historical era {}: {error:#}", era.name);
                    tracing::warn!(era = %era.name, %message, "Historical worker failed");
                    *state = State::Failed(message.clone());
                    bail!("{message}");
                }
            }
        }
        let State::Running(process) = &mut *state else {
            unreachable!("spawned or failed")
        };
        let result = match process.child.try_wait() {
            Ok(Some(status)) => Err(eyre::eyre!(
                "historical era {} exited with {status}",
                era.name
            )),
            Err(error) => Err(error.into()),
            Ok(None) => match &process.ready {
                Some(worker) => return Ok(worker.clone()),
                None => ready(&self.inner, era, process).await,
            },
        };
        match result {
            Ok(worker) => {
                process.ready = Some(worker.clone());
                Ok(worker)
            }
            Err(error) => {
                let message = format!("historical era {} unavailable: {error:#}", era.name);
                tracing::warn!(era = %era.name, %message, "Historical worker failed");
                let previous = std::mem::replace(&mut *state, State::Failed(message.clone()));
                if let State::Running(mut process) = previous {
                    // Keep this child owned while waiting. Cancellation falls back to kill_on_drop.
                    let _ = process.child.kill().await;
                }
                bail!("{message}")
            }
        }
    }

    pub async fn request(&self, index: usize, method: &str, params: RpcParams) -> RpcResult<Value> {
        let worker = self
            .get(index)
            .await
            .map_err(|error| ErrorObjectOwned::owned(-32000, error.to_string(), None::<()>))?;
        if !worker.info.methods.iter().any(|name| name == method) {
            return Err(ErrorObjectOwned::owned(
                -32004,
                format!(
                    "{method} is unavailable in historical era {}",
                    self.inner.eras[index].name
                ),
                None::<()>,
            ));
        }
        worker
            .client
            .request(method, params)
            .await
            .map_err(upstream_error)
    }

    /// Observe exited workers without blocking behind an in-progress startup handshake.
    pub async fn check_alive(&self) -> Result<()> {
        for (index, slot) in self.inner.states.iter().enumerate() {
            let Ok(mut state) = slot.try_lock() else {
                continue;
            };
            match &mut *state {
                State::Failed(error) => bail!("{error}"),
                State::Running(process) => {
                    if let Some(status) = process.child.try_wait()? {
                        let message = format!(
                            "historical era {} exited with {status}",
                            self.inner.eras[index].name
                        );
                        *state = State::Failed(message.clone());
                        bail!("{message}");
                    }
                }
                State::Dormant => {}
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.inner.closing.store(true, Ordering::Release);
        self.inner.shutdown.notify_waiters();
        let processes =
            futures::future::join_all(self.inner.states.iter().zip(&self.inner.eras).map(
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

fn spawn(context: &WorkerContext, era: &WorkerEra) -> Result<Process> {
    let deadline = Instant::now()
        .checked_add(context.startup_timeout)
        .ok_or_else(|| eyre::eyre!("historical worker startup timeout exceeds the clock range"))?;
    // Reserve a loopback port until immediately before spawn. The worker binds independently;
    // its PID handshake detects the small remaining bind race and prevents misrouting.
    let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = reservation.local_addr()?.port();
    let client = HttpClientBuilder::default()
        .max_request_size(u32::MAX)
        .max_response_size(context.max_response_bytes)
        // Execution timeouts and public limits belong to the ordinary RPC implementation.
        .request_timeout(Duration::MAX)
        .build(format!("http://127.0.0.1:{port}"))?;
    let mut command = Command::new(&era.binary);
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
    let child = spawn_child(&mut command)
        .wrap_err_with(|| format!("launching {}", era.binary.display()))?;
    Ok(Process {
        child,
        client,
        ready: None,
        deadline,
    })
}

async fn ready(
    inner: &Inner,
    era: &WorkerEra,
    process: &mut Process,
) -> Result<Arc<HistoricalWorker>> {
    let pid = process
        .child
        .id()
        .ok_or_else(|| eyre::eyre!("historical worker exited before handshake"))?;
    let handshake = wait_for_worker(
        &process.client,
        WorkerIdentity {
            chain_id: &inner.context.chain_id,
            genesis_hash: &inner.context.genesis_hash,
            read_only: true,
        },
        pid,
        process.deadline,
        || {
            ensure!(
                !inner.closing.load(Ordering::Acquire),
                "historical workers are shutting down"
            );
            if let Some(status) = process.child.try_wait()? {
                bail!("historical worker exited with {status}");
            }
            Ok(())
        },
    );
    let info = tokio::select! {
        _ = inner.shutdown.notified() => bail!("historical workers are shutting down"),
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
                _ => vec!["tempo_executionInfo".into(), "eth_call".into()],
            }
        });
        let mut methods = RpcModule::new(info);
        if mode == "stalled" {
            methods
                .register_async_method("tempo_executionInfo", |_, _, _| async {
                    std::future::pending::<Value>().await
                })
                .unwrap();
        } else if mode != "missing-protocol" {
            methods
                .register_method("tempo_executionInfo", |_, info, _| info.clone())
                .unwrap();
        }
        methods
            .register_method("eth_call", |params, _, _| params.parse::<Value>())
            .unwrap();
        let server = ServerBuilder::default()
            .build((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let _server = server.start(methods);
        std::future::pending::<()>().await;
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        starts: PathBuf,
        workers: HistoricalWorkers,
    }

    impl Fixture {
        fn new(mode: &str, delay_ms: u64) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let binary = directory.path().join("tempo-frozen");
            let test_binary = std::env::current_exe().unwrap();
            let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$$\" >> \"$0.starts\"\n\
                 while [ \"$#\" -gt 0 ]; do\n\
                   if [ \"$1\" = --port ]; then shift; export TEMPO_WORKER_TEST_PORT=\"$1\"; fi\n\
                   shift\n\
                 done\n\
                 export TEMPO_WORKER_TEST_MODE={}\n\
                 export TEMPO_WORKER_TEST_DELAY_MS={}\n\
                 exec {} --exact workers::tests::child_rpc_fixture --ignored --nocapture\n",
                quote(mode),
                delay_ms,
                quote(test_binary.to_str().unwrap())
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
                    startup_timeout: if mode == "stalled" {
                        Duration::from_millis(200)
                    } else {
                        Duration::from_secs(5)
                    },
                    max_response_bytes: u32::MAX,
                },
                vec![WorkerEra {
                    name: "frozen".into(),
                    start_timestamp: 0,
                    binary: binary.clone(),
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
                .unwrap()
                .lines()
                .map(|line| line.parse().unwrap())
                .collect()
        }

        async fn spawned_pid(&self) -> u32 {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(text) = std::fs::read_to_string(&self.starts)
                        && let Some(pid) = text.lines().next().and_then(|line| line.parse().ok())
                    {
                        return pid;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap()
        }
    }

    fn assert_reaped(pid: u32) {
        // SAFETY: signal zero only checks whether the process exists.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
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
            let timeout = Duration::from_secs(if mode == "stalled" { 1 } else { 6 });
            let error = tokio::time::timeout(timeout, fixture.workers.get(0))
                .await
                .unwrap_or_else(|_| panic!("worker startup exceeded test deadline: {mode}"))
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
    async fn cancelled_startup_remains_owned_and_is_reused() {
        let fixture = Fixture::new("", 400);
        let workers = fixture.workers.clone();
        let request = tokio::spawn(async move { workers.get(0).await });
        let pid = fixture.spawned_pid().await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        let worker = fixture.workers.get(0).await.unwrap();
        assert_eq!(worker.info.process_id, pid);
        assert_eq!(fixture.pids(), [pid]);
        fixture.workers.shutdown().await.unwrap();
        assert_reaped(pid);
    }

    #[tokio::test]
    async fn shutdown_interrupts_startup_and_reaps_child() {
        let fixture = Fixture::new("", 60_000);
        let workers = fixture.workers.clone();
        let request = tokio::spawn(async move { workers.get(0).await });
        let pid = fixture.spawned_pid().await;
        tokio::time::timeout(Duration::from_secs(2), fixture.workers.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert!(request.await.unwrap().is_err());
        assert_reaped(pid);
    }
}
