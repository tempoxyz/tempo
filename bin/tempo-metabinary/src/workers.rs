//! Lazy, private historical RPC processes for an ordinary node.
//!
//! The node remains the only writer and keeps its normal public RPC transports. These workers
//! only open existing storage and are started when a historical execution request needs them.

use alloy_primitives::{B256, U64};
use eyre::{Context, OptionExt, Result, bail, ensure};
use jsonrpsee::{
    core::{
        RpcResult,
        client::{ClientT, Error as ClientError},
    },
    http_client::{HttpClient, HttpClientBuilder},
    types::error::METHOD_NOT_FOUND_CODE,
};
use serde_json::value::RawValue;
use std::{net::TcpListener, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    catalog::FrozenEra,
    handshake::{WorkerIdentity, wait_for_worker},
    process::{shutdown_children, spawn_child},
    routing::{RpcParams, execution_error, unsupported, upstream_error},
};

/// Default deadline for starting and validating a historical RPC worker.
pub const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 120;

const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_DELAY: Duration = Duration::from_secs(30);

/// Clones share one process per era. Startup is serialized independently for each era.
///
/// A cancelled request leaves a starting child owned by its state, so another request can finish
/// the handshake. Unleased workers are stopped after five idle minutes and restarted on demand.
/// Failed and idle children are stopped by tracked tasks, outside request cancellation.
/// Explicit shutdown reaps every child; final drop kills children as a fallback.
pub struct HistoricalWorkers {
    context: WorkerContext,
    eras: Vec<(FrozenEra, Mutex<State>)>,
    shutdown: CancellationToken,
    stopping: TaskTracker,
}

impl HistoricalWorkers {
    /// `eras` come from a validated `ChainEras`, which owns executable checks.
    pub fn new(context: WorkerContext, eras: Vec<FrozenEra>) -> Result<Arc<Self>> {
        ensure!(
            !context.startup_timeout.is_zero(),
            "historical worker startup timeout must be positive"
        );
        let runtime = tokio::runtime::Handle::try_current()
            .wrap_err("historical workers require a Tokio runtime")?;
        let workers = Arc::new(Self {
            context,
            eras: eras
                .into_iter()
                .map(|era| (era, Mutex::new(State::Dormant)))
                .collect(),
            shutdown: CancellationToken::new(),
            stopping: TaskTracker::new(),
        });
        let weak = Arc::downgrade(&workers);
        runtime.spawn(
            workers
                .shutdown
                .clone()
                .run_until_cancelled_owned(async move {
                    loop {
                        tokio::time::sleep(IDLE_CHECK_INTERVAL).await;
                        let Some(workers) = weak.upgrade() else { break };
                        workers.reap_idle().await;
                    }
                }),
        );
        Ok(workers)
    }

    /// Starts the era's worker on demand. A failure stops it and starts the retry cooldown.
    pub async fn get(&self, index: usize) -> Result<Arc<HistoricalWorker>> {
        let (era, state) = self
            .eras
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown historical era {index}"))?;
        let mut state = state.lock().await;
        ensure!(
            !self.shutdown.is_cancelled(),
            "historical workers are shutting down"
        );
        if let State::Failed(error, retry_at) = &*state {
            ensure!(Instant::now() >= *retry_at, "{error}");
            *state = State::Dormant;
        }
        let result = async {
            if matches!(*state, State::Dormant) {
                *state = State::Running(Box::new(spawn(&self.context, era)?));
            }
            let State::Running(process) = &mut *state else {
                unreachable!("spawned or failed")
            };
            if let Some(status) = process.child.try_wait()? {
                bail!("historical era {era} exited with {status}");
            }
            process.last_used = Instant::now();
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
                let message = format!("historical era {era} unavailable: {error:#}");
                tracing::warn!(%era, %message, "Historical worker failed");
                let failed = State::Failed(message.clone(), Instant::now() + RETRY_DELAY);
                if let State::Running(process) = std::mem::replace(&mut *state, failed) {
                    self.stop(era, process);
                }
                bail!("{message}");
            }
        }
    }

    /// Methods the worker does not serve fail with `-32004`.
    pub async fn request(
        &self,
        index: usize,
        method: &str,
        params: RpcParams,
    ) -> RpcResult<Box<RawValue>> {
        let worker = self.get(index).await.map_err(execution_error)?;
        worker
            .client
            .request(method, params)
            .await
            .map_err(|error| match error {
                ClientError::Call(error) if error.code() == METHOD_NOT_FOUND_CODE => {
                    unsupported(format!(
                        "{method} is unavailable in historical era {}",
                        self.eras[index].0
                    ))
                }
                error => upstream_error(error),
            })
    }

    async fn reap_idle(&self) {
        for (era, state) in &self.eras {
            let Ok(mut state) = state.try_lock() else {
                continue;
            };
            let State::Running(process) = &mut *state else {
                continue;
            };
            let now = Instant::now();
            if process.ready.as_ref().map_or(0, Arc::strong_count) > 1 {
                process.last_used = now;
                continue;
            }
            if now.duration_since(process.last_used) < IDLE_TIMEOUT {
                continue;
            }
            if let State::Running(process) = std::mem::replace(&mut *state, State::Dormant) {
                tracing::debug!(%era, "Stopping idle historical RPC worker");
                self.stop(era, process);
            }
        }
    }

    /// Stop a child that its state no longer owns. Shutdown waits for these tasks.
    fn stop(&self, era: &FrozenEra, mut process: Box<Process>) {
        let name = era.to_string();
        self.stopping.spawn(async move {
            if let Err(error) = process.stop(&name).await {
                tracing::warn!(era = %name, %error, "Failed to stop historical worker");
            }
        });
    }

    /// Retryable after cancellation; children stay owned until reaped.
    pub async fn shutdown(&self) -> Result<()> {
        self.shutdown.cancel();
        let mut states =
            futures::future::join_all(self.eras.iter().map(|(_, state)| state.lock())).await;
        let names: Vec<_> = self.eras.iter().map(|(era, _)| era.to_string()).collect();
        // Retain children in their states so cancelled shutdown can be retried and reaped.
        shutdown_children(states.iter_mut().zip(&names).filter_map(|(state, name)| {
            match &mut **state {
                State::Running(process) => Some((name.as_str(), &mut process.child)),
                _ => None,
            }
        }))
        .await?;
        for state in &mut states {
            if let State::Running(process) = &**state {
                process.cleanup()?;
            }
            **state = State::Dormant;
        }
        // Stop tasks are spawned only under a state lock held above, so none can follow this wait.
        self.stopping.close();
        self.stopping.wait().await;
        Ok(())
    }
}

/// Resolved from the ordinary node's chain and data-directory configuration.
#[derive(Clone, Debug)]
pub struct WorkerContext {
    pub chain: String,
    pub datadir: PathBuf,
    pub static_files_path: Option<PathBuf>,
    pub rocksdb_path: Option<PathBuf>,
    /// Private execution configuration produced by the node, without duplicating its CLI.
    pub rpc_config: PathBuf,
    pub chain_id: U64,
    pub genesis_hash: B256,
    pub startup_timeout: Duration,
}

/// RPC client for a verified worker. Retain this handle while using its client to protect the
/// worker from idle shutdown.
#[derive(Debug)]
pub struct HistoricalWorker {
    pub client: HttpClient,
}

struct Process {
    child: Child,
    client: HttpClient,
    ready: Option<Arc<HistoricalWorker>>,
    deadline: Instant,
    last_used: Instant,
    secondary_path: PathBuf,
}

/// `Dormant` -> `Running` -> `Failed` -> `Dormant` after the cooldown; idle reaping and shutdown
/// return `Running` to `Dormant`.
enum State {
    Dormant,
    Running(Box<Process>),
    Failed(String, Instant),
}

fn spawn(context: &WorkerContext, era: &FrozenEra) -> Result<Process> {
    let now = Instant::now();
    let deadline = now
        .checked_add(context.startup_timeout)
        .ok_or_eyre("historical worker startup timeout exceeds the clock range")?;
    // Reserve a loopback port until immediately before spawn. The PID handshake detects
    // accidental port collisions. Local processes are trusted.
    let reservation = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = reservation.local_addr()?.port();
    let client = HttpClientBuilder::default()
        .max_request_size(u32::MAX)
        .max_response_size(u32::MAX)
        // Execution timeouts and public limits belong to the ordinary RPC implementation.
        .request_timeout(Duration::MAX)
        .build(format!("http://127.0.0.1:{port}"))?;
    let binary = &era.binary;
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
    command.arg("--rpc-config").arg(&context.rpc_config);
    drop(reservation);
    let child =
        spawn_child(&mut command).wrap_err_with(|| format!("launching {}", binary.display()))?;
    let rocksdb = context
        .rocksdb_path
        .clone()
        .unwrap_or_else(|| context.datadir.join("rocksdb"));
    // Match Reth's secondary naming and remove only this owned child's directory after reaping.
    let secondary_path = rocksdb.parent().unwrap_or(&rocksdb).join(format!(
        "rocksdb-secondary-tmp-{}",
        child.id().ok_or_eyre("historical worker has no PID")?
    ));
    Ok(Process {
        child,
        client,
        ready: None,
        deadline,
        last_used: now,
        secondary_path,
    })
}

async fn ready(
    workers: &HistoricalWorkers,
    era: &FrozenEra,
    process: &mut Process,
) -> Result<Arc<HistoricalWorker>> {
    let pid = process
        .child
        .id()
        .ok_or_eyre("historical worker exited before handshake")?;
    let handshake = wait_for_worker(
        &process.client,
        WorkerIdentity {
            chain_id: workers.context.chain_id,
            genesis_hash: workers.context.genesis_hash,
        },
        pid,
        process.deadline,
        || {
            if let Some(status) = process.child.try_wait()? {
                bail!("historical worker exited with {status}");
            }
            Ok(())
        },
    );
    tokio::select! {
        biased;
        _ = workers.shutdown.cancelled() => { bail!("historical workers are shutting down"); },
        result = handshake => result?,
    }
    tracing::debug!(%era, pid, "Historical RPC worker ready");
    Ok(Arc::new(HistoricalWorker {
        client: process.client.clone(),
    }))
}

impl Process {
    async fn stop(&mut self, name: &str) -> Result<()> {
        shutdown_children([(name, &mut self.child)]).await?;
        self.cleanup()
    }

    fn cleanup(&self) -> Result<()> {
        match std::fs::remove_dir_all(&self.secondary_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).wrap_err_with(|| {
                format!(
                    "removing historical secondary {}",
                    self.secondary_path.display()
                )
            }),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        handshake::{EXECUTION_INFO_METHOD, EXECUTION_INFO_PROTOCOL_VERSION},
        process::tests::assert_reaped,
    };
    use futures::FutureExt as _;
    use jsonrpsee::{RpcModule, server::ServerBuilder};
    use serde_json::{Value, json};
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
            "protocolVersion": EXECUTION_INFO_PROTOCOL_VERSION + u32::from(mode == "wrong-protocol"),
            "processId": std::process::id() + u32::from(mode == "wrong-pid"),
            "chainId": if mode == "wrong-chain" { "0x2" } else { "0x1" },
            "genesisHash": format!("0x{}", if mode == "wrong-genesis" { "11" } else { "00" }.repeat(32)),
            "readOnly": mode != "writer",
        });
        let mut methods = RpcModule::new((info, mode.clone()));
        if mode != "missing-protocol" {
            methods
                .register_async_method(EXECUTION_INFO_METHOD, |_, info, _| async move {
                    if info.1 == "stalled" {
                        std::future::pending::<()>().await;
                    }
                    info.0.clone()
                })
                .unwrap();
        }
        methods
            .register_async_method("eth_call", |params, info, _| async move {
                if info.1 == "stalled-call" {
                    std::future::pending::<()>().await;
                }
                params.parse::<Value>()
            })
            .unwrap();
        methods
            .register_method("eth_estimateGas", |_, _, _| {
                Err::<(), _>(jsonrpsee::types::ErrorObjectOwned::owned(
                    -32000,
                    "execution reverted",
                    None::<()>,
                ))
            })
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
                "#!/bin/sh\nmkdir -p {secondary_root}/rocksdb-secondary-tmp-$$\n\
                 printf '%s\\n' \"$$\" >> \"$0.starts\"\n\
                 while [ \"$1\" != --port ]; do shift; done\n\
                 export TEMPO_WORKER_TEST_PORT=\"$2\" TEMPO_WORKER_TEST_MODE={mode} TEMPO_WORKER_TEST_DELAY_MS={delay_ms}\n\
                 exec {} --exact workers::tests::child_rpc_fixture --ignored --nocapture\n",
                quote(std::env::current_exe().unwrap().to_str().unwrap()),
                secondary_root = quote(directory.path().to_str().unwrap()),
            );
            std::fs::write(&binary, script).unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
            let workers = HistoricalWorkers::new(
                WorkerContext {
                    chain: "test-chain".into(),
                    datadir: directory.path().join("data with spaces"),
                    static_files_path: Some(directory.path().join("custom static files")),
                    rocksdb_path: Some(directory.path().join("custom rocksdb")),
                    rpc_config: directory.path().join("rpc config.json"),
                    chain_id: U64::from(1),
                    genesis_hash: B256::ZERO,
                    startup_timeout: Duration::from_secs(if mode == "stalled" { 2 } else { 5 }),
                },
                vec![FrozenEra {
                    until: tempo_hardfork::TempoHardfork::T1,
                    binary: binary.clone(),
                    checkpoint: Default::default(),
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

        /// Background stops remove the secondary only after reaping the child.
        async fn stopped(&self, pid: u32) {
            let secondary = self
                ._directory
                .path()
                .join(format!("rocksdb-secondary-tmp-{pid}"));
            tokio::time::timeout(Duration::from_secs(15), async {
                while secondary.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn workers_start_lazily_coalesce_and_restart_after_idle() {
        let fixture = Fixture::new("", 0);
        let workers = &fixture.workers;
        assert!(!fixture.starts.exists());
        let (first, second) = tokio::join!(workers.get(0), workers.get(0));
        let first = first.unwrap();
        second.unwrap();
        let pid = fixture.spawned_pid().await;
        assert_eq!(fixture.pids(), [pid]);
        let params = json!({"request": {"to": "0x1234"}, "blockId": "0x1"});
        let response = workers
            .request(0, "eth_call", RpcParams(params.clone()))
            .await
            .unwrap();
        assert_eq!(response.get(), params.to_string());
        let unknown = workers
            .request(0, "debug_unknown", RpcParams(Value::Null))
            .await
            .unwrap_err();
        assert_eq!(unknown.code(), -32004);
        assert_eq!(
            unknown.message(),
            "debug_unknown is unavailable in historical era pre-T1"
        );
        let reverted = workers
            .request(0, "eth_estimateGas", RpcParams(Value::Null))
            .await
            .unwrap_err();
        assert_eq!(
            (reverted.code(), reverted.message()),
            (-32000, "execution reverted")
        );

        tokio::time::pause();
        tokio::time::advance(IDLE_TIMEOUT + IDLE_CHECK_INTERVAL).await;
        workers.reap_idle().await;
        assert!(matches!(*workers.eras[0].1.lock().await, State::Running(_)));
        drop(first);
        workers.reap_idle().await;
        tokio::time::advance(IDLE_TIMEOUT - IDLE_CHECK_INTERVAL).await;
        assert!(matches!(*workers.eras[0].1.lock().await, State::Running(_)));
        tokio::time::advance(IDLE_CHECK_INTERVAL * 2).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !matches!(*workers.eras[0].1.lock().await, State::Dormant) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.stopped(pid).await;
        workers.get(0).await.unwrap();
        workers.shutdown().await.unwrap();
        assert_reaped(*fixture.pids().last().unwrap());
        assert!(workers.get(0).await.is_err());
    }

    #[tokio::test]
    async fn cancelled_calls_release_the_worker() {
        let fixture = Fixture::new("stalled-call", 0);
        let workers = &fixture.workers;
        workers.get(0).await.unwrap();
        let pid = fixture.spawned_pid().await;
        let call = workers.request(0, "eth_call", RpcParams(json!([])));
        assert!(call.now_or_never().is_none());
        {
            let mut state = workers.eras[0].1.lock().await;
            let State::Running(process) = &mut *state else {
                unreachable!()
            };
            assert_eq!(Arc::strong_count(process.ready.as_ref().unwrap()), 1);
            process.last_used = Instant::now() - IDLE_TIMEOUT;
        }
        workers.reap_idle().await;
        assert!(matches!(*workers.eras[0].1.lock().await, State::Dormant));
        fixture.stopped(pid).await;
        workers.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_identity_mismatch_and_reaps_failed_startup() {
        for mode in [
            "wrong-pid",
            "wrong-chain",
            "wrong-genesis",
            "writer",
            "wrong-protocol",
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
            fixture.stopped(pid).await;
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
                fixture.workers.reap_idle().await;
                fixture.workers.get(0).await.unwrap();
                assert_eq!(fixture.pids(), [pid]);
                fixture.workers.shutdown().await.unwrap();
            }
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn failed_workers_recover_after_cooldown() {
        let fixture = Fixture::new("wrong-chain", 0);
        let workers = &fixture.workers;
        for crash in [false, true] {
            if crash {
                workers.get(0).await.unwrap();
                let mut state = workers.eras[0].1.lock().await;
                let State::Running(process) = &mut *state else {
                    unreachable!()
                };
                process.child.kill().await.unwrap();
            }
            assert!(workers.get(0).await.is_err());
            let pids = fixture.pids();
            fixture.stopped(*pids.last().unwrap()).await;
            tokio::time::pause();
            tokio::time::advance(RETRY_DELAY - Duration::from_secs(1)).await;
            assert!(workers.get(0).await.is_err());
            assert_eq!(fixture.pids(), pids);
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::time::resume();
            let binary = &workers.eras[0].0.binary;
            let script = std::fs::read_to_string(binary).unwrap();
            std::fs::write(binary, script.replace("MODE=wrong-chain", "MODE=")).unwrap();
        }
        workers.get(0).await.unwrap();
        workers.shutdown().await.unwrap();
    }
}
