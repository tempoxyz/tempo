//! Stop consensus while the execution runtime can still service its requests.

use std::thread::{self, JoinHandle};

use eyre::WrapErr as _;
use tokio_util::sync::CancellationToken;

pub(super) struct ConsensusThread {
    shutdown: CancellationToken,
    handle: Option<JoinHandle<eyre::Result<()>>>,
    outcome: Option<thread::Result<eyre::Result<()>>>,
}

impl ConsensusThread {
    pub(super) fn new(shutdown: CancellationToken, handle: JoinHandle<eyre::Result<()>>) -> Self {
        Self {
            shutdown,
            handle: Some(handle),
            outcome: None,
        }
    }

    /// Arm only after consuming the startup sender. Otherwise joining during
    /// cancellation could wait for a sender held by the same dropped future.
    pub(super) fn stop_on_drop(&mut self) -> ConsensusShutdownGuard<'_> {
        ConsensusShutdownGuard(self)
    }

    fn stop_and_join(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.handle.take() {
            // The CLI polls/drops its launch future on its calling thread. Its
            // multithreaded execution runtime stays live until this returns.
            self.outcome = Some(handle.join());
            tracing::debug!("consensus thread stopped");
        }
    }

    pub(super) fn finish(mut self, node_result: eyre::Result<()>) -> eyre::Result<()> {
        self.stop_and_join();
        let consensus_result = match self.outcome.take().expect("consensus thread was joined") {
            Ok(result) => result.wrap_err("consensus task exited with error"),
            // A cancelled launch future cannot return its error. Keep the
            // thread's panic until normal control flow is outside its Drop.
            Err(unwind) => std::panic::resume_unwind(unwind),
        };
        match (node_result, consensus_result) {
            (Err(node), Err(consensus)) => {
                Err(node).wrap_err(format!("consensus task also failed: {consensus:#}"))
            }
            (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Drop for ConsensusThread {
    fn drop(&mut self) {
        // Also reap an unstarted/failed launcher or an unwinding CLI, after its
        // captured startup sender has been dropped. Never panic a second time
        // by resuming a consensus panic while the CLI is already unwinding.
        self.stop_and_join();
    }
}

pub(super) struct ConsensusShutdownGuard<'a>(&'a mut ConsensusThread);

impl Drop for ConsensusShutdownGuard<'_> {
    fn drop(&mut self) {
        self.0.stop_and_join();
    }
}

#[cfg(test)]
mod tests {
    use super::ConsensusThread;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _};
    use eyre::WrapErr as _;
    use futures::FutureExt as _;
    use reth_cli_runner::CliRunner;
    use std::{
        future::pending,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;

    fn run_runner_fixture(wait_for_signal: bool) {
        let runner = CliRunner::try_default_runtime().unwrap();
        let shutdown = CancellationToken::new();
        let cl_shutdown = shutdown.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let cl_stopped = stopped.clone();
        let (request_tx, request_rx) = oneshot::channel();
        let (response_tx, response_rx) = oneshot::channel();
        let handle = thread::spawn(move || {
            futures::executor::block_on(async move {
                cl_shutdown.cancelled().await;
                // Cleanup must still be able to make progress on the EL runtime.
                request_tx.send(()).unwrap();
                response_rx.await.unwrap();
                cl_stopped.store(true, Ordering::SeqCst);
                Ok(())
            })
        });
        let mut consensus = ConsensusThread::new(shutdown, handle);
        let consensus_ref = &mut consensus;
        let (engine_stopped_tx, engine_stopped_rx) = mpsc::channel();
        let result = runner.run_command_until_exit(|ctx| async move {
            ctx.task_executor.handle().spawn(async move {
                request_rx.await.unwrap();
                response_tx.send(()).unwrap();
            });
            ctx.task_executor
                .spawn_with_graceful_shutdown_signal(async move |signal| {
                    let _guard = signal.await;
                    engine_stopped_tx
                        .send(stopped.load(Ordering::SeqCst))
                        .unwrap();
                });

            if wait_for_signal {
                let _guard = consensus_ref.stop_on_drop();
                // Let the SDK's surrounding select poll both signal listeners
                // before telling the parent that it can deliver a signal.
                tokio::task::yield_now().await;
                use std::io::Write as _;
                println!("TEMPO_SHUTDOWN_TEST_READY");
                std::io::stdout().flush().unwrap();
                pending::<()>().await;
            } else {
                // Reproduce cancellation without signalling the shared test
                // process. The subprocess tests exercise real OS signals.
                let mut launch = Box::pin(async move {
                    let _guard = consensus_ref.stop_on_drop();
                    pending::<()>().await;
                });
                assert!(launch.as_mut().now_or_never().is_none());
                drop(launch);
            }
            Ok(())
        });
        consensus.finish(result).unwrap();
        assert!(
            engine_stopped_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
        );
    }

    #[test]
    fn cancelled_launcher_joins_consensus_before_sdk_engine_shutdown() {
        run_runner_fixture(false);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "invoked in an isolated subprocess by the signal tests"]
    fn signal_shutdown_child() {
        assert_eq!(
            std::env::var("TEMPO_SHUTDOWN_TEST_CHILD").as_deref(),
            Ok("1")
        );
        run_runner_fixture(true);
        println!("TEMPO_SHUTDOWN_TEST_DONE");
    }

    #[cfg(unix)]
    fn assert_signal_shutdown(signal: &str) {
        use std::{
            io::{BufRead as _, BufReader, Read as _},
            process::{Child, Command, Stdio},
            time::Instant,
        };

        struct StopChild(Child);
        impl Drop for StopChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        const MAX_OUTPUT: u64 = 64 * 1024;
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut child = StopChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "consensus_shutdown::tests::signal_shutdown_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("TEMPO_SHUTDOWN_TEST_CHILD", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut output = String::new();
            let mut done = false;
            // Bound even a missing newline or unexpected fixture output.
            for line in BufReader::new(stdout.take(MAX_OUTPUT + 1)).lines() {
                let line = line?;
                output.push_str(&line);
                output.push('\n');
                if output.len() as u64 > MAX_OUTPUT {
                    return Err(std::io::Error::other(
                        "shutdown child output exceeded limit",
                    ));
                }
                if line.contains("TEMPO_SHUTDOWN_TEST_READY") {
                    let _ = ready_tx.send(());
                }
                done |= line == "TEMPO_SHUTDOWN_TEST_DONE";
            }
            Ok((output, done))
        });
        ready_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("shutdown child did not become ready before deadline");
        assert!(
            Command::new("kill")
                .arg(format!("-{signal}"))
                .arg(child.0.id().to_string())
                .status()
                .expect("failed to signal shutdown child")
                .success()
        );
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown child exceeded deadline"
            );
            thread::sleep(Duration::from_millis(10));
        };
        let (output, done) = reader.join().unwrap().unwrap();
        assert!(
            status.success(),
            "shutdown child failed with {status}: {output}"
        );
        assert!(
            done,
            "shutdown child did not complete ordered cleanup: {output}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sdk_sigint_stops_consensus_before_engine() {
        assert_signal_shutdown("INT");
    }

    #[cfg(unix)]
    #[test]
    fn sdk_sigterm_stops_consensus_before_engine() {
        assert_signal_shutdown("TERM");
    }

    #[test]
    fn normal_return_and_outer_cleanup_join_only_once() {
        let shutdown = CancellationToken::new();
        let cl_shutdown = shutdown.clone();
        let exits = Arc::new(AtomicUsize::new(0));
        let cl_exits = exits.clone();
        let handle = thread::spawn(move || {
            futures::executor::block_on(cl_shutdown.cancelled());
            cl_exits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        let mut consensus = ConsensusThread::new(shutdown, handle);
        {
            let _guard = consensus.stop_on_drop();
        }
        consensus.stop_and_join();
        consensus.finish(Ok(())).unwrap();
        assert_eq!(exits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_unpolled_launcher_releases_startup_sender_before_join() {
        let (startup_tx, startup_rx) = oneshot::channel::<()>();
        let handle = thread::spawn(move || {
            startup_rx
                .blocking_recv()
                .wrap_err("consensus startup closed")?;
            panic!("an unpolled launcher must not start consensus");
        });
        let mut consensus = ConsensusThread::new(CancellationToken::new(), handle);
        let consensus_ref = &mut consensus;
        let launch = async move {
            startup_tx.send(()).unwrap();
            let _guard = consensus_ref.stop_on_drop();
            pending::<()>().await;
        };
        drop(launch);
        let err = consensus
            .finish(Err(eyre::eyre!("node launch cancelled")))
            .unwrap_err();
        let report = format!("{err:#}");
        assert!(report.contains("node launch cancelled"));
        assert!(report.contains("consensus startup closed"));
    }

    #[test]
    fn failed_launcher_releases_startup_sender_before_join() {
        let (startup_tx, startup_rx) = oneshot::channel::<()>();
        let handle = thread::spawn(move || {
            startup_rx
                .blocking_recv()
                .wrap_err("consensus startup closed")?;
            panic!("a failed launcher must not start consensus");
        });
        let consensus = ConsensusThread::new(CancellationToken::new(), handle);
        let result = futures::executor::block_on(async move {
            let _startup_tx = startup_tx;
            Err(eyre::eyre!("execution launch failed"))
        });
        let err = consensus.finish(result).unwrap_err();
        let report = format!("{err:#}");
        assert!(report.contains("execution launch failed"));
        assert!(report.contains("consensus startup closed"));
    }

    #[test]
    fn completed_consensus_failure_and_node_error_are_preserved() {
        for node_fails in [false, true] {
            let handle = thread::spawn(|| Err(eyre::eyre!("consensus failed before shutdown")));
            let mut consensus = ConsensusThread::new(CancellationToken::new(), handle);
            drop(consensus.stop_on_drop());
            let node_result = if node_fails {
                Err(eyre::eyre!("execution engine failed"))
            } else {
                Ok(())
            };
            let err = consensus.finish(node_result).unwrap_err();
            let report = format!("{err:#}");
            assert!(report.contains("consensus failed before shutdown"));
            assert_eq!(report.contains("execution engine failed"), node_fails);
        }
        let handle = thread::spawn(|| Ok(()));
        let consensus = ConsensusThread::new(CancellationToken::new(), handle);
        let err = consensus
            .finish(Err(eyre::eyre!("execution engine failed")))
            .unwrap_err();
        assert_eq!(err.to_string(), "execution engine failed");
    }

    #[test]
    fn consensus_panic_is_resumed_after_drop_cleanup() {
        let handle = thread::spawn(|| panic!("consensus panic"));
        let mut consensus = ConsensusThread::new(CancellationToken::new(), handle);
        assert!(catch_unwind(AssertUnwindSafe(|| drop(consensus.stop_on_drop()))).is_ok());
        let panic = catch_unwind(AssertUnwindSafe(|| consensus.finish(Ok(())))).unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"consensus panic"));
    }

    #[test]
    fn consensus_panic_does_not_double_panic_during_cli_unwind() {
        let panic = catch_unwind(|| {
            let handle = thread::spawn(|| panic!("consensus panic"));
            let _consensus = ConsensusThread::new(CancellationToken::new(), handle);
            panic!("CLI panic");
        })
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"CLI panic"));
    }

    #[test]
    fn joins_after_commonware_supervised_tasks_are_dropped() {
        struct MarkStopped(Arc<AtomicBool>);
        impl Drop for MarkStopped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        // Commonware syncs the entire storage filesystem before polling its
        // root task. This test only exercises task teardown, so keep that sync
        // away from unrelated build and test writes on the shared CI disk.
        #[cfg(target_os = "linux")]
        let storage = tempfile::tempdir_in("/dev/shm").unwrap();
        #[cfg(not(target_os = "linux"))]
        let storage = tempfile::tempdir().unwrap();
        let cfg = commonware_runtime::tokio::Config::default()
            .with_worker_threads(1)
            .with_storage_directory(storage.path().to_path_buf());
        let shutdown = CancellationToken::new();
        let cl_shutdown = shutdown.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let cl_stopped = stopped.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            commonware_runtime::tokio::Runner::new(cfg).start(async move |ctx| {
                let _task = ctx.child("worker").spawn(move |_| async move {
                    let _marker = MarkStopped(cl_stopped);
                    ready_tx.send(()).unwrap();
                    pending::<()>().await;
                });
                cl_shutdown.cancelled().await;
                Ok(())
            })
        });
        let mut consensus = ConsensusThread::new(shutdown, handle);
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(consensus.stop_on_drop());
        assert!(stopped.load(Ordering::SeqCst));
        consensus.finish(Ok(())).unwrap();
    }
}
