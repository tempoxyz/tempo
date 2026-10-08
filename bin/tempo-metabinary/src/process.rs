//! Ordinary Tempo processes supervised by the wrapper. No database code belongs here.

use crate::manifest::{Era, Manifest};
use eyre::{Context, Result, bail, ensure};
use std::{ffi::OsString, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

struct Worker {
    name: String,
    child: Child,
}

/// Owns every child, including temporary bootstrap commands.
///
/// Call [`Self::shutdown`] to terminate and reap children cleanly. `kill_on_drop` is a
/// cancellation fallback so a failed startup cannot leave a live writer behind.
#[derive(Default)]
pub struct ProcessGroup {
    workers: Vec<Worker>,
}

impl ProcessGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn worker_pid(&self, name: &str) -> Option<u32> {
        self.workers
            .iter()
            .find(|worker| worker.name == name)
            .and_then(|worker| worker.child.id())
    }

    /// Start the sole database writer. Wait for its RPC readiness before starting readers.
    pub fn spawn_live(&mut self, manifest: &Manifest) -> Result<()> {
        manifest.validate()?;
        let era = manifest.live();
        let mut args = vec![OsString::from("node")];
        args.extend(era.node_args.iter().map(OsString::from));
        shared_args(manifest, &mut args);
        args.extend([
            "--http".into(),
            "--http.addr".into(),
            "127.0.0.1".into(),
            "--http.port".into(),
            era.rpc_port.to_string().into(),
            "--http.api".into(),
            "all".into(),
            "--ipcdisable".into(),
        ]);
        if let Some(port) = era.ws_port {
            args.extend([
                "--ws".into(),
                "--ws.addr".into(),
                "127.0.0.1".into(),
                "--ws.port".into(),
                port.to_string().into(),
                "--ws.api".into(),
                "all".into(),
            ]);
        }
        self.spawn(era, &args, &era.name)
    }

    pub fn spawn_history(&mut self, manifest: &Manifest) -> Result<()> {
        manifest.validate()?;
        for index in 0..manifest.eras.len() - 1 {
            self.spawn_reader(manifest, index)?;
        }
        Ok(())
    }

    /// Start a read-only RPC worker, also used to inspect storage after a bootstrap phase.
    pub fn spawn_reader(&mut self, manifest: &Manifest, index: usize) -> Result<()> {
        manifest.validate()?;
        let era = manifest
            .eras
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown era index {index}"))?;
        let mut args = vec![OsString::from("rpc-only")];
        shared_args(manifest, &mut args);
        args.extend(["--port".into(), era.rpc_port.to_string().into()]);
        self.spawn(era, &args, &era.name)
    }

    /// Run one era's canonical block import. Only one writer may run at a time.
    /// The caller must verify its pinned checkpoint via `spawn_reader` before advancing.
    pub async fn run_bootstrap(&mut self, manifest: &Manifest, index: usize) -> Result<()> {
        manifest.validate_bootstrap()?;
        ensure!(
            self.workers.is_empty(),
            "stop all workers before running bootstrap"
        );
        let era = manifest
            .eras
            .get(index)
            .ok_or_else(|| eyre::eyre!("unknown era index {index}"))?;
        let bootstrap = era
            .bootstrap
            .as_ref()
            .ok_or_else(|| eyre::eyre!("era {} has no bootstrap", era.name))?;
        let mut args: Vec<OsString> = bootstrap.args.iter().map(OsString::from).collect();
        shared_args(manifest, &mut args);
        args.push("--fail-on-invalid-block".into());
        self.spawn(era, &args, &format!("{} bootstrap", era.name))?;
        let result = self.workers[0].child.wait().await;
        // Remove only after wait has completed: cancellation keeps the child owned and killed.
        let status = result.wrap_err_with(|| format!("waiting for {} bootstrap", era.name))?;
        self.workers.clear();
        ensure!(
            status.success(),
            "{} bootstrap exited with {status}",
            era.name
        );
        Ok(())
    }

    /// An unexpected exit must stop the public server and the remaining workers.
    pub fn check_alive(&mut self) -> Result<()> {
        for worker in &mut self.workers {
            if let Some(status) = worker
                .child
                .try_wait()
                .wrap_err_with(|| format!("checking {}", worker.name))?
            {
                bail!("worker {} exited with {status}", worker.name);
            }
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let mut first_error = None;
        let mut workers = std::mem::take(&mut self.workers);
        // Request every shutdown before waiting, so a slow reader cannot keep the writer alive.
        // Readers are launched after the writer, so signal them first.
        for worker in workers.iter_mut().rev() {
            if let Err(error) = request_termination(&mut worker.child) {
                first_error
                    .get_or_insert_with(|| error.wrap_err(format!("stopping {}", worker.name)));
                let _ = worker.child.start_kill();
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let results = futures::future::join_all(workers.iter_mut().map(|worker| async {
            wait_for_exit(&mut worker.child, deadline)
                .await
                .wrap_err_with(|| format!("reaping {}", worker.name))
        }))
        .await;
        for result in results {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn spawn(&mut self, era: &Era, args: &[OsString], name: &str) -> Result<()> {
        ensure!(
            !self.workers.iter().any(|worker| worker.name == name),
            "worker {name} already running"
        );
        let child = Command::new(&era.binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .wrap_err_with(|| format!("starting {name} from {}", era.binary.display()))?;
        self.workers.push(Worker {
            name: name.to_owned(),
            child,
        });
        Ok(())
    }
}

fn shared_args(manifest: &Manifest, args: &mut Vec<OsString>) {
    args.extend([
        "--chain".into(),
        manifest.chain.clone().into(),
        "--datadir".into(),
        manifest.datadir.as_os_str().to_owned(),
    ]);
}

fn request_termination(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: kill does not dereference memory. A PID remains ours until it is reaped.
        let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
    }
    #[cfg(not(unix))]
    child.start_kill()?;

    Ok(())
}

async fn wait_for_exit(child: &mut Child, deadline: tokio::time::Instant) -> Result<()> {
    match tokio::time::timeout_at(deadline, child.wait()).await {
        Ok(result) => {
            result?;
        }
        Err(_) => {
            child.kill().await?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::manifest::Bootstrap;
    use std::os::unix::fs::PermissionsExt;

    fn era(binary: &str, name: &str) -> Era {
        Era {
            name: name.into(),
            start_timestamp: 0,
            binary: binary.into(),
            node_args: vec![],
            rpc_port: 18545,
            ws_port: None,
            bootstrap: None,
        }
    }

    #[tokio::test]
    async fn shutdown_reaps_all_children_even_after_one_exits() {
        let mut group = ProcessGroup::new();
        group
            .spawn(
                &era("/bin/sh", "running"),
                &["-c".into(), "exec sleep 60".into()],
                "running",
            )
            .unwrap();
        group
            .spawn(
                &era("/bin/sh", "exited"),
                &["-c".into(), "exit 7".into()],
                "exited",
            )
            .unwrap();
        let running_pid = group.workers[0].child.id().unwrap();
        group.workers[1].child.wait().await.unwrap();
        assert!(group.check_alive().is_err());
        group.shutdown().await.unwrap();
        assert!(group.workers.is_empty());
        // ESRCH demonstrates that the subprocess was reaped, not just signalled.
        assert_eq!(unsafe { libc::kill(running_pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test]
    async fn failed_spawn_keeps_previous_child_owned_for_cleanup() {
        let mut group = ProcessGroup::new();
        group
            .spawn(
                &era("/bin/sh", "first"),
                &["-c".into(), "exec sleep 60".into()],
                "first",
            )
            .unwrap();
        assert!(
            group
                .spawn(&era("/nonexistent-tempo-test", "second"), &[], "second")
                .is_err()
        );
        assert_eq!(group.workers.len(), 1);
        group.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn bootstrap_uses_same_storage_and_requires_block_validation() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("tempo");
        let output = temp.path().join("tempo.args");
        // Keep arguments as distinct lines, including paths containing spaces.
        std::fs::write(&binary, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut frozen = era(binary.to_str().unwrap(), "frozen");
        frozen.bootstrap = Some(Bootstrap {
            args: vec!["import".into(), "canonical-blocks.rlp".into()],
            terminal_block_number: 42,
            terminal_block_hash: format!("0x{}", "11".repeat(32)),
        });
        let mut live = era("/bin/false", "live");
        live.start_timestamp = 100;
        live.rpc_port = 18546;
        let manifest = Manifest {
            chain: "tempo".into(),
            datadir: temp.path().join("data with spaces"),
            chain_id: "0x1".into(),
            genesis_hash: format!("0x{}", "00".repeat(32)),
            eras: vec![frozen, live],
        };
        let mut group = ProcessGroup::new();
        group.run_bootstrap(&manifest, 0).await.unwrap();
        let actual = std::fs::read_to_string(output).unwrap();
        assert_eq!(
            actual.lines().collect::<Vec<_>>(),
            vec![
                "import",
                "canonical-blocks.rlp",
                "--chain",
                "tempo",
                "--datadir",
                manifest.datadir.to_str().unwrap(),
                "--fail-on-invalid-block",
            ]
        );
        assert!(group.workers.is_empty());
    }
}
