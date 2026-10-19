//! Child process lifecycle with bounded shutdown.

use eyre::{WrapErr as _, eyre};
use futures::future::join_all;
use std::{io, ops::ControlFlow, process::Stdio, time::Duration};
use tokio::{
    process::{Child, Command},
    time::Instant,
};
use tracing::warn;

/// Time children get to exit after SIGTERM before they are killed.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Spawns `cmd` with stdin closed, stdout/stderr inherited, and `kill_on_drop` set.
pub fn spawn_child(cmd: &mut Command) -> io::Result<Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
}

/// Runs a child to completion. `Break` if a shutdown signal stopped it, error on non-zero exit.
pub async fn run_child(name: &str, mut cmd: Command) -> eyre::Result<ControlFlow<()>> {
    let mut child = spawn_child(&mut cmd).wrap_err_with(|| format!("failed to spawn {name}"))?;
    tokio::select! {
        status = child.wait() => {
            let status = status.wrap_err_with(|| format!("failed to wait for {name}"))?;
            eyre::ensure!(status.success(), "{name} exited with {status}");
            Ok(ControlFlow::Continue(()))
        }
        signal = shutdown_signal() => {
            let stopped = shutdown_children([(name, &mut child)]).await;
            signal.wrap_err("failed to listen for shutdown signals")?;
            stopped?;
            Ok(ControlFlow::Break(()))
        }
    }
}

/// SIGTERMs every child, then reaps them concurrently, killing those alive after the grace.
///
/// Returns the first error once all are reaped. Callers keep ownership, so dropping this future
/// still kills them through `kill_on_drop`.
pub async fn shutdown_children<'a>(
    children: impl IntoIterator<Item = (&'a str, &'a mut Child)>,
) -> eyre::Result<()> {
    let mut children: Vec<_> = children.into_iter().collect();
    let mut first_error = None;
    for (name, child) in &mut children {
        if let Err(err) = terminate(child) {
            if let Err(kill) = child.start_kill() {
                warn!(%kill, name, "failed to kill child after signaling failed");
            }
            first_error.get_or_insert(eyre!(err).wrap_err(format!("failed to signal {name}")));
        }
    }

    let deadline = Instant::now() + SHUTDOWN_GRACE;
    let results = join_all(children.into_iter().map(|(name, child)| async move {
        match tokio::time::timeout_at(deadline, child.wait()).await {
            Ok(status) => status.map(drop),
            Err(_) => child.kill().await,
        }
        .wrap_err_with(|| format!("failed to reap {name}"))
    }))
    .await;
    for result in results {
        if let Err(err) = result {
            first_error.get_or_insert(err);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Asks `child` to exit. One that already exited is fine.
#[cfg(unix)]
fn terminate(child: &mut Child) -> io::Result<()> {
    // `None` once the child has been reaped.
    let Some(pid) = child.id() else { return Ok(()) };
    let pid = libc::pid_t::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: `kill` has no memory-safety preconditions.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
        return Ok(());
    }
    match io::Error::last_os_error() {
        err if err.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        err => Err(err),
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) -> io::Result<()> {
    child.start_kill()
}

/// Resolves on Ctrl-C, or SIGTERM on unix.
async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);
        cmd
    }

    fn is_reaped(pid: u32) -> bool {
        // SAFETY: probing with signal 0 has no side effects.
        let rc = unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), 0) };
        rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[tokio::test]
    async fn run_child_reports_failures() {
        assert_eq!(
            run_child("ok", sh("exit 0")).await.unwrap(),
            ControlFlow::Continue(())
        );
        for (cmd, expected) in [
            (
                Command::new("/nonexistent/tempo-era"),
                "failed to spawn era",
            ),
            (sh("exit 3"), "era exited with exit status: 3"),
        ] {
            assert_eq!(
                run_child("era", cmd).await.unwrap_err().to_string(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn shutdown_reaps_exited_and_running_children() {
        let mut exited = spawn_child(&mut sh("exit 0")).unwrap();
        let mut running = spawn_child(&mut sh("sleep 60")).unwrap();
        // Ignores SIGTERM, so it must be killed after the grace period.
        let mut stubborn = spawn_child(&mut sh("trap '' TERM; sleep 60")).unwrap();
        let pids = [exited.id(), running.id(), stubborn.id()].map(Option::unwrap);
        // Let the shell install its trap before signaling.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let children = [
            ("exited", &mut exited),
            ("running", &mut running),
            ("stubborn", &mut stubborn),
        ];
        tokio::time::timeout(SHUTDOWN_GRACE * 2, shutdown_children(children))
            .await
            .unwrap()
            .unwrap();
        for pid in pids {
            assert!(is_reaped(pid), "{pid} still exists");
        }
        assert_eq!(running.try_wait().unwrap().unwrap().code(), None);
    }
}
