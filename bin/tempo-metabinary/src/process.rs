//! Shared child ownership and cleanup for finite writer children and private historical workers.

use eyre::{Context, Result, ensure};
use std::{ops::ControlFlow, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Every supervised child uses the same I/O and cancellation fallback.
pub(crate) fn spawn_child(command: &mut Command) -> std::io::Result<Child> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
}

/// Run a finite child to successful completion; an unsuccessful exit is an error. A shutdown signal
/// stops and reaps it instead, returning `Break`.
pub async fn run_child(name: &str, command: &mut Command) -> Result<ControlFlow<()>> {
    let mut child = spawn_child(command).wrap_err_with(|| format!("starting {name}"))?;
    let result = tokio::select! {
        status = child.wait() => status.map(Some).map_err(Into::into),
        result = shutdown_signal() => result.map(|()| None),
    };
    let shutdown = shutdown_children([(name, &mut child)]).await;
    let status = result?;
    shutdown?;
    let Some(status) = status else {
        return Ok(ControlFlow::Break(()));
    };
    ensure!(status.success(), "{name} exited with {status}");
    Ok(ControlFlow::Continue(()))
}

/// Wait for a node shutdown signal.
pub(crate) async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// Signal all owned children before concurrently reaping them under one grace period.
/// Callers retain ownership across this await so cancellation still triggers `kill_on_drop`.
pub(crate) async fn shutdown_children<'a>(
    children: impl IntoIterator<Item = (&'a str, &'a mut Child)>,
) -> Result<()> {
    let mut children: Vec<_> = children.into_iter().collect();
    let mut first_error = None;
    for (name, child) in &mut children {
        if let Err(error) = request_termination(child) {
            first_error.get_or_insert_with(|| error.wrap_err(format!("stopping {name}")));
            let _ = child.start_kill();
        }
    }
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE_PERIOD;
    let reap_error =
        futures::future::join_all(children.into_iter().map(|(name, child)| async move {
            wait_for_exit(child, deadline)
                .await
                .wrap_err_with(|| format!("reaping {name}"))
        }))
        .await
        .into_iter()
        .find_map(Result::err);
    first_error.or(reap_error).map_or(Ok(()), Err)
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
    if let Ok(result) = tokio::time::timeout_at(deadline, child.wait()).await {
        result?;
    } else {
        child.kill().await?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn assert_reaped(pid: u32) {
        // SAFETY: signal zero only checks whether the process exists.
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[tokio::test]
    async fn failed_spawn_and_shutdown_reap_every_child() {
        let mut children: Vec<_> = ["exec sleep 60", "exec sleep 60", "exit 7"]
            .into_iter()
            .map(|command| spawn_child(Command::new("/bin/sh").args(["-c", command])).unwrap())
            .collect();
        let pids: Vec<_> = children.iter().map(|child| child.id().unwrap()).collect();
        assert!(spawn_child(&mut Command::new("/nonexistent-tempo-test")).is_err());
        children[2].wait().await.unwrap();
        wait_for_exit(&mut children[1], tokio::time::Instant::now())
            .await
            .unwrap();
        shutdown_children(children.iter_mut().map(|child| ("test worker", child)))
            .await
            .unwrap();
        for pid in pids {
            assert_reaped(pid);
        }
    }

    #[tokio::test]
    async fn finite_children_must_exit_successfully() {
        let run = |script| async move {
            run_child("test child", Command::new("/bin/sh").args(["-c", script])).await
        };
        assert_eq!(run("exit 0").await.unwrap(), ControlFlow::Continue(()));
        assert_eq!(
            run("exit 7").await.unwrap_err().to_string(),
            "test child exited with exit status: 7"
        );
    }
}
