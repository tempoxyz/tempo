//! Shared child ownership and cleanup for finite imports and private historical workers.

use crate::manifest::{Bootstrap, Era, Manifest};
use eyre::{Context, Result};
use std::{process::Stdio, time::Duration};
use tokio::process::{Child, Command};

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(10);

/// Start a canonical-file import from a validated manifest. The caller reaps this sole writer before opening a
/// read-only checkpoint worker or starting another import; cancellation falls back to kill-on-drop.
pub fn spawn_bootstrap(manifest: &Manifest, era: &Era, bootstrap: &Bootstrap) -> Result<Child> {
    spawn_child(
        Command::new(&era.binary)
            .args(&bootstrap.args)
            .args(["--chain", &manifest.chain, "--datadir"])
            .arg(&manifest.datadir)
            .arg("--fail-on-invalid-block"),
    )
    .wrap_err_with(|| {
        format!(
            "starting {} bootstrap from {}",
            era.name,
            era.binary.display()
        )
    })
}

/// Every supervised child uses the same I/O and cancellation fallback.
pub(crate) fn spawn_child(command: &mut Command) -> std::io::Result<Child> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
}

/// Signal all owned children before concurrently reaping them under one grace period.
/// Callers retain ownership across this await so cancellation still triggers `kill_on_drop`.
pub async fn shutdown_children<'a>(
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
    use crate::manifest::tests::manifest;
    use std::os::unix::fs::PermissionsExt;

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
    async fn bootstrap_uses_same_storage_and_requires_block_validation() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("tempo");
        let output = temp.path().join("tempo.args");
        // Keep arguments as distinct lines, including paths containing spaces.
        std::fs::write(&binary, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.args\"\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut manifest = manifest();
        manifest.datadir = temp.path().join("data with spaces");
        manifest.eras[0].binary = binary;
        manifest.eras[0].bootstrap.as_mut().unwrap().args =
            vec!["import".into(), "canonical-blocks.rlp".into()];
        let era = &manifest.eras[0];
        let mut child = spawn_bootstrap(&manifest, era, era.bootstrap.as_ref().unwrap()).unwrap();
        let pid = child.id().unwrap();
        assert!(child.wait().await.unwrap().success());
        let actual = std::fs::read_to_string(output).unwrap();
        assert_eq!(
            actual.lines().collect::<Vec<_>>(),
            vec![
                "import",
                "canonical-blocks.rlp",
                "--chain",
                &manifest.chain,
                "--datadir",
                manifest.datadir.to_str().unwrap(),
                "--fail-on-invalid-block",
            ]
        );
        assert_reaped(pid);
    }
}
