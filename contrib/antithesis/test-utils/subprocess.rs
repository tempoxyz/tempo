//! Shared cleanup for socket subprocess tests.

use std::{
    fs,
    io::{self, ErrorKind, Write},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// Owns a test command and its socket directory, including during unwinding.
pub(crate) struct SocketProcess {
    /// Private directory removed after the child exits, even on panic.
    pub(crate) directory: PathBuf,
    /// None before spawning and after collecting output.
    pub(crate) child: Option<Child>,
}

impl SocketProcess {
    /// Creates the directory before any fallible socket setup or spawning.
    pub(crate) fn new() -> io::Result<Self> {
        let directory = std::env::temp_dir().join(format!(
            "trie-command-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        Ok(Self { directory, child: None })
    }

    /// Reaps by the caller's deadline and collects output; timeout leaves cleanup to Drop.
    pub(crate) fn output(&mut self, deadline: Instant) -> io::Result<Output> {
        wait(self.child.as_mut().expect("command was spawned"), deadline)?;
        // The child is already reaped; collecting its output cannot wait for its exit.
        let output = self.child.take().expect("command was spawned").wait_with_output()?;
        fs::remove_dir_all(&self.directory)?;
        Ok(output)
    }
}

impl Drop for SocketProcess {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(_)) => {}
                status => {
                    if let Err(error) = status {
                        report(error);
                    }
                    if let Err(error) = child.kill() {
                        // The child may have exited between try_wait and kill.
                        if error.kind() != ErrorKind::InvalidInput {
                            report(error);
                        }
                    }
                    // try_wait reaps too, without an unbounded wait if killing failed.
                    if let Err(error) = wait(child, Instant::now() + CLEANUP_TIMEOUT) {
                        report(error);
                    }
                }
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.directory) &&
            error.kind() != ErrorKind::NotFound
        {
            report(error);
        }
    }
}

fn wait(child: &mut Child, deadline: Instant) -> io::Result<()> {
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(ErrorKind::TimedOut, "test command did not finish"));
        }
        thread::yield_now();
    }
    Ok(())
}

fn report(error: io::Error) {
    if writeln!(io::stderr().lock(), "test command cleanup: {error}").is_err() {
        // A closed stderr cannot report cleanup errors; never panic while unwinding.
    }
}
