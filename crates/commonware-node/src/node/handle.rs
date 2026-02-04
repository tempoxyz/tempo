//! Handle to a spawned consensus node.
//!
//! Provides bidirectional control: signal shutdown to the consensus thread,
//! and be notified when it exits (success, error, or panic).

use eyre::eyre;
use std::thread::JoinHandle;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Future that completes when the consensus node exits.
pub type ConsensusExitFuture = oneshot::Receiver<eyre::Result<()>>;

/// Handle to a spawned consensus node.
pub struct ConsensusNodeHandle {
    shutdown_token: CancellationToken,
    thread_handle: JoinHandle<eyre::Result<()>>,
}

impl ConsensusNodeHandle {
    pub(crate) fn new(
        shutdown_token: CancellationToken,
        thread_handle: JoinHandle<eyre::Result<()>>,
    ) -> Self {
        Self {
            shutdown_token,
            thread_handle,
        }
    }

    /// Signal shutdown and wait for the thread. Returns `Err` if the consensus thread failed already.
    pub fn shutdown(self) -> eyre::Result<()> {
        self.shutdown_token.cancel();
        match self.thread_handle.join() {
            Ok(result) => result,
            Err(_) => Err(eyre!("consensus thread panicked")),
        }
    }
}
