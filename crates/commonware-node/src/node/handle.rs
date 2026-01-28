//! Handle to interact with a spawned consensus node.

use std::thread::JoinHandle;

use tokio::sync::oneshot;

/// A receiver that signals when the consensus node has exited.
///
/// This can be awaited in async code to detect when consensus shuts down.
pub struct ConsensusDeadSignal(oneshot::Receiver<()>);

impl ConsensusDeadSignal {
    /// Waits for the consensus node to signal completion.
    pub async fn wait(self) {
        let _ = self.0.await;
    }
}

/// Handle to a spawned consensus node.
///
/// This handle allows waiting for the consensus node to complete
/// and checking if it's still running.
pub struct ConsensusNodeHandle {
    thread_handle: JoinHandle<eyre::Result<()>>,
    dead_rx: Option<oneshot::Receiver<()>>,
}

impl ConsensusNodeHandle {
    pub(super) fn new(
        thread_handle: JoinHandle<eyre::Result<()>>,
        dead_rx: oneshot::Receiver<()>,
    ) -> Self {
        Self {
            thread_handle,
            dead_rx: Some(dead_rx),
        }
    }

    /// Takes the dead signal receiver, which can be moved into async code.
    ///
    /// This can only be called once. Returns `None` if already taken.
    pub fn take_dead_signal(&mut self) -> Option<ConsensusDeadSignal> {
        self.dead_rx.take().map(ConsensusDeadSignal)
    }

    /// Waits for the consensus node thread to complete and returns the result.
    ///
    /// # Panics
    /// Re-panics if the consensus thread panicked.
    pub fn join(self) -> eyre::Result<()> {
        match self.thread_handle.join() {
            Ok(result) => result,
            Err(unwind) => std::panic::resume_unwind(unwind),
        }
    }

    /// Checks if the consensus node thread has finished.
    pub fn is_finished(&self) -> bool {
        self.thread_handle.is_finished()
    }
}
