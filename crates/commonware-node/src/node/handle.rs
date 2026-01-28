//! Handle to a spawned consensus node.

use std::thread::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Handle to a spawned consensus node.
///
/// This handle provides control over the consensus node lifecycle:
/// - Call [`shutdown`](Self::shutdown) to trigger graceful shutdown
/// - Call [`join`](Self::join) to wait for the thread to complete
/// - Dropping the handle does NOT stop consensus
pub struct ConsensusNodeHandle {
    thread_handle: Option<JoinHandle<eyre::Result<()>>>,
    shutdown_token: CancellationToken,
}

impl ConsensusNodeHandle {
    /// Create a new handle with its shutdown token.
    /// The thread handle is attached later via `with_thread`.
    pub(super) fn create() -> (Self, CancellationToken) {
        let shutdown_token = CancellationToken::new();
        let handle = Self {
            thread_handle: None,
            shutdown_token: shutdown_token.clone(),
        };
        (handle, shutdown_token)
    }

    /// Attach the thread handle after spawning.
    pub(super) fn with_thread(mut self, thread_handle: JoinHandle<eyre::Result<()>>) -> Self {
        self.thread_handle = Some(thread_handle);
        self
    }

    /// Signal the consensus node to shut down gracefully.
    ///
    /// This triggers the internal cancellation token. The consensus stack
    /// will exit its event loop and the thread will complete.
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    /// Waits for the consensus node thread to complete and returns the result.
    ///
    /// # Panics
    /// Re-panics if the consensus thread panicked.
    pub fn join(self) -> eyre::Result<()> {
        match self.thread_handle.expect("thread handle not set").join() {
            Ok(result) => result,
            Err(unwind) => std::panic::resume_unwind(unwind),
        }
    }

    /// Checks if the consensus node thread has finished.
    pub fn is_finished(&self) -> bool {
        self.thread_handle.as_ref().is_some_and(|h| h.is_finished())
    }
}
