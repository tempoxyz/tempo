//! Standard-compatible threads and borrowed scopes for the selected backend.

pub use crate::time::sleep;
#[cfg(feature = "fuzz")]
pub use shuttle::thread::{
    JoinHandle, Result, Scope, ScopedJoinHandle, Thread, ThreadId, current, panicking, park, scope,
    spawn, yield_now,
};
#[cfg(not(feature = "fuzz"))]
pub use std::thread::{
    Builder, JoinHandle, Result, Scope, ScopedJoinHandle, Thread, ThreadId, current, panicking,
    park, scope, spawn, yield_now,
};

/// Parks until unparked or the selected clock reaches the timeout.
pub fn park_timeout(duration: crate::time::Duration) {
    #[cfg(not(feature = "fuzz"))]
    std::thread::park_timeout(duration);
    #[cfg(feature = "fuzz")]
    {
        let timer = crate::deterministic::Timer::new(crate::time::Instant::now() + duration);
        shuttle::thread::park();
        drop(timer);
    }
}

/// Returns available native parallelism, or one logical execution thread in simulation.
pub fn available_parallelism() -> std::io::Result<std::num::NonZeroUsize> {
    #[cfg(not(feature = "fuzz"))]
    {
        std::thread::available_parallelism()
    }
    #[cfg(feature = "fuzz")]
    {
        Ok(std::num::NonZeroUsize::MIN)
    }
}

/// A logical thread builder; scoped tasks inherit their scope's stack settings.
#[cfg(feature = "fuzz")]
#[derive(Debug, Default)]
pub struct Builder(shuttle::thread::Builder);

#[cfg(feature = "fuzz")]
impl Builder {
    /// Creates a thread builder with default settings.
    pub fn new() -> Self {
        Self(shuttle::thread::Builder::new())
    }
    /// Sets the name of a non-scoped logical thread.
    pub fn name(self, name: String) -> Self {
        Self(self.0.name(name))
    }
    /// Sets stack size for a non-scoped logical thread.
    pub fn stack_size(self, size: usize) -> Self {
        Self(self.0.stack_size(size))
    }
    /// Spawns a named logical thread in the current simulation.
    pub fn spawn<F, T>(self, work: F) -> std::io::Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.0.spawn(work)
    }
    /// Spawns a borrowing logical thread; Shuttle does not support scoped metadata.
    ///
    /// Configured name and stack size apply only to non-scoped threads.
    pub fn spawn_scoped<'scope, 'env, F, T>(
        self,
        scope: &'scope Scope<'scope, 'env>,
        work: F,
    ) -> std::io::Result<ScopedJoinHandle<'scope, T>>
    where
        F: FnOnce() -> T + Send + 'scope,
        T: Send + 'scope,
    {
        Ok(scope.spawn(work))
    }
}
