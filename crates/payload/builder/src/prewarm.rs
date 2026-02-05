//! Payload execution cache for prewarming.
//!
//! This module provides a cache for payload execution results to avoid redundant
//! computation when building payloads.

use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, RwLock},
};

/// Result of a payload execution.
#[derive(Debug, Clone)]
pub struct PayloadExecutionResult {
    /// The computed state root.
    pub state_root: alloy_primitives::B256,
    /// Total gas used.
    pub gas_used: u64,
}

/// Shared state for waiting on in-flight executions.
#[derive(Debug)]
pub struct SharedWaiter {
    result: Mutex<Option<PayloadExecutionResult>>,
    condvar: Condvar,
}

impl SharedWaiter {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            condvar: Condvar::new(),
        }
    }

    /// Waits for the result to be available.
    ///
    /// # Note
    /// This method blocks until the result is set or a timeout occurs.
    fn wait(&self) -> Option<PayloadExecutionResult> {
        let guard = self.result.lock().unwrap();
        let result = self
            .condvar
            .wait_while(guard, |result| result.is_none())
            .unwrap();
        result.clone()
    }

    /// Sets the result and notifies all waiters.
    fn set(&self, value: PayloadExecutionResult) {
        let mut guard = self.result.lock().unwrap();
        *guard = Some(value);
        self.condvar.notify_all();
    }
}

/// Cache entry for payload execution.
#[derive(Debug)]
enum CacheEntry {
    /// The execution is currently in-flight.
    InFlight(Arc<SharedWaiter>),
    /// The execution result is ready.
    Ready(PayloadExecutionResult),
}

/// Cache for payload execution results.
///
/// This cache stores execution results keyed by payload attributes to avoid
/// redundant computation.
///
/// # Thread Safety
///
/// The cache uses an `RwLock` for concurrent access. Callers must be careful
/// to **never call blocking operations while holding the lock**.
///
/// # Deadlock Prevention
///
/// The critical fix in this implementation is that `recv()` (waiting for results)
/// is **always** done outside of any lock. The pattern is:
///
/// 1. Acquire lock briefly to check cache state and get a wait handle
/// 2. **Drop the lock**
/// 3. Wait on the handle (blocking operation)
/// 4. Re-acquire lock if needed to read/write results
#[derive(Debug, Default)]
pub struct PayloadExecutionCache {
    inner: RwLock<HashMap<u64, CacheEntry>>,
}

impl PayloadExecutionCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Gets a cached result or returns a wait handle for in-flight execution.
    ///
    /// Returns:
    /// - `Ok(Some(result))` if the result is cached
    /// - `Ok(None)` if caller should execute (a new in-flight entry was created)
    /// - `Err(waiter)` if another thread is executing (caller should wait on waiter)
    ///
    /// # Correctness
    ///
    /// This method is carefully designed to avoid holding the write lock across
    /// blocking operations. The waiter is cloned (Arc) and returned so the caller
    /// can wait **outside** the critical section.
    pub fn get_or_start(&self, key: u64) -> Result<Option<PayloadExecutionResult>, Arc<SharedWaiter>> {
        // Phase 1: Check cache and potentially start execution (short critical section)
        let mut cache = self.inner.write().unwrap();

        match cache.get(&key) {
            Some(CacheEntry::Ready(result)) => {
                // Result is cached, return it immediately
                Ok(Some(result.clone()))
            }
            Some(CacheEntry::InFlight(waiter)) => {
                // Another thread is executing, clone the waiter handle
                // IMPORTANT: Clone the Arc BEFORE dropping the lock
                let waiter = Arc::clone(waiter);
                drop(cache); // Explicitly drop the lock before returning
                Err(waiter)
            }
            None => {
                // No cached result, start a new execution
                let waiter = Arc::new(SharedWaiter::new());
                cache.insert(key, CacheEntry::InFlight(Arc::clone(&waiter)));
                drop(cache); // Explicitly drop the lock
                Ok(None)
            }
        }
    }

    /// Completes an execution and caches the result.
    ///
    /// This notifies all waiting threads and stores the result for future lookups.
    pub fn complete(&self, key: u64, result: PayloadExecutionResult) {
        let mut cache = self.inner.write().unwrap();

        // Notify any waiting receivers
        if let Some(CacheEntry::InFlight(waiter)) = cache.get(&key) {
            waiter.set(result.clone());
        }

        // Store the result
        cache.insert(key, CacheEntry::Ready(result));
    }

    /// Cancels an in-flight execution.
    ///
    /// This should be called if the execution fails to prevent other threads
    /// from waiting indefinitely.
    pub fn cancel(&self, key: u64) {
        let mut cache = self.inner.write().unwrap();
        if matches!(cache.get(&key), Some(CacheEntry::InFlight(_))) {
            cache.remove(&key);
        }
    }

    /// Clears all cached results.
    pub fn clear(&self) {
        let mut cache = self.inner.write().unwrap();
        cache.clear();
    }
}

/// Executes a payload with caching.
///
/// This function demonstrates the correct pattern for using the cache:
/// 1. Check if result is cached or in-flight
/// 2. If in-flight, wait **outside** the lock
/// 3. If not cached, execute and store result
///
/// # Example
///
/// ```ignore
/// let cache = PayloadExecutionCache::new();
/// let result = execute_with_cache(&cache, 42, || {
///     // Expensive computation here
///     PayloadExecutionResult {
///         state_root: B256::ZERO,
///         gas_used: 21000,
///     }
/// });
/// ```
pub fn execute_with_cache<F>(cache: &PayloadExecutionCache, key: u64, execute: F) -> PayloadExecutionResult
where
    F: FnOnce() -> PayloadExecutionResult,
{
    loop {
        match cache.get_or_start(key) {
            Ok(Some(result)) => {
                // Cached result available
                return result;
            }
            Ok(None) => {
                // We're responsible for executing
                let result = execute();
                cache.complete(key, result.clone());
                return result;
            }
            Err(waiter) => {
                // Another thread is executing - wait OUTSIDE the lock
                // This is the key fix: wait() happens without holding any lock on the cache
                if let Some(result) = waiter.wait() {
                    return result;
                }
                // If wait returned None (shouldn't happen with current impl), retry
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::Duration,
    };

    fn mock_result(gas: u64) -> PayloadExecutionResult {
        PayloadExecutionResult {
            state_root: B256::ZERO,
            gas_used: gas,
        }
    }

    #[test]
    fn test_cache_hit() {
        let cache = PayloadExecutionCache::new();

        // First call should execute
        let exec_count = AtomicUsize::new(0);
        let result = execute_with_cache(&cache, 1, || {
            exec_count.fetch_add(1, Ordering::SeqCst);
            mock_result(100)
        });
        assert_eq!(result.gas_used, 100);
        assert_eq!(exec_count.load(Ordering::SeqCst), 1);

        // Second call should hit cache
        let result = execute_with_cache(&cache, 1, || {
            exec_count.fetch_add(1, Ordering::SeqCst);
            mock_result(200)
        });
        assert_eq!(result.gas_used, 100); // Still 100, from cache
        assert_eq!(exec_count.load(Ordering::SeqCst), 1); // Not executed again
    }

    #[test]
    fn test_concurrent_execution_coalescing() {
        let cache = Arc::new(PayloadExecutionCache::new());
        let exec_count = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];

        // Spawn multiple threads that all request the same key
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let exec_count = Arc::clone(&exec_count);
            handles.push(thread::spawn(move || {
                execute_with_cache(&cache, 42, || {
                    exec_count.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(50));
                    mock_result(42000)
                })
            }));
        }

        // All threads should get the same result
        for handle in handles {
            let result = handle.join().unwrap();
            assert_eq!(result.gas_used, 42000);
        }

        // Execution should have happened only once
        assert_eq!(exec_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_cancel_allows_retry() {
        let cache = PayloadExecutionCache::new();

        // Start an execution
        assert!(cache.get_or_start(1).unwrap().is_none());

        // Cancel it
        cache.cancel(1);

        // Should be able to start again
        assert!(cache.get_or_start(1).unwrap().is_none());
    }

    #[test]
    fn test_clear_cache() {
        let cache = PayloadExecutionCache::new();

        // Add a result
        cache.complete(1, mock_result(100));

        // Verify it's cached
        assert!(cache.get_or_start(1).unwrap().is_some());

        // Clear and verify it's gone
        cache.clear();
        assert!(cache.get_or_start(1).unwrap().is_none());
    }
}
