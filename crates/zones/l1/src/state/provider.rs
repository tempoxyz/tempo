//! Cache-first, RPC-fallback provider for reading L1 contract storage slots.
//!
//! [`L1StateProvider`] wraps a [`L1StateCache`] and a [`DynProvider<TempoNetwork>`] backed by an
//! HTTP transport. Reads are served from the in-memory cache when possible. On cache miss the
//! provider falls back to `eth_getStorageAt` via the shared HTTP provider and writes the result
//! back into the cache.
//!
//! Both a synchronous ([`L1StateProvider::get_storage`]) and an asynchronous
//! ([`L1StateProvider::get_storage_async`]) entry point are provided. The synchronous variant is
//! intended for use inside EVM precompiles where async is unavailable — it retries the RPC
//! call indefinitely with exponential backoff to avoid bricking the chain on transient outages.
//! RPC simulations and cache prewarming instead make one time-limited attempt, so an outage fails
//! them rather than holding RPC permits or prewarming threads.

use alloy_primitives::{Address, B256, U256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use eyre::Result;
use std::{num::NonZeroU32, time::Duration};
use tempo_alloy::TempoNetwork;
use tracing::{debug, info, warn};
use zone_precompiles::{
    L1StateError, L1StorageReader,
    tx_context::{self, ExecutionOrigin},
};

use super::cache::L1StateCache;
use crate::{metrics::L1StateMetricsByOrigin, rpc::rpc_connection_config};

/// Synchronous RPC attempts per cache miss during an RPC simulation or cache prewarming.
const NON_CANONICAL_SYNC_ATTEMPTS: NonZeroU32 = NonZeroU32::MIN;

/// Time limit on one cache-miss fetch during an RPC simulation or cache prewarming, so an L1
/// endpoint that stops responding fails the execution.
const NON_CANONICAL_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for the [`L1StateProvider`].
#[derive(Debug, Clone)]
pub struct L1StateProviderConfig {
    /// Optional known L1 chain ID, avoiding an RPC lookup when configured.
    pub chain_id: Option<u64>,
    /// HTTP RPC endpoint for Tempo L1.
    pub l1_rpc_url: String,
    /// Zone portal address on Tempo L1, used for sequencer lookups.
    pub portal_address: Address,
    /// Maximum number of transport-level retries for failed/rate-limited RPC requests.
    /// Defaults to 10.
    pub max_retries: u32,
    /// Initial backoff in milliseconds for the transport-level retry layer.
    /// Defaults to 20ms.
    pub initial_backoff_ms: u64,
    /// Interval between WebSocket reconnection attempts.
    /// Defaults to 100ms.
    pub retry_connection_interval: std::time::Duration,
    /// Maximum number of synchronous RPC attempts per cache miss. `None` retries indefinitely.
    /// RPC simulations and cache prewarming always make a single attempt.
    pub max_sync_attempts: Option<NonZeroU32>,
}

impl Default for L1StateProviderConfig {
    fn default() -> Self {
        Self {
            chain_id: None,
            l1_rpc_url: String::new(),
            portal_address: Address::ZERO,
            max_retries: 10,
            initial_backoff_ms: 20,
            retry_connection_interval: std::time::Duration::from_millis(100),
            max_sync_attempts: None,
        }
    }
}

/// Cache-first, RPC-fallback provider for reading Tempo L1 contract storage.
///
/// `L1StateProvider` is the core bridge between synchronous EVM execution (precompiles) and the
/// asynchronous L1 RPC layer. It holds:
///
/// - A [`L1StateCache`] for fast in-memory lookups.
/// - A [`DynProvider<TempoNetwork>`] (alloy HTTP provider) created once and reused across calls.
/// - A [`tokio::runtime::Handle`] used by the synchronous [`get_storage`](Self::get_storage)
///   method to dispatch async work from a blocking context.
///
/// # Sync dispatch safety
///
/// [`get_storage`](Self::get_storage) calls `runtime_handle.block_on(...)` to execute the async
/// RPC fetch. This is safe **only** when the caller is running on a blocking / OS thread that is
/// *not* part of the tokio async runtime (e.g. the EVM execution thread spawned via
/// `spawn_blocking`). Calling it from within an async task on the same runtime will panic.
#[derive(Debug, Clone)]
pub struct L1StateProvider {
    /// Known L1 chain ID, if configured.
    chain_id: Option<u64>,
    /// In-memory cache of L1 contract storage slots, checked before any RPC call.
    cache: L1StateCache,
    /// HTTP provider pointed at **Tempo L1**, used as a fallback when the cache misses.
    /// Wraps a [`RetryBackoffLayer`] that handles retries with exponential backoff.
    provider: DynProvider<TempoNetwork>,
    /// Handle to the tokio runtime, used by [`get_storage`](Self::get_storage) to
    /// dispatch async RPC calls from a blocking (non-async) context.
    runtime_handle: tokio::runtime::Handle,
    /// Optional finite attempt limit for synchronous cache-miss fallback outside RPC simulations and prewarming.
    max_sync_attempts: Option<NonZeroU32>,
    metrics: L1StateMetricsByOrigin,
}

impl L1StateProvider {
    /// Returns the chain ID reported by the configured L1 provider.
    pub async fn chain_id(&self) -> Result<u64> {
        match self.chain_id {
            Some(chain_id) => Ok(chain_id),
            None => Ok(self.provider.get_chain_id().await?),
        }
    }

    /// Create a new provider.
    ///
    /// The provider is created eagerly from [`L1StateProviderConfig::l1_rpc_url`] and reused
    /// for the lifetime of this instance. The transport (HTTP or WebSocket) is auto-detected
    /// from the URL scheme. `runtime_handle` is stored for later use by the synchronous
    /// [`get_storage`](Self::get_storage) method.
    pub async fn new(
        config: L1StateProviderConfig,
        cache: L1StateCache,
        runtime_handle: tokio::runtime::Handle,
    ) -> Result<Self> {
        let retry_layer =
            RetryBackoffLayer::new(config.max_retries, config.initial_backoff_ms, u64::MAX);

        let conn_config = rpc_connection_config(config.retry_connection_interval);

        let client = RpcClient::builder()
            .layer(retry_layer)
            .connect_with_config(&config.l1_rpc_url, conn_config)
            .await
            .map_err(|e| {
                eyre::eyre!(
                    "Failed to connect L1 state provider at {}: {e}",
                    config.l1_rpc_url
                )
            })?;

        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_client(client)
            .erased();

        Ok(Self {
            chain_id: config.chain_id,
            cache,
            provider,
            runtime_handle,
            max_sync_attempts: config.max_sync_attempts,
            metrics: L1StateMetricsByOrigin::new(),
        })
    }

    /// Create a provider from pre-constructed components.
    ///
    /// Used by `ZoneEvmConfig::new_without_l1` to build a fallback provider
    /// that won't panic on an empty RPC URL.
    pub fn new_raw(
        config: L1StateProviderConfig,
        cache: L1StateCache,
        provider: DynProvider<TempoNetwork>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            chain_id: config.chain_id,
            cache,
            provider,
            runtime_handle,
            max_sync_attempts: config.max_sync_attempts,
            metrics: L1StateMetricsByOrigin::new(),
        }
    }

    /// Read a storage slot synchronously at a specific L1 block — cache first, RPC fallback.
    ///
    /// This method is designed for use inside EVM precompiles that run on a **blocking thread**.
    /// On cache miss it retries the RPC call until the value is fetched, up to
    /// [`L1StateProviderConfig::max_sync_attempts`] when set. The transport layer handles backoff
    /// internally via [`RetryBackoffLayer`], so retries here are immediate. This ensures a
    /// transient L1 RPC outage stalls block production rather than bricking the chain with a hard
    /// precompile error.
    ///
    /// During an RPC simulation or cache prewarming (any origin but [`ExecutionOrigin::Canonical`])
    /// it makes one attempt limited to [`NON_CANONICAL_FETCH_TIMEOUT`] and returns an error if that
    /// fails, since retrying would only hold an RPC permit or a prewarming thread.
    ///
    /// # Panics
    ///
    /// Panics if called from within an async context on the same tokio runtime (see struct-level
    /// docs).
    pub fn get_storage(&self, address: Address, slot: B256, block_number: u64) -> Result<B256> {
        {
            let mut cache = self.cache.lock();
            if let Some(value) = cache.get(address, slot, block_number) {
                return Ok(value);
            }
        }

        // Published by `ZoneEvm::transact_raw` on the EVM thread. Any other caller reads
        // `Canonical` and keeps the unbounded retry.
        let origin = tx_context::execution_origin();
        self.metrics.record_cache_miss(origin);
        warn!(%address, %slot, block_number, ?origin, "L1 storage cache miss, fetching from RPC");

        let canonical = origin == ExecutionOrigin::Canonical;
        let max_sync_attempts = if !canonical {
            Some(NON_CANONICAL_SYNC_ATTEMPTS)
        } else {
            self.max_sync_attempts
        };
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let start = std::time::Instant::now();
            let result = tokio::task::block_in_place(|| {
                self.runtime_handle.block_on(async {
                    let fetch = self.fetch_slot(address, slot, block_number);
                    if canonical {
                        return fetch.await;
                    }
                    tokio::time::timeout(NON_CANONICAL_FETCH_TIMEOUT, fetch)
                        .await
                        .unwrap_or_else(|_| {
                            Err(eyre::eyre!(
                                "eth_getStorageAt timed out after {NON_CANONICAL_FETCH_TIMEOUT:?}"
                            ))
                        })
                })
            });
            let elapsed = start.elapsed();

            match result {
                Ok(value) => {
                    self.cache.lock().set(address, slot, block_number, value);
                    if attempt > 1 {
                        info!(%address, %slot, block_number, %value, ?elapsed, attempt, "L1 storage RPC fetch succeeded after retries");
                    } else {
                        info!(%address, %slot, block_number, %value, ?elapsed, "L1 storage RPC fetch succeeded");
                    }
                    return Ok(value);
                }
                Err(rpc_err) => {
                    if max_sync_attempts.is_some_and(|max_attempts| attempt >= max_attempts.get()) {
                        return Err(eyre::eyre!(
                            "L1 storage RPC fetch failed after {attempt} attempts for address={address} slot={slot} block={block_number}: {rpc_err}"
                        ));
                    }
                    warn!(%address, %slot, block_number, %rpc_err, ?elapsed, attempt, "L1 storage RPC fetch failed, retrying");
                }
            }
        }
    }

    /// Read a storage slot asynchronously at a specific L1 block — cache first, RPC fallback.
    ///
    /// Same semantics as [`get_storage`](Self::get_storage) but natively async. The
    /// transport-level [`RetryBackoffLayer`] handles retries with exponential backoff.
    pub async fn get_storage_async(
        &self,
        address: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256> {
        {
            let mut cache = self.cache.lock();
            if let Some(value) = cache.get(address, slot, block_number) {
                return Ok(value);
            }
        }

        // Async reads come from outside the EVM.
        self.metrics.record_cache_miss(ExecutionOrigin::Canonical);
        warn!(%address, %slot, block_number, "L1 storage cache miss, fetching from RPC");

        let value = self.fetch_slot(address, slot, block_number).await?;
        self.cache.lock().set(address, slot, block_number, value);
        Ok(value)
    }

    /// Expose the shared cache handle for external use (e.g. the engine).
    pub fn cache(&self) -> &L1StateCache {
        &self.cache
    }

    /// Fetch a single storage slot from L1 at a specific block via the shared HTTP provider.
    async fn fetch_slot(&self, address: Address, slot: B256, block_number: u64) -> Result<B256> {
        let value: U256 = self.provider.get_storage_at(address, slot.into()).number(block_number).await.map_err(|e| {
            warn!(%address, %slot, block_number, %e, "eth_getStorageAt RPC call failed");
            eyre::eyre!("eth_getStorageAt failed for address={address} slot={slot} block={block_number}: {e}")
        })?;

        let result = B256::from(value);
        debug!(%address, %slot, block_number, %result, "fetched L1 storage slot from RPC");
        Ok(result)
    }
}

impl L1StorageReader for L1StateProvider {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> std::result::Result<B256, L1StateError> {
        self.get_storage(account, slot, block_number)
            .map_err(|error| L1StateError::StorageUnavailable {
                account,
                slot,
                block_number,
                reason: error.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn finite_sync_attempt_limit_returns_diagnostic_error() {
        let config = L1StateProviderConfig {
            max_sync_attempts: Some(NonZeroU32::MIN),
            ..Default::default()
        };
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect("http://127.0.0.1:1")
            .await
            .expect("HTTP transport construction is lazy")
            .erased();
        let reader = L1StateProvider::new_raw(
            config,
            L1StateCache::default(),
            provider,
            tokio::runtime::Handle::current(),
        );

        let err =
            tokio::task::spawn_blocking(move || reader.get_storage(Address::ZERO, B256::ZERO, 7))
                .await
                .expect("storage task must not panic")
                .expect_err("dead endpoint must fail after one attempt");
        let message = err.to_string();
        assert!(message.contains("after 1 attempts"), "{message}");
        assert!(message.contains("block=7"), "{message}");
    }

    /// Reads `slot 0` at block 7 with `origin` from a provider that otherwise retries
    /// indefinitely.
    async fn non_canonical_read(l1_rpc_url: &str, origin: ExecutionOrigin) -> Result<B256> {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(l1_rpc_url)
            .await
            .expect("HTTP transport construction is lazy")
            .erased();
        let reader = L1StateProvider::new_raw(
            L1StateProviderConfig::default(),
            L1StateCache::default(),
            provider,
            tokio::runtime::Handle::current(),
        );

        tokio::task::spawn_blocking(move || {
            let _guard = tx_context::set_current_transaction(B256::ZERO, Address::ZERO, origin);
            reader.get_storage(Address::ZERO, B256::ZERO, 7)
        })
        .await
        .expect("storage task must not panic")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_canonical_read_fails_after_one_attempt() {
        for origin in [ExecutionOrigin::Simulation, ExecutionOrigin::Prewarming] {
            let message = non_canonical_read("http://127.0.0.1:1", origin)
                .await
                .expect_err("dead endpoint must fail a non-canonical read")
                .to_string();
            assert!(
                message.contains("after 1 attempts"),
                "{origin:?}: {message}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_canonical_fetch_times_out_on_silent_endpoint() {
        // Accepts connections but never responds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let _accept = tokio::spawn(async move {
            let mut connections = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                connections.push(stream);
            }
        });

        for origin in [ExecutionOrigin::Simulation, ExecutionOrigin::Prewarming] {
            let message = tokio::time::timeout(
                NON_CANONICAL_FETCH_TIMEOUT * 2,
                non_canonical_read(&url, origin),
            )
            .await
            .expect("non-canonical read must not wait past its fetch timeout")
            .expect_err("silent endpoint must fail a non-canonical read")
            .to_string();
            assert!(message.contains("timed out"), "{origin:?}: {message}");
        }
    }
}
