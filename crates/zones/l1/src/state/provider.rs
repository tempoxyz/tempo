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

use alloy_primitives::{Address, B256, U256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_client::RpcClient;
use alloy_transport::layers::RetryBackoffLayer;
use eyre::{Result, WrapErr as _};
use std::num::NonZeroU32;
use tempo_alloy::TempoNetwork;
use tempo_contracts::TempoHardfork;
use tempo_primitives::account::decode_config_commitment;
use tracing::{debug, info, warn};
use zone_precompiles::{L1StateError, L1StorageReader};

use super::cache::L1StateCache;
use crate::rpc::rpc_connection_config;

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
    /// Optional finite attempt limit for synchronous cache-miss fallback.
    max_sync_attempts: Option<NonZeroU32>,
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
        }
    }

    /// Read a storage slot synchronously at a specific L1 block — cache first, RPC fallback.
    ///
    /// This method is designed for use inside EVM precompiles that run on a **blocking thread**.
    /// On cache miss it retries the RPC call indefinitely until the value is fetched. The
    /// transport layer handles backoff internally via [`RetryBackoffLayer`], so retries here
    /// are immediate. This ensures a transient L1 RPC outage stalls block production rather
    /// than bricking the chain with a hard precompile error.
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

        warn!(%address, %slot, block_number, "L1 storage cache miss, fetching from RPC");

        let value = self.fetch_blocking(
            format_args!("storage address={address} slot={slot} block={block_number}"),
            || self.fetch_slot(address, slot, block_number),
        )?;
        self.cache.lock().set(address, slot, block_number, value);
        Ok(value)
    }

    /// Read an account's TIP-1108 configuration commitment synchronously at a specific L1 block,
    /// zero when it has none — cache first, RPC fallback.
    ///
    /// Same blocking and retry semantics as [`get_storage`](Self::get_storage).
    pub fn get_config_commitment(&self, account: Address, block_number: u64) -> Result<B256> {
        if let Some(commitment) = self.cache.lock().get_commitment(account, block_number) {
            return Ok(commitment);
        }

        warn!(%account, block_number, "L1 account commitment cache miss, fetching from RPC");

        let commitment = self.fetch_blocking(
            format_args!("account commitment account={account} block={block_number}"),
            || self.fetch_config_commitment(account, block_number),
        )?;
        self.cache
            .lock()
            .set_commitment(account, block_number, commitment);
        Ok(commitment)
    }

    /// Runs `fetch` on the runtime from a blocking thread, retrying until it succeeds or
    /// [`L1StateProviderConfig::max_sync_attempts`] is reached. `read` names the value in logs
    /// and errors.
    fn fetch_blocking<Fut>(
        &self,
        read: std::fmt::Arguments<'_>,
        fetch: impl Fn() -> Fut,
    ) -> Result<B256>
    where
        Fut: std::future::Future<Output = Result<B256>>,
    {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let start = std::time::Instant::now();
            let result = tokio::task::block_in_place(|| self.runtime_handle.block_on(fetch()));
            let elapsed = start.elapsed();

            match result {
                Ok(value) => {
                    if attempt > 1 {
                        info!(%read, %value, ?elapsed, attempt, "L1 RPC fetch succeeded after retries");
                    } else {
                        info!(%read, %value, ?elapsed, "L1 RPC fetch succeeded");
                    }
                    return Ok(value);
                }
                Err(rpc_err) => {
                    if self
                        .max_sync_attempts
                        .is_some_and(|max_attempts| attempt >= max_attempts.get())
                    {
                        return Err(eyre::eyre!(
                            "L1 RPC fetch failed after {attempt} attempts for {read}: {rpc_err}"
                        ));
                    }
                    warn!(%read, %rpc_err, ?elapsed, attempt, "L1 RPC fetch failed, retrying");
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

    /// Fetch an account's TIP-1108 commitment from L1 at a specific block via
    /// `eth_getAccountInfo`, rejecting an extension that is not a valid commitment.
    async fn fetch_config_commitment(&self, account: Address, block_number: u64) -> Result<B256> {
        let info = self
            .provider
            .get_account_info(account)
            .number(block_number)
            .await
            .wrap_err_with(|| {
                format!("eth_getAccountInfo failed for account={account} block={block_number}")
            })?;
        // A nonempty extension only exists once Tempo has activated T14.
        let commitment = decode_config_commitment(&info.extension, TempoHardfork::T14)
            .wrap_err_with(|| {
                format!("invalid account commitment for account={account} block={block_number}")
            })?;
        debug!(%account, block_number, %commitment, "fetched L1 account commitment from RPC");
        Ok(commitment)
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

    fn read_l1_config_commitment(
        &self,
        account: Address,
        block_number: u64,
    ) -> std::result::Result<B256, L1StateError> {
        self.get_config_commitment(account, block_number)
            .map_err(|error| L1StateError::AccountUnavailable {
                account,
                block_number,
                reason: format!("{error:#}"),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn cached_commitment_is_served_without_rpc() {
        let config = L1StateProviderConfig {
            max_sync_attempts: Some(NonZeroU32::MIN),
            ..Default::default()
        };
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect("http://127.0.0.1:1")
            .await
            .expect("HTTP transport construction is lazy")
            .erased();
        let cache = L1StateCache::default();
        let (account, commitment) = (Address::repeat_byte(1), B256::repeat_byte(2));
        cache.lock().set_commitment(account, 7, commitment);
        let reader =
            L1StateProvider::new_raw(config, cache, provider, tokio::runtime::Handle::current());

        let (cached, missing) = tokio::task::spawn_blocking(move || {
            (
                reader.read_l1_config_commitment(account, 7),
                reader.read_l1_config_commitment(account, 8),
            )
        })
        .await
        .expect("commitment task must not panic");
        assert_eq!(cached, Ok(commitment));
        // A miss at another height goes to the dead endpoint and fails closed.
        let missing = missing.expect_err("dead endpoint must fail after one attempt");
        assert!(matches!(
            missing,
            L1StateError::AccountUnavailable {
                block_number: 8,
                ..
            }
        ));
        assert!(missing.is_unavailable());
    }
}
