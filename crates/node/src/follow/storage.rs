//! Finalization storage for follow mode.
//!
//! This module provides storage for finalization certificates using commonware's
//! `immutable::Archive`. The storage uses the same partition layout as validator
//! nodes for snapshot compatibility.
//!
//! # Architecture
//!
//! The storage runs inside a dedicated commonware tokio runtime and communicates
//! with the follow mode provider via channels. This allows the main Reth runtime
//! to remain independent while still benefiting from commonware's storage system.

use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use commonware_codec::Encode;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{Clock, Metrics, Runner as _, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::{Archive as _, Identifier, immutable};
use const_hex as hex;
use eyre::WrapErr as _;
use reth_tracing::tracing::{debug, error, info, warn};
use tokio::sync::{mpsc, oneshot};

use super::provider::digest::Digest;
use crate::rpc::consensus::CertifiedBlock;

/// Partition prefix matching the validator node for snapshot compatibility.
const PARTITION_PREFIX: &str = "engine";
const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";

// =============================================================================
// FORMAT-AFFECTING CONSTANTS (MUST match validator for snapshot compatibility)
// =============================================================================

/// Determines blob segmentation in ordinal index. MUST match validator.
const IMMUTABLE_ITEMS_PER_SECTION: NonZeroU64 =
    NonZeroU64::new(262_144).expect("value is not zero");

/// Initial hash table size (power of 2). Affects hash indexing. MUST match validator.
const BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES: u32 = 2u32.pow(21);

/// Compression level for journal data. MUST match validator if data is compressed.
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);

// =============================================================================
// RUNTIME TUNING PARAMETERS (can differ from validator)
// =============================================================================

/// Controls when table resizes are triggered.
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;

/// Controls pace of incremental resize operations.
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16);

/// Threshold for creating new journal sections.
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB

/// Read buffer size during recovery.
const REPLAY_BUFFER: NonZeroUsize = NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero");

/// Write buffer size for pending data.
const WRITE_BUFFER: NonZeroUsize = NonZeroUsize::new(1024 * 1024).expect("value is not zero");

/// Page cache configuration.
const BUFFER_POOL_PAGE_SIZE: std::num::NonZeroU16 =
    std::num::NonZeroU16::new(4_096).expect("value is not zero");
const BUFFER_POOL_CAPACITY: NonZeroUsize = NonZeroUsize::new(8_192).expect("value is not zero");

/// Commands sent to the storage service.
enum StorageCmd {
    /// Store a finalization certificate.
    Put {
        height: u64,
        digest: Digest,
        finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    },
    /// Get a finalization by height.
    Get {
        height: u64,
        reply: oneshot::Sender<Option<CertifiedBlock>>,
    },
    /// Get the latest stored finalization.
    Latest {
        reply: oneshot::Sender<Option<(u64, CertifiedBlock)>>,
    },
}

/// Handle to the finalization storage service.
///
/// This handle can be cloned and used from any async context to interact
/// with the storage service running in the commonware runtime.
#[derive(Clone)]
pub(super) struct FinalizationStoreHandle {
    tx: mpsc::Sender<StorageCmd>,
}

impl FinalizationStoreHandle {
    /// Store a finalization certificate.
    ///
    /// This is a fire-and-forget operation. The certificate will be persisted
    /// asynchronously.
    pub(super) fn put(
        &self,
        height: u64,
        digest: Digest,
        finalization: Finalization<Scheme<PublicKey, MinSig>, Digest>,
    ) {
        if let Err(e) = self.tx.try_send(StorageCmd::Put {
            height,
            digest,
            finalization,
        }) {
            warn!(height, error = %e, "failed to send finalization to storage");
        }
    }

    /// Get a finalization by height.
    pub(super) async fn get(&self, height: u64) -> Option<CertifiedBlock> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(StorageCmd::Get {
                height,
                reply: reply_tx,
            })
            .await
            .ok()?;
        reply_rx.await.ok().flatten()
    }

    /// Get the latest stored finalization and its height.
    pub(super) async fn latest(&self) -> Option<(u64, CertifiedBlock)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(StorageCmd::Latest { reply: reply_tx })
            .await
            .ok()?;
        reply_rx.await.ok().flatten()
    }
}

/// Configuration for the finalization storage service.
#[derive(Clone)]
pub(super) struct FinalizationStoreConfig {
    /// Directory for storage data.
    pub storage_dir: PathBuf,
    /// Number of worker threads for the storage runtime.
    pub worker_threads: Option<usize>,
}

/// Start the finalization storage service.
///
/// This spawns a new thread running a commonware tokio runtime that manages
/// the finalization archive. Returns a handle for interacting with the storage.
///
/// # Arguments
/// * `config` - Storage configuration
/// * `shutdown_token` - Cancellation token for graceful shutdown
///
/// # Returns
/// A tuple of (handle, join_handle) where handle is used to interact with storage
/// and join_handle can be used to wait for the service to stop.
pub(super) async fn start_finalization_store_async(
    config: FinalizationStoreConfig,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> eyre::Result<(
    FinalizationStoreHandle,
    std::thread::JoinHandle<eyre::Result<()>>,
)> {
    let (tx, rx) = mpsc::channel::<StorageCmd>(1024);
    let (ready_tx, ready_rx) = oneshot::channel::<eyre::Result<()>>();

    let handle = std::thread::Builder::new()
        .name("follow-storage".to_string())
        .spawn(move || run_storage_service(config, rx, ready_tx, shutdown_token))
        .map_err(|e| eyre::eyre!("failed to spawn storage thread: {}", e))?;

    // Wait for the storage service to be ready (async)
    match ready_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(eyre::eyre!("storage service failed to start")),
    }

    Ok((FinalizationStoreHandle { tx }, handle))
}

/// Run the storage service inside a commonware runtime.
fn run_storage_service(
    config: FinalizationStoreConfig,
    mut rx: mpsc::Receiver<StorageCmd>,
    ready_tx: oneshot::Sender<eyre::Result<()>>,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> eyre::Result<()> {
    let mut runtime_config = commonware_runtime::tokio::Config::default()
        .with_storage_directory(config.storage_dir.clone())
        .with_catch_panics(true);
    if let Some(threads) = config.worker_threads {
        runtime_config = runtime_config.with_worker_threads(threads);
    }

    let runner = commonware_runtime::tokio::Runner::new(runtime_config);
    runner.start(async move |ctx| {
        let ctx = ctx.with_label("follow_storage");

        // Initialize the archive
        let archive = match init_archive(&ctx).await {
            Ok(archive) => {
                info!(
                    storage_dir = %config.storage_dir.display(),
                    "follow mode finalization storage initialized"
                );
                let _ = ready_tx.send(Ok(()));
                archive
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return Ok(());
            }
        };

        // Run the service loop
        run_service_loop(archive, &mut rx, shutdown_token).await;

        Ok(())
    })
}

type FinalizationArchive<C> =
    immutable::Archive<C, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>;

/// Initialize the finalization archive with validator-compatible settings.
async fn init_archive<C>(ctx: &C) -> eyre::Result<FinalizationArchive<C>>
where
    C: Spawner + Storage + Metrics + Clock + Clone,
{
    let page_cache_ref = CacheRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

    let archive = immutable::Archive::init(
        ctx.clone(),
        immutable::Config {
            metadata_partition: format!("{PARTITION_PREFIX}-{FINALIZATIONS_BY_HEIGHT}-metadata"),
            freezer_table_partition: format!(
                "{PARTITION_PREFIX}-{FINALIZATIONS_BY_HEIGHT}-freezer-table"
            ),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!(
                "{PARTITION_PREFIX}-{FINALIZATIONS_BY_HEIGHT}-freezer-key"
            ),
            freezer_key_page_cache: page_cache_ref,
            freezer_value_partition: format!(
                "{PARTITION_PREFIX}-{FINALIZATIONS_BY_HEIGHT}-freezer-value"
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{PARTITION_PREFIX}-{FINALIZATIONS_BY_HEIGHT}-ordinal"),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: Scheme::<PublicKey, MinSig>::certificate_codec_config_unbounded(),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .wrap_err("failed to initialize finalizations archive")?;

    Ok(archive)
}

/// Run the storage service command loop.
async fn run_service_loop<C>(
    mut archive: FinalizationArchive<C>,
    rx: &mut mpsc::Receiver<StorageCmd>,
    shutdown_token: tokio_util::sync::CancellationToken,
) where
    C: Spawner + Storage + Metrics + Clock + Clone,
{
    loop {
        tokio::select! {
            biased;

            _ = shutdown_token.cancelled() => {
                debug!("follow storage received shutdown signal");
                break;
            }

            cmd = rx.recv() => {
                match cmd {
                    Some(StorageCmd::Put { height, digest, finalization }) => {
                        if let Err(e) = archive.put(height, digest, finalization).await {
                            error!(height, error = %e, "failed to store finalization");
                        } else {
                            debug!(height, "stored finalization");
                        }
                    }
                    Some(StorageCmd::Get { height, reply }) => {
                        let result = match archive.get(Identifier::Index(height)).await {
                            Ok(Some(finalization)) => Some(finalization_to_certified_block(height, &finalization)),
                            Ok(None) => None,
                            Err(e) => {
                                error!(height, error = %e, "failed to get finalization");
                                None
                            }
                        };
                        let _ = reply.send(result);
                    }
                    Some(StorageCmd::Latest { reply }) => {
                        let result = match archive.last_index() {
                            Some(height) => {
                                match archive.get(Identifier::Index(height)).await {
                                    Ok(Some(finalization)) => {
                                        Some((height, finalization_to_certified_block(height, &finalization)))
                                    }
                                    Ok(None) => None,
                                    Err(e) => {
                                        error!(height, error = %e, "failed to get latest finalization");
                                        None
                                    }
                                }
                            }
                            None => None,
                        };
                        let _ = reply.send(result);
                    }
                    None => {
                        debug!("follow storage channel closed");
                        break;
                    }
                }
            }
        }
    }

    // Sync the archive before exiting
    if let Err(e) = archive.sync().await {
        error!(error = %e, "failed to sync finalization archive");
    }
}

/// Convert a stored finalization to a CertifiedBlock for RPC responses.
fn finalization_to_certified_block(
    height: u64,
    finalization: &Finalization<Scheme<PublicKey, MinSig>, Digest>,
) -> CertifiedBlock {
    CertifiedBlock {
        epoch: finalization.proposal.round.epoch().get(),
        view: finalization.proposal.round.view().get(),
        height: Some(height),
        digest: finalization.proposal.payload.0,
        certificate: hex::encode(finalization.encode()),
    }
}
