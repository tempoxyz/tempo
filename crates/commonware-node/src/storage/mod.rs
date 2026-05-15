//! This module defines consensus archive formats.
//!
//! Finalized blocks are stored in a [`hybrid::Hybrid`] store which
//! merges a prunable archive (holding the most recently finalized blocks) with
//! a lookup into reth (used for blocks below the prunable retention window).
//!
//! Older deployments stored finalized blocks in an immutable archive. To
//! preserve the ability to roll back to one of those releases, the
//! [`legacy`] module is opened on every restart and every newly
//! finalized block is dual-written to it from [`hybrid::Hybrid`]. The
//! legacy archive is read-only from this binary's perspective; it
//! exists purely so the previous binary can still serve traffic if an
//! operator rolls back. The whole legacy code path is slated for
//! removal in an upcoming release.

use std::time::Instant;

use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    archive::{immutable, prunable},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use eyre::{WrapErr as _, ensure};
use tracing::{info, instrument};

use crate::{
    config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    consensus::{Digest, block::Block},
};

pub(crate) mod hybrid;
pub(in crate::storage) mod legacy;

pub(crate) use hybrid::{FinalizedBlocksProvider, Hybrid};

const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";
const PRUNABLE_FINALIZED_BLOCKS: &str = "finalized-blocks-prunable";

pub(in crate::storage) const IMMUTABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(262_144);
pub(in crate::storage) const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
pub(in crate::storage) const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 64KB chunks
pub(in crate::storage) const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
pub(in crate::storage) const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);

pub(crate) const REPLAY_BUFFER: std::num::NonZeroUsize = NZUsize!(8 * 1024 * 1024); // 8MB
pub(crate) const WRITE_BUFFER: std::num::NonZeroUsize = NZUsize!(1024 * 1024); // 1MB
pub(crate) const PRUNABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(4_096);
pub(crate) const MAX_REPAIR: std::num::NonZeroUsize = NZUsize!(20);
pub(crate) const BUFFER_POOL_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096); // 4KB
pub(crate) const BUFFER_POOL_CAPACITY: std::num::NonZeroUsize = NZUsize!(8_192); // 32MB (8k page slots)

/// Default number of finalized blocks (relative to reth's finalized
/// watermark) to keep cached in the prunable archive.
///
/// Beyond this depth, [`Hybrid`] falls back to looking up blocks from
/// reth's storage via the [`TempoFullNode`] provider.
///
/// The prunable archive evicts in `PRUNABLE_ITEMS_PER_SECTION`-sized
/// batches (see [`hybrid`]'s "Section-rounding" docs). When reth is
/// caught up to the marshal's tip the cache holds between `RETENTION`
/// and `RETENTION + PRUNABLE_ITEMS_PER_SECTION − 1` items; if reth is
/// lagging the marshal, the cache can hold more (it never drops blocks
/// reth doesn't yet have). The assertion below keeps the section
/// overshoot small relative to `RETENTION` (current ratio: 4×).
pub(crate) const DEFAULT_FINALIZED_BLOCKS_RETENTION: u64 = 16_384;

const _: () = assert!(
    DEFAULT_FINALIZED_BLOCKS_RETENTION >= 2 * PRUNABLE_ITEMS_PER_SECTION.get(),
    "DEFAULT_FINALIZED_BLOCKS_RETENTION must be at least 2 * PRUNABLE_ITEMS_PER_SECTION; \
     otherwise the section-rounding overshoot dominates the working set",
);

pub(crate) async fn init_finalizations_archive<TContext>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<
    immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
    commonware_storage::archive::Error,
>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let start = Instant::now();
    let archive = immutable::Archive::init(
        context.with_label("finalizations_by_height"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-{FINALIZATIONS_BY_HEIGHT}-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-{FINALIZATIONS_BY_HEIGHT}-freezer-table"
            ),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!(
                "{partition_prefix}-{FINALIZATIONS_BY_HEIGHT}-freezer-key"
            ),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!(
                "{partition_prefix}-{FINALIZATIONS_BY_HEIGHT}-freezer-value"
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{partition_prefix}-{FINALIZATIONS_BY_HEIGHT}-ordinal"),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: Scheme::<PublicKey, MinSig>::certificate_codec_config_unbounded(),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await;

    info!(
        elapsed = %tempo_telemetry_util::display_duration(start.elapsed()),
        "restored finalizations by height archive"
    );

    archive
}

/// Initialize the [`Hybrid`] finalized blocks store backed by a prunable
/// archive (for `retention_blocks` recent items) and a reth provider lookup
/// (for everything older).
///
/// Always opens the legacy immutable finalized-blocks archive for
/// write-through, creating its partitions on disk if they don't yet
/// exist. The legacy archive is **not** destroyed — see [`legacy`] for
/// the rollback-safety rationale. The whole legacy code path is slated
/// for removal in an upcoming release.
#[instrument(skip_all, fields(partition_prefix, retention_blocks), err(Display))]
pub(crate) async fn init_finalized_blocks<TContext, P>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
    provider: P,
    retention_blocks: u64,
) -> eyre::Result<Hybrid<TContext, P>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: FinalizedBlocksProvider + 'static,
{
    ensure!(
        retention_blocks > 0,
        "finalized blocks retention must be greater than zero",
    );

    let prunable =
        init_prunable_finalized_blocks_archive(context, partition_prefix, page_cache.clone())
            .await
            .wrap_err("failed to initialize prunable finalized blocks archive")?;

    let legacy =
        legacy::init_legacy_finalized_blocks_archive(context, partition_prefix, page_cache)
            .await
            .wrap_err("failed to initialize legacy immutable finalized blocks archive")?;

    Ok(Hybrid::new(hybrid::Config {
        prunable,
        legacy,
        provider,
        retention_blocks,
    }))
}

/// Initialize the prunable archive that holds recently finalized blocks.
///
/// This archive only holds at most `retention_blocks` items at any time;
/// older blocks are removed by the prune step in
/// [`Hybrid`](hybrid::Hybrid).
async fn init_prunable_finalized_blocks_archive<TContext>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<prunable::Archive<TwoCap, TContext, Digest, Block>, commonware_storage::archive::Error>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let start = Instant::now();
    let archive = prunable::Archive::init(
        context.with_label("finalized_blocks_prunable"),
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-key"),
            key_page_cache: page_cache,
            value_partition: format!("{partition_prefix}-{PRUNABLE_FINALIZED_BLOCKS}-value"),
            compression: FREEZER_VALUE_COMPRESSION,
            codec_config: (),
            items_per_section: PRUNABLE_ITEMS_PER_SECTION,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        },
    )
    .await;

    info!(
        elapsed = %tempo_telemetry_util::display_duration(start.elapsed()),
        "restored prunable finalized blocks archive",
    );

    archive
}
