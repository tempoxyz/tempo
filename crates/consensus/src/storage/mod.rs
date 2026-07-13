//! This module defines consensus archive formats.
//!
//! Finalized blocks are stored in a Hybrid store which merges a prunable
//! archive (holding the most recently finalized blocks) with a lookup into the
//! execution layer (used for blocks below the prunable retention window).

use std::time::Instant;

use alloy_consensus::Sealable as _;
use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::{
    archive::{Archive as _, Identifier, immutable, prunable},
    translator::TwoCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use eyre::{WrapErr as _, ensure};
use reth_provider::{BlockIdReader, BlockReader};
use tracing::{info, instrument};

use crate::{
    config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    consensus::{Digest, block::Block},
};

pub(crate) mod hybrid;
pub mod snapshot;

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
/// Beyond this depth, [`Hybrid`] falls back to looking up blocks from the
/// execution layer.
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

    // Contiguous run of blocks starting at the prunable archive's first index.
    let start_range = prunable.first_index().and_then(|first| {
        prunable
            .next_gap(first)
            .0
            .map(|end| format!("{first}..={end}"))
    });

    info!(
        consensus_cache.start_range = start_range,
        consensus_cache.last_block = prunable.last_index(),
        execution_layer.finalized_height = provider.finalized_height(),
        "initialized finalized blocks store",
    );

    Ok(Hybrid::new(hybrid::Config {
        prunable,
        execution_block_provider: provider,
        retention_blocks,
    }))
}

/// Initialize the prunable archive that holds recently finalized blocks.
///
/// This archive only holds at most `retention_blocks` items at any time;
/// older blocks are removed by the prune step in
/// [`Hybrid`].
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

/// Finds the latest finalization certificate backed by finalized execution storage.
///
/// Searches backwards from the execution provider's finalized tip. At
/// most `max_depth` blocks behind that starting height are inspected.
///
/// Returns `None` if no persisted finalization certificate has a matching
/// finalized execution block.
pub async fn find_last_finalized_marker<TContext, P>(
    context: &TContext,
    execution_provider: &P,
    max_depth: u64,
) -> eyre::Result<Option<(u64, Finalization<Scheme<PublicKey, MinSig>, Digest>)>>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
    P: BlockIdReader + BlockReader<Block = tempo_primitives::Block> + Send + Sync + ?Sized,
{
    let page_cache = CacheRef::from_pooler(context, BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);
    let archive = init_finalizations_archive(context, crate::PARTITION_PREFIX, page_cache)
        .await
        .wrap_err("failed to open finalizations-by-height archive")?;

    if archive.last_index().is_none() {
        return Ok(None);
    }
    let Some(finalized_tip) = execution_provider
        .finalized_block_number()
        .wrap_err("failed reading finalized block number from execution provider")?
    else {
        return Ok(None);
    };

    let search_end = finalized_tip.saturating_sub(max_depth);
    for height in (search_end..=finalized_tip).rev() {
        let Some(finalization) = archive
            .get(Identifier::Index(height))
            .await
            .wrap_err_with(|| format!("failed reading finalization at height {height}"))?
        else {
            continue;
        };

        let Some(block) = execution_provider
            .block_by_number(height)
            .wrap_err_with(|| format!("failed reading block at height {height}"))?
        else {
            continue;
        };

        let finalization_digest = finalization.proposal.payload;
        let block_digest = Digest(block.header.hash_slow());
        ensure!(
            finalization_digest == block_digest,
            "digest mismatch at height `{height}`. finalization: {finalization_digest}, execution: {block_digest}",
        );

        return Ok(Some((height, finalization)));
    }

    Ok(None)
}
