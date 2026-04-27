//! This module defines consensus archive formats

use std::time::Instant;

use commonware_consensus::simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization};
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::immutable;
use commonware_utils::{NZU16, NZU64, NZUsize};
use tracing::info;

use crate::{
    config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    consensus::{Digest, block::Block},
};

const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";
const FINALIZED_BLOCKS: &str = "finalized_blocks";

const IMMUTABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 64KB chunks
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);

pub(crate) const REPLAY_BUFFER: std::num::NonZeroUsize = NZUsize!(8 * 1024 * 1024); // 8MB
pub(crate) const WRITE_BUFFER: std::num::NonZeroUsize = NZUsize!(1024 * 1024); // 1MB
pub(crate) const PRUNABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(4_096);
pub(crate) const MAX_REPAIR: std::num::NonZeroUsize = NZUsize!(20);
pub(crate) const BUFFER_POOL_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096); // 4KB
pub(crate) const BUFFER_POOL_CAPACITY: std::num::NonZeroUsize = NZUsize!(8_192); // 32MB

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

/// Initialize the finalized blocks archive with the standard format.
pub(crate) async fn init_finalized_blocks_archive<TContext>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<immutable::Archive<TContext, Digest, Block>, commonware_storage::archive::Error>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    let start = Instant::now();
    let archive = immutable::Archive::init(
        context.with_label("finalized_blocks"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-{FINALIZED_BLOCKS}-metadata"),
            freezer_table_partition: format!("{partition_prefix}-{FINALIZED_BLOCKS}-freezer-table"),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!("{partition_prefix}-{FINALIZED_BLOCKS}-freezer-key"),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!("{partition_prefix}-{FINALIZED_BLOCKS}-freezer-value"),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{partition_prefix}-{FINALIZED_BLOCKS}-ordinal"),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: (),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await;

    info!(elapsed = %tempo_telemetry_util::display_duration(start.elapsed()), "restored finalized blocks archive");

    archive
}
