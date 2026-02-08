//! Shared storage configuration for consensus and follow engines.
//!
//! This module defines the archive formats used by both engines to ensure
//! data compatibility. A node that starts as a follower can be promoted to
//! a validator (or vice versa) without data migration.

use commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::immutable;
use commonware_utils::{NZU16, NZU64, NZUsize};

use crate::{
    config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    consensus::{Digest, block::Block},
};

/// Archive partition names - shared between consensus and follow engines.
const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";
const FINALIZED_BLOCKS: &str = "finalized-blocks";

// Storage constants
const IMMUTABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 64KB chunks
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);

// Marshal configuration
pub(crate) const REPLAY_BUFFER: std::num::NonZeroUsize = NZUsize!(8 * 1024 * 1024); // 8MB
pub(crate) const WRITE_BUFFER: std::num::NonZeroUsize = NZUsize!(1024 * 1024); // 1MB
pub(crate) const PRUNABLE_ITEMS_PER_SECTION: std::num::NonZeroU64 = NZU64!(4_096);
pub(crate) const MAX_REPAIR: std::num::NonZeroUsize = NZUsize!(20);

const BUFFER_POOL_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: std::num::NonZeroUsize = NZUsize!(8_192); // 32MB

/// Type alias for the finalizations archive.
pub(crate) type FinalizationsArchive<TContext> = immutable::Archive<
    TContext,
    Digest,
    commonware_consensus::simplex::types::Finalization<Scheme<PublicKey, MinSig>, Digest>,
>;

/// Type alias for the finalized blocks archive.
pub(crate) type FinalizedBlocksArchive<TContext> = immutable::Archive<TContext, Digest, Block>;

/// Create a shared page cache for archives.
pub(crate) fn create_page_cache() -> CacheRef {
    CacheRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY)
}

/// Initialize the finalizations archive with the standard format.
pub(crate) async fn init_finalizations_archive<TContext>(
    context: TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<FinalizationsArchive<TContext>, commonware_storage::archive::Error>
where
    TContext: Clock + Metrics + Spawner + Storage + Clone + Send + 'static,
{
    immutable::Archive::init(
        context,
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
    .await
}

/// Initialize the finalized blocks archive with the standard format.
pub(crate) async fn init_finalized_blocks_archive<TContext>(
    context: TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<FinalizedBlocksArchive<TContext>, commonware_storage::archive::Error>
where
    TContext: Clock + Metrics + Spawner + Storage + Clone + Send + 'static,
{
    immutable::Archive::init(
        context,
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
    .await
}
