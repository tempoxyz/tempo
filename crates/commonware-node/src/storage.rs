//! Shared storage configuration for consensus and follow engines.
//!
//! This module defines the archive formats used by both engines to ensure
//! data compatibility. A node that starts as a follower can be promoted to
//! a validator (or vice versa) without data migration.

use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};

use commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig, certificate::Scheme as _, ed25519::PublicKey,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::immutable;
use eyre::WrapErr as _;

use crate::config::BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES;
use crate::consensus::{Digest, block::Block};

/// Archive partition names - shared between consensus and follow engines.
const FINALIZATIONS_BY_HEIGHT: &str = "finalizations-by-height";
const FINALIZED_BLOCKS: &str = "finalized-blocks";

// Storage constants - must match between engines for compatibility.
const IMMUTABLE_ITEMS_PER_SECTION: NonZeroU64 =
    NonZeroU64::new(262_144).expect("value is not zero");
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 64KB chunks
const FREEZER_VALUE_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_VALUE_COMPRESSION: Option<u8> = Some(3);

// Marshal configuration shared between consensus and follow engines.
pub(crate) const REPLAY_BUFFER: NonZeroUsize =
    NonZeroUsize::new(8 * 1024 * 1024).expect("value is not zero"); // 8MB
pub(crate) const WRITE_BUFFER: NonZeroUsize =
    NonZeroUsize::new(1024 * 1024).expect("value is not zero"); // 1MB
pub(crate) const PRUNABLE_ITEMS_PER_SECTION: NonZeroU64 =
    NonZeroU64::new(4_096).expect("value is not zero");
pub(crate) const MAX_REPAIR: NonZeroUsize = NonZeroUsize::new(20).expect("value is not zero");

const BUFFER_POOL_PAGE_SIZE: NonZeroU16 = NonZeroU16::new(4_096).expect("value is not zero"); // 4KB
const BUFFER_POOL_CAPACITY: NonZeroUsize = NonZeroUsize::new(8_192).expect("value is not zero"); // 32MB

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
) -> eyre::Result<FinalizationsArchive<TContext>>
where
    TContext: Clock + Metrics + Spawner + Storage + Clone + Send + 'static,
{
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!(
                "{}-{}-metadata",
                partition_prefix, FINALIZATIONS_BY_HEIGHT
            ),
            freezer_table_partition: format!(
                "{}-{}-freezer-table",
                partition_prefix, FINALIZATIONS_BY_HEIGHT
            ),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!(
                "{}-{}-freezer-key",
                partition_prefix, FINALIZATIONS_BY_HEIGHT
            ),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!(
                "{}-{}-freezer-value",
                partition_prefix, FINALIZATIONS_BY_HEIGHT
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{}-{}-ordinal", partition_prefix, FINALIZATIONS_BY_HEIGHT),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: Scheme::<PublicKey, MinSig>::certificate_codec_config_unbounded(),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .wrap_err("failed to initialize finalizations archive")
}

/// Initialize the finalized blocks archive with the standard format.
pub(crate) async fn init_finalized_blocks_archive<TContext>(
    context: TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> eyre::Result<FinalizedBlocksArchive<TContext>>
where
    TContext: Clock + Metrics + Spawner + Storage + Clone + Send + 'static,
{
    immutable::Archive::init(
        context,
        immutable::Config {
            metadata_partition: format!("{}-{}-metadata", partition_prefix, FINALIZED_BLOCKS),
            freezer_table_partition: format!(
                "{}-{}-freezer-table",
                partition_prefix, FINALIZED_BLOCKS
            ),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!("{}-{}-freezer-key", partition_prefix, FINALIZED_BLOCKS),
            freezer_key_page_cache: page_cache.clone(),
            freezer_value_partition: format!(
                "{}-{}-freezer-value",
                partition_prefix, FINALIZED_BLOCKS
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{}-{}-ordinal", partition_prefix, FINALIZED_BLOCKS),
            items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
            codec_config: (),
            replay_buffer: REPLAY_BUFFER,
            freezer_key_write_buffer: WRITE_BUFFER,
            freezer_value_write_buffer: WRITE_BUFFER,
            ordinal_write_buffer: WRITE_BUFFER,
        },
    )
    .await
    .wrap_err("failed to initialize finalized blocks archive")
}
