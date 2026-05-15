//! The legacy immutable finalized blocks archive.
//!
//! Older deployments stored finalized blocks in an immutable archive. This
//! module owns the on-disk shape of that archive — the partition naming
//! scheme, the open/init function, and the [`Legacy`] type alias — but is
//! deliberately unaware of how it is consumed: every consumer (today only
//! [`super::hybrid`]'s rollback-safety dual-write path) lives elsewhere and
//! depends on this module, not the other way around.

use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef};
use commonware_storage::archive::immutable;

use super::{
    BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES, FREEZER_TABLE_RESIZE_CHUNK_SIZE,
    FREEZER_TABLE_RESIZE_FREQUENCY, FREEZER_VALUE_COMPRESSION, FREEZER_VALUE_TARGET_SIZE,
    IMMUTABLE_ITEMS_PER_SECTION, REPLAY_BUFFER, WRITE_BUFFER,
};
use crate::consensus::{Digest, block::Block};

/// Partition-name prefix used by every blob/journal/freezer file backing
/// the legacy archive.
const LEGACY_FINALIZED_BLOCKS: &str = "finalized_blocks";

/// Initialize the legacy immutable finalized blocks archive.
pub(in crate::storage) async fn init_legacy_finalized_blocks_archive<TContext>(
    context: &TContext,
    partition_prefix: &str,
    page_cache: CacheRef,
) -> Result<immutable::Archive<TContext, Digest, Block>, commonware_storage::archive::Error>
where
    TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Clone + Send + 'static,
{
    immutable::Archive::init(
        context.with_label("finalized_blocks_legacy"),
        immutable::Config {
            metadata_partition: format!("{partition_prefix}-{LEGACY_FINALIZED_BLOCKS}-metadata"),
            freezer_table_partition: format!(
                "{partition_prefix}-{LEGACY_FINALIZED_BLOCKS}-freezer-table"
            ),
            freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
            freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
            freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
            freezer_key_partition: format!(
                "{partition_prefix}-{LEGACY_FINALIZED_BLOCKS}-freezer-key"
            ),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!(
                "{partition_prefix}-{LEGACY_FINALIZED_BLOCKS}-freezer-value"
            ),
            freezer_value_target_size: FREEZER_VALUE_TARGET_SIZE,
            freezer_value_compression: FREEZER_VALUE_COMPRESSION,
            ordinal_partition: format!("{partition_prefix}-{LEGACY_FINALIZED_BLOCKS}-ordinal"),
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
