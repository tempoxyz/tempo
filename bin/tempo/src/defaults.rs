use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::{
    DefaultEngineValues, DefaultPayloadBuilderValues, DefaultTxPoolValues,
};
use std::{borrow::Cow, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42431";

fn init_download_urls() {
    let download_defaults = DownloadDefaults {
        available_snapshots: vec![
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42431 (moderato)"),
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42429 (andantino)"),
        ],
        default_base_url: Cow::Borrowed(DEFAULT_DOWNLOAD_URL),
        long_help: None,
    };

    download_defaults
        .try_init()
        .expect("failed to initialize download URLs");
}

fn init_payload_builder_defaults() {
    DefaultPayloadBuilderValues::default()
        .with_interval(Duration::from_millis(100))
        .with_max_payload_tasks(16)
        .with_deadline(4)
        .try_init()
        .expect("failed to initialize payload builder defaults");
}

fn init_txpool_defaults() {
    DefaultTxPoolValues::default()
        .with_pending_max_count(50000)
        .with_basefee_max_count(50000)
        .with_queued_max_count(50000)
        .with_pending_max_size(100)
        .with_basefee_max_size(100)
        .with_queued_max_size(100)
        .with_no_locals(true)
        .with_max_queued_lifetime(Duration::from_secs(120))
        .with_max_new_pending_txs_notifications(150000)
        .with_max_account_slots(150000)
        .with_pending_tx_listener_buffer_size(50000)
        .with_new_tx_listener_buffer_size(50000)
        .with_disable_transactions_backup(true)
        .with_additional_validation_tasks(8)
        .with_minimal_protocol_basefee(TempoHardfork::default().base_fee())
        .with_minimum_priority_fee(Some(0))
        .with_max_batch_size(50000)
        .try_init()
        .expect("failed to initialize txpool defaults");
}

/// How many canonical blocks ahead of the last persisted block before flushing to disk.
/// Higher = better write batching but more memory; lower = frequent writes.
const PERSIST_THRESHOLD: u64 = 16;

/// Reorgs shallower than this depth stay entirely in memory (no disk I/O).
const REORG_SAFE_DEPTH: u64 = 8;

fn init_engine_defaults() {
    DefaultEngineValues::default()
        .with_persistence_threshold(PERSIST_THRESHOLD)
        .with_memory_block_buffer_target(REORG_SAFE_DEPTH)
        .try_init()
        .expect("failed to initialize engine defaults");
}

pub(crate) fn init_defaults() {
    init_download_urls();
    init_payload_builder_defaults();
    init_txpool_defaults();
    init_engine_defaults();
}
