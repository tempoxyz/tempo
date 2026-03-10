use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::{DefaultPayloadBuilderValues, DefaultTxPoolValues};
use std::{borrow::Cow, time::Duration};
use tempo_chainspec::hardfork::TempoHardfork;

// Download defaults
pub const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/4217";

// Payload builder defaults
pub const DEFAULT_PAYLOAD_INTERVAL_MS: u64 = 100;
pub const DEFAULT_MAX_PAYLOAD_TASKS: usize = 16;
pub const DEFAULT_PAYLOAD_DEADLINE: u64 = 4;

// Txpool defaults
pub const DEFAULT_PENDING_MAX_COUNT: usize = 50000;
pub const DEFAULT_BASEFEE_MAX_COUNT: usize = 50000;
pub const DEFAULT_QUEUED_MAX_COUNT: usize = 50000;
pub const DEFAULT_PENDING_MAX_SIZE: usize = 100;
pub const DEFAULT_BASEFEE_MAX_SIZE: usize = 100;
pub const DEFAULT_QUEUED_MAX_SIZE: usize = 100;
pub const DEFAULT_MAX_QUEUED_LIFETIME_SECS: u64 = 120;
pub const DEFAULT_MAX_NEW_PENDING_TXS_NOTIFICATIONS: usize = 150000;
pub const DEFAULT_MAX_ACCOUNT_SLOTS: usize = 150000;
pub const DEFAULT_PENDING_TX_LISTENER_BUFFER_SIZE: usize = 50000;
pub const DEFAULT_NEW_TX_LISTENER_BUFFER_SIZE: usize = 50000;
pub const DEFAULT_ADDITIONAL_VALIDATION_TASKS: usize = 8;
pub const DEFAULT_MINIMUM_PRIORITY_FEE: u128 = 0;
pub const DEFAULT_MAX_BATCH_SIZE: usize = 50000;

fn init_download_urls() {
    let download_defaults = DownloadDefaults {
        available_snapshots: vec![
            Cow::Owned(format!("{DEFAULT_DOWNLOAD_URL} (mainnet)")),
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
        .with_interval(Duration::from_millis(DEFAULT_PAYLOAD_INTERVAL_MS))
        .with_max_payload_tasks(DEFAULT_MAX_PAYLOAD_TASKS)
        .with_deadline(DEFAULT_PAYLOAD_DEADLINE)
        .try_init()
        .expect("failed to initialize payload builder defaults");
}

fn init_txpool_defaults() {
    DefaultTxPoolValues::default()
        .with_pending_max_count(DEFAULT_PENDING_MAX_COUNT)
        .with_basefee_max_count(DEFAULT_BASEFEE_MAX_COUNT)
        .with_queued_max_count(DEFAULT_QUEUED_MAX_COUNT)
        .with_pending_max_size(DEFAULT_PENDING_MAX_SIZE)
        .with_basefee_max_size(DEFAULT_BASEFEE_MAX_SIZE)
        .with_queued_max_size(DEFAULT_QUEUED_MAX_SIZE)
        .with_no_locals(true)
        .with_max_queued_lifetime(Duration::from_secs(DEFAULT_MAX_QUEUED_LIFETIME_SECS))
        .with_max_new_pending_txs_notifications(DEFAULT_MAX_NEW_PENDING_TXS_NOTIFICATIONS)
        .with_max_account_slots(DEFAULT_MAX_ACCOUNT_SLOTS)
        .with_pending_tx_listener_buffer_size(DEFAULT_PENDING_TX_LISTENER_BUFFER_SIZE)
        .with_new_tx_listener_buffer_size(DEFAULT_NEW_TX_LISTENER_BUFFER_SIZE)
        .with_disable_transactions_backup(true)
        .with_additional_validation_tasks(DEFAULT_ADDITIONAL_VALIDATION_TASKS)
        .with_minimal_protocol_basefee(TempoHardfork::default().base_fee())
        .with_minimum_priority_fee(Some(DEFAULT_MINIMUM_PRIORITY_FEE))
        .with_max_batch_size(DEFAULT_MAX_BATCH_SIZE)
        .try_init()
        .expect("failed to initialize txpool defaults");
}

pub fn init_defaults() {
    init_download_urls();
    init_payload_builder_defaults();
    init_txpool_defaults();
}
