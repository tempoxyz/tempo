use reth_cli_commands::download::DownloadDefaults;
use reth_ethereum::node::core::args::DefaultPayloadBuilderValues;
use std::{borrow::Cow, time::Duration};

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42429";

fn init_download_urls() {
    let download_defaults = DownloadDefaults {
        available_snapshots: vec![Cow::Borrowed(
            "https://snapshots.tempoxyz.dev/42429 (andantino-1)",
        )],
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

pub(crate) fn init_defaults() {
    init_download_urls();
    init_payload_builder_defaults();
}
