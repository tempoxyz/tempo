use std::borrow::Cow;

use reth_cli_commands::download::DownloadDefaults;

pub(crate) const DEFAULT_DOWNLOAD_URL: &str = "https://snapshots.tempoxyz.dev/42426";

pub(crate) fn init_download_urls() {
    let download_defaults = DownloadDefaults {
        available_snapshots: vec![
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42426 (andante-1)"),
            Cow::Borrowed("https://snapshots.tempoxyz.dev/42427 (andantino-1)"),
        ],
        default_base_url: Cow::Borrowed(DEFAULT_DOWNLOAD_URL),
        long_help: None,
    };

    download_defaults
        .try_init()
        .expect("failed to initialize download URLs");
}
