//! Standard OTLP file export with the SDK's batch processor, without a collector.

use reth_tracing_otlp::{span_layer_with_provider, OtlpConfig, OtlpProtocol, SdkTracerProvider};
use std::path::Path;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, util::SubscriberInitExt, Layer,
};

/// Drains completed spans after workload threads have stopped.
pub(crate) struct Guard(SdkTracerProvider);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Err(error) = self.0.shutdown() {
            eprintln!("OTLP shutdown failed: {error}");
        }
    }
}

/// Install before runtime threads. Each process gets a separate crash-tolerant stream.
pub(crate) fn install(datadir: &Path) -> eyre::Result<Guard> {
    let directory = datadir.join("traces");
    std::fs::create_dir_all(&directory)?;
    let path = std::fs::canonicalize(directory)?.join(format!("{}.pb", std::process::id()));
    let endpoint =
        url::Url::from_file_path(path).map_err(|()| eyre::eyre!("invalid OTLP file path"))?;
    let config = OtlpConfig::new("reth-trie-dst", endpoint, OtlpProtocol::Http, None)?;
    let (layer, provider) = span_layer_with_provider(config)?;
    let guard = Guard(provider);
    tracing_subscriber::registry()
        .with(layer.with_level(true).with_filter(LevelFilter::DEBUG))
        .try_init()?;
    Ok(guard)
}
