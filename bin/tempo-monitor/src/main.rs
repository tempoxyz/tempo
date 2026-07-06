fn main() -> eyre::Result<()> {
    tempo::tempo_main_with(tempo::TempoOverrides::new().install_exex(
        monitor::reth::EXEX_ID,
        |ctx| async move {
            tracing::warn!(
                exex_id = monitor::reth::EXEX_ID,
                "tempo-monitor is using InMemoryMonitorStore; monitor state is not restart-durable"
            );
            // TODO: Replace the in-memory backend with durable monitor-owned storage before using
            // this binary for production proof claims.
            let store = monitor::store::InMemoryMonitorStore::new();
            let config = monitor::reth::MonitorExExConfig::default();
            Ok(async move {
                monitor::reth::run_monitor_exex(ctx, store, config)
                    .await
                    .map_err(|err| eyre::eyre!("tempo monitor ExEx failed: {err:?}"))
            })
        },
    ))
}
