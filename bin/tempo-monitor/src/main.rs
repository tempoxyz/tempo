fn main() -> eyre::Result<()> {
    tempo::tempo_main_with(tempo::TempoOverrides::new().install_exex(
        monitor::reth::EXEX_ID,
        |ctx| async move {
            // TODO: Replace the in-memory backend with the durable monitor-owned store before
            // using this binary for production proof claims. This keeps the ExEx wiring buildable
            // while the durable backend is implemented behind the same store trait.
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
