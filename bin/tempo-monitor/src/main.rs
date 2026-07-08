use monitor::{
    reth::{EXEX_ID, MonitorExExConfig, run_monitor_exex},
    store::{MdbxMonitorStore, MdbxMonitorStoreConfig},
};

fn main() -> eyre::Result<()> {
    tempo::tempo_main_with(
        tempo::TempoOverrides::new().install_exex(EXEX_ID, |ctx| async move {
            let store_path = ctx.config.datadir().data_dir().join("monitor.mdbx");
            tracing::info!(
                exex_id = EXEX_ID,
                path = %store_path.display(),
                "opening durable monitor MDBX store"
            );

            Ok(async move {
                run_monitor_exex(
                    ctx,
                    MdbxMonitorStore::open(&store_path, MdbxMonitorStoreConfig::default())?,
                    MonitorExExConfig::default(),
                )
                .await
                .map_err(|err| eyre::eyre!("tempo monitor ExEx failed: {err:?}"))
            })
        }),
    )
}
