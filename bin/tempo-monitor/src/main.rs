use monitor::{
    reth::{EXEX_ID, MonitorExExConfig, run_monitor_exex},
    store::{
        JsonlOutboxSink, MdbxMonitorStore, MdbxMonitorStoreConfig, OutboxWorker, OutboxWorkerConfig,
    },
};

fn main() -> eyre::Result<()> {
    tempo::tempo_main_with(
        tempo::TempoOverrides::new().install_exex(EXEX_ID, |ctx| async move {
            let datadir = ctx.config.datadir();
            let data_dir = datadir.data_dir();
            let store_path = data_dir.join("monitor.mdbx");
            let outbox_path = data_dir.join("monitor-outbox.jsonl");
            let outbox_config = OutboxWorkerConfig::default();
            tracing::info!(
                exex_id = EXEX_ID,
                path = %store_path.display(),
                "opening durable monitor MDBX store"
            );
            tracing::info!(
                exex_id = EXEX_ID,
                outbox_enabled = outbox_config.enabled,
                jsonl_path = %outbox_path.display(),
                batch_size = outbox_config.batch_size,
                poll_interval_ms = outbox_config.poll_interval.as_millis(),
                "configuring monitor JSONL outbox worker"
            );

            Ok(async move {
                let store = MdbxMonitorStore::open(&store_path, MdbxMonitorStoreConfig::default())?;
                let outbox_worker = OutboxWorker::new(
                    store.clone(),
                    JsonlOutboxSink::open(&outbox_path)?,
                    outbox_config,
                );
                tokio::select! {
                    result = run_monitor_exex(ctx, store, MonitorExExConfig::default()) => {
                        result.map_err(|err| eyre::eyre!("tempo monitor ExEx failed: {err:?}"))
                    }
                    result = outbox_worker.run_forever() => {
                        result.map_err(|err| eyre::eyre!("tempo monitor outbox worker failed: {err:?}"))
                    }
                }
            })
        }),
    )
}
