use crate::crescendo::{
    DesireType, NETWORK_STATS, TX_QUEUE, TX_TRACKER, WorkerType,
    config::{self, Config},
    tx_gen::TxGenerator,
    utils, workers,
};
use clap::Parser;
use eyre::WrapErr;
use std::{path::PathBuf, sync::Arc, thread, time::Duration};
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Run maximum TPS throughput benchmarking
#[derive(Parser, Debug)]
pub struct TPSArgs {
    /// Path to the configuration file
    #[arg(short, long)]
    pub config: PathBuf,
}

impl TPSArgs {
    pub async fn run(self) -> eyre::Result<()> {
        println!("[~] Loading config from {}...", self.config.display());
        config::init(Config::from_file(&self.config)?);

        if let Err(err) =
            utils::increase_nofile_limit(config::get().network_worker.total_connections * 10)
        {
            println!("[!] Failed to increase file descriptor limit: {err}.");
        }
        
        let mut core_ids =
            core_affinity::get_core_ids().ok_or_else(|| eyre::eyre!("Failed to get core IDs"))?;
        println!("[*] Detected {} effective cores.", core_ids.len());

        // Initialize Rayon with explicit thread count.
        rayon::ThreadPoolBuilder::new()
            .num_threads(core_ids.len())
            .build_global()?;

        // Pin the tokio runtime to a core (if enabled).
        utils::maybe_pin_thread(
            core_ids
                .pop()
                .ok_or_else(|| eyre::eyre!("No core available for main runtime"))?,
        );

        let tx_generator = TxGenerator::new()
            .await
            .wrap_err("failed to construct transaction generator")?;

        // Given our desired breakdown of workers, translate this into actual numbers of workers to spawn.
        let (workers, worker_counts) = workers::assign_workers(
            core_ids, // Doesn't include the main runtime core.
            vec![
                (
                    WorkerType::TxGen,
                    DesireType::Percentage(config::get().workers.tx_gen_worker_percentage),
                ),
                (
                    WorkerType::Network,
                    DesireType::Percentage(config::get().workers.network_worker_percentage),
                ),
            ],
            config::get().workers.thread_pinning, // Only log core ranges if thread pinning is actually enabled.
        );

        let connections_per_network_worker =
            config::get().network_worker.total_connections / worker_counts[&WorkerType::Network];
        println!("[*] Connections per network worker: {connections_per_network_worker}");

        // TODO: Having the assign_workers function do this would be cleaner.
        let cancellation_token = CancellationToken::new();
        let tx_gen_worker_count = worker_counts[&WorkerType::TxGen] as usize;
        let mut tx_gen_worker_id = 0;
        let mut network_worker_id = 0;

        println!("[*] Starting workers...");

        // Spawn the workers, pinning them to the appropriate cores if enabled.
        for (core_id, worker_type) in workers {
            match worker_type {
                WorkerType::TxGen => {
                    let tx_gen_clone: Arc<TxGenerator> = Arc::clone(&tx_generator);
                    let cloned_token = cancellation_token.clone();
                    thread::spawn(move || {
                        utils::maybe_pin_thread(core_id);
                        tx_gen_clone.tx_gen_worker(
                            tx_gen_worker_id,
                            tx_gen_worker_count,
                            cloned_token,
                        );
                    });
                    tx_gen_worker_id += 1;
                }
                WorkerType::Network => {
                    let cloned_token = cancellation_token.clone();
                    thread::spawn(move || {
                        utils::maybe_pin_thread(core_id);
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("Failed to build tokio runtime");

                        rt.block_on(async {
                            for i in 0..connections_per_network_worker {
                                tokio::spawn(workers::network_worker(
                                    (network_worker_id * connections_per_network_worker + i)
                                        as usize,
                                    cloned_token.clone(),
                                ));
                            }
                            cloned_token.cancelled().await;
                        });
                    });
                    network_worker_id += 1;
                }
            }
        }

        println!("[*] Starting reporters...");

        // Start reporters.
        tokio::spawn(TX_QUEUE.start_reporter(
            Duration::from_secs(config::get().reporters.tx_queue_report_interval_secs),
            cancellation_token.clone(),
        ));
        tokio::spawn(NETWORK_STATS.start_reporter(
            Duration::from_secs(config::get().reporters.network_stats_report_interval_secs),
            cancellation_token.clone(),
        ));

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(config::get().benchmark.run_duration)).await;
            println!("[*] Stopping reporters...");
            cancellation_token.cancel();
        })
        .await?;

        println!("[*] All workers stopped, entering cool down period");
        time::sleep(Duration::from_secs(
            config::get().benchmark.cool_down_duration,
        ))
        .await;

        let report = TX_TRACKER
            .tally_sent_txs(0)
            .await
            .expect("Failed to generate tx report");

        println!("Final report: {:?}", report);

        Ok(())
    }
}
