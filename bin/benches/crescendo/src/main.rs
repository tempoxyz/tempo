use std::future::pending;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use clap::Parser;
use mimalloc::MiMalloc;

mod config;
mod network_stats;
mod tx_queue;
mod utils;
mod workers;

use crate::config::Config;
use crate::network_stats::NETWORK_STATS;
use crate::tx_queue::TX_QUEUE;
use crate::workers::{DesireType, WorkerType};

#[global_allocator]
// Increases RPS by ~5.5% at the time of
// writing. ~3.3% faster than jemalloc.
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Path to the configuration file (positional argument)
    config_file: Option<PathBuf>,
    /// Path to the configuration file (flag variant)
    #[arg(short, long, hide = true)]
    config: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = CliArgs::parse();

    let config_path = args.config_file.or(args.config).expect("[!] Config file path must be provided.");
    println!("[~] Loading config from {}...", config_path.display());
    config::init(if config_path.exists() {
        Config::from_file(&config_path).unwrap_or_else(|e| panic!("[!] Failed to load config file: {e:?}"))
    } else {
        panic!("[!] Config file not found: {}", config_path.display());
    });

    if let Err(err) = utils::increase_nofile_limit(config::get().network_worker.total_connections * 10) {
        println!("[!] Failed to increase file descriptor limit: {err}.");
    }

    let mut core_ids = core_affinity::get_core_ids().unwrap();
    println!("[*] Detected {} effective cores.", core_ids.len());

    // Initialize Rayon with explicit thread count.
    rayon::ThreadPoolBuilder::new().num_threads(core_ids.len()).build_global().unwrap();

    // Pin the tokio runtime to a core (if enabled).
    utils::maybe_pin_thread(core_ids.pop().unwrap());

    // Given our desired breakdown of workers, translate this into actual numbers of workers to spawn.
    let (workers, worker_counts) = workers::assign_workers(
        core_ids, // Doesn't include the main runtime core.
        vec![
            (WorkerType::TxGen, DesireType::Percentage(config::get().workers.tx_gen_worker_percentage)),
            (WorkerType::Network, DesireType::Percentage(config::get().workers.network_worker_percentage)),
        ],
        config::get().workers.thread_pinning, // Only log core ranges if thread pinning is actually enabled.
    );

    let connections_per_network_worker =
        config::get().network_worker.total_connections / worker_counts[&WorkerType::Network];
    println!("[*] Connections per network worker: {connections_per_network_worker}");

    // TODO: Having the assign_workers function do this would be cleaner.
    let mut tx_gen_worker_id = 0;
    let mut network_worker_id = 0;

    println!("[*] Starting workers...");

    // Spawn the workers, pinning them to the appropriate cores if enabled.
    for (core_id, worker_type) in workers {
        match worker_type {
            WorkerType::TxGen => {
                thread::spawn(move || {
                    utils::maybe_pin_thread(core_id);
                    workers::tx_gen_worker(tx_gen_worker_id);
                });
                tx_gen_worker_id += 1;
            }
            WorkerType::Network => {
                thread::spawn(move || {
                    utils::maybe_pin_thread(core_id);
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

                    rt.block_on(async {
                        for i in 0..connections_per_network_worker {
                            tokio::spawn(workers::network_worker(
                                (network_worker_id * connections_per_network_worker + i) as usize,
                            ));
                        }
                        pending::<()>().await; // Keep the runtime alive forever.
                    });
                });
                network_worker_id += 1;
            }
        }
    }

    println!("[*] Starting reporters...");

    // Start reporters.
    tokio::spawn(TX_QUEUE.start_reporter(Duration::from_secs(config::get().reporters.tx_queue_report_interval_secs)));
    tokio::spawn(
        NETWORK_STATS.start_reporter(Duration::from_secs(config::get().reporters.network_stats_report_interval_secs)),
    )
    .await // Keep the main thread alive forever.
    .unwrap();
}
