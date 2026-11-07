use std::path::PathBuf;

use clap::Parser;
use flux::{
    communication::cleanup_shmem,
    spine::ScopedSpine,
    tile::{TileConfig, attach_tile},
};
use tempo_flux_node::{spine::NodeSpine, tempo, tiles::*};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "./tempo-flux-data")]
    datadir: PathBuf,
    #[arg(long, default_value_t = 500)]
    block_time_ms: u64,
    #[arg(long, default_value_t = 20_000)]
    max_txs: u32,
    /// Load generator rate; 0 disables it.
    #[arg(long, default_value_t = 10_000)]
    tps: u64,
    #[arg(long, default_value_t = 2_000)]
    accounts: usize,
    #[arg(long, default_value_t = 200_000)]
    presigned: usize,
    #[arg(long, default_value_t = 4)]
    verifiers: usize,
    /// Pin tiles to consecutive cores from this one; unpinned when absent.
    #[arg(long)]
    first_core: Option<usize>,
    #[arg(long)]
    duration_secs: Option<u64>,
    /// Worker threads that execute a block's transactions, sharded by sender.
    #[arg(long, default_value_t = 1)]
    exec_threads: usize,
    /// Pin execution workers to consecutive cores from this one.
    #[arg(long)]
    exec_first_core: Option<usize>,
    /// Re-run every block sequentially and assert the parallel result matches.
    #[arg(long)]
    verify_parallel: bool,
    /// Check the incremental state root against a full recompute every block.
    #[arg(long)]
    verify_root: bool,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.datadir).expect("create datadir");

    tracing::info!(
        count = args.presigned,
        accounts = args.accounts,
        "presigning 0x76 pathUSD transfers"
    );
    let (funded, txs) = tempo::presign(args.accounts, args.presigned, 24);
    let hardfork = tempo::hardfork();
    tracing::info!(?hardfork, "seeding genesis");
    let state = tempo::genesis(&funded, hardfork);
    let (genesis, genesis_payload) = genesis_diff(&state);

    let shmem = args.datadir.join("shmem");
    cleanup_shmem(&shmem);
    let mut spine = NodeSpine::new_with_base_dir(&shmem, None);

    let mut core = args.first_core;
    let mut next = || {
        let c = core;
        if let Some(c) = core.as_mut() {
            *c += 1;
        }
        match c {
            Some(c) => TileConfig::new(c, None),
            None => TileConfig::background(None, None),
        }
    };

    std::thread::scope(|scope| {
        let mut scoped = ScopedSpine::new(&mut spine, scope, None, None);
        attach_tile(
            StorageTile::new(args.datadir.join("blocks.log"), args.duration_secs),
            &mut scoped,
            next(),
        );
        attach_tile(
            ExecutorTile::new(
                state,
                hardfork,
                args.exec_threads,
                args.exec_first_core,
                args.verify_parallel,
            ),
            &mut scoped,
            next(),
        );
        let mut merkle = MerkleTile::new(&genesis, &genesis_payload);
        merkle.verify = args.verify_root;
        attach_tile(merkle, &mut scoped, next());
        attach_tile(BuilderTile::default(), &mut scoped, next());
        attach_tile(
            ConsensusTile::new(args.block_time_ms, args.max_txs),
            &mut scoped,
            next(),
        );
        for index in 0..args.verifiers {
            attach_tile(VerifierTile { index, rejected: 0 }, &mut scoped, next());
        }
        if args.tps > 0 {
            attach_tile(LoadgenTile::new(txs, args.tps), &mut scoped, next());
        }
    });
    cleanup_shmem(&shmem);
}
