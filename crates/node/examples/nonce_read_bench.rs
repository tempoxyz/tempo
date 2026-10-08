//! Focused local benchmark of native versus replay-wrapped read transactions.
//! Each worker repeatedly opens a transaction and reads an absent nonce slot.
//! The replay cache is already warm at a non-genesis Finish checkpoint.
use alloy_primitives::keccak256;
use reth_db_api::{Database, tables, transaction::DbTx};
use reth_primitives_traits::RecoveredBlock;
use reth_provider::{
    BlockWriter, StageCheckpointWriter, StaticFileProviderFactory,
    test_utils::create_test_provider_factory_with_node_types,
};
use reth_stages_types::{StageCheckpoint, StageId};
use std::{hint::black_box, sync::Barrier, time::Instant};
use tempo_chainspec::spec::DEV;
use tempo_node::{TempoNode, storage::TempoDatabase};
use tempo_precompiles::EXPIRING_NONCE_PRECOMPILE_ADDRESS;
use tempo_primitives::{Block, BlockBody, TempoHeader};

fn measure<D: Database>(db: &D, threads: usize, iterations: usize) -> f64 {
    let barrier = Barrier::new(threads + 1);
    let address = keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS);
    let slot = keccak256(b"absent nonce slot");
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..iterations {
                    let tx = db.tx().unwrap();
                    black_box(
                        tx.get_by_key_subkey::<tables::HashedStorages>(address, slot)
                            .unwrap(),
                    );
                }
            });
        }
        let start = Instant::now();
        barrier.wait();
        // Joining scoped threads is part of the measurement.
        start
    })
    .elapsed()
    .as_secs_f64()
        * 1e9
        / (threads * iterations) as f64
}

fn main() {
    let factory = create_test_provider_factory_with_node_types::<TempoNode>(DEV.clone());
    let rw = factory.provider_rw().unwrap();
    for number in 0..=1 {
        rw.insert_block(&RecoveredBlock::new_unhashed(
            Block {
                header: TempoHeader {
                    inner: alloy::consensus::Header {
                        number,
                        timestamp: 1000 + number,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                body: BlockBody::default(),
            },
            vec![],
        ))
        .unwrap();
    }
    rw.save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(1))
        .unwrap();
    rw.commit().unwrap();
    let native = factory.db_ref();
    let replay = TempoDatabase::new(
        native.clone(),
        DEV.clone(),
        factory.static_file_provider().directory().to_owned(),
    );
    replay
        .tx()
        .unwrap()
        .get::<tables::HashedStorages>(keccak256(EXPIRING_NONCE_PRECOMPILE_ADDRESS))
        .unwrap();
    let rounds = std::env::var("NONCE_READ_ROUNDS").map_or(7, |v| v.parse().unwrap());
    let iterations = std::env::var("NONCE_READ_ITERATIONS").map_or(100_000, |v| v.parse().unwrap());
    println!("round,threads,native_ns_per_tx,replay_ns_per_tx");
    for threads in [1, 2, 4, 8, 16] {
        for round in 0..rounds {
            let (native_ns, replay_ns) = if round % 2 == 0 {
                (
                    measure(native, threads, iterations),
                    measure(&replay, threads, iterations),
                )
            } else {
                let replay_ns = measure(&replay, threads, iterations);
                (measure(native, threads, iterations), replay_ns)
            };
            println!("{round},{threads},{native_ns},{replay_ns}");
        }
    }
}
