use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};
use tempo_transaction_pool::bench_support::{
    aa2d_pool_fixture, best_transactions_snapshot, expiring_nonce_pool_fixture,
};

const TOTAL_TXS: usize = 50_000;
const TXS_PER_SENDER: usize = 16;
const SEQUENCES: usize = TOTAL_TXS / TXS_PER_SENDER;

fn best_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("best_transactions");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(10);

    let aa2d_pool = aa2d_pool_fixture(SEQUENCES, TXS_PER_SENDER);
    bench_next_one(&mut group, "aa2d/next/50k_txs_16_per_sender", &aa2d_pool);

    let expiring_nonce_pool = expiring_nonce_pool_fixture(SEQUENCES, TXS_PER_SENDER);
    bench_next_one(
        &mut group,
        "expiring_nonce/next/50k_txs_16_per_sender",
        &expiring_nonce_pool,
    );

    group.finish();
}

fn bench_next_one(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    id: &str,
    pool: &tempo_transaction_pool::AA2dPool,
) {
    group.bench_function(id, |b| {
        b.iter_batched_ref(
            || best_transactions_snapshot(pool),
            |best_txs| {
                let yielded = black_box(best_txs.next().is_some());
                assert!(yielded);
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, best_transactions);
criterion_main!(benches);
