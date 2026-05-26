use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};
use tempo_transaction_pool::bench_support::expired_txpool_maintenance_fixture;

const TOTAL_TXS: usize = 50_000;
const TXS_PER_SENDER: usize = 16;
const SEQUENCES: usize = TOTAL_TXS / TXS_PER_SENDER;

fn txpool_maintenance(c: &mut Criterion) {
    let mut group = c.benchmark_group("txpool_maintenance");
    group
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(10);

    group.bench_function("expired_valid_before/50k_txs_16_per_sender", |b| {
        b.iter_batched_ref(
            || expired_txpool_maintenance_fixture(SEQUENCES, TXS_PER_SENDER),
            |fixture| {
                let evicted = black_box(fixture.run_one());
                assert_eq!(evicted, TOTAL_TXS);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(benches, txpool_maintenance);
criterion_main!(benches);
