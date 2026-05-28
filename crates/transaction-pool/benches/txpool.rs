//! Criterion benchmarks for txgen-style TIP20 expiring nonce transaction-pool load.
//!
//! Run with:
//! `cargo bench -p tempo-transaction-pool --features test-utils --bench txpool`

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use reth_transaction_pool::TransactionPool;
use std::hint::black_box;
use tempo_transaction_pool::bench_utils::{
    TxpoolBenchConfig, add_validated_transaction_for_bench, fresh_pool,
    populated_pool_with_expiry_state, txgen_tip20_expiring_nonce_workload,
};

fn txpool_tip20_expiring_nonce(c: &mut Criterion) {
    let config = config_from_env();
    let workload = txgen_tip20_expiring_nonce_workload(&config);

    let mut group = c.benchmark_group("txpool/tip20_expiring_nonce");
    group.throughput(Throughput::Elements(config.tx_count as u64));

    group.bench_function(BenchmarkId::new("add_transactions", config.tx_count), |b| {
        b.iter_batched(
            || (fresh_pool(&config), workload.transactions.clone()),
            |(pool, txs)| {
                for tx in txs {
                    black_box(
                        add_validated_transaction_for_bench(&pool, tx)
                            .expect("benchmark transaction should be admitted"),
                    );
                }
                black_box(pool.pool_size());
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function(
        BenchmarkId::new("maintain_expiry_tick", config.tx_count),
        |b| {
            b.iter_batched(
                || populated_pool_with_expiry_state(&workload, &config),
                |(pool, mut state)| {
                    let tip_timestamp = config.block_timestamp + config.valid_for_secs;
                    black_box(state.evict_expired(&pool, tip_timestamp));
                    black_box(pool.pool_size());
                },
                BatchSize::LargeInput,
            );
        },
    );

    group.finish();
}

fn config_from_env() -> TxpoolBenchConfig {
    let mut config = TxpoolBenchConfig::default();
    config.account_count = env_usize("TEMPO_TXPOOL_BENCH_ACCOUNTS", config.account_count);
    config.tx_count = env_usize("TEMPO_TXPOOL_BENCH_TXS", config.tx_count);
    config.valid_for_secs = env_u64("TEMPO_TXPOOL_BENCH_VALID_FOR_SECS", config.valid_for_secs);
    config
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

criterion_group!(benches, txpool_tip20_expiring_nonce);
criterion_main!(benches);
