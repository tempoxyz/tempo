use criterion::{Criterion, criterion_group, criterion_main};
use reth_evm::{Database, block::TxResult};

pub mod blockstm {
    pub use tempo_payload_builder::blockstm::*;
}

pub fn hydrate_blockstm_commit_cache<DB>(
    db: &mut DB,
    result: &tempo_evm::TempoTxResult,
) -> Result<(), DB::Error>
where
    DB: Database,
{
    for address in result.result().state.keys() {
        let _ = db.basic(*address)?;
    }
    Ok(())
}

mod support {
    #![allow(dead_code)]

    include!("../src/blockstm_benchmark_tests.rs");

    pub(super) fn criterion_entry(c: &mut criterion::Criterion) {
        let (txs, pooled, participants) = workload();
        assert_eq!(txs.len(), BENCH_TX_COUNT);
        assert_eq!(pooled.len(), BENCH_TX_COUNT);
        assert_eq!(participants.len(), ACCOUNT_COUNT);

        let fixture = seed_fixture(&participants);
        let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
        let workers = blockstm_bench_workers();

        println!(
            "blockstm_tip20_builder_repeated txs={} accounts={} workers={}",
            BENCH_TX_COUNT, ACCOUNT_COUNT, workers
        );

        let mut group = c.benchmark_group("blockstm_tip20_builder_repeated");
        group.throughput(criterion::Throughput::Elements(BENCH_TX_COUNT as u64));
        group.bench_function("full_parallel_end_to_end", |b| {
            b.iter(|| {
                let run = execute_parallel_blockstm(
                    &config,
                    &fixture,
                    &txs,
                    &pooled,
                    &participants,
                    workers,
                    false,
                );
                black_box((run.gas_used, run.stats.accepted));
            });
        });
        group.finish();
    }
}

fn blockstm_tip20_builder_repeated(c: &mut Criterion) {
    support::criterion_entry(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(10));
    targets = blockstm_tip20_builder_repeated
}
criterion_main!(benches);
