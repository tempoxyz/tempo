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
    include!("../src/blockstm_benchmark_tests.rs");

    const DEFAULT_EXISTING_TIP20_BASELINE_TPS: f64 = 88_000.0;

    fn tps(duration: Duration) -> f64 {
        BENCH_TX_COUNT as f64 / duration.as_secs_f64()
    }

    fn existing_tip20_baseline_tps() -> f64 {
        std::env::var("TEMPO_EXISTING_TIP20_BASELINE_TPS")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(DEFAULT_EXISTING_TIP20_BASELINE_TPS)
    }

    fn assert_release_gate() {
        let (txs, pooled, participants) = workload();
        assert_eq!(txs.len(), BENCH_TX_COUNT);
        assert_eq!(pooled.len(), BENCH_TX_COUNT);
        assert_eq!(participants.len(), ACCOUNT_COUNT);

        let fixture = seed_fixture(&participants);
        let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
        let workers = blockstm_bench_workers();

        let expected = execute_serial(&config, &fixture, &txs, &pooled, &participants);
        let parallel = execute_parallel_blockstm(
            &config,
            &fixture,
            &txs,
            &pooled,
            &participants,
            workers,
            true,
        );
        assert_eq!(
            parallel.digest.as_ref(),
            Some(&expected),
            "Block-STM output must match serial"
        );
        assert_parallel_benchmark_stats(&parallel.stats);
        let semantic = execute_parallel_blockstm_semantic_only(
            &config,
            &fixture,
            &txs,
            &pooled,
            &participants,
            workers,
            true,
        );
        assert_eq!(
            semantic.digest.as_ref(),
            Some(&expected),
            "Block-STM semantic-parallel output must match serial state"
        );
        assert_parallel_benchmark_stats(&semantic.stats);

        let mut serial_times = Vec::with_capacity(BENCH_SAMPLES);
        let mut parallel_times = Vec::with_capacity(BENCH_SAMPLES);
        let mut semantic_times = Vec::with_capacity(BENCH_SAMPLES);
        let mut last_parallel_stats = parallel.stats.clone();
        let mut last_speculative_wall = parallel.speculative_wall;
        let mut last_commit_wall = parallel.commit_wall;
        let mut last_phase_times = parallel.phase_times;
        let mut last_semantic_stats = semantic.stats.clone();
        let mut last_semantic_speculative_wall = semantic.speculative_wall;
        let mut last_semantic_phase_times = semantic.phase_times;
        for _ in 0..BENCH_SAMPLES {
            let started = Instant::now();
            let run = execute_parallel_blockstm(
                &config,
                &fixture,
                &txs,
                &pooled,
                &participants,
                workers,
                false,
            );
            assert_eq!(run.gas_used, expected.gas_used);
            assert_parallel_benchmark_stats(&run.stats);
            parallel_times.push(started.elapsed());
            last_parallel_stats = run.stats;
            last_speculative_wall = run.speculative_wall;
            last_commit_wall = run.commit_wall;
            last_phase_times = run.phase_times;

            let started = Instant::now();
            let semantic_run = execute_parallel_blockstm_semantic_only(
                &config,
                &fixture,
                &txs,
                &pooled,
                &participants,
                workers,
                false,
            );
            assert_eq!(semantic_run.gas_used, expected.gas_used);
            assert_parallel_benchmark_stats(&semantic_run.stats);
            semantic_times.push(started.elapsed());
            last_semantic_stats = semantic_run.stats;
            last_semantic_speculative_wall = semantic_run.speculative_wall;
            last_semantic_phase_times = semantic_run.phase_times;

            let started = Instant::now();
            let serial_gas = execute_serial_no_digest(&config, &fixture, &pooled);
            assert_eq!(serial_gas, expected.gas_used);
            serial_times.push(started.elapsed());
        }

        let serial_median = median(serial_times);
        let parallel_median = median(parallel_times);
        let semantic_median = median(semantic_times);
        let serial_tps = tps(serial_median);
        let parallel_tps = tps(parallel_median);
        let semantic_tps = tps(semantic_median);
        let speedup = parallel_tps / serial_tps;
        let existing_tip20_baseline_tps = existing_tip20_baseline_tps();

        println!(
            "blockstm_tip20_builder_release_gate txs={} accounts={} workers={} serial_median={:?} parallel_median={:?} semantic_median={:?} serial_tps={:.2} parallel_tps={:.2} semantic_tps={:.2} speedup={:.2}x semantic_speedup={:.2}x existing_tip20_baseline_tps={:.2} accepted={} rejected={} speculative={} committed={} reused_worker_results={} conflicts={} reexecutions={} serial_commit_reexecutions={} fallback={} built_blocks={} max_in_flight={} worker_lanes={} semantic_actions={} speculative_wall={:?} commit_wall={:?} phases={{setup:{:?}, batch_setup:{:?}, worker_merge:{:?}, semantic_reduce:{:?}, strip_state:{:?}, hydrate_cache:{:?}, commit_tx:{:?}, bump_bal_index:{:?}, final_semantic_commit:{:?}}} semantic_path={{accepted:{}, speculative:{}, max_in_flight:{}, worker_lanes:{}, speculative_wall:{:?}, semantic_reduce:{:?}, final_semantic_commit:{:?}}} actions={{ExpiringNonceUse:{}, Tip20FeeEscrowDelta:{}, Tip20TransferDelta:{}, CollectedFeesDelta:{}, SemanticPrefixRead:{}}}",
            BENCH_TX_COUNT,
            ACCOUNT_COUNT,
            workers,
            serial_median,
            parallel_median,
            semantic_median,
            serial_tps,
            parallel_tps,
            semantic_tps,
            speedup,
            semantic_tps / serial_tps,
            existing_tip20_baseline_tps,
            last_parallel_stats.accepted,
            last_parallel_stats.rejected,
            last_parallel_stats.speculative_executions,
            last_parallel_stats.committed,
            last_parallel_stats.reused_worker_results,
            last_parallel_stats.conflicts,
            last_parallel_stats.reexecutions,
            last_parallel_stats.serial_commit_reexecutions,
            last_parallel_stats.fallback,
            last_parallel_stats.built_blocks,
            last_parallel_stats.max_in_flight_real_evm_executions,
            last_parallel_stats.worker_lanes_with_attempts,
            last_parallel_stats.semantic_actions,
            last_speculative_wall,
            last_commit_wall,
            last_phase_times.setup,
            last_phase_times.batch_setup,
            last_phase_times.worker_merge,
            last_phase_times.semantic_reduce,
            last_phase_times.strip_state,
            last_phase_times.hydrate_cache,
            last_phase_times.commit_tx,
            last_phase_times.bump_bal_index,
            last_phase_times.final_semantic_commit,
            last_semantic_stats.accepted,
            last_semantic_stats.speculative_executions,
            last_semantic_stats.max_in_flight_real_evm_executions,
            last_semantic_stats.worker_lanes_with_attempts,
            last_semantic_speculative_wall,
            last_semantic_phase_times.semantic_reduce,
            last_semantic_phase_times.final_semantic_commit,
            last_parallel_stats.action_counts.expiring_nonce_uses,
            last_parallel_stats.action_counts.tip20_fee_escrows,
            last_parallel_stats.action_counts.tip20_transfers,
            last_parallel_stats.action_counts.collected_fees,
            last_parallel_stats.action_counts.semantic_prefix_reads,
        );

        assert!(
            speedup > 2.0,
            "Block-STM release TPS {parallel_tps:.2} must be over 2x same-harness serial TPS {serial_tps:.2}"
        );
        assert!(
            parallel_tps > existing_tip20_baseline_tps * 2.0,
            "Block-STM release TPS {parallel_tps:.2} must be over 2x existing pure TIP20 baseline {existing_tip20_baseline_tps:.2}"
        );
        assert!(
            parallel_tps >= 500_000.0,
            "Full Block-STM builder TPS {parallel_tps:.2} must be at least 500k"
        );
        assert!(
            semantic_tps >= 500_000.0,
            "Block-STM semantic-parallel TPS {semantic_tps:.2} must be at least 500k"
        );
    }

    pub(super) fn criterion_entry(_c: &mut criterion::Criterion) {
        assert_release_gate();
    }
}

fn blockstm_tip20_builder(c: &mut Criterion) {
    support::criterion_entry(c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = blockstm_tip20_builder
}
criterion_main!(benches);
