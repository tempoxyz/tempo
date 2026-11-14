//! Parallel TIP20 execution benchmark.
//!
//! Executes the same block of txgen-style expiring-nonce pathUSD transfers as `tip20_execution`
//! sequentially and with evm2's optimistic parallel executor at several thread counts, and checks
//! that every variant commits the sequential result. Set `TEMPO_TIP20_EXEC_TXS` to replay a txgen raw transaction file,
//! `TEMPO_PAR_THREADS` (comma-separated) and `TEMPO_PAR_ITERS` to change the sweep.

#[path = "tip20_execution.rs"]
#[allow(dead_code)]
mod tip20;

use alloy_consensus::transaction::Recovered;
use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::{
    block::{StateUpdate, ethereum::parallel::ParallelCommit},
    bytecode::Bytecode,
    evm::{AccountInfo, Cache, CacheDB, DbResult, DynDatabase, DynDatabaseRef, EmptyDB},
    interpreter::Word,
};
use reth_evm::{BlockExecutor, BlockExecutorFactory};
use reth_evm_ethereum::EthBlockExecutionCtx;
use std::{
    collections::BTreeMap,
    hint::black_box,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::{ParallelExecution, TempoBlockExecutionCtx, TempoEvm, TempoEvmConfig, TempoTxEnv};
use tempo_primitives::TempoTxEnvelope;
use tip20::common::bench_env;

/// The pre-block state as a shared database for the workers.
struct Snapshot(Cache);

impl DynDatabaseRef for Snapshot {
    fn get_account(&self, address: &Address) -> DbResult<Option<AccountInfo>> {
        Ok(self.0.accounts.get(address).cloned().flatten())
    }

    fn get_code_by_hash(&self, code_hash: &B256) -> DbResult<Bytecode> {
        Ok(self.0.contracts.get(code_hash).cloned().unwrap_or_default())
    }

    fn get_storage(&self, address: &Address, key: &Word) -> DbResult<Word> {
        Ok(self
            .0
            .storage
            .get(address)
            .and_then(|storage| storage.slots.get(key))
            .copied()
            .unwrap_or_default())
    }

    fn get_block_hash(&self, number: &Word) -> DbResult<B256> {
        DynDatabase::get_block_hash(&mut EmptyDB::default(), number)
    }
}

/// The executor's view of the pre-block state, read through the same snapshot as the workers.
struct SnapshotDb(Arc<Snapshot>);

impl DynDatabase for SnapshotDb {
    fn get_account(&mut self, address: &Address) -> DbResult<Option<AccountInfo>> {
        self.0.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> DbResult<Bytecode> {
        self.0.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> DbResult<Word> {
        self.0.get_storage(address, key)
    }

    fn get_block_hash(&mut self, number: &Word) -> DbResult<B256> {
        self.0.get_block_hash(number)
    }
}

struct Run {
    elapsed: Duration,
    reexecuted: usize,
    output: String,
}

fn ctx(txs: usize) -> TempoBlockExecutionCtx<'static> {
    TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: B256::ZERO,
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(txs),
            slot_number: None,
        },
        general_gas_limit: 10_000_000_000,
        shared_gas_limit: 0,
        consensus_context: None,
    }
}

#[expect(clippy::too_many_arguments)]
fn run(
    config: &TempoEvmConfig,
    snapshot: &Arc<Snapshot>,
    txs: &[Recovered<TempoTxEnvelope>],
    block_timestamp: u64,
    hardfork: TempoHardfork,
    threads: Option<NonZeroUsize>,
    commit: ParallelCommit,
    verify: bool,
) -> Run {
    let tx_envs: Vec<_> = txs
        .iter()
        .map(|tx| Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer()))
        .collect();
    let db = CacheDB::new(SnapshotDb(snapshot.clone()));
    let env = bench_env(hardfork, block_timestamp);
    let evm = BlockExecutorFactory::evm_with_env(config, db, env.clone());
    let mut executor = config.create_executor(evm, ctx(txs.len()));
    executor
        .apply_pre_execution_changes()
        .expect("pre-execution changes failed");
    let updates = Arc::new(Mutex::new(Vec::new()));
    if verify {
        let updates = updates.clone();
        executor.set_state_hook(move |mut update| {
            // Accounts and slots stream in hash-map order: sort them to compare runs.
            update.accounts.sort_by_key(|account| account.address);
            for account in &mut update.accounts {
                account.storage.sort_by_key(|(slot, _)| *slot);
            }
            updates.lock().unwrap().push(update);
        });
    }

    executor.set_parallel_execution(threads.map(|threads| ParallelExecution { threads, commit }));
    let make_evm = evm_factory(|db| BlockExecutorFactory::evm_with_env(config, db, env.clone()));
    let start = Instant::now();
    let reexecuted = executor
        .execute_block_transactions(tx_envs.into_iter().zip(txs), &**snapshot, make_evm)
        .expect("block execution failed")
        .reexecuted;
    let elapsed = start.elapsed();

    let receipts = black_box(executor.receipts());
    assert_eq!(receipts.len(), txs.len());
    assert!(
        receipts.iter().all(|receipt| receipt.success),
        "transaction reverted"
    );
    let output = if verify {
        format!("{receipts:?}\n{:?}", final_state(&updates.lock().unwrap()))
    } else {
        String::new()
    };
    Run {
        elapsed,
        reexecuted,
        output,
    }
}

/// The block's final state from its streamed updates: every account and slot it changed, at its
/// last value.
fn final_state(updates: &[StateUpdate]) -> BTreeMap<Address, (String, BTreeMap<U256, U256>)> {
    let mut state = BTreeMap::new();
    for update in updates {
        for account in &update.accounts {
            let entry = state
                .entry(account.address)
                .or_insert_with(|| (String::new(), BTreeMap::new()));
            entry.0 = format!("{:?}", account.current);
            if account.wiped {
                entry.1.clear();
            }
            for (key, slot) in &account.storage {
                entry.1.insert(*key, slot.present_value);
            }
        }
    }
    state
}

/// Pins the closure's signature to the higher-ranked one the parallel executor takes.
fn evm_factory<F>(f: F) -> F
where
    F: for<'x> Fn(Box<dyn DynDatabase + 'x>) -> TempoEvm<'x>,
{
    f
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn main() {
    let workload = tip20::workload();
    let hardfork = tip20::common::latest_known_hardfork();
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
    let iters = std::env::var("TEMPO_PAR_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let threads: Vec<usize> = std::env::var("TEMPO_PAR_THREADS")
        .unwrap_or_else(|_| "2,4,8,16".into())
        .split(',')
        .map(|t| t.trim().parse().expect("invalid thread count"))
        .collect();

    let seeded = tip20::seed_in_memory_cache_db(
        &workload.participants,
        workload.block_timestamp,
        false,
        hardfork,
    );
    let snapshot = Arc::new(Snapshot(seeded.cache));
    let txs = &workload.transactions;
    println!(
        "hardfork {hardfork:?}, {} transactions, {iters} iterations",
        txs.len()
    );
    println!(
        "{:<34} {:>10} {:>10} {:>9} {:>10}",
        "variant", "median ms", "tx/s", "vs seq", "re-exec"
    );

    let run = |t, commit, verify| {
        run(
            &config,
            &snapshot,
            txs,
            workload.block_timestamp,
            hardfork,
            t,
            commit,
            verify,
        )
    };
    let mut baseline = None;
    let reference = run(None, ParallelCommit::InOrder, true).output;
    let variants = std::iter::once((None, ParallelCommit::InOrder)).chain(
        [ParallelCommit::InOrder, ParallelCommit::Batched]
            .into_iter()
            .flat_map(|commit| threads.iter().map(move |&t| (NonZeroUsize::new(t), commit))),
    );
    for (t, commit) in variants {
        let mut samples = Vec::with_capacity(iters);
        let mut reexecuted = 0;
        for i in 0..iters + 2 {
            let result = run(t, commit, i == 0);
            if i == 0 && result.output != reference {
                std::fs::write("/tmp/tip20_parallel_diverged.txt", &result.output).unwrap();
                panic!("threads {t:?} diverged from sequential execution");
            }
            if i >= 2 {
                samples.push(result.elapsed);
                reexecuted = reexecuted.max(result.reexecuted);
            }
        }
        let median = median(samples);
        let baseline = *baseline.get_or_insert(median);
        let label = match t {
            Some(t) => format!("{commit:?} {t}T"),
            None => "sequential".into(),
        };
        println!(
            "{label:<34} {:>10.2} {:>10.0} {:>8.0}% {:>10}",
            median.as_secs_f64() * 1e3,
            txs.len() as f64 / median.as_secs_f64(),
            (median.as_secs_f64() / baseline.as_secs_f64() - 1.0) * 100.0,
            if t.is_some() {
                reexecuted.to_string()
            } else {
                "-".into()
            },
        );
    }
}
