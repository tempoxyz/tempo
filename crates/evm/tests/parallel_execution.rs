//! Parallel block execution commits exactly what sequential execution does.
//!
//! Executes small blocks of expiring-nonce pathUSD transfers (the `tip20_execution` bench's
//! workload) with TempoBlockExecutor::execute_block_transactions sequentially and with evm2's
//! parallel executor, and compares receipts, final state, executor counters and finish output.

#[path = "../benches/tip20_execution.rs"]
#[allow(dead_code)]
mod tip20;

use alloy_consensus::transaction::{Recovered, TxHashRef};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use evm2::{
    block::{
        StateUpdate,
        ethereum::parallel::{ParallelCommit, ParallelExecutionStats},
    },
    bytecode::Bytecode,
    evm::{AccountInfo, Cache, CacheDB, DbResult, DynDatabase, DynDatabaseRef, EmptyDB},
    interpreter::Word,
};
use reth_evm::{BlockExecutor, BlockExecutorFactory, BundleState};
use reth_evm_ethereum::EthBlockExecutionCtx;
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::{Arc, Mutex},
};
use tempo_chainspec::TempoChainSpec;
use tempo_contracts::precompiles::ITIP20;
use tempo_evm::{
    ExecutorState, ParallelExecution, TempoBlockExecutionCtx, TempoEvm, TempoEvmConfig, TempoTxEnv,
};
use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, storage::StorageKey};
use tempo_primitives::{TempoReceipt, TempoTxEnvelope};
use test_case::test_matrix;
use tip20::common::{
    DEFAULT_BLOCK_TIMESTAMP, bench_env, latest_known_hardfork, sign_precompile_call,
};

/// Block gas limit of bench_env.
const BLOCK_GAS_LIMIT: u64 = 10_000_000_000;
/// Transactions per block: enough for conflicts between workers, small enough to stay fast.
const TX_COUNT: usize = 300;
/// Distinct senders, so blocks have both independent and conflicting transactions.
const SENDER_COUNT: u8 = 32;
/// Consensus epoch length of the test blocks.
const EPOCH_LENGTH: u64 = 1_000;
/// NonceManager's expiringNonceSeen mapping slot (see its storage layout docs).
const EXPIRING_NONCE_SEEN_SLOT: u64 = 1;
/// NonceManager's expiringNonceRing mapping slot (see its storage layout docs).
const EXPIRING_NONCE_RING_SLOT: u64 = 2;

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

/// Senders and recipients of the test blocks.
struct Accounts {
    signers: Vec<PrivateKeySigner>,
    participants: Vec<Address>,
}

impl Accounts {
    fn new() -> Self {
        let signers: Vec<_> = (1..=SENDER_COUNT)
            .map(|i| PrivateKeySigner::from_bytes(&B256::with_last_byte(i)).unwrap())
            .collect();
        let participants = signers.iter().map(|signer| signer.address()).collect();
        Self {
            signers,
            participants,
        }
    }

    /// count pathUSD transfers; every non_payment_every-th transaction instead calls an EOA
    /// with calldata, which is not a payment.
    fn transactions(
        &self,
        count: usize,
        non_payment_every: Option<usize>,
    ) -> Vec<Recovered<TempoTxEnvelope>> {
        (0..count)
            .map(|idx| {
                let signer = &self.signers[idx % self.signers.len()];
                let recipient =
                    self.participants[(idx.wrapping_mul(17) + 1) % self.participants.len()];
                if non_payment_every.is_some_and(|every| idx % every == every - 1) {
                    sign_precompile_call(signer, recipient, Bytes::from(idx.to_be_bytes()))
                } else {
                    let transfer = ITIP20::transferCall {
                        to: recipient,
                        amount: U256::from(idx as u64 + 1),
                    };
                    sign_precompile_call(
                        signer,
                        PATH_USD_ADDRESS,
                        Bytes::from(transfer.abi_encode()),
                    )
                }
            })
            .collect()
    }

    /// The pre-block state: pathUSD minted to every participant, fee and nonce managers set up.
    fn seed(&self) -> Cache {
        tip20::seed_in_memory_cache_db(
            &self.participants,
            DEFAULT_BLOCK_TIMESTAMP,
            false,
            latest_known_hardfork(),
        )
        .cache
    }
}

/// Everything one execution of a block committed.
#[derive(Debug, PartialEq)]
struct Outcome {
    /// Error of execute_block_transactions, if any.
    error: Option<String>,
    receipts: Vec<TempoReceipt>,
    state: BTreeMap<Address, (String, BTreeMap<U256, U256>)>,
    executor_state: ExecutorState,
    /// finish output, or its error.
    finish: Result<(String, BundleState), String>,
}

fn ctx(
    txs: usize,
    general_gas_limit: u64,
    shared_gas_limit: u64,
) -> TempoBlockExecutionCtx<'static> {
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
        general_gas_limit,
        shared_gas_limit,
        consensus_context: None,
    }
}

/// Executes txs as one block over snapshot and returns what it committed, with the execution
/// counters when it succeeded.
fn execute(
    snapshot: &Arc<Snapshot>,
    txs: &[Recovered<TempoTxEnvelope>],
    ctx: TempoBlockExecutionCtx<'static>,
    parallel: Option<ParallelExecution>,
) -> (Outcome, Option<ParallelExecutionStats>) {
    let config = TempoEvmConfig::new(Arc::new(TempoChainSpec::moderato()));
    let tx_envs: Vec<_> = txs
        .iter()
        .map(|tx| Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer()))
        .collect();
    let mut env = bench_env(latest_known_hardfork(), DEFAULT_BLOCK_TIMESTAMP);
    // Block 1 is not an epoch boundary, which would need a DKG outcome in the extra data.
    env.block.ext.epoch_length = NonZeroU64::new(EPOCH_LENGTH).unwrap();
    let db = CacheDB::new(SnapshotDb(snapshot.clone()));
    let evm = BlockExecutorFactory::evm_with_env(&config, db, env.clone());
    let mut executor = config.create_executor(evm, ctx);
    executor
        .apply_pre_execution_changes()
        .expect("pre-execution changes failed");
    let updates = Arc::new(Mutex::new(Vec::new()));
    let hook_updates = updates.clone();
    executor.set_state_hook(move |mut update| {
        // Accounts and slots stream in hash-map order: sort them to compare runs.
        update.accounts.sort_by_key(|account| account.address);
        for account in &mut update.accounts {
            account.storage.sort_by_key(|(slot, _)| *slot);
        }
        hook_updates.lock().unwrap().push(update);
    });
    executor.set_parallel_execution(parallel);

    let make_evm = evm_factory(|db| BlockExecutorFactory::evm_with_env(&config, db, env.clone()));
    let result =
        executor.execute_block_transactions(tx_envs.into_iter().zip(txs), &**snapshot, make_evm);
    let error = result.as_ref().err().map(|error| error.to_string());
    let receipts = executor.receipts().to_vec();
    let executor_state = executor.executor_state();
    let finish = executor
        .finish()
        .map(|output| (format!("{:?}", output.result), output.state))
        .map_err(|error| error.to_string());
    let state = final_state(&updates.lock().unwrap());
    let outcome = Outcome {
        error,
        receipts,
        state,
        executor_state,
        finish,
    };
    (outcome, result.ok())
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

fn parallel(threads: usize, commit: ParallelCommit) -> Option<ParallelExecution> {
    Some(ParallelExecution {
        threads: NonZeroUsize::new(threads).unwrap(),
        commit,
    })
}

/// Asserts that a parallel execution committed some transactions from their speculative execution,
/// so a batched block did not fall back to sequential execution. A single in-order worker executes
/// everything on the executor.
fn ensure_speculative(
    stats: Option<ParallelExecutionStats>,
    commit: ParallelCommit,
    threads: usize,
) {
    let stats = stats.expect("parallel execution failed");
    assert_eq!(stats.transactions, TX_COUNT);
    if commit == ParallelCommit::Batched || threads > 1 {
        assert!(stats.speculative > 0, "{stats:?}");
    }
}

#[test_matrix([ParallelCommit::InOrder, ParallelCommit::Batched], [1, 2, 4])]
fn parallel_commits_sequential_result(commit: ParallelCommit, threads: usize) {
    let accounts = Accounts::new();
    let snapshot = Arc::new(Snapshot(accounts.seed()));
    let txs = accounts.transactions(TX_COUNT, None);
    let ctx = || ctx(txs.len(), BLOCK_GAS_LIMIT, 0);

    let (sequential, _) = execute(&snapshot, &txs, ctx(), None);
    assert_eq!(sequential.error, None);
    assert_eq!(sequential.receipts.len(), TX_COUNT);
    assert!(sequential.receipts.iter().all(|receipt| receipt.success));
    assert!(sequential.finish.is_ok(), "{:?}", sequential.finish);

    let (outcome, stats) = execute(&snapshot, &txs, ctx(), parallel(threads, commit));
    assert_eq!(outcome, sequential);
    ensure_speculative(stats, commit, threads);
}

/// The block crosses from the non-shared section into the gas incentive section mid-block, by
/// exhausting the non-shared budget (shared_gas_limit) or the non-payment budget
/// (general_gas_limit).
#[test_matrix([false, true], [ParallelCommit::InOrder, ParallelCommit::Batched], [1, 4])]
fn parallel_section_accounting_matches_sequential(
    exhaust_non_payment: bool,
    commit: ParallelCommit,
    threads: usize,
) {
    let accounts = Accounts::new();
    let snapshot = Arc::new(Snapshot(accounts.seed()));
    let txs = accounts.transactions(TX_COUNT, Some(7));

    // The budget allows about the gas of the first half of the block.
    let (probe, _) = execute(&snapshot, &txs, ctx(txs.len(), BLOCK_GAS_LIMIT, 0), None);
    assert_eq!(probe.error, None);
    let half = probe.receipts[TX_COUNT / 2].cumulative_gas_used;
    let ctx = || {
        if exhaust_non_payment {
            // Non-payment transactions are a seventh of the block.
            ctx(txs.len(), half / 7, 0)
        } else {
            ctx(txs.len(), BLOCK_GAS_LIMIT, BLOCK_GAS_LIMIT - half)
        }
    };

    let (sequential, _) = execute(&snapshot, &txs, ctx(), None);
    assert_eq!(sequential.error, None);
    assert_eq!(sequential.receipts.len(), TX_COUNT);
    let state = format!("{:?}", sequential.executor_state);
    assert!(state.contains("GasIncentive"), "{state}");
    // The first quarter of the block still fits the non-shared section.
    let (prefix, _) = execute(&snapshot, &txs[..TX_COUNT / 4], ctx(), None);
    let state = format!("{:?}", prefix.executor_state);
    assert!(state.contains("NonShared"), "{state}");

    let (outcome, stats) = execute(&snapshot, &txs, ctx(), parallel(threads, commit));
    assert_eq!(outcome, sequential);
    ensure_speculative(stats, commit, threads);
}

/// Transaction 50 finds an unexpired entry at its expiring-nonce ring slot: a batched block falls
/// back to sequential execution, and both commit modes report the sequential error after
/// committing exactly the transactions before it.
#[test_matrix([ParallelCommit::InOrder, ParallelCommit::Batched], [1, 4])]
fn parallel_full_ring_reports_sequential_error(commit: ParallelCommit, threads: usize) {
    const FULL_INDEX: u32 = 50;

    let accounts = Accounts::new();
    let mut cache = accounts.seed();
    let blocker = B256::repeat_byte(0xab);
    let nonce_storage = &mut cache
        .storage
        .entry(NONCE_PRECOMPILE_ADDRESS)
        .or_default()
        .slots;
    nonce_storage.insert(
        FULL_INDEX.mapping_slot(U256::from(EXPIRING_NONCE_RING_SLOT)),
        U256::from_be_bytes(blocker.0),
    );
    nonce_storage.insert(
        blocker.mapping_slot(U256::from(EXPIRING_NONCE_SEEN_SLOT)),
        U256::from(DEFAULT_BLOCK_TIMESTAMP + 100),
    );
    let snapshot = Arc::new(Snapshot(cache));
    let txs = accounts.transactions(TX_COUNT, None);
    let ctx = || ctx(txs.len(), BLOCK_GAS_LIMIT, 0);

    let (sequential, _) = execute(&snapshot, &txs, ctx(), None);
    assert_eq!(
        sequential.error.as_deref(),
        Some(
            format!(
                "EVM reported invalid transaction ({}): nonce manager error: Tempo Transaction \
                 nonce error: ExpiringNonceSetFull(ExpiringNonceSetFull)",
                txs[FULL_INDEX as usize].tx_hash()
            )
            .as_str()
        )
    );
    assert_eq!(sequential.receipts.len(), FULL_INDEX as usize);

    let (outcome, stats) = execute(&snapshot, &txs, ctx(), parallel(threads, commit));
    assert_eq!(stats, None);
    assert_eq!(outcome.error, sequential.error);
    assert_eq!(outcome.receipts, sequential.receipts);
    assert_eq!(outcome.executor_state, sequential.executor_state);
    assert_eq!(outcome.state, sequential.state);
    assert_eq!(outcome.finish, sequential.finish);
}

#[test_matrix([0, 1], [ParallelCommit::InOrder, ParallelCommit::Batched], [1, 4])]
fn parallel_executes_tiny_blocks(count: usize, commit: ParallelCommit, threads: usize) {
    let accounts = Accounts::new();
    let snapshot = Arc::new(Snapshot(accounts.seed()));
    let txs = accounts.transactions(count, None);
    let ctx = || ctx(txs.len(), BLOCK_GAS_LIMIT, 0);

    let (sequential, _) = execute(&snapshot, &txs, ctx(), None);
    assert_eq!(sequential.error, None);
    assert_eq!(sequential.receipts.len(), count);

    let (outcome, stats) = execute(&snapshot, &txs, ctx(), parallel(threads, commit));
    assert_eq!(outcome, sequential);
    assert_eq!(
        stats.expect("parallel execution failed").transactions,
        count
    );
}
