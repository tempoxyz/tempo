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
    io,
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
    /// Receipts streamed to the receipt callback, each once, in block order.
    streamed: Vec<TempoReceipt>,
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
    execute_until(snapshot, txs, ctx, parallel, None)
}

/// Executes txs as one block like [`execute`], with the transaction stream yielding an error
/// instead of the transaction at fail_at.
fn execute_until(
    snapshot: &Arc<Snapshot>,
    txs: &[Recovered<TempoTxEnvelope>],
    ctx: TempoBlockExecutionCtx<'static>,
    parallel: Option<ParallelExecution>,
    fail_at: Option<usize>,
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
    let mut streamed = Vec::new();
    let result = executor.execute_transaction_stream(
        tx_envs.into_iter().zip(txs).enumerate().map(|(index, tx)| {
            if Some(index) == fail_at {
                Err(io::Error::other("transaction failed to decode"))
            } else {
                Ok(tx)
            }
        }),
        &**snapshot,
        make_evm,
        |_, _| {},
        |index, receipt| {
            // A batched commit that fails executes the block again, streaming the receipts before
            // the failure again, unchanged.
            if let Some(seen) = streamed.get(index) {
                assert_eq!(seen, receipt, "receipt {index} changed");
            } else {
                assert_eq!(index, streamed.len(), "receipt {index} out of order");
                streamed.push(receipt.clone());
            }
        },
    );
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
        streamed,
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
    assert_eq!(outcome.streamed, sequential.streamed);
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

/// The transaction stream ends with an error at transaction 70: the transactions before it commit
/// and the block reports the error, as executing it one transaction at a time does.
#[test_matrix([ParallelCommit::InOrder, ParallelCommit::Batched], [1, 4])]
fn parallel_stream_error_matches_sequential(commit: ParallelCommit, threads: usize) {
    const FAIL_AT: usize = 70;

    let accounts = Accounts::new();
    let snapshot = Arc::new(Snapshot(accounts.seed()));
    let txs = accounts.transactions(TX_COUNT, None);
    let ctx = || ctx(txs.len(), BLOCK_GAS_LIMIT, 0);

    let (sequential, _) = execute_until(&snapshot, &txs, ctx(), None, Some(FAIL_AT));
    assert_eq!(
        sequential.error.as_deref(),
        Some("transaction failed to decode")
    );
    assert_eq!(sequential.receipts.len(), FAIL_AT);
    assert_eq!(sequential.streamed, sequential.receipts);

    let (outcome, stats) = execute_until(
        &snapshot,
        &txs,
        ctx(),
        parallel(threads, commit),
        Some(FAIL_AT),
    );
    assert_eq!(stats, None);
    assert_eq!(outcome, sequential);
}

/// Seeded randomized differential test: Tempo-like blocks execute in parallel exactly as they do
/// sequentially.
///
/// Every seed builds one block mixing TIP-20 transfers over several tokens, hot recipients, one hot
/// sponsor, channel opens on the channel reserve, issuer mints, approvals and transferFrom, batched
/// calls, reverting and out-of-gas calls, non-payment calls, expiring, protocol and 2D nonce chains
/// and EIP-1559 transactions, sometimes with invalid transactions, stream errors or tight section
/// budgets. Each runs sequentially and with both commit modes on 1, 4 and 8 workers, comparing
/// receipts, streamed receipts, streamed state, executor counters and finish output.
///
/// TEMPO_PARALLEL_FUZZ_SEEDS sets how many seeds run (default 12), from TEMPO_PARALLEL_FUZZ_START
/// (default 0). A mismatch panics with the seed and the minimized transaction indices.
mod fuzz {
    use super::*;
    use alloy_consensus::{SignableTransaction, TxEip1559, transaction::SignerRecoverable};
    use alloy_primitives::{Signature, TxKind};
    use alloy_signer::SignerSync;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempo_contracts::precompiles::{ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS};
    use tempo_precompiles::{
        error::TempoPrecompileError,
        nonce::NonceManager,
        storage::StorageCtx,
        tip_fee_manager::TipFeeManager,
        tip20::{ISSUER_ROLE, TIP20Token},
        tip20_channel_reserve::TIP20ChannelReserve,
        tip20_factory::TIP20Factory,
        tip403_registry::TIP403Registry,
    };
    use tempo_primitives::transaction::{Call, TEMPO_EXPIRING_NONCE_KEY, TempoTransaction};
    use tip20::common::{TXGEN_FEE_PER_GAS, TXGEN_GAS_LIMIT, bench_evm, seeded_db};

    /// Chain id of bench_env.
    const CHAIN_ID: u64 = 1337;
    /// Senders, recipients and spenders.
    const PARTICIPANTS: u8 = 24;
    /// TIP-20 tokens besides pathUSD.
    const EXTRA_TOKENS: u8 = 3;
    /// Balance of every participant in every token.
    const MINT: u128 = 1_000_000_000_000_000_000;
    /// Parallel configurations every block runs in.
    const CONFIGS: [(ParallelCommit, usize); 6] = [
        (ParallelCommit::InOrder, 1),
        (ParallelCommit::InOrder, 4),
        (ParallelCommit::InOrder, 8),
        (ParallelCommit::Batched, 1),
        (ParallelCommit::Batched, 4),
        (ParallelCommit::Batched, 8),
    ];

    /// Transactions parallel executions committed from their speculative execution.
    static SPECULATIVE: AtomicUsize = AtomicUsize::new(0);
    /// Transactions parallel executions executed again on the executor.
    static REEXECUTED: AtomicUsize = AtomicUsize::new(0);

    /// SplitMix64.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn index(&mut self, n: usize) -> usize {
            self.below(n as u64) as usize
        }

        /// True with probability pct percent.
        fn chance(&mut self, pct: u64) -> bool {
            self.below(1000) < pct * 10
        }
    }

    /// Accounts, tokens and the pre-block state shared by every seed.
    struct World {
        signers: Vec<PrivateKeySigner>,
        addresses: Vec<Address>,
        sponsor: PrivateKeySigner,
        tokens: Vec<Address>,
        /// Recipients most transfers go to: a hot account and the channel reserve.
        hot: Vec<Address>,
        snapshot: Arc<Snapshot>,
    }

    impl World {
        fn new() -> Self {
            let signers: Vec<_> = (1..=PARTICIPANTS)
                .map(|i| PrivateKeySigner::from_bytes(&B256::with_last_byte(i)).unwrap())
                .collect();
            let addresses: Vec<_> = signers.iter().map(|signer| signer.address()).collect();
            let sponsor = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x5f)).unwrap();
            let tokens: Vec<_> = (0..=EXTRA_TOKENS)
                .map(|id| {
                    let mut bytes = PATH_USD_ADDRESS.into_array();
                    bytes[19] = id;
                    Address::from(bytes)
                })
                .collect();
            let hot = vec![Address::repeat_byte(0x77), addresses[1]];

            let mut evm = bench_evm(
                Default::default(),
                latest_known_hardfork(),
                DEFAULT_BLOCK_TIMESTAMP,
            );
            let admin = addresses[0];
            let holders: Vec<_> = addresses
                .iter()
                .copied()
                .chain([sponsor.address()])
                .collect();
            StorageCtx::enter_evm(&mut evm, || {
                TIP403Registry::new().initialize()?;
                TIP20Factory::new().initialize()?;
                for (id, token) in tokens.iter().enumerate() {
                    let quote = if id == 0 {
                        Address::ZERO
                    } else {
                        PATH_USD_ADDRESS
                    };
                    TIP20Factory::new().create_token_reserved_address(
                        *token, "Token", "TKN", "USD", quote, admin,
                    )?;
                    let mut tip20 = TIP20Token::from_address(*token)?;
                    tip20.grant_role_internal(admin, ISSUER_ROLE)?;
                    for holder in &holders {
                        tip20.mint(
                            admin,
                            ITIP20::mintCall {
                                to: *holder,
                                amount: U256::from(MINT),
                            },
                        )?;
                    }
                    // Every participant lets the next one spend its tokens.
                    for (i, owner) in addresses.iter().enumerate() {
                        tip20.approve(
                            *owner,
                            ITIP20::approveCall {
                                spender: addresses[(i + 1) % addresses.len()],
                                amount: U256::from(MINT / 1000),
                            },
                        )?;
                    }
                }
                TipFeeManager::new().initialize()?;
                // Fee AMM liquidity, so fees paid in any token swap to the validator's pathUSD.
                for token in &tokens[1..] {
                    TipFeeManager::new().mint(
                        admin,
                        *token,
                        PATH_USD_ADDRESS,
                        U256::from(MINT / 10),
                        admin,
                    )?;
                }
                NonceManager::new().initialize()?;
                TIP20ChannelReserve::new().initialize()?;
                Ok::<(), TempoPrecompileError>(())
            })
            .expect("failed to seed fuzz state");
            evm.state_mut().commit_transaction();
            evm.state_mut().clear_transaction_state();
            let snapshot = Arc::new(Snapshot(seeded_db(&evm).cache));

            Self {
                signers,
                addresses,
                sponsor,
                tokens,
                hot,
                snapshot,
            }
        }
    }

    /// One generated block and how it executes.
    struct Block {
        txs: Vec<Recovered<TempoTxEnvelope>>,
        /// The transaction stream fails at this index.
        fail_at: Option<usize>,
        /// Section budgets cut at the gas used before this fraction (per mille) of the block.
        tight: Option<(bool, u64)>,
    }

    /// Per-block generator state.
    struct Generator<'a> {
        world: &'a World,
        rng: Rng,
        /// Next protocol nonce of each participant.
        nonces: Vec<u64>,
        /// Next nonce of each participant's 2D nonce keys 1 to 3.
        nonces_2d: Vec<[u64; 3]>,
    }

    impl<'a> Generator<'a> {
        fn new(world: &'a World, seed: u64) -> Self {
            let n = world.signers.len();
            Self {
                world,
                rng: Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) ^ 0xdead_beef),
                nonces: vec![0; n],
                nonces_2d: vec![[0; 3]; n],
            }
        }

        fn token(&mut self) -> Address {
            if self.rng.chance(50) {
                PATH_USD_ADDRESS
            } else {
                self.world.tokens[self.rng.index(self.world.tokens.len())]
            }
        }

        fn recipient(&mut self) -> Address {
            if self.rng.chance(35) {
                self.world.hot[self.rng.index(self.world.hot.len())]
            } else {
                self.world.addresses[self.rng.index(self.world.addresses.len())]
            }
        }

        fn amount(&mut self) -> U256 {
            if self.rng.chance(3) {
                // More than any balance: the transfer reverts.
                U256::from(MINT) * U256::from(1000)
            } else {
                U256::from(1 + self.rng.below(1_000_000))
            }
        }

        fn transfer(&mut self) -> Call {
            let token = self.token();
            let call = ITIP20::transferCall {
                to: self.recipient(),
                amount: self.amount(),
            };
            Call::new(token, Bytes::from(call.abi_encode()))
        }

        /// One call of sender's transaction.
        fn call(&mut self, sender: usize) -> Call {
            match self.rng.below(100) {
                0..50 => self.transfer(),
                50..62 => {
                    let token = self.token();
                    let call = ITIP20ChannelReserve::openCall {
                        payee: self.world.addresses[self.rng.index(self.world.addresses.len())],
                        operator: Address::ZERO,
                        token,
                        deposit: alloy_primitives::aliases::U96::from(1 + self.rng.below(10_000)),
                        salt: B256::from(U256::from(self.rng.next())),
                        authorizedSigner: Address::ZERO,
                    };
                    Call::new(
                        TIP20_CHANNEL_RESERVE_ADDRESS,
                        Bytes::from(call.abi_encode()),
                    )
                }
                62..72 => {
                    // Spend the previous participant's allowance, or one that does not exist.
                    let n = self.world.addresses.len();
                    let from = if self.rng.chance(85) {
                        (sender + n - 1) % n
                    } else {
                        self.rng.index(n)
                    };
                    let token = self.token();
                    let call = ITIP20::transferFromCall {
                        from: self.world.addresses[from],
                        to: self.recipient(),
                        amount: U256::from(1 + self.rng.below(1_000_000_000)),
                    };
                    Call::new(token, Bytes::from(call.abi_encode()))
                }
                72..78 => {
                    // Only participant 0 is an issuer: mints by others revert.
                    let token = self.token();
                    let call = ITIP20::mintCall {
                        to: self.recipient(),
                        amount: U256::from(1 + self.rng.below(1_000_000)),
                    };
                    Call::new(token, Bytes::from(call.abi_encode()))
                }
                78..84 => {
                    let token = self.token();
                    let n = self.world.addresses.len();
                    let call = ITIP20::approveCall {
                        spender: self.world.addresses[(sender + 1) % n],
                        amount: U256::from(self.rng.below(1_000_000_000)),
                    };
                    Call::new(token, Bytes::from(call.abi_encode()))
                }
                84..90 => {
                    // Not a payment: an EOA call with calldata.
                    let to = self.world.addresses[self.rng.index(self.world.addresses.len())];
                    Call::new(to, Bytes::from(self.rng.next().to_be_bytes()))
                }
                90..94 => {
                    // Unknown selector: reverts.
                    let token = self.token();
                    Call::new(token, Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]))
                }
                94..97 => {
                    // Transfer to the zero address: reverts.
                    let token = self.token();
                    let call = ITIP20::transferCall {
                        to: Address::ZERO,
                        amount: U256::ONE,
                    };
                    Call::new(token, Bytes::from(call.abi_encode()))
                }
                _ => {
                    // Read-only call.
                    let token = self.token();
                    let call = ITIP20::balanceOfCall {
                        account: self.recipient(),
                    };
                    Call::new(token, Bytes::from(call.abi_encode()))
                }
            }
        }

        fn gas_limit(&mut self) -> u64 {
            if self.rng.chance(3) {
                // Often runs out of gas during execution, rarely below the intrinsic gas.
                285_000 + self.rng.below(120_000)
            } else {
                TXGEN_GAS_LIMIT
            }
        }

        fn transaction(&mut self) -> Recovered<TempoTxEnvelope> {
            let sender = self.rng.index(self.world.signers.len());
            let signer = &self.world.signers[sender];
            if self.rng.chance(5) {
                // An EIP-1559 call on the protocol nonce.
                let call = self.transfer();
                let nonce = self.nonces[sender];
                self.nonces[sender] += 1;
                let tx = TxEip1559 {
                    chain_id: CHAIN_ID,
                    nonce,
                    gas_limit: self.gas_limit(),
                    max_fee_per_gas: TXGEN_FEE_PER_GAS,
                    max_priority_fee_per_gas: self.rng.below(2) as u128,
                    to: TxKind::Call(call.to.into_to().unwrap()),
                    value: U256::ZERO,
                    access_list: Default::default(),
                    input: call.input,
                };
                let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
                return TempoTxEnvelope::Eip1559(tx.into_signed(signature))
                    .try_into_recovered()
                    .unwrap();
            }

            let calls = if self.rng.chance(8) {
                (0..2 + self.rng.below(3))
                    .map(|_| self.call(sender))
                    .collect()
            } else {
                vec![self.call(sender)]
            };
            let (nonce_key, nonce, valid_before) = match self.rng.below(100) {
                0..70 => (
                    TEMPO_EXPIRING_NONCE_KEY,
                    0,
                    Some(
                        NonZeroU64::new(DEFAULT_BLOCK_TIMESTAMP + 1 + self.rng.below(25)).unwrap(),
                    ),
                ),
                70..85 => {
                    let nonce = self.nonces[sender];
                    self.nonces[sender] += 1;
                    (U256::ZERO, nonce, None)
                }
                _ => {
                    let key = self.rng.index(3);
                    let nonce = self.nonces_2d[sender][key];
                    self.nonces_2d[sender][key] += 1;
                    (U256::from(key + 1), nonce, None)
                }
            };
            let sponsor = match self.rng.below(100) {
                0..20 => Some(&self.world.sponsor),
                // Another participant: a sponsor that is the sender is invalid.
                20..25 => {
                    let n = self.world.signers.len();
                    Some(&self.world.signers[(sender + 1 + self.rng.index(n - 1)) % n])
                }
                _ => None,
            };
            let mut tx = TempoTransaction {
                chain_id: CHAIN_ID,
                fee_token: if self.rng.chance(10) {
                    None
                } else {
                    Some(PATH_USD_ADDRESS)
                },
                max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
                max_fee_per_gas: TXGEN_FEE_PER_GAS,
                gas_limit: self.gas_limit(),
                calls,
                access_list: Default::default(),
                nonce_key,
                nonce,
                fee_payer_signature: sponsor.map(|_| Signature::test_signature()),
                valid_before,
                valid_after: None,
                key_authorization: None,
                tempo_authorization_list: Vec::new(),
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
            if let Some(sponsor) = sponsor {
                tx.fee_payer_signature = Some(
                    sponsor
                        .sign_hash_sync(&tx.fee_payer_signature_hash(signer.address()))
                        .unwrap(),
                );
            }
            TempoTxEnvelope::from(tx.into_signed(signature.into()))
                .try_into_recovered()
                .unwrap()
        }

        fn block(mut self) -> Block {
            let count = match self.rng.below(100) {
                0..25 => self.rng.index(130),
                25..90 => 128 + self.rng.index(300),
                _ => 400 + self.rng.index(600),
            };
            let mut txs: Vec<_> = (0..count).map(|_| self.transaction()).collect();
            // Rarely, an invalid transaction ends the block with an error.
            if !txs.is_empty() && self.rng.chance(6) {
                let at = self.rng.index(txs.len());
                match self.rng.below(3) {
                    // Replays an earlier transaction.
                    0 => {
                        let replay = txs[self.rng.index(at + 1)].clone();
                        txs.insert(at, replay);
                    }
                    // Skips a protocol nonce.
                    1 => {
                        let sender = self.rng.index(self.world.signers.len());
                        self.nonces[sender] += 1;
                        txs.insert(at, self.transaction_from_protocol_nonce(sender));
                    }
                    // Drains a sender's fee balance.
                    _ => {
                        let sender = self.rng.index(self.world.signers.len());
                        txs.insert(at, self.drain(sender));
                    }
                }
            }
            let fail_at =
                (!txs.is_empty() && self.rng.chance(5)).then(|| self.rng.index(txs.len()));
            let tight = self
                .rng
                .chance(15)
                .then(|| (self.rng.chance(50), self.rng.below(1000)));
            Block {
                txs,
                fail_at,
                tight,
            }
        }

        fn transaction_from_protocol_nonce(&mut self, sender: usize) -> Recovered<TempoTxEnvelope> {
            let nonce = self.nonces[sender];
            self.nonces[sender] += 1;
            self.sign(sender, vec![self.transfer_static()], U256::ZERO, nonce)
        }

        fn transfer_static(&self) -> Call {
            let call = ITIP20::transferCall {
                to: self.world.hot[0],
                amount: U256::ONE,
            };
            Call::new(PATH_USD_ADDRESS, Bytes::from(call.abi_encode()))
        }

        /// Sends almost all of sender's pathUSD to the hot account on an expiring nonce.
        fn drain(&mut self, sender: usize) -> Recovered<TempoTxEnvelope> {
            let call = ITIP20::transferCall {
                to: self.world.hot[0],
                amount: U256::from(MINT - 1_000),
            };
            let call = Call::new(PATH_USD_ADDRESS, Bytes::from(call.abi_encode()));
            self.sign(sender, vec![call], TEMPO_EXPIRING_NONCE_KEY, 0)
        }

        fn sign(
            &self,
            sender: usize,
            calls: Vec<Call>,
            nonce_key: U256,
            nonce: u64,
        ) -> Recovered<TempoTxEnvelope> {
            let signer = &self.world.signers[sender];
            let tx = TempoTransaction {
                chain_id: CHAIN_ID,
                fee_token: Some(PATH_USD_ADDRESS),
                max_priority_fee_per_gas: TXGEN_FEE_PER_GAS,
                max_fee_per_gas: TXGEN_FEE_PER_GAS,
                gas_limit: TXGEN_GAS_LIMIT,
                calls,
                access_list: Default::default(),
                nonce_key,
                nonce,
                fee_payer_signature: None,
                valid_before: (nonce_key == TEMPO_EXPIRING_NONCE_KEY)
                    .then(|| NonZeroU64::new(DEFAULT_BLOCK_TIMESTAMP + 20).unwrap()),
                valid_after: None,
                key_authorization: None,
                tempo_authorization_list: Vec::new(),
            };
            let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
            TempoTxEnvelope::from(tx.into_signed(signature.into()))
                .try_into_recovered()
                .unwrap()
        }
    }

    /// The block's execution context: tight section budgets cut at the gas the sequential execution
    /// used before a point in the block.
    fn block_ctx(
        snapshot: &Arc<Snapshot>,
        txs: &[Recovered<TempoTxEnvelope>],
        tight: Option<(bool, u64)>,
    ) -> TempoBlockExecutionCtx<'static> {
        let Some((non_payment, per_mille)) = tight else {
            return ctx(txs.len(), BLOCK_GAS_LIMIT, 0);
        };
        let (probe, _) = execute(snapshot, txs, ctx(txs.len(), BLOCK_GAS_LIMIT, 0), None);
        let gas = probe
            .receipts
            .get(probe.receipts.len() * per_mille as usize / 1000)
            .map_or(0, |receipt| receipt.cumulative_gas_used);
        if non_payment {
            ctx(txs.len(), gas / 8, 0)
        } else {
            ctx(txs.len(), BLOCK_GAS_LIMIT, BLOCK_GAS_LIMIT - gas)
        }
    }

    /// Describes the first difference between two outcomes.
    fn first_difference(expected: &Outcome, actual: &Outcome) -> String {
        if expected.error != actual.error {
            return format!("error: {:?} != {:?}", expected.error, actual.error);
        }
        for (name, a, b) in [
            ("receipts", &expected.receipts, &actual.receipts),
            ("streamed", &expected.streamed, &actual.streamed),
        ] {
            if a.len() != b.len() {
                return format!("{name}: {} != {} receipts", a.len(), b.len());
            }
            if let Some(i) = (0..a.len()).find(|&i| a[i] != b[i]) {
                return format!("{name}[{i}]: {:?} != {:?}", a[i], b[i]);
            }
        }
        for (address, value) in &expected.state {
            if actual.state.get(address) != Some(value) {
                return format!(
                    "state of {address}: {value:?} != {:?}",
                    actual.state.get(address)
                );
            }
        }
        for address in actual.state.keys() {
            if !expected.state.contains_key(address) {
                return format!(
                    "state of {address}: only in parallel {:?}",
                    actual.state[address]
                );
            }
        }
        if expected.executor_state != actual.executor_state {
            return format!(
                "executor state: {:?} != {:?}",
                expected.executor_state, actual.executor_state
            );
        }
        if expected.finish != actual.finish {
            return match (&expected.finish, &actual.finish) {
                (Ok((a, _)), Ok((b, _))) if a != b => format!("finish result: {a} != {b}"),
                (Ok(_), Ok(_)) => "finish bundle state differs".to_string(),
                (a, b) => format!("finish: {:?} != {:?}", a.as_ref().err(), b.as_ref().err()),
            };
        }
        "equal".to_string()
    }

    /// Runs txs sequentially and in every configuration; returns the first mismatch.
    fn check(
        snapshot: &Arc<Snapshot>,
        txs: &[Recovered<TempoTxEnvelope>],
        fail_at: Option<usize>,
        tight: Option<(bool, u64)>,
        configs: &[(ParallelCommit, usize)],
    ) -> Option<((ParallelCommit, usize), String, Outcome)> {
        let ctx = block_ctx(snapshot, txs, tight);
        let (sequential, _) = execute_until(snapshot, txs, ctx.clone(), None, fail_at);
        for &(commit, threads) in configs {
            let (outcome, stats) = execute_until(
                snapshot,
                txs,
                ctx.clone(),
                parallel(threads, commit),
                fail_at,
            );
            if outcome != sequential {
                return Some((
                    (commit, threads),
                    first_difference(&sequential, &outcome),
                    sequential,
                ));
            }
            if let Some(stats) = stats {
                assert_eq!(stats.transactions, txs.len());
                SPECULATIVE.fetch_add(stats.speculative, Ordering::Relaxed);
                REEXECUTED.fetch_add(stats.reexecuted, Ordering::Relaxed);
            }
        }
        None
    }

    /// Removes transactions while some configuration still mismatches, repeating each check to
    /// catch scheduling-dependent mismatches.
    fn minimize(
        snapshot: &Arc<Snapshot>,
        mut txs: Vec<Recovered<TempoTxEnvelope>>,
        tight: Option<(bool, u64)>,
        config: (ParallelCommit, usize),
    ) -> Vec<Recovered<TempoTxEnvelope>> {
        let fails = |txs: &[Recovered<TempoTxEnvelope>]| {
            (0..4).any(|_| check(snapshot, txs, None, tight, &[config]).is_some())
        };
        let mut chunk = txs.len() / 2;
        while chunk > 0 {
            let mut start = 0;
            while start < txs.len() {
                let end = (start + chunk).min(txs.len());
                let candidate: Vec<_> = txs[..start].iter().chain(&txs[end..]).cloned().collect();
                if fails(&candidate) {
                    txs = candidate;
                } else {
                    start = end;
                }
            }
            chunk /= 2;
        }
        txs
    }

    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    #[test]
    fn parallel_fuzz_matches_sequential() {
        let start = env_u64("TEMPO_PARALLEL_FUZZ_START", 0);
        let seeds = env_u64("TEMPO_PARALLEL_FUZZ_SEEDS", 12);
        let world = World::new();
        let mut totals = [0usize; 4];
        for seed in start..start + seeds {
            let block = Generator::new(&world, seed).block();
            let mismatch = check(
                &world.snapshot,
                &block.txs,
                block.fail_at,
                block.tight,
                &CONFIGS,
            );
            if let Some((config, difference, _)) = mismatch {
                let minimal = minimize(&world.snapshot, block.txs.clone(), block.tight, config);
                let hashes: Vec<_> = minimal.iter().map(|tx| *tx.tx_hash()).collect();
                let minimal_difference =
                    check(&world.snapshot, &minimal, None, block.tight, &[config])
                        .map(|(_, difference, _)| difference);
                panic!(
                    "seed {seed} {config:?}: {difference}\nminimized to {} of {} transactions \
                     {hashes:?}: {minimal_difference:?}",
                    minimal.len(),
                    block.txs.len(),
                );
            }
            // Coverage: blocks, transactions, failed receipts, blocks ending with an error.
            let ctx = block_ctx(&world.snapshot, &block.txs, block.tight);
            let (sequential, _) =
                execute_until(&world.snapshot, &block.txs, ctx, None, block.fail_at);
            totals[0] += 1;
            totals[1] += sequential.receipts.len();
            totals[2] += sequential.receipts.iter().filter(|r| !r.success).count();
            totals[3] += usize::from(sequential.error.is_some());
            if std::env::var("TEMPO_PARALLEL_FUZZ_VERBOSE").is_ok() {
                eprintln!(
                    "seed {seed}: {} txs, {} receipts, {} failed, error {:?}",
                    block.txs.len(),
                    sequential.receipts.len(),
                    sequential.receipts.iter().filter(|r| !r.success).count(),
                    sequential.error
                );
            }
        }
        eprintln!(
            "fuzzed {} blocks: {} receipts, {} failed, {} ended with an error; parallel runs \
             committed {} speculative and {} re-executed transactions",
            totals[0],
            totals[1],
            totals[2],
            totals[3],
            SPECULATIVE.load(Ordering::Relaxed),
            REEXECUTED.load(Ordering::Relaxed),
        );
    }
}
