use super::*;
use crate::test_utils::test_evm_with_basefee;
use alloy_evm::Evm;
use alloy_primitives::{Bytes, TxKind};
use alloy_trie::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use revm::{
    DatabaseCommit,
    context::TxEnv,
    database::{CacheDB, EmptyDB},
};

type TestDB = CacheDB<EmptyDB>;

fn address(index: u64) -> Address {
    Address::from_word(B256::from(U256::from(index + 0x10000)))
}

fn contract(db: &mut TestDB, address: Address, code: &[u8]) {
    db.insert_account_info(
        address,
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::copy_from_slice(code))),
    );
}

fn transaction(sender: u64, target: Address, nonce: u64, data: &[u8]) -> TempoTxEnv {
    TempoTxEnv {
        inner: TxEnv {
            caller: address(sender),
            kind: TxKind::Call(target),
            nonce,
            gas_limit: 1_000_000,
            gas_price: 0,
            data: Bytes::copy_from_slice(data),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn root(db: &TestDB) -> B256 {
    state_root_unhashed(db.cache.accounts.iter().filter_map(|(address, account)| {
        account.info().map(|info| {
            (
                *address,
                TrieAccount {
                    nonce: info.nonce,
                    balance: info.balance,
                    code_hash: info.code_hash,
                    storage_root: storage_root_unhashed(
                        account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| (B256::from(*slot), *value)),
                    ),
                },
            )
        })
    }))
}

/// Compare full per-transaction outcomes, receipts (including cumulative gas), and the
/// Ethereum state trie, not just the subset of writes the scheduler happens to report.
fn differential(
    db: TestDB,
    transactions: &[TempoTxEnv],
    threads: usize,
    batch_size: usize,
) -> ExecutionStats {
    differential_at_spec(db, transactions, threads, batch_size, TempoHardfork::T0)
}

fn differential_at_spec(
    db: TestDB,
    transactions: &[TempoTxEnv],
    threads: usize,
    batch_size: usize,
    spec: TempoHardfork,
) -> ExecutionStats {
    differential_with_backoff(db, transactions, threads, batch_size, spec, false)
}

fn differential_with_backoff(
    db: TestDB,
    transactions: &[TempoTxEnv],
    threads: usize,
    batch_size: usize,
    spec: TempoHardfork,
    adaptive: bool,
) -> ExecutionStats {
    for streaming in [true, false] {
        differential_mode(
            db.clone(),
            transactions,
            threads,
            batch_size,
            spec,
            adaptive,
            (streaming, true),
        );
    }
    // Exercise actual streaming, then a frozen view that makes conflict-count
    // assertions deterministic and forces the maximum number of reuse checks.
    differential_mode(
        db.clone(),
        transactions,
        threads,
        batch_size,
        spec,
        adaptive,
        (true, false),
    );
    differential_mode(
        db,
        transactions,
        threads,
        batch_size,
        spec,
        adaptive,
        (false, false),
    )
}

fn differential_mode(
    db: TestDB,
    transactions: &[TempoTxEnv],
    threads: usize,
    batch_size: usize,
    spec: TempoHardfork,
    adaptive: bool,
    (streaming, fee_rebasing): (bool, bool),
) -> ExecutionStats {
    // Exercise both worker strategies against full canonical outcomes. Keep the
    // original strategy's counters for tests targeting particular replay paths.
    differential_worker_mode(
        db.clone(),
        transactions,
        threads,
        batch_size,
        spec,
        adaptive,
        (streaming, fee_rebasing, true),
    );
    differential_worker_mode(
        db,
        transactions,
        threads,
        batch_size,
        spec,
        adaptive,
        (streaming, fee_rebasing, false),
    )
}

fn differential_worker_mode(
    db: TestDB,
    transactions: &[TempoTxEnv],
    threads: usize,
    batch_size: usize,
    spec: TempoHardfork,
    adaptive: bool,
    (streaming, fee_rebasing, chained): (bool, bool, bool),
) -> ExecutionStats {
    let env = EvmEnv {
        cfg_env: revm::context::CfgEnv::new_with_spec_and_gas_params(
            spec,
            tempo_revm::gas_params::tempo_gas_params(spec),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                gas_limit: 500_000_000,
                basefee: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let mut sequential = TempoEvm::new(db.clone(), env.clone());
    let mut parallel = TempoEvm::new(db, env);
    parallel.set_speculative_executor(Some(
        SpeculativeExecutor::new(threads, batch_size)
            .unwrap()
            .with_adaptive_backoff(adaptive)
            .with_streaming(streaming)
            .with_fee_rebasing(fee_rebasing)
            .with_chained_workers(chained)
            .with_minimum_body_duration(Duration::ZERO),
    ));
    let mut sequential_gas = 0;
    let mut parallel_gas = 0;
    for batch in transactions.chunks(batch_size) {
        parallel.prepare_transactions(batch.iter().cloned().map(|tx| (tx, Address::ZERO)));
        for tx in batch {
            let expected = sequential.transact_raw(tx.clone());
            let actual = parallel.transact_raw(tx.clone());
            match (expected, actual) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(expected, actual, "different execution for {tx:?}");
                    sequential_gas += expected.result.tx_gas_used();
                    parallel_gas += actual.result.tx_gas_used();
                    let receipt = |result: &ResultAndState<TempoHaltReason>, gas| {
                        tempo_primitives::TempoReceipt {
                            tx_type: tempo_primitives::TempoTxType::Legacy,
                            success: result.result.is_success(),
                            cumulative_gas_used: gas,
                            logs: result.result.logs().to_vec(),
                        }
                    };
                    assert_eq!(
                        receipt(&expected, sequential_gas),
                        receipt(&actual, parallel_gas)
                    );
                    sequential.db_mut().commit(expected.state);
                    parallel.db_mut().commit(actual.state);
                }
                (Err(expected), Err(actual)) => {
                    assert_eq!(expected.to_string(), actual.to_string())
                }
                (expected, actual) => panic!("different validity: {expected:?} vs {actual:?}"),
            }
        }
    }
    assert_eq!(root(sequential.db()), root(parallel.db()));
    parallel.execution_stats()
}

#[test]
fn disjoint_storage_writes_reuse_results() {
    let target = address(900);
    let mut db = TestDB::default();
    // SSTORE(calldata[0], calldata[32]).
    contract(&mut db, target, &[0x60, 0x20, 0x35, 0x60, 0, 0x35, 0x55, 0]);
    let txs = (0..32)
        .map(|i| {
            let mut input = U256::from(i).to_be_bytes::<32>().to_vec();
            input.extend_from_slice(&U256::from(i + 1).to_be_bytes::<32>());
            transaction(i, target, 0, &input)
        })
        .collect::<Vec<_>>();
    let stats = differential(db, &txs, 4, 32);
    assert_eq!(stats.reused, 32);
    assert_eq!(stats.conflicts, 0);
}

#[test]
fn shared_storage_replays_only_conflicting_transactions() {
    let target = address(900);
    let mut db = TestDB::default();
    // Increment slot zero and return it; both gas and output depend on the prefix.
    contract(
        &mut db,
        target,
        &[
            0x60, 0, 0x54, 0x60, 1, 1, 0x80, 0x60, 0, 0x55, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0,
            0xf3,
        ],
    );
    contract(&mut db, address(901), &[0]);
    let txs = (0..16)
        .map(|i| transaction(i, if i % 2 == 0 { target } else { address(901) }, 0, &[]))
        .collect::<Vec<_>>();
    let stats = differential(db, &txs, 4, 16);
    assert_eq!(stats.conflicts, 7);
    assert_eq!(stats.reused, 9);
}

#[test]
fn speculative_nonce_errors_are_retried_in_order() {
    let txs = (0..16)
        .map(|i| transaction(1, address(900), i, &[]))
        .collect::<Vec<_>>();
    let stats = differential(TestDB::default(), &txs, 4, 16);
    assert_eq!(stats.reused, 1);
    assert_eq!(stats.retries, 15);
}

#[test]
fn chained_workers_reuse_nonce_dependencies() {
    let mut db = TestDB::default();
    contract(&mut db, address(900), &[0]);
    let txs = (0..32)
        .map(|i| transaction(i % 4, address(900), i / 4, &[]))
        .collect::<Vec<_>>();
    for spec in FEE_SPECS {
        for streaming in [false, true] {
            let stats = differential_worker_mode(
                db.clone(),
                &txs,
                4,
                32,
                spec,
                false,
                (streaming, true, true),
            );
            assert_eq!(stats.reused, 32, "{spec:?}, streaming={streaming}");
            assert_eq!(stats.conflicts + stats.retries, 0);
        }
    }
}

#[test]
fn chained_workers_revalidate_transitive_predictions() {
    let mut db = TestDB::default();
    let target = address(900);
    // Increment and return a counter. The second lane invalidates the first
    // lane's predictions, including the result chained from its stale result.
    contract(
        &mut db,
        target,
        &[
            0x60, 0, 0x54, 0x60, 1, 1, 0x80, 0x60, 0, 0x55, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3,
        ],
    );
    let txs = [
        transaction(1, target, 0, &[]),
        transaction(2, target, 0, &[]),
        transaction(1, target, 1, &[]),
        transaction(1, target, 2, &[]),
    ];
    for spec in FEE_SPECS {
        let stats =
            differential_worker_mode(db.clone(), &txs, 2, 4, spec, false, (false, true, true));
        assert_eq!(stats.reused, 1);
        assert_eq!(stats.conflicts, 3);
    }
}

#[test]
fn chained_workers_reject_predictions_from_skipped_candidates() {
    let mut db = TestDB::default();
    contract(&mut db, address(900), &[0]);
    let txs = [
        transaction(1, address(900), 0, &[]),
        transaction(1, address(900), 1, &[]),
        transaction(2, address(900), 0, &[]),
    ];
    let mut sequential = test_evm_with_basefee(db.clone(), 0);
    let mut parallel = test_evm_with_basefee(db, 0);
    parallel.set_speculative_executor(Some(
        SpeculativeExecutor::new(2, 3)
            .unwrap()
            .with_streaming(false),
    ));
    parallel.prepare_transactions(txs.iter().cloned().map(|tx| (tx, Address::ZERO)));
    // A pool preview candidate can disappear before authoritative selection.
    // Its predicted nonce must not make the next transaction valid.
    let expected = sequential.transact_raw(txs[1].clone()).unwrap_err();
    let actual = parallel.transact_raw(txs[1].clone()).unwrap_err();
    assert_eq!(expected.to_string(), actual.to_string());
    assert_eq!(parallel.execution_stats().conflicts, 1);
    let expected = sequential.transact_raw(txs[2].clone()).unwrap();
    let actual = parallel.transact_raw(txs[2].clone()).unwrap();
    assert_eq!(expected, actual);
    sequential.db_mut().commit(expected.state);
    parallel.db_mut().commit(actual.state);
    assert_eq!(root(sequential.db()), root(parallel.db()));
}

#[test]
fn failed_speculation_does_not_hide_the_next_transactions_reads() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    let txs = [
        transaction(
            0,
            PATH_USD_ADDRESS,
            0,
            &ITIP20::transferCall {
                to: address(2),
                amount: U256::from(17),
            }
            .abi_encode(),
        ),
        // Validation loads sender 2's balance, then fails on its nonce.
        transaction(2, address(900), 1, &[]),
        transaction(
            2,
            PATH_USD_ADDRESS,
            0,
            &ITIP20::transferCall {
                to: address(100),
                amount: U256::from(3),
            }
            .abi_encode(),
        ),
    ];
    // One worker makes the error immediately precede the last execution. That
    // execution must record the balance read even if revm retained it on error.
    let stats = differential(funded_tip20_db(3), &txs, 1, 3);
    assert_eq!(stats.retries, 1);
    assert_eq!(stats.conflicts, 1);
}

#[test]
fn conflict_backoff_preserves_results_and_resumes_parallel_work() {
    let shared = address(900);
    let independent = address(901);
    let mut db = TestDB::default();
    // Increment a shared slot so all but the first candidate conflict.
    contract(
        &mut db,
        shared,
        &[0x60, 0, 0x54, 0x60, 1, 1, 0x60, 0, 0x55, 0],
    );
    contract(&mut db, independent, &[0]);
    let txs = (0..320)
        .map(|i| transaction(i, if i < 288 { shared } else { independent }, 0, &[]))
        .collect::<Vec<_>>();
    let stats = differential_with_backoff(db, &txs, 4, 32, TempoHardfork::T0, true);
    assert_eq!(stats.speculated, 64);
    assert_eq!(stats.conflicts, 31);
    assert_eq!(stats.backoff, 256);
    assert_eq!(stats.reused, 33);
}

#[test]
fn backoff_advances_candidates_without_converting_transactions() {
    let target = address(900);
    let mut db = TestDB::default();
    contract(
        &mut db,
        target,
        &[0x60, 0, 0x54, 0x60, 1, 1, 0x60, 0, 0x55, 0],
    );
    let mut evm = test_evm_with_basefee(db, 0);
    evm.ctx_mut().block.gas_limit = 500_000_000;
    evm.set_speculative_executor(Some(
        SpeculativeExecutor::new(4, 32)
            .unwrap()
            .with_streaming(false),
    ));
    evm.prepare_transactions((0..32).map(|i| (transaction(i, target, 0, &[]), Address::ZERO)));
    for i in 0..32 {
        let result = evm.transact_raw(transaction(i, target, 0, &[])).unwrap();
        evm.db_mut().commit(result.state);
    }
    assert_eq!(evm.execution_stats().conflicts, 31);
    let visited = std::cell::Cell::new(0);
    let mut candidates = (32..96).inspect(|_| visited.set(visited.get() + 1));
    evm.prepare_transactions_with(&mut candidates, |_| {
        panic!("backoff must not clone or convert candidate transaction data")
    });
    assert_eq!(visited.get(), 32);
    assert_eq!(candidates.next(), Some(64));
}

#[test]
fn reverted_reads_remain_dependencies() {
    let target = address(900);
    let mut db = TestDB::default();
    // With empty calldata, return slot zero as REVERT data; otherwise store calldata.
    contract(
        &mut db,
        target,
        &[
            0x36, 0x60, 0x14, 0x57, 0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xfd, 0, 0,
            0, 0, 0, 0x5b, 0x60, 0, 0x35, 0x60, 0, 0x55, 0,
        ],
    );
    let txs = vec![
        transaction(1, target, 0, &U256::from(42).to_be_bytes::<32>()),
        transaction(2, target, 0, &[]),
    ];
    let stats = differential(db, &txs, 2, 2);
    assert_eq!(stats.conflicts, 1);
}

#[test]
fn generated_dependency_graphs_match_across_workers_and_windows() {
    for paid in [false, true] {
        let target = address(900);
        let mut db = if paid {
            funded_tip20_db(16)
        } else {
            TestDB::default()
        };
        if paid {
            contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
        }
        // Increment the storage key in calldata and emit the new value.
        contract(
            &mut db,
            target,
            &[0x60, 0, 0x35, 0x80, 0x54, 0x60, 1, 1, 0x90, 0x55, 0],
        );
        let mut seed = 0x1234_5678u64;
        let mut nonces = [0; 16];
        let txs = (0..160)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let sender = (seed % 16) as usize;
                let mut tx = transaction(
                    sender as u64,
                    target,
                    nonces[sender],
                    &U256::from(seed % 31).to_be_bytes::<32>(),
                );
                tx.inner.gas_price = u128::from(paid);
                nonces[sender] += 1;
                tx
            })
            .collect::<Vec<_>>();
        for threads in [1, 2, 4] {
            for window in [1, 7, 32] {
                differential(db.clone(), &txs, threads, window);
            }
        }
    }
}

#[test]
fn changing_block_environment_discards_candidates() {
    let mut db = TestDB::default();
    let target = address(900);
    // Return COINBASE.
    contract(
        &mut db,
        target,
        &[0x41, 0x60, 0, 0x52, 0x60, 0x20, 0x60, 0, 0xf3],
    );
    let mut evm = test_evm_with_basefee(db, 0);
    evm.set_speculative_executor(Some(SpeculativeExecutor::new(2, 2).unwrap()));
    let tx = transaction(1, target, 0, &[]);
    evm.prepare_transactions([(tx.clone(), Address::ZERO)]);
    evm.ctx_mut().block.beneficiary = address(123);
    let result = evm.transact_raw(tx).unwrap();
    assert_eq!(
        result.result.output().unwrap().as_ref(),
        address(123).into_word().as_slice()
    );
    assert_eq!(evm.execution_stats().reused, 0);
}

fn funded_tip20_db(users: u64) -> TestDB {
    funded_tip20_accounts((0..users).map(address))
}

fn funded_tip20_accounts(users: impl IntoIterator<Item = Address>) -> TestDB {
    use revm::context_interface::JournalTr;
    use tempo_precompiles::{storage::StorageCtx, test_util::TIP20Setup};
    let mut evm = test_evm_with_basefee(TestDB::default(), 0);
    StorageCtx::enter_ctx(evm.ctx_mut(), || {
        let mut setup = TIP20Setup::path_usd(address(999)).with_issuer(address(999));
        for user in users {
            setup = setup.with_mint(user, U256::from(1_000_000_000u64));
        }
        setup.apply().unwrap();
    });
    let state = evm.ctx_mut().journaled_state.finalize();
    evm.db_mut().commit(state);
    evm.finish().0
}

const FEE_SPECS: [TempoHardfork; 8] = [
    TempoHardfork::T0,
    TempoHardfork::T1,
    TempoHardfork::T1A,
    TempoHardfork::T1B,
    TempoHardfork::T1C,
    TempoHardfork::T2,
    TempoHardfork::T3,
    TempoHardfork::T4,
];

#[test]
fn fee_rebasing_reuses_native_payments() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip20::ITIP20};
    let mut db = funded_tip20_db(16);
    contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
    let txs = (0..16)
        .map(|i| {
            let mut tx = transaction(
                i,
                PATH_USD_ADDRESS,
                0,
                &ITIP20::transferCall {
                    to: address(100 + i),
                    amount: U256::from(17),
                }
                .abi_encode(),
            );
            tx.inner.gas_price = 1;
            tx
        })
        .collect::<Vec<_>>();
    for spec in FEE_SPECS {
        let stats = differential_mode(db.clone(), &txs, 4, 16, spec, false, (false, true));
        assert_eq!(stats.reused, 16, "{spec:?}");
        assert_eq!(stats.fees_rebased, 15, "{spec:?}");
        assert_eq!(stats.conflicts, 0);
    }
}

#[test]
fn fee_rebasing_preserves_observed_and_reverted_fee_reads() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::IFeeManager, tip20::ITIP20,
    };
    let inputs = [
        (
            PATH_USD_ADDRESS,
            ITIP20::balanceOfCall {
                account: TIP_FEE_MANAGER_ADDRESS,
            }
            .abi_encode(),
        ),
        (
            TIP_FEE_MANAGER_ADDRESS,
            IFeeManager::collectedFeesCall {
                validator: Address::ZERO,
                token: PATH_USD_ADDRESS,
            }
            .abi_encode(),
        ),
    ];
    for spec in FEE_SPECS {
        for (target, input) in &inputs {
            for revert in [false, true] {
                let mut db = funded_tip20_db(2);
                contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
                let target = if revert {
                    // Forward calldata to the native view, then revert with its output.
                    // The fee balance may already be cached by pre-execution.
                    let mut code = vec![
                        0x36, 0x60, 0, 0x60, 0, 0x37, 0x60, 32, 0x60, 0, 0x36, 0x60, 0, 0x73,
                    ];
                    code.extend_from_slice(target.as_slice());
                    code.extend_from_slice(&[0x5a, 0xfa, 0x50, 0x60, 32, 0x60, 0, 0xfd]);
                    contract(&mut db, address(900), &code);
                    address(900)
                } else {
                    *target
                };
                let txs = (0..2)
                    .map(|i| {
                        let mut tx = transaction(i, target, 0, input);
                        tx.inner.gas_price = 1;
                        tx
                    })
                    .collect::<Vec<_>>();
                let stats = differential_mode(db, &txs, 2, 2, spec, false, (false, true));
                assert_eq!(stats.fees_rebased, 0, "{spec:?}, revert={revert}");
                assert_eq!(stats.conflicts, 1, "{spec:?}, revert={revert}");
            }
        }
    }
}

#[test]
fn custom_gas_parameters_disable_fee_rebasing() {
    use revm::context_interface::cfg::GasId;
    for spec in FEE_SPECS {
        let mut db = funded_tip20_db(2);
        contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
        let mut env = EvmEnv::<_, TempoBlockEnv> {
            cfg_env: revm::context::CfgEnv::new_with_spec_and_gas_params(
                spec,
                tempo_revm::gas_params::tempo_gas_params(spec),
            ),
            ..Default::default()
        };
        let id = GasId::sstore_set_without_load_cost();
        let cost = env.cfg_env.gas_params.get(id);
        env.cfg_env.gas_params.override_gas([(id, cost + 1)]);
        env.block_env.inner.basefee = 0;
        env.block_env.inner.gas_limit = 30_000_000;
        let mut sequential = TempoEvm::new(db.clone(), env.clone());
        let mut parallel = TempoEvm::new(db, env);
        parallel.set_speculative_executor(Some(
            SpeculativeExecutor::new(2, 2)
                .unwrap()
                .with_adaptive_backoff(false)
                .with_streaming(false),
        ));
        let txs = (0..2)
            .map(|i| {
                let mut tx = transaction(i, address(900), 0, &[]);
                tx.inner.gas_price = 1;
                tx
            })
            .collect::<Vec<_>>();
        parallel.prepare_transactions(txs.iter().cloned().map(|tx| (tx, Address::ZERO)));
        for tx in txs {
            let expected = sequential.transact_raw(tx.clone()).unwrap();
            let actual = parallel.transact_raw(tx).unwrap();
            assert_eq!(actual, expected);
            sequential.db_mut().commit(expected.state);
            parallel.db_mut().commit(actual.state);
        }
        assert_eq!(root(parallel.db()), root(sequential.db()));
        assert_eq!(parallel.execution_stats().fees_rebased, 0);
        assert_eq!(parallel.execution_stats().conflicts, 1);
    }
}

#[test]
fn fee_rebasing_preserves_contract_writes_to_fee_slots() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::IFeeManager, tip20::ITIP20,
    };
    let inputs = [
        (
            PATH_USD_ADDRESS,
            ITIP20::transferCall {
                to: TIP_FEE_MANAGER_ADDRESS,
                amount: U256::from(17),
            }
            .abi_encode(),
        ),
        (
            TIP_FEE_MANAGER_ADDRESS,
            IFeeManager::distributeFeesCall {
                validator: Address::ZERO,
                token: PATH_USD_ADDRESS,
            }
            .abi_encode(),
        ),
    ];
    for spec in FEE_SPECS {
        for (target, input) in &inputs {
            let mut db = funded_tip20_db(2);
            contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
            let txs = (0..2)
                .map(|i| {
                    let mut tx = transaction(i, *target, 0, input);
                    tx.inner.gas_price = 1;
                    tx
                })
                .collect::<Vec<_>>();
            let stats = differential_mode(db, &txs, 2, 2, spec, false, (false, true));
            assert_eq!(stats.fees_rebased, 0, "{spec:?}");
            assert_eq!(stats.conflicts, 1, "{spec:?}");
        }
    }
}

#[test]
fn fee_rebasing_replays_intermediate_and_accumulator_overflow() {
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip_fee_manager::TipFeeManager,
        tip20::TIP20Token,
    };
    for spec in FEE_SPECS {
        for maximum_fee_overflow in [false, true] {
            let mut db = funded_tip20_db(2);
            contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
            let txs = (0..2)
                .map(|i| {
                    let mut tx = transaction(i, address(900), 0, &[]);
                    tx.inner.gas_price = if maximum_fee_overflow {
                        1_000_000_000_000
                    } else {
                        1
                    };
                    tx
                })
                .collect::<Vec<_>>();
            if maximum_fee_overflow {
                let slot = TIP20Token::from_address(PATH_USD_ADDRESS).unwrap().balances
                    [TIP_FEE_MANAGER_ADDRESS]
                    .slot();
                let maximum = tempo_primitives::transaction::calc_gas_balance_spending(
                    txs[0].inner.gas_limit,
                    txs[0].inner.gas_price,
                );
                db.insert_account_storage(PATH_USD_ADDRESS, slot, U256::MAX - maximum)
                    .unwrap();
            } else {
                let slot =
                    TipFeeManager::new().collected_fees[Address::ZERO][PATH_USD_ADDRESS].slot();
                db.insert_account_storage(TIP_FEE_MANAGER_ADDRESS, slot, U256::MAX - U256::ONE)
                    .unwrap();
            }
            let stats = differential_mode(db, &txs, 2, 2, spec, false, (false, true));
            assert_eq!(
                stats.fees_rebased, 0,
                "{spec:?}, maximum={maximum_fee_overflow}"
            );
            assert_eq!(
                stats.conflicts, 1,
                "{spec:?}, maximum={maximum_fee_overflow}"
            );
        }
    }
}

#[test]
fn tip20_transfers_track_balances_and_fee_counters() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    for paid in [false, true] {
        let mut db = funded_tip20_db(16);
        contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
        let txs = (0..16)
            .map(|i| {
                let mut tx = transaction(
                    i,
                    PATH_USD_ADDRESS,
                    0,
                    &ITIP20::transferCall {
                        to: address(100 + i),
                        amount: U256::from(17),
                    }
                    .abi_encode(),
                );
                tx.inner.gas_price = u128::from(paid);
                tx
            })
            .collect::<Vec<_>>();
        for spec in [
            TempoHardfork::T0,
            TempoHardfork::T1B,
            TempoHardfork::T3,
            TempoHardfork::T4,
        ] {
            let stats = differential_at_spec(db.clone(), &txs, 4, 16, spec);
            assert_eq!(stats.reused + stats.conflicts + stats.retries, 16);
            if paid {
                assert!(
                    stats.conflicts > 0,
                    "shared fee updates must conflict at {spec:?}"
                );
                assert!(
                    stats.bodies_reused > 0,
                    "independent transfer bodies at {spec:?}"
                );
            } else {
                assert_eq!(stats.reused, 16);
            }
        }
    }
}

#[test]
fn prefetched_aa_nonce_is_revalidated_after_prepare() {
    use alloy_evm::FromRecoveredTx;
    use tempo_precompiles::{NONCE_PRECOMPILE_ADDRESS, nonce::slots, storage::StorageKey};
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};

    let mut db = funded_tip20_db(1);
    let target = address(900);
    contract(&mut db, target, &[0]);
    db.insert_account_info(
        NONCE_PRECOMPILE_ADDRESS,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    let nonce_key = U256::from(13);
    let slot = nonce_key.mapping_slot(address(0).mapping_slot(slots::NONCES));
    let signed = TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        nonce_key,
        calls: vec![Call {
            to: target.into(),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    }
    .into_signed(TempoSignature::default());
    let tx = TempoTxEnv::from_recovered_tx(&signed, address(0));
    let mut sequential = test_evm_with_basefee(db.clone(), 0);
    let mut parallel = test_evm_with_basefee(db, 0);
    parallel.set_speculative_executor(Some(
        SpeculativeExecutor::new(1, 1)
            .unwrap()
            .with_streaming(false),
    ));
    parallel.prepare_transactions([(tx.clone(), Address::ZERO)]);
    // The prefetch/worker sees nonce zero, then an earlier canonical transaction
    // consumes it. The hint must not turn this now-invalid transaction into a commit.
    for evm in [&mut sequential, &mut parallel] {
        evm.db_mut()
            .insert_account_storage(NONCE_PRECOMPILE_ADDRESS, slot, U256::from(1))
            .unwrap();
    }
    let expected = sequential.transact_raw(tx.clone()).unwrap_err();
    let actual = parallel.transact_raw(tx).unwrap_err();
    assert_eq!(expected.to_string(), actual.to_string());
    assert_eq!(parallel.execution_stats().conflicts, 1);
    assert_eq!(parallel.execution_stats().reused, 0);
    assert_eq!(root(sequential.db()), root(parallel.db()));
}

#[test]
fn aa_multi_call_transfers_and_two_dimensional_nonces() {
    use alloy_evm::FromRecoveredTx;
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};
    let db = funded_tip20_db(8);
    let txs = (0..32)
        .map(|i| {
            let sender = i % 8;
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 3_000_000,
                nonce: i / 16,
                nonce_key: U256::from(1 + i / 8 % 2),
                calls: (0..2)
                    .map(|j| Call {
                        to: PATH_USD_ADDRESS.into(),
                        value: U256::ZERO,
                        input: ITIP20::transferCall {
                            to: address(100 + j),
                            amount: U256::from(3),
                        }
                        .abi_encode()
                        .into(),
                    })
                    .collect(),
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            TempoTxEnv::from_recovered_tx(&signed, address(sender))
        })
        .collect::<Vec<_>>();
    for spec in [
        TempoHardfork::T0,
        TempoHardfork::T1B,
        TempoHardfork::T3,
        TempoHardfork::T4,
    ] {
        let stats = differential_at_spec(db.clone(), &txs, 4, 32, spec);
        assert!(stats.conflicts + stats.retries > 0);
        assert!(stats.reused > 0);
    }
}

#[test]
fn sponsored_expiring_nonces_preserve_ring_updates_and_replay_rejection() {
    use alloy_evm::FromRecoveredTx;
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
    };
    let db = funded_tip20_db(8);
    let mut txs = (0..16)
        .map(|i| {
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1,
                nonce_key: TEMPO_EXPIRING_NONCE_KEY,
                valid_before: std::num::NonZeroU64::new(25),
                calls: vec![Call {
                    to: PATH_USD_ADDRESS.into(),
                    value: U256::ZERO,
                    input: ITIP20::transferCall {
                        to: address(100 + i),
                        amount: U256::from(i + 1),
                    }
                    .abi_encode()
                    .into(),
                }],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            let mut env = TempoTxEnv::from_recovered_tx(&signed, address(i % 7));
            // Signature recovery precedes EVM execution. Share one recovered sponsor.
            env.fee_payer = Some(Some(address(7)));
            env
        })
        .collect::<Vec<_>>();
    txs.push(txs[0].clone());
    for spec in [
        TempoHardfork::T1,
        TempoHardfork::T1A,
        TempoHardfork::T1B,
        TempoHardfork::T1C,
        TempoHardfork::T2,
        TempoHardfork::T3,
        TempoHardfork::T4,
    ] {
        let stats = differential_at_spec(db.clone(), &txs, 4, 32, spec);
        assert_eq!(
            stats.reused, 1,
            "first sponsored transaction should execute at {spec:?}"
        );
        assert_eq!(
            stats.conflicts, 16,
            "ring updates and duplicate must replay at {spec:?}"
        );
    }
}

#[test]
fn expiring_nonce_ring_wrap_rechecks_full_and_expired_entries() {
    use alloy_evm::FromRecoveredTx;
    use revm::Database as _;
    use tempo_precompiles::{
        NONCE_PRECOMPILE_ADDRESS,
        nonce::{EXPIRING_NONCE_SET_CAPACITY, slots},
        storage::StorageKey,
    };
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
    };

    let now = revm::context::BlockEnv::default()
        .timestamp
        .saturating_to::<u64>();
    let old_hash = B256::repeat_byte(0xff);
    let target = address(900);
    let txs = (0..3)
        .map(|i: u64| {
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1,
                nonce_key: TEMPO_EXPIRING_NONCE_KEY,
                valid_before: std::num::NonZeroU64::new(now + 25),
                calls: vec![Call {
                    to: target.into(),
                    value: U256::ZERO,
                    input: Bytes::copy_from_slice(&i.to_be_bytes()),
                }],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            TempoTxEnv::from_recovered_tx(&signed, address(i))
        })
        .collect::<Vec<_>>();

    for spec in FEE_SPECS.into_iter().filter(|spec| spec.is_t1()) {
        for expired in [false, true] {
            let mut db = funded_tip20_db(3);
            contract(&mut db, target, &[0]);
            db.insert_account_info(
                NONCE_PRECOMPILE_ADDRESS,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
            for (slot, value) in [
                (
                    slots::EXPIRING_NONCE_RING_PTR,
                    U256::from(EXPIRING_NONCE_SET_CAPACITY - 1),
                ),
                (
                    0u32.mapping_slot(slots::EXPIRING_NONCE_RING),
                    U256::from_be_bytes(old_hash.0),
                ),
                (
                    old_hash.mapping_slot(slots::EXPIRING_NONCE_SEEN),
                    U256::from(if expired { now } else { now + 25 }),
                ),
            ] {
                db.insert_account_storage(NONCE_PRECOMPILE_ADDRESS, slot, value)
                    .unwrap();
            }

            // The first transaction wraps the pointer to slot zero. A frozen
            // worker sees the previously empty final slot for every candidate;
            // ordered replay must check the newly reached entry's expiry.
            let mut canonical = TempoEvm::new(
                db.clone(),
                EvmEnv {
                    cfg_env: revm::context::CfgEnv::new_with_spec_and_gas_params(
                        spec,
                        tempo_revm::gas_params::tempo_gas_params(spec),
                    ),
                    block_env: TempoBlockEnv {
                        inner: revm::context::BlockEnv {
                            basefee: 0,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                },
            );
            let first = canonical.transact_raw(txs[0].clone()).unwrap();
            canonical.db_mut().commit(first.state);
            assert_eq!(
                canonical
                    .db_mut()
                    .storage(NONCE_PRECOMPILE_ADDRESS, slots::EXPIRING_NONCE_RING_PTR)
                    .unwrap(),
                U256::ZERO
            );
            let second = canonical.transact_raw(txs[1].clone());
            if expired {
                let second = second.unwrap();
                canonical.db_mut().commit(second.state);
                assert_eq!(
                    canonical
                        .db_mut()
                        .storage(
                            NONCE_PRECOMPILE_ADDRESS,
                            old_hash.mapping_slot(slots::EXPIRING_NONCE_SEEN)
                        )
                        .unwrap(),
                    U256::ZERO
                );
            } else {
                assert!(
                    matches!(second, Err(EVMError::Transaction(TempoInvalidTransaction::NonceManagerError(ref error))) if error.contains("ExpiringNonceSetFull")),
                    "{spec:?}: {second:?}"
                );
            }

            let stats = differential_at_spec(db, &txs, 3, 3, spec);
            assert_eq!(stats.reused, 1, "{spec:?}, expired={expired}: {stats:?}");
            assert_eq!(stats.conflicts, 2, "{spec:?}, expired={expired}: {stats:?}");
        }
    }
}

#[test]
fn selfdestruct_balance_changes_invalidate_later_reads() {
    let source = address(900);
    let beneficiary = address(901);
    let observer = address(902);
    let mut db = TestDB::default();
    let mut destruct = vec![0x73]; // PUSH20 beneficiary; SELFDESTRUCT
    destruct.extend_from_slice(beneficiary.as_slice());
    destruct.push(0xff);
    contract(&mut db, source, &destruct);
    db.cache.accounts.get_mut(&source).unwrap().info.balance = U256::from(777);
    let mut observe = vec![0x73]; // SSTORE(0, BALANCE(beneficiary))
    observe.extend_from_slice(beneficiary.as_slice());
    observe.extend_from_slice(&[0x31, 0x60, 0, 0x55, 0]);
    contract(&mut db, observer, &observe);
    let stats = differential(
        db,
        &[
            transaction(0, source, 0, &[]),
            transaction(1, observer, 0, &[]),
        ],
        2,
        2,
    );
    assert_eq!(stats.reused, 1);
    assert_eq!(stats.conflicts, 1);
}

#[test]
fn keychain_spending_limits_and_revocation_invalidate_candidates() {
    use alloy_sol_types::SolCall;
    use revm::context_interface::JournalTr;
    use tempo_precompiles::{
        ACCOUNT_KEYCHAIN_ADDRESS, PATH_USD_ADDRESS,
        account_keychain::{
            AccountKeychain, KeyRestrictions, SignatureType, TokenLimit, authorizeKeyCall,
            revokeKeyCall,
        },
        storage::StorageCtx,
        tip20::ITIP20,
    };
    use tempo_primitives::transaction::{
        Call, KeychainSignature, PrimitiveSignature, TempoSignature,
    };
    let caller = address(0);
    let key = address(500);
    for spec in [TempoHardfork::T3, TempoHardfork::T4] {
        let mut setup = test_evm_with_basefee(funded_tip20_db(1), 0);
        setup.ctx_mut().cfg.spec = spec;
        StorageCtx::enter_ctx(setup.ctx_mut(), || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize().unwrap();
            keychain.set_transaction_key(Address::ZERO).unwrap();
            keychain.set_tx_origin(caller).unwrap();
            keychain
                .authorize_key(
                    caller,
                    authorizeKeyCall {
                        keyId: key,
                        signatureType: SignatureType::Secp256k1,
                        config: KeyRestrictions {
                            expiry: u64::MAX,
                            enforceLimits: true,
                            limits: vec![TokenLimit {
                                token: PATH_USD_ADDRESS,
                                amount: U256::from(5),
                                period: 0,
                            }],
                            allowAnyCalls: true,
                            allowedCalls: vec![],
                        },
                    },
                )
                .unwrap();
        });
        let state = setup.ctx_mut().journaled_state.finalize();
        setup.db_mut().commit(state);
        let db = setup.finish().0;
        let keyed = |channel: u64| {
            let input = ITIP20::transferCall {
                to: address(100),
                amount: U256::from(3),
            }
            .abi_encode();
            let mut tx = transaction(0, PATH_USD_ADDRESS, 0, &input);
            tx.tempo_tx_env = Some(Box::new(tempo_revm::TempoBatchCallEnv {
                signature: TempoSignature::Keychain(KeychainSignature::new(
                    caller,
                    PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature()),
                )),
                override_key_id: Some(key),
                nonce_key: U256::from(channel),
                aa_calls: vec![Call {
                    to: PATH_USD_ADDRESS.into(),
                    value: U256::ZERO,
                    input: input.into(),
                }],
                ..Default::default()
            }));
            tx
        };
        let revoke = transaction(
            0,
            ACCOUNT_KEYCHAIN_ADDRESS,
            0,
            &revokeKeyCall { keyId: key }.abi_encode(),
        );
        let stats = differential_at_spec(db, &[keyed(1), keyed(2), revoke, keyed(3)], 4, 4, spec);
        assert!(stats.reused > 0, "the authorized key must execute");
        assert!(
            stats.conflicts >= 2,
            "spending and revocation must cause replay"
        );
    }
}

#[test]
fn paid_call_bodies_reuse_success_revert_and_halt() {
    for ending in [0x00, 0xfd, 0xfe] {
        let mut db = funded_tip20_db(16);
        contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
        let target = address(900);
        // Disjoint write, transient write, LOG0, then success/revert/invalid opcode.
        let mut code = vec![
            0x60, 1, 0x60, 0, 0x35, 0x55, 0x60, 1, 0x60, 0, 0x5d, 0x60, 0, 0x60, 0, 0xa0, 0x60, 0,
            0x60, 0,
        ];
        code.push(ending);
        contract(&mut db, target, &code);
        let txs = (0..16)
            .map(|i| {
                let mut tx = transaction(i, target, 0, &U256::from(i).to_be_bytes::<32>());
                tx.inner.gas_price = 1;
                tx
            })
            .collect::<Vec<_>>();
        for spec in [
            TempoHardfork::T0,
            TempoHardfork::T1B,
            TempoHardfork::T3,
            TempoHardfork::T4,
        ] {
            let stats = differential_at_spec(db.clone(), &txs, 4, 16, spec);
            assert!(
                stats.bodies_reused >= 14,
                "ending={ending:x} spec={spec:?}: {stats:?}"
            );
        }
    }
}

#[test]
fn native_fee_balance_reads_prevent_body_reuse_including_reverts() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, tip20::ITIP20};
    for wrapped in [false, true] {
        let mut db = funded_tip20_db(8);
        contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
        let target = if wrapped {
            address(900)
        } else {
            PATH_USD_ADDRESS
        };
        if wrapped {
            // Read the native fee balance through STATICCALL, then REVERT with its
            // return data. The reverted read must remain a dependency.
            let mut code = vec![
                0x60, 36, 0x60, 0, 0x60, 0, 0x37, 0x60, 32, 0x60, 0, 0x60, 36, 0x60, 0, 0x73,
            ];
            code.extend_from_slice(PATH_USD_ADDRESS.as_slice());
            code.extend_from_slice(&[0x62, 0x0f, 0x42, 0x40, 0xfa, 0x50, 0x60, 32, 0x60, 0, 0xfd]);
            contract(&mut db, target, &code);
        }
        let txs = (0..8)
            .map(|i| {
                let mut tx = transaction(
                    i,
                    target,
                    0,
                    &ITIP20::balanceOfCall {
                        account: TIP_FEE_MANAGER_ADDRESS,
                    }
                    .abi_encode(),
                );
                tx.inner.gas_price = 1;
                tx
            })
            .collect::<Vec<_>>();
        for spec in [
            TempoHardfork::T0,
            TempoHardfork::T1B,
            TempoHardfork::T3,
            TempoHardfork::T4,
        ] {
            let stats = differential_at_spec(db.clone(), &txs, 4, 8, spec);
            assert_eq!(stats.conflicts, 7);
            assert_eq!(stats.bodies_reused, 0, "wrapped={wrapped} spec={spec:?}");
        }
    }
}

#[test]
fn body_replay_preserves_precompile_failure() {
    let mut db = funded_tip20_db(16);
    contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
    // Invalid pairing input halts the transaction rather than returning success.
    let target = Address::with_last_byte(8);
    let txs = (0..16)
        .map(|i| {
            let mut tx = transaction(i, target, 0, &[1]);
            tx.inner.gas_price = 1;
            tx
        })
        .collect::<Vec<_>>();
    let stats = differential(db, &txs, 4, 16);
    assert_eq!(stats.bodies_reused, 15);
}

#[test]
fn expiring_aa_bodies_rebase_nonce_ring_and_atomic_reverts() {
    use alloy_evm::FromRecoveredTx;
    use tempo_primitives::{
        TempoSignature, TempoTransaction,
        transaction::{Call, TEMPO_EXPIRING_NONCE_KEY},
    };
    let mut db = funded_tip20_db(16);
    for native in [
        tempo_precompiles::TIP_FEE_MANAGER_ADDRESS,
        tempo_precompiles::NONCE_PRECOMPILE_ADDRESS,
    ] {
        contract(&mut db, native, &[0]);
    }
    let writer = address(900);
    let reverter = address(901);
    contract(
        &mut db,
        writer,
        &[0x60, 1, 0x60, 0, 0x35, 0x55, 0x60, 0, 0x60, 0, 0xa0, 0],
    );
    contract(&mut db, reverter, &[0x60, 0, 0x60, 0, 0xfd]);
    let mut txs = (0..16)
        .map(|i| {
            let tx = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1,
                nonce_key: TEMPO_EXPIRING_NONCE_KEY,
                valid_before: std::num::NonZeroU64::new(25),
                calls: vec![
                    Call {
                        to: writer.into(),
                        value: U256::ZERO,
                        input: U256::from(i).to_be_bytes::<32>().into(),
                    },
                    Call {
                        to: if i % 2 == 0 { writer } else { reverter }.into(),
                        value: U256::ZERO,
                        input: U256::from(i).to_be_bytes::<32>().into(),
                    },
                ],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            TempoTxEnv::from_recovered_tx(&tx, address(i))
        })
        .collect::<Vec<_>>();
    txs.push(txs[0].clone());
    for spec in [
        TempoHardfork::T1,
        TempoHardfork::T1B,
        TempoHardfork::T3,
        TempoHardfork::T4,
    ] {
        let stats = differential_at_spec(db.clone(), &txs, 4, 32, spec);
        assert_eq!(stats.bodies_reused, 15, "{spec:?}: {stats:?}");
        assert_eq!(
            stats.conflicts, 16,
            "duplicate nonce must still fail at {spec:?}"
        );
    }
}

#[test]
fn body_reuse_does_not_bypass_fee_settlement_overflow() {
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, storage::StorageKey, tip_fee_manager::slots,
    };
    let mut db = funded_tip20_db(2);
    contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
    let collected =
        PATH_USD_ADDRESS.mapping_slot(Address::ZERO.mapping_slot(slots::COLLECTED_FEES));
    db.insert_account_storage(
        TIP_FEE_MANAGER_ADDRESS,
        collected,
        U256::MAX - U256::from(1),
    )
    .unwrap();
    let target = address(900);
    contract(&mut db, target, &[0x60, 1, 0x60, 0, 0x35, 0x55, 0]);
    let txs = (0..2)
        .map(|i| {
            let mut tx = transaction(i, target, 0, &U256::from(i).to_be_bytes::<32>());
            tx.inner.gas_price = 1;
            tx
        })
        .collect::<Vec<_>>();
    let stats = differential(db, &txs, 2, 2);
    assert_eq!(stats.reused, 1);
    assert_eq!(stats.conflicts, 1);
    assert_eq!(stats.bodies_reused, 1);
}

#[test]
fn body_reuse_rechecks_amm_liquidity_and_reservations() {
    use revm::context_interface::JournalTr;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        storage::{ContractStorage, Handler, Mapping, StorageCtx},
        test_util::TIP20Setup,
        tip_fee_manager::{
            amm::{Pool, PoolKey},
            slots,
        },
        tip20::{ITIP20, TIP20Token},
    };
    let mut db = funded_tip20_db(64);
    contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
    let mut setup = test_evm_with_basefee(db, 0);
    let fee_token = StorageCtx::enter_ctx(setup.ctx_mut(), || {
        let mut token =
            TIP20Setup::create("Fee asset", "FEE", address(999)).with_issuer(address(999));
        for i in 0..64 {
            token = token.with_mint(address(i), U256::from(1_000_000_000u64));
        }
        let fee_token = token.apply().unwrap().address();
        TIP20Token::from_address(PATH_USD_ADDRESS)
            .unwrap()
            .mint(
                address(999),
                ITIP20::mintCall {
                    to: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::from(250),
                },
            )
            .unwrap();
        let mut pools = Mapping::<B256, Pool>::new(slots::POOLS, TIP_FEE_MANAGER_ADDRESS);
        pools[PoolKey::new(fee_token, PATH_USD_ADDRESS).get_id()]
            .write(Pool {
                reserve_user_token: 0,
                reserve_validator_token: 250,
            })
            .unwrap();
        fee_token
    });
    let state = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(state);
    let mut db = setup.finish().0;
    let target = address(900);
    contract(&mut db, target, &[0x60, 1, 0x60, 0, 0x35, 0x55, 0]);
    let txs = (0..64)
        .map(|i| {
            let mut tx = transaction(i, target, 0, &U256::from(i).to_be_bytes::<32>());
            tx.inner.gas_price = 100_000_000;
            tx.fee_token = Some(fee_token);
            tx
        })
        .collect::<Vec<_>>();
    for spec in [
        TempoHardfork::T0,
        TempoHardfork::T1B,
        TempoHardfork::T1C,
        TempoHardfork::T4,
    ] {
        let stats = differential_at_spec(db.clone(), &txs, 4, 64, spec);
        assert!(stats.bodies_reused > 0, "{spec:?}: {stats:?}");
        assert!(
            stats.bodies_reused < 63,
            "liquidity must eventually run out at {spec:?}"
        );
    }
}

#[test]
fn reward_changes_rebase_unobserved_slots_and_invalidate_observed_slots() {
    use alloy_sol_types::SolCall;
    use revm::context_interface::JournalTr;
    use tempo_precompiles::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        storage::StorageCtx,
        tip20::{ITIP20, TIP20Token},
    };

    let mut db = funded_tip20_db(16);
    contract(&mut db, TIP_FEE_MANAGER_ADDRESS, &[0]);
    let target = address(900);
    contract(&mut db, target, &[0]);
    let recipient = address(99);
    let mut setup = test_evm_with_basefee(db, 0);
    StorageCtx::enter_ctx(setup.ctx_mut(), || {
        let mut token = TIP20Token::from_address(PATH_USD_ADDRESS).unwrap();
        for i in 0..16 {
            token
                .set_reward_recipient(address(i), ITIP20::setRewardRecipientCall { recipient })
                .unwrap();
        }
        token
            .distribute_reward(
                address(0),
                ITIP20::distributeRewardCall {
                    amount: U256::from(1_000_000),
                },
            )
            .unwrap();
    });
    let state = setup.ctx_mut().journaled_state.finalize();
    setup.db_mut().commit(state);
    let db = setup.finish().0;

    for observe in [false, true] {
        let txs = (0..16)
            .map(|i| {
                let mut tx = if i == 0 {
                    transaction(
                        i,
                        PATH_USD_ADDRESS,
                        0,
                        &ITIP20::distributeRewardCall {
                            amount: U256::from(1_000_000),
                        }
                        .abi_encode(),
                    )
                } else if observe {
                    transaction(
                        i,
                        PATH_USD_ADDRESS,
                        0,
                        &ITIP20::getPendingRewardsCall { account: recipient }.abi_encode(),
                    )
                } else {
                    transaction(i, target, 0, &[])
                };
                tx.inner.gas_price = 1;
                tx
            })
            .collect::<Vec<_>>();
        for spec in [TempoHardfork::T0, TempoHardfork::T1C, TempoHardfork::T4] {
            let stats = differential_at_spec(db.clone(), &txs, 4, 16, spec);
            assert_eq!(stats.conflicts, 15, "{spec:?}: {stats:?}");
            if observe {
                assert_eq!(stats.bodies_reused, 0, "{spec:?}: {stats:?}");
            } else {
                assert_eq!(stats.bodies_reused, 15, "{spec:?}: {stats:?}");
            }
        }
    }
}

#[test]
fn body_replay_preserves_storage_gas_and_warmness() {
    use revm::context::transaction::AccessListItem;
    for warm in [false, true] {
        let mut db = funded_tip20_db(16);
        contract(&mut db, tempo_precompiles::TIP_FEE_MANAGER_ADDRESS, &[0]);
        let target = address(900);
        // SSTORE's gas/refund depends on the old value even without an SLOAD.
        contract(
            &mut db,
            target,
            &[0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 0, 0x54, 0x00],
        );
        let txs = (0..16)
            .map(|i| {
                let mut tx = transaction(i, target, 0, &U256::from(i % 3).to_be_bytes::<32>());
                tx.inner.gas_price = 1;
                if warm {
                    tx.inner.access_list.0.push(AccessListItem {
                        address: target,
                        storage_keys: vec![B256::ZERO],
                    });
                }
                tx
            })
            .collect::<Vec<_>>();
        for spec in [
            TempoHardfork::T0,
            TempoHardfork::T1B,
            TempoHardfork::T3,
            TempoHardfork::T4,
        ] {
            differential_at_spec(db.clone(), &txs, 4, 16, spec);
        }
    }
}

/// In-memory execution benchmark. This includes scheduling, read validation, replay,
/// receipt construction and commits, but excludes signing, networking and trie hashing.
/// Run with `cargo test -p tempo-evm --release execution_throughput -- --ignored --nocapture`.
#[test]
#[ignore]
fn execution_throughput() {
    use alloy_evm::FromRecoveredTx;
    use alloy_sol_types::SolCall;
    use std::time::Instant;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};
    let counts =
        std::env::var("TEMPO_BENCH_COUNTS").unwrap_or_else(|_| "10000,25000,50000,100000".into());
    let workers = std::env::var("TEMPO_BENCH_WORKERS").unwrap_or_else(|_| "0,1,4,16,32".into());
    let workloads = std::env::var("TEMPO_BENCH_WORKLOADS")
        .unwrap_or_else(|_| "storage,compute,compute_paid,tip20,tip20_paid".into());
    let batch_size = std::env::var("TEMPO_BENCH_BATCH_SIZE")
        .map_or(128, |value| value.parse::<usize>().unwrap());
    let profile = std::env::var_os("TEMPO_BENCH_PHASES").is_some();
    let streaming = std::env::var("TEMPO_BENCH_STREAMING").map_or(true, |value| value != "0");
    let fee_rebasing = std::env::var("TEMPO_BENCH_FEE_REBASING").map_or(true, |value| value != "0");
    let chained = std::env::var("TEMPO_BENCH_CHAINED").map_or(true, |value| value != "0");
    println!(
        "workload\ttransactions\tworkers\tseconds\ttps\treused\tconflicts\tretries\tbackoff\tbodies_reused\tfees_rebased"
    );
    for count in counts.split(',').map(|s| s.parse::<u64>().unwrap()) {
        for workload in workloads.split(',') {
            assert!(matches!(
                workload,
                "storage"
                    | "compute"
                    | "compute_paid"
                    | "compute_paid_chains"
                    | "tip20"
                    | "tip20_paid"
                    | "tip20_paid_aa"
            ));
            let users = if matches!(workload, "compute_paid_chains" | "tip20_paid_aa") {
                100
            } else {
                count
            };
            let mut db = if matches!(workload, "storage" | "compute") {
                TestDB::default()
            } else {
                funded_tip20_db(users)
            };
            let target = address(count + 900);
            if workload == "storage" {
                contract(&mut db, target, &[0x60, 0x20, 0x35, 0x60, 0, 0x35, 0x55, 0]);
            }
            if workload.starts_with("compute") {
                // 500 KECCAK256 iterations per transaction.
                contract(
                    &mut db,
                    target,
                    &[
                        0x61, 0x01, 0xf4, 0x5b, 0x60, 0x20, 0x60, 0, 0x20, 0x50, 0x60, 1, 0x90,
                        0x03, 0x80, 0x60, 3, 0x57, 0x50, 0,
                    ],
                );
            }
            let txs = (0..count)
                .map(|i| {
                    if workload == "tip20_paid_aa" {
                        let signed = TempoTransaction {
                            chain_id: 1,
                            gas_limit: 1_000_000,
                            max_fee_per_gas: 1,
                            max_priority_fee_per_gas: 1,
                            nonce_key: U256::from(1 + i / users),
                            calls: vec![Call {
                                to: PATH_USD_ADDRESS.into(),
                                value: U256::ZERO,
                                input: ITIP20::transferCall {
                                    to: address(count + 1000 + i),
                                    amount: U256::from(17),
                                }
                                .abi_encode()
                                .into(),
                            }],
                            ..Default::default()
                        }
                        .into_signed(TempoSignature::default());
                        TempoTxEnv::from_recovered_tx(&signed, address(i % users))
                    } else if workload.starts_with("compute") {
                        let mut tx = transaction(i % users, target, i / users, &[]);
                        tx.inner.gas_price = u128::from(workload.starts_with("compute_paid"));
                        tx
                    } else if workload == "storage" {
                        let mut input = U256::from(i).to_be_bytes::<32>().to_vec();
                        input.extend_from_slice(&U256::from(i + 1).to_be_bytes::<32>());
                        transaction(i, target, 0, &input)
                    } else {
                        let mut tx = transaction(
                            i,
                            PATH_USD_ADDRESS,
                            0,
                            &ITIP20::transferCall {
                                to: address(count + 1000 + i),
                                amount: U256::from(17),
                            }
                            .abi_encode(),
                        );
                        tx.inner.gas_price = u128::from(workload == "tip20_paid");
                        tx
                    }
                })
                .collect::<Vec<_>>();
            let mut baseline = None;
            for threads in workers.split(',').map(|s| s.parse::<usize>().unwrap()) {
                let mut evm = test_evm_with_basefee(db.clone(), 0);
                evm.ctx_mut().block.gas_limit = 500_000_000;
                if threads > 0 {
                    evm.set_speculative_executor(Some(
                        SpeculativeExecutor::new(threads, batch_size)
                            .unwrap()
                            .with_streaming(streaming)
                            .with_fee_rebasing(fee_rebasing)
                            .with_chained_workers(chained),
                    ));
                }
                let mut receipts = Vec::with_capacity(txs.len());
                let mut cumulative_gas = 0;
                let mut phases = [Duration::ZERO; 3];
                let start = Instant::now();
                for batch in txs.chunks(batch_size) {
                    let preparation_start = profile.then(Instant::now);
                    if threads > 0 {
                        evm.prepare_transactions(
                            batch.iter().cloned().map(|tx| (tx, Address::ZERO)),
                        );
                    }
                    if let Some(start) = preparation_start {
                        phases[0] += start.elapsed();
                    }
                    for tx in batch {
                        let execution_start = profile.then(Instant::now);
                        let result = evm.transact_raw(tx.clone()).unwrap();
                        if let Some(start) = execution_start {
                            phases[1] += start.elapsed();
                        }
                        assert!(result.result.is_success());
                        cumulative_gas += result.result.tx_gas_used();
                        receipts.push(tempo_primitives::TempoReceipt {
                            tx_type: tx.inner.tx_type.try_into().unwrap(),
                            success: true,
                            cumulative_gas_used: cumulative_gas,
                            logs: result.result.into_logs(),
                        });
                        let commit_start = profile.then(Instant::now);
                        evm.db_mut().commit(result.state);
                        if let Some(start) = commit_start {
                            phases[2] += start.elapsed();
                        }
                    }
                }
                let elapsed = start.elapsed().as_secs_f64();
                let stats = evm.execution_stats();
                if profile {
                    eprintln!(
                        "PHASES workload={workload} count={count} workers={threads} batch={batch_size} prepare={:.6} ordered={:.6} commit={:.6}",
                        phases[0].as_secs_f64(),
                        phases[1].as_secs_f64(),
                        phases[2].as_secs_f64()
                    );
                }
                let output = (root(evm.db()), receipts);
                if let Some(baseline) = &baseline {
                    assert_eq!(&output, baseline);
                } else {
                    baseline = Some(output);
                }
                println!(
                    "{workload}\t{count}\t{threads}\t{elapsed:.6}\t{:.0}\t{}\t{}\t{}\t{}\t{}\t{}",
                    count as f64 / elapsed,
                    stats.reused,
                    stats.conflicts,
                    stats.retries,
                    stats.backoff,
                    stats.bodies_reused,
                    stats.fees_rebased
                );
            }
        }
    }
}

#[test]
fn block_executor_preserves_receipts_state_hooks_and_gas_limits() {
    use crate::test_utils::{TestExecutorBuilder, test_chainspec};
    use alloy_consensus::{Signed, TxLegacy};
    use alloy_evm::block::BlockExecutor;
    use alloy_primitives::Signature;
    use reth_primitives_traits::{Recovered, SignedTransaction};
    use std::sync::Mutex;
    use tempo_primitives::TempoTxEnvelope;

    let txs = (0..8)
        .map(|i| {
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    gas_limit: 100_000,
                    gas_price: 1,
                    to: address(100 + i).into(),
                    ..Default::default()
                },
                Signature::test_signature(),
            ))
        })
        .collect::<Vec<_>>();
    let recovered = txs
        .iter()
        .map(|tx| Recovered::new_unchecked(tx, tx.try_recover().unwrap()))
        .collect::<Vec<_>>();
    let db = funded_tip20_accounts(recovered.iter().map(|tx| tx.signer()));
    let spec = test_chainspec();
    let mut expected_output = None;
    for parallel in [false, true] {
        let mut executor = TestExecutorBuilder::default()
            .with_parent_beacon_block_root(B256::ZERO)
            .build_with_transactions(db.clone(), &spec, &txs);
        if parallel {
            executor
                .evm_mut()
                .set_speculative_executor(Some(SpeculativeExecutor::new(4, 4).unwrap()));
        }
        let changes = Arc::new(Mutex::new(Vec::new()));
        let captured = changes.clone();
        executor.set_state_hook(Some(Box::new(
            move |source, state: &reth_revm::state::EvmState| {
                captured
                    .lock()
                    .unwrap()
                    .push((format!("{source:?}"), state.clone()));
            },
        )));
        executor.apply_pre_execution_changes().unwrap();
        for tx in &recovered {
            executor.execute_transaction(tx).unwrap();
        }
        if parallel {
            assert!(executor.evm().execution_stats().reused > 0);
        }
        let (evm, result) = executor.finish().unwrap();
        let output = (root(evm.db()), result, changes.lock().unwrap().clone());
        if let Some(expected) = &expected_output {
            assert_eq!(&output, expected);
        } else {
            expected_output = Some(output);
        }
    }
}

#[test]
fn custom_precompiles_and_inspection_disable_speculation() {
    let mut evm = test_evm_with_basefee(TestDB::default(), 0);
    evm.set_speculative_executor(Some(SpeculativeExecutor::new(2, 2).unwrap()));
    evm.set_inspector_enabled(true);
    assert_eq!(evm.speculative_batch_size(), 0);
    evm.set_inspector_enabled(false);
    assert_eq!(evm.speculative_batch_size(), 2);
    let _ = evm.precompiles_mut();
    assert_eq!(evm.speculative_batch_size(), 0);
}

#[test]
fn changed_configuration_keeps_the_original_evm_components() {
    let mut evm = test_evm_with_basefee(TestDB::default(), 0);
    evm.set_speculative_executor(Some(SpeculativeExecutor::new(2, 8).unwrap()));
    // The existing EVM still has its original instruction/precompile tables.
    evm.ctx_mut().cfg.spec = TempoHardfork::T4;
    evm.prepare_transactions([(transaction(0, address(100), 0, &[]), Address::ZERO)]);
    assert_eq!(evm.execution_stats().speculated, 0);
}

#[test]
fn speculative_windows_are_bounded_by_declared_gas() {
    let mut parallel = test_evm_with_basefee(TestDB::default(), 0);
    parallel.ctx_mut().block.gas_limit = 1_000_000;
    parallel.set_speculative_executor(Some(SpeculativeExecutor::new(2, 8).unwrap()));
    let mut sequential = test_evm_with_basefee(TestDB::default(), 0);
    sequential.ctx_mut().block.gas_limit = 1_000_000;
    let txs = (0..3)
        .map(|i| {
            let mut tx = transaction(i, address(100), 0, &[]);
            tx.inner.gas_limit = 600_000;
            tx
        })
        .collect::<Vec<_>>();
    parallel.prepare_transactions(txs.iter().cloned().map(|tx| (tx, Address::ZERO)));
    assert_eq!(parallel.execution_stats().speculated, 1);
    for tx in txs {
        let expected = sequential.transact_raw(tx.clone()).unwrap();
        let actual = parallel.transact_raw(tx).unwrap();
        assert_eq!(actual, expected);
        sequential.db_mut().commit(expected.state);
        parallel.db_mut().commit(actual.state);
    }
    assert_eq!(root(parallel.db()), root(sequential.db()));
}

#[test]
fn subblock_fee_failures_preserve_nonce_only_commits() {
    use alloy_evm::FromRecoveredTx;
    use tempo_precompiles::PATH_USD_ADDRESS;
    use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};
    let db = funded_tip20_db(8);
    let txs = (0..8)
        .map(|i| {
            let signed = TempoTransaction {
                chain_id: 1,
                gas_limit: 1_000_000,
                max_fee_per_gas: 1_000_000_000_000_000_000,
                fee_token: Some(PATH_USD_ADDRESS),
                nonce_key: U256::from(1),
                calls: vec![Call {
                    to: address(100).into(),
                    value: U256::ZERO,
                    input: Bytes::new(),
                }],
                ..Default::default()
            }
            .into_signed(TempoSignature::default());
            let mut env = TempoTxEnv::from_recovered_tx(&signed, address(i));
            env.tempo_tx_env.as_mut().unwrap().subblock_transaction = true;
            env
        })
        .collect::<Vec<_>>();
    for spec in [TempoHardfork::T0, TempoHardfork::T1B, TempoHardfork::T4] {
        let stats = differential_at_spec(db.clone(), &txs, 4, 8, spec);
        assert!(
            stats.reused > 0,
            "caught fee failures produce reusable outcomes at {spec:?}"
        );
        // The first transaction can create the shared native nonce account; later
        // candidates must then replay even though their nonce slots are disjoint.
        assert_eq!(stats.reused + stats.conflicts, 8);
        assert_eq!(
            stats.retries, 0,
            "fee failures are caught subblock halts, not transaction errors"
        );
    }
}

#[test]
fn contract_creation_invalidates_later_code_reads() {
    let creator = address(1);
    let created = creator.create(0);
    let mut create = transaction(1, Address::ZERO, 0, &[]);
    create.inner.kind = TxKind::Create;
    // Initcode returns `PUSH1 7 PUSH1 0 SSTORE STOP` as deployed runtime.
    create.inner.data = Bytes::from_static(&[
        0x60, 6, 0x60, 12, 0x60, 0, 0x39, 0x60, 6, 0x60, 0, 0xf3, 0x60, 7, 0x60, 0, 0x55, 0,
    ]);
    let txs = [
        create,
        transaction(2, created, 0, &[]),
        transaction(1, created, 1, &[]),
    ];
    let stats = differential(TestDB::default(), &txs, 3, 3);
    assert_eq!(stats.reused, 1);
    assert_eq!(stats.conflicts, 1);
    assert_eq!(stats.retries, 1);
}

#[test]
fn transient_storage_is_reset_between_worker_transactions() {
    let mut db = TestDB::default();
    let target = address(900);
    // Return the old transient value, then set it to one. It must be zero for every tx.
    contract(
        &mut db,
        target,
        &[
            0x60, 0, 0x5c, 0x60, 0, 0x52, 0x60, 1, 0x60, 0, 0x5d, 0x60, 32, 0x60, 0, 0xf3,
        ],
    );
    let txs = (0..32)
        .map(|i| transaction(i, target, 0, &[]))
        .collect::<Vec<_>>();
    let stats = differential(db, &txs, 2, 32);
    assert_eq!(stats.reused, 32);
}

#[derive(Debug)]
struct LocalDatabase {
    inner: TestDB,
    // Makes this database !Send and !Sync, like a thread-bound provider transaction.
    _thread_bound: std::rc::Rc<()>,
    panic_on_storage: bool,
    storage_error: Option<Address>,
}

#[derive(Debug, thiserror::Error)]
#[error("injected storage failure")]
struct LocalDatabaseError;
impl DBErrorMarker for LocalDatabaseError {}

impl revm::Database for LocalDatabase {
    type Error = LocalDatabaseError;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(revm::Database::basic(&mut self.inner, address).unwrap())
    }
    fn storage(&mut self, account: Address, slot: U256) -> Result<U256, Self::Error> {
        // Fail on the worker's contract read, after fee prefetching has finished.
        assert!(
            !(self.panic_on_storage && account == address(900)),
            "injected provider panic"
        );
        if self.storage_error == Some(account) {
            return Err(LocalDatabaseError);
        }
        Ok(revm::Database::storage(&mut self.inner, account, slot).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(revm::Database::code_by_hash(&mut self.inner, hash).unwrap())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(revm::Database::block_hash(&mut self.inner, number).unwrap())
    }
}

#[test]
fn thread_bound_database_and_provider_unwind() {
    for panic_on_storage in [false, true] {
        let mut db = LocalDatabase {
            inner: TestDB::default(),
            _thread_bound: Default::default(),
            panic_on_storage,
            storage_error: None,
        };
        let target = address(900);
        contract(&mut db.inner, target, &[0x60, 0, 0x54, 0]);
        let pool = SpeculativeExecutor::new(4, 4).unwrap();
        let mut evm = test_evm_with_basefee(db, 0);
        evm.set_speculative_executor(Some(pool));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evm.prepare_transactions(
                (0..4).map(|i| (transaction(i, target, 0, &[]), Address::ZERO)),
            );
            let result = evm.transact_raw(transaction(0, target, 0, &[])).unwrap();
            assert!(result.result.is_success());
            assert_eq!(evm.execution_stats().reused, 1);
        }));
        assert_eq!(outcome.is_err(), panic_on_storage);
    }
}

#[test]
fn streaming_returns_before_later_reads_and_joins_cancelled_workers() {
    let mut db = LocalDatabase {
        inner: TestDB::default(),
        _thread_bound: Default::default(),
        panic_on_storage: true,
        storage_error: None,
    };
    let first = address(901);
    let later = address(900);
    contract(&mut db.inner, first, &[0]);
    contract(&mut db.inner, later, &[0x60, 0, 0x54, 0]);
    let (_, env) = test_evm_with_basefee(TestDB::default(), 0).finish();
    let tx = transaction(0, first, 0, &[]);
    let pool = SpeculativeExecutor::new(1, 2).unwrap();
    let mut batch = pool.speculate(
        &mut db,
        vec![
            (tx.clone(), env.clone()),
            (transaction(1, later, 0, &[]), env),
        ],
    );
    let shared = Arc::downgrade(&batch.shared);
    // The batch must also complete after the last executor handle is dropped.
    drop(pool);
    assert!(
        batch
            .take(&tx, &mut db)
            .unwrap()
            .result
            .unwrap()
            .result
            .is_success()
    );
    // A single worker sends the first result before asking for the second body's
    // storage. Neither taking that result nor abandoning the batch may read it.
    drop(batch);
    assert!(
        shared.upgrade().is_none(),
        "cancelled worker still owns batch state"
    );
}

#[test]
fn provider_errors_retry_on_the_owning_thread() {
    use alloy_sol_types::SolCall;
    use tempo_precompiles::{PATH_USD_ADDRESS, tip20::ITIP20};
    for target in [address(900), PATH_USD_ADDRESS] {
        let mut db = funded_tip20_db(1);
        let tx = if target == PATH_USD_ADDRESS {
            transaction(
                0,
                target,
                0,
                &ITIP20::transferCall {
                    to: address(901),
                    amount: U256::ONE,
                }
                .abi_encode(),
            )
        } else {
            contract(&mut db, target, &[0x60, 0, 0x54, 0]);
            transaction(0, target, 0, &[])
        };
        let failing = |inner| LocalDatabase {
            inner,
            _thread_bound: Default::default(),
            panic_on_storage: false,
            storage_error: Some(target),
        };
        let mut sequential = test_evm_with_basefee(failing(db.clone()), 0);
        let mut parallel = test_evm_with_basefee(failing(db), 0);
        parallel.set_speculative_executor(Some(SpeculativeExecutor::new(2, 2).unwrap()));
        parallel.prepare_transactions([(tx.clone(), Address::ZERO)]);
        assert_eq!(
            parallel.transact_raw(tx.clone()).unwrap_err().to_string(),
            sequential.transact_raw(tx).unwrap_err().to_string(),
        );
        assert_eq!(parallel.execution_stats().retries, 1);
        assert_eq!(parallel.execution_stats().reused, 0);
    }
}

#[test]
fn streaming_mixed_prefix_reads_force_replay() {
    let target = address(900);
    let mut db = TestDB::default();
    // Return (storage[0], address(this).balance), combining an on-demand storage
    // read with prefetched account metadata.
    contract(
        &mut db,
        target,
        &[
            0x60, 0, 0x54, 0x60, 0, 0x52, 0x30, 0x31, 0x60, 32, 0x52, 0x60, 64, 0x60, 0, 0xf3,
        ],
    );
    let tx = transaction(0, target, 0, &[]);
    let mut evm = test_evm_with_basefee(db, 0);
    evm.set_speculative_executor(Some(SpeculativeExecutor::new(1, 1).unwrap()));
    evm.prepare_transactions([(tx.clone(), Address::ZERO)]);
    let mut info = revm::Database::basic(evm.db_mut(), target)
        .unwrap()
        .unwrap();
    info.balance = U256::from(17);
    evm.db_mut().insert_account_info(target, info);
    evm.db_mut()
        .insert_account_storage(target, U256::ZERO, U256::from(9))
        .unwrap();
    let mut sequential = test_evm_with_basefee(evm.db().clone(), 0);
    assert_eq!(
        evm.transact_raw(tx.clone()).unwrap(),
        sequential.transact_raw(tx).unwrap()
    );
    assert_eq!(evm.execution_stats().conflicts, 1);
    assert_eq!(evm.execution_stats().reused, 0);
}

#[test]
fn worker_panic_releases_other_workers_waiting_for_reads() {
    let (_, env) = test_evm_with_basefee(TestDB::default(), 0).finish();
    let tx = transaction(0, address(900), 0, &[]);
    let shared = Arc::new(Work {
        inputs: vec![(tx.clone(), env)],
        prefetched: HashMap::default(),
        cache: RwLock::default(),
        next: AtomicUsize::new(0),
        cancelled: AtomicBool::new(false),
    });
    let (sender, receiver) = mpsc::channel();
    // Deliver a worker failure before another worker's outstanding read.
    sender
        .send(Message::Stopped(Some(Box::new("worker failure"))))
        .unwrap();
    let worker = std::thread::spawn(move || {
        let (reply, receive) = mpsc::sync_channel(1);
        sender
            .send(Message::Read(
                ReadKey::Storage(address(900), U256::ZERO),
                reply,
            ))
            .unwrap();
        assert!(receive.recv().is_err());
        sender.send(Message::Stopped(None)).unwrap();
    });
    let mut batch = SpeculativeBatch {
        shared,
        receiver,
        outputs: vec![None],
        cursor: 0,
        workers: 2,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        batch.take(&tx, &mut TestDB::default());
    }));
    assert_eq!(
        *result.unwrap_err().downcast::<&str>().unwrap(),
        "worker failure"
    );
    drop(batch);
    worker.join().unwrap();
}
