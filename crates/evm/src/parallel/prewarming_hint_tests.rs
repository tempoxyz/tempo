//! The SDK hint may omit payloads; the ordered candidate must retain them.

use super::*;
use crate::{TempoReceiptBuilder, evm::TempoEvmFactory};
use alloy_evm::{
    EvmFactory,
    eth::receipt_builder::{ReceiptBuilder, ReceiptBuilderCtx},
};
use alloy_primitives::{Bytes, Log, TxKind};
use alloy_trie::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use reth_trie::MultiProofTargetsV2;
use revm::{
    context::{
        CfgEnv, TxEnv,
        result::{ResultGas, SuccessReason},
    },
    database::EmptyDB,
    state::EvmState,
};
use std::{collections::BTreeMap, convert::Infallible};
use tempo_primitives::{TempoReceipt, TempoTxType};
use tempo_revm::ExecutionContext;

type TestDB = CacheDB<EmptyDB>;
type TargetKey = (B256, Option<usize>);

#[derive(Debug, PartialEq, Eq)]
struct ProofTargets {
    accounts: Vec<TargetKey>,
    storage: BTreeMap<B256, Vec<TargetKey>>,
    storage_count: usize,
}

fn proof_targets(state: EvmState) -> ProofTargets {
    let (targets, storage_count) = MultiProofTargetsV2::from_state(state);
    let mut accounts = targets
        .account_targets
        .into_iter()
        .map(|target| (target.key(), target.parent.path_len()))
        .collect::<Vec<_>>();
    accounts.sort_unstable();
    let storage = targets
        .storage_targets
        .into_iter()
        .map(|(address, targets)| {
            let mut slots = targets
                .into_iter()
                .map(|target| (target.key(), target.parent.path_len()))
                .collect::<Vec<_>>();
            slots.sort_unstable();
            (address, slots)
        })
        .collect();
    ProofTargets {
        accounts,
        storage,
        storage_count,
    }
}

fn fixture(create: bool, end: u8) -> (TestDB, Env, TempoTxEnv) {
    let target = Address::with_last_byte(100);
    // Write storage and memory, emit one topic with 32 data bytes, then return,
    // revert, or halt. For CREATE this same bytecode is the init code.
    let code = Bytes::from(vec![
        0x60, 1, 0x60, 0, 0x55, 0x60, 0x2a, 0x60, 0, 0x52, 0x60, 7, 0x60, 32, 0x60, 0, 0xa1, 0x60,
        32, 0x60, 0, end,
    ]);
    let mut db = TestDB::default();
    if !create {
        db.insert_account_info(
            target,
            AccountInfo::default().with_code(Bytecode::new_raw(code.clone())),
        );
    }
    let env = Env {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T0,
            tempo_revm::gas_params::tempo_gas_params(TempoHardfork::T0),
        ),
        block_env: TempoBlockEnv {
            inner: revm::context::BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller: Address::with_last_byte(101),
            kind: if create {
                TxKind::Create
            } else {
                TxKind::Call(target)
            },
            data: if create { code } else { Bytes::new() },
            gas_limit: 1_000_000,
            gas_price: 0,
            ..Default::default()
        },
        execution_context: ExecutionContext::Transaction {
            tx_hash: B256::with_last_byte(1),
        },
        ..Default::default()
    };
    (db, env, tx)
}

fn receipt(evm: &TempoEvm<TestDB>, result: &ResultAndState<TempoHaltReason>) -> TempoReceipt {
    TempoReceiptBuilder.build_receipt(ReceiptBuilderCtx {
        tx_type: TempoTxType::Legacy,
        evm,
        result: result.result.clone(),
        state: &result.state,
        cumulative_gas_used: result.result.tx_gas_used(),
    })
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

#[test]
fn hint_projection_preserves_variants_gas_create_address_and_proof_targets() {
    let gas = ResultGas::new_with_state_gas(45_000, 4_321, 25_000, 1_234);
    let logs = vec![Log::new_unchecked(
        Address::with_last_byte(9),
        vec![B256::with_last_byte(10), B256::with_last_byte(11)],
        Bytes::from(vec![12; 64]),
    )];
    let output = Bytes::from(vec![13; 1024]);
    let created = Address::with_last_byte(14);
    let reason = TempoHaltReason::PrecompileErrorWithContext("retained halt reason".into());
    let cases = [
        (
            ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas,
                logs: logs.clone(),
                output: Output::Call(output.clone()),
            },
            ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas,
                logs: vec![],
                output: Output::Call(Bytes::new()),
            },
        ),
        (
            ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas,
                logs: logs.clone(),
                output: Output::Create(output.clone(), Some(created)),
            },
            ExecutionResult::Success {
                reason: SuccessReason::Return,
                gas,
                logs: vec![],
                output: Output::Create(Bytes::new(), Some(created)),
            },
        ),
        (
            ExecutionResult::Success {
                reason: SuccessReason::Stop,
                gas,
                logs: logs.clone(),
                output: Output::Create(output.clone(), None),
            },
            ExecutionResult::Success {
                reason: SuccessReason::Stop,
                gas,
                logs: vec![],
                output: Output::Create(Bytes::new(), None),
            },
        ),
        (
            ExecutionResult::Revert {
                gas,
                logs: logs.clone(),
                output,
            },
            ExecutionResult::Revert {
                gas,
                logs: vec![],
                output: Bytes::new(),
            },
        ),
        (
            ExecutionResult::Halt {
                reason: reason.clone(),
                gas,
                logs,
            },
            ExecutionResult::Halt {
                reason,
                gas,
                logs: vec![],
            },
        ),
    ];
    for (full_result, expected_hint) in cases {
        let (db, env, tx) = fixture(false, 0xf3);
        let evm = TempoEvm::new(db.clone(), env.clone());
        let mut candidate = PrewarmingExecutor::new(db, env)
            .execute(tx.clone(), None)
            .unwrap();
        candidate.result.result = full_result;
        let before = candidate.result.clone();
        let before_receipt = receipt(&evm, &before);
        let expected_targets = proof_targets(before.state.clone());
        assert!(!expected_targets.accounts.is_empty());
        assert!(!expected_targets.storage.is_empty());
        assert!(expected_targets.storage_count > 0);

        let mut hint = candidate.prewarming_hint_result();
        assert_eq!(hint.result, expected_hint);
        let hint_logs = match &hint.result {
            ExecutionResult::Success { logs, .. }
            | ExecutionResult::Revert { logs, .. }
            | ExecutionResult::Halt { logs, .. } => logs,
        };
        assert_eq!(hint_logs.capacity(), 0);
        assert_eq!(hint.state, before.state);
        assert_eq!(proof_targets(hint.state.clone()), expected_targets);
        assert_eq!(candidate.result, before);
        assert_eq!(receipt(&evm, &candidate.result), before_receipt);

        // The consumer owns its state independently of publication and reuse.
        hint.state.clear();
        assert_eq!(candidate.result, before);
        let retained = candidate
            .into_candidate::<Infallible>(&tx)
            .unwrap()
            .result
            .unwrap();
        assert_eq!(retained, before);
        assert_eq!(receipt(&evm, &retained), before_receipt);
    }
}

#[test]
fn engine_hint_projection_keeps_full_canonical_results_receipts_and_roots() {
    for (create, end) in [(false, 0xf3), (true, 0xf3), (false, 0xfd), (false, 0xfe)] {
        let (db, env, tx) = fixture(create, end);
        let cache = EnginePrewarmingCache::default();
        let session = cache.begin(env.clone(), [B256::with_last_byte(1)]).unwrap();
        let factory = TempoEvmFactory {
            engine_prewarming: Some(cache),
        };
        let mut relaxed = env.clone();
        relaxed.cfg_env.disable_nonce_check = true;
        relaxed.cfg_env.disable_balance_check = true;
        let mut worker = factory.create_evm(db.clone(), relaxed);
        let mut canonical = TempoEvm::new(db.clone(), env.clone());
        let mut actual = factory.create_evm(db, env);
        actual.set_speculative_executor(Some(SpeculativeExecutor::new(1, 128).unwrap()));

        let hint = worker.transact_raw(tx.clone()).unwrap();
        let expected = canonical.transact_raw(tx.clone()).unwrap();
        assert_eq!(hint.state, expected.state);
        assert_eq!(
            proof_targets(hint.state),
            proof_targets(expected.state.clone())
        );
        assert!(hint.result.logs().is_empty());
        match (&hint.result, &expected.result) {
            (
                ExecutionResult::Success {
                    reason,
                    gas,
                    output,
                    ..
                },
                ExecutionResult::Success {
                    reason: expected_reason,
                    gas: expected_gas,
                    output: expected_output,
                    logs,
                },
            ) => {
                assert_eq!(reason, expected_reason);
                assert_eq!(gas, expected_gas);
                assert!(output.data().is_empty());
                assert_eq!(output.address(), expected_output.address());
                assert_eq!(matches!(output, Output::Create(..)), create);
                assert_eq!(expected_output.data().len(), 32);
                assert_eq!(logs.len(), 1);
                assert_eq!(logs[0].data.data.len(), 32);
                assert_eq!(logs[0].data.topics().len(), 1);
            }
            (
                ExecutionResult::Revert { gas, output, .. },
                ExecutionResult::Revert {
                    gas: expected_gas,
                    output: expected_output,
                    ..
                },
            ) => {
                assert_eq!(gas, expected_gas);
                assert!(output.is_empty());
                assert_eq!(expected_output.len(), 32);
                assert_eq!(end, 0xfd);
            }
            (
                ExecutionResult::Halt { reason, gas, .. },
                ExecutionResult::Halt {
                    reason: expected_reason,
                    gas: expected_gas,
                    ..
                },
            ) => {
                assert_eq!(reason, expected_reason);
                assert_eq!(gas, expected_gas);
                assert_eq!(end, 0xfe);
            }
            pair => panic!("hint changed the result variant: {pair:?}"),
        }

        let observed = actual.transact_raw(tx).unwrap();
        assert_eq!(observed, expected);
        assert_eq!(actual.validator_fee(), canonical.validator_fee());
        assert_eq!(actual.execution_stats().reused, 1);
        assert_eq!(receipt(&actual, &observed), receipt(&canonical, &expected));
        actual.db_mut().commit(observed.state);
        canonical.db_mut().commit(expected.state);
        assert_eq!(root(actual.db()), root(canonical.db()));
        drop(session);
    }
}
