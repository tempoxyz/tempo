//! Partial proof hints are bounded and advisory, with no database access in the hook.

use super::*;
use alloy_evm::{Evm, FromRecoveredTx};
use alloy_primitives::{B256, Bytes, TxKind, U256, map::HashSet};
use alloy_sol_types::SolCall;
use reth_evm::ProofKeyHint;
use revm::{
    Database, DatabaseCommit,
    context::{BlockEnv, CfgEnv, JournalTr},
    database::{CacheDB, EmptyDB},
    state::{AccountInfo, Bytecode},
};
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS, PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
    nonce::slots as nonce_slots,
    storage::{StorageCtx, StorageKey},
    test_util::TIP20Setup,
    tip20::{ITIP20, slots as token_slots},
};
use tempo_primitives::{TempoSignature, TempoTransaction, transaction::Call};
use tempo_revm::ExecutionContext;

type TestDB = CacheDB<EmptyDB>;

fn address(index: u64) -> Address {
    Address::from_word(B256::from(U256::from(index + 0x1_0000)))
}

fn env() -> EvmEnvFor<TempoEvmConfig> {
    let spec = TempoHardfork::T14;
    EvmEnv {
        cfg_env: CfgEnv::new_with_spec_and_gas_params(
            spec,
            tempo_revm::gas_params::tempo_gas_params(spec),
        ),
        block_env: TempoBlockEnv {
            inner: BlockEnv {
                basefee: 0,
                gas_limit: 30_000_000,
                timestamp: U256::from(10),
                ..Default::default()
            },
            ..Default::default()
        },
    }
}

fn config() -> TempoEvmConfig {
    TempoEvmConfig::moderato()
        .with_speculative_executor(
            parallel::SpeculativeExecutor::new(1, 128)
                .unwrap()
                .with_proof_prefetch(true),
        )
        .with_engine_prewarming()
}

fn paid_aa(nonce_key: U256) -> TempoTxEnv {
    let tx = TempoTransaction {
        chain_id: 1,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        nonce_key,
        valid_before: NonZeroU64::new(25),
        calls: vec![Call {
            to: PATH_USD_ADDRESS.into(),
            value: U256::ZERO,
            input: ITIP20::transferCall {
                to: address(100),
                amount: U256::from(17),
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    }
    .into_signed(TempoSignature::default());
    TempoTxEnv::from_recovered_tx(&tx, address(0))
}

fn hints(
    config: &TempoEvmConfig,
    txs: &[TempoTxEnv],
    env: &EvmEnvFor<TempoEvmConfig>,
) -> Vec<ProofKeyHint> {
    let mut keys = Vec::new();
    config.prewarm_proof_keys(txs, env, |key| {
        keys.push(key);
        true
    });
    keys
}

#[derive(Debug)]
struct RecordingDb<'a> {
    db: &'a mut TestDB,
    reads: &'a mut HashSet<ProofKeyHint>,
}

impl Database for RecordingDb<'_> {
    type Error = <TestDB as Database>::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads.insert(ProofKeyHint::Account(address));
        Database::basic(self.db, address)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.reads.insert(ProofKeyHint::Storage(address, slot));
        self.db.storage(address, slot)
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.db.code_by_hash(hash)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.db.block_hash(number)
    }
}

#[test]
fn paid_tip20_hints_include_actual_keyed_and_expiring_aa_reads() {
    let config = config();
    for nonce_key in [U256::from(13), U256::MAX] {
        let mut setup = crate::test_utils::test_evm_with_basefee(TestDB::default(), 0);
        StorageCtx::enter_ctx(setup.ctx_mut(), StorageActions::disabled(), || {
            TIP20Setup::path_usd(address(999))
                .with_issuer(address(999))
                .with_mint(address(0), U256::from(1_000_000_000u64))
                .apply()
                .unwrap();
        });
        let state = setup.ctx_mut().journaled_state.finalize();
        setup.db_mut().commit(state);
        let mut db = setup.finish().0;
        for &(address, activation) in tempo_precompiles::SYSTEM_PRECOMPILES {
            if TempoHardfork::T14 >= activation {
                db.insert_account_info(
                    address,
                    AccountInfo::default()
                        .with_code(Bytecode::new_raw(Bytes::from_static(&[0xef]))),
                );
            }
        }
        db.insert_account_info(
            address(0),
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
        let tx = paid_aa(nonce_key);
        let nonce_slot = if nonce_key == U256::MAX {
            tx.unique_tx_identifier()
                .unwrap()
                .mapping_slot(nonce_slots::EXPIRING_NONCE_SEEN)
        } else {
            nonce_key.mapping_slot(address(0).mapping_slot(nonce_slots::NONCES))
        };
        let keys = hints(&config, std::slice::from_ref(&tx), &env());
        let mut reads = HashSet::default();
        let mut evm = TempoEvm::new(
            RecordingDb {
                db: &mut db,
                reads: &mut reads,
            },
            env(),
        );
        assert!(evm.transact_raw(tx).unwrap().result.is_success());
        drop(evm);
        for key in [
            ProofKeyHint::Account(address(0)),
            ProofKeyHint::Account(PATH_USD_ADDRESS),
            ProofKeyHint::Storage(NONCE_PRECOMPILE_ADDRESS, nonce_slot),
            ProofKeyHint::Storage(
                PATH_USD_ADDRESS,
                address(0).mapping_slot(token_slots::BALANCES),
            ),
            ProofKeyHint::Storage(
                PATH_USD_ADDRESS,
                address(100).mapping_slot(token_slots::BALANCES),
            ),
            ProofKeyHint::Storage(
                PATH_USD_ADDRESS,
                TIP_FEE_MANAGER_ADDRESS.mapping_slot(token_slots::BALANCES),
            ),
        ] {
            assert!(reads.contains(&key), "actual execution must read {key:?}");
            assert!(keys.contains(&key), "partial hints must include {key:?}");
        }
    }
}

#[test]
fn hints_require_enabled_marked_canonical_configuration_and_transaction_context() {
    let enabled = config();
    let mut disabled = enabled.clone();
    disabled.speculative_executor = disabled
        .speculative_executor
        .map(|executor| executor.with_proof_prefetch(false));
    let unmarked = TempoEvmConfig::moderato()
        .with_speculative_executor(enabled.speculative_executor.clone().unwrap());
    for config in [TempoEvmConfig::moderato(), disabled, unmarked] {
        config.prewarm_proof_keys(
            std::iter::from_fn(|| -> Option<&TempoTxEnv> {
                panic!("disabled hook consumed input")
            }),
            &env(),
            |_| panic!("disabled hook emitted keys"),
        );
    }
    for relaxed in 0..4 {
        let mut env = env();
        match relaxed {
            0 => env.cfg_env.disable_nonce_check = true,
            1 => env.cfg_env.disable_balance_check = true,
            2 => env.cfg_env.disable_base_fee = true,
            _ => env.cfg_env.disable_fee_charge = true,
        }
        assert!(hints(&enabled, &[paid_aa(U256::MAX)], &env).is_empty());
    }
    for invalid_context in 0..3 {
        let mut tx = paid_aa(U256::MAX);
        match invalid_context {
            0 => tx.is_system_tx = true,
            1 => tx.execution_context = ExecutionContext::Simulation,
            _ => tx.fee_payer = Some(None),
        }
        assert!(hints(&enabled, &[tx], &env()).is_empty());
    }
}

#[test]
fn hints_bound_transactions_and_call_scans_and_reset_batch_deduplication() {
    let config = config();
    let txs = (0..17)
        .map(|i| {
            let mut tx = paid_aa(U256::from(13));
            tx.inner.caller = address(i);
            tx.inner.gas_price = 0;
            let aa = tx.tempo_tx_env.as_mut().unwrap();
            aa.aa_calls.extend((1..8).map(|call| Call {
                to: if call == 1 {
                    TxKind::Create
                } else {
                    TxKind::Call(address(1000 + call))
                },
                value: U256::ZERO,
                input: Bytes::new(),
            }));
            tx
        })
        .collect::<Vec<_>>();
    let keys = hints(&config, &txs, &env());
    assert!(keys.contains(&ProofKeyHint::Account(address(15))));
    assert!(!keys.contains(&ProofKeyHint::Account(address(16))));
    assert!(keys.contains(&ProofKeyHint::Account(address(1003))));
    assert!(
        !keys.contains(&ProofKeyHint::Account(address(1004))),
        "Create calls also consume the scan budget"
    );
    assert_eq!(
        keys.len(),
        keys.iter().copied().collect::<HashSet<_>>().len()
    );
    assert_eq!(
        keys,
        hints(&config, &txs, &env()),
        "a later batch gets a fresh planner"
    );
}

#[test]
fn hints_stop_at_consumer_limit_and_internal_key_budget() {
    let config = config();
    // Distinct synthetic token/payer keys exercise the cap; this is not an
    // execution fixture and makes no claim that those tokens exist in state.
    let txs = (0..16)
        .map(|i| {
            let mut tx = paid_aa(U256::from(13));
            tx.inner.caller = address(i);
            tx.fee_payer = Some(Some(address(200 + i)));
            let mut token = PATH_USD_ADDRESS;
            token.0[19] = (i * 2 + 1) as u8;
            tx.fee_token = Some(token);
            token.0[19] += 1;
            tx.tempo_tx_env.as_mut().unwrap().aa_calls[0].to = token.into();
            tx
        })
        .collect::<Vec<_>>();
    let mut env = env();
    env.cfg_env.spec = TempoHardfork::T1;
    let keys = hints(&config, &txs, &env);
    assert_eq!(keys.len(), 512);
    assert_eq!(
        keys.len(),
        keys.iter().copied().collect::<HashSet<_>>().len()
    );
    for limit in [1, 3, 30] {
        let mut stopped = Vec::new();
        config.prewarm_proof_keys(&txs, &env, |key| {
            stopped.push(key);
            stopped.len() < limit
        });
        assert_eq!(stopped, keys[..limit]);
    }
}
