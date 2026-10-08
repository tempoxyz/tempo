//! Signed migration through the production handler, including same-block retirement and rollback.
use super::*;
use alloy_evm::FromRecoveredTx;
use alloy_primitives::keccak256;
use revm::context::result::EVMError;
use tempo_revm::{
    ExecutionContext, TempoInvalidTransaction, TempoTxEnv, native_multisig::NativeMultisigError,
};

fn fixture() -> Fixture {
    let mut f = Fixture::with_parent(false);
    f.evm.ctx_mut().block.account_migration_enabled = true;
    f.config.version = 1;
    f.config.salt =
        keccak256([b"tempo:multisig:upgrade".as_slice(), f.account.as_slice()].concat());
    f
}

fn upgrade(f: &Fixture) -> Call {
    Call {
        to: NATIVE_MULTISIG_ADDRESS.into(),
        value: U256::ZERO,
        input: INativeMultisig::upgradeAccountCall {
            threshold: f.config.threshold,
            owners: f
                .config
                .owners
                .iter()
                .map(|owner| INativeMultisig::MultisigOwner {
                    owner: owner.owner,
                    weight: owner.weight,
                })
                .collect(),
        }
        .abi_encode()
        .into(),
    }
}

fn root_signed(f: &Fixture, nonce: u64, gas_limit: u64, calls: Vec<Call>) -> AASigned {
    let tx = TempoTransaction {
        chain_id: 1,
        nonce,
        gas_limit,
        calls,
        ..Default::default()
    };
    let signature = f.owner.sign_hash_sync(&tx.signature_hash()).unwrap();
    tx.into_signed(TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        signature,
    )))
}

#[test]
fn migration_runtime_same_block_root_retirement_and_explicit_owner_signing() {
    let mut f = fixture();
    let block = f.evm.ctx_mut().block.clone();
    let tx = root_signed(&f, 3, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        INativeMultisig::upgradeAccountCall::abi_decode_returns(output.result.output().unwrap())
            .unwrap(),
        f.config.commitment().unwrap()
    );
    assert_eq!(output.state[&f.account].info.balance, U256::from(42));
    f.evm.db_mut().commit(output.state);
    let old_root = root_signed(&f, 4, 1_000_000, vec![f.getter()]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&old_root, f.account))
        .unwrap_err();
    assert_eq!(
        error,
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::RootKeyRetired { account: f.account }
        ))
    );
    let tx = f.signed(4, vec![f.getter()]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());
    assert_eq!(f.evm.ctx_mut().block.timestamp, block.timestamp);
    assert_eq!(f.evm.ctx_mut().block.number, block.number);
}

#[test]
fn migration_runtime_out_of_gas_rolls_back_commitment_and_event_not_nonce() {
    let mut probe = fixture();
    let tx = root_signed(&probe, 3, 1_000_000, vec![upgrade(&probe)]);
    let output = probe
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, probe.account))
        .unwrap();
    assert!(output.result.is_success());
    let used = output.result.tx_gas_used();
    let mut f = fixture();
    let tx = root_signed(&f, 3, used - 1, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(!output.result.is_success(), "{:?}", output.result);
    assert_eq!(
        decode_config_commitment(&output.state[&f.account].info.extension, true).unwrap(),
        B256::ZERO
    );
    assert_eq!(output.state[&f.account].info.nonce, 4);
    assert!(
        output
            .result
            .logs()
            .iter()
            .all(|log| log.address != NATIVE_MULTISIG_ADDRESS)
    );
    f.evm.db_mut().commit(output.state);
    let retry = root_signed(&f, 4, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&retry, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
}

#[test]
fn migration_runtime_simulation_is_noncommitting_and_does_not_seed_next_transaction() {
    let mut f = fixture();
    let tx = root_signed(&f, 3, 1_000_000, vec![upgrade(&f)]);
    let mut env = TempoTxEnv::from_recovered_tx(&tx, f.account);
    env.execution_context = ExecutionContext::Simulation;
    let output = f.evm.transact(env).unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    // RPC callers discard state. The next transaction must authenticate its own context.
    assert_eq!(f.commitment(), B256::ZERO);
    let delegated = f.signed(3, vec![upgrade(&f)]);
    let error = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&delegated, f.account))
        .unwrap_err();
    assert!(matches!(
        error,
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::InvalidAccount { .. }
        ))
    ));
    assert_eq!(f.commitment(), B256::ZERO);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&tx, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
}
