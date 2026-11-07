//! Tests that a zone prices Tempo commitment reads into its cold account access (TIP-1154).

use crate::zone_evm::tests::{config, transaction};
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
use evm2::{
    EvmFeatures, TxResult,
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
    interpreter::{InstrStop, op},
};
use reth_evm::BlockExecutorFactory;
use tempo_chainspec::{constants::gas::L1_COMMITMENT_READ_GAS, hardfork::TempoHardfork};
use tempo_evm::{TempoEvmEnv, TempoEvmTypes};
use zone_precompiles::{ZONE_FEE_MANAGER_ADDRESS, zone_fee_manager};

const SENDER: Address = Address::repeat_byte(0x01);
const PROBE: Address = Address::repeat_byte(0x02);
const CONTRACT: Address = Address::repeat_byte(0x03);
const ELIGIBLE: Address = Address::repeat_byte(0x04);
const BENEFICIARY: Address = Address::repeat_byte(0x05);

/// Code that loads each target with `opcode`, as `BALANCE` or `CALL` with all gas.
fn probe(opcode: u8, targets: &[Address]) -> Bytes {
    let mut code = Vec::new();
    for target in targets {
        if opcode == op::CALL {
            code.extend([op::PUSH0; 5]);
        }
        code.push(op::PUSH20);
        code.extend_from_slice(target.as_slice());
        if opcode == op::CALL {
            code.push(op::GAS);
        }
        code.extend([opcode, op::POP]);
    }
    code.push(op::STOP);
    code.into()
}

/// Calls [`PROBE`] holding `code` from [`SENDER`] at `spec`, without fees.
fn run(spec: TempoHardfork, code: Bytes, gas_limit: u64) -> TxResult<TempoEvmTypes> {
    let mut db = InMemoryDB::default();
    db.insert_account_info(&ZONE_FEE_MANAGER_ADDRESS, AccountInfo::default());
    db.insert_account_storage(
        &ZONE_FEE_MANAGER_ADDRESS,
        &zone_fee_manager::slots::DEFAULT_FEE_TOKEN,
        &U256::from_be_slice(tempo_precompiles::DEFAULT_FEE_TOKEN.as_slice()),
    );
    db.insert_account_info(&SENDER, AccountInfo::default().with_nonce(1));
    db.insert_account_info(
        &PROBE,
        AccountInfo::default().with_code(Bytecode::new_raw(code)),
    );
    db.insert_account_info(
        &CONTRACT,
        AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[op::STOP]))),
    );
    let mut env = TempoEvmEnv {
        spec,
        ..Default::default()
    };
    env.version = tempo_chainspec::gas_params::version(evm2::SpecId::from(spec), spec, false);
    env.version.features.remove(EvmFeatures::FEE_CHARGE);
    env.block.gas_limit = U256::from(30_000_000);
    env.block.beneficiary = BENEFICIARY;
    let mut evm = BlockExecutorFactory::evm_with_env(&config(), db, env);
    let tx = TxLegacy {
        nonce: 1,
        gas_limit,
        to: TxKind::Call(PROBE),
        ..Default::default()
    };
    let tx = transaction(SENDER, tx.into_signed(Signature::test_signature()));
    evm.transact(&tx).unwrap().discard()
}

/// Gas a call to [`PROBE`] holding `probe(opcode, targets)` spends on the loads alone.
fn load_gas(spec: TempoHardfork, opcode: u8, targets: &[Address]) -> u64 {
    let gas_used = |targets: &[Address]| {
        let result = run(spec, probe(opcode, targets), 1_000_000);
        assert!(result.status, "{result:?}");
        result.tx_gas_used()
    };
    gas_used(targets) - gas_used(&[])
}

#[test]
fn cold_loads_pay_a_tempo_read_from_t14() {
    for opcode in [op::BALANCE, op::CALL] {
        // Zone contracts pay the read too. A warm reload pays nothing more.
        for targets in [[ELIGIBLE].as_slice(), &[CONTRACT], &[ELIGIBLE, ELIGIBLE]] {
            assert_eq!(
                load_gas(TempoHardfork::T14, opcode, targets)
                    - load_gas(TempoHardfork::T13, opcode, targets),
                L1_COMMITMENT_READ_GAS,
                "{opcode} {targets:?}"
            );
        }
    }
}

#[test]
fn beneficiary_and_sender_stay_warm_from_t14() {
    // The sender's read is intrinsic, and the beneficiary's is one per block, so their loads only
    // pay warm access.
    for account in [SENDER, BENEFICIARY] {
        assert_eq!(
            load_gas(TempoHardfork::T14, op::BALANCE, &[account]),
            load_gas(TempoHardfork::T13, op::BALANCE, &[account])
        );
    }
}

#[test]
fn cold_load_that_cannot_pay_its_tempo_read_runs_out_of_gas() {
    let paid = run(
        TempoHardfork::T14,
        probe(op::BALANCE, &[ELIGIBLE]),
        1_000_000,
    )
    .tx_gas_used();
    // One gas short of the cold access, after the 2 of the trailing POP.
    let result = run(
        TempoHardfork::T14,
        probe(op::BALANCE, &[ELIGIBLE]),
        paid - 3,
    );
    assert_eq!(result.stop, InstrStop::OutOfGas);
    assert!(run(TempoHardfork::T14, probe(op::BALANCE, &[ELIGIBLE]), paid).status);
}
