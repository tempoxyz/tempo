//! Tests that a zone charges each Tempo commitment read through its gas schedule (TIP-1154).

use crate::zone_evm::tests::{config, fee_free_env, transaction};
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_sol_types::{SolCall, SolError};
use evm2::{
    TxResult,
    bytecode::Bytecode,
    evm::{AccountInfo, InMemoryDB},
    interpreter::{InstrStop, op},
};
use reth_evm::BlockExecutorFactory;
use tempo_chainspec::{constants::gas::L1_COMMITMENT_READ_GAS, hardfork::TempoHardfork};
use tempo_contracts::precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount};
use tempo_evm::TempoEvmTypes;
use zone_precompiles::{ZONE_FEE_MANAGER_ADDRESS, test_utils::MockL1Reader, zone_fee_manager};

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

/// Executes `tx` from [`SENDER`] at `spec`, with [`PROBE`] holding `code` and Tempo read
/// through `l1`.
fn execute(
    spec: TempoHardfork,
    tx: TxLegacy,
    code: Bytes,
    l1: &MockL1Reader,
) -> TxResult<TempoEvmTypes> {
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
    let mut env = fee_free_env(spec);
    env.block.beneficiary = BENEFICIARY;
    let mut evm = BlockExecutorFactory::evm_with_env(&config(l1.clone()), db, env);
    let tx = transaction(
        SENDER,
        TxLegacy { nonce: 1, ..tx }.into_signed(Signature::test_signature()),
    );
    evm.transact(&tx).unwrap().discard()
}

/// Runs a call at `spec` to [`PROBE`] holding `code`, returning its result and the accounts
/// whose commitments were read from Tempo.
fn run(
    spec: TempoHardfork,
    code: Bytes,
    gas_limit: u64,
) -> (TxResult<TempoEvmTypes>, Vec<Address>) {
    let l1 = MockL1Reader::default();
    let tx = TxLegacy {
        gas_limit,
        to: TxKind::Call(PROBE),
        ..Default::default()
    };
    let result = execute(spec, tx, code, &l1);
    let reads = l1
        .commitment_requests()
        .into_iter()
        .map(|(account, _)| account)
        .collect();
    (result, reads)
}

/// Gas a call to [`PROBE`] holding `probe(opcode, targets)` spends on the loads alone.
fn load_gas(spec: TempoHardfork, opcode: u8, targets: &[Address]) -> u64 {
    let gas_used = |targets: &[Address]| {
        let (result, _) = run(spec, probe(opcode, targets), 1_000_000);
        assert!(result.status, "{result:?}");
        result.tx_gas_used()
    };
    gas_used(targets) - gas_used(&[])
}

#[test]
fn cold_loads_pay_a_tempo_read_from_t14() {
    for opcode in [op::BALANCE, op::CALL] {
        // Zone contracts pay the read too, though the overlay reads nothing for them. A warm
        // reload pays nothing more.
        for targets in [[ELIGIBLE].as_slice(), &[CONTRACT], &[ELIGIBLE, ELIGIBLE]] {
            assert_eq!(
                load_gas(TempoHardfork::T14, opcode, targets)
                    - load_gas(TempoHardfork::T13, opcode, targets),
                L1_COMMITMENT_READ_GAS,
                "{opcode} {targets:?}"
            );
        }
    }
    let (_, reads) = run(
        TempoHardfork::T14,
        probe(op::BALANCE, &[ELIGIBLE]),
        1_000_000,
    );
    assert!(reads.contains(&ELIGIBLE), "{reads:?}");
    let (_, reads) = run(
        TempoHardfork::T13,
        probe(op::BALANCE, &[ELIGIBLE]),
        1_000_000,
    );
    assert!(reads.is_empty(), "{reads:?}");
}

#[test]
fn beneficiary_is_cold_and_sender_warm_from_t14() {
    assert_eq!(
        load_gas(TempoHardfork::T14, op::BALANCE, &[BENEFICIARY]),
        load_gas(TempoHardfork::T14, op::BALANCE, &[ELIGIBLE])
    );
    // The sender's read is intrinsic, so its loads only pay warm access.
    assert_eq!(
        load_gas(TempoHardfork::T14, op::BALANCE, &[SENDER]),
        load_gas(TempoHardfork::T13, op::BALANCE, &[SENDER])
    );
}

#[test]
fn cold_load_that_cannot_pay_its_tempo_read_reads_nothing() {
    let (result, _) = run(
        TempoHardfork::T14,
        probe(op::BALANCE, &[ELIGIBLE]),
        1_000_000,
    );
    let paid = result.tx_gas_used();
    // One gas short of the cold access, after the 2 of the trailing POP.
    let (result, reads) = run(
        TempoHardfork::T14,
        probe(op::BALANCE, &[ELIGIBLE]),
        paid - 3,
    );
    assert_eq!(result.stop, InstrStop::OutOfGas);
    assert!(!reads.contains(&ELIGIBLE), "{reads:?}");

    let (result, reads) = run(TempoHardfork::T14, probe(op::BALANCE, &[ELIGIBLE]), paid);
    assert!(result.status, "{result:?}");
    assert!(reads.contains(&ELIGIBLE), "{reads:?}");
}

#[test]
fn configurable_account_precompile_reads_tempo_and_rejects_writes() {
    let l1 = MockL1Reader::default();
    let commitment = B256::repeat_byte(7);
    l1.insert_commitment(ELIGIBLE, 0, commitment);
    let call = |input: Vec<u8>| TxLegacy {
        gas_limit: 1_000_000,
        to: TxKind::Call(CONFIGURABLE_ACCOUNT_ADDRESS),
        input: input.into(),
        ..Default::default()
    };

    let read = execute(
        TempoHardfork::T14,
        call(IConfigurableAccount::getConfigCommitmentCall { account: ELIGIBLE }.abi_encode()),
        Bytes::new(),
        &l1,
    );
    assert!(read.status, "{read:?}");
    assert_eq!(read.output[..], commitment[..]);

    for selector in [
        IConfigurableAccount::updateConfigCall::SELECTOR,
        IConfigurableAccount::upgradeAccountCall::SELECTOR,
    ] {
        let rejected = execute(
            TempoHardfork::T14,
            call(selector.to_vec()),
            Bytes::new(),
            &l1,
        );
        assert_eq!(rejected.stop, InstrStop::Revert);
        assert_eq!(
            rejected.output,
            IConfigurableAccount::UnsupportedOnZone {}.abi_encode()
        );
    }
}
